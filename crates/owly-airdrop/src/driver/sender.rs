//! The sender driver: `/Discover` a receiver, then `/Ask` and `/Upload` on
//! one fresh TLS connection (HTTP-1), running a
//! [`proto::sender::Transfer`](crate::proto::sender::Transfer).
//!
//! The archive is compressed into a temporary file before the `/Ask`, so the
//! upload can carry a `Content-Length` like Finder's (UP-1a).

use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::net::SocketAddrV6;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use flate2::Compression;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::tls::{self, Identity};
use crate::proto::archive::compress::{Compressor, Encoder};
use crate::proto::archive::cpio::{self, Entry};
use crate::proto::archive::extract::RelPath;
use crate::proto::mdns::{SUPPORTS_DVZIP, SUPPORTS_MIXED_TYPES, SUPPORTS_PIPELINING};
use crate::proto::messages::{AskFile, Offer};
use crate::proto::sender::{self, Action, Config, Outcome, Receiver, ResponseReader, Transfer};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(10);
/// A write the receiver doesn't take in this long fails the transfer, so a
/// receiver that stops reading can't hold the sender forever (SEC-10).
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound TLS close_notify on teardown: on a dead link whose kernel send
/// buffer is already full, an unbounded `shutdown()` blocks until TCP's
/// retransmission limit expires.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// What to send.
#[derive(Debug, Clone)]
pub enum Payload {
    Files(Vec<PathBuf>),
    Urls(Vec<String>),
}

/// Upload progress, in bytes of the compressed body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub sent: u64,
    pub total: u64,
}

/// What a transfer reports while it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The receiver accepted the `/Ask`. A failure after this one is the
    /// upload's.
    Accepted,
    Progress(Progress),
}

pub struct Sender {
    config: Config,
    connector: TlsConnector,
}

impl Sender {
    pub fn new(config: Config) -> io::Result<Self> {
        Self::with_client_identity(config, None)
    }

    /// A sender that presents a client certificate, as Apple senders do
    /// (TLS-3). For tests.
    #[doc(hidden)]
    pub fn with_client_identity(config: Config, identity: Option<&Identity>) -> io::Result<Self> {
        Ok(Sender {
            config,
            connector: TlsConnector::from(tls::client_config(identity)?),
        })
    }

    async fn connect(&self, addr: SocketAddrV6) -> io::Result<TlsStream<TcpStream>> {
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        stream.set_nodelay(true)?;
        timeout(
            CONNECT_TIMEOUT,
            self.connector.connect(tls::server_name(), stream),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }

    /// `/Discover` on a connection of its own (DISCOVERING in §8.1).
    /// `None` if the receiver doesn't want to be listed (DISC-1).
    pub async fn discover(&self, addr: SocketAddrV6) -> io::Result<Option<Receiver>> {
        let mut tls = self.connect(addr).await?;
        let response = timeout(DISCOVER_TIMEOUT, async {
            tls.write_all(&sender::discover_request()).await?;
            tls.flush().await?;
            read_response(&mut tls).await
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        shutdown(&mut tls).await;
        Ok(sender::parse_discover_response(&response))
    }

    /// Asks the receiver at `addr` to take `payload`, and uploads it if it
    /// does. `receiver_flags` is its TXT `flags`, or `0` if they aren't
    /// known, and decides between DVZip and gzip (UP-1b).
    pub async fn send(
        &self,
        addr: SocketAddrV6,
        payload: &Payload,
        receiver_flags: u32,
        events: Option<mpsc::UnboundedSender<Event>>,
    ) -> io::Result<Outcome> {
        let compressor = compressor(receiver_flags);
        let (offer, archive) = match payload {
            Payload::Urls(urls) => (Offer::Urls(urls.clone()), None),
            Payload::Files(paths) => {
                let paths = paths.clone();
                let (offer, file, len) =
                    tokio::task::spawn_blocking(move || prepare(&paths, compressor))
                        .await
                        .map_err(io::Error::other)??;
                (offer, Some((file, len)))
            }
        };
        let transfer_id = uuid_v4()?;
        let body = archive.as_ref().map(|(_, len)| (compressor, *len));
        let mut transfer = Transfer::new(&self.config, &transfer_id, &offer, body);
        let mut archive = archive.map(|(file, _)| tokio::fs::File::from_std(file));

        let mut tls = self.connect(addr).await?;
        let mut buf = vec![0; 16 << 10];
        let mut timer: Option<Instant> = None;
        let mut eof = false;
        loop {
            while let Some(action) = transfer.poll() {
                match action {
                    Action::Transmit(bytes) => {
                        // Flushed, or tokio-rustls may hold it back.
                        if let Err(e) = write(&mut tls, &bytes).await {
                            transfer.receive_eof();
                            tracing::debug!("write failed: {e}");
                        }
                    }
                    Action::SetTimer(after) => timer = after.map(|d| Instant::now() + d),
                    Action::Accepted => {
                        if let Some(events) = &events {
                            let _ = events.send(Event::Accepted);
                        }
                    }
                    Action::SendUpload(head) => {
                        let file = archive.as_mut().expect("a file share has an archive");
                        match upload(&mut tls, &head, file, events.as_ref()).await {
                            Ok(()) => transfer.upload_sent(),
                            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                                // SEC-10: the receiver stopped reading, so
                                // fail now instead of waiting another
                                // UPLOAD_RESPONSE_TIMEOUT.
                                tracing::debug!("upload stalled: {e}");
                                transfer.timeout();
                            }
                            Err(e) => {
                                // The receiver may have refused and closed;
                                // its response, if any, says why.
                                tracing::debug!("upload write failed: {e}");
                                transfer.upload_sent();
                            }
                        }
                    }
                    Action::Done(outcome) => {
                        shutdown(&mut tls).await;
                        return Ok(outcome);
                    }
                }
            }
            tokio::select! {
                read = tls.read(&mut buf), if !eof => match read {
                    Ok(0) | Err(_) => {
                        eof = true;
                        transfer.receive_eof();
                    }
                    Ok(n) => transfer.receive(&buf[..n]),
                },
                () = sleep_until(timer.unwrap_or_else(Instant::now)), if timer.is_some() => {
                    timer = None;
                    transfer.timeout();
                }
            }
        }
    }
}

async fn read_response<S: AsyncReadExt + Unpin>(stream: &mut S) -> io::Result<sender::Response> {
    let mut reader = ResponseReader::new();
    let mut buf = vec![0; 16 << 10];
    loop {
        let n = stream.read(&mut buf).await?;
        let result = if n == 0 {
            reader.receive_eof().map(Some)
        } else {
            reader.receive(&buf[..n])
        };
        match result {
            Ok(Some(response)) => return Ok(response),
            Ok(None) => {}
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }
}

async fn upload<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    head: &[u8],
    file: &mut tokio::fs::File,
    events: Option<&mpsc::UnboundedSender<Event>>,
) -> io::Result<()> {
    let total = file.metadata().await?.len();
    write(stream, head).await?;
    let mut buf = vec![0; 64 << 10];
    let mut sent = 0;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        write(stream, &buf[..n]).await?;
        sent += n as u64;
        if let Some(events) = events {
            let _ = events.send(Event::Progress(Progress { sent, total }));
        }
    }
    Ok(())
}

/// Writes and flushes `bytes`, failing if the receiver stalls.
async fn write<S: AsyncWriteExt + Unpin>(stream: &mut S, bytes: &[u8]) -> io::Result<()> {
    let written = async {
        stream.write_all(bytes).await?;
        stream.flush().await
    };
    timeout(WRITE_TIMEOUT, written)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the receiver stopped reading"))?
}

/// Sends TLS close_notify if the peer is still reachable, without blocking
/// forever when the socket's send buffer is wedged on a dead link.
async fn shutdown<S: AsyncWriteExt + Unpin>(stream: &mut S) {
    let _ = timeout(SHUTDOWN_TIMEOUT, stream.shutdown()).await;
}

/// DVZip unless the receiver's TXT `flags` leave it out. Flags with neither
/// SupportsPipelining nor SupportsMixedTypes aren't a valid receiver's
/// (MDNS-5), such as the `0` of an instance whose TXT hasn't arrived, so
/// they say nothing and get DVZip too (UP-1b).
fn compressor(receiver_flags: u32) -> Compressor {
    let known = receiver_flags & (SUPPORTS_PIPELINING | SUPPORTS_MIXED_TYPES) != 0;
    if known && receiver_flags & SUPPORTS_DVZIP == 0 {
        Compressor::Gzip
    } else {
        Compressor::DvZip
    }
}

/// A fresh transfer ID: an uppercase UUID v4 (§6.4).
fn uuid_v4() -> io::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| io::Error::other(e.to_string()))?;
    b[6] = b[6] & 0x0f | 0x40;
    b[8] = b[8] & 0x3f | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02X}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// Checks that `paths` can be offered and archived before taking the radio
/// or discovering peers.
pub fn validate_files(paths: &[PathBuf]) -> io::Result<()> {
    collect_items(paths).map(drop)
}

fn collect_items(paths: &[PathBuf]) -> io::Result<Vec<(String, PathBuf, std::fs::Metadata)>> {
    let mut items: Vec<(String, PathBuf, std::fs::Metadata)> = Vec::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid(format!("{} has no UTF-8 file name", path.display())))?;
        RelPath::file_name(name).map_err(|e| invalid(e.to_string()))?;
        if items.iter().any(|(n, _, _)| n == name) {
            return Err(invalid(format!("two items are called {name}")));
        }
        let meta = std::fs::metadata(path)?;
        if meta.is_file() {
            if meta.len() > cpio::ODC_MAX_SIZE {
                return Err(invalid(format!(
                    "{} is too large for an archive",
                    path.display()
                )));
            }
        } else if !meta.is_dir() {
            return Err(invalid(format!(
                "{} isn't a file or directory",
                path.display()
            )));
        }
        items.push((name.to_string(), path.clone(), meta));
    }
    if items.is_empty() {
        return Err(invalid("nothing to send".into()));
    }
    Ok(items)
}

/// Builds the `/Ask` offer for `paths` and compresses their archive into a
/// temporary file, returning it rewound with its length.
pub fn prepare(paths: &[PathBuf], compressor: Compressor) -> io::Result<(Offer, File, u64)> {
    let items = collect_items(paths)?;

    let mut spool = tempfile::tempfile()?;
    let mut writer = ArchiveWriter {
        encoder: Encoder::new(compressor, Compression::fast()),
        out: io::BufWriter::new(&mut spool),
        ino: 1,
        buf: vec![0; 64 << 10],
    };
    // UP-2a: the root entry first.
    writer.entry(&dir_entry(".", mtime(&items[0].2)), None)?;
    let mut files = Vec::new();
    for (name, path, meta) in &items {
        let size = if meta.is_dir() {
            writer.tree(path, &format!("./{name}"))?
        } else {
            writer.file(path, &format!("./{name}"), meta)?;
            meta.len()
        };
        files.push(AskFile {
            name: name.clone(),
            file_type: sender::uti(name, meta.is_dir()).into(),
            size: Some(size),
            bom_path: format!("./{name}"),
            is_directory: meta.is_dir(),
        });
    }
    writer.finish()?;
    let len = spool.stream_position()?;
    spool.rewind()?;
    Ok((Offer::Files(files), spool, len))
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn mtime(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// The owner a Mac's archives carry; receivers ignore it.
const UID: u32 = 501;
const GID: u32 = 20;

/// UP-2: entries for an odc archive.
pub fn file_entry(name: &str, size: u64, ino: u32, mtime: u64) -> Entry {
    Entry {
        name: name.into(),
        mode: cpio::MODE_FILE | 0o644,
        size,
        nlink: 1,
        ino,
        uid: UID,
        gid: GID,
        mtime,
    }
}

pub fn dir_entry(name: &str, mtime: u64) -> Entry {
    Entry {
        name: name.into(),
        mode: cpio::MODE_DIR | 0o755,
        size: 0,
        nlink: 2,
        ino: 0,
        uid: UID,
        gid: GID,
        mtime,
    }
}

struct ArchiveWriter<W: Write> {
    encoder: Encoder,
    out: W,
    ino: u32,
    buf: Vec<u8>,
}

impl<W: Write> ArchiveWriter<W> {
    fn entry(&mut self, entry: &Entry, data: Option<&mut dyn Read>) -> io::Result<()> {
        let mut entry = entry.clone();
        entry.ino = self.ino;
        self.ino += 1;
        let header = self.encoder.write(&cpio::odc_header(&entry));
        self.out.write_all(&header)?;
        if let Some(data) = data {
            let mut left = entry.size;
            let cap = self.buf.len();
            while left > 0 {
                let n = data.read(&mut self.buf[..(left as usize).min(cap)])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "file shrank while sending",
                    ));
                }
                left -= n as u64;
                let compressed = self.encoder.write(&self.buf[..n]);
                self.out.write_all(&compressed)?;
            }
        }
        Ok(())
    }

    fn file(&mut self, path: &Path, name: &str, meta: &std::fs::Metadata) -> io::Result<()> {
        if meta.len() > cpio::ODC_MAX_SIZE {
            return Err(invalid(format!(
                "{} is too large for an archive",
                path.display()
            )));
        }
        let mut file = File::open(path)?;
        self.entry(
            &file_entry(name, meta.len(), 0, mtime(meta)),
            Some(&mut file),
        )
    }

    /// A directory and everything under it, in name order. Symlinks and
    /// special files are left out. Returns the total file size.
    fn tree(&mut self, path: &Path, name: &str) -> io::Result<u64> {
        self.entry(&dir_entry(name, mtime(&std::fs::metadata(path)?)), None)?;
        let mut children: Vec<_> = std::fs::read_dir(path)?.collect::<Result<_, _>>()?;
        children.sort_by_key(|c| c.file_name());
        let mut total = 0;
        for child in children {
            let Some(child_name) = child.file_name().to_str().map(String::from) else {
                continue;
            };
            if RelPath::file_name(&child_name).is_err() {
                continue;
            }
            let meta = std::fs::symlink_metadata(child.path())?;
            let child_path = format!("{name}/{child_name}");
            if meta.is_dir() {
                total += self.tree(&child.path(), &child_path)?;
            } else if meta.is_file() {
                self.file(&child.path(), &child_path, &meta)?;
                total += meta.len();
            }
        }
        Ok(total)
    }

    fn finish(mut self) -> io::Result<()> {
        let trailer = self.encoder.write(&cpio::odc_trailer());
        self.out.write_all(&trailer)?;
        self.out.write_all(&self.encoder.finish())?;
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: SEC-10
    #[tokio::test(start_paused = true)]
    async fn a_receiver_that_stops_reading_fails_the_upload() {
        // A pipe nobody reads: the write fills it, then waits.
        let (mut ours, _theirs) = tokio::io::duplex(1024);
        let started = Instant::now();
        let e = write(&mut ours, &[0; 4096]).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), WRITE_TIMEOUT);
    }

    // spec: SEC-10
    #[tokio::test(start_paused = true)]
    async fn shutdown_bounds_a_stalled_close_notify() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::AsyncWrite;

        struct StuckShutdown;
        impl AsyncWrite for StuckShutdown {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }

        let mut stream = StuckShutdown;
        let started = Instant::now();
        shutdown(&mut stream).await;
        assert_eq!(started.elapsed(), SHUTDOWN_TIMEOUT);
    }

    // spec: UP-1b, MDNS-5
    #[test]
    fn gzip_only_for_a_receiver_whose_flags_leave_out_dvzip() {
        assert_eq!(compressor(0x089), Compressor::Gzip);
        assert_eq!(compressor(0x08b), Compressor::DvZip);
        assert_eq!(compressor(0x3fb), Compressor::DvZip);
        // No TXT yet, or flags no valid receiver sends.
        assert_eq!(compressor(0), Compressor::DvZip);
        assert_eq!(compressor(0x001), Compressor::DvZip);
    }

    #[test]
    fn validate_files_rejects_missing_and_duplicate_names() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let dup = sub.join("a.txt");
        std::fs::write(&a, b"one").unwrap();
        std::fs::write(&dup, b"two").unwrap();

        assert!(validate_files(&[a.clone(), sub.clone()]).is_ok());
        assert_eq!(
            validate_files(&[dir.path().join("missing.txt")])
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            validate_files(&[a, dup]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            validate_files(&[]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
