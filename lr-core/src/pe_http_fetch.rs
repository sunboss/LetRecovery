//! Minimal HTTP/1.1 file fetcher for the WinPE "online image" install mode.
//!
//! When the handoff config carries `ImageSourceUrl`, the PE endpoint downloads the
//! installation image itself instead of using a file staged by the desktop client.
//! This is the macOS-Internet-Recovery-style flow: boot PE -> network -> fetch image.
//!
//! Design notes:
//! - Pure `std` only (no new dependencies): `TcpStream` + hand-rolled HTTP/1.1.
//!   WinPE ships no modern TLS stack guarantees for third-party crates, and the
//!   reference image server (`netinstall_server.py`) speaks plain HTTP.
//! - Only `http://` URLs are supported in v1. `https://` is rejected with a clear
//!   error; TLS support is a follow-up.
//! - Resumable via `Range` requests; SHA-256 verified after completion using the
//!   existing [`crate::hash`] helpers.
//! - Everything here is platform-independent so it can be unit-tested on Linux.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// Maximum bytes accepted for the HTTP response header block.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Maximum redirects followed for one fetch.
const MAX_REDIRECTS: usize = 5;
/// Outer retry attempts for transient transport failures.
const MAX_ATTEMPTS: usize = 3;
/// TCP connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Per-read timeout while streaming the body.
const READ_TIMEOUT: Duration = Duration::from_secs(120);
/// Chunk size for body streaming.
const STREAM_BUF: usize = 64 * 1024;

const USER_AGENT: &str = "LetRecovery-PE-Fetch/1.0";

/// What to download and how to verify it.
#[derive(Debug, Clone)]
pub struct FetchSpec {
    /// `http://host[:port]/path` — plain HTTP only in v1.
    pub url: String,
    /// Destination file. A partial file is resumed with `Range` when possible.
    pub dest: PathBuf,
    /// Expected final size in bytes. `None` skips the length check.
    pub expected_length: Option<u64>,
    /// Expected SHA-256 (hex, case-insensitive). `None` skips the hash check.
    pub expected_sha256: Option<String>,
}

/// Progress sink: `(downloaded_bytes_total, expected_total_bytes_or_unknown)`.
pub type ProgressFn<'a> = dyn FnMut(u64, Option<u64>) + 'a;

impl FetchSpec {
    /// Basic sanity checks before any network I/O.
    pub fn validate(&self) -> Result<()> {
        let parsed: url::Url = self
            .url
            .parse()
            .with_context(|| format!("invalid image source URL: {}", self.url))?;
        if parsed.scheme() != "http" {
            bail!(
                "only http:// image URLs are supported in v1 (got scheme '{}'); serve the image over plain HTTP",
                parsed.scheme()
            );
        }
        if !parsed.has_host() {
            bail!("image source URL has no host: {}", self.url);
        }
        if let Some(length) = self.expected_length {
            if length == 0 {
                bail!("expected image length must be nonzero");
            }
        }
        if let Some(sha) = self.expected_sha256.as_deref() {
            let sha = sha.trim();
            if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("expected SHA-256 must be 64 hex digits");
            }
        }
        Ok(())
    }
}

/// Download `spec.url` to `spec.dest`, resuming a partial file when the server
/// cooperates, then verifying length and SHA-256 when expectations are set.
///
/// Transient transport failures are retried; verification failures (wrong size
/// or hash) are returned immediately because retrying cannot fix them.
pub fn fetch(spec: &FetchSpec, progress: &mut ProgressFn) -> Result<()> {
    spec.validate()?;
    let mut attempt = 0;
    loop {
        attempt += 1;
        match fetch_once(spec, progress) {
            Ok(()) => return Ok(()),
            Err(error) => {
                if error.downcast_ref::<VerificationError>().is_some() {
                    return Err(error);
                }
                if attempt >= MAX_ATTEMPTS {
                    return Err(error).with_context(|| {
                        format!(
                            "download failed after {MAX_ATTEMPTS} attempts: {}",
                            spec.url
                        )
                    });
                }
                log::warn!(
                    "[PE FETCH] attempt {attempt}/{MAX_ATTEMPTS} failed: {error:#}; retrying"
                );
                std::thread::sleep(Duration::from_secs(2 * attempt as u64));
            }
        }
    }
}

/// Marker for deterministic post-download verification failures: retrying the
/// transfer cannot change the outcome, so [`fetch`] does not retry these.
#[derive(Debug)]
struct VerificationError(String);

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for VerificationError {}

fn fetch_once(spec: &FetchSpec, progress: &mut ProgressFn) -> Result<()> {
    let mut url: url::Url = spec.url.parse().expect("validated URL");
    let resume_from = partial_length(&spec.dest);

    let mut redirects = 0;
    // (url, resume_from) pair per redirect hop; a 416 resets resume to 0 and retries inline.
    let mut current_resume = resume_from;
    loop {
        let outcome = http_get(&url, &spec.dest, current_resume, progress)?;
        match outcome {
            GetOutcome::Done => break,
            GetOutcome::Redirect(next) => {
                redirects += 1;
                if redirects > MAX_REDIRECTS {
                    bail!("too many redirects fetching {}", spec.url);
                }
                log::info!("[PE FETCH] redirect -> {next}");
                url = next;
                // Keep the resume offset across redirects; servers in a redirect chain
                // normally honor Range consistently.
            }
            GetOutcome::RangeNotSatisfiable => {
                if current_resume == 0 {
                    bail!("server reports Range Not Satisfiable for a fresh download");
                }
                log::info!("[PE FETCH] server rejected Range; restarting from byte 0");
                std::fs::remove_file(&spec.dest).ok();
                current_resume = 0;
            }
        }
    }

    verify_result(spec)
}

enum GetOutcome {
    Done,
    Redirect(url::Url),
    RangeNotSatisfiable,
}

fn partial_length(dest: &Path) -> u64 {
    std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0)
}

fn http_get(
    url: &url::Url,
    dest: &Path,
    resume_from: u64,
    progress: &mut ProgressFn,
) -> Result<GetOutcome> {
    let host = url.host_str().unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(80);
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve {host}:{port}"))?
        .collect();
    if addrs.is_empty() {
        bail!("no addresses resolved for {host}:{port}");
    }
    let mut last_error = None;
    let mut stream = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let stream = stream.with_context(|| {
        format!(
            "cannot connect to {host}:{port}: {}",
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown".to_owned())
        )
    })?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;

    let path = {
        let p = url.path();
        let path = if p.is_empty() { "/" } else { p };
        match url.query() {
            Some(q) => format!("{path}?{q}"),
            None => path.to_owned(),
        }
    };
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n"
    );
    if resume_from > 0 {
        request.push_str(&format!("Range: bytes={resume_from}-\r\n"));
    }
    request.push_str("\r\n");
    stream
        .try_clone()
        .context("clone tcp stream")?
        .write_all(request.as_bytes())
        .context("send HTTP request")?;

    let mut reader = BufReader::new(stream);
    let (status, headers) = read_response_head(&mut reader)?;
    log::info!("[PE FETCH] GET {url} resume={resume_from} -> HTTP {status}");

    match status {
        200 => {
            if resume_from > 0 {
                // Server ignored our Range; restart cleanly to avoid a corrupt file.
                log::info!("[PE FETCH] server ignored Range; restarting from byte 0");
                std::fs::remove_file(dest).ok();
            }
            let total = content_total(&headers, 0);
            stream_body(&mut reader, dest, 0, total, &headers, progress)?;
            Ok(GetOutcome::Done)
        }
        206 => {
            let total = content_total(&headers, resume_from);
            stream_body(&mut reader, dest, resume_from, total, &headers, progress)?;
            Ok(GetOutcome::Done)
        }
        301 | 302 | 303 | 307 | 308 => {
            let location = headers
                .get("location")
                .with_context(|| format!("HTTP {status} without Location"))?;
            let next = url
                .join(location)
                .with_context(|| format!("bad redirect Location: {location}"))?;
            if next.scheme() != "http" {
                bail!(
                    "redirect leaves plain HTTP (to '{}'); refusing",
                    next.scheme()
                );
            }
            Ok(GetOutcome::Redirect(next))
        }
        416 => Ok(GetOutcome::RangeNotSatisfiable),
        _ => {
            bail!("server returned HTTP {status} for {url}");
        }
    }
}

fn read_response_head(reader: &mut BufReader<TcpStream>) -> Result<(u16, HashMap<String, String>)> {
    let mut status_line = String::new();
    let mut used = 0usize;
    loop {
        let n = reader
            .read_line(&mut status_line)
            .context("read HTTP status line")?;
        if n == 0 {
            bail!("connection closed before HTTP status line");
        }
        used += n;
        if used > MAX_HEADER_BYTES {
            bail!("HTTP response head exceeds {MAX_HEADER_BYTES} bytes");
        }
        if status_line.ends_with("\r\n") || status_line.ends_with('\n') {
            break;
        }
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("malformed HTTP status line: {status_line:?}"))?;

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).context("read HTTP header")?;
        if n == 0 {
            bail!("connection closed inside HTTP headers");
        }
        used += n;
        if used > MAX_HEADER_BYTES {
            bail!("HTTP response head exceeds {MAX_HEADER_BYTES} bytes");
        }
        let trimmed = line.trim_end_matches(|c| matches!(c, '\r' | '\n'));
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    Ok((status, headers))
}

/// Best-effort total size for progress reporting.
fn content_total(headers: &HashMap<String, String>, resume_from: u64) -> Option<u64> {
    // Prefer Content-Range: "bytes 100-999/12345".
    if let Some(range) = headers.get("content-range") {
        if let Some(total) = range.rsplit('/').next().and_then(|s| s.parse::<u64>().ok()) {
            return Some(total);
        }
    }
    // Fall back to Content-Length (+ resume offset for 206).
    headers
        .get("content-length")
        .and_then(|s| s.parse::<u64>().ok())
        .map(|len| len + resume_from)
}

fn stream_body(
    reader: &mut BufReader<TcpStream>,
    dest: &Path,
    resume_from: u64,
    total: Option<u64>,
    headers: &HashMap<String, String>,
    progress: &mut ProgressFn,
) -> Result<()> {
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create download directory {}", parent.display()))?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(resume_from == 0)
        .open(dest)
        .with_context(|| format!("open destination {}", dest.display()))?;
    if resume_from > 0 {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(resume_from))?;
    }

    let chunked = headers
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let mut downloaded = resume_from;
    progress(downloaded, total);

    let mut buf = vec![0u8; STREAM_BUF];
    if chunked {
        loop {
            let size = read_chunk_size(reader)?;
            if size == 0 {
                // Consume trailing headers after the zero chunk.
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line)?;
                    if line
                        .trim_end_matches(|c| matches!(c, '\r' | '\n'))
                        .is_empty()
                    {
                        break;
                    }
                }
                break;
            }
            copy_exact(reader, &mut file, &mut buf, size)?;
            downloaded += size;
            // RFC 9112 §7.1: chunk-data is always followed by CRLF.
            let mut crlf = [0u8; 2];
            reader
                .read_exact(&mut crlf)
                .context("read chunk-data terminator")?;
            if crlf != [b'\r', b'\n'] {
                bail!("bad chunk-data terminator: {crlf:02x?}");
            }
            progress(downloaded, total);
        }
    } else if let Some(len) = headers
        .get("content-length")
        .and_then(|s| s.parse::<u64>().ok())
    {
        copy_exact(reader, &mut file, &mut buf, len)?;
        downloaded += len;
        progress(downloaded, total);
    } else {
        // No length framing: read until the server closes the connection.
        loop {
            let n = reader.read(&mut buf).context("read response body")?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
            downloaded += n as u64;
            progress(downloaded, total);
        }
    }
    file.flush()?;
    Ok(())
}

fn read_chunk_size(reader: &mut BufReader<TcpStream>) -> Result<u64> {
    let mut line = String::new();
    reader.read_line(&mut line).context("read chunk size")?;
    let hex = line
        .trim_end_matches(|c| matches!(c, '\r' | '\n'))
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    u64::from_str_radix(hex, 16).with_context(|| format!("bad chunk size: {hex:?}"))
}

fn copy_exact(
    reader: &mut BufReader<TcpStream>,
    file: &mut std::fs::File,
    buf: &mut [u8],
    mut remaining: u64,
) -> Result<()> {
    while remaining > 0 {
        let want = (buf.len() as u64).min(remaining) as usize;
        let n = reader
            .read(&mut buf[..want])
            .context("read response body")?;
        if n == 0 {
            bail!("connection closed with {remaining} body bytes unread");
        }
        file.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

fn verify_result(spec: &FetchSpec) -> Result<()> {
    let actual_len = partial_length(&spec.dest);
    if let Some(expected) = spec.expected_length {
        if actual_len != expected {
            return Err(VerificationError(format!(
                "downloaded size mismatch: got {actual_len} bytes, expected {expected} bytes"
            ))
            .into());
        }
    }
    if let Some(expected) = spec.expected_sha256.as_deref() {
        let expected = expected.trim().to_ascii_lowercase();
        log::info!("[PE FETCH] verifying SHA-256 of {}", spec.dest.display());
        let actual = crate::hash::sha256_file(&spec.dest, |_| {})
            .map_err(|e| anyhow::anyhow!("hash downloaded file: {e}"))?;
        if !actual.eq_ignore_ascii_case(&expected) {
            return Err(VerificationError(format!(
                "SHA-256 mismatch for {}: got {actual}, expected {expected}",
                spec.dest.display()
            ))
            .into());
        }
        log::info!("[PE FETCH] SHA-256 verified");
    }
    Ok(())
}

/// Derive a safe local file name from an image URL's path.
/// Returns `None` when the URL has no usable trailing path segment; callers
/// should fall back to a fixed name like `online_image.wim`.
pub fn file_name_from_url(url: &str) -> Option<String> {
    let parsed: url::Url = url.parse().ok()?;
    let segment = parsed.path_segments()?.next_back()?;
    // Strip query-ish leftovers some servers append to the path segment.
    let name = segment.split(['?', '#']).next().unwrap_or("").trim();
    if name.is_empty() || name.len() > 128 {
        return None;
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
    {
        return None;
    }
    // Only image-ish extensions are accepted; anything else falls back.
    let lower = name.to_ascii_lowercase();
    if ["wim", "esd", "swm", "gho", "ghs", "iso"]
        .iter()
        .any(|ext| lower.ends_with(&format!(".{ext}")))
    {
        Some(name.to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny scripted HTTP server: each connection gets the next scripted response.
    /// The listener is bound before the thread spawns, so there is no startup race.
    fn scripted_server(responses: Vec<Vec<u8>>) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            for body in responses {
                let (mut stream, _) = listener.accept().unwrap();
                // Read the request head (bounded).
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = Vec::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    head.extend_from_slice(line.as_bytes());
                    if head.ends_with(b"\r\n\r\n") || head.len() > 8192 {
                        break;
                    }
                }
                // Stash the request for assertions via a sidecar file.
                std::fs::write(
                    format!("/tmp/pe_fetch_req_{port}.txt"),
                    String::from_utf8_lossy(&head).as_bytes(),
                )
                .ok();
                stream.write_all(&body).unwrap();
            }
        });
        // Give the listener a moment to start accepting.
        std::thread::sleep(Duration::from_millis(50));
        (port, handle)
    }

    fn temp_dest(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("pe_fetch_test_{name}.bin"));
        std::fs::remove_file(&path).ok();
        path
    }

    #[test]
    fn file_name_from_url_picks_image_segment() {
        assert_eq!(
            file_name_from_url("http://192.168.1.10:8080/images/win11.wim"),
            Some("win11.wim".to_owned())
        );
        assert_eq!(
            file_name_from_url("http://h/images/a.ESD?token=xyz"),
            Some("a.ESD".to_owned())
        );
        // No usable segment -> None (caller falls back).
        assert_eq!(file_name_from_url("http://h/images/"), None);
        assert_eq!(file_name_from_url("http://h/get?id=1"), None);
        assert_eq!(file_name_from_url("http://h/x.exe"), None);
        // Percent-encoded dot segments are normalized away by the URL parser,
        // so the result stays a plain file name (safe).
        assert_eq!(
            file_name_from_url("http://h/%2e%2e/x.wim"),
            Some("x.wim".to_owned())
        );
        assert_eq!(file_name_from_url("not a url"), None);
    }

    #[test]
    fn rejects_non_http_scheme() {
        let spec = FetchSpec {
            url: "https://example.com/a.wim".to_owned(),
            dest: temp_dest("scheme"),
            expected_length: None,
            expected_sha256: None,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn rejects_bad_sha256() {
        let spec = FetchSpec {
            url: "http://example.com/a.wim".to_owned(),
            dest: temp_dest("sha"),
            expected_length: None,
            expected_sha256: Some("zzz".to_owned()),
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn downloads_plain_200_with_content_length() {
        let payload = b"hello-pe-fetch".to_vec();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        )
        .into_bytes()
        .into_iter()
        .chain(payload.clone())
        .collect::<Vec<_>>();
        let (port, _h) = scripted_server(vec![response]);
        let dest = temp_dest("plain200");
        let spec = FetchSpec {
            url: format!("http://127.0.0.1:{port}/image.wim"),
            dest: dest.clone(),
            expected_length: Some(payload.len() as u64),
            expected_sha256: Some(crate::hash::sha256_bytes(&payload)),
        };
        let mut seen = Vec::new();
        fetch(&spec, &mut |d, t| seen.push((d, t))).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
        assert!(seen.iter().any(|(d, _)| *d == payload.len() as u64));
        std::fs::remove_file(&dest).ok();
    }

    #[test]
    fn resumes_with_range_when_server_supports_206() {
        let payload = b"0123456789abcdef".to_vec();
        // Pre-create a partial file with the first 6 bytes.
        let dest = temp_dest("resume206");
        std::fs::write(&dest, &payload[..6]).unwrap();
        let response = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 6-{}/16\r\nContent-Length: 10\r\nConnection: close\r\n\r\n",
            payload.len() - 1
        )
        .into_bytes()
        .into_iter()
        .chain(payload[6..].to_vec())
        .collect::<Vec<_>>();
        let (port, _h) = scripted_server(vec![response]);
        let spec = FetchSpec {
            url: format!("http://127.0.0.1:{port}/image.wim"),
            dest: dest.clone(),
            expected_length: Some(16),
            expected_sha256: Some(crate::hash::sha256_bytes(&payload)),
        };
        fetch(&spec, &mut |_, _| {}).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
        // The request must have carried a Range header.
        let req = std::fs::read_to_string(format!("/tmp/pe_fetch_req_{port}.txt")).unwrap();
        assert!(req.to_ascii_lowercase().contains("range: bytes=6-"));
        std::fs::remove_file(&dest).ok();
    }

    #[test]
    fn restarts_when_server_ignores_range() {
        let payload = b"full-content-here".to_vec();
        let dest = temp_dest("ignore_range");
        std::fs::write(&dest, b"stale-partial").unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        )
        .into_bytes()
        .into_iter()
        .chain(payload.clone())
        .collect::<Vec<_>>();
        let (port, _h) = scripted_server(vec![response]);
        let spec = FetchSpec {
            url: format!("http://127.0.0.1:{port}/image.wim"),
            dest: dest.clone(),
            expected_length: Some(payload.len() as u64),
            expected_sha256: Some(crate::hash::sha256_bytes(&payload)),
        };
        fetch(&spec, &mut |_, _| {}).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
        std::fs::remove_file(&dest).ok();
    }

    #[test]
    fn follows_redirect() {
        let payload = b"redirected-body".to_vec();
        let (port, _h) = scripted_server(vec![
            "HTTP/1.1 302 Found\r\nLocation: /real.wim\r\nConnection: close\r\n\r\n"
                .to_string()
                .into_bytes(),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            )
            .into_bytes()
            .into_iter()
            .chain(payload.clone())
            .collect::<Vec<_>>(),
        ]);
        let dest = temp_dest("redirect");
        let spec = FetchSpec {
            url: format!("http://127.0.0.1:{port}/start"),
            dest: dest.clone(),
            expected_length: None,
            expected_sha256: None,
        };
        fetch(&spec, &mut |_, _| {}).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
        std::fs::remove_file(&dest).ok();
    }

    #[test]
    fn detects_sha256_mismatch() {
        let payload = b"tampered".to_vec();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        )
        .into_bytes()
        .into_iter()
        .chain(payload)
        .collect::<Vec<_>>();
        let (port, _h) = scripted_server(vec![response]);
        let dest = temp_dest("tampersha");
        let spec = FetchSpec {
            url: format!("http://127.0.0.1:{port}/image.wim"),
            dest: dest.clone(),
            expected_length: None,
            expected_sha256: Some("0".repeat(64)),
        };
        let err = fetch(&spec, &mut |_, _| {}).unwrap_err();
        assert!(format!("{err:#}").contains("SHA-256 mismatch"));
        std::fs::remove_file(&dest).ok();
    }

    #[test]
    fn downloads_chunked_body() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n1\r\n \r\n6\r\nworld!\r\n0\r\n\r\n"
            .to_vec();
        let (port, _h) = scripted_server(vec![response]);
        let dest = temp_dest("chunked");
        let spec = FetchSpec {
            url: format!("http://127.0.0.1:{port}/c"),
            dest: dest.clone(),
            expected_length: None,
            expected_sha256: None,
        };
        fetch(&spec, &mut |_, _| {}).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello world!");
        std::fs::remove_file(&dest).ok();
    }

    #[test]
    fn reads_until_close_without_length() {
        let payload = b"no-length-framing".to_vec();
        let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
            .to_vec()
            .into_iter()
            .chain(payload.clone())
            .collect::<Vec<_>>();
        let (port, _h) = scripted_server(vec![response]);
        let dest = temp_dest("noclen");
        let spec = FetchSpec {
            url: format!("http://127.0.0.1:{port}/c"),
            dest: dest.clone(),
            expected_length: None,
            expected_sha256: None,
        };
        fetch(&spec, &mut |_, _| {}).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
        std::fs::remove_file(&dest).ok();
    }

    #[test]
    fn server_error_surfaces_status() {
        let (port, _h) = scripted_server(vec![
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        ]);
        let dest = temp_dest("err500");
        let spec = FetchSpec {
            url: format!("http://127.0.0.1:{port}/c"),
            dest: dest.clone(),
            expected_length: None,
            expected_sha256: None,
        };
        // Retries 3 times; the scripted server only answers once, later attempts fail to
        // connect — either way the result must be an error, not success.
        assert!(fetch(&spec, &mut |_, _| {}).is_err());
        std::fs::remove_file(&dest).ok();
    }
}
