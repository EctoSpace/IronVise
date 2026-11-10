//! `ironvise health`: exit 0 when the local Observer answers `GET /api/status`.
//!
//! The container image has no shell and no curl. Docker's health check runs
//! this command directly.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Probe `127.0.0.1:$ECTO_BIND_PORT` (default 3000). Returns 0 when the status
/// line is HTTP 200, and 1 otherwise.
pub fn run() -> u8 {
    let port = std::env::var("ECTO_BIND_PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("127.0.0.1:{port}");
    match probe(&addr) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("health: {e}");
            1
        }
    }
}

fn probe(addr: &str) -> Result<(), String> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|e| format!("bad address {addr}: {e}"))?;
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(2))
        .map_err(|e| format!("cannot connect to {addr}: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let request = format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write to {addr}: {e}"))?;
    let mut buf = [0u8; 256];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("read from {addr}: {e}"))?;
    let head = String::from_utf8_lossy(&buf[..n]);
    let line = head.lines().next().unwrap_or("").trim();
    if http_ok(line) {
        Ok(())
    } else {
        Err(format!("{addr} answered {line:?}"))
    }
}

fn http_ok(status_line: &str) -> bool {
    status_line.split_whitespace().nth(1) == Some("200")
}

#[cfg(test)]
mod tests {
    use super::{http_ok, probe};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn status_line_200_is_healthy() {
        assert!(http_ok("HTTP/1.1 200 OK"));
        assert!(!http_ok("HTTP/1.1 503 Service Unavailable"));
        assert!(!http_ok(""));
    }

    #[test]
    fn probe_accepts_a_local_200() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 128];
            let _ = sock.read(&mut buf);
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        assert!(probe(&addr.to_string()).is_ok());
    }
}
