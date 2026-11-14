//! A forward proxy on `127.0.0.1` for the transport tests: HTTP `CONNECT` tunnels and plain
//! forwarding of absolute-form requests (RFC 9110 sections 9.3.6 and 7.1), with optional Basic
//! proxy authentication (RFC 9110 section 11.7, RFC 7617).
//!
//! It logs every request it receives — the method, the request target (the `CONNECT` authority or
//! the absolute URI) and all headers — and records the bytes the client sends through its tunnels,
//! so that a test can show what a proxy sees. Its behavior is set by [`ProxyServer::set_behavior`]:
//! pass requests on, refuse them with a status, stall without answering, or close the connection.
//! With [`ProxyServer::require_basic`] a request without the expected `Proxy-Authorization` is
//! answered `407`, and the body of the `407` and of every refusal echoes the `Proxy-Authorization`
//! it received, verbatim and decoded, as a careless proxy might: the secret tests use that echo.
//!
//! It connects only to loopback IP literals. A `CONNECT` or a forwarded request to any other host
//! is answered `403` without a connection attempt, so a test can never reach the network through
//! it. A forwarded request goes to the target with `Proxy-Authorization`, `Proxy-Connection` and
//! `Connection` removed and `connection: close` added; the answer is relayed and the client
//! connection closed after it.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Largest request head the proxy reads.
const MAX_HEAD: usize = 64 * 1024;

/// Most tunnel bytes kept for [`ProxyServer::tunneled`].
const MAX_TUNNELED: usize = 1024 * 1024;

/// What the proxy does with a request that passed the credential check.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Behavior {
    /// Opens the tunnel or forwards the request.
    #[default]
    Pass,
    /// Answers with this status and an echo of the `Proxy-Authorization` it received.
    Refuse(u16),
    /// Reads the request and never answers; the connection stays open.
    Stall,
    /// Reads the request and closes the connection without an answer.
    Close,
}

/// One request the proxy received.
#[derive(Clone, Debug)]
pub struct ProxyRequest {
    /// The method: `CONNECT`, or the method of a forwarded request.
    pub method: String,
    /// The request target: `host:port` for `CONNECT`, the absolute URI otherwise.
    pub target: String,
    /// Every header, names in lowercase, in the order received.
    pub headers: Vec<(String, String)>,
}

impl ProxyRequest {
    /// The first value of header `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct State {
    behavior: Mutex<Behavior>,
    /// The `Proxy-Authorization` value the proxy accepts, when it demands one.
    expected: Mutex<Option<String>>,
    log: Mutex<Vec<ProxyRequest>>,
    tunneled: Mutex<Vec<u8>>,
    connections: AtomicUsize,
}

/// A running proxy on `127.0.0.1` with an ephemeral port. It stops accepting connections when
/// dropped.
pub struct ProxyServer {
    addr: SocketAddr,
    state: Arc<State>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl fmt::Debug for ProxyServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyServer")
            .field("addr", &self.addr)
            .field("requests", &self.log().len())
            .finish_non_exhaustive()
    }
}

impl ProxyServer {
    /// Binds `127.0.0.1:0` and serves on it. It passes every request on and demands no
    /// credentials until told otherwise.
    ///
    /// Must be called inside a Tokio runtime; the proxy runs as tasks on it.
    ///
    /// # Panics
    ///
    /// If the loopback socket cannot be bound.
    pub async fn start() -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind 127.0.0.1:0");
        let addr = listener
            .local_addr()
            .expect("local address of the listener");
        let state = Arc::new(State::default());
        let (tx, mut rx) = oneshot::channel::<()>();
        let accepting = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => return,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { continue };
                        accepting.connections.fetch_add(1, Ordering::SeqCst);
                        tokio::spawn(serve(stream, accepting.clone()));
                    }
                }
            }
        });
        Self {
            addr,
            state,
            shutdown: Some(tx),
        }
    }

    /// The socket address the proxy listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>`, the proxy URL.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Demands `Proxy-Authorization: Basic <base64(user:password)>` from now on.
    pub fn require_basic(&self, user: &str, password: &str) {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        *self.state.expected.lock().expect("proxy state") = Some(format!("Basic {token}"));
    }

    /// Sets what the proxy does with requests that pass the credential check.
    pub fn set_behavior(&self, behavior: Behavior) {
        *self.state.behavior.lock().expect("proxy state") = behavior;
    }

    /// Every request received so far.
    pub fn log(&self) -> Vec<ProxyRequest> {
        self.state.log.lock().expect("proxy state").clone()
    }

    /// The bytes clients sent through tunnels after the `CONNECT` exchange, at most 1 MiB.
    pub fn tunneled(&self) -> Vec<u8> {
        self.state.tunneled.lock().expect("proxy state").clone()
    }

    /// Number of TCP connections accepted so far.
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// A parsed request head and the bytes read after it.
struct Head {
    request: ProxyRequest,
    rest: Vec<u8>,
}

async fn read_head(stream: &mut TcpStream) -> Option<Head> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let rest = buf[end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let target = first.next()?.to_owned();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Some(Head {
        request: ProxyRequest {
            method,
            target,
            headers,
        },
        rest,
    })
}

/// `host:port` as a loopback socket address, or `None` for anything else.
fn loopback(authority: &str) -> Option<SocketAddr> {
    let (host, port) = authority.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = host.parse().ok()?;
    if !ip.is_loopback() {
        return None;
    }
    Some(SocketAddr::new(ip, port.parse().ok()?))
}

/// The echo of the credentials the proxy received, verbatim and decoded.
fn echo(received: Option<&str>) -> String {
    let Some(value) = received else {
        return "no Proxy-Authorization header was sent".to_owned();
    };
    let decoded = value
        .strip_prefix("Basic ")
        .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
        .map(|d| String::from_utf8_lossy(&d).into_owned())
        .unwrap_or_default();
    format!("proxy refused Proxy-Authorization: {value} (user:password {decoded})")
}

async fn answer(stream: &mut TcpStream, status: u16, extra: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status} Proxy Answer\r\n{extra}content-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn serve(mut stream: TcpStream, state: Arc<State>) {
    let Some(Head { request, rest }) = read_head(&mut stream).await else {
        return;
    };
    state.log.lock().expect("proxy state").push(request.clone());
    let behavior = *state.behavior.lock().expect("proxy state");
    let expected = state.expected.lock().expect("proxy state").clone();
    let received = request.header("proxy-authorization");
    if let Some(expected) = expected
        && received != Some(expected.as_str())
    {
        let body = echo(received);
        answer(
            &mut stream,
            407,
            "proxy-authenticate: Basic realm=\"mock\"\r\n",
            &body,
        )
        .await;
        return;
    }
    match behavior {
        Behavior::Pass => {}
        Behavior::Refuse(status) => {
            answer(&mut stream, status, "", &echo(received)).await;
            return;
        }
        Behavior::Stall => {
            // Hold the connection open without answering until the client gives up.
            let mut sink = [0u8; 1024];
            while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
            return;
        }
        Behavior::Close => return,
    }
    if request.method == "CONNECT" {
        tunnel(stream, &request, rest, &state).await;
    } else {
        forward(stream, &request, rest).await;
    }
}

async fn tunnel(mut stream: TcpStream, request: &ProxyRequest, rest: Vec<u8>, state: &Arc<State>) {
    let Some(target) = loopback(&request.target) else {
        answer(
            &mut stream,
            403,
            "",
            "the mock proxy connects to loopback only",
        )
        .await;
        return;
    };
    let Ok(upstream) = TcpStream::connect(target).await else {
        answer(&mut stream, 502, "", "the target refused the connection").await;
        return;
    };
    if stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    let (mut client_read, mut client_write) = stream.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let recorder = state.clone();
    let up = tokio::spawn(async move {
        let record = |bytes: &[u8]| {
            let mut kept = recorder.tunneled.lock().expect("proxy state");
            let room = MAX_TUNNELED.saturating_sub(kept.len());
            kept.extend_from_slice(&bytes[..bytes.len().min(room)]);
        };
        if !rest.is_empty() {
            record(&rest);
            if upstream_write.write_all(&rest).await.is_err() {
                return;
            }
        }
        let mut buf = [0u8; 16 * 1024];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    record(&buf[..n]);
                    if upstream_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = upstream_write.shutdown().await;
    });
    let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
    let _ = client_write.shutdown().await;
    let _ = up.await;
}

async fn forward(mut stream: TcpStream, request: &ProxyRequest, mut body: Vec<u8>) {
    let Some(rest) = request.target.strip_prefix("http://") else {
        answer(
            &mut stream,
            400,
            "",
            "the mock proxy forwards http:// URIs only",
        )
        .await;
        return;
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let Some(target) = loopback(authority) else {
        answer(
            &mut stream,
            403,
            "",
            "the mock proxy connects to loopback only",
        )
        .await;
        return;
    };
    let length = request
        .header("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut chunk = [0u8; 16 * 1024];
    while body.len() < length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(length);
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        answer(&mut stream, 502, "", "the target refused the connection").await;
        return;
    };
    let mut head = format!("{} {path} HTTP/1.1\r\n", request.method);
    for (name, value) in &request.headers {
        if matches!(
            name.as_str(),
            "proxy-authorization" | "proxy-connection" | "connection"
        ) {
            continue;
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("connection: close\r\n\r\n");
    if upstream.write_all(head.as_bytes()).await.is_err()
        || upstream.write_all(&body).await.is_err()
    {
        return;
    }
    let _ = tokio::io::copy(&mut upstream, &mut stream).await;
    let _ = stream.shutdown().await;
}
