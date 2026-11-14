//! A SOCKS5 proxy on `127.0.0.1` for the transport tests: the `CONNECT` command of RFC 1928 with
//! the "no authentication" method or the username/password method of RFC 1929.
//!
//! It logs every handshake — the methods offered, the credentials received, whether they were
//! accepted, and the destination asked for — so that a test can show what a SOCKS5 proxy sees and
//! whether the client resolved the name itself (`socks5`) or left it to the proxy (`socks5h`).
//! With [`SocksServer::require_credentials`] it selects the username/password method and accepts
//! only the given pair.
//!
//! It connects only to loopback addresses. Choices of its own, which the RFCs leave open or which
//! a real proxy would make differently:
//!
//! - Method selection: with credentials required it selects `0x02` when offered and answers
//!   `0xFF` (no acceptable method) otherwise; without, it selects `0x00` when offered and answers
//!   `0xFF` otherwise. Then it closes the connection.
//! - A refused username/password is answered with status `0x01`, then the connection is closed.
//! - The only name it resolves is `localhost`, to `127.0.0.1`; any other name is answered with
//!   reply `0x04` (host unreachable). An IP address that is not loopback is answered with reply
//!   `0x02` (connection not allowed by ruleset), without a connection attempt.
//! - A target that refuses the connection is answered with reply `0x05`; a command other than
//!   `CONNECT` with `0x07`; an unknown address type with `0x08`.
//! - The bound address in a successful reply is `0.0.0.0:0`.
//! - [`SocksServer::echo_credentials`] makes it answer a plain-HTTP request itself with `400`
//!   and the received credentials in the body; no real proxy is known to do that, it stands for
//!   one that tampers with the relayed traffic.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// The destination a client asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    /// An IP address and port (address types `0x01` and `0x04`): the client resolved the name.
    Ip(SocketAddr),
    /// A host name and port (address type `0x03`): the proxy is to resolve the name.
    Domain(String, u16),
}

/// One SOCKS5 handshake the proxy received.
#[derive(Clone, Debug, Default)]
pub struct SocksRequest {
    /// The authentication methods the client offered.
    pub methods: Vec<u8>,
    /// The username of the RFC 1929 request, when one was sent.
    pub username: Option<String>,
    /// The password of the RFC 1929 request, when one was sent.
    pub password: Option<String>,
    /// True when the proxy accepted the method and, if required, the credentials.
    pub authenticated: bool,
    /// The destination of the `CONNECT` request, when one was sent.
    pub destination: Option<Destination>,
}

#[derive(Default)]
struct State {
    /// The username and password the proxy accepts, when it demands them.
    expected: Mutex<Option<(String, String)>>,
    log: Mutex<Vec<SocksRequest>>,
    connections: AtomicUsize,
    /// Answer the client itself instead of relaying, echoing the credentials.
    echo: std::sync::atomic::AtomicBool,
}

/// A running SOCKS5 proxy on `127.0.0.1` with an ephemeral port. It stops accepting connections
/// when dropped.
pub struct SocksServer {
    addr: SocketAddr,
    state: Arc<State>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl fmt::Debug for SocksServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocksServer")
            .field("addr", &self.addr)
            .field("requests", &self.log().len())
            .finish_non_exhaustive()
    }
}

impl SocksServer {
    /// Binds `127.0.0.1:0` and serves on it, without authentication until told otherwise.
    ///
    /// Must be called inside a Tokio runtime; the proxy runs as tasks on it.
    ///
    /// # Panics
    ///
    /// If the loopback socket cannot be bound.
    pub async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
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

    /// `<scheme>://127.0.0.1:<port>`, the proxy URL; `scheme` is `socks5` or `socks5h`.
    pub fn url(&self, scheme: &str) -> String {
        format!("{scheme}://{}", self.addr)
    }

    /// Demands the username/password method with exactly these credentials from now on.
    pub fn require_credentials(&self, username: &str, password: &str) {
        *self.state.expected.lock().expect("socks state") =
            Some((username.to_owned(), password.to_owned()));
    }

    /// Every handshake received so far.
    pub fn log(&self) -> Vec<SocksRequest> {
        self.state.log.lock().expect("socks state").clone()
    }

    /// Number of TCP connections accepted so far.
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    /// From now on, after a successful handshake, reads the client's HTTP request head itself
    /// instead of relaying it and answers `400` with a plain-text body that echoes the username
    /// and password it received, as a careless or hostile proxy could for a plain-HTTP target.
    pub fn echo_credentials(&self) {
        self.state.echo.store(true, Ordering::SeqCst);
    }
}

impl Drop for SocksServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn read_vec(stream: &mut TcpStream, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

async fn read_u8(stream: &mut TcpStream) -> Option<u8> {
    stream.read_u8().await.ok()
}

/// A reply to the `CONNECT` request with `rep` and the bound address `0.0.0.0:0`.
async fn reply(stream: &mut TcpStream, rep: u8) {
    let _ = stream
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await;
}

async fn serve(mut stream: TcpStream, state: Arc<State>) {
    let index = {
        let mut log = state.log.lock().expect("socks state");
        log.push(SocksRequest::default());
        log.len() - 1
    };
    let upstream = handshake(&mut stream, &state, index).await;
    let Some(upstream) = upstream else {
        let _ = stream.shutdown().await;
        return;
    };
    if state.echo.load(Ordering::SeqCst) {
        drop(upstream);
        let (user, pass) = state
            .log
            .lock()
            .expect("socks state")
            .get(index)
            .map(|e| (e.username.clone(), e.password.clone()))
            .unwrap_or_default();
        let mut head = Vec::new();
        let mut chunk = [0u8; 4096];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 64 * 1024 {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => head.extend_from_slice(&chunk[..n]),
            }
        }
        let body = format!(
            "socks proxy refused user {} with password {}",
            user.unwrap_or_default(),
            pass.unwrap_or_default()
        );
        let answer = format!(
            "HTTP/1.1 400 Bad Request\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(answer.as_bytes()).await;
        let _ = stream.shutdown().await;
        return;
    }
    let (mut client_read, mut client_write) = stream.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let up = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut client_read, &mut upstream_write).await;
        let _ = upstream_write.shutdown().await;
    });
    let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
    let _ = client_write.shutdown().await;
    let _ = up.await;
}

/// The handshake up to the reply to `CONNECT`: the connection to the destination when it
/// succeeded. Everything is recorded before the answer that follows it is sent, so that a test
/// sees it as soon as the client has the answer.
async fn handshake(stream: &mut TcpStream, state: &State, index: usize) -> Option<TcpStream> {
    let record = |change: &dyn Fn(&mut SocksRequest)| {
        if let Some(entry) = state.log.lock().expect("socks state").get_mut(index) {
            change(entry);
        }
    };
    // Method negotiation (RFC 1928 section 3).
    if read_u8(stream).await? != 0x05 {
        return None;
    }
    let count = read_u8(stream).await?;
    let methods = read_vec(stream, usize::from(count)).await?;
    record(&|e| e.methods = methods.clone());
    let expected = state.expected.lock().expect("socks state").clone();
    let method = if expected.is_some() { 0x02 } else { 0x00 };
    if !methods.contains(&method) {
        let _ = stream.write_all(&[0x05, 0xFF]).await;
        return None;
    }
    stream.write_all(&[0x05, method]).await.ok()?;
    // Username/password (RFC 1929 section 2).
    if let Some((username, password)) = expected {
        if read_u8(stream).await? != 0x01 {
            return None;
        }
        let len = read_u8(stream).await?;
        let user = read_vec(stream, usize::from(len)).await?;
        let len = read_u8(stream).await?;
        let pass = read_vec(stream, usize::from(len)).await?;
        let user = String::from_utf8_lossy(&user).into_owned();
        let pass = String::from_utf8_lossy(&pass).into_owned();
        let accepted = user == username && pass == password;
        record(&|e| {
            e.username = Some(user.clone());
            e.password = Some(pass.clone());
        });
        if !accepted {
            let _ = stream.write_all(&[0x01, 0x01]).await;
            return None;
        }
        stream.write_all(&[0x01, 0x00]).await.ok()?;
    }
    record(&|e| e.authenticated = true);
    // The request (RFC 1928 sections 4 and 5).
    let head = read_vec(stream, 4).await?;
    if head[0] != 0x05 {
        return None;
    }
    let destination = match head[3] {
        0x01 => {
            let raw = read_vec(stream, 4).await?;
            let ip = Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]);
            Destination::Ip(SocketAddr::new(
                IpAddr::V4(ip),
                stream.read_u16().await.ok()?,
            ))
        }
        0x04 => {
            let raw: [u8; 16] = read_vec(stream, 16).await?.try_into().ok()?;
            let ip = Ipv6Addr::from(raw);
            Destination::Ip(SocketAddr::new(
                IpAddr::V6(ip),
                stream.read_u16().await.ok()?,
            ))
        }
        0x03 => {
            let len = read_u8(stream).await?;
            let name = read_vec(stream, usize::from(len)).await?;
            let name = String::from_utf8_lossy(&name).into_owned();
            Destination::Domain(name, stream.read_u16().await.ok()?)
        }
        _ => {
            reply(stream, 0x08).await;
            return None;
        }
    };
    record(&|e| e.destination = Some(destination.clone()));
    if head[1] != 0x01 {
        reply(stream, 0x07).await;
        return None;
    }
    let target = match destination {
        Destination::Ip(addr) if addr.ip().is_loopback() => addr,
        Destination::Ip(_) => {
            reply(stream, 0x02).await;
            return None;
        }
        Destination::Domain(name, port) if name.eq_ignore_ascii_case("localhost") => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        }
        Destination::Domain(..) => {
            reply(stream, 0x04).await;
            return None;
        }
    };
    let Ok(upstream) = TcpStream::connect(target).await else {
        reply(stream, 0x05).await;
        return None;
    };
    reply(stream, 0x00).await;
    Some(upstream)
}
