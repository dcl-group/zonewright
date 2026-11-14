//! Test support for the transport: certificates generated at test time, loopback servers,
//! contexts and handles, and the shared secret-test support.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::context::{Context, ContextOptions};
use crate::id::ProviderId;

use super::{Http, HttpBuilder};

// The secret-test support of the integration tests, shared so that both use one definition of
// the canaries, their spellings and the log capture.
#[path = "../../tests/common/echo.rs"]
#[allow(dead_code)] // Shared with the integration tests; the transport's tests use part of it.
pub(crate) mod echo;

/// Validity around now: from a day ago for a week, inside the limits platform verifiers put on
/// server certificates.
fn validity(params: &mut CertificateParams) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let epoch = rcgen::date_time_ymd(1970, 1, 1);
    let day = Duration::from_secs(86_400);
    params.not_before = epoch + (now - day);
    params.not_after = epoch + (now + 7 * day);
}

/// A root CA and the issuer that signs with it.
pub(crate) fn ca() -> (rcgen::Certificate, Issuer<'static, KeyPair>) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "zonewright test root");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    validity(&mut params);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert, Issuer::new(params, key))
}

/// A server certificate for `127.0.0.1` signed by `issuer`, with its key.
pub(crate) fn server_cert(
    issuer: &Issuer<'static, KeyPair>,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    validity(&mut params);
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap();
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

/// A self-signed TLS client certificate: DER, key, and both as PEM.
pub(crate) fn client_cert() -> (
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    String,
    String,
) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "zonewright test client");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    validity(&mut params);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        format!("Subject: test client\n{}", cert.pem()),
        key.serialize_pem(),
    )
}

/// A minimal HTTPS server on `127.0.0.1` built from `rustls` alone, on its own threads: it
/// completes the handshake, reads one request head, answers `200` with a small JSON body and
/// closes. It offers ALPN `h2` and `http/1.1` and records what was negotiated.
pub(crate) struct TlsServer {
    pub(crate) addr: SocketAddr,
    pub(crate) connections: Arc<AtomicUsize>,
    pub(crate) answered: Arc<AtomicUsize>,
    pub(crate) alpn: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl TlsServer {
    pub(crate) fn start(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Self {
        TlsServer::start_on("127.0.0.1:0", chain, key)
    }

    /// [`TlsServer::start`] on the address `bind`.
    pub(crate) fn start_on(
        bind: &str,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let listener = TcpListener::bind(bind).unwrap();
        let server = TlsServer {
            addr: listener.local_addr().unwrap(),
            connections: Arc::default(),
            answered: Arc::default(),
            alpn: Arc::default(),
        };
        let (connections, answered, alpn) = (
            server.connections.clone(),
            server.answered.clone(),
            server.alpn.clone(),
        );
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                connections.fetch_add(1, Ordering::SeqCst);
                let (config, answered, alpn) = (config.clone(), answered.clone(), alpn.clone());
                std::thread::spawn(move || serve_tls(stream, config, &answered, &alpn));
            }
        });
        server
    }

    pub(crate) fn url(&self) -> String {
        match self.addr {
            SocketAddr::V4(addr) => format!("https://{addr}/tls"),
            SocketAddr::V6(addr) => format!("https://[{}]:{}/tls", addr.ip(), addr.port()),
        }
    }
}

fn serve_tls(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    answered: &AtomicUsize,
    alpn: &Mutex<Vec<Vec<u8>>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(conn) = ServerConnection::new(config) else {
        return;
    };
    let mut tls = StreamOwned::new(conn, stream);
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match tls.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    if let Some(protocol) = tls.conn.alpn_protocol() {
        alpn.lock().unwrap().push(protocol.to_vec());
    }
    let body = b"{\"ok\":true}";
    let answer = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    if tls.write_all(answer.as_bytes()).is_ok() && tls.write_all(body).is_ok() {
        answered.fetch_add(1, Ordering::SeqCst);
    }
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// A TCP listener on `127.0.0.1` that accepts connections and never says anything, so a TLS
/// handshake with it never completes. Counts connections.
pub(crate) struct SilentServer {
    pub(crate) addr: SocketAddr,
    pub(crate) connections: Arc<AtomicUsize>,
}

impl SilentServer {
    pub(crate) fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let count = connections.clone();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                count.fetch_add(1, Ordering::SeqCst);
                held.push(stream);
            }
        });
        SilentServer { addr, connections }
    }
}

/// Test options: loopback only, short timeouts unless a test sets its own.
pub(crate) fn options() -> ContextOptions {
    ContextOptions {
        loopback_only: true,
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
        ..ContextOptions::default()
    }
}

/// A context from `options`.
pub(crate) fn context(options: ContextOptions) -> Context {
    Context::new(options).unwrap()
}

/// A handle for a test client of the `cloudflare` ID on `ctx`, configured by `configure`.
pub(crate) fn http(ctx: &Context, configure: impl FnOnce(HttpBuilder) -> HttpBuilder) -> Http {
    configure(Http::builder(ctx, ProviderId::Cloudflare))
        .build()
        .unwrap()
}
