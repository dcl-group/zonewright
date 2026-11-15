//! Stateful mock provider APIs for the `zonewright` test suite.
//!
//! This crate is test tooling. It is published so that the tests of `zonewright` can be built from
//! its package, and so that an application can test its own use of `zonewright` without live
//! accounts. Its API follows the needs of those tests and changes more freely than that of
//! `zonewright`; it is released with the same version number.
//!
//! It holds one stateful mock per provider API (one module per provider ID), the echo server used
//! by the secret tests ([`echo`]), and the harness they share:
//!
//! - [`MockServer`]: serves an [`axum::Router`] over plain HTTP/1.1 on `127.0.0.1` with an
//!   ephemeral port, and shuts it down when dropped. Nothing is global; any number of servers run
//!   side by side in one test binary.
//! - [`RequestLog`]: every request the server received — method, path, query, all headers, body —
//!   and the status it was answered with.
//! - [`Faults`]: a queue of injected behaviors ([`Fault`]) consulted before the router sees a
//!   request: answer with a status, `429` with `Retry-After`, a redirect, an oversized body, a
//!   delay, a dropped connection, a truncated body, slow headers, or a hook that changes the
//!   mock's state between two requests.
//! - [`proxy::ProxyServer`]: a forward proxy (`CONNECT` tunnels and plain forwarding) with optional
//!   Basic proxy authentication, for the tests of the transport's proxy setting.
//! - [`socks::SocksServer`]: a SOCKS5 proxy (RFC 1928 `CONNECT`) with optional username/password
//!   authentication (RFC 1929), for the same tests.
//!
//! # Writing a provider mock
//!
//! A provider mock lives in its own module, `src/<id>.rs`, and needs nothing from any shared file.
//! It keeps its state behind an `Arc<Mutex<_>>`, builds an `axum` router over that state, and
//! starts it with [`MockServer::start`]. Request logging and fault injection come with the server.
//! Error texts in a mock are invented; request and response shapes follow the provider's public
//! documentation, with a reference in the module.
//!
//! ```
//! use std::sync::{Arc, Mutex};
//!
//! use axum::extract::{Path, State};
//! use axum::routing::get;
//! use axum::{Json, Router};
//! use zonewright_mock::{Fault, MockServer};
//!
//! /// The mock's state; tests read and change it through the handle.
//! #[derive(Default)]
//! struct Zones {
//!     names: Vec<String>,
//! }
//!
//! /// The handle a test holds.
//! struct ExampleMock {
//!     server: MockServer,
//!     state: Arc<Mutex<Zones>>,
//! }
//!
//! impl ExampleMock {
//!     async fn start(seed: Zones) -> Self {
//!         let state = Arc::new(Mutex::new(seed));
//!         let router = Router::new()
//!             .route("/v1/zones/{name}", get(get_zone))
//!             .with_state(state.clone());
//!         Self { server: MockServer::start(router).await, state }
//!     }
//! }
//!
//! async fn get_zone(
//!     State(state): State<Arc<Mutex<Zones>>>,
//!     Path(name): Path<String>,
//! ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
//!     let zones = state.lock().unwrap();
//!     if zones.names.contains(&name) {
//!         Ok(Json(serde_json::json!({ "name": name })))
//!     } else {
//!         Err(axum::http::StatusCode::NOT_FOUND)
//!     }
//! }
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! let mock = ExampleMock::start(Zones { names: vec!["example.test".into()] }).await;
//! // The client under test is pointed at `mock.server.base_url()`.
//! assert!(mock.server.base_url().starts_with("http://127.0.0.1:"));
//!
//! // Answer the next two zone reads with 503, then let requests through again.
//! mock.server
//!     .faults()
//!     .push(Fault::on("GET", "/v1/zones/*").times(2).status(503));
//!
//! // ... drive the client, then assert on what the mock received and holds:
//! assert_eq!(mock.server.log().count(Some("GET"), "/v1/zones/*"), 0);
//! assert_eq!(mock.state.lock().unwrap().names.len(), 1);
//! # }
//! ```

mod conn;
pub mod echo;
mod fault;
mod log;

pub mod dns;
pub mod proxy;
pub mod socks;

pub mod acme_dns;
pub mod beget;
pub mod cloud_ru;
pub mod cloudflare;
pub mod digitalocean;
pub mod hetzner;
pub mod nicru;
pub mod regru;
pub mod rfc2136;
pub mod route53;
pub mod selectel_v2;
pub mod timeweb_cloud;
pub mod vk_cloud;
pub mod yandex_360;
pub mod yandex_cloud;

pub use axum;
pub use fault::{Fault, Faults};
pub use log::{LoggedRequest, RequestLog};

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;

use conn::{Conn, MockListener};
use fault::{Action, Plan};

/// Largest request body the harness reads. Anything a client sends is far below it.
const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

/// A running mock HTTP server on `127.0.0.1` with an ephemeral port.
///
/// The server stops accepting connections when this value is dropped; open connections are closed
/// once their current request finishes.
pub struct MockServer {
    addr: SocketAddr,
    log: RequestLog,
    faults: Faults,
    connections: Arc<AtomicUsize>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl fmt::Debug for MockServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockServer")
            .field("addr", &self.addr)
            .field("requests", &self.log.len())
            .field("pending_faults", &self.faults.pending())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct Shared {
    log: RequestLog,
    faults: Faults,
}

impl MockServer {
    /// Binds `127.0.0.1:0` and serves `router` on it, with request logging and fault injection
    /// in front of every route and of the fallback.
    ///
    /// Must be called inside a Tokio runtime; the server runs as a task on it.
    ///
    /// # Panics
    ///
    /// If the loopback socket cannot be bound.
    pub async fn start(router: Router) -> Self {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind 127.0.0.1:0");
        let addr = listener
            .local_addr()
            .expect("local address of the listener");
        let log = RequestLog::default();
        let faults = Faults::default();
        let connections = Arc::new(AtomicUsize::new(0));
        let shared = Shared {
            log: log.clone(),
            faults: faults.clone(),
        };
        let app = router
            .layer(middleware::from_fn_with_state(shared, harness))
            .into_make_service_with_connect_info::<Conn>();
        let (tx, rx) = oneshot::channel::<()>();
        let listener = MockListener::new(listener, connections.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
        Self {
            addr,
            log,
            faults,
            connections,
            shutdown: Some(tx),
        }
    }

    /// The socket address the server listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>`, without a trailing slash.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// [`base_url`](Self::base_url) followed by `path`, which should start with `/`.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// The log of requests received.
    pub fn log(&self) -> &RequestLog {
        &self.log
    }

    /// The fault queue.
    pub fn faults(&self) -> &Faults {
        &self.faults
    }

    /// Number of TCP connections accepted so far, whether or not a request arrived on them. A
    /// test that must prove an address was never contacted asserts that this is zero.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// The middleware in front of every mock: logs the request, then applies the fault that takes it,
/// if any.
async fn harness(State(shared): State<Shared>, request: Request, next: Next) -> Response {
    let conn = request
        .extensions()
        .get::<ConnectInfo<Conn>>()
        .map(|c| c.0.clone());
    let (parts, body) = request.into_parts();
    let body = match axum::body::to_bytes(body, MAX_REQUEST_BODY).await {
        Ok(body) => body,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let mut entry = LoggedRequest::new(
        parts.method.clone(),
        parts.uri.path().to_owned(),
        parts.uri.query().map(str::to_owned),
        parts.headers.clone(),
        body.clone(),
    );
    let plan = shared.faults.take(&entry);
    entry.faulted = plan.is_some();
    let uid = shared.log.push(entry);

    let Some(Plan {
        delay,
        hook,
        headers,
        action,
    }) = plan
    else {
        let response = next.run(Request::from_parts(parts, Body::from(body))).await;
        shared.log.set_status(uid, response.status().as_u16());
        return response;
    };

    if let Some(delay) = delay {
        tokio::time::sleep(delay).await;
    }
    if let Some(hook) = hook {
        hook();
    }
    let mut response = match action {
        Action::PassThrough => next.run(Request::from_parts(parts, Body::from(body))).await,
        Action::Respond { status, body } => (status, body).into_response(),
        Action::Raw(chunks) => return write_raw(conn, chunks).await,
    };
    for (name, value) in headers {
        response.headers_mut().append(name, value);
    }
    shared.log.set_status(uid, response.status().as_u16());
    response
}

/// Takes the connection from the HTTP server, writes `chunks` and closes it. The returned response
/// is never sent: the server finds the connection gone when it tries.
async fn write_raw(conn: Option<Conn>, chunks: Vec<(std::time::Duration, Bytes)>) -> Response {
    let Some(mut stream) = conn.and_then(|c| c.take()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    // A separate task, so the script runs to the end even if the server drops this future.
    let script = tokio::spawn(async move {
        for (pause, bytes) in chunks {
            if !pause.is_zero() {
                tokio::time::sleep(pause).await;
            }
            if stream.write_all(&bytes).await.is_err() {
                return;
            }
            let _ = stream.flush().await;
        }
        let _ = stream.shutdown().await;
    });
    let _ = script.await;
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}
