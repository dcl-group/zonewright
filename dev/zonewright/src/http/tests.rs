//! Tests of the transport against loopback servers: TLS and client construction, the URL policy
//! at send time, redirects, proxies, timeouts, the size cap, retries, rate limits, cached tokens,
//! pacing, the Keystone exchange, and secrets in errors and in `tracing`.
//!
//! The transport is private to the crate, so these are unit tests rather than integration tests.
//! Tests that talk to a socket run on the real clock: with a paused clock, `tokio` advances time
//! whenever the runtime waits, including while it waits for a loopback socket, which could fire
//! a request timeout before the answer is read. Tests without sockets (token cache, gate,
//! poller, pager) use a paused clock in their own modules.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use reqwest::header::HeaderName;
use reqwest::{Method, Url};
use secrecy::SecretString;
use serde::Deserialize;
use zonewright_mock::axum::Router;
use zonewright_mock::axum::extract::State;
use zonewright_mock::axum::http::StatusCode;
use zonewright_mock::axum::response::IntoResponse;
use zonewright_mock::axum::routing;
use zonewright_mock::echo::{Echo, Spelling};
use zonewright_mock::{Fault, MockServer};

use crate::context::ContextOptions;
use crate::error::{Error, ErrorKind};

use super::keystone::{Keystone, ProjectScope, X_AUTH_TOKEN};
use super::request::{BODY_LIMIT, Request, TokenAuth};
use super::testing::echo::{
    CANARIES, CANARY_KEY, CANARY_PASSWORD, CANARY_TOKEN, CANARY_USER, Dialect, LogCapture,
    REDACTED, WITHHELD, assert_clean, dialects,
};
use super::testing::{self, SilentServer, TlsServer};
use super::tls::{self, Trust};
use super::token::{Token, TokenSource};
use super::url::Endpoint;
use super::{Http, HttpBuilder, Transport, encode};

// --- helpers ---

/// A server that answers every request `200` with a small JSON body.
async fn ok_server() -> MockServer {
    let router = Router::new().fallback(|| async {
        (
            StatusCode::OK,
            [("content-type", "application/json")],
            "{\"ok\":true}",
        )
    });
    MockServer::start(router).await
}

fn url(raw: &str) -> Url {
    Url::parse(raw).unwrap()
}

fn get(server: &MockServer, path: &str) -> Request {
    Request::get(url(&server.url(path)))
}

fn post(server: &MockServer, path: &str) -> Request {
    Request::new(Method::POST, url(&server.url(path)))
}

fn default_http() -> Http {
    testing::http(&testing::context(testing::options()), |b| b)
}

/// The endpoint of a mock server, as a client would parse it from its settings.
fn endpoint_of(server: &MockServer) -> Endpoint {
    Endpoint::parse_with("base_url", &server.base_url(), true).unwrap()
}

/// A handle whose declared endpoint is `server`, configured further by `configure`.
fn http_on(server: &MockServer, configure: impl FnOnce(HttpBuilder) -> HttpBuilder) -> Http {
    let ctx = testing::context(testing::options());
    testing::http(&ctx, |b| configure(b.endpoint(&endpoint_of(server))))
}

fn kind<T: std::fmt::Debug>(result: Result<T, Error>) -> ErrorKind {
    result.unwrap_err().kind()
}

/// A token endpoint and an API behind it: `POST /token` issues `tok-<n>`, everything else is
/// answered `200`. Faults decide what the API does.
async fn token_server() -> (MockServer, Arc<AtomicUsize>) {
    let issued = Arc::new(AtomicUsize::new(0));
    let router = Router::new()
        .route(
            "/token",
            routing::post(|State(issued): State<Arc<AtomicUsize>>| async move {
                let n = issued.fetch_add(1, Ordering::SeqCst) + 1;
                let body =
                    serde_json::json!({ "access_token": format!("tok-{n}"), "expires_in": 3600 });
                (StatusCode::OK, zonewright_mock::axum::Json(body)).into_response()
            }),
        )
        .fallback(|| async { (StatusCode::OK, "{}") })
        .with_state(issued.clone());
    (MockServer::start(router).await, issued)
}

#[derive(Deserialize)]
struct TokenAnswer {
    access_token: String,
    expires_in: Option<u64>,
}

/// A password-grant exchange against `token_url`, the way an OAuth client does it.
async fn fetch_token(http: &Http, token_url: &str) -> Result<Token, Error> {
    let request = Request::new(Method::POST, url(token_url))
        .idempotent()
        .anonymous()
        .form(&[
            ("grant_type", "password"),
            ("username", CANARY_USER),
            ("password", CANARY_PASSWORD),
        ]);
    let response = http.send(&request).await?;
    if !response.is_success() {
        return Err(http.reject(&response));
    }
    let answer: TokenAnswer = response.json("the token answer is not in the expected form")?;
    Ok(Token::new(
        SecretString::from(answer.access_token),
        answer.expires_in.map(Duration::from_secs),
    ))
}

// --- TLS and client construction ---

#[tokio::test]
async fn no_process_wide_crypto_provider_is_installed_or_needed() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    let (ca, issuer) = testing::ca();
    let (leaf, key) = testing::server_cert(&issuer);
    let server = TlsServer::start(vec![leaf], key);
    let ctx = testing::context(ContextOptions {
        extra_root_certificates: vec![ca.der().to_vec()],
        ..testing::options()
    });
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    let http = testing::http(&ctx, |b| b);
    let response = http.send(&Request::get(url(&server.url()))).await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
}

#[tokio::test]
async fn https_succeeds_with_the_extra_root_and_negotiates_http1() {
    let (ca, issuer) = testing::ca();
    let (leaf, key) = testing::server_cert(&issuer);
    let server = TlsServer::start(vec![leaf], key);
    let ctx = testing::context(ContextOptions {
        extra_root_certificates: vec![ca.der().to_vec()],
        ..testing::options()
    });
    let http = testing::http(&ctx, |b| b);
    let response = http.send(&Request::get(url(&server.url()))).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"{\"ok\":true}");
    assert_eq!(server.answered.load(Ordering::SeqCst), 1);
    // The server offered h2 first; the client's ALPN list has only http/1.1.
    assert_eq!(*server.alpn.lock().unwrap(), vec![b"http/1.1".to_vec()]);
}

#[tokio::test]
async fn https_fails_without_the_extra_root() {
    let (_ca, issuer) = testing::ca();
    let (leaf, key) = testing::server_cert(&issuer);
    let server = TlsServer::start(vec![leaf], key);
    let http = default_http();
    // Idempotent, yet a refused certificate is not retried: the next attempt would be refused
    // the same way.
    let started = Instant::now();
    let e = http
        .send(&Request::get(url(&server.url())))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e}");
    assert!(!e.is_retryable());
    assert!(e.to_string().contains("certificate"), "{e}");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(server.answered.load(Ordering::SeqCst), 0);
    assert!(started.elapsed() < Duration::from_millis(400));
}

#[tokio::test]
async fn a_server_certificate_for_another_name_is_refused_without_retry() {
    let (ca, issuer) = testing::ca();
    // A certificate for 127.0.0.1, reached as [::1]: the name does not match.
    let (leaf, key) = testing::server_cert(&issuer);
    let server = TlsServer::start_on("[::1]:0", vec![leaf], key);
    let ctx = testing::context(ContextOptions {
        extra_root_certificates: vec![ca.der().to_vec()],
        ..testing::options()
    });
    let http = testing::http(&ctx, |b| b);
    let e = http
        .send(&Request::get(url(&server.url())))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e}");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn no_ca_certificates_refuse_https_before_connecting_and_keep_http() {
    let provider = tls::crypto_provider();
    let transport = Transport::with_trust(
        &testing::options(),
        provider.clone(),
        Trust::reject_all(&provider),
    )
    .unwrap();
    let http = HttpBuilder::new(transport, crate::id::ProviderId::Cloudflare)
        .build()
        .unwrap();
    let silent = SilentServer::start();
    let e = http
        .send(&Request::get(url(&format!("https://{}/x", silent.addr))))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
    assert!(!e.is_retryable());
    assert!(e.to_string().contains("no CA certificates"), "{e}");
    assert_eq!(silent.connections.load(Ordering::SeqCst), 0);
    // Plain-HTTP loopback endpoints keep working.
    let server = ok_server().await;
    assert_eq!(http.send(&get(&server, "/x")).await.unwrap().status(), 200);
}

#[tokio::test]
async fn user_agent_accept_and_content_type_are_sent() {
    let server = ok_server().await;
    let ctx = testing::context(ContextOptions {
        user_agent_suffix: Some("app/1.0 (+https://example.org)".to_owned()),
        ..testing::options()
    });
    let http = testing::http(&ctx, |b| b);
    let request = post(&server, "/x")
        .accept(encode::XML)
        .json(&serde_json::json!({ "a": 1 }))
        .unwrap();
    http.send(&request).await.unwrap();
    let logged = server.log().last().unwrap();
    assert_eq!(
        logged.header("user-agent"),
        Some(concat!(
            "zonewright/",
            env!("CARGO_PKG_VERSION"),
            " app/1.0 (+https://example.org)"
        ))
    );
    assert_eq!(logged.header("accept"), Some("application/xml"));
    assert_eq!(logged.header("content-type"), Some("application/json"));
    assert_eq!(logged.body_str(), "{\"a\":1}");
    assert!(logged.header("cookie").is_none());
    assert!(logged.header("authorization").is_none());
}

// --- URL policy, redirects, proxies ---

#[tokio::test]
async fn redirects_are_not_followed_with_or_without_a_client_certificate() {
    let (_, _, cert_pem, key_pem) = testing::client_cert();
    for with_cert in [false, true] {
        for status in [301, 302, 303, 307, 308] {
            let target = ok_server().await;
            let server = ok_server().await;
            let http = http_on(&server, |b| {
                let b = b.bearer("api_token", CANARY_TOKEN);
                if with_cert {
                    b.client_identity(&cert_pem, &key_pem)
                } else {
                    b
                }
            });
            server.faults().push(
                Fault::any()
                    .always()
                    .redirect(status, &target.url("/stolen")),
            );
            for request in [
                get(&server, "/x"),
                post(&server, "/x").form(&[("p", CANARY_PASSWORD)]),
            ] {
                let e = http.send(&request).await.unwrap_err();
                let Error::Rejected { status: got, .. } = &e else {
                    panic!("{e:?}");
                };
                assert_eq!(*got, Some(status));
            }
            // One request each, no retry, and the target was never contacted.
            assert_eq!(server.log().len(), 2);
            assert_eq!(target.connections(), 0);
            assert!(target.log().is_empty());
        }
    }
}

/// Set in the environment of the child process of [`proxy_variables_are_ignored`].
const PROXY_CHILD: &str = "ZONEWRIGHT_TEST_PROXY_CHILD";

#[test]
fn proxy_variables_are_ignored() {
    if std::env::var_os(PROXY_CHILD).is_some() {
        return;
    }
    // The variables must be set before `reqwest` reads them, and changing the environment of
    // this multi-threaded process is not sound, so the check runs in a child process.
    let proxy = SilentServer::start();
    let proxy_url = format!("http://{}", proxy.addr);
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "http::tests::proxy_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROXY_CHILD, "1")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env(name, &proxy_url);
    }
    let out = command.output().unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("1 passed"), "the child ran the test: {text}");
    // The control client of the child went to the proxy; the transport did not.
    assert_eq!(proxy.connections.load(Ordering::SeqCst), 1, "{text}");
}

#[tokio::test]
async fn proxy_child() {
    if std::env::var_os(PROXY_CHILD).is_none() {
        return;
    }
    let server = ok_server().await;
    let http = default_http();
    assert_eq!(
        http.send(&get(&server, "/direct")).await.unwrap().status(),
        200
    );
    assert_eq!(server.log().len(), 1);
    // Control: a client built the same way but without `no_proxy` uses the proxy from the
    // environment, so the variables are in effect and the check above is not vacuous.
    let provider = tls::crypto_provider();
    let trust = Trust::platform(Vec::new(), &provider).unwrap();
    let control = reqwest::Client::builder()
        .tls_backend_preconfigured(tls::client_config(&provider, &trust, None).unwrap())
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    let _ = control.get(server.url("/via-proxy")).send().await;
    assert_eq!(server.log().len(), 1);
}

#[tokio::test]
async fn loopback_only_refuses_before_any_connection() {
    let server = ok_server().await;
    let silent = SilentServer::start();
    let http = default_http();
    let port = server.addr().port();
    for raw in [
        format!("http://localhost:{port}/x"),
        "https://192.0.2.1/x".to_owned(),
        "https://example.invalid/x".to_owned(),
        format!("https://localhost:{}/x", silent.addr.port()),
    ] {
        let started = Instant::now();
        let e = http.send(&Request::get(url(&raw))).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{raw}");
        assert!(!e.is_retryable());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!e.to_string().contains("example") && !e.to_string().contains("192.0.2.1"));
    }
    assert_eq!(server.connections(), 0);
    assert_eq!(silent.connections.load(Ordering::SeqCst), 0);
    // The policy at construction says the same.
    let ctx = testing::context(testing::options());
    assert_eq!(
        Endpoint::parse("base_url", "https://api.example.org", &ctx)
            .unwrap_err()
            .kind(),
        ErrorKind::Config
    );
}

#[tokio::test]
async fn request_urls_that_break_the_policy_are_refused_without_echo() {
    let server = ok_server().await;
    let http = default_http();
    let port = server.addr().port();
    for raw in [
        format!("http://user:pw-canary@127.0.0.1:{port}/x"),
        format!("http://127.0.0.1:{port}/x#frag-canary"),
        "http://10.0.0.1/x".to_owned(),
        format!("ftp://127.0.0.1:{port}/x"),
    ] {
        let e = http.send(&Request::get(url(&raw))).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{raw}");
        let text = format!("{e} {e:?}");
        assert!(
            !text.contains("canary") && !text.contains("10.0.0.1"),
            "{text}"
        );
    }
    assert_eq!(server.connections(), 0);
}

// --- timeouts and the size cap ---

#[tokio::test]
async fn connect_timeout_is_transient() {
    let silent = SilentServer::start();
    let ctx = testing::context(ContextOptions {
        connect_timeout: Duration::from_millis(300),
        request_timeout: Duration::from_secs(30),
        ..testing::options()
    });
    let http = testing::http(&ctx, |b| b);
    // The TCP connection is accepted; the TLS handshake never completes, and the connect
    // timeout covers it.
    let started = Instant::now();
    let request = Request::new(Method::POST, url(&format!("https://{}/x", silent.addr)));
    let e = http.send(&request).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e}");
    assert!(e.to_string().contains("timed out"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(silent.connections.load(Ordering::SeqCst), 1);
}

fn short_timeout_http() -> Http {
    let ctx = testing::context(ContextOptions {
        request_timeout: Duration::from_millis(400),
        ..testing::options()
    });
    testing::http(&ctx, |b| b)
}

#[tokio::test]
async fn request_timeout_is_transient() {
    let server = ok_server().await;
    server
        .faults()
        .push(Fault::any().always().delay(Duration::from_secs(10)));
    let http = short_timeout_http();
    let started = Instant::now();
    let e = http.send(&post(&server, "/slow")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e}");
    assert!(e.to_string().contains("timed out"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(server.log().len(), 1);
}

#[tokio::test]
async fn slow_headers_hit_the_request_timeout() {
    let server = ok_server().await;
    server.faults().push(
        Fault::any()
            .always()
            .slow_headers(200, Duration::from_secs(10), "{}"),
    );
    let http = short_timeout_http();
    let started = Instant::now();
    let e = http.send(&post(&server, "/slow")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// A raw answer: `head`, then `body`, then a pause far longer than the test; the connection
/// stays open. A client that tried to read the whole body would hang until its timeout.
fn stalled(head: String, body: Vec<u8>) -> Fault {
    Fault::any().raw(vec![
        (Duration::ZERO, Bytes::from(head)),
        (Duration::ZERO, Bytes::from(body)),
        (Duration::from_secs(3600), Bytes::from_static(b"never")),
    ])
}

#[tokio::test]
async fn declared_oversized_body_is_refused_without_reading_it() {
    let server = ok_server().await;
    server.faults().push(stalled(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 104857600\r\n\r\n"
            .to_owned(),
        Vec::new(),
    ));
    let started = Instant::now();
    let e = default_http()
        .send(&get(&server, "/big"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e}");
    assert!(e.to_string().contains("4 MiB"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(5));
    // Not retried, although the request is idempotent.
    assert_eq!(server.log().len(), 1);
}

#[tokio::test]
async fn chunked_oversized_body_is_refused_at_the_limit() {
    let server = ok_server().await;
    let mut chunk = format!("{:x}\r\n", BODY_LIMIT + 1).into_bytes();
    chunk.extend(std::iter::repeat_n(b'x', BODY_LIMIT + 1));
    chunk.extend_from_slice(b"\r\n");
    server.faults().push(stalled(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n"
            .to_owned(),
        chunk,
    ));
    let started = Instant::now();
    let e = default_http()
        .send(&get(&server, "/big"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn oversized_bodies_from_the_mock_helpers_and_error_bodies_are_protocol() {
    let http = default_http();
    for fault in [
        Fault::any().oversized_body(200, BODY_LIMIT + 1),
        Fault::any().oversized_chunked_body(200, BODY_LIMIT + 1),
        Fault::any().oversized_body(500, BODY_LIMIT + 1),
        Fault::any().oversized_body(401, BODY_LIMIT + 1),
    ] {
        let server = ok_server().await;
        server.faults().push(fault);
        assert_eq!(
            kind(http.send(&get(&server, "/big")).await),
            ErrorKind::Protocol
        );
        assert_eq!(server.log().len(), 1);
    }
}

#[tokio::test]
async fn body_at_the_limit_is_read() {
    let server = ok_server().await;
    server
        .faults()
        .push(Fault::any().respond(200, vec![b'x'; BODY_LIMIT]));
    let response = default_http().send(&get(&server, "/big")).await.unwrap();
    assert_eq!(response.body().len(), BODY_LIMIT);
}

#[tokio::test]
async fn truncated_body_is_transient() {
    let server = ok_server().await;
    server.faults().push(
        Fault::any()
            .always()
            .truncated_body(200, 100, "{\"partial\":"),
    );
    let e = default_http().send(&post(&server, "/x")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e}");
}

// --- retries ---

#[tokio::test]
async fn idempotent_requests_retry_5xx_with_backoff() {
    let server = ok_server().await;
    server.faults().push(Fault::any().times(2).status(503));
    let started = Instant::now();
    let response = default_http().send(&get(&server, "/x")).await.unwrap();
    let elapsed = started.elapsed();
    assert_eq!(response.status(), 200);
    assert_eq!(response.attempt(), 3);
    assert_eq!(server.log().len(), 3);
    // 500 ms and 1000 ms, each plus up to 25 %.
    assert!(elapsed >= Duration::from_millis(1500), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(1875 + 1000), "{elapsed:?}");
}

#[tokio::test]
async fn idempotent_requests_stop_at_three_attempts() {
    let server = ok_server().await;
    server.faults().push(
        Fault::any()
            .always()
            .respond(502, "{\"message\":\"bad gateway\"}"),
    );
    let e = default_http().send(&get(&server, "/x")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient);
    assert!(e.to_string().contains("status 502: bad gateway"), "{e}");
    assert_eq!(server.log().len(), 3);
}

#[tokio::test]
async fn connection_errors_are_retried_for_idempotent_requests_only() {
    let http = default_http();
    let server = ok_server().await;
    server
        .faults()
        .push(Fault::any().times(2).drop_connection());
    assert_eq!(http.send(&get(&server, "/x")).await.unwrap().status(), 200);
    assert_eq!(server.log().len(), 3);

    let server = ok_server().await;
    server
        .faults()
        .push(Fault::any().always().drop_connection());
    assert_eq!(
        kind(http.send(&get(&server, "/x")).await),
        ErrorKind::Transient
    );
    assert_eq!(server.log().len(), 3);

    let server = ok_server().await;
    server
        .faults()
        .push(Fault::any().always().drop_connection());
    assert_eq!(
        kind(http.send(&post(&server, "/x")).await),
        ErrorKind::Transient
    );
    assert_eq!(server.log().len(), 1);
}

#[tokio::test]
async fn non_idempotent_requests_are_sent_exactly_once() {
    let http = default_http();
    for (fault, expected) in [
        (Fault::any().always().status(500), ErrorKind::Transient),
        (Fault::any().always().status(503), ErrorKind::Transient),
        (
            Fault::any().always().rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::any().always().status(429), ErrorKind::RateLimited),
        (Fault::any().always().status(401), ErrorKind::Auth),
        (Fault::any().always().status(403), ErrorKind::Forbidden),
    ] {
        let server = ok_server().await;
        server.faults().push(fault);
        let request = post(&server, "/x")
            .json(&serde_json::json!({ "v": 1 }))
            .unwrap();
        assert_eq!(kind(http.send(&request).await), expected);
        assert_eq!(server.log().len(), 1, "{expected:?}");
    }
    // A 429 with a short wait on a non-idempotent request is not slept through.
    let server = ok_server().await;
    server.faults().push(Fault::any().rate_limited("2"));
    let e = http.send(&post(&server, "/x")).await.unwrap_err();
    assert_eq!(e.retry_after(), Some(Duration::from_secs(2)));
}

#[tokio::test]
async fn other_statuses_and_kept_statuses_go_back_to_the_client() {
    let http = default_http();
    for status in [200, 201, 204, 400, 404, 409, 422] {
        let server = ok_server().await;
        server.faults().push(Fault::any().status(status));
        assert_eq!(
            http.send(&get(&server, "/x")).await.unwrap().status(),
            status
        );
    }
    let server = ok_server().await;
    server.faults().push(Fault::any().status(401));
    let response = http
        .send(&get(&server, "/x").keep_status(401))
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let server = ok_server().await;
    server.faults().push(Fault::any().status(503));
    let response = http
        .send(&get(&server, "/x").keep_status(503))
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(server.log().len(), 1);
}

#[tokio::test]
async fn retry_after_seconds_within_the_bound_is_honored() {
    let server = ok_server().await;
    server.faults().push(Fault::any().rate_limited("2"));
    let started = Instant::now();
    let response = default_http().send(&get(&server, "/x")).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(server.log().len(), 2);
    assert!(started.elapsed() >= Duration::from_secs(2));
}

fn http_date_in(seconds: i64) -> String {
    let at = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(seconds))
        .unwrap();
    jiff::fmt::rfc2822::DateTimePrinter::new()
        .timestamp_to_rfc9110_string(&at)
        .unwrap()
}

#[tokio::test]
async fn retry_after_http_date_within_the_bound_is_honored() {
    let server = ok_server().await;
    server
        .faults()
        .push(Fault::any().rate_limited(&http_date_in(3)));
    let started = Instant::now();
    let response = default_http().send(&get(&server, "/x")).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(server.log().len(), 2);
    // The date has a resolution of one second.
    assert!(
        started.elapsed() >= Duration::from_millis(1900),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn retry_after_beyond_the_bound_is_rate_limited() {
    let http = default_http();
    let server = ok_server().await;
    server.faults().push(Fault::any().rate_limited("120"));
    let e = http.send(&get(&server, "/x")).await.unwrap_err();
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
    assert_eq!(server.log().len(), 1);

    let server = ok_server().await;
    server
        .faults()
        .push(Fault::any().rate_limited(&http_date_in(300)));
    let e = http.send(&get(&server, "/x")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited);
    let wait = e.retry_after().unwrap();
    assert!(
        wait > Duration::from_secs(297) && wait <= Duration::from_secs(300),
        "{wait:?}"
    );
    assert_eq!(server.log().len(), 1);
}

#[tokio::test]
async fn rate_limit_without_a_wait_uses_the_backoff_and_stops_at_the_bound() {
    let http = default_http();
    let server = ok_server().await;
    server.faults().push(Fault::any().status(429));
    let started = Instant::now();
    assert_eq!(http.send(&get(&server, "/x")).await.unwrap().status(), 200);
    assert!(started.elapsed() >= Duration::from_millis(500));
    assert_eq!(server.log().len(), 2);

    let server = ok_server().await;
    server
        .faults()
        .push(Fault::any().always().rate_limited("1"));
    let e = http.send(&get(&server, "/x")).await.unwrap_err();
    assert_eq!(e.retry_after(), Some(Duration::from_secs(1)));
    assert_eq!(server.log().len(), 3);
}

// --- cached tokens ---

async fn token_call(
    http: &Http,
    tokens: &TokenSource,
    server: &MockServer,
    request: Request,
) -> Result<super::Response, Error> {
    let token_url = server.url("/token");
    http.send_with_token(&request, tokens, &TokenAuth::BEARER, || {
        fetch_token(http, &token_url)
    })
    .await
}

fn api_requests(server: &MockServer) -> Vec<zonewright_mock::LoggedRequest> {
    server.log().matching(None, "/api")
}

#[tokio::test]
async fn a_rejected_cached_token_is_refreshed_once() {
    let (server, issued) = token_server().await;
    let http = http_on(&server, |b| b);
    let tokens = TokenSource::new(None);
    // Warm the cache.
    token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap();
    server.faults().push(Fault::path("/api").status(401));
    let response = token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(issued.load(Ordering::SeqCst), 2);
    let api = api_requests(&server);
    assert_eq!(api.len(), 3);
    assert_eq!(api[1].header("authorization"), Some("Bearer tok-1"));
    assert_eq!(api[2].header("authorization"), Some("Bearer tok-2"));
    // The new token is cached.
    token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap();
    assert_eq!(issued.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_token_refresh_counts_toward_the_bound() {
    let (server, issued) = token_server().await;
    let http = http_on(&server, |b| b);
    let tokens = TokenSource::new(None);
    token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap();
    server.faults().push(Fault::path("/api").status(401));
    server
        .faults()
        .push(Fault::path("/api").always().status(503));
    let e = token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient);
    // 1 warm-up, then 401, 503, 503: three attempts in all.
    assert_eq!(api_requests(&server).len(), 4);
    assert_eq!(issued.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_rejected_new_token_is_auth() {
    let (server, issued) = token_server().await;
    let http = http_on(&server, |b| b);
    let tokens = TokenSource::new(None);
    // Cold cache: the token fetched during the call is rejected.
    server
        .faults()
        .push(Fault::path("/api").always().status(401));
    let e = token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth);
    assert_eq!(api_requests(&server).len(), 1);
    assert_eq!(issued.load(Ordering::SeqCst), 1);
    // Warm cache, rejected twice: one refresh, then Auth.
    server.faults().clear();
    token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap();
    server
        .faults()
        .push(Fault::path("/api").always().status(401));
    let e = token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth);
    assert_eq!(api_requests(&server).len(), 4);
    assert_eq!(issued.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_rejected_cached_token_on_a_non_idempotent_request_is_transient() {
    let (server, issued) = token_server().await;
    let http = http_on(&server, |b| b);
    let tokens = TokenSource::new(None);
    token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap();
    server.faults().push(Fault::path("/api").status(401));
    let e = token_call(&http, &tokens, &server, post(&server, "/api"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient);
    assert!(e.to_string().contains("token"), "{e}");
    assert_eq!(api_requests(&server).len(), 2);
    assert_eq!(issued.load(Ordering::SeqCst), 1);
    // The token was discarded: the repeat of the operation obtains a new one.
    token_call(&http, &tokens, &server, post(&server, "/api"))
        .await
        .unwrap();
    assert_eq!(issued.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn token_fetch_failures_are_returned() {
    let (server, _) = token_server().await;
    let http = http_on(&server, |b| b);
    let tokens = TokenSource::new(None);
    server.faults().push(Fault::path("/token").status(401));
    let e = token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth);
    assert!(api_requests(&server).is_empty());
}

// --- pacing ---

#[tokio::test]
async fn pacing_spaces_every_attempt() {
    let server = ok_server().await;
    let ctx = testing::context(testing::options());
    let http = testing::http(&ctx, |b| b.pacing(Duration::from_millis(300)));
    let started = Instant::now();
    for _ in 0..3 {
        http.send(&get(&server, "/x")).await.unwrap();
    }
    assert!(started.elapsed() >= Duration::from_millis(600));
    // Retries pass the gate too: a 503 then the retry, after the back-off and not before the
    // interval.
    server.faults().push(Fault::any().status(503));
    http.send(&get(&server, "/x")).await.unwrap();
    assert_eq!(server.log().len(), 5);
}

// --- Keystone ---

#[tokio::test]
async fn keystone_exchanges_the_password_for_a_scoped_token() {
    let expires = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(24 * 3600))
        .unwrap()
        .to_string();
    let router = Router::new()
        .route(
            "/identity/v3/auth/tokens",
            routing::post(move || {
                let expires = expires.clone();
                async move {
                    (
                        StatusCode::CREATED,
                        [("x-subject-token", "ks-token-1")],
                        zonewright_mock::axum::Json(
                            serde_json::json!({ "token": { "expires_at": expires } }),
                        ),
                    )
                }
            }),
        )
        .fallback(|| async { (StatusCode::OK, "{}") });
    let server = MockServer::start(router).await;
    let ctx = testing::context(testing::options());
    let identity = Endpoint::parse("auth_url", &server.url("/identity/v3/"), &ctx).unwrap();
    let api = Endpoint::parse("dns_url", &server.url("/dns"), &ctx).unwrap();
    let http = testing::http(&ctx, |b| {
        b.secret(CANARY_PASSWORD).endpoint(&identity).endpoint(&api)
    });
    let keystone = Keystone::new(
        &identity,
        "user-1",
        "123456",
        ProjectScope::Id("project-abc"),
        &SecretString::from(CANARY_PASSWORD),
    )
    .unwrap();
    assert!(!format!("{keystone:?}").contains("cAnary"));
    let tokens = TokenSource::new(None);
    for _ in 0..2 {
        let request = get(&server, "/dns/zones");
        let response = http
            .send_with_token(&request, &tokens, &X_AUTH_TOKEN, || {
                keystone.fetch_token(&http)
            })
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }
    let exchanges = server
        .log()
        .matching(Some("POST"), "/identity/v3/auth/tokens");
    assert_eq!(exchanges.len(), 1);
    assert!(exchanges[0].header("authorization").is_none());
    assert_eq!(
        exchanges[0].header("content-type"),
        Some("application/json")
    );
    assert_eq!(
        exchanges[0].body_json().unwrap(),
        serde_json::json!({ "auth": {
            "identity": { "methods": ["password"], "password": { "user": {
                "name": "user-1", "domain": { "name": "123456" }, "password": CANARY_PASSWORD
            } } },
            "scope": { "project": { "id": "project-abc" } }
        } })
    );
    let api = server.log().matching(Some("GET"), "/dns/zones");
    assert_eq!(api.len(), 2);
    for request in api {
        assert_eq!(request.header("x-auth-token"), Some("ks-token-1"));
    }
}

/// The scope by project name carries the project's domain; the project ID the answer states is
/// returned with the token, and is absent when the answer states none.
#[tokio::test]
async fn keystone_scopes_by_project_name_and_returns_the_project_id() {
    let router = Router::new().route(
        "/v3/auth/tokens",
        routing::post(|body: zonewright_mock::axum::body::Bytes| async move {
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let project = &request["auth"]["scope"]["project"];
            // Scoped by name: the answer states the project; by ID: it states none.
            let answer = if project.get("name").is_some() {
                serde_json::json!({ "token": { "project": { "id": "project-from-name" } } })
            } else {
                serde_json::json!({ "token": {} })
            };
            (
                StatusCode::CREATED,
                [("x-subject-token", "ks-token-2")],
                zonewright_mock::axum::Json(answer),
            )
        }),
    );
    let server = MockServer::start(router).await;
    let ctx = testing::context(testing::options());
    let identity = Endpoint::parse("auth_url", &server.url("/v3"), &ctx).unwrap();
    let http = testing::http(&ctx, |b| b.secret(CANARY_PASSWORD).endpoint(&identity));
    let password = SecretString::from(CANARY_PASSWORD);

    let by_name = Keystone::new(
        &identity,
        "user-1",
        "user-domain",
        ProjectScope::Name {
            name: "dns-project",
            domain: "123456",
        },
        &password,
    )
    .unwrap();
    let issued = by_name.fetch(&http).await.unwrap();
    assert_eq!(issued.project_id.as_deref(), Some("project-from-name"));
    assert!(!format!("{issued:?}").contains("ks-token"));
    let request = server.log().last().unwrap();
    assert_eq!(
        request.body_json().unwrap()["auth"]["scope"],
        serde_json::json!({ "project": { "name": "dns-project", "domain": { "name": "123456" } } })
    );
    assert_eq!(
        request.body_json().unwrap()["auth"]["identity"]["password"]["user"]["domain"],
        serde_json::json!({ "name": "user-domain" })
    );

    let by_id = Keystone::new(
        &identity,
        "user-1",
        "user-domain",
        ProjectScope::Id("project-abc"),
        &password,
    )
    .unwrap();
    assert_eq!(by_id.fetch(&http).await.unwrap().project_id, None);
    assert_eq!(
        server.log().last().unwrap().body_json().unwrap()["auth"]["scope"],
        serde_json::json!({ "project": { "id": "project-abc" } })
    );
    // `fetch_token` is the same exchange without the project.
    by_id.fetch_token(&http).await.unwrap();
    assert_eq!(server.log().len(), 3);
}

#[tokio::test]
async fn keystone_failures() {
    let ctx = testing::context(testing::options());
    let http = testing::http(&ctx, |b| b.secret(CANARY_PASSWORD));
    for (fault, expected) in [
        (Fault::any().status(401), ErrorKind::Auth),
        (Fault::any().status(400), ErrorKind::Auth),
        (Fault::any().status(403), ErrorKind::Forbidden),
        (Fault::any().status(404), ErrorKind::Rejected),
        (Fault::any().always().status(500), ErrorKind::Transient),
        // 201 without the token header.
        (Fault::any().respond(201, "{}"), ErrorKind::Protocol),
    ] {
        let server = ok_server().await;
        server.faults().push(fault);
        let identity = Endpoint::parse("auth_url", &server.url("/v3"), &ctx).unwrap();
        let keystone = Keystone::new(
            &identity,
            "u",
            "d",
            ProjectScope::Id("p"),
            &SecretString::from(CANARY_PASSWORD),
        )
        .unwrap();
        assert_eq!(kind(keystone.fetch(&http).await), expected);
    }
}

// --- credentials and endpoints ---

#[tokio::test]
async fn anonymous_requests_carry_no_credential() {
    let server = ok_server().await;
    let http = http_on(&server, |b| b.bearer("api_token", CANARY_TOKEN));
    http.send(&get(&server, "/with")).await.unwrap();
    http.send(&get(&server, "/without").anonymous())
        .await
        .unwrap();
    let with = server.log().matching(None, "/with");
    let without = server.log().matching(None, "/without");
    assert!(
        with[0]
            .header("authorization")
            .unwrap()
            .starts_with("Bearer ")
    );
    assert!(without[0].header("authorization").is_none());
}

#[tokio::test]
async fn credentials_go_only_to_declared_endpoints() {
    let own = ok_server().await;
    let other = ok_server().await;
    let http = http_on(&own, |b| b.bearer("api_token", CANARY_TOKEN));
    assert_eq!(http.send(&get(&own, "/x")).await.unwrap().status(), 200);
    for request in [get(&other, "/x"), get(&other, "/x").anonymous()] {
        let e = http.send(&request).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{e}");
        assert!(!e.is_retryable());
    }
    // Same host, another port: another origin.
    assert_eq!(other.connections(), 0);
    assert!(other.log().is_empty());

    // A client certificate counts as a credential too.
    let (_, _, cert_pem, key_pem) = testing::client_cert();
    let http = http_on(&own, |b| b.client_identity(&cert_pem, &key_pem));
    assert_eq!(kind(http.send(&get(&other, "/x")).await), ErrorKind::Config);
    assert_eq!(other.connections(), 0);

    // Credentials without a declared endpoint are refused at construction.
    let ctx = testing::context(testing::options());
    let e = Http::builder(&ctx, crate::id::ProviderId::Cloudflare)
        .bearer("api_token", CANARY_TOKEN)
        .build()
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
    let e = Http::builder(&ctx, crate::id::ProviderId::Cloudflare)
        .client_identity(&cert_pem, &key_pem)
        .build()
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);

    // A cached token is not sent, and not even fetched, without a declared endpoint.
    let (server, issued) = token_server().await;
    let anonymous = default_http();
    let tokens = TokenSource::new(None);
    let e = token_call(&anonymous, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
    assert_eq!(issued.load(Ordering::SeqCst), 0);
    assert!(server.log().is_empty());
}

// --- rate-limit extremes, stalled bodies, rejected tokens ---

#[tokio::test]
async fn a_zero_or_past_wait_still_backs_off() {
    let http = default_http();
    let past = (jiff::Timestamp::now().as_second() - 100).to_string();
    for fault in [
        Fault::any().times(2).rate_limited("0"),
        Fault::any().times(2).rate_limited(&http_date_in(-60)),
        Fault::any()
            .times(2)
            .status(429)
            .header("ratelimit-reset", &past),
    ] {
        let server = ok_server().await;
        server.faults().push(fault);
        let started = Instant::now();
        assert_eq!(http.send(&get(&server, "/x")).await.unwrap().status(), 200);
        assert_eq!(server.log().len(), 3);
        // 500 ms and 1000 ms of back-off at least.
        assert!(started.elapsed() >= Duration::from_millis(1500));
    }
}

#[tokio::test]
async fn huge_waits_are_reported_clamped() {
    let http = default_http();
    let far = (jiff::Timestamp::now().as_second() + 10 * 365 * 86_400).to_string();
    for fault in [
        Fault::any().always().rate_limited("18446744073709551615"),
        Fault::any()
            .always()
            .rate_limited("99999999999999999999999"),
        Fault::any()
            .always()
            .status(429)
            .header("ratelimit-reset", &far),
    ] {
        let server = ok_server().await;
        server.faults().push(fault);
        let e = http.send(&get(&server, "/x")).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::RateLimited);
        let wait = e.retry_after();
        // A number too large to parse is no wait at all: the back-off applies.
        assert!(
            wait.is_none() || wait == Some(Duration::from_secs(24 * 3600)),
            "{wait:?}"
        );
        if let Some(wait) = wait {
            // A caller can add it to an instant.
            let _ = std::time::Instant::now() + wait;
        }
    }
    let server = ok_server().await;
    server
        .faults()
        .push(Fault::any().rate_limited("18446744073709551615"));
    let e = http.send(&get(&server, "/x")).await.unwrap_err();
    assert_eq!(e.retry_after(), Some(Duration::from_secs(24 * 3600)));
    assert_eq!(server.log().len(), 1);
}

#[tokio::test]
async fn a_body_that_stalls_or_trickles_hits_the_request_timeout() {
    let http = short_timeout_http();
    let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n";
    // Ten bytes, then nothing.
    let server = ok_server().await;
    server
        .faults()
        .push(stalled(head.to_owned(), b"{\"partial\"".to_vec()));
    let started = Instant::now();
    let e = http.send(&post(&server, "/x")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e}");
    assert!(e.to_string().contains("timed out"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(3));
    // One byte every 100 ms: each read makes progress, the whole request does not finish.
    let server = ok_server().await;
    let mut chunks = vec![(Duration::ZERO, Bytes::from_static(head.as_bytes()))];
    chunks.extend((0..100).map(|_| (Duration::from_millis(100), Bytes::from_static(b" "))));
    server.faults().push(Fault::any().raw(chunks));
    let started = Instant::now();
    let e = http.send(&post(&server, "/x")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn a_rejected_token_with_an_oversized_answer_is_not_kept() {
    let (server, issued) = token_server().await;
    let http = http_on(&server, |b| b);
    let tokens = TokenSource::new(None);
    token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap();
    server
        .faults()
        .push(Fault::path("/api").oversized_body(401, BODY_LIMIT + 1));
    let e = token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol);
    token_call(&http, &tokens, &server, get(&server, "/api"))
        .await
        .unwrap();
    assert_eq!(issued.load(Ordering::SeqCst), 2);
    let api = api_requests(&server);
    assert_eq!(
        api.last().unwrap().header("authorization"),
        Some("Bearer tok-2")
    );
}

// --- secrets ---

/// One position in which a client sends a credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Position {
    Bearer,
    Header,
    Basic,
    Form,
    Json,
    Query,
}

const POSITIONS: [Position; 6] = [
    Position::Bearer,
    Position::Header,
    Position::Basic,
    Position::Form,
    Position::Json,
    Position::Query,
];

/// A handle that carries the canaries in `position`, with every canary registered as the
/// client's credentials would be, and `server` as its endpoint.
fn canary_http(ctx: &crate::context::Context, server: &MockServer, position: Position) -> Http {
    testing::http(ctx, |b| {
        let b = b
            .endpoint(&endpoint_of(server))
            .secret(CANARY_TOKEN)
            .secret(CANARY_PASSWORD)
            .secret(CANARY_KEY)
            .secret(CANARY_USER);
        match position {
            Position::Bearer => b.bearer("api_token", CANARY_TOKEN),
            Position::Header => b.auth_header(
                "api_key",
                HeaderName::from_static("x-api-key"),
                "",
                CANARY_KEY,
            ),
            Position::Basic => b.basic(CANARY_USER, CANARY_PASSWORD),
            Position::Form | Position::Json | Position::Query => b,
        }
    })
}

fn canary_request(server: &MockServer, position: Position) -> Request {
    let request = post(server, "/a");
    match position {
        Position::Form => request.form(&[("user", CANARY_USER), ("password", CANARY_PASSWORD)]),
        Position::Json => request
            .json(&serde_json::json!({ "user": CANARY_USER, "password": CANARY_PASSWORD }))
            .unwrap(),
        Position::Query => Request::new(
            Method::POST,
            endpoint_of(server)
                .url()
                .path("/a")
                .query("key", CANARY_KEY)
                .build()
                .unwrap(),
        ),
        Position::Bearer | Position::Header | Position::Basic => request,
    }
}

/// The error a client makes of the answer: the transport's own for 401, 403, 429 and 5xx, the
/// default classification for anything else.
async fn error_of(http: &Http, request: &Request) -> Error {
    match http.send(request).await {
        Ok(response) => http.reject(&response),
        Err(e) => e,
    }
}

/// Whether the canaries must be cut out in place, the rest of the message kept: the echo
/// repeats them in a spelling the scrubber knows exactly, after the transport decoded what the
/// body format encodes (a JSON message field, the string values of other JSON). Elsewhere the
/// message may be withheld as a whole; it must never leak.
fn precise(position: Position, dialect: &Dialect) -> bool {
    match (dialect.spelling, dialect.name) {
        (
            Spelling::Verbatim,
            "json" | "json_ascii" | "json_go" | "json_dotnet" | "json_unicode" | "json_unknown_key"
            | "text",
        ) => true,
        // XML-escaped or PHP-escaped JSON-escaped text is not a spelling of the scrubber.
        (Spelling::Verbatim, "xml" | "json_ascii_with_notice") => position != Position::Json,
        // A JSON body form-encoded is not either; every other position is, encoded once more.
        (Spelling::FormPlus | Spelling::FormPercent, "json" | "text") => position != Position::Json,
        _ => false,
    }
}

#[tokio::test]
async fn secrets_never_reach_errors() {
    let ctx = testing::context(testing::options());
    let mut precise_cases = 0;
    for dialect in dialects() {
        for status in [400, 401, 403, 429, 500] {
            let echo = dialect.echo(status).start().await;
            for position in POSITIONS {
                let http = canary_http(&ctx, &echo, position);
                let request = canary_request(&echo, position);
                let e = error_of(&http, &request).await;
                let what = format!(
                    "{position:?} {} {:?} {status}",
                    dialect.name, dialect.spelling
                );
                for text in [e.to_string(), format!("{e:?}"), format!("{http:?}")] {
                    assert_clean(&what, &text, &CANARIES);
                }
                if status == 429 {
                    continue;
                }
                // The echo reached the error path: the test is not vacuous.
                assert!(e.to_string().contains(REDACTED), "{what}: {e}");
                if precise(position, &dialect) {
                    precise_cases += 1;
                    assert!(!e.to_string().contains(WITHHELD), "{what}: {e}");
                }
            }
            assert_eq!(echo.api_requests(), POSITIONS.len());
        }
    }
    assert!(precise_cases > 100, "{precise_cases}");
}

#[tokio::test]
async fn tokens_obtained_at_run_time_never_reach_errors() {
    let ctx = testing::context(testing::options());
    for dialect in dialects() {
        for status in [400, 401, 500] {
            let echo = dialect.echo(status).start().await;
            let http = canary_http(&ctx, &echo, Position::Form);
            let tokens = TokenSource::new(None);
            let token_url = echo.token_url();
            let fetch = || async {
                let request = Request::new(Method::POST, url(&token_url))
                    .idempotent()
                    .anonymous()
                    .form(&[("password", CANARY_PASSWORD)]);
                let response = http.send(&request).await?;
                let answer: TokenAnswer = response.json("token answer")?;
                Ok(Token::new(SecretString::from(answer.access_token), None))
            };
            // Sent once, so that a 500 is not retried with back-off.
            let request = post(&echo, "/a");
            let e = match http
                .send_with_token(&request, &tokens, &TokenAuth::BEARER, fetch)
                .await
            {
                Ok(response) => http.reject(&response),
                Err(e) => e,
            };
            let what = format!("{} {:?} {status}", dialect.name, dialect.spelling);
            let secrets = [CANARY_PASSWORD, echo.issued_token()];
            for text in [e.to_string(), format!("{e:?}")] {
                assert_clean(&what, &text, &secrets);
            }
            assert!(e.to_string().contains(REDACTED), "{what}: {e}");
            assert!(echo.token_requests() >= 1 && echo.api_requests() >= 1);
        }
    }
}

#[tokio::test]
async fn keystone_password_and_token_never_reach_errors() {
    let ctx = testing::context(testing::options());
    // 400, 401 and 403, each answered at once: the exchange is idempotent, and a 5xx would be
    // retried with back-off for every dialect. The 5xx path is the same transport code.
    for dialect in dialects() {
        for status in [400, 401, 403] {
            let echo = dialect.echo(status).start().await;
            let http = testing::http(&ctx, |b| b.secret(CANARY_PASSWORD).secret(CANARY_USER));
            let identity = Endpoint::parse("auth_url", &echo.url("/v3"), &ctx).unwrap();
            let keystone = Keystone::new(
                &identity,
                CANARY_USER,
                "domain",
                ProjectScope::Id("project"),
                &SecretString::from(CANARY_PASSWORD),
            )
            .unwrap();
            let e = keystone.fetch(&http).await.unwrap_err();
            let what = format!("keystone {} {:?} {status}", dialect.name, dialect.spelling);
            for text in [e.to_string(), format!("{e:?}"), format!("{keystone:?}")] {
                assert_clean(&what, &text, &[CANARY_PASSWORD, CANARY_USER]);
            }
            assert!(e.to_string().contains(REDACTED), "{what}: {e}");
        }
    }
}

/// Field names the transport's request events may carry.
const EVENT_FIELDS: [&str; 7] = [
    "message",
    "provider",
    "method",
    "path",
    "status",
    "attempt",
    "elapsed_ms",
];

#[tokio::test]
async fn nothing_secret_reaches_tracing() {
    // The context is built before the capture: on a host without CA certificates it logs a
    // warning of its own, which belongs to no request.
    let ctx = testing::context(testing::options());
    let (capture, _guard) = LogCapture::install();
    // Success, 401 and 500, with the canaries in every position.
    for status in [200, 401, 500] {
        let echo = Echo::new(status).start().await;
        for position in POSITIONS {
            let http = canary_http(&ctx, &echo, position);
            let _ = error_of(&http, &canary_request(&echo, position)).await;
        }
    }
    // A token obtained at run time, then a 401 for it and a 500.
    let echo = Echo::new(200).start().await;
    let http = canary_http(&ctx, &echo, Position::Form);
    let tokens = TokenSource::new(None);
    let token_url = echo.token_url();
    let fetch = || async {
        let request = Request::new(Method::POST, url(&token_url))
            .idempotent()
            .anonymous()
            .form(&[("password", CANARY_PASSWORD)]);
        let answer: TokenAnswer = http.send(&request).await?.json("token answer")?;
        Ok(Token::new(SecretString::from(answer.access_token), None))
    };
    let query = endpoint_of(&echo)
        .url()
        .path("/q")
        .query("filter", CANARY_KEY)
        .build()
        .unwrap();
    for fault in [
        None,
        Some(Fault::path("/q").status(401)),
        Some(Fault::path("/q").status(500)),
    ] {
        if let Some(fault) = fault {
            echo.faults().push(fault);
        }
        let _ = http
            .send_with_token(
                &Request::new(Method::POST, query.clone()),
                &tokens,
                &TokenAuth::BEARER,
                fetch,
            )
            .await;
    }
    assert!(echo.token_requests() >= 1);

    let entries = capture.entries();
    assert!(!entries.is_empty());
    let ours: Vec<_> = entries
        .iter()
        .filter(|e| e.target == "zonewright::http")
        .collect();
    let requests: Vec<_> = ours
        .iter()
        .filter(|e| e.field("message") == Some("provider request"))
        .collect();
    assert!(
        requests.len() >= 3 * POSITIONS.len() + 3,
        "{}",
        capture.text()
    );
    for event in &ours {
        assert!(!event.span, "{event}");
        if event.field("message") == Some("provider request") {
            assert_eq!(event.level, tracing::Level::DEBUG);
            for name in event.names() {
                assert!(
                    EVENT_FIELDS.contains(&name),
                    "unexpected field {name}: {event}"
                );
            }
            let path = event.field("path").unwrap();
            assert!(path.starts_with('/') && !path.contains('?'), "{event}");
            assert!(event.field("method").is_some() && event.field("elapsed_ms").is_some());
        } else {
            // Operator warnings carry no request data.
            assert_eq!(event.level, tracing::Level::WARN, "{event}");
            for name in event.names() {
                assert!(["message", "lifetime_s"].contains(&name), "{event}");
            }
        }
    }
    assert!(requests.iter().any(|e| e.field("status") == Some("401")));
    assert!(requests.iter().any(|e| e.field("status") == Some("500")));
    // Nothing captured from any target carries a secret, an issued token or a query string.
    let text = capture.text();
    assert_clean(
        "the captured log",
        &text,
        &[
            CANARY_TOKEN,
            CANARY_PASSWORD,
            CANARY_KEY,
            CANARY_USER,
            echo.issued_token(),
        ],
    );
    assert!(!text.contains("filter="), "{text}");
}
