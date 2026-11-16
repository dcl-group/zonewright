//! Tests of the explicit proxy (`ContextOptions::proxy`) against loopback servers: forwarding and
//! `CONNECT` tunnels, what the proxy sees, certificate checks through a tunnel, an `https://`
//! proxy, a SOCKS5 proxy with and without credentials and with local or proxy-side name
//! resolution, the exclusion list, the error kinds and `certainly_unsent` of every way a proxy
//! can fail, the interaction with the URL policy, `loopback_only` and the endpoint binding, the
//! environment, and the proxy password in errors, `Debug` and `tracing`.
//!
//! The HTTP proxy is `zonewright_mock::proxy::ProxyServer`; the `https://` proxy is a
//! [`TlsFront`](super::testing::TlsFront) in front of it; the SOCKS5 proxy is
//! `zonewright_mock::socks::SocksServer`, and the SOCKS5 tests run with the `socks` feature only.
//! Timing follows the rules at the top of `tests.rs`: lower bounds only where they are the
//! subject, generous upper bounds, and counts instead of times.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use base64::Engine as _;
use reqwest::{Method, Url};
use secrecy::SecretString;
use zonewright_mock::axum::Router;
use zonewright_mock::axum::http::StatusCode;
use zonewright_mock::proxy::{Behavior, ProxyServer};
#[cfg(feature = "socks")]
use zonewright_mock::socks::{Destination, SocksServer};
use zonewright_mock::{Fault, MockServer};

use crate::context::{ContextOptions, HttpProxy};
use crate::error::{Error, ErrorKind};

use super::Http;
use super::request::Request;
use super::testing::echo::{
    CANARY_KEY, CANARY_TOKEN, LogCapture, REDACTED, assert_clean, find_secret,
};
use super::testing::{self, SilentServer, TlsFront, TlsServer};
use super::url::Endpoint;

/// The proxy user of these tests. The proxy password is [`CANARY_TOKEN`] (a canary without
/// control characters, which a Basic password cannot carry); the provider credential is
/// [`CANARY_KEY`].
const PROXY_USER: &str = "proxy-user";

/// A request timeout no test waits for.
const LONG_TIMEOUT: Duration = Duration::from_secs(600);

/// The upper bound of a call that must end at a short timeout rather than at [`LONG_TIMEOUT`].
const GENEROUS: Duration = Duration::from_secs(60);

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

fn post_to(raw: &str) -> Request {
    Request::new(Method::POST, url(raw))
}

/// The test options with `proxy_url` as the proxy, with the canary credentials when `auth`.
fn with_proxy(proxy_url: &str, auth: bool) -> ContextOptions {
    let mut proxy = HttpProxy::new(proxy_url.to_owned());
    if auth {
        proxy = proxy.with_credentials(
            PROXY_USER.to_owned(),
            SecretString::from(CANARY_TOKEN.to_owned()),
        );
    }
    ContextOptions {
        proxy: Some(proxy),
        ..testing::options()
    }
}

/// The `Proxy-Authorization` value for `user` and `password`.
fn basic(user: &str, password: &str) -> String {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    format!("Basic {token}")
}

/// A handle with a declared endpoint at `base` and the provider canary as its bearer token.
fn bearer_http(ctx: &crate::context::Context, base: &str) -> Http {
    let api = Endpoint::parse_with("base_url", base, true).unwrap();
    testing::http(ctx, |b| b.endpoint(&api).bearer("api_token", CANARY_KEY))
}

/// An HTTPS target whose certificate the context trusts through the returned CA certificate.
fn https_target() -> (TlsServer, Vec<u8>) {
    let (ca, issuer) = testing::ca();
    let (leaf, key) = testing::server_cert(&issuer);
    (TlsServer::start(vec![leaf], key), ca.der().to_vec())
}

// --- requests through the proxy ---

#[tokio::test]
async fn a_plain_http_request_is_forwarded_through_the_proxy() {
    let server = ok_server().await;
    let proxy = ProxyServer::start().await;
    proxy.require_basic(PROXY_USER, CANARY_TOKEN);
    let ctx = testing::context(with_proxy(&proxy.url(), true));
    let http = bearer_http(&ctx, &server.base_url());
    let response = http.send(&get(&server, "/x?q=1")).await.unwrap();
    assert_eq!(response.status(), 200);
    let log = proxy.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].method, "GET");
    assert_eq!(log[0].target, server.url("/x?q=1"));
    assert_eq!(
        log[0].header("proxy-authorization"),
        Some(basic(PROXY_USER, CANARY_TOKEN).as_str())
    );
    // The proxy credential is a hop-by-hop header, consumed by the proxy; the provider
    // credential travels in its own header only.
    let logged = server.log().last().unwrap();
    assert!(logged.header("proxy-authorization").is_none());
    assert_eq!(
        logged.header("authorization"),
        Some(format!("Bearer {CANARY_KEY}").as_str())
    );
    // Without credentials, no `Proxy-Authorization` is sent at all.
    let open = ProxyServer::start().await;
    let ctx = testing::context(with_proxy(&open.url(), false));
    let http = testing::http(&ctx, |b| b);
    assert_eq!(http.send(&get(&server, "/y")).await.unwrap().status(), 200);
    assert!(open.log()[0].header("proxy-authorization").is_none());
}

#[tokio::test]
async fn an_https_request_is_tunneled_and_the_proxy_sees_the_authority_only() {
    let (target, ca) = https_target();
    let proxy = ProxyServer::start().await;
    proxy.require_basic(PROXY_USER, CANARY_TOKEN);
    let ctx = testing::context(ContextOptions {
        extra_root_certificates: vec![ca],
        ..with_proxy(&proxy.url(), true)
    });
    let http = bearer_http(&ctx, &format!("https://{}", target.addr));
    let response = http
        .send(&Request::get(url(&format!(
            "{}?filter=secret-query",
            target.url()
        ))))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"{\"ok\":true}");
    // One CONNECT with the authority and the proxy credential, nothing else.
    let log = proxy.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].method, "CONNECT");
    assert_eq!(log[0].target, target.addr.to_string());
    assert_eq!(
        log[0].header("proxy-authorization"),
        Some(basic(PROXY_USER, CANARY_TOKEN).as_str())
    );
    assert!(log[0].header("authorization").is_none());
    // What went through the tunnel is TLS: no path, query, header or credential in clear text.
    let tunneled = String::from_utf8_lossy(&proxy.tunneled()).into_owned();
    assert!(tunneled.len() > 100, "{}", tunneled.len());
    for clear in [
        "/tls",
        "secret-query",
        "Bearer",
        "authorization",
        "zonewright/",
    ] {
        assert!(!tunneled.contains(clear), "the proxy saw {clear}");
    }
    assert_eq!(find_secret(&tunneled, &[CANARY_KEY, CANARY_TOKEN]), None);
    // The target got the request with the provider credential and without the proxy's.
    let heads = target.heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1);
    let head = heads[0].to_ascii_lowercase();
    assert!(
        head.starts_with("get /tls?filter=secret-query http/1.1"),
        "{head}"
    );
    assert!(head.contains("authorization: bearer"), "{head}");
    assert!(!head.contains("proxy-authorization"), "{head}");
    // ALPN inside the tunnel is the crate's own.
    assert_eq!(*target.alpn.lock().unwrap(), vec![b"http/1.1".to_vec()]);
}

#[tokio::test]
async fn an_untrusted_target_certificate_is_refused_through_the_proxy() {
    let (target, _ca) = https_target();
    let proxy = ProxyServer::start().await;
    // The context trusts another CA, not the target's.
    let (other_ca, _) = testing::ca();
    let ctx = testing::context(ContextOptions {
        extra_root_certificates: vec![other_ca.der().to_vec()],
        ..with_proxy(&proxy.url(), false)
    });
    let http = testing::http(&ctx, |b| b);
    let e = http
        .try_send(&Request::get(url(&target.url())))
        .await
        .unwrap_err();
    assert_eq!(e.error().kind(), ErrorKind::Config, "{e:?}");
    assert!(!e.error().is_retryable());
    assert!(e.error().to_string().contains("certificate"), "{e:?}");
    // A refused certificate is never "certainly unsent" (section 5.3), proxy or not.
    assert!(!e.certainly_unsent());
    // Not retried: one tunnel, one handshake, no request.
    assert_eq!(proxy.log().len(), 1);
    assert_eq!(target.connections.load(Ordering::SeqCst), 1);
    assert_eq!(target.answered.load(Ordering::SeqCst), 0);
    assert!(target.heads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_https_proxy_is_verified_with_the_context_trust() {
    let (ca, issuer) = testing::ca();
    let proxy = ProxyServer::start().await;
    let (leaf, key) = testing::server_cert(&issuer);
    let front = TlsFront::start(vec![leaf], key, proxy.addr());
    let (leaf, key) = testing::server_cert(&issuer);
    let target = TlsServer::start(vec![leaf], key);
    let server = ok_server().await;
    let ctx = testing::context(ContextOptions {
        extra_root_certificates: vec![ca.der().to_vec()],
        ..with_proxy(&front.url(), true)
    });
    let http = testing::http(&ctx, |b| b);
    // A plain-HTTP loopback target, forwarded through the TLS connection to the proxy.
    assert_eq!(http.send(&get(&server, "/x")).await.unwrap().status(), 200);
    // An HTTPS target: TLS inside the tunnel inside TLS.
    let response = http.send(&Request::get(url(&target.url()))).await.unwrap();
    assert_eq!(response.status(), 200);
    let log = proxy.log();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].method, "GET");
    assert_eq!(log[1].method, "CONNECT");
    for entry in &log {
        assert_eq!(
            entry.header("proxy-authorization"),
            Some(basic(PROXY_USER, CANARY_TOKEN).as_str())
        );
    }
    assert!(front.handshakes.load(Ordering::SeqCst) >= 2);
    assert_eq!(*target.alpn.lock().unwrap(), vec![b"http/1.1".to_vec()]);

    // A proxy certificate from a CA the context does not trust is refused like a provider's.
    let (_, untrusted) = testing::ca();
    let proxy = ProxyServer::start().await;
    let (leaf, key) = testing::server_cert(&untrusted);
    let front = TlsFront::start(vec![leaf], key, proxy.addr());
    let ctx = testing::context(ContextOptions {
        extra_root_certificates: vec![ca.der().to_vec()],
        ..with_proxy(&front.url(), true)
    });
    let http = testing::http(&ctx, |b| b);
    for request in [get(&server, "/x"), Request::get(url(&target.url()))] {
        let e = http.try_send(&request).await.unwrap_err();
        assert_eq!(e.error().kind(), ErrorKind::Config, "{e:?}");
        assert!(e.error().to_string().contains("proxy"), "{e:?}");
        assert!(!e.certainly_unsent());
    }
    // One connection per request, no retry, no completed handshake, nothing reached the proxy.
    assert_eq!(front.connections.load(Ordering::SeqCst), 2);
    assert_eq!(front.handshakes.load(Ordering::SeqCst), 0);
    assert!(proxy.log().is_empty());
}

// --- a proxy that refuses, fails or stalls ---

#[tokio::test]
async fn refused_proxy_credentials_are_proxy_auth_and_not_retried() {
    let (target, ca) = https_target();
    let server = ok_server().await;
    let proxy = ProxyServer::start().await;
    proxy.require_basic(PROXY_USER, "the-right-password");
    for auth in [true, false] {
        let ctx = testing::context(ContextOptions {
            extra_root_certificates: vec![ca.clone()],
            ..with_proxy(&proxy.url(), auth)
        });
        let http = testing::http(&ctx, |b| b);
        // CONNECT answered 407: nothing reached the provider; an idempotent request is not
        // repeated, because the next attempt would be refused the same way.
        for request in [Request::get(url(&target.url())), post_to(&target.url())] {
            let before = proxy.log().len();
            let e = http.try_send(&request).await.unwrap_err();
            assert_eq!(e.error().kind(), ErrorKind::ProxyAuth, "{e:?}");
            assert!(!e.error().is_retryable());
            assert_eq!(e.error().retry_after(), None);
            assert!(e.error().to_string().contains("proxy credentials"), "{e:?}");
            assert!(e.certainly_unsent(), "{e:?}");
            assert_eq!(proxy.log().len(), before + 1);
        }
        assert_eq!(target.connections.load(Ordering::SeqCst), 0);
        // A forwarded request answered 407 by the proxy: the same error, but the request was
        // written to the proxy, so it is not "certainly unsent". A kept 407 is no exception.
        for request in [get(&server, "/x"), get(&server, "/x").keep_status(407)] {
            let before = proxy.log().len();
            let e = http.try_send(&request).await.unwrap_err();
            assert_eq!(e.error().kind(), ErrorKind::ProxyAuth, "{e:?}");
            assert!(!e.certainly_unsent(), "{e:?}");
            assert_eq!(proxy.log().len(), before + 1);
        }
        assert!(server.log().is_empty());
    }
}

#[tokio::test]
async fn a_refused_connect_is_transient_unsent_and_retried_only_when_idempotent() {
    let (target, ca) = https_target();
    let proxy = ProxyServer::start().await;
    proxy.set_behavior(Behavior::Refuse(403));
    let ctx = testing::context(ContextOptions {
        extra_root_certificates: vec![ca],
        ..with_proxy(&proxy.url(), true)
    });
    let http = testing::http(&ctx, |b| b);
    let e = http.try_send(&post_to(&target.url())).await.unwrap_err();
    assert_eq!(e.error().kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.error().to_string().contains("through the proxy"), "{e:?}");
    assert!(e.certainly_unsent());
    assert_eq!(proxy.log().len(), 1);
    // An idempotent request is retried like after any connection failure.
    let e = http
        .try_send(&Request::get(url(&target.url())))
        .await
        .unwrap_err();
    assert_eq!(e.error().kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.certainly_unsent());
    assert_eq!(proxy.log().len(), 1 + 3);
    // A proxy that closes the connection instead of answering is the same.
    proxy.set_behavior(Behavior::Close);
    let e = http.try_send(&post_to(&target.url())).await.unwrap_err();
    assert_eq!(e.error().kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.certainly_unsent());
    assert_eq!(target.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unreachable_proxy_is_transient_and_unsent() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = listener.local_addr().unwrap();
    drop(listener);
    let server = ok_server().await;
    let ctx = testing::context(with_proxy(&format!("http://{closed}"), true));
    let http = testing::http(&ctx, |b| b);
    for request in [
        post_to("https://127.0.0.1:9/x"),
        Request::new(Method::POST, url(&server.url("/x"))),
    ] {
        let e = http.try_send(&request).await.unwrap_err();
        assert_eq!(e.error().kind(), ErrorKind::Transient, "{e:?}");
        assert!(e.error().to_string().contains("through the proxy"), "{e:?}");
        assert!(e.certainly_unsent(), "{e:?}");
    }
    assert_eq!(server.connections(), 0);
}

#[tokio::test]
async fn a_stalled_connect_hits_the_connect_timeout() {
    let proxy = ProxyServer::start().await;
    proxy.set_behavior(Behavior::Stall);
    let ctx = testing::context(ContextOptions {
        connect_timeout: Duration::from_millis(300),
        request_timeout: LONG_TIMEOUT,
        ..with_proxy(&proxy.url(), true)
    });
    let http = testing::http(&ctx, |b| b);
    let started = Instant::now();
    let e = http
        .try_send(&post_to("https://127.0.0.1:9/x"))
        .await
        .unwrap_err();
    assert_eq!(e.error().kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.error().to_string().contains("timed out"), "{e:?}");
    assert!(started.elapsed() < GENEROUS);
    assert!(e.certainly_unsent());
    assert_eq!(proxy.log().len(), 1);
    assert_eq!(proxy.connections(), 1);
}

#[tokio::test]
async fn a_forwarded_request_lost_at_the_proxy_is_not_unsent() {
    let server = ok_server().await;
    let proxy = ProxyServer::start().await;
    proxy.set_behavior(Behavior::Stall);
    let ctx = testing::context(ContextOptions {
        request_timeout: Duration::from_millis(400),
        ..with_proxy(&proxy.url(), true)
    });
    let http = testing::http(&ctx, |b| b);
    // Written to the proxy, then no answer: the request timeout, and the outcome is unknown.
    let e = http
        .try_send(&Request::new(Method::POST, url(&server.url("/x"))))
        .await
        .unwrap_err();
    assert_eq!(e.error().kind(), ErrorKind::Transient, "{e:?}");
    assert!(!e.certainly_unsent(), "{e:?}");
    assert_eq!(proxy.log().len(), 1);
    // The same after the target answered slowly through a passing proxy.
    proxy.set_behavior(Behavior::Pass);
    server
        .faults()
        .push(Fault::any().always().delay(Duration::from_secs(3600)));
    let e = http
        .try_send(&Request::new(Method::POST, url(&server.url("/y"))))
        .await
        .unwrap_err();
    assert_eq!(e.error().kind(), ErrorKind::Transient, "{e:?}");
    assert!(!e.certainly_unsent(), "{e:?}");
    assert_eq!(server.log().len(), 1);
}

// --- policies ---

#[tokio::test]
async fn the_target_policies_are_unchanged_by_the_proxy() {
    let server = ok_server().await;
    let other = ok_server().await;
    let proxy = ProxyServer::start().await;
    let ctx = testing::context(with_proxy(&proxy.url(), true));
    // `loopback_only` applies to the request URL, whatever the proxy.
    let http = testing::http(&ctx, |b| b);
    for raw in ["https://192.0.2.1/x", "https://example.invalid/x"] {
        let e = http.try_send(&post_to(raw)).await.unwrap_err();
        assert_eq!(e.error().kind(), ErrorKind::Config, "{raw}");
        assert!(e.certainly_unsent());
    }
    // Credentials go only to declared endpoints.
    let bound = bearer_http(&ctx, &server.base_url());
    let e = bound.try_send(&get(&other, "/x")).await.unwrap_err();
    assert_eq!(e.error().kind(), ErrorKind::Config, "{e:?}");
    assert!(e.certainly_unsent());
    assert_eq!(proxy.connections(), 0);
    assert_eq!(other.connections(), 0);
    // The URL policy: plain HTTP only for loopback literals.
    let e = http
        .try_send(&post_to("http://10.0.0.1/x"))
        .await
        .unwrap_err();
    assert_eq!(e.error().kind(), ErrorKind::Config);
    assert_eq!(proxy.connections(), 0);
}

#[tokio::test]
async fn plain_http_is_never_forwarded_to_a_proxy_off_the_host() {
    let server = ok_server().await;
    let proxy = ProxyServer::start().await;
    // A proxy named by a host name is not a loopback IP literal, so the policy treats it as off
    // the host. The name is `localhost` and the proxy a local one, so that even a transport that
    // broke the rule would reach nothing but this test's proxy, which counts the attempt. Not
    // `loopback_only`, so that the setting itself is accepted.
    let ctx = testing::context(ContextOptions {
        loopback_only: false,
        ..with_proxy(&format!("http://localhost:{}", proxy.addr().port()), true)
    });
    let http = testing::http(&ctx, |b| b);
    let e = http.try_send(&get(&server, "/x")).await.unwrap_err();
    assert_eq!(e.error().kind(), ErrorKind::Config, "{e:?}");
    assert!(e.error().to_string().contains("plain-HTTP"), "{e:?}");
    assert!(e.certainly_unsent());
    assert_eq!(proxy.connections(), 0);
    assert_eq!(server.connections(), 0);
}

#[test]
fn proxy_settings_are_checked_by_the_context() {
    for (raw, loopback_only) in [
        ("http://user:pw-canary@127.0.0.1:3128", true),
        ("socks4://127.0.0.1:1080", true),
        ("http://127.0.0.1:3128/path", true),
        ("http://192.0.2.1:3128", true),
    ] {
        let mut options = with_proxy(raw, true);
        options.loopback_only = loopback_only;
        let e = crate::context::Context::new(options).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{raw}");
        let text = format!("{e} {e:?}");
        assert!(text.contains("proxy.url"), "{text}");
        assert!(
            !text.contains("canary") && !text.contains("192.0.2.1"),
            "{text}"
        );
    }
    // Debug of the options, the context and a handle shows no credential.
    let mut options = with_proxy("http://127.0.0.1:3128", true);
    let ctx = testing::context(options.clone());
    let http = testing::http(&ctx, |b| b);
    let text = format!("{options:?} {ctx:?} {:?} {http:?}", ctx.http());
    assert_clean("Debug", &text, &[CANARY_TOKEN]);
    assert!(
        text.contains("127.0.0.1:3128") && text.contains("proxied: true"),
        "{text}"
    );
    options.proxy = Some(HttpProxy::new(
        "http://u:pw-canary@127.0.0.1:3128".to_owned(),
    ));
    assert!(!format!("{options:?}").contains("canary"));
}

// --- the environment ---

/// Set in the environment of the child process of
/// [`proxy_variables_are_ignored_with_the_setting`].
const PROXY_SETTING_CHILD: &str = "ZONEWRIGHT_TEST_PROXY_SETTING_CHILD";

#[test]
fn proxy_variables_are_ignored_with_the_setting() {
    if std::env::var_os(PROXY_SETTING_CHILD).is_some() {
        return;
    }
    // As in `tests.rs`: the variables must be set before `reqwest` reads them, so the check
    // runs in a child process. They point at a silent server; `NO_PROXY` names the target, which
    // would make an environment-driven client bypass any proxy for it.
    let silent = SilentServer::start();
    let env_proxy = format!("http://{}", silent.addr);
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "http::proxy_tests::proxy_setting_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROXY_SETTING_CHILD, "1")
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1");
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env(name, &env_proxy);
    }
    let out = command.output().unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("1 passed"), "the child ran the test: {text}");
    // Only the control client of the child went to the proxy of the environment.
    assert_eq!(silent.connections.load(Ordering::SeqCst), 1, "{text}");
}

#[tokio::test]
async fn proxy_setting_child() {
    if std::env::var_os(PROXY_SETTING_CHILD).is_none() {
        return;
    }
    let server = ok_server().await;
    let proxy = ProxyServer::start().await;
    let ctx = testing::context(with_proxy(&proxy.url(), true));
    let http = testing::http(&ctx, |b| b);
    assert_eq!(http.send(&get(&server, "/x")).await.unwrap().status(), 200);
    // Through the configured proxy, although `NO_PROXY` names the target.
    assert_eq!(proxy.log().len(), 1);
    assert_eq!(server.log().len(), 1);
    // Control: a client that reads the environment sends a request for another loopback
    // address to the environment's proxy, so the variables are in effect.
    let provider = super::tls::crypto_provider();
    let trust = super::tls::Trust::from_options(&ContextOptions::default(), &provider).unwrap();
    let control = reqwest::Client::builder()
        .tls_backend_preconfigured(super::tls::client_config(&provider, &trust, None).unwrap())
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    let _ = control.get("http://[::1]:9/via-env").send().await;
    assert_eq!(proxy.log().len(), 1);
}

// --- secrets ---

/// Every error a proxy can cause, with the proxy echoing the credentials it received in the body
/// of its `407` and of its refusals, and the captured `tracing` events: no spelling of the proxy
/// password anywhere.
#[tokio::test]
async fn the_proxy_password_never_reaches_errors_or_tracing() {
    let (target, ca) = https_target();
    let server = ok_server().await;
    let ctx_options = |proxy: &ProxyServer| ContextOptions {
        extra_root_certificates: vec![ca.clone()],
        ..with_proxy(&proxy.url(), true)
    };
    // The contexts are built before the capture (a host without CA certificates logs a warning).
    let demanding = ProxyServer::start().await;
    demanding.require_basic(PROXY_USER, "the-right-password");
    let refusing = ProxyServer::start().await;
    refusing.require_basic(PROXY_USER, CANARY_TOKEN);
    let ctx_demanding = testing::context(ctx_options(&demanding));
    let ctx_refusing = testing::context(ctx_options(&refusing));
    let (capture, _guard) = LogCapture::install();
    let token = basic(PROXY_USER, CANARY_TOKEN);
    let token = token.trim_start_matches("Basic ");
    let mut errors: Vec<Error> = Vec::new();

    // 407 to CONNECT and to a forwarded request.
    let http = bearer_http(&ctx_demanding, &format!("https://{}", target.addr));
    errors.push(http.send(&post_to(&target.url())).await.unwrap_err());
    let http = testing::http(&ctx_demanding, |b| b);
    errors.push(
        http.send(&Request::new(Method::POST, url(&server.url("/x"))))
            .await
            .unwrap_err(),
    );
    assert_eq!(demanding.log().len(), 2);

    // Refusals whose body reaches the error: a forwarded request answered 502 (the transport's
    // 5xx path) and 400 (the client's classification).
    let mut detailed = 0;
    for status in [502, 400, 403] {
        refusing.set_behavior(Behavior::Refuse(status));
        let http = bearer_http(&ctx_refusing, &server.base_url());
        let request = Request::new(Method::POST, url(&server.url("/x")));
        let e = match http.send(&request).await {
            Ok(response) => http.reject(&response),
            Err(e) => e,
        };
        // The echo reached the error text and was cut out.
        assert!(e.to_string().contains(REDACTED), "{status}: {e}");
        detailed += 1;
        errors.push(e);
        // A refused CONNECT: the body is never read.
        let http = bearer_http(&ctx_refusing, &format!("https://{}", target.addr));
        errors.push(http.send(&post_to(&target.url())).await.unwrap_err());
    }
    assert_eq!(detailed, 3);
    assert!(server.log().is_empty());

    for e in &errors {
        for text in [e.to_string(), format!("{e:?}")] {
            assert_clean("an error", &text, &[CANARY_TOKEN, CANARY_KEY]);
            assert!(!text.contains(token), "the base64 credentials leak: {text}");
        }
    }
    let log = capture.text();
    assert!(!capture.entries().is_empty());
    assert_clean("the captured log", &log, &[CANARY_TOKEN, CANARY_KEY]);
    assert!(!log.contains(token), "{log}");
    assert!(
        !log.to_ascii_lowercase().contains("proxy-authorization"),
        "{log}"
    );
}

// --- SOCKS5 ---

/// The options of [`with_proxy`] with `exclusions`.
fn excluding(mut options: ContextOptions, exclusions: &[&str]) -> ContextOptions {
    let list = exclusions.iter().map(|e| (*e).to_owned()).collect();
    options.proxy = options.proxy.map(|p| p.with_exclusions(list));
    options
}

#[cfg(feature = "socks")]
#[tokio::test]
async fn requests_go_through_a_socks5_proxy_without_credentials() {
    let server = ok_server().await;
    let (target, ca) = https_target();
    let socks = SocksServer::start().await;
    for scheme in ["socks5", "socks5h"] {
        let before = socks.log().len();
        let ctx = testing::context(ContextOptions {
            extra_root_certificates: vec![ca.clone()],
            ..with_proxy(&socks.url(scheme), false)
        });
        let http = bearer_http(&ctx, &server.base_url());
        assert_eq!(
            http.send(&get(&server, "/x?q=1")).await.unwrap().status(),
            200
        );
        let http = testing::http(&ctx, |b| b);
        let response = http.send(&Request::get(url(&target.url()))).await.unwrap();
        assert_eq!(response.status(), 200);
        let log = socks.log();
        assert_eq!(log.len(), before + 2, "{scheme}");
        for (entry, addr) in log[before..].iter().zip([server.addr(), target.addr]) {
            assert_eq!(entry.methods, [0x00], "{scheme}");
            assert!(entry.authenticated && entry.username.is_none(), "{scheme}");
            // An IP-literal URL is sent as an address in both modes.
            assert_eq!(entry.destination, Some(Destination::Ip(addr)), "{scheme}");
        }
        // The plain-HTTP request reached the server in origin form, with the provider
        // credential and without any proxy header.
        let logged = server.log().last().unwrap();
        assert_eq!(logged.path, "/x");
        assert!(logged.header("proxy-authorization").is_none());
        assert_eq!(
            logged.header("authorization"),
            Some(format!("Bearer {CANARY_KEY}").as_str())
        );
    }
    assert_eq!(target.answered.load(Ordering::SeqCst), 2);
}

#[cfg(feature = "socks")]
#[tokio::test]
async fn a_socks5_proxy_gets_the_credentials_with_rfc_1929() {
    let server = ok_server().await;
    let socks = SocksServer::start().await;
    // The canary password contains `@`, `:`-free punctuation, `/`, `+`, quotes and spaces: it is
    // percent-encoded into the proxy URL and must arrive unchanged.
    socks.require_credentials(PROXY_USER, CANARY_TOKEN);
    for scheme in ["socks5", "socks5h"] {
        let ctx = testing::context(with_proxy(&socks.url(scheme), true));
        let http = testing::http(&ctx, |b| b);
        assert_eq!(http.send(&get(&server, "/x")).await.unwrap().status(), 200);
    }
    let log = socks.log();
    assert_eq!(log.len(), 2);
    for entry in &log {
        assert_eq!(entry.methods, [0x02]);
        assert_eq!(entry.username.as_deref(), Some(PROXY_USER));
        assert_eq!(entry.password.as_deref(), Some(CANARY_TOKEN));
        assert!(entry.authenticated);
    }
    assert_eq!(server.log().len(), 2);
}

#[cfg(feature = "socks")]
#[tokio::test]
async fn a_refused_socks5_authentication_is_proxy_auth_and_not_retried() {
    let server = ok_server().await;
    let socks = SocksServer::start().await;
    socks.require_credentials(PROXY_USER, "the-right-password");
    // With the wrong password, and without credentials (no acceptable method).
    for auth in [true, false] {
        let ctx = testing::context(with_proxy(&socks.url("socks5"), auth));
        let http = testing::http(&ctx, |b| b);
        for request in [
            get(&server, "/x"),
            Request::new(Method::POST, url(&server.url("/x"))),
        ] {
            let before = socks.connections();
            let e = http.try_send(&request).await.unwrap_err();
            assert_eq!(e.error().kind(), ErrorKind::ProxyAuth, "{auth}: {e:?}");
            assert!(!e.error().is_retryable());
            assert!(e.certainly_unsent(), "{e:?}");
            // One attempt, idempotent or not.
            assert_eq!(socks.connections(), before + 1);
        }
    }
    let log = socks.log();
    assert_eq!(log.len(), 4);
    for entry in &log[..2] {
        assert_eq!(entry.methods, [0x02]);
        assert_eq!(entry.password.as_deref(), Some(CANARY_TOKEN));
        assert!(!entry.authenticated && entry.destination.is_none());
    }
    for entry in &log[2..] {
        assert_eq!(entry.methods, [0x00]);
        assert!(entry.username.is_none() && !entry.authenticated);
    }
    assert_eq!(server.connections(), 0);
}

#[cfg(feature = "socks")]
#[tokio::test]
async fn socks5_resolves_names_locally_and_socks5h_at_the_proxy() {
    let (ca, issuer) = testing::ca();
    let (leaf, key) = testing::server_cert_for(&issuer, &["localhost"]);
    let target = TlsServer::start(vec![leaf], key);
    let port = target.addr.port();
    let named = format!("https://localhost:{port}/tls");
    let socks = SocksServer::start().await;
    // Not `loopback_only`, so that the URL can name a host. The name is `localhost`, and the mock
    // proxy resolves no other, so nothing leaves the host.
    let context = |proxy: HttpProxy| {
        testing::context(ContextOptions {
            loopback_only: false,
            extra_root_certificates: vec![ca.der().to_vec()],
            proxy: Some(proxy),
            ..testing::options()
        })
    };
    // `socks5h`: the proxy gets the name.
    let ctx = context(HttpProxy::new(socks.url("socks5h")));
    let http = testing::http(&ctx, |b| b);
    let response = http.send(&Request::get(url(&named))).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        socks.log()[0].destination,
        Some(Destination::Domain("localhost".to_owned(), port))
    );
    // `socks5`: the client resolved the name and the proxy gets an address. Which loopback
    // address the resolver returns first is the platform's choice, so the outcome of the
    // request is not the subject; a POST is not repeated.
    let ctx = context(HttpProxy::new(socks.url("socks5")));
    let http = testing::http(&ctx, |b| b);
    let _ = http.send(&post_to(&named)).await;
    let log = socks.log();
    assert_eq!(log.len(), 2);
    match &log[1].destination {
        Some(Destination::Ip(addr)) => {
            assert!(addr.ip().is_loopback() && addr.port() == port, "{addr}")
        }
        other => panic!("the proxy got {other:?}"),
    }
    // The longest credentials the crate accepts fit `hyper-util`'s handshake buffer together
    // with a host name.
    let password = "p".repeat(super::proxy::SOCKS_CREDENTIALS_MAX - 1);
    socks.require_credentials("u", &password);
    let ctx = context(
        HttpProxy::new(socks.url("socks5h"))
            .with_credentials("u".to_owned(), SecretString::from(password.clone())),
    );
    let http = testing::http(&ctx, |b| b);
    assert_eq!(
        http.send(&Request::get(url(&named)))
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(socks.log()[2].password.as_deref(), Some(password.as_str()));
}

// --- exclusions ---

/// A plain-HTTP server on `[::1]` that answers every request `200` and closes the connection:
/// a second loopback host next to the mock servers on `127.0.0.1`. Plain HTTP, because
/// `reqwest` 0.13.5 cannot reach an `https://` IPv6 literal through a proxy: it passes the
/// bracketed host to `ServerName::try_from` (`connect.rs`, `connect_via_proxy` and
/// `connect_socks`; observed on 2026-11-15).
struct V6Server {
    addr: std::net::SocketAddr,
    requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl V6Server {
    async fn start() -> V6Server {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = requests.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let log = log.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&head).into_owned();
                    log.lock()
                        .unwrap()
                        .push(text.lines().next().unwrap_or("").to_owned());
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        V6Server { addr, requests }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

#[tokio::test]
async fn excluded_hosts_are_reached_directly() {
    let server = ok_server().await;
    let v6 = V6Server::start().await;
    let proxy = ProxyServer::start().await;
    let options = |exclusions: &[&str]| excluding(with_proxy(&proxy.url(), true), exclusions);
    // `127.0.0.0/8` excluded: the server on 127.0.0.1 directly, the one on [::1] through the
    // proxy.
    let http = testing::http(&testing::context(options(&["127.0.0.0/8"])), |b| b);
    assert_eq!(
        http.send(&get(&server, "/direct")).await.unwrap().status(),
        200
    );
    assert!(proxy.log().is_empty());
    assert_eq!(server.log().len(), 1);
    let response = http.send(&Request::get(url(&v6.url("/a")))).await.unwrap();
    assert_eq!(response.status(), 200);
    let log = proxy.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].target, v6.url("/a"));
    // `::1` excluded: the other way round.
    let http = testing::http(&testing::context(options(&["::1"])), |b| b);
    assert_eq!(
        http.send(&get(&server, "/proxied")).await.unwrap().status(),
        200
    );
    let log = proxy.log();
    assert_eq!(log.len(), 2);
    assert_eq!(log[1].target, server.url("/proxied"));
    let response = http.send(&Request::get(url(&v6.url("/b")))).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(proxy.log().len(), 2);
    assert_eq!(
        *v6.requests.lock().unwrap(),
        ["GET /a HTTP/1.1", "GET /b HTTP/1.1"]
    );
    // A SOCKS5 proxy follows the list the same way. `socks5h`, because with `socks5` `reqwest`
    // 0.13.5 hands the bracketed IPv6 host to its resolver, which fails (`connect.rs`,
    // `socks::connect`, `http_resolve`).
    #[cfg(feature = "socks")]
    {
        let socks = SocksServer::start().await;
        let ctx = testing::context(excluding(
            with_proxy(&socks.url("socks5h"), false),
            &["127.0.0.1"],
        ));
        let http = testing::http(&ctx, |b| b);
        assert_eq!(
            http.send(&get(&server, "/direct")).await.unwrap().status(),
            200
        );
        assert_eq!(socks.connections(), 0);
        let response = http.send(&Request::get(url(&v6.url("/c")))).await.unwrap();
        assert_eq!(response.status(), 200);
        let log = socks.log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].destination, Some(Destination::Ip(v6.addr)));
    }
}

#[tokio::test]
async fn an_excluded_host_is_outside_the_proxy_rules() {
    let server = ok_server().await;
    let proxy = ProxyServer::start().await;
    // Through a proxy that is not a loopback IP literal plain HTTP is refused (see
    // `plain_http_is_never_forwarded_to_a_proxy_off_the_host`), but an excluded loopback host
    // is reached directly.
    let options = excluding(
        ContextOptions {
            loopback_only: false,
            ..with_proxy(&format!("http://localhost:{}", proxy.addr().port()), true)
        },
        &["127.0.0.1"],
    );
    let http = testing::http(&testing::context(options), |b| b);
    assert_eq!(http.send(&get(&server, "/x")).await.unwrap().status(), 200);
    assert_eq!(proxy.connections(), 0);
    // A 407 answered by an excluded host, or relayed through a SOCKS5 proxy, is the provider's
    // status, not a refusal of the proxy credentials.
    server.faults().push(Fault::any().always().status(407));
    let response = http.send(&get(&server, "/y")).await.unwrap();
    assert_eq!(response.status(), 407);
    #[cfg(feature = "socks")]
    {
        let socks = SocksServer::start().await;
        let ctx = testing::context(with_proxy(&socks.url("socks5"), false));
        let response = testing::http(&ctx, |b| b)
            .send(&get(&server, "/z"))
            .await
            .unwrap();
        assert_eq!(response.status(), 407);
        assert_eq!(socks.log().len(), 1);
    }
    assert_eq!(proxy.connections(), 0);
}

#[test]
fn invalid_exclusions_are_refused_by_the_context() {
    for entry in [
        "*",
        ".example.org",
        "exc-canary.example.org:443",
        "10.0.0.1/8",
    ] {
        let options = excluding(
            with_proxy("http://127.0.0.1:3128", true),
            &["api.example.org", entry],
        );
        let e = crate::context::Context::new(options).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{entry}");
        let text = format!("{e} {e:?}");
        assert!(text.contains("proxy.exclusions[1]"), "{text}");
        assert!(
            !text.contains("canary") && !text.contains("example"),
            "{text}"
        );
    }
}

/// The SOCKS5 password, in any spelling, in no error, `Debug` output or `tracing` event: a
/// refused password, an unreachable proxy, a successful request and a provider error through
/// the proxy.
#[cfg(feature = "socks")]
#[tokio::test]
async fn the_socks5_password_never_reaches_errors_debug_or_tracing() {
    let server = ok_server().await;
    let refusing = SocksServer::start().await;
    refusing.require_credentials(PROXY_USER, "the-right-password");
    let accepting = SocksServer::start().await;
    accepting.require_credentials(PROXY_USER, CANARY_TOKEN);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = listener.local_addr().unwrap();
    drop(listener);
    let accepting_options = with_proxy(&accepting.url("socks5h"), true);
    let ctx_refusing = testing::context(with_proxy(&refusing.url("socks5h"), true));
    let ctx_closed = testing::context(with_proxy(&format!("socks5://{closed}"), true));
    let ctx_accepting = testing::context(accepting_options.clone());
    let echoing = SocksServer::start().await;
    echoing.require_credentials(PROXY_USER, CANARY_TOKEN);
    echoing.echo_credentials();
    let ctx_echoing = testing::context(with_proxy(&echoing.url("socks5"), true));
    // The contexts are built before the capture (a host without CA certificates logs a warning).
    let (capture, _guard) = LogCapture::install();
    let mut errors: Vec<Error> = Vec::new();

    let http = testing::http(&ctx_refusing, |b| b);
    let e = http.send(&get(&server, "/x")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ProxyAuth);
    errors.push(e);
    let http = testing::http(&ctx_closed, |b| b);
    let e = http.send(&post_to(&server.url("/x"))).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient);
    errors.push(e);
    let http = bearer_http(&ctx_accepting, &server.base_url());
    assert_eq!(http.send(&get(&server, "/ok")).await.unwrap().status(), 200);
    server.faults().push(Fault::any().always().status(502));
    errors.push(http.send(&post_to(&server.url("/x"))).await.unwrap_err());
    // A proxy that answers a plain-HTTP request itself with the credentials it received: the
    // echo reaches the error text and is cut out.
    let echo_http = testing::http(&ctx_echoing, |b| b);
    let response = echo_http.send(&get(&server, "/echo")).await.unwrap();
    assert_eq!(response.status(), 400);
    let e = echo_http.reject(&response);
    assert!(e.to_string().contains(REDACTED), "{e}");
    errors.push(e);
    // Both requests reached the server through the proxy (on one pooled connection or two).
    assert_eq!(server.log().len(), 2);
    assert!(accepting.log().iter().all(|e| e.authenticated));
    assert!(!accepting.log().is_empty());
    assert_eq!(refusing.log()[0].password.as_deref(), Some(CANARY_TOKEN));

    for e in &errors {
        for text in [e.to_string(), format!("{e:?}")] {
            assert_clean("an error", &text, &[CANARY_TOKEN, CANARY_KEY]);
        }
    }
    let debug = format!(
        "{accepting_options:?} {ctx_accepting:?} {:?} {http:?} {:?}",
        ctx_accepting.http(),
        ctx_accepting.http().client
    );
    assert_clean("Debug", &debug, &[CANARY_TOKEN]);
    assert!(debug.contains("proxied: true"), "{debug}");
    let log = capture.text();
    assert!(!capture.entries().is_empty());
    assert_clean("the captured log", &log, &[CANARY_TOKEN, CANARY_KEY]);
}
