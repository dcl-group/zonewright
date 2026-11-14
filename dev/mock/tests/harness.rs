//! Self-tests of the shared harness: server lifecycle, request log, fault injection and the echo
//! server. Requests are written by hand over a raw `TcpStream`, so the crate needs no HTTP client.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::{get, post};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zonewright_mock::echo::{self, Echo, EchoServer, Spelling};
use zonewright_mock::{Fault, MockServer};

const TIMEOUT: Duration = Duration::from_secs(10);

/// A parsed answer, or what arrived before the connection closed.
#[derive(Debug)]
struct Answer {
    raw: Vec<u8>,
    status: Option<u16>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    fn parse(raw: Vec<u8>) -> Self {
        let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
            return Self {
                raw,
                status: None,
                headers: Vec::new(),
                body: Vec::new(),
            };
        };
        let head = String::from_utf8_lossy(&raw[..end]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|s| s.parse().ok());
        let headers = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        let body = raw[end + 4..].to_vec();
        Self {
            raw,
            status,
            headers,
            body,
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn request(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut r = format!("{method} {path} HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n");
    for (n, v) in headers {
        r.push_str(&format!("{n}: {v}\r\n"));
    }
    r.push_str(&format!("content-length: {}\r\n\r\n{body}", body.len()));
    r.into_bytes()
}

/// Sends one request and reads until the server closes the connection. A reset counts as a close.
async fn send_raw(addr: SocketAddr, bytes: &[u8]) -> Answer {
    tokio::time::timeout(TIMEOUT, async {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(bytes).await.unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw).await;
        Answer::parse(raw)
    })
    .await
    .expect("answer within the timeout")
}

async fn send(addr: SocketAddr, method: &str, path: &str) -> Answer {
    send_raw(addr, &request(method, path, &[], "")).await
}

fn hello_router() -> Router {
    Router::new().route("/hello", get(|| async { "hi" })).route(
        "/zones/{id}/records",
        post(|body: Bytes| async move { body }),
    )
}

#[tokio::test]
async fn start_serves_and_logs_everything() {
    let server = MockServer::start(hello_router()).await;
    assert!(server.addr().ip().is_loopback());
    assert_eq!(server.base_url(), format!("http://{}", server.addr()));
    assert_eq!(server.url("/x"), format!("http://{}/x", server.addr()));

    let a = send(server.addr(), "GET", "/hello?a=1&b=two").await;
    assert_eq!(a.status, Some(200));
    assert_eq!(a.body_str(), "hi");

    let body = r#"{"name":"_acme-challenge"}"#;
    let a = send_raw(
        server.addr(),
        &request(
            "POST",
            "/zones/z1/records",
            &[("authorization", "Bearer tok/en+1"), ("x-api-key", "k@y")],
            body,
        ),
    )
    .await;
    assert_eq!(a.status, Some(200));
    assert_eq!(a.body_str(), body);

    let log = server.log();
    assert_eq!(log.len(), 2);
    let entries = log.entries();
    assert_eq!(entries[0].seq, 0);
    assert_eq!(entries[0].method, "GET");
    assert_eq!(entries[0].path, "/hello");
    assert_eq!(entries[0].query.as_deref(), Some("a=1&b=two"));
    assert_eq!(entries[0].status, Some(200));
    assert!(!entries[0].faulted);
    assert_eq!(entries[1].seq, 1);
    assert_eq!(entries[1].header("authorization"), Some("Bearer tok/en+1"));
    assert_eq!(entries[1].header("X-Api-Key"), Some("k@y"));
    assert_eq!(entries[1].body_str(), body);
    assert_eq!(entries[1].body_json().unwrap()["name"], "_acme-challenge");
    assert_eq!(log.count(Some("post"), "/zones/*/records"), 1);
    assert_eq!(log.count(None, "/zones/**"), 1);
    assert_eq!(log.matching(Some("GET"), "/hello").len(), 1);
    assert!(log.contains("tok/en+1"));
    assert!(log.contains(b"k@y"));
    assert!(log.contains("b=two"));
    assert!(!log.contains("absent-canary"));
    assert_eq!(log.last().unwrap().path, "/zones/z1/records");
    assert!(server.connections() >= 2);

    log.clear();
    assert!(log.is_empty());
    send(server.addr(), "GET", "/hello").await;
    assert_eq!(log.entries()[0].seq, 0);
}

#[tokio::test]
async fn unrouted_requests_are_logged_and_faultable() {
    let server = MockServer::start(hello_router()).await;
    let a = send(server.addr(), "DELETE", "/nowhere").await;
    assert_eq!(a.status, Some(404));
    assert_eq!(server.log().entries()[0].status, Some(404));

    server.faults().push(Fault::path("/nowhere").status(418));
    let a = send(server.addr(), "GET", "/nowhere").await;
    assert_eq!(a.status, Some(418));
}

#[tokio::test]
async fn status_fault_applies_n_times_then_passes() {
    let server = MockServer::start(hello_router()).await;
    server
        .faults()
        .push(Fault::on("GET", "/hello").times(2).respond(503, "busy"));
    assert_eq!(server.faults().pending(), 1);

    // A request that does not match is untouched.
    assert_eq!(
        send(server.addr(), "POST", "/hello").await.status,
        Some(405)
    );
    let a = send(server.addr(), "GET", "/hello").await;
    assert_eq!((a.status, a.body_str().as_str()), (Some(503), "busy"));
    assert_eq!(send(server.addr(), "GET", "/hello").await.status, Some(503));
    assert_eq!(server.faults().pending(), 0);
    assert_eq!(send(server.addr(), "GET", "/hello").await.status, Some(200));

    let faulted: Vec<bool> = server.log().entries().iter().map(|e| e.faulted).collect();
    assert_eq!(faulted, [false, true, true, false]);
    let statuses: Vec<_> = server.log().entries().iter().map(|e| e.status).collect();
    assert_eq!(statuses, [Some(405), Some(503), Some(503), Some(200)]);
}

#[tokio::test]
async fn skip_always_clear_and_order() {
    let server = MockServer::start(hello_router()).await;
    server
        .faults()
        .push(Fault::any().skip(1).always().status(500));
    // Pushed later: never reached while the first one matches.
    server.faults().push(Fault::any().status(401));

    assert_eq!(send(server.addr(), "GET", "/hello").await.status, Some(200));
    for _ in 0..3 {
        assert_eq!(send(server.addr(), "GET", "/hello").await.status, Some(500));
    }
    assert_eq!(server.faults().pending(), 2);
    server.faults().clear();
    assert_eq!(send(server.addr(), "GET", "/hello").await.status, Some(200));
}

#[tokio::test]
async fn times_zero_removes_without_acting() {
    let server = MockServer::start(hello_router()).await;
    server.faults().push(Fault::any().times(0).status(500));
    assert_eq!(send(server.addr(), "GET", "/hello").await.status, Some(200));
    assert_eq!(server.faults().pending(), 0);
}

#[tokio::test]
async fn predicate_narrows_the_match() {
    let server = MockServer::start(hello_router()).await;
    server.faults().push(
        Fault::on("POST", "/zones/*/records")
            .when(|r| r.body_str().contains("victim"))
            .status(409),
    );
    let post = |body: &'static str| {
        let addr = server.addr();
        async move { send_raw(addr, &request("POST", "/zones/a/records", &[], body)).await }
    };
    assert_eq!(post("other").await.status, Some(200));
    assert_eq!(post("the victim").await.status, Some(409));
    assert_eq!(post("the victim").await.status, Some(200));
}

#[tokio::test]
async fn rate_limited_and_extra_headers() {
    let server = MockServer::start(hello_router()).await;
    server.faults().push(Fault::any().rate_limited("2"));
    server
        .faults()
        .push(Fault::any().header("ratelimit-reset", "1700000000"));

    let a = send(server.addr(), "GET", "/hello").await;
    assert_eq!(a.status, Some(429));
    assert_eq!(a.header("retry-after"), Some("2"));

    // A header on a pass-through fault is added to the mock's own answer.
    let a = send(server.addr(), "GET", "/hello").await;
    assert_eq!(a.status, Some(200));
    assert_eq!(a.body_str(), "hi");
    assert_eq!(a.header("ratelimit-reset"), Some("1700000000"));
}

#[tokio::test]
async fn redirect_points_elsewhere_and_target_sees_nothing() {
    let server = MockServer::start(hello_router()).await;
    let target = MockServer::start(hello_router()).await;
    server
        .faults()
        .push(Fault::any().redirect(307, &target.url("/hello")));
    let a = send(server.addr(), "POST", "/zones/z/records").await;
    assert_eq!(a.status, Some(307));
    assert_eq!(a.header("location"), Some(target.url("/hello").as_str()));
    assert_eq!(target.connections(), 0);
    assert!(target.log().is_empty());
}

#[tokio::test]
async fn oversized_bodies() {
    let server = MockServer::start(hello_router()).await;
    let len = 5 * 1024 * 1024 + 7;
    server.faults().push(Fault::any().oversized_body(200, len));
    let a = send(server.addr(), "GET", "/hello").await;
    assert_eq!(a.status, Some(200));
    assert_eq!(a.header("content-length"), Some(len.to_string().as_str()));
    assert_eq!(a.body.len(), len);

    server
        .faults()
        .push(Fault::any().oversized_chunked_body(500, len));
    let a = send(server.addr(), "GET", "/hello").await;
    assert_eq!(a.status, Some(500));
    assert_eq!(a.header("transfer-encoding"), Some("chunked"));
    assert_eq!(a.header("content-length"), None);
    assert_eq!(decode_chunked(&a.body), len);
    assert_eq!(server.log().entries()[1].status, None);
}

fn decode_chunked(mut body: &[u8]) -> usize {
    let mut total = 0;
    loop {
        let eol = body.windows(2).position(|w| w == b"\r\n").unwrap();
        let size = usize::from_str_radix(std::str::from_utf8(&body[..eol]).unwrap(), 16).unwrap();
        body = &body[eol + 2..];
        if size == 0 {
            return total;
        }
        assert!(body[..size].iter().all(|&b| b == b'x'));
        total += size;
        assert_eq!(&body[size..size + 2], b"\r\n");
        body = &body[size + 2..];
    }
}

#[tokio::test]
async fn dropped_connection_sends_nothing_and_server_survives() {
    let server = MockServer::start(hello_router()).await;
    server
        .faults()
        .push(Fault::on("GET", "/hello").drop_connection());
    let a = send(server.addr(), "GET", "/hello").await;
    assert!(
        a.raw.is_empty(),
        "got {:?}",
        String::from_utf8_lossy(&a.raw)
    );
    let entry = server.log().entries()[0].clone();
    assert!(entry.faulted);
    assert_eq!(entry.status, None);
    assert_eq!(send(server.addr(), "GET", "/hello").await.status, Some(200));
}

#[tokio::test]
async fn dropped_connection_on_a_kept_alive_connection() {
    let server = MockServer::start(hello_router()).await;
    server
        .faults()
        .push(Fault::on("GET", "/hello").skip(1).drop_connection());
    let mut s = TcpStream::connect(server.addr()).await.unwrap();
    let keep = b"GET /hello HTTP/1.1\r\nhost: x\r\n\r\n";
    s.write_all(keep).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(TIMEOUT, s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
    s.write_all(keep).await.unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(TIMEOUT, s.read_to_end(&mut rest))
        .await
        .unwrap();
    assert!(rest.is_empty());
    assert_eq!(server.connections(), 1);
}

#[tokio::test]
async fn truncated_body_closes_early() {
    let server = MockServer::start(hello_router()).await;
    server
        .faults()
        .push(Fault::any().truncated_body(200, 100, r#"{"result":"#));
    let a = send(server.addr(), "GET", "/hello").await;
    assert_eq!(a.status, Some(200));
    assert_eq!(a.header("content-length"), Some("100"));
    assert_eq!(a.body_str(), r#"{"result":"#);
}

#[tokio::test]
async fn slow_headers_pause_inside_the_head() {
    let server = MockServer::start(hello_router()).await;
    let pause = Duration::from_millis(300);
    server
        .faults()
        .push(Fault::any().slow_headers(201, pause, "{}"));
    let mut s = TcpStream::connect(server.addr()).await.unwrap();
    s.write_all(&request("GET", "/hello", &[], ""))
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(TIMEOUT, s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let first = Instant::now();
    assert_eq!(&buf[..n], b"HTTP/1.1 201 Created\r\n");
    let mut rest = Vec::new();
    s.read_to_end(&mut rest).await.unwrap();
    assert!(first.elapsed() >= pause - Duration::from_millis(50));
    let mut all = buf[..n].to_vec();
    all.extend(rest);
    let a = Answer::parse(all);
    assert_eq!(a.status, Some(201));
    assert_eq!(a.body_str(), "{}");
}

#[tokio::test]
async fn raw_script() {
    let server = MockServer::start(hello_router()).await;
    server.faults().push(Fault::any().raw(vec![
        (
            Duration::ZERO,
            Bytes::from_static(b"HTTP/1.1 502 Bad Gateway\r\n"),
        ),
        (
            Duration::from_millis(10),
            Bytes::from_static(b"content-length: 2\r\n\r\nno"),
        ),
    ]));
    let a = send(server.addr(), "GET", "/hello").await;
    assert_eq!(a.status, Some(502));
    assert_eq!(a.body_str(), "no");
}

#[tokio::test]
async fn delay_then_pass_through() {
    let server = MockServer::start(hello_router()).await;
    let delay = Duration::from_millis(200);
    server
        .faults()
        .push(Fault::on("GET", "/hello").delay(delay));
    let start = Instant::now();
    let a = send(server.addr(), "GET", "/hello").await;
    assert!(start.elapsed() >= delay);
    assert_eq!(a.body_str(), "hi");
    assert!(server.log().entries()[0].faulted);
}

#[tokio::test]
async fn delayed_request_does_not_block_others() {
    let server = MockServer::start(hello_router()).await;
    server
        .faults()
        .push(Fault::any().delay(Duration::from_millis(500)));
    let addr = server.addr();
    let slow = tokio::spawn(async move { send(addr, "GET", "/hello").await });
    // Wait until the slow request is logged, so it took the fault.
    while server.log().is_empty() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let start = Instant::now();
    assert_eq!(send(addr, "GET", "/hello").await.status, Some(200));
    assert!(start.elapsed() < Duration::from_millis(400));
    assert_eq!(slow.await.unwrap().status, Some(200));
    assert_eq!(server.log().entries()[0].status, Some(200));
}

#[tokio::test]
async fn hook_changes_state_before_the_mock_answers() {
    let state = Arc::new(Mutex::new(Vec::<String>::new()));
    let router =
        Router::new()
            .route(
                "/values",
                get(|State(s): State<Arc<Mutex<Vec<String>>>>| async move {
                    s.lock().unwrap().join(",")
                }),
            )
            .with_state(state.clone());
    let server = MockServer::start(router).await;
    let hooked = state.clone();
    let runs = Arc::new(AtomicUsize::new(0));
    let counted = runs.clone();
    server
        .faults()
        .push(Fault::on("GET", "/values").run(move || {
            hooked.lock().unwrap().push("foreign".into());
            counted.fetch_add(1, Ordering::SeqCst);
        }));
    assert_eq!(
        send(server.addr(), "GET", "/values").await.body_str(),
        "foreign"
    );
    assert_eq!(
        send(server.addr(), "GET", "/values").await.body_str(),
        "foreign"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn servers_are_independent_and_stop_on_drop() {
    let a = MockServer::start(hello_router()).await;
    let b = MockServer::start(hello_router()).await;
    assert_ne!(a.addr(), b.addr());
    a.faults().push(Fault::any().always().status(500));
    assert_eq!(send(b.addr(), "GET", "/hello").await.status, Some(200));
    assert_eq!(send(a.addr(), "GET", "/hello").await.status, Some(500));
    assert_eq!(a.log().len(), 1);
    assert_eq!(b.log().len(), 1);

    let addr = a.addr();
    drop(a);
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if TcpStream::connect(addr).await.is_err() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "server still accepting after drop"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// --- echo ---

const CANARY: &str = "can ary/sec+ret@1";

#[tokio::test]
async fn echo_repeats_headers_and_body_in_json() {
    let echo = EchoServer::start(400).await;
    let a = send_raw(
        echo.addr(),
        &request(
            "POST",
            "/v1/zones?x=1",
            &[("authorization", &format!("Bearer {CANARY}"))],
            &format!("password={CANARY}"),
        ),
    )
    .await;
    assert_eq!(a.status, Some(400));
    let v: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
    for field in [
        "error",
        "message",
        "description",
        "detail",
        "error_text",
        "error_description",
    ] {
        let t = v[field].as_str().unwrap();
        assert!(
            t.contains(&format!("authorization: Bearer {CANARY}")),
            "{t}"
        );
        assert!(t.contains(&format!("body: password={CANARY}")), "{t}");
        assert!(t.contains("request POST /v1/zones?x=1"), "{t}");
    }
    assert!(v["errors"][0]["message"].as_str().unwrap().contains(CANARY));
    assert_eq!(echo.api_requests(), 1);
    assert_eq!(echo.token_requests(), 0);
    assert!(echo.log().contains(CANARY));
}

#[tokio::test]
async fn echo_issues_tokens_and_echoes_them_back() {
    let echo = EchoServer::start(500).await;
    assert_eq!(echo.token_url(), echo.url(echo::DEFAULT_TOKEN_PATH));
    let a = send(echo.addr(), "POST", "/echo-token/v3/auth/tokens").await;
    assert_eq!(a.status, Some(201));
    assert_eq!(a.header("x-subject-token"), Some(echo.issued_token()));
    let v: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
    assert_eq!(v["access_token"], echo.issued_token());
    assert_eq!(v["iamToken"], echo.issued_token());
    assert_eq!(v["token"]["expires_at"], "2099-01-01T00:00:00Z");

    let token = echo.issued_token().to_owned();
    let a = send_raw(
        echo.addr(),
        &request("GET", "/zones", &[("x-auth-token", &token)], ""),
    )
    .await;
    assert_eq!(a.status, Some(500));
    let v: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
    assert!(v["message"].as_str().unwrap().contains(&token));
    assert_eq!(echo.token_requests(), 1);
    assert_eq!(echo.api_requests(), 1);
}

#[tokio::test]
async fn echo_custom_token_path_and_value() {
    let echo = Echo::new(401)
        .token_path("/oauth/token")
        .issued_token("tok@custom")
        .start()
        .await;
    assert!(echo.token_url().ends_with("/oauth/token"));
    let a = send(echo.addr(), "POST", "/oauth/token").await;
    let v: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
    assert_eq!(v["access_token"], "tok@custom");
    assert_eq!(
        send(echo.addr(), "GET", "/echo-token").await.status,
        Some(401)
    );
}

#[tokio::test]
async fn echo_renderers_and_spellings() {
    let echo = Echo::new(403)
        .render_under(
            "/xml",
            echo::xml("<ErrorResponse><Message>{text}</Message></ErrorResponse>"),
        )
        .render_under("/text", echo::text())
        .render_under("/ascii", echo::json_ascii())
        .render_under(
            "/custom",
            Arc::new(|e: &echo::Echoed| {
                use axum::response::IntoResponse;
                (e.status, format!("custom:{}", e.body)).into_response()
            }),
        )
        .start()
        .await;
    let post = |path: &'static str| {
        let addr = echo.addr();
        async move {
            send_raw(
                addr,
                &request("POST", path, &[("x-api-key", "<k&y>")], "a/b é"),
            )
            .await
        }
    };

    let a = post("/xml/zones").await;
    assert_eq!(a.status, Some(403));
    assert_eq!(a.header("content-type"), Some("application/xml"));
    let body = a.body_str();
    assert!(body.starts_with("<ErrorResponse><Message>request POST /xml/zones"));
    assert!(body.contains("x-api-key: &lt;k&amp;y&gt;"), "{body}");

    let a = post("/text").await;
    assert!(a.body_str().contains("x-api-key: <k&y>"));
    assert!(a.body_str().contains("body: a/b é"));

    let a = post("/ascii").await;
    let body = a.body_str();
    assert!(body.contains(r"body: a\/b \u00e9"), "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v["detail"].as_str().unwrap().contains("body: a/b é"));

    assert_eq!(post("/custom").await.body_str(), "custom:a/b é");

    let plus = Echo::new(400).spelling(Spelling::FormPlus).start().await;
    let a = send_raw(plus.addr(), &request("POST", "/", &[], CANARY)).await;
    let v: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("can+ary%2Fsec%2Bret%401")
    );

    let pct = Echo::new(400).spelling(Spelling::FormPercent).start().await;
    let a = send_raw(pct.addr(), &request("POST", "/", &[], CANARY)).await;
    let v: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("can%20ary%2Fsec%2Bret%401")
    );
}

#[tokio::test]
async fn echo_has_fault_injection() {
    let echo = EchoServer::start(400).await;
    echo.faults().push(Fault::any().status(502));
    assert_eq!(send(echo.addr(), "GET", "/").await.status, Some(502));
    assert_eq!(send(echo.addr(), "GET", "/").await.status, Some(400));
}
