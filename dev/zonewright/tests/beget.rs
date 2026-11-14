//! Tests of the Beget client (`beget`) against its mock.
#![cfg(feature = "beget")]
// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use secrecy::SecretString;
use serde_json::{Value, json};
use zonewright::providers::beget::{Beget, BegetConfig, BegetCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RemoveOutcome, RrSet, RrsetTtl, Txt, ValueGuarantee,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::StatusCode;
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::beget::{BegetMock, Seed, TxtField, input_of, params_of};
use zonewright_mock::echo::{EchoServer, Echoed, Render};

use common::echo::{CANARY_KEY, CANARY_PASSWORD, CANARY_TOKEN, LogCapture, REDACTED};
use common::echo::{Dialect, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The login and the API password of the standard seed.
const LOGIN: &str = "test-only-login";
const PASSWORD: &str = "test-only-password";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const LIST: &str = "/api/domain/getList";
const DATA: &str = "/api/dns/getData";
const CHANGE: &str = "/api/dns/changeRecords";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings pointed at the mock, without request pacing.
fn settings(mock: &BegetMock) -> BegetConfig {
    let mut config = BegetConfig::new(LOGIN.to_owned());
    config.base_url = mock.base_url();
    config.min_request_interval_ms = 0;
    config
}

fn credentials(password: &str) -> BegetCredentials {
    BegetCredentials::new(SecretString::from(password.to_owned()))
}

fn client_with(mock: &BegetMock, password: &str, ctx: &Context) -> Beget {
    Beget::new(settings(mock), credentials(password), ctx).unwrap()
}

async fn setup() -> (BegetMock, Beget) {
    let mock = BegetMock::start(Seed::standard()).await;
    let client = client_with(&mock, PASSWORD, &context());
    (mock, client)
}

/// Adds `value` at [`NAME`].
async fn add(client: &impl Provider, value: &str) -> Result<AddOutcome, Error> {
    client
        .add_txt_value(&zone(), &name(), &txt(value), None)
        .await
}

/// Removes `value` at [`NAME`].
async fn remove(client: &impl Provider, value: &str) -> Result<RemoveOutcome, Error> {
    client.remove_txt_value(&zone(), &name(), &txt(value)).await
}

/// Number of `changeRecords` requests the mock received.
fn writes(mock: &BegetMock) -> usize {
    mock.log().count(Some("POST"), CHANGE)
}

/// The `input_data` of the last `changeRecords` request.
fn last_change(mock: &BegetMock) -> Value {
    let request = mock.log().matching(Some("POST"), CHANGE).pop().unwrap();
    input_of(&request).unwrap()
}

/// The settings JSON of `from_json` for `mock`.
fn settings_json(mock: &BegetMock) -> String {
    json!({ "login": LOGIN, "base_url": mock.base_url(), "min_request_interval_ms": 0 }).to_string()
}

/// The answer of a successful call.
fn success_body(result: &Value) -> String {
    json!({"status": "success", "answer": {"status": "success", "result": result}}).to_string()
}

// ---- Secrets (design section 12.2) -------------------------------------------------------------

/// Neither client type nor credentials type can be printed with `Display` or serialized.
/// Checked at compile time: the call is ambiguous if the trait is implemented.
macro_rules! assert_not_impl {
    ($ty:ty: $($tr:path),+ $(,)?) => {
        $(
            const _: () = {
                trait AmbiguousIfImpl<A> {
                    fn some_item() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                #[allow(dead_code)] // Reason: a marker type that is never built.
                struct Invalid;
                impl<T: ?Sized + $tr> AmbiguousIfImpl<Invalid> for T {}
                let _ = <$ty as AmbiguousIfImpl<_>>::some_item;
            };
        )+
    };
}

assert_not_impl!(Beget: std::fmt::Display, serde::Serialize);
assert_not_impl!(BegetCredentials: std::fmt::Display, serde::Serialize);

/// What the echo's reads answer: no record, a record with a foreign value, or a record with
/// the value `v1`.
#[derive(Clone, Copy)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
}

fn ok_json(result: &Value) -> axum::response::Response {
    let body = json!({"status": "success", "answer": {"status": "success", "result": result}});
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// A renderer that answers the domain list like the API and every other request with `errors`.
fn list_then(errors: Render) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.path.ends_with("/domain/getList") {
            return ok_json(&json!([{"id": "1", "fqdn": "example.org"}]));
        }
        errors(e)
    })
}

/// A renderer that answers both reads like the API and every other request with `errors`.
fn reads_then(errors: Render, existing: Existing) -> Render {
    let list = list_then(errors);
    Arc::new(move |e: &Echoed| {
        if !e.path.ends_with("/dns/getData") {
            return list(e);
        }
        // The form body of a read of `NAME` repeats the name unencoded (its characters are all
        // unreserved).
        let fqdn = if e.body.contains(NAME) {
            NAME
        } else {
            "example.org"
        };
        let records = match existing {
            Existing::Nothing => json!([]),
            Existing::Foreign => {
                json!({"TXT": [{"txtdata": "foreign", "priority": 10, "ttl": 300}]})
            }
            Existing::Ours => json!({"TXT": [{"txtdata": "v1", "priority": 10, "ttl": 300}]}),
        };
        ok_json(&json!({
            "is_under_control": 1, "is_beget_dns": 1, "is_subdomain": 0,
            "fqdn": fqdn, "records": records, "set_type": 1
        }))
    })
}

/// The API's error envelope with the echoed request text as the error text, on the call's level
/// (`top`) or on the method's.
fn envelope(top: bool, code: &'static str) -> Render {
    Arc::new(move |e: &Echoed| {
        let body = if top {
            json!({"status": "error", "error_code": code, "error_text": e.text})
        } else {
            json!({"status": "success", "answer": {"status": "error",
                "errors": [{"error_code": code, "error_text": e.text}]}})
        };
        (StatusCode::OK, axum::Json(body)).into_response()
    })
}

/// The envelopes every echo round runs with: HTTP 200 and the error in the body.
fn envelopes() -> Vec<(&'static str, Render)> {
    vec![
        ("200 top AUTH_ERROR", envelope(true, "AUTH_ERROR")),
        (
            "200 top INCORRECT_REQUEST",
            envelope(true, "INCORRECT_REQUEST"),
        ),
        ("200 answer INVALID_DATA", envelope(false, "INVALID_DATA")),
        ("200 answer METHOD_FAILED", envelope(false, "METHOD_FAILED")),
    ]
}

fn echo_client(echo: &EchoServer, ctx: &Context) -> Beget {
    let mut config = BegetConfig::new(CANARY_KEY.to_owned());
    config.base_url = echo.url("/api");
    config.min_request_interval_ms = 0;
    Beget::new(config, credentials(CANARY_PASSWORD), ctx).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Write {
    Add,
    Remove,
}

/// `check` and a write against an echo that quotes every request back: no canary in any error,
/// `ZoneCheck::detail` or `Debug`, and the write's error shows the redaction.
async fn echo_round(label: &str, client: &Beget, write: Write) {
    let mut texts = vec![format!("{client:?}")];
    match client.check(&[zone()]).await {
        Ok(report) => texts.extend(
            report
                .zones
                .iter()
                .filter_map(|z| z.detail.as_ref().map(|d| d.as_str().to_owned())),
        ),
        Err(e) => texts.push(format!("{e} | {e:?}")),
    }
    let result = match write {
        Write::Add => add(client, "v1").await.map(|o| format!("{o:?}")),
        Write::Remove => remove(client, "v1").await.map(|o| format!("{o:?}")),
    };
    let text = match result {
        Ok(outcome) => panic!("{label}: the echo accepted a write: {outcome}"),
        Err(e) => format!("{e} | {e:?}"),
    };
    assert!(
        text.contains(REDACTED),
        "{label}: the echo did not reach the error: {text}"
    );
    texts.push(text);
    for text in &texts {
        assert_clean(label, text, &[CANARY_PASSWORD, CANARY_KEY]);
    }
}

/// `check` and the writes against an echo, for every dialect. Four kinds of request reach it:
/// the domain list, the read of a name, and the change; the credentials travel in the form body
/// of every one of them, so the echo repeats them in every error body. Both levels of the
/// API's error envelope are covered, besides the HTTP statuses.
///
/// Reads that the echo answers with a 5xx are left out: the transport repeats an idempotent
/// request with real back-off sleeps, which would add seconds per dialect without coverage (the
/// 5xx body is covered by the change's 500).
///
/// The dialects run in parallel, each on its own echo servers: hundreds of rounds, none of
/// which waits for a timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beget_secret_echo() {
    let mut tasks = tokio::task::JoinSet::new();
    for dialect in dialects() {
        tasks.spawn(echo_dialect(dialect));
    }
    while let Some(result) = tasks.join_next().await {
        if let Err(e) = result {
            std::panic::resume_unwind(e.into_panic());
        }
    }
}

/// The rounds of [`beget_secret_echo`] for one dialect.
async fn echo_dialect(dialect: Dialect) {
    // One server and one context for every case: each case reconfigures the server, and
    // every client reuses the context's pooled connection (see `EchoServer::reset`).
    let ctx = context();
    let echo = EchoServer::start(200).await;
    {
        // Everything is the echo: the domain list is the first request of `check`, and the
        // read of the name the first of a write.
        let mut variants: Vec<(String, Render, u16)> = [400u16, 401, 403]
            .iter()
            .map(|&s| (format!("{s}"), dialect.render.clone(), s))
            .collect();
        variants.extend(envelopes().into_iter().map(|(n, r)| (n.to_owned(), r, 200)));
        for (what, render, status) in &variants {
            let label = format!("{} {:?} {what} list", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(*status).render(render.clone()));
            let client = echo_client(&echo, &ctx);
            echo_round(&label, &client, Write::Add).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
            assert!(
                echo.log().count(Some("POST"), LIST) > 0
                    && echo.log().count(Some("POST"), DATA) > 0,
                "{label}: a request kind did not reach the echo"
            );
        }
        // The domain list is answered; the read of a name is the echo.
        for (what, render, status) in &variants {
            let label = format!("{} {:?} {what} read", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(*status).render(list_then(render.clone())));
            let client = echo_client(&echo, &ctx);
            let mut texts = vec![format!("{client:?}")];
            match client.check(&[zone()]).await {
                Ok(report) => texts.extend(
                    report
                        .zones
                        .iter()
                        .filter_map(|z| z.detail.as_ref().map(|d| d.as_str().to_owned())),
                ),
                Err(e) => texts.push(format!("{e} | {e:?}")),
            }
            let e = add(&client, "v1").await.unwrap_err();
            texts.push(format!("{e} | {e:?}"));
            for text in &texts {
                assert_clean(&label, text, &[CANARY_PASSWORD, CANARY_KEY]);
            }
            assert!(
                echo.log().count(Some("POST"), DATA) > 0,
                "{label}: the read did not reach the echo"
            );
        }
        // The reads are answered, so the write itself reaches the echo: a change with and
        // without a foreign record at the name, and a removal.
        let mut changes: Vec<(String, Render, u16)> = [400u16, 401, 403, 422, 500]
            .iter()
            .map(|&s| (format!("{s}"), dialect.render.clone(), s))
            .collect();
        changes.extend(envelopes().into_iter().map(|(n, r)| (n.to_owned(), r, 200)));
        // The cases with a foreign record and the removal differ from the first only in what the
        // read answers, so a lighter set of answers is enough there.
        let light = |what: &str| {
            matches!(
                what,
                "400" | "500" | "200 top AUTH_ERROR" | "200 answer INVALID_DATA"
            )
        };
        for (existing, write) in [
            (Existing::Nothing, Write::Add),
            (Existing::Foreign, Write::Add),
            (Existing::Ours, Write::Remove),
        ] {
            for (what, render, status) in &changes {
                if !matches!(existing, Existing::Nothing) && !light(what) {
                    continue;
                }
                let label = format!("{} {:?} {what} {write:?}", dialect.name, dialect.spelling);
                echo.reset(
                    dialect
                        .echo(*status)
                        .render(reads_then(render.clone(), existing)),
                );
                let client = echo_client(&echo, &ctx);
                echo_round(&label, &client, write).await;
                assert_eq!(
                    echo.log().count(Some("POST"), CHANGE),
                    1,
                    "{label}: the change did not reach the echo exactly once"
                );
            }
        }
    }
}

/// A `TRACE` capture over a success, a wrong password, a 500 and a 401: the transport's events
/// are there, and no canary is.
#[tokio::test(flavor = "current_thread")]
async fn beget_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.login = CANARY_KEY.into();
    seed.password = CANARY_PASSWORD.into();
    let mock = BegetMock::start(seed).await;
    let mut config = settings(&mock);
    config.login = CANARY_KEY.into();
    let client = Beget::new(config.clone(), credentials(CANARY_PASSWORD), &context()).unwrap();
    let mut texts = Vec::new();

    add(&client, "v1").await.unwrap();
    remove(&client, "v1").await.unwrap();
    client.check(&[zone()]).await.unwrap();

    mock.faults().push(Fault::on("POST", CHANGE).status(500));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    mock.faults().push(Fault::on("POST", CHANGE).status(401));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    // A wrong password is answered by the API's own envelope, HTTP 200.
    let wrong = Beget::new(config, credentials(CANARY_TOKEN), &context()).unwrap();
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?} | {wrong:?} | {client:?}"));

    let entries = capture.entries();
    assert!(
        entries.iter().any(|e| e.target == "zonewright::http"),
        "the capture holds no transport event"
    );
    texts.push(capture.text());
    for text in &texts {
        assert_clean(
            "beget logs and errors",
            text,
            &[CANARY_PASSWORD, CANARY_TOKEN, CANARY_KEY],
        );
    }
}

/// The credentials are in the form body of every request and in no URL: no query string, no
/// credential in the path, no header that carries them.
#[tokio::test]
async fn beget_credentials_only_in_the_form_body() {
    let (mock, client) = setup().await;
    client.check(&[zone()]).await.unwrap();
    client.list_zones().await.unwrap();
    add(&client, "AAA").await.unwrap();
    remove(&client, "AAA").await.unwrap();
    let entries = mock.log().entries();
    assert_eq!(entries.len(), 7, "{entries:?}");
    for request in entries {
        assert_eq!(request.method.as_str(), "POST");
        assert_eq!(request.query, None, "{}", request.path);
        assert!(!request.path.contains(LOGIN) && !request.path.contains(PASSWORD));
        assert!(
            request
                .header("content-type")
                .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded")),
            "{:?}",
            request.headers
        );
        for (name, value) in &request.headers {
            let value = value.to_str().unwrap_or_default();
            assert!(
                !value.contains(PASSWORD) && !value.contains(LOGIN),
                "{name}: {value}"
            );
        }
        let params = params_of(&request);
        let field = |key: &str| {
            params
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(field("login"), Some(LOGIN));
        assert_eq!(field("passwd"), Some(PASSWORD));
        assert_eq!(field("output_format"), Some("json"));
        if request.path == LIST {
            // As the documentation's example call: no arguments.
            assert_eq!(field("input_data"), None);
        } else {
            assert_eq!(field("input_format"), Some("json"));
        }
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely ends
/// with the zone's text, the zone's text inside another name, and a sibling zone.
#[tokio::test]
async fn beget_name_outside_zone_sends_nothing() {
    let (mock, client) = setup().await;
    let value = txt("v1");
    for (zone, name) in [
        ("example.org", "example.net"),
        ("example.org", "badexample.org"),
        ("example.org", "example.org.evil.net"),
        ("a.example.org", "b.example.org"),
    ] {
        let (zone, name) = (dn(zone), dn(name));
        let e = client
            .add_txt_value(&zone, &name, &value, None)
            .await
            .unwrap_err();
        assert!(matches!(e, Error::NameOutsideZone { .. }), "{e:?}");
        let e = client
            .remove_txt_value(&zone, &name, &value)
            .await
            .unwrap_err();
        assert!(matches!(e, Error::NameOutsideZone { .. }), "{e:?}");
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
}

/// A value the capabilities do not accept and a TTL outside the range are refused before any
/// request.
#[tokio::test]
async fn beget_invalid_input_sends_nothing() {
    let (mock, client) = setup().await;
    for value in ["two words", "quo\"te", "back\\slash"] {
        let e = add(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
        let e = remove(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
    }
    for ttl in [10, 59, 86_401] {
        let e = client
            .add_txt_value(
                &zone(),
                &name(),
                &txt("v1"),
                Some(RrsetTtl::from_secs(ttl).unwrap()),
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{ttl}: {e:?}");
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
}

/// `Created`, `Appended` for a second value (the apex and the wildcard of one certificate share
/// a name), then `AlreadyPresent` without a write.
#[tokio::test]
async fn beget_add_is_idempotent() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    let before = writes(&mock);
    assert_eq!(
        add(&client, "BBB").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(mock.control().txt_values(NAME), ["AAA", "BBB"]);
}

/// Removing an absent value next to foreign ones writes nothing; adding and removing our value
/// leaves the foreign records, their TTLs and their priorities as they were.
#[tokio::test]
async fn beget_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_txt(NAME, "foreign-1", 600);
    control.insert(NAME, "TXT", "foreign-2", json!("20"), Some(json!(900)));
    let foreign = control.records(NAME);

    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);

    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    let held = control.records(NAME);
    assert_eq!(held[..2], foreign[..], "{held:?}");
    assert_eq!(held[2].value, "ours");
    // The value joins the set with the set's TTL (design section 3.6).
    assert_eq!(held[2].ttl, Some(json!(600)));

    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.records(NAME), foreign);

    // A single foreign value is never a reason to delete anything.
    control.remove_type(NAME, "TXT");
    control.insert_txt(NAME, "only-foreign", 600);
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(control.txt_values(NAME), ["only-foreign"]);
}

/// Foreign values go back byte for byte: quotes, spaces and split strings are not normalized.
#[tokio::test]
async fn beget_foreign_values_are_written_back_verbatim() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let foreign = [
        "\"quoted string\"",
        "v=spf1 include:_spf.example.org ~all",
        "\"part one\" \"part two\"",
        "\"unterminated",
    ];
    for value in foreign {
        control.insert_txt(NAME, value, 300);
    }
    add(&client, "ours").await.unwrap();
    remove(&client, "ours").await.unwrap();
    assert_eq!(control.txt_values(NAME), foreign);
}

/// Other record types at the same name are untouched. The API deletes the A and MX records a
/// `changeRecords` request leaves out (the mock does the same), and the A and MX records it
/// returns cannot be written back as they were, so a name that holds any is refused for both
/// operations and nothing is written: A only (the first TXT value), TXT with A, TXT with MX and
/// their priorities, A with MX, in the documented and in the observed answer shape.
#[tokio::test]
async fn beget_other_types_at_the_name_are_untouched() {
    let states: [&[(&str, &str, Value)]; 4] = [
        &[("A", "192.0.2.1", json!("0"))],
        &[
            ("A", "192.0.2.1", json!("0")),
            ("TXT", "foreign", json!(10)),
        ],
        &[
            ("MX", "mx1.example.org", json!("10")),
            ("MX", "mx2.example.org", json!(20)),
            ("TXT", "foreign", json!(10)),
        ],
        &[
            ("A", "192.0.2.1", json!(0)),
            ("MX", "mx1.example.org", json!(10)),
        ],
    ];
    for observed in [false, true] {
        for state in states {
            let (mock, client) = setup().await;
            mock.control().set_observed(observed);
            for (rtype, value, priority) in state {
                mock.control()
                    .insert(NAME, rtype, value, priority.clone(), Some(json!(300)));
            }
            let before = mock.control().records(NAME);
            let what = format!("observed {observed}: {state:?}");
            for e in [
                add(&client, "ours").await.unwrap_err(),
                remove(&client, "foreign").await.unwrap_err(),
            ] {
                assert_eq!(e.kind(), ErrorKind::Rejected, "{what}: {e:?}");
            }
            assert_eq!(writes(&mock), 0, "{what}");
            assert_eq!(mock.control().records(NAME), before, "{what}");
        }
    }
}

/// The name server settings of a domain (`DNS`, `DNS_IP`) are listed at its apex. Nothing says
/// that a write of the A, MX and TXT group leaves them alone, so a name with them is refused
/// and nothing is written, in both answer shapes; `check` only reads it.
#[tokio::test]
async fn beget_apex_name_server_settings_are_refused() {
    for observed in [false, true] {
        let (mock, client) = setup().await;
        mock.control().set_observed(observed);
        mock.control()
            .insert_txt("example.org", "site-verification=abc", 300);
        let apex = zone();
        let value = txt("v1");
        let e = client
            .add_txt_value(&apex, &apex, &value, None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{observed}: {e:?}");
        let e = client
            .remove_txt_value(&apex, &apex, &txt("site-verification=abc"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{observed}: {e:?}");
        let read = mock.log().matching(Some("POST"), DATA).pop().unwrap();
        assert_eq!(input_of(&read).unwrap(), json!({"fqdn": "example.org"}));
        assert!(client.check(&[apex]).await.unwrap().zones[0].found);
        assert_eq!(writes(&mock), 0, "{observed}");
        assert_eq!(
            mock.control().txt_values("example.org"),
            ["site-verification=abc"]
        );
    }
}

/// The DNS page's example answer for a name without TXT records holds a placeholder entry
/// (empty value, priority 0), and unused name server slots with a `null` value: neither is a
/// record, so the first value is written alone, and a removal finds nothing.
#[tokio::test]
async fn beget_documented_placeholders_are_not_records() {
    let (mock, client) = setup().await;
    let body = success_body(&json!({
        "is_under_control": 1, "is_beget_dns": 1, "is_subdomain": 1, "fqdn": NAME,
        "records": {
            "DNS": [], "DNS_IP": [{"value": null, "priority": 10}],
            "TXT": [{"value": "", "priority": 0}]
        },
        "set_type": 1
    }));
    mock.faults()
        .push(Fault::on("POST", DATA).respond(200, body.clone()));
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        last_change(&mock),
        json!({"fqdn": NAME, "records": {"TXT": [{"value": "ours", "priority": 10, "ttl": 300}]}})
    );
    mock.faults()
        .push(Fault::on("POST", DATA).respond(200, body));
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 1);
}

/// The answer shape lego observed from the live API: TXT records as `{ttl, txtdata}`, the
/// flags as booleans. Foreign values survive an add and a remove, and are written back with
/// their text and TTL. An empty name answered without `records` is not taken for "no
/// records": nothing is written.
#[tokio::test]
async fn beget_observed_answer_shape() {
    let (mock, client) = setup().await;
    mock.control().set_observed(true);
    mock.control().insert_txt(NAME, "foreign", 600);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    let sent = last_change(&mock);
    assert_eq!(
        sent["records"],
        json!({"TXT": [
            {"value": "foreign", "priority": 10, "ttl": 600},
            {"value": "ours", "priority": 10, "ttl": 600}
        ]}),
        "{sent}"
    );
    assert_eq!(
        add(&client, "ours").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(mock.control().txt_values(NAME), ["foreign"]);
    assert_eq!(mock.control().records(NAME)[0].ttl, Some(json!(600)));

    mock.control().remove_type(NAME, "TXT");
    let before = writes(&mock);
    let e = add(&client, "ours").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), before);
}

/// A name that holds records a TXT write cannot carry is refused for both operations, and
/// nothing is written: NS, CNAME, a name server setting and any other type; a TXT record with
/// an empty text (it may be a record of its own), without a TTL (writing it back without one
/// could change it) or with an attribute the write cannot carry; and a `set_type` other than 1.
#[tokio::test]
async fn beget_refuses_names_with_unwritable_records() {
    for (rtype, value, ttl) in [
        ("NS", "ns.example.net", Some(json!(300))),
        ("CNAME", "target.example.net", Some(json!(300))),
        ("CAA", "0 issue ca.example.net", Some(json!(300))),
        ("DNS", "ns1.example.net", None),
        ("DNS_IP", "192.0.2.53", None),
        ("TXT", "", Some(json!(300))),
        ("TXT", "no-ttl", None),
    ] {
        for observed in [false, true] {
            if observed && ttl.is_none() && rtype == "TXT" {
                // The observed shape always states a TTL.
                continue;
            }
            let (mock, client) = setup().await;
            mock.control().set_observed(observed);
            mock.control()
                .insert(NAME, rtype, value, json!(10), ttl.clone());
            mock.control().insert_txt(NAME, "v1", 300);
            let before = mock.control().records(NAME);
            let what = format!("{rtype} {value:?} observed {observed}");
            for e in [
                add(&client, "v2").await.unwrap_err(),
                remove(&client, "v1").await.unwrap_err(),
            ] {
                assert_eq!(e.kind(), ErrorKind::Rejected, "{what}: {e:?}");
            }
            assert_eq!(writes(&mock), 0, "{what}");
            assert_eq!(mock.control().records(NAME), before, "{what}");
        }
    }
    let answers = [
        json!({"fqdn": NAME, "records": {"TXT": []}, "set_type": 2}),
        json!({"fqdn": NAME, "records": {"TXT": []}, "set_type": 3}),
        json!({"fqdn": NAME, "records": {"TXT": []}, "set_type": "3"}),
        json!({"fqdn": NAME, "records": {"TXT": []}, "set_type": 7}),
        json!({"fqdn": NAME, "records": {"TXT": [
            {"txtdata": "v1", "ttl": 300, "comment": "kept by someone"}
        ]}, "set_type": 1}),
        // An empty TXT entry with a TTL is not the documented placeholder.
        json!({"fqdn": NAME, "records": {"TXT": [
            {"value": "", "priority": 0, "ttl": 300}
        ]}, "set_type": 1}),
    ];
    for answer in answers {
        let (mock, client) = setup().await;
        let body = success_body(&answer);
        mock.faults()
            .push(Fault::on("POST", DATA).respond(200, body.clone()));
        let e = add(&client, "v2").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{answer}: {e:?}");
        mock.faults()
            .push(Fault::on("POST", DATA).respond(200, body));
        let e = remove(&client, "v1").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{answer}: {e:?}");
        assert_eq!(writes(&mock), 0);
    }
}

/// A write happens only after a complete read of the requested name. A read that fails, is cut
/// short or is about something else is an error and nothing is written.
#[tokio::test]
async fn beget_incomplete_get_data_never_overwrites() {
    let envelope = |result: Value| success_body(&result);
    let bodies: Vec<(&str, u16, String, ErrorKind)> = vec![
        (
            "result is true",
            200,
            envelope(json!(true)),
            ErrorKind::Protocol,
        ),
        (
            "result is a list",
            200,
            envelope(json!([])),
            ErrorKind::Protocol,
        ),
        (
            "no fqdn",
            200,
            envelope(json!({"records": {"TXT": []}})),
            ErrorKind::Protocol,
        ),
        (
            "another fqdn",
            200,
            envelope(json!({"fqdn": "other.example.org", "records": []})),
            ErrorKind::Protocol,
        ),
        (
            "no records",
            200,
            envelope(json!({"fqdn": NAME})),
            ErrorKind::Protocol,
        ),
        (
            "records null",
            200,
            envelope(json!({"fqdn": NAME, "records": null})),
            ErrorKind::Protocol,
        ),
        (
            "records not a map",
            200,
            envelope(json!({"fqdn": NAME, "records": "x"})),
            ErrorKind::Protocol,
        ),
        (
            "TXT not a list",
            200,
            envelope(json!({"fqdn": NAME, "records": {"TXT": "x"}})),
            ErrorKind::Protocol,
        ),
        (
            "TXT entry without text",
            200,
            envelope(json!({"fqdn": NAME, "records": {"TXT": [{"priority": 10}]}})),
            ErrorKind::Protocol,
        ),
        (
            "TXT text not a string",
            200,
            envelope(json!({"fqdn": NAME, "records": {"TXT": [{"value": 7, "ttl": 300}]}})),
            ErrorKind::Protocol,
        ),
        (
            "TXT entry not an object",
            200,
            envelope(json!({"fqdn": NAME, "records": {"TXT": ["foreign"]}})),
            ErrorKind::Protocol,
        ),
        (
            "not JSON",
            200,
            "<html>maintenance</html>".to_owned(),
            ErrorKind::Protocol,
        ),
        ("empty body", 200, String::new(), ErrorKind::Protocol),
        (
            "no answer",
            200,
            json!({"status": "success"}).to_string(),
            ErrorKind::Protocol,
        ),
        (
            "no result",
            200,
            json!({"status": "success", "answer": {"status": "success"}}).to_string(),
            ErrorKind::Protocol,
        ),
        (
            "no status",
            200,
            json!({"answer": {"status": "success", "result": {}}}).to_string(),
            ErrorKind::Protocol,
        ),
        ("HTTP 400", 400, "{}".to_owned(), ErrorKind::Rejected),
        ("HTTP 404", 404, "{}".to_owned(), ErrorKind::Rejected),
    ];
    for (what, status, body, kind) in bodies {
        let (mock, client) = setup().await;
        mock.control().insert_txt(NAME, "foreign", 300);
        let before = mock.control().records(NAME);
        for write in [Write::Add, Write::Remove] {
            mock.faults()
                .push(Fault::on("POST", DATA).respond(status, body.clone()));
            let e = match write {
                Write::Add => add(&client, "ours").await,
                Write::Remove => remove(&client, "foreign")
                    .await
                    .map(|_| AddOutcome::Created),
            }
            .unwrap_err();
            assert_eq!(e.kind(), kind, "{what} {write:?}: {e:?}");
        }
        assert_eq!(writes(&mock), 0, "{what}");
        assert_eq!(mock.control().records(NAME), before, "{what}");
    }
}

/// The read of a name is answered with an error of the API, on either level: no write.
#[tokio::test]
async fn beget_failed_read_never_writes() {
    let (mock, client) = setup().await;
    mock.control().insert_txt(NAME, "foreign", 300);
    for body in [
        json!({"status": "error", "error_code": "AUTH_ERROR", "error_text": "x"}),
        json!({"status": "success", "answer": {"status": "error",
            "errors": [{"error_code": "METHOD_FAILED", "error_text": "x"}]}}),
    ] {
        mock.faults()
            .push(Fault::on("POST", DATA).respond(200, body.to_string()));
        assert!(add(&client, "ours").await.is_err());
        mock.faults()
            .push(Fault::on("POST", DATA).respond(200, body.to_string()));
        assert!(remove(&client, "foreign").await.is_err());
    }
    // A read that fails with a 5xx after its retries: `beget_reads_are_retried`.
    assert_eq!(writes(&mock), 0);
    assert_eq!(mock.control().txt_values(NAME), ["foreign"]);
}

/// Removing the last value writes the group with an empty TXT list; a second removal finds
/// nothing and writes nothing.
#[tokio::test]
async fn beget_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().records(NAME).is_empty());
    let sent = last_change(&mock);
    assert_eq!(sent, json!({"fqdn": NAME, "records": {"TXT": []}}));
}

/// Removing twice: `Removed` or `RrsetDeleted`, then `NotPresent` without a write.
#[tokio::test]
async fn beget_remove_is_idempotent() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    add(&client, "BBB").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    let before = writes(&mock);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before + 1);
}

/// Two clients sharing a `Context` add to one name at once, the first write delayed: the second
/// waits for the lock and sees the first one's value. Without the name lock both would read "no
/// record" and the second write would replace the first.
#[tokio::test]
async fn beget_concurrent_adds_are_serialized() {
    let mock = BegetMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, PASSWORD, &ctx);
    let b = client_with(&mock, PASSWORD, &ctx);
    mock.faults()
        .push(Fault::on("POST", CHANGE).delay(Duration::from_millis(300)));
    let (zone, name, aaa, bbb) = (zone(), name(), txt("AAA"), txt("BBB"));
    let (ra, rb) = tokio::join!(
        a.add_txt_value(&zone, &name, &aaa, None),
        b.add_txt_value(&zone, &name, &bbb, None),
    );
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [AddOutcome::Appended, AddOutcome::Created]);
    let mut values = mock.control().txt_values(NAME);
    values.sort();
    assert_eq!(values, ["AAA", "BBB"]);
}

/// The record-level operations are not offered: `Unsupported`, and nothing is sent.
#[tokio::test]
async fn beget_unsupported_operations_send_nothing() {
    let (mock, client) = setup().await;
    let set = RrSet::new(name(), RecordType::TXT, None, [txt("v").to_data().unwrap()]).unwrap();
    let errors = [
        client.list_rrsets(&zone()).await.unwrap_err(),
        client
            .get_rrset(&zone(), &name(), RecordType::TXT)
            .await
            .unwrap_err(),
        client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err(),
        client
            .delete_rrset(&zone(), &name(), RecordType::TXT, Expect::Any)
            .await
            .unwrap_err(),
    ];
    for e in errors {
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e:?}");
    }
    assert!(mock.log().is_empty());
}

/// Retry behavior (design section 5.3): a change is sent once whatever happens (a 502, a 429, a
/// 401, and the API's own `LIMIT_ERROR` and `METHOD_FAILED` are the operation's error, and the
/// repeat starts with a read); a repeated change could replace what someone wrote in between.
#[tokio::test]
async fn beget_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let changes = || mock.log().count(Some("POST"), CHANGE);

    mock.faults().push(Fault::on("POST", CHANGE).status(502));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(changes(), 1);
    assert!(mock.control().records(NAME).is_empty());

    mock.faults()
        .push(Fault::on("POST", CHANGE).rate_limited("1"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(changes(), 2);

    mock.faults().push(Fault::on("POST", CHANGE).status(401));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(changes(), 3);

    let limit = json!({"status": "success", "answer": {"status": "error",
        "errors": [{"error_code": "LIMIT_ERROR", "error_text": "slow down"}]}});
    mock.faults()
        .push(Fault::on("POST", CHANGE).respond(200, limit.to_string()));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(changes(), 4);

    let failed = json!({"status": "success", "answer": {"status": "error",
        "errors": [{"error_code": "METHOD_FAILED", "error_text": "internal"}]}});
    mock.faults()
        .push(Fault::on("POST", CHANGE).respond(200, failed.to_string()));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(changes(), 5);
    assert!(mock.control().records(NAME).is_empty());

    // The change is answered 502 but was applied: the repeat finds the value instead of adding
    // a second copy.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("POST", CHANGE)
            .run(move || hook.insert_txt(NAME, "AAA", 300))
            .status(502),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(changes(), 6);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(changes(), 6);
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);

    // The same for a removal: a 502, a 429 and a 401 each send one request.
    for (fault, kind) in [
        (Fault::on("POST", CHANGE).status(502), ErrorKind::Transient),
        (
            Fault::on("POST", CHANGE).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("POST", CHANGE).status(401), ErrorKind::Auth),
    ] {
        let before = changes();
        mock.faults().push(fault);
        let e = remove(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(changes(), before + 1);
    }
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);

    // A change refused by the provider is not repeated either.
    let refused = json!({"status": "success", "answer": {"status": "error",
        "errors": [{"error_code": "INVALID_DATA", "error_text": "bad priority"}]}});
    let before = changes();
    mock.faults()
        .push(Fault::on("POST", CHANGE).respond(200, refused.to_string()));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(changes(), before + 1);

    // A success answer whose result says the change was not made is a refusal, not a success.
    mock.faults()
        .push(Fault::on("POST", CHANGE).respond(200, success_body(&json!(false))));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    mock.faults()
        .push(Fault::on("POST", CHANGE).respond(200, success_body(&json!("ok"))));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// Reads are the requests that are repeated: a 502 on a read is retried, the retries count
/// toward three attempts in all, and a read that fails after them writes nothing. The
/// transport's back-off sleeps for real (1.5 s in this test), so each case runs once.
#[tokio::test]
async fn beget_reads_are_retried() {
    let (mock, client) = setup().await;
    mock.control().insert_txt(NAME, "foreign", 300);
    mock.faults().push(Fault::on("POST", LIST).status(502));
    client.list_zones().await.unwrap();
    assert_eq!(mock.log().count(Some("POST"), LIST), 2);

    mock.faults()
        .push(Fault::on("POST", DATA).always().status(503));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("POST"), DATA), 3);
    assert_eq!(writes(&mock), 0);
    assert_eq!(mock.control().txt_values(NAME), ["foreign"]);
}

// ---- Answers and errors ------------------------------------------------------------------------

/// Both levels of the envelope and the HTTP statuses map to the error kinds of design section 2.9.
#[tokio::test]
async fn beget_errors_are_mapped() {
    let (mock, client) = setup().await;
    let top = |code: &str| {
        json!({"status": "error", "error_code": code, "error_text": "text of the error"})
            .to_string()
    };
    let inner = |codes: &[&str]| {
        let errors: Vec<Value> = codes
            .iter()
            .map(|c| json!({"error_code": c, "error_text": "text of the error"}))
            .collect();
        json!({"status": "success", "answer": {"status": "error", "errors": errors}}).to_string()
    };
    let cases: Vec<(u16, String, ErrorKind)> = vec![
        (200, top("AUTH_ERROR"), ErrorKind::Auth),
        (200, top("INCORRECT_REQUEST"), ErrorKind::Rejected),
        (200, top("NO_SUCH_METHOD"), ErrorKind::Rejected),
        (200, top("SOMETHING_NEW"), ErrorKind::Rejected),
        (
            200,
            json!({"status": "error"}).to_string(),
            ErrorKind::Rejected,
        ),
        (200, inner(&["AUTH_ERROR"]), ErrorKind::Auth),
        (200, inner(&["LIMIT_ERROR"]), ErrorKind::RateLimited),
        (200, inner(&["METHOD_FAILED"]), ErrorKind::Transient),
        (200, inner(&["INVALID_DATA"]), ErrorKind::Rejected),
        (
            200,
            inner(&["INVALID_DATA", "LIMIT_ERROR"]),
            ErrorKind::RateLimited,
        ),
        (200, inner(&["INVALID_DATA", "AUTH_ERROR"]), ErrorKind::Auth),
        (200, inner(&[]), ErrorKind::Rejected),
        (401, "{}".to_owned(), ErrorKind::Auth),
        (403, "{}".to_owned(), ErrorKind::Forbidden),
        (400, top("INCORRECT_REQUEST"), ErrorKind::Rejected),
        (418, "teapot".to_owned(), ErrorKind::Rejected),
    ];
    for (status, body, kind) in cases {
        mock.faults()
            .push(Fault::on("POST", LIST).respond(status, body.clone()));
        let e = client.list_zones().await.unwrap_err();
        assert_eq!(e.kind(), kind, "{status} {body}: {e:?}");
        if status == 200 && body.contains("text of the error") && kind != ErrorKind::RateLimited {
            // The provider's text reaches the error.
            assert!(e.to_string().contains("text of the error"), "{e}");
        }
        if let Error::Rejected { status: s, .. } = &e {
            assert_eq!(*s, (status != 200).then_some(status), "{status} {body}");
        }
    }
    // A wrong password is the API's own AUTH_ERROR.
    let wrong = client_with(&mock, "wrong-password", &context());
    for e in [
        wrong.check(&[]).await.unwrap_err(),
        wrong.list_zones().await.unwrap_err(),
        add(&wrong, "AAA").await.unwrap_err(),
    ] {
        assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
        assert!(!e.to_string().contains("wrong-password"));
    }
    assert_eq!(writes(&mock), 0);
}

/// The domain list must be a list of objects with names; names that are not names are skipped.
#[tokio::test]
async fn beget_list_zones() {
    let mock = BegetMock::start(Seed::standard()).await;
    mock.control().insert_domain("example.net", true);
    mock.control().insert_domain("example.com", false);
    let client = client_with(&mock, PASSWORD, &context());
    let zones: Vec<String> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name.as_str().to_owned())
        .collect();
    assert_eq!(zones, ["example.com.", "example.net.", "example.org."]);

    let body = |result: Value| success_body(&result);
    mock.faults().push(Fault::on("POST", LIST).respond(
        200,
        body(json!([{"id": "1", "fqdn": "example.org"}, {"id": "2", "fqdn": "not a name"}])),
    ));
    let zones = client.list_zones().await.unwrap();
    assert_eq!(zones.len(), 1);

    // An answer that is not a list, or an item without a name, is not a listing.
    for result in [
        json!({"fqdn": "example.org"}),
        json!(true),
        json!([{"id": "1"}]),
        json!(["example.org"]),
    ] {
        mock.faults()
            .push(Fault::on("POST", LIST).respond(200, body(result.clone())));
        let e = client.list_zones().await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{result}: {e:?}");
    }
    mock.faults()
        .push(Fault::on("POST", LIST).respond(200, body(json!([]))));
    assert!(client.list_zones().await.unwrap().is_empty());
}

/// `check` lists the domains, which tests the credentials on every call, and reads each zone.
#[tokio::test]
async fn beget_check_exercises_the_credentials() {
    let mock = BegetMock::start(Seed::standard()).await;
    mock.control().insert_domain("elsewhere.example", false);
    let client = client_with(&mock, PASSWORD, &context());
    let report = client
        .check(&[zone(), dn("missing.test"), dn("elsewhere.example")])
        .await
        .unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones[0].found && report.zones[0].detail.is_none());
    assert!(!report.zones[1].found && report.zones[1].detail.is_none());
    // A domain that Beget's name servers do not serve cannot be changed through them.
    assert!(!report.zones[2].found);
    let detail = report.zones[2].detail.as_ref().unwrap();
    assert!(detail.as_str().contains("name servers"), "{detail}");
    assert_eq!(mock.log().count(Some("POST"), LIST), 1);
    // Only the zones that the account has are read.
    assert_eq!(mock.log().count(Some("POST"), DATA), 2);

    // With no zone the credentials are still tested, on every call.
    let report = client.check(&[]).await.unwrap();
    assert!(report.credentials_verified && report.zones.is_empty());
    assert_eq!(mock.log().count(Some("POST"), LIST), 2);
    let report = client.check(&[]).await.unwrap();
    assert!(report.credentials_verified);
    assert_eq!(mock.log().count(Some("POST"), LIST), 3);

    // A refusal of the credentials is an error, never a report.
    let wrong = client_with(&mock, "wrong-password", &context());
    let e = wrong.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    mock.faults().push(Fault::on("POST", LIST).status(401));
    let e = client.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");

    // The provider refuses to describe a domain of the list: its reason is the detail.
    let refused = json!({"status": "success", "answer": {"status": "error",
        "errors": [{"error_code": "INVALID_DATA", "error_text": "no such domain"}]}});
    mock.faults()
        .push(Fault::on("POST", DATA).respond(200, refused.to_string()));
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    assert!(
        report.zones[0]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("no such domain")
    );
    // A read that does not say whether the domain is served is not a guess.
    let body = success_body(&json!({"fqdn": "example.org", "records": []}));
    mock.faults()
        .push(Fault::on("POST", DATA).respond(200, body));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// The text of a TXT record is in `txtdata` (as lego reads it), in `value` (as the
/// documentation's example shows) or in both.
#[tokio::test]
async fn beget_txt_text_in_either_field() {
    for field in [TxtField::Txtdata, TxtField::Value, TxtField::Both] {
        let (mock, client) = setup().await;
        mock.control().set_txt_field(field);
        mock.control().insert_txt(NAME, "foreign", 300);
        assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
        assert_eq!(
            add(&client, "ours").await.unwrap(),
            AddOutcome::AlreadyPresent
        );
        assert_eq!(
            remove(&client, "ours").await.unwrap(),
            RemoveOutcome::Removed
        );
        assert_eq!(mock.control().txt_values(NAME), ["foreign"], "{field:?}");
    }
}

/// The TTL policy (design section 3.6, a TTL per record): a new set takes the caller's TTL or
/// the configured one; a value that joins a set takes the set's, the smallest of its records';
/// kept records keep theirs; a record whose TTL the API does not state is not written back.
#[tokio::test]
async fn beget_ttl_policy() {
    let mock = BegetMock::start(Seed::standard()).await;
    let mut config = settings(&mock);
    config.ttl = RrsetTtl::from_secs(120).unwrap();
    let client = Beget::new(config, credentials(PASSWORD), &context()).unwrap();
    let ttl_of = |mock: &BegetMock| {
        mock.control()
            .records(NAME)
            .into_iter()
            .map(|r| r.ttl)
            .collect::<Vec<_>>()
    };

    add(&client, "AAA").await.unwrap();
    assert_eq!(ttl_of(&mock), [Some(json!(120))]);
    mock.control().remove_type(NAME, "TXT");

    client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("AAA"),
            Some(RrsetTtl::from_secs(900).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(ttl_of(&mock), [Some(json!(900))]);

    // Joining the set: the set's TTL, not the configured one and not the caller's.
    client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("BBB"),
            Some(RrsetTtl::from_secs(600).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(ttl_of(&mock), [Some(json!(900)), Some(json!(900))]);
    mock.control().remove_type(NAME, "TXT");

    // Records with different TTLs: ours takes the smallest, theirs keep their own.
    mock.control().insert_txt(NAME, "foreign-a", 900);
    mock.control().insert_txt(NAME, "foreign-b", 600);
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        ttl_of(&mock),
        [Some(json!(900)), Some(json!(600)), Some(json!(600))]
    );
    mock.control().remove_type(NAME, "TXT");

    // The API states no TTL for a record: it is not written back without one.
    mock.control()
        .insert(NAME, "TXT", "foreign", json!(10), None);
    let before = writes(&mock);
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(writes(&mock), before);
    assert_eq!(ttl_of(&mock), [None]);
}

/// Names are sent in Unicode form and compared in their canonical form.
#[tokio::test]
async fn beget_internationalized_names_are_sent_in_unicode() {
    let mut seed = Seed::standard();
    seed.domains = vec!["пример.рф".into()];
    let mock = BegetMock::start(seed).await;
    let client = client_with(&mock, PASSWORD, &context());
    let zone = dn("пример.рф");
    let name = dn("_acme-challenge.пример.рф");
    assert_eq!(
        client
            .add_txt_value(&zone, &name, &txt("AAA"), None)
            .await
            .unwrap(),
        AddOutcome::Created
    );
    let read = mock.log().matching(Some("POST"), DATA).pop().unwrap();
    assert_eq!(
        input_of(&read).unwrap(),
        json!({"fqdn": "_acme-challenge.пример.рф"})
    );
    assert_eq!(
        mock.control().txt_values("_acme-challenge.пример.рф"),
        ["AAA"]
    );
    assert_eq!(
        client
            .remove_txt_value(&zone, &name, &txt("AAA"))
            .await
            .unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    let report = client.check(&[zone]).await.unwrap();
    assert!(report.zones[0].found);
}

/// More than ten TXT values is refused before the write, with the set as it was.
#[tokio::test]
async fn beget_record_limit() {
    let (mock, client) = setup().await;
    for i in 0..10 {
        mock.control()
            .insert_txt(NAME, &format!("foreign-{i}"), 300);
    }
    let e = add(&client, "one-too-many").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(mock.control().txt_values(NAME).len(), 10);
    // Removing one still works.
    assert_eq!(
        remove(&client, "foreign-3").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(mock.control().txt_values(NAME).len(), 9);
}

/// Requests are spaced by `min_request_interval_ms` (the API allows 60 requests a minute).
#[tokio::test]
async fn beget_requests_are_paced() {
    let mock = BegetMock::start(Seed::standard()).await;
    let mut config = settings(&mock);
    config.min_request_interval_ms = 250;
    let client = Beget::new(config, credentials(PASSWORD), &context()).unwrap();
    let start = Instant::now();
    client.check(&[]).await.unwrap();
    client.check(&[]).await.unwrap();
    client.check(&[]).await.unwrap();
    assert!(
        start.elapsed() >= Duration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
}

/// The API allows concurrent writers outside the process to lose a change; the capability says so.
#[test]
fn beget_capabilities_state_the_value_guarantee() {
    let caps = &ProviderId::Beget.meta().capabilities;
    assert_eq!(caps.txt_values, ValueGuarantee::ReadThenWrite);
    assert!(caps.list_zones && caps.add_txt_value && caps.remove_txt_value);
    assert!(!caps.list_rrsets && !caps.get_rrset && !caps.set_rrset && !caps.delete_rrset);
    assert!(caps.txt_plain_only);
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn beget_from_json_builds_the_client() {
    let mock = BegetMock::start(Seed::standard()).await;
    let ctx = context();
    let client = AnyProvider::from_json(
        ProviderId::Beget,
        &settings_json(&mock),
        &SecretString::from(format!("{{\"password\": \"{PASSWORD}\", \"other\": 1}}")),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Beget);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

/// The smallest configuration the shared test support uses to build a client without a request.
#[test]
fn beget_minimal_configuration_builds() {
    let client = AnyProvider::from_json(
        ProviderId::Beget,
        r#"{"login":"zw-test-login","base_url":"http://127.0.0.1:9/api"}"#,
        &SecretString::from(r#"{"password":"test-only-password"}"#.to_owned()),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Beget);
    AnyProvider::from_json(
        ProviderId::Beget,
        "{}",
        &SecretString::from(r#"{"password":"test-only-password"}"#.to_owned()),
        &context(),
    )
    .unwrap_err();
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn beget_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || json!({ "login": "zw-login", "base_url": "http://127.0.0.1:1/api" });
    let with = |key: &str, value: Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let password = json!({"password": "pw"}).to_string();
    let cases = [
        (with("ttl", json!(59)), password.clone(), "ttl"),
        (with("ttl", json!(86_401)), password.clone(), "ttl"),
        (
            with("min_request_interval_ms", json!(60_001)),
            password.clone(),
            "min_request_interval_ms",
        ),
        (with("login", json!("")), password.clone(), "login"),
        (
            with("login", json!("bad\nlogin")),
            password.clone(),
            "login",
        ),
        (
            json!({"base_url": "http://127.0.0.1:1/api"}),
            password.clone(),
            "login",
        ),
        (
            with(canary, json!(canary)),
            password.clone(),
            "unknown keys",
        ),
        (
            with("propagation_timeout_s", json!(30)),
            password.clone(),
            "unknown keys",
        ),
        (
            with("base_url", json!(format!("http://example.com/{canary}"))),
            password.clone(),
            "base_url",
        ),
        (
            with(
                "base_url",
                json!(format!("https://u:{canary}@api.example.org")),
            ),
            password.clone(),
            "base_url",
        ),
        (
            base(),
            json!({"password": 5, canary: canary}).to_string(),
            "password",
        ),
        (base(), json!({"passwd": canary}).to_string(), "password"),
        (base(), json!({"password": ""}).to_string(), "password"),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::Beget,
            &settings.to_string(),
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{key}: {e:?}");
        let text = format!("{e} | {e:?}");
        assert!(key == "unknown keys" || text.contains(key), "{key}: {text}");
        assert!(!text.contains(canary), "{key}: {text}");
    }
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round; the defaults of the metadata are those of the settings type.
#[test]
fn beget_config_keys_match_metadata() {
    let meta = ProviderId::Beget.meta();
    let settings = serde_json::to_value(BegetConfig::new("login".to_owned())).unwrap();
    let mut settings_keys: Vec<&str> = settings
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    settings_keys.sort_unstable();
    let mut meta_settings: Vec<&str> = meta
        .fields
        .iter()
        .filter(|f| !f.secret)
        .map(|f| f.key)
        .collect();
    meta_settings.sort_unstable();
    assert_eq!(settings_keys, meta_settings);
    let secret: Vec<&str> = meta
        .fields
        .iter()
        .filter(|f| f.secret)
        .map(|f| f.key)
        .collect();
    assert_eq!(secret, ["password"]);
    for field in meta.fields.iter().filter(|f| f.default.is_some()) {
        let value = &settings[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
    }
}

// ---- Live (design section 12.5; run only by the maintainer) ------------------------------------

fn live_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("set {key} to run the live test"))
}

/// A random 64-bit number without a dependency: the standard library seeds its hasher keys
/// randomly per process.
fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    hasher.finish()
}

/// Adds and removes two values under a generated label in the zone the maintainer names, and
/// removes exactly the values it added afterwards, also when the body failed.
///
/// It also settles what no source does: that the API accepts `POST` with the login and the
/// password in the form body, and what a write of the TXT set does to other records of the name
/// (the generated label holds none).
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_beget_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_BEGET_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_BEGET_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_BEGET_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::Beget,
            &settings,
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap(),
    );
    let tag = random_u64();
    let name = zone.prepend(&format!("_zw-live-{tag:016x}")).unwrap();
    let values = [
        txt(&format!("zw-live-{tag:016x}-a")),
        txt(&format!("zw-live-{tag:016x}-b")),
    ];

    let body = {
        let (client, zone, name, values) =
            (client.clone(), zone.clone(), name.clone(), values.clone());
        tokio::spawn(async move {
            let report = client.check(std::slice::from_ref(&zone)).await.unwrap();
            assert!(report.credentials_verified);
            assert!(report.zones[0].found, "{report:?}");
            let [a, b] = &values;
            assert_eq!(
                client.add_txt_value(&zone, &name, a, None).await.unwrap(),
                AddOutcome::Created
            );
            assert_eq!(
                client.add_txt_value(&zone, &name, b, None).await.unwrap(),
                AddOutcome::Appended
            );
            assert_eq!(
                client.add_txt_value(&zone, &name, b, None).await.unwrap(),
                AddOutcome::AlreadyPresent
            );
            assert_eq!(
                client.remove_txt_value(&zone, &name, a).await.unwrap(),
                RemoveOutcome::Removed
            );
            assert_eq!(
                client.remove_txt_value(&zone, &name, a).await.unwrap(),
                RemoveOutcome::NotPresent
            );
            assert_eq!(
                client.remove_txt_value(&zone, &name, b).await.unwrap(),
                RemoveOutcome::RrsetDeleted
            );
        })
    };
    let outcome = body.await;

    // Cleanup: exactly the values this test added, with the value operations.
    let mut cleanup = Vec::new();
    for value in &values {
        if let Err(e) = client.remove_txt_value(&zone, &name, value).await {
            cleanup.push(format!("{e}"));
        }
    }
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}
