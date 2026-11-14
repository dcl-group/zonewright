//! Tests of the Hetzner client (`hetzner`) against its mock.
#![cfg(feature = "hetzner")]
// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;
use zonewright::providers::hetzner::{Hetzner, HetznerConfig, HetznerCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RemoveOutcome, RrSet, Ttl, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::echo::{EchoServer, Echoed, Render};
use zonewright_mock::hetzner::{HetznerMock, Seed};

use common::echo::{CANARY_KEY, CANARY_TOKEN, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The token of the standard seed.
const TOKEN: &str = "test-only-token";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// The same name relative to the zone, as the API spells it.
const RR: &str = "_acme-challenge";

/// Fault patterns of the mock's paths.
const ZONES: &str = "/v1/zones";
const ZONE: &str = "/v1/zones/*";
const RRSET: &str = "/v1/zones/*/rrsets/*/TXT";
const ADD: &str = "/v1/zones/*/rrsets/*/TXT/actions/add_records";
const REMOVE: &str = "/v1/zones/*/rrsets/*/TXT/actions/remove_records";
const ACTION: &str = "/v1/actions/*";

/// A TXT value as the API stores a plain value of ours.
fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings pointed at `base_url`, with the shortest polling interval.
fn settings(base_url: String) -> HetznerConfig {
    let mut config = HetznerConfig::default();
    config.base_url = base_url;
    config.action_poll_ms = 250;
    config
}

fn credentials(token: &str) -> HetznerCredentials {
    HetznerCredentials::new(SecretString::from(token.to_owned()))
}

fn client_with(mock: &HetznerMock, token: &str, ctx: &Context) -> Hetzner {
    Hetzner::new(settings(mock.base_url()), credentials(token), ctx).unwrap()
}

async fn setup() -> (HetznerMock, Hetzner) {
    let mock = HetznerMock::start(Seed::standard()).await;
    let client = client_with(&mock, TOKEN, &context());
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

/// Number of write requests the mock received.
fn writes(mock: &HetznerMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), ADD) + log.count(Some("POST"), REMOVE)
}

/// The settings JSON of `from_json` for `mock`.
fn settings_json(mock: &HetznerMock) -> String {
    serde_json::json!({ "base_url": mock.base_url(), "action_poll_ms": 250 }).to_string()
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

assert_not_impl!(Hetzner: std::fmt::Display, serde::Serialize);
assert_not_impl!(HetznerCredentials: std::fmt::Display, serde::Serialize);

/// What the echo's rrset read answers: no rrset, an rrset with a foreign value, or one with the
/// value `v1`.
#[derive(Clone, Copy)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
}

fn ok(body: serde_json::Value) -> axum::response::Response {
    (StatusCode::OK, axum::Json(body)).into_response()
}

fn pagination() -> serde_json::Value {
    serde_json::json!({"pagination": {
        "page": 1, "per_page": 1, "previous_page": null, "next_page": null,
        "last_page": null, "total_entries": 0
    }})
}

fn zone_body() -> serde_json::Value {
    serde_json::json!({"zone": {"id": 1001, "name": "example.org", "mode": "primary"}})
}

fn action_body(status: &str) -> serde_json::Value {
    serde_json::json!({"action": {"id": 7, "command": "x", "status": status, "error": null}})
}

/// The requests the echo can answer normally: the probe, the zone, the rrset and the action.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Echo {
    /// Everything but the writes is answered like the API; the writes are the echo.
    Writes,
    /// The writes are accepted with a running action; the look at the action is the echo.
    Poll,
    /// Only the probe is answered; every other request is the echo.
    Probe,
    /// Everything is the echo.
    All,
}

/// A renderer that answers like the API where `mode` says and with `errors` elsewhere.
fn answering(errors: Render, existing: Existing, mode: Echo) -> Render {
    Arc::new(move |e: &Echoed| {
        let path = e.path.as_str();
        if e.method == Method::GET && path == "/v1/zones" && mode != Echo::All {
            return ok(serde_json::json!({"zones": [], "meta": pagination()}));
        }
        if mode == Echo::Probe || mode == Echo::All {
            return errors(e);
        }
        if e.method == Method::GET {
            if path.contains("/rrsets/") {
                let values: &[&str] = match existing {
                    Existing::Nothing => {
                        let body = serde_json::json!({"error": {"code": "not_found"}});
                        return (StatusCode::NOT_FOUND, axum::Json(body)).into_response();
                    }
                    Existing::Foreign => &["\"foreign\""],
                    Existing::Ours => &["\"v1\""],
                };
                let records: Vec<_> = values
                    .iter()
                    .map(|v| serde_json::json!({"value": v, "comment": ""}))
                    .collect();
                return ok(serde_json::json!({"rrset": {
                    "id": "_acme-challenge/TXT", "name": "_acme-challenge", "type": "TXT",
                    "ttl": 60, "labels": {}, "protection": {"change": false}, "zone": 1001,
                    "records": records
                }}));
            }
            if path.contains("/actions/") {
                return if mode == Echo::Poll {
                    errors(e)
                } else {
                    ok(action_body("success"))
                };
            }
            return ok(zone_body());
        }
        if mode == Echo::Poll {
            return (StatusCode::CREATED, axum::Json(action_body("running"))).into_response();
        }
        errors(e)
    })
}

fn echo_client(echo: &EchoServer) -> Hetzner {
    let config = settings(echo.url("/v1"));
    Hetzner::new(config, credentials(CANARY_TOKEN), &context()).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Write {
    Add,
    Remove,
}

/// `check` and a write against an echo that quotes every request back: no canary in any error,
/// `ZoneCheck::detail` or `Debug`, and the write's error shows the redaction.
async fn echo_round(label: &str, client: &Hetzner, write: Write) {
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
        assert_clean(label, text, &[CANARY_TOKEN]);
    }
}

/// `check` and the writes against an echo, for every dialect. Every kind of request reaches it:
/// the probe, the zone read, the rrset read, the add, the remove and the look at an action. The
/// requests the transport repeats on a 5xx (the reads) never get one: the back-off would add
/// seconds per dialect without coverage.
#[tokio::test]
async fn hetzner_secret_echo() {
    for dialect in dialects() {
        // The probe is the echo.
        for status in [400, 401] {
            let label = format!("{} {:?} {status} probe", dialect.name, dialect.spelling);
            let echo = dialect.echo(status).start().await;
            let client = echo_client(&echo);
            echo_round(&label, &client, Write::Add).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
        }
        // The probe is answered; the zone read is the echo.
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} zone", dialect.name, dialect.spelling);
            let echo = dialect
                .echo(status)
                .render_under(
                    "/v1",
                    answering(dialect.render.clone(), Existing::Nothing, Echo::Probe),
                )
                .start()
                .await;
            let client = echo_client(&echo);
            let e = client.check(&[zone()]).await.unwrap_err();
            let text = format!("{e} | {e:?} | {client:?}");
            assert_clean(&label, &text, &[CANARY_TOKEN]);
            assert!(
                echo.log().count(Some("GET"), ZONE) > 0,
                "{label}: the zone read did not reach the echo"
            );
        }
        // Everything is answered but the writes: an add (with and without a foreign value at
        // the name) and a remove.
        for (existing, write, statuses) in [
            (
                Existing::Nothing,
                Write::Add,
                [400, 401, 403, 422, 423, 500].as_slice(),
            ),
            (
                Existing::Foreign,
                Write::Add,
                [400, 401, 403, 422, 423, 500].as_slice(),
            ),
            (
                Existing::Ours,
                Write::Remove,
                [400, 401, 403, 422, 423, 500].as_slice(),
            ),
        ] {
            for &status in statuses {
                let label = format!("{} {:?} {status} {write:?}", dialect.name, dialect.spelling);
                let echo = dialect
                    .echo(status)
                    .render_under(
                        "/v1",
                        answering(dialect.render.clone(), existing, Echo::Writes),
                    )
                    .start()
                    .await;
                let client = echo_client(&echo);
                echo_round(&label, &client, write).await;
                let path = match write {
                    Write::Add => ADD,
                    Write::Remove => REMOVE,
                };
                assert_eq!(
                    echo.log().count(Some("POST"), path),
                    1,
                    "{label}: the write did not reach the echo exactly once"
                );
            }
        }
        // The writes are accepted; the look at the action is the echo.
        for (existing, write) in [
            (Existing::Nothing, Write::Add),
            (Existing::Ours, Write::Remove),
        ] {
            for status in [400, 401, 403, 404, 422] {
                let label = format!(
                    "{} {:?} {status} action {write:?}",
                    dialect.name, dialect.spelling
                );
                let echo = dialect
                    .echo(status)
                    .render_under(
                        "/v1",
                        answering(dialect.render.clone(), existing, Echo::Poll),
                    )
                    .start()
                    .await;
                let client = echo_client(&echo);
                echo_round(&label, &client, write).await;
                assert!(
                    echo.log().count(Some("GET"), ACTION) >= 1,
                    "{label}: the action look did not reach the echo"
                );
            }
        }
    }
}

/// A `TRACE` capture over a success, repeated 401s, a 500 and a wrong token: the transport's
/// events are there, and no canary is.
#[tokio::test(flavor = "current_thread")]
async fn hetzner_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.token = CANARY_TOKEN.into();
    let mock = HetznerMock::start(seed).await;
    let client = client_with(&mock, CANARY_TOKEN, &context());
    let mut texts = Vec::new();

    add(&client, "v1").await.unwrap();
    remove(&client, "v1").await.unwrap();

    mock.faults()
        .push(Fault::on("GET", RRSET).always().status(401));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("POST", ADD).status(500));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    let wrong = client_with(&mock, CANARY_KEY, &context());
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
        assert_clean("hetzner logs and errors", text, &[CANARY_TOKEN, CANARY_KEY]);
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely ends
/// with the zone's text, the zone's text inside another name, and a sibling zone.
#[tokio::test]
async fn hetzner_name_outside_zone_sends_nothing() {
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
async fn hetzner_invalid_input_sends_nothing() {
    let (mock, client) = setup().await;
    for value in ["two words", "quo\"te", "back\\slash"] {
        let e = add(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
        let e = remove(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
    }
    for ttl in [0, 30, 59] {
        let e = client
            .add_txt_value(
                &zone(),
                &name(),
                &txt("v1"),
                Some(Ttl::from_secs(ttl).unwrap()),
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
async fn hetzner_add_is_idempotent() {
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
    assert_eq!(
        mock.control().txt_values(RR),
        [quoted("AAA"), quoted("BBB")]
    );
    // Each of the two writes was waited for.
    assert_eq!(mock.log().count(Some("GET"), ACTION), 2);
}

/// Removing an absent value next to foreign ones writes nothing; adding and removing our value
/// leaves the foreign records, their comments and the rrset's TTL as they were. A single foreign
/// value is never a reason to delete anything.
#[tokio::test]
async fn hetzner_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset("example.org", RR, "TXT", Some(600), &["\"foreign-1\""]);
    control.add_value("example.org", RR, "TXT", "\"foreign-2\"", "keep me");
    let original = control.rrsets();

    let ours = txt("ours");
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &ours)
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        control.txt_values(RR),
        ["\"foreign-1\"", "\"foreign-2\"", "\"ours\""]
    );
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.rrsets(), original);
    // Only our value was named by a request.
    let removes = mock.log().matching(Some("POST"), REMOVE);
    assert_eq!(removes.len(), 1);
    assert_eq!(
        removes[0].body_json().unwrap(),
        serde_json::json!({"records": [{"value": "\"ours\""}]})
    );

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_rrset("example.org", other, "TXT", Some(60), &["\"foreign\""]);
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &ours)
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(control.txt_values("_acme-challenge.www"), ["\"foreign\""]);
}

/// Rrsets of other types at the same name and TXT rrsets at other names are not touched, and an
/// answer about another rrset is never taken for ours.
#[tokio::test]
async fn hetzner_other_types_at_the_name_are_untouched() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset("example.org", RR, "A", Some(300), &["192.0.2.1"]);
    control.insert_rrset("example.org", RR, "CNAME", Some(300), &["\"AAA\""]);
    control.insert_rrset("example.org", "other", "TXT", Some(300), &["\"AAA\""]);
    let original = control.rrsets();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(control.rrsets(), original);

    // The path names the type, but an answer about another type or another name is an
    // answer in an unexpected form: it is not read as the rrset asked for.
    for body in [
        r#"{"rrset":{"name":"_acme-challenge","type":"A","ttl":60,"records":[{"value":"\"AAA\""}]}}"#,
        r#"{"rrset":{"name":"other","type":"TXT","ttl":60,"records":[{"value":"\"AAA\""}]}}"#,
        r#"{"rrset":{"name":"_acme-challenge.example.org","type":"TXT","ttl":60,"records":[]}}"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", RRSET).respond(200, body));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
        mock.faults()
            .push(Fault::on("GET", RRSET).respond(200, body));
        let e = remove(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    assert_eq!(writes(&mock), 2);
}

#[tokio::test]
async fn hetzner_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().rrsets().is_empty());
    assert_eq!(mock.log().count(Some("POST"), REMOVE), 1);
}

#[tokio::test]
async fn hetzner_remove_is_idempotent() {
    let (mock, client) = setup().await;
    // No rrset at all.
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
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
    assert!(mock.control().rrsets().is_empty());
}

/// Every record that holds the value, whatever its spelling at the provider, is removed with the
/// text the API returned for it, and nothing else is.
#[tokio::test]
async fn hetzner_remove_uses_the_text_the_api_returned() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(
        "example.org",
        RR,
        "TXT",
        Some(60),
        &["\"AAA\"", "\"foreign\"", "\"A\" \"AA\""],
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt_values(RR), ["\"foreign\""]);
    let removes = mock.log().matching(Some("POST"), REMOVE);
    assert_eq!(
        removes[0].body_json().unwrap(),
        serde_json::json!({"records": [{"value": "\"AAA\""}, {"value": "\"A\" \"AA\""}]})
    );
}

/// Two clients sharing a `Context` add to one name at once, the first write delayed: the second
/// waits for the lock and sees the first one's value. Without the name lock both would read "no
/// rrset" and both report `Created`.
#[tokio::test]
async fn hetzner_concurrent_adds_are_serialized() {
    let mock = HetznerMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, TOKEN, &ctx);
    let b = client_with(&mock, TOKEN, &ctx);
    mock.faults()
        .push(Fault::on("POST", ADD).delay(Duration::from_millis(300)));
    let (zone, name, aaa, bbb) = (zone(), name(), txt("AAA"), txt("BBB"));
    let (ra, rb) = tokio::join!(
        a.add_txt_value(&zone, &name, &aaa, None),
        b.add_txt_value(&zone, &name, &bbb, None),
    );
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [AddOutcome::Appended, AddOutcome::Created]);
    let mut values = mock.control().txt_values(RR);
    values.sort();
    assert_eq!(values, [quoted("AAA"), quoted("BBB")]);
}

/// A foreign value added between the read and the write is not lost, by an add or by a remove:
/// the request names only our value. A foreign writer that creates the rrset with another TTL
/// first makes the API refuse the write, and nothing of the foreign rrset changes.
#[tokio::test]
async fn hetzner_foreign_value_added_between_read_and_write_survives() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset("example.org", RR, "TXT", Some(600), &["\"foreign-1\""]);
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", ADD).run(move || {
        hook.add_value("example.org", RR, "TXT", "\"foreign-2\"", "");
    }));
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        control.txt_values(RR),
        ["\"foreign-1\"", "\"foreign-2\"", "\"ours\""]
    );

    let hook = control.clone();
    mock.faults().push(Fault::on("POST", REMOVE).run(move || {
        hook.add_value("example.org", RR, "TXT", "\"foreign-3\"", "");
    }));
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(
        control.txt_values(RR),
        ["\"foreign-1\"", "\"foreign-2\"", "\"foreign-3\""]
    );
    assert_eq!(control.rrset(RR, "TXT").unwrap().ttl, Some(600));

    // The rrset did not exist at the read and was created, with another TTL, before the write.
    control.delete_rrset("example.org", RR, "TXT");
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", ADD).run(move || {
        hook.insert_rrset("example.org", RR, "TXT", Some(300), &["\"foreign\""]);
    }));
    let e = add(&client, "ours").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(control.txt_values(RR), ["\"foreign\""]);
    // The repeat reads the new state and adds to it with its TTL.
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    assert_eq!(control.txt_values(RR), ["\"foreign\"", "\"ours\""]);
    assert_eq!(control.rrset(RR, "TXT").unwrap().ttl, Some(300));
}

/// A zone deleted and created again gets a new identifier. The cached one is not trusted when
/// the API does not know it: the zone is looked up again and the read repeated, so a removal
/// never reports `NotPresent` for a value that is published, and a write goes to the new zone.
#[tokio::test]
async fn hetzner_stale_zone_id() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "AAA").await.unwrap();
    let first = control.zone_id("example.org").unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONE), 1);

    // The zone is recreated with its records: the removal finds the value under the new
    // identifier.
    let second = control.recreate_zone("example.org", true);
    assert_ne!(first, second);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.rrsets().is_empty());
    let reads = mock.log().matching(Some("GET"), RRSET);
    assert_eq!(
        reads[1].path,
        format!("/v1/zones/{first}/rrsets/_acme-challenge/TXT")
    );
    assert_eq!(
        reads[2].path,
        format!("/v1/zones/{second}/rrsets/_acme-challenge/TXT")
    );
    assert_eq!(mock.log().count(Some("GET"), ZONE), 2);

    // The zone is recreated empty: an add goes to the new zone, a removal is `NotPresent`
    // only because the value really is gone.
    add(&client, "BBB").await.unwrap();
    let third = control.recreate_zone("example.org", false);
    assert_eq!(add(&client, "CCC").await.unwrap(), AddOutcome::Created);
    assert_eq!(control.txt_values(RR), [quoted("CCC")]);
    let posts = mock.log().matching(Some("POST"), ADD);
    assert!(posts[2].path.starts_with(&format!("/v1/zones/{third}/")));
    control.recreate_zone("example.org", false);
    assert_eq!(
        remove(&client, "CCC").await.unwrap(),
        RemoveOutcome::NotPresent
    );

    // The zone is deleted between the read and the write: nothing was written, the
    // identifier is forgotten, and the repeat says the zone is gone.
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", ADD).run(move || {
        hook.delete_zone("example.org");
    }));
    let e = add(&client, "DDD").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    let e = add(&client, "DDD").await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    control.add_zone("example.org", "primary");
    assert_eq!(add(&client, "DDD").await.unwrap(), AddOutcome::Created);
}

/// A removal answered "not found" says that the rrset, or the zone, is gone. It is done only
/// when a new read finds the value gone; a zone recreated with the value in it is a conflict
/// and the value stays.
#[tokio::test]
async fn hetzner_remove_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", REMOVE).run(move || {
        hook.delete_rrset("example.org", RR, "TXT");
    }));
    // The rrset is deleted by another writer between the read and the write: the value is
    // gone, as asked.
    let before = mock.log().count(Some("GET"), RRSET);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.rrsets().is_empty());
    assert_eq!(mock.log().count(Some("GET"), RRSET), before + 2);

    // The zone is recreated, records kept, between the read and the write.
    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", REMOVE).run(move || {
        hook.recreate_zone("example.org", true);
    }));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(control.txt_values(RR), [quoted("AAA")]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.rrsets().is_empty());
}

/// The record-level operations are not offered: `Unsupported`, and nothing is sent.
#[tokio::test]
async fn hetzner_unsupported_operations_send_nothing() {
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

/// Retry behavior: an add and a remove are sent once whatever happens (a 502, a 429 and a 401
/// are the operation's error, and the repeat starts with a read); a repeated append could add a
/// value twice and a repeated removal could remove one a writer added after the read.
#[tokio::test]
async fn hetzner_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let posts = || mock.log().count(Some("POST"), ADD);

    mock.faults().push(Fault::on("POST", ADD).status(502));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(posts(), 1);
    assert!(mock.control().rrsets().is_empty());

    mock.faults().push(Fault::on("POST", ADD).rate_limited("1"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(posts(), 2);

    mock.faults().push(Fault::on("POST", ADD).status(401));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(posts(), 3);
    assert!(mock.control().rrsets().is_empty());

    // The write is answered 502 but was applied: the repeat finds the value instead of adding
    // it a second time.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("POST", ADD)
            .run(move || {
                hook.insert_rrset("example.org", RR, "TXT", Some(60), &["\"AAA\""]);
            })
            .status(502),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(posts(), 4);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(posts(), 4);

    // A write refused by the provider is not repeated either.
    mock.faults().push(Fault::on("POST", ADD).respond(
        422,
        r#"{"error":{"code":"invalid_input","message":"ttl is too low","details":null}}"#,
    ));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(posts(), 5);

    // The same for the removal, which can name only our value but is never repeated blindly.
    let deletes = || mock.log().count(Some("POST"), REMOVE);
    mock.faults().push(Fault::on("POST", REMOVE).status(502));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(deletes(), 1);
    mock.faults()
        .push(Fault::on("POST", REMOVE).rate_limited("1"));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(deletes(), 2);
    mock.faults().push(Fault::on("POST", REMOVE).status(401));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(deletes(), 3);
    assert_eq!(mock.control().txt_values(RR), [quoted("AAA")]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(deletes(), 4);
}

// ---- Actions -----------------------------------------------------------------------------------

/// A write returns after its action has finished: with several looks the operation waits, and
/// the change is there when it returns.
#[tokio::test]
async fn hetzner_waits_for_the_action() {
    let (mock, client) = setup().await;
    mock.control().set_action_looks(2);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.control().txt_values(RR), [quoted("AAA")]);
    assert_eq!(mock.log().count(Some("GET"), ACTION), 2);
    let look = mock.log().matching(Some("GET"), ACTION).pop().unwrap();
    assert_eq!(look.path, "/v1/actions/5001");
    assert_eq!(look.header("authorization"), Some("Bearer test-only-token"));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().rrsets().is_empty());
}

/// An action that finishes with an error is `Rejected` with the provider's message, and its
/// change was not made. The repeat starts with a read and converges.
#[tokio::test]
async fn hetzner_failed_action_is_rejected() {
    let (mock, client) = setup().await;
    mock.control()
        .fail_next_action("action_failed", "the zone could not be updated");
    let e = add(&client, "AAA").await.unwrap_err();
    match &e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(*status, None);
            assert_eq!(
                detail.as_str(),
                "the action failed: action_failed: the zone could not be updated"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(mock.control().rrsets().is_empty());
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

/// The message of a failed action can quote the request; the token in it is cut out.
#[tokio::test]
async fn hetzner_failed_action_message_is_scrubbed() {
    let mut seed = Seed::standard();
    seed.token = CANARY_TOKEN.into();
    let mock = HetznerMock::start(seed).await;
    let client = client_with(&mock, CANARY_TOKEN, &context());
    mock.control().fail_next_action(
        "action_failed",
        &format!("Authorization: Bearer {CANARY_TOKEN}"),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    let text = format!("{e} | {e:?}");
    assert_eq!(e.kind(), ErrorKind::Rejected, "{text}");
    assert!(text.contains(REDACTED), "{text}");
    assert_clean("failed action", &text, &[CANARY_TOKEN]);
}

/// A look at the action that fails, or answers something else, ends the wait: the write was
/// accepted and its outcome is unknown (`Transient`), or the answer is not understood
/// (`Protocol`). The repeat reads the state first.
#[tokio::test]
async fn hetzner_action_look_failures() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", ACTION).status(404));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    // The look is a read: a 5xx is retried before it counts.
    mock.faults().push(Fault::on("GET", ACTION).status(502));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.log().count(Some("GET"), ACTION), 3);
    assert_eq!(mock.control().txt_values(RR), [quoted("AAA")]);

    // An unknown status is an answer the client cannot interpret; an action other than the one
    // asked for, or an answer without one, ends the wait like any failed look.
    for (body, what, kind) in [
        (
            r#"{"action":{"id":5003,"status":"weird","error":null}}"#,
            "status",
            ErrorKind::Protocol,
        ),
        (
            r#"{"action":{"id":1,"status":"success","error":null}}"#,
            "id",
            ErrorKind::Transient,
        ),
        (r#"{"action":null}"#, "shape", ErrorKind::Transient),
    ] {
        mock.faults()
            .push(Fault::on("GET", ACTION).respond(200, body));
        let e = add(&client, what).await.unwrap_err();
        assert_eq!(e.kind(), kind, "{what}: {e:?}");
    }
    // A write answered without an action.
    mock.faults()
        .push(Fault::on("POST", ADD).respond(201, r#"{"action":null}"#));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

// ---- Requests, names and TTLs ------------------------------------------------------------------

/// The requests as the documentation and lego describe them: the token in `Authorization`, the
/// zone by identifier, the relative name, the quoted value and the TTL in the body, the removal
/// with the text as stored.
#[tokio::test]
async fn hetzner_request_shapes() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let log = mock.log();
    let zone_read = log.matching(Some("GET"), ZONE).pop().unwrap();
    assert_eq!(zone_read.path, "/v1/zones/example.org");
    assert_eq!(
        zone_read.header("authorization"),
        Some("Bearer test-only-token")
    );
    let id = mock.control().zone_id("example.org").unwrap();
    let read = log.matching(Some("GET"), RRSET).pop().unwrap();
    assert_eq!(
        read.path,
        format!("/v1/zones/{id}/rrsets/_acme-challenge/TXT")
    );
    assert_eq!(read.header("authorization"), Some("Bearer test-only-token"));
    let post = log.matching(Some("POST"), ADD).pop().unwrap();
    assert_eq!(
        post.path,
        format!("/v1/zones/{id}/rrsets/_acme-challenge/TXT/actions/add_records")
    );
    assert_eq!(post.header("authorization"), Some("Bearer test-only-token"));
    assert_eq!(post.header("content-type"), Some("application/json"));
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({"records": [{"value": "\"AAA\""}], "ttl": 60})
    );
    let get = log.matching(Some("GET"), ACTION).pop().unwrap();
    assert_eq!(get.path, "/v1/actions/5001");

    remove(&client, "AAA").await.unwrap();
    let delete = log.matching(Some("POST"), REMOVE).pop().unwrap();
    assert_eq!(
        delete.path,
        format!("/v1/zones/{id}/rrsets/_acme-challenge/TXT/actions/remove_records")
    );
    assert_eq!(
        delete.body_json().unwrap(),
        serde_json::json!({"records": [{"value": "\"AAA\""}]})
    );
}

/// The apex is `@`; a deeper name is relative to the zone, however many labels it has.
#[tokio::test]
async fn hetzner_names_are_relative_to_the_zone() {
    let (mock, client) = setup().await;
    for (owner, stored) in [
        ("example.org", "@"),
        ("_acme-challenge.example.org", "_acme-challenge"),
        ("_acme-challenge.www.example.org", "_acme-challenge.www"),
    ] {
        let owner = dn(owner);
        let added = client
            .add_txt_value(&zone(), &owner, &txt("AAA"), None)
            .await
            .unwrap();
        assert_eq!(added, AddOutcome::Created, "{owner}");
        assert_eq!(
            mock.control().txt_values(stored),
            [quoted("AAA")],
            "{owner}: {:?}",
            mock.control().rrsets()
        );
        assert_eq!(
            client
                .remove_txt_value(&zone(), &owner, &txt("AAA"))
                .await
                .unwrap(),
            RemoveOutcome::RrsetDeleted
        );
    }
    let reads: Vec<_> = mock
        .log()
        .matching(Some("GET"), RRSET)
        .iter()
        .map(|r| r.path.rsplit("/rrsets/").next().unwrap().to_owned())
        .collect();
    assert_eq!(
        reads[..2],
        ["@/TXT".to_owned(), "@/TXT".to_owned()],
        "{reads:?}"
    );
}

/// An internationalized name goes to the API in Punycode, as `rr_name` requires; a wildcard
/// name addresses the rrset `*`, percent-encoded in the path, and leaves the rrsets of names
/// below and beside it alone.
#[tokio::test]
async fn hetzner_idn_and_wildcard_names() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset("example.org", "a", "TXT", Some(60), &["\"foreign\""]);
    control.insert_rrset(
        "example.org",
        "_acme-challenge.a",
        "TXT",
        Some(60),
        &["\"x\""],
    );
    for (owner, stored, path) in [
        (
            "_acme-challenge.пример.example.org",
            "_acme-challenge.xn--e1afmkfd",
            "_acme-challenge.xn--e1afmkfd",
        ),
        ("*.example.org", "*", "%2A"),
    ] {
        let owner = dn(owner);
        assert_eq!(
            client
                .add_txt_value(&zone(), &owner, &txt("AAA"), None)
                .await
                .unwrap(),
            AddOutcome::Created,
            "{owner}"
        );
        assert_eq!(control.txt_values(stored), [quoted("AAA")], "{owner}");
        let post = mock.log().matching(Some("POST"), ADD).pop().unwrap();
        assert_eq!(
            post.path,
            format!("/v1/zones/1001/rrsets/{path}/TXT/actions/add_records")
        );
        assert_eq!(
            client
                .remove_txt_value(&zone(), &owner, &txt("AAA"))
                .await
                .unwrap(),
            RemoveOutcome::RrsetDeleted,
            "{owner}"
        );
    }
    assert_eq!(control.txt_values("a"), ["\"foreign\""]);
    assert_eq!(control.txt_values("_acme-challenge.a"), ["\"x\""]);
    assert_eq!(control.rrsets().len(), 2);
}

/// The TTL of a new rrset is the caller's, else the configured one; a value added to an existing
/// rrset carries the rrset's TTL as read, whatever the caller asks (the API refuses another one);
/// an rrset without a TTL gets a write without one.
#[tokio::test]
async fn hetzner_ttl_policy() {
    let mock = HetznerMock::start(Seed::standard()).await;
    let mut config = settings(mock.base_url());
    config.ttl = 77;
    let client = Hetzner::new(config, credentials(TOKEN), &context()).unwrap();
    let control = mock.control();
    client
        .add_txt_value(&zone(), &dn("a.example.org"), &txt("v"), None)
        .await
        .unwrap();
    assert_eq!(control.rrset("a", "TXT").unwrap().ttl, Some(77));
    client
        .add_txt_value(
            &zone(),
            &dn("b.example.org"),
            &txt("v"),
            Some(Ttl::from_secs(120).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(control.rrset("b", "TXT").unwrap().ttl, Some(120));

    control.insert_rrset("example.org", RR, "TXT", Some(900), &["\"foreign\""]);
    client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("ours"),
            Some(Ttl::from_secs(3000).unwrap()),
        )
        .await
        .unwrap();
    let set = control.rrset(RR, "TXT").unwrap();
    assert_eq!(set.ttl, Some(900));
    assert_eq!(set.values(), ["\"foreign\"", "\"ours\""]);

    // An rrset that has no TTL of its own: the write carries none.
    control.insert_rrset("example.org", "zone-default", "TXT", None, &["\"foreign\""]);
    client
        .add_txt_value(&zone(), &dn("zone-default.example.org"), &txt("ours"), None)
        .await
        .unwrap();
    let post = mock.log().matching(Some("POST"), ADD).pop().unwrap();
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({"records": [{"value": "\"ours\""}]})
    );
    assert_eq!(control.rrset("zone-default", "TXT").unwrap().ttl, None);
}

// ---- Zones -------------------------------------------------------------------------------------

/// A zone in secondary mode is not writable: operations on it are `Rejected` before any write,
/// and `check` reports it as not usable with the reason.
#[tokio::test]
async fn hetzner_secondary_zone_is_not_writable() {
    let (mock, client) = setup().await;
    let secondary = dn("mirror.example.net");
    let owner = dn("_acme-challenge.mirror.example.net");
    let e = client
        .add_txt_value(&secondary, &owner, &txt("v"), None)
        .await
        .unwrap_err();
    match &e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(*status, Some(422));
            assert!(detail.as_str().contains("incorrect_zone_mode"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
    let e = client
        .remove_txt_value(&secondary, &owner, &txt("v"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(writes(&mock), 0);

    // The mode changes under a cached identifier (the zone is deleted and created again as a
    // secondary zone): the API's own refusal is the error.
    add(&client, "AAA").await.unwrap();
    mock.control().delete_zone("example.org");
    mock.control().add_zone("example.org", "secondary");
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    assert!(report.zones[0].detail.is_some());
    assert_eq!(writes(&mock), 1);
}

/// `check` makes a request on every call, so a token revoked in between is noticed, and looks
/// every zone up afresh.
#[tokio::test]
async fn hetzner_check_exercises_the_credentials() {
    let (mock, client) = setup().await;
    let report = client
        .check(&[zone(), dn("missing.test"), dn("mirror.example.net")])
        .await
        .unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones[0].found && report.zones[0].detail.is_none());
    assert!(!report.zones[1].found && report.zones[1].detail.is_none());
    assert!(!report.zones[2].found);
    let detail = report.zones[2].detail.as_ref().unwrap();
    assert!(detail.as_str().contains("primary"), "{detail}");
    client.check(&[]).await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);
    assert_eq!(mock.log().count(Some("GET"), ZONE), 3);
    // The probe is the smallest listing.
    let probe = mock.log().matching(Some("GET"), ZONES).pop().unwrap();
    assert_eq!(probe.query.as_deref(), Some("per_page=1"));

    // The cached identifier is not used by `check`: a zone recreated in between is looked up
    // again.
    add(&client, "AAA").await.unwrap();
    let before = mock.log().count(Some("GET"), ZONE);
    client.check(&[zone()]).await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONE), before + 1);

    // The probe is refused: the credentials are not accepted, and no zone is asked for.
    mock.faults().push(Fault::on("GET", ZONES).status(401));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    mock.faults().push(Fault::on("GET", ZONES).status(403));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    mock.faults().push(Fault::on("GET", ZONES).respond(
        400,
        r#"{"error":{"code":"invalid_input","message":"refused","details":null}}"#,
    ));
    let e = client.check(&[zone()]).await.unwrap_err();
    match &e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(*status, Some(400));
            assert_eq!(detail.as_str(), "invalid_input: refused");
        }
        other => panic!("{other:?}"),
    }
    // An answer without the list of zones is not a working token's answer.
    mock.faults()
        .push(Fault::on("GET", ZONES).respond(200, r#"{"meta":{}}"#));
    let e = client.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    // The same for the zone read, and an answer about another zone.
    mock.faults().push(Fault::on("GET", ZONE).respond(
        400,
        r#"{"error":{"code":"invalid_input","message":"refused","details":null}}"#,
    ));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    mock.faults().push(Fault::on("GET", ZONE).respond(
        200,
        r#"{"zone":{"id":1,"name":"other.example","mode":"primary"}}"#,
    ));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");

    let wrong = client_with(&mock, "wrong-token", &context());
    let e = wrong.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(!format!("{e} {e:?} {wrong:?}").contains("wrong-token"));
}

#[tokio::test]
async fn hetzner_zone_not_found() {
    let (_mock, client) = setup().await;
    let other = dn("example.net");
    let owner = dn("_acme-challenge.example.net");
    let e = client
        .add_txt_value(&other, &owner, &txt("v"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let e = client
        .remove_txt_value(&other, &owner, &txt("v"))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
}

/// Only zones in primary mode are listed, in pages fetched by number; the listing is complete or
/// it fails.
#[tokio::test]
async fn hetzner_list_zones_pages_by_number() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_zone("other.test", "primary");
    control.add_zone("third.test", "primary");
    control.add_zone("shadow.test", "secondary");
    control.set_page_cap(1);
    let zones = client.list_zones().await.unwrap();
    let names: Vec<_> = zones
        .iter()
        .map(|z| z.name.without_dot().to_owned())
        .collect();
    assert_eq!(names, ["example.org", "other.test", "third.test"]);
    let gets = mock.log().matching(Some("GET"), ZONES);
    assert_eq!(gets.len(), 3);
    for (index, get) in gets.iter().enumerate() {
        assert_eq!(
            get.query.as_deref(),
            Some(format!("mode=primary&per_page=50&page={}", index + 1).as_str())
        );
    }
    // `total_entries` may be null: the listing ends at the last page.
    control.set_null_total(true);
    assert_eq!(client.list_zones().await.unwrap().len(), 3);
    // The identifiers of a listing are cached: the first read of the rrset uses one.
    add(&client, "AAA").await.unwrap();
    let id = control.zone_id("example.org").unwrap();
    let first = mock.log().matching(Some("GET"), RRSET).remove(0);
    assert_eq!(
        first.path,
        format!("/v1/zones/{id}/rrsets/_acme-challenge/TXT")
    );
}

/// A listing that stops short of the total it states, lacks its list or its pagination, does not
/// advance or has an empty page before its end is an error, never a shorter result.
#[tokio::test]
async fn hetzner_truncated_listing_is_protocol() {
    let (mock, client) = setup().await;
    let zone = r#"{"id":1,"name":"example.org","mode":"primary"}"#;
    let pagination = |page: u32, next: &str, total: &str| -> String {
        format!(
            r#"{{"zones":[{zone}],"meta":{{"pagination":{{"page":{page},"per_page":1,"next_page":{next},"total_entries":{total}}}}}}}"#
        )
    };
    for body in [
        // Ends before the total.
        pagination(1, "null", "3"),
        // No pagination, no list, a list that is not one.
        format!(r#"{{"zones":[{zone}],"meta":{{}}}}"#),
        format!(r#"{{"zones":[{zone}]}}"#),
        r#"{"meta":{"pagination":{"next_page":null,"total_entries":0}}}"#.to_owned(),
        r#"{"zones":null,"meta":{"pagination":{"next_page":null,"total_entries":0}}}"#.to_owned(),
        // A zone without an identifier.
        r#"{"zones":[{"name":"example.org","mode":"primary"}],"meta":{"pagination":{"next_page":null,"total_entries":1}}}"#
            .to_owned(),
        // A next page that does not advance, or goes back.
        pagination(1, "1", "2"),
        // An empty page before the end.
        r#"{"zones":[],"meta":{"pagination":{"next_page":2,"total_entries":1}}}"#.to_owned(),
        // No next page key at all.
        format!(r#"{{"zones":[{zone}],"meta":{{"pagination":{{"total_entries":1}}}}}}"#),
        // Not JSON.
        "<html>oops</html>".to_owned(),
    ] {
        mock.faults()
            .push(Fault::on("GET", ZONES).respond(200, body.clone()));
        let e = client.list_zones().await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    // Two pages whose first is wrong and whose second would complete the listing if the first
    // were taken as it is: an empty page before the end with no total to compare with, and a
    // second page that points back to the first.
    let other = r#"{"id":2,"name":"other.test","mode":"primary"}"#;
    for (first, second) in [
        (
            r#"{"zones":[],"meta":{"pagination":{"page":1,"next_page":2,"total_entries":null}}}"#
                .to_owned(),
            format!(
                r#"{{"zones":[{other}],"meta":{{"pagination":{{"page":2,"next_page":null,"total_entries":null}}}}}}"#
            ),
        ),
        (
            pagination(1, "2", "null"),
            format!(
                r#"{{"zones":[{other}],"meta":{{"pagination":{{"page":2,"next_page":1,"total_entries":null}}}}}}"#
            ),
        ),
    ] {
        mock.faults().clear();
        mock.faults()
            .push(Fault::on("GET", ZONES).respond(200, first.clone()));
        mock.faults()
            .push(Fault::on("GET", ZONES).respond(200, second.clone()));
        let e = client.list_zones().await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{first} / {second}: {e:?}");
    }
    mock.faults().clear();
    // A listing of one page that is complete is not an error.
    mock.faults()
        .push(Fault::on("GET", ZONES).respond(200, pagination(1, "null", "1")));
    assert_eq!(client.list_zones().await.unwrap().len(), 1);
    // A zone in secondary mode in the answer is skipped even if the filter did not.
    mock.faults().push(Fault::on("GET", ZONES).respond(
        200,
        r#"{"zones":[{"id":1,"name":"a.test","mode":"secondary"},{"id":2,"name":"b.test","mode":"primary"}],"meta":{"pagination":{"next_page":null,"total_entries":2}}}"#,
    ));
    let zones = client.list_zones().await.unwrap();
    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0].name.without_dot(), "b.test");
}

/// An rrset answer without its records is an error, never an empty rrset: a write after it would
/// treat the name as free. The same for an answer without a usable TTL.
#[tokio::test]
async fn hetzner_rrset_without_records_is_protocol() {
    let (mock, client) = setup().await;
    for body in [
        r#"{"rrset":{"name":"_acme-challenge","type":"TXT","ttl":60}}"#,
        r#"{"rrset":{"name":"_acme-challenge","type":"TXT","ttl":60,"records":null}}"#,
        r#"{"rrset":null}"#,
        r#"{}"#,
        // Without its TTL (a required key), or with one outside the documented range: an add
        // after it would carry no TTL and could change the TTL of the rrset.
        r#"{"rrset":{"name":"_acme-challenge","type":"TXT","records":[{"value":"\"f\""}]}}"#,
        r#"{"rrset":{"name":"_acme-challenge","type":"TXT","ttl":4294967295,"records":[{"value":"\"f\""}]}}"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", RRSET).respond(200, body));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);
}

// ---- Errors ------------------------------------------------------------------------------------

#[tokio::test]
async fn hetzner_rate_limit() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RRSET).rate_limited("1"));
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), RRSET), 2);
    mock.faults()
        .push(Fault::on("GET", RRSET).rate_limited("120"));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
    // The reset time of Hetzner's header is a Unix time.
    let reset = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    mock.faults().push(
        Fault::on("GET", RRSET)
            .status(429)
            .header("ratelimit-reset", &reset.to_string()),
    );
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    let wait = e.retry_after().unwrap();
    assert!(
        wait > Duration::from_secs(500) && wait <= Duration::from_secs(600),
        "{wait:?}"
    );
}

/// A 5xx on a read is retried; three in a row are `Transient`, which is retryable.
#[tokio::test]
async fn hetzner_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RRSET).status(502));
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("GET", RRSET).times(3).status(503));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("GET"), RRSET), 5);
}

/// `locked` and `conflict` say that another action is running or the resource changed; the
/// operation is `Transient` and nothing was written. Other refusals are `Rejected` with the
/// status and the provider's message; a status the client cannot interpret is `Protocol`.
#[tokio::test]
async fn hetzner_refusals_are_classified() {
    let (mock, client) = setup().await;
    for (status, code, kind) in [
        (423, "locked", ErrorKind::Transient),
        (409, "conflict", ErrorKind::Conflict),
    ] {
        mock.faults().push(Fault::on("POST", ADD).respond(
            status,
            format!(r#"{{"error":{{"code":"{code}","message":"busy","details":null}}}}"#),
        ));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), kind, "{code}: {e:?}");
        assert!(e.is_retryable(), "{code}: {e:?}");
        assert!(e.to_string().contains("busy"), "{e}");
    }
    assert!(mock.control().rrsets().is_empty());
    mock.faults().push(Fault::on("POST", ADD).respond(
        409,
        r#"{"error":{"code":"uniqueness_error","message":"exists","details":null}}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(409));
            assert_eq!(detail.as_str(), "uniqueness_error: exists");
        }
        other => panic!("{other:?}"),
    }
    mock.faults().push(Fault::on("POST", ADD).respond(
        422,
        r#"{"error":{"code":"invalid_input","message":"ttl is too low","details":null}}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(422));
            assert_eq!(detail.as_str(), "invalid_input: ttl is too low");
        }
        other => panic!("{other:?}"),
    }
    mock.faults().push(
        Fault::on("GET", RRSET).respond(418, r#"{"error":{"code":"teapot","message":"no"}}"#),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    mock.faults().push(Fault::on("GET", RRSET).respond(204, ""));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 4);
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn hetzner_from_json_builds_the_client() {
    let mock = HetznerMock::start(Seed::standard()).await;
    let ctx = context();
    let client = AnyProvider::from_json(
        ProviderId::Hetzner,
        &settings_json(&mock),
        &SecretString::from(format!("{{\"api_token\": \"{TOKEN}\", \"other\": 1}}")),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Hetzner);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

/// The smallest configuration the shared test support uses to build a client without a request.
#[test]
fn hetzner_minimal_configuration_builds() {
    let client = AnyProvider::from_json(
        ProviderId::Hetzner,
        r#"{"base_url":"http://127.0.0.1:9/v1"}"#,
        &SecretString::from(r#"{"api_token":"test-only-token"}"#.to_owned()),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Hetzner);
    // The default endpoint is not a loopback address.
    AnyProvider::from_json(
        ProviderId::Hetzner,
        "{}",
        &SecretString::from(r#"{"api_token":"test-only-token"}"#.to_owned()),
        &context(),
    )
    .unwrap_err();
}

/// A token pasted with surrounding whitespace is sent without it.
#[tokio::test]
async fn hetzner_token_is_trimmed() {
    let mock = HetznerMock::start(Seed::standard()).await;
    let client = client_with(&mock, &format!(" {TOKEN}\n"), &context());
    client.check(&[zone()]).await.unwrap();
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn hetzner_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || serde_json::json!({ "base_url": "http://127.0.0.1:1/v1" });
    let with = |key: &str, value: serde_json::Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let token = serde_json::json!({"api_token": "tk"}).to_string();
    let cases = [
        (with("ttl", serde_json::json!(59)), token.clone(), "ttl"),
        (with("ttl", serde_json::json!(0)), token.clone(), "ttl"),
        (
            with("ttl", serde_json::json!(2_147_483_648_u64)),
            token.clone(),
            "ttl",
        ),
        (
            with("action_poll_ms", serde_json::json!(249)),
            token.clone(),
            "action_poll_ms",
        ),
        (
            with("action_poll_ms", serde_json::json!(60_001)),
            token.clone(),
            "action_poll_ms",
        ),
        (
            with(canary, serde_json::json!(canary)),
            token.clone(),
            "unknown keys",
        ),
        (
            with("zone_id", serde_json::json!(1)),
            token.clone(),
            "unknown keys",
        ),
        (
            with(
                "base_url",
                serde_json::json!(format!("http://example.com/{canary}")),
            ),
            token.clone(),
            "base_url",
        ),
        (
            with(
                "base_url",
                serde_json::json!(format!("https://u:{canary}@api.example.org")),
            ),
            token.clone(),
            "base_url",
        ),
        (
            base(),
            serde_json::json!({"api_token": 5, canary: canary}).to_string(),
            "api_token",
        ),
        (
            base(),
            serde_json::json!({"token": canary}).to_string(),
            "api_token",
        ),
        (
            base(),
            serde_json::json!({"api_token": ""}).to_string(),
            "api_token",
        ),
        (
            base(),
            serde_json::json!({"api_token": "  \n"}).to_string(),
            "api_token",
        ),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::Hetzner,
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
    // A token with a character a header cannot carry is a configuration error.
    let e = Hetzner::new(HetznerConfig::default(), credentials("bad\u{1}token"), &ctx).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
    assert!(!format!("{e}").contains("bad"));
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round; the defaults of the metadata are those of the settings type, and the metadata's ranges
/// are the ones the client enforces.
#[test]
fn hetzner_config_keys_match_metadata() {
    let meta = ProviderId::Hetzner.meta();
    let settings = serde_json::to_value(HetznerConfig::default()).unwrap();
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
    assert_eq!(secret, ["api_token"]);
    for field in meta.fields.iter().filter(|f| f.default.is_some()) {
        let value = &settings[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
    }
    // The ends of the metadata's ranges build a client; one step beyond them does not.
    let ctx = context();
    for key in ["ttl", "action_poll_ms"] {
        let field = meta.field(key).unwrap();
        let zonewright::FieldKind::Integer { min, max } = field.kind else {
            panic!("{key} is not an integer field");
        };
        for (value, valid) in [(min, true), (max, true), (min - 1, false), (max + 1, false)] {
            let mut settings = serde_json::json!({ "base_url": "http://127.0.0.1:1/v1" });
            settings[key] = serde_json::json!(value);
            let built = AnyProvider::from_json(
                ProviderId::Hetzner,
                &settings.to_string(),
                &SecretString::from(r#"{"api_token":"tk"}"#.to_owned()),
                &ctx,
            );
            assert_eq!(built.is_ok(), valid, "{key} = {value}");
        }
    }
    let caps = &meta.capabilities;
    assert!(caps.list_zones && caps.add_txt_value && caps.remove_txt_value);
    assert!(!caps.list_rrsets && !caps.get_rrset && !caps.set_rrset && !caps.delete_rrset);
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
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_hetzner_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_HETZNER_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_HETZNER_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_HETZNER_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::Hetzner,
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
