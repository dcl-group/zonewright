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
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Preconditions, Provider, ProviderDefaultTtl, ProviderId, RecordData, RecordType, RemoveOutcome,
    RrSet, RrsetTtl, SetOutcome, SkipReason, TtlSupport, Txt, TypeSet,
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
const RRSETS: &str = "/v1/zones/*/rrsets";
const ANY_RRSET: &str = "/v1/zones/*/rrsets/*/*";
const SET_RECORDS: &str = "/v1/zones/*/rrsets/*/*/actions/set_records";
const CHANGE_TTL: &str = "/v1/zones/*/rrsets/*/*/actions/change_ttl";

/// The owner name the record-level tests write to.
const REC: &str = "rec.example.org";

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

/// Number of write requests of every kind the mock received: the TXT value actions and the
/// record-level create, set, TTL change and delete.
fn record_writes(mock: &HetznerMock) -> usize {
    let log = mock.log();
    writes(mock)
        + log.count(Some("POST"), RRSETS)
        + log.count(Some("POST"), SET_RECORDS)
        + log.count(Some("POST"), CHANGE_TTL)
        + log.count(Some("DELETE"), ANY_RRSET)
}

fn rd(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap()
}

/// An rrset of canonical texts.
fn rrset(name: &str, rtype: RecordType, ttl: Option<u32>, texts: &[&str]) -> RrSet {
    RrSet::new(
        dn(name),
        rtype,
        ttl.map(|t| RrsetTtl::from_secs(t).unwrap()),
        texts.iter().map(|t| rd(rtype, t)),
    )
    .unwrap()
}

/// The values the mock stores for `name` and `rtype`, in its order.
fn stored(mock: &HetznerMock, name: &str, rtype: &str) -> Vec<String> {
    mock.control()
        .rrset(name, rtype)
        .map(|r| r.values())
        .unwrap_or_default()
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
        // The rrset listing is one of the reads the echo answers in `Writes` mode.
        if e.method == Method::GET && path.ends_with("/rrsets") && mode == Echo::Writes {
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

fn echo_client(echo: &EchoServer, ctx: &Context) -> Hetzner {
    let config = settings(echo.url("/v1"));
    Hetzner::new(config, credentials(CANARY_TOKEN), ctx).unwrap()
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
    // One server and one context for every case: each case reconfigures the server, and
    // every client reuses the context's pooled connection (see `EchoServer::reset`).
    let ctx = context();
    let echo = EchoServer::start(200).await;
    for dialect in dialects() {
        // The probe is the echo.
        for status in [400, 401] {
            let label = format!("{} {:?} {status} probe", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status));
            let client = echo_client(&echo, &ctx);
            echo_round(&label, &client, Write::Add).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
        }
        // The probe is answered; the zone read is the echo.
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} zone", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status).render_under(
                "/v1",
                answering(dialect.render.clone(), Existing::Nothing, Echo::Probe),
            ));
            let client = echo_client(&echo, &ctx);
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
                echo.reset(dialect.echo(status).render_under(
                    "/v1",
                    answering(dialect.render.clone(), existing, Echo::Writes),
                ));
                let client = echo_client(&echo, &ctx);
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
                echo.reset(dialect.echo(status).render_under(
                    "/v1",
                    answering(dialect.render.clone(), existing, Echo::Poll),
                ));
                let client = echo_client(&echo, &ctx);
                echo_round(&label, &client, write).await;
                assert!(
                    echo.log().count(Some("GET"), ACTION) >= 1,
                    "{label}: the action look did not reach the echo"
                );
            }
        }
        record_echo_rounds(&dialect, &echo, &ctx).await;
    }
}

/// The record-level requests, each the echo in turn: the rrset listing, the create, the record
/// replacement, the TTL change and the delete; then the look at the action of a create and of
/// a delete.
async fn record_echo_rounds(dialect: &common::echo::Dialect, echo: &EchoServer, ctx: &Context) {
    for (existing, op, statuses) in [
        (
            Existing::Nothing,
            RecordOp::List,
            [400, 401, 403, 422].as_slice(),
        ),
        (
            Existing::Nothing,
            RecordOp::Create,
            [400, 401, 403, 422, 500].as_slice(),
        ),
        (
            Existing::Foreign,
            RecordOp::Replace,
            [400, 401, 403, 422, 423, 500].as_slice(),
        ),
        (
            Existing::Foreign,
            RecordOp::Ttl,
            [400, 401, 403, 422, 423, 500].as_slice(),
        ),
        (
            Existing::Foreign,
            RecordOp::Delete,
            [400, 401, 403, 422, 423, 500].as_slice(),
        ),
    ] {
        for &status in statuses {
            let label = format!("{} {:?} {status} {op:?}", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status).render_under(
                "/v1",
                answering(dialect.render.clone(), existing, Echo::Writes),
            ));
            let client = echo_client(echo, ctx);
            record_echo_round(&label, &client, op).await;
            let (method, path) = op.request();
            assert_eq!(
                echo.log().count(Some(method), path),
                1,
                "{label}: the request did not reach the echo exactly once"
            );
        }
    }
    for (existing, op) in [
        (Existing::Nothing, RecordOp::Create),
        (Existing::Foreign, RecordOp::Delete),
    ] {
        for status in [400, 401, 403, 404, 422] {
            let label = format!(
                "{} {:?} {status} action {op:?}",
                dialect.name, dialect.spelling
            );
            echo.reset(dialect.echo(status).render_under(
                "/v1",
                answering(dialect.render.clone(), existing, Echo::Poll),
            ));
            let client = echo_client(echo, ctx);
            record_echo_round(&label, &client, op).await;
            assert!(
                echo.log().count(Some("GET"), ACTION) >= 1,
                "{label}: the action look did not reach the echo"
            );
        }
    }
}

/// A record-level request of the echo test.
#[derive(Clone, Copy, Debug)]
enum RecordOp {
    List,
    Create,
    Replace,
    Ttl,
    Delete,
}

impl RecordOp {
    /// The method and path pattern of the request that is the echo.
    fn request(self) -> (&'static str, &'static str) {
        match self {
            RecordOp::List => ("GET", RRSETS),
            RecordOp::Create => ("POST", RRSETS),
            RecordOp::Replace => ("POST", SET_RECORDS),
            RecordOp::Ttl => ("POST", CHANGE_TTL),
            RecordOp::Delete => ("DELETE", ANY_RRSET),
        }
    }
}

/// One record-level operation against an echo: it fails, its error shows the redaction, and no
/// canary is in the error or in the client's `Debug`.
async fn record_echo_round(label: &str, client: &Hetzner, op: RecordOp) {
    let ours = rrset(NAME, RecordType::TXT, None, &["\"v1\""]);
    let retuned = rrset(NAME, RecordType::TXT, Some(120), &["\"foreign\""]);
    let result = match op {
        RecordOp::List => client.list_rrsets(&zone()).await.map(|l| format!("{l:?}")),
        RecordOp::Create | RecordOp::Replace => client
            .set_rrset(&zone(), &ours, Expect::Any)
            .await
            .map(|o| format!("{o:?}")),
        RecordOp::Ttl => client
            .set_rrset(&zone(), &retuned, Expect::Any)
            .await
            .map(|o| format!("{o:?}")),
        RecordOp::Delete => client
            .delete_rrset(&zone(), &name(), RecordType::TXT, Expect::Any)
            .await
            .map(|o| format!("{o:?}")),
    };
    let text = match result {
        Ok(outcome) => panic!("{label}: the echo accepted the operation: {outcome}"),
        Err(e) => format!("{e} | {e:?} | {client:?}"),
    };
    assert!(
        text.contains(REDACTED),
        "{label}: the echo did not reach the error: {text}"
    );
    assert_clean(label, &text, &[CANARY_TOKEN]);
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
    let set = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    client
        .set_rrset(&zone(), &set, Expect::Absent)
        .await
        .unwrap();
    let set = rrset(REC, RecordType::A, Some(600), &["192.0.2.2"]);
    client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
    client.list_rrsets(&zone()).await.unwrap();
    client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap();
    mock.faults()
        .push(Fault::on("POST", SET_RECORDS).status(500));
    client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
    let other = rrset(REC, RecordType::A, None, &["192.0.2.3"]);
    let e = client
        .set_rrset(&zone(), &other, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

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

/// Every operation is offered. A type outside the record-level list (one whose value form no
/// source gives, or that the API does not have) is `UnsupportedRecordType` for a read and a
/// write, and so is a write of SOA; nothing is sent.
#[tokio::test]
async fn hetzner_unsupported_operations_send_nothing() {
    let (mock, client) = setup().await;
    let caps = client.capabilities();
    for operation in [
        zonewright::Operation::Check,
        zonewright::Operation::ListZones,
        zonewright::Operation::ListRrsets,
        zonewright::Operation::GetRrset,
        zonewright::Operation::SetRrset,
        zonewright::Operation::DeleteRrset,
        zonewright::Operation::AddTxtValue,
        zonewright::Operation::RemoveTxtValue,
    ] {
        assert!(caps.supports(operation), "{operation}");
    }
    let unknown = RecordData::parse(RecordType::from_code(65_280), "\\# 1 00").unwrap();
    for (rtype, data) in [
        (
            RecordType::CAA,
            rd(RecordType::CAA, "0 issue \"ca.example.net\""),
        ),
        (RecordType::HTTPS, rd(RecordType::HTTPS, "1 . alpn=\"h2\"")),
        (RecordType::SVCB, rd(RecordType::SVCB, "1 svc.example.net.")),
        (RecordType::SSHFP, rd(RecordType::SSHFP, "4 2 0a1b0a1b")),
        (
            RecordType::from_code(43),
            RecordData::parse(RecordType::from_code(43), "\\# 4 0a0b0c0d").unwrap(),
        ),
        (RecordType::from_code(65_280), unknown),
    ] {
        let set = RrSet::new(dn(REC), rtype, None, [data]).unwrap();
        let errors = [
            client
                .get_rrset(&zone(), &dn(REC), rtype)
                .await
                .unwrap_err(),
            client
                .set_rrset(&zone(), &set, Expect::Any)
                .await
                .unwrap_err(),
            client
                .delete_rrset(&zone(), &dn(REC), rtype, Expect::Any)
                .await
                .unwrap_err(),
        ];
        for e in errors {
            assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
        }
    }
    let soa = rrset(
        "example.org",
        RecordType::SOA,
        None,
        &["hydrogen.ns.hetzner.com. dns.hetzner.com. 1 86400 10800 3600000 3600"],
    );
    let e = client
        .set_rrset(&zone(), &soa, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &zone(), RecordType::SOA, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
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

/// A refusal carries the `code` of the documented error body, and a failed action the `code` of
/// its `error`; the kinds do not change.
#[tokio::test]
async fn hetzner_refusal_carries_the_provider_code() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", ADD).respond(
        422,
        r#"{"error":{"code":"invalid_input","message":"invalid input in field 'records'","details":{}}}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(e.provider_code().map(|c| c.as_str()), Some("invalid_input"));

    mock.control()
        .fail_next_action("action_failed", "the zone could not be updated");
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(e.provider_code().map(|c| c.as_str()), Some("action_failed"));

    // `locked` and `conflict` keep their kinds and carry no code.
    mock.faults().push(Fault::on("POST", ADD).respond(
        409,
        r#"{"error":{"code":"conflict","message":"changed","details":{}}}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(e.provider_code(), None);
}

/// A code that echoes the token is not carried, in an error body or in a failed action, and the
/// token appears nowhere in the error. The token fits the code's alphabet, so only the scrubber
/// keeps it out.
#[tokio::test]
async fn hetzner_provider_code_never_carries_a_credential() {
    let (mock, client) = setup().await;
    let body = serde_json::json!({"error": {"code": TOKEN, "message": "m", "details": {}}});
    mock.faults()
        .push(Fault::on("POST", ADD).respond(422, body.to_string()));
    let refused = add(&client, "AAA").await.unwrap_err();
    mock.control().fail_next_action(TOKEN, "m");
    let failed = add(&client, "AAA").await.unwrap_err();
    for e in [refused, failed] {
        assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
        assert_eq!(e.provider_code(), None);
        let text = format!("{e} | {e:?}");
        assert!(!text.contains(TOKEN), "{text}");
    }
}

/// A look at the action that fails, or answers something the client cannot read, ends the wait:
/// the write was accepted and its outcome is unknown (`Transient`, design section 3.7). The same
/// holds for the action the write itself returned, and for a write answered without an action.
/// The repeat reads the state first.
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

    // An unknown status, an action other than the one asked for, or an answer without one ends
    // the wait like any failed look.
    for (body, what, kind) in [
        (
            r#"{"action":{"id":5003,"status":"weird","error":null}}"#,
            "status",
            ErrorKind::Transient,
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
    // The action the write returned has an unknown status: it is not polled.
    let looks = mock.log().count(Some("GET"), ACTION);
    mock.faults().push(Fault::on("POST", ADD).respond(
        201,
        r#"{"action":{"id":5003,"status":"weird","error":null}}"#,
    ));
    let e = add(&client, "unpolled").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), ACTION), looks);
    // A write answered without an action.
    mock.faults()
        .push(Fault::on("POST", ADD).respond(201, r#"{"action":null}"#));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
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
    config.ttl = RrsetTtl::from_secs(77).unwrap();
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
            Some(RrsetTtl::from_secs(120).unwrap()),
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
            Some(RrsetTtl::from_secs(3000).unwrap()),
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
        // Above the largest TTL the value no longer fits the setting's type: refused while the
        // settings are read, by position (the deserializer cannot name the key).
        (
            with("ttl", serde_json::json!(2_147_483_648_u64)),
            token.clone(),
            "line 1",
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
        let (min, max) = match field.kind {
            zonewright::FieldKind::Integer { min, max } => (min, max),
            zonewright::FieldKind::Ttl { min, max, .. } => (i64::from(min), i64::from(max)),
            _ => panic!("{key} is not an integer field"),
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
    assert!(caps.list_rrsets && caps.get_rrset && caps.set_rrset && caps.delete_rrset);
    assert_eq!(
        caps.record_types,
        TypeSet::Listed(&[
            RecordType::A,
            RecordType::AAAA,
            RecordType::CNAME,
            RecordType::MX,
            RecordType::NS,
            RecordType::PTR,
            RecordType::SOA,
            RecordType::SRV,
            RecordType::TLSA,
            RecordType::TXT,
        ])
    );
    assert_eq!(caps.read_only_types, [RecordType::SOA]);
    assert_eq!(caps.preconditions, Preconditions::ReadThenWrite);
    assert!(!caps.atomic_rrset_write);
    assert!(caps.asynchronous && caps.txt_plain_only);
    assert_eq!(caps.provider_default_ttl, ProviderDefaultTtl::Requestable);
    assert_eq!(
        caps.ttl,
        TtlSupport::PerRrset {
            min: 60,
            max: 2_147_483_647
        }
    );
}

// ---- Record level ------------------------------------------------------------------------------

/// Every writable type in the record-level list goes through set, get and list with canonical
/// equality, is written as its canonical text, is `Unchanged` on a repeat without a write, and
/// is deleted under an exact expectation. The cases include the apex, a wildcard name, an
/// internationalized name, a long TXT value and multi-value sets.
#[tokio::test]
async fn hetzner_record_round_trips() {
    let (mock, client) = setup().await;
    let long = "k".repeat(300);
    let long_txt = Txt::new(long.as_bytes()).unwrap().to_data().unwrap();
    let idn = dn("пример.example.org");
    let tlsa = format!("3 1 1 {}", "0a".repeat(32));
    let cases: Vec<(&str, RecordType, Vec<String>)> = vec![
        (
            REC,
            RecordType::A,
            vec!["192.0.2.1".into(), "192.0.2.2".into()],
        ),
        (
            REC,
            RecordType::AAAA,
            vec!["2001:db8::1".into(), "2001:db8::2:1".into()],
        ),
        (
            "cname.example.org",
            RecordType::CNAME,
            vec!["target.example.net.".into()],
        ),
        (
            "example.org",
            RecordType::MX,
            vec!["10 mail.example.org.".into(), "20 mx2.example.net.".into()],
        ),
        (
            "sub.example.org",
            RecordType::NS,
            vec!["ns1.example.net.".into(), "ns2.example.net.".into()],
        ),
        (
            "_app._tcp.example.org",
            RecordType::PTR,
            vec!["foo._app._tcp.example.org.".into()],
        ),
        (
            "_sip._tcp.example.org",
            RecordType::SRV,
            vec!["10 20 5060 sip.example.org.".into(), "0 0 0 .".into()],
        ),
        ("_443._tcp.example.org", RecordType::TLSA, vec![tlsa]),
        (
            "example.org",
            RecordType::TXT,
            vec!["\"v=spf1 mx -all\"".into(), long_txt.as_str().to_owned()],
        ),
        ("*.example.org", RecordType::A, vec!["192.0.2.3".into()]),
        (idn.as_str(), RecordType::TXT, vec!["\"idn\"".into()]),
    ];
    for (name, rtype, texts) in &cases {
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        let wanted = rrset(name, *rtype, Some(300), &texts);
        assert_eq!(
            client
                .set_rrset(&zone(), &wanted, Expect::Absent)
                .await
                .unwrap(),
            SetOutcome::Created,
            "{name} {rtype}"
        );
        let set = mock.control().rrset(name, &rtype.to_string()).unwrap();
        assert_eq!(set.ttl, Some(300), "{rtype}");
        let mut values = set.values();
        values.sort_unstable();
        let mut expected = texts.clone();
        expected.sort_unstable();
        assert_eq!(values, expected, "{rtype}: written as canonical text");
        let read = client
            .get_rrset(&zone(), &dn(name), *rtype)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, wanted, "{rtype}");
        assert!(read.records().iter().all(RecordData::is_canonical));
        let before = record_writes(&mock);
        assert_eq!(
            client
                .set_rrset(&zone(), &wanted, Expect::Matches(&read))
                .await
                .unwrap(),
            SetOutcome::Unchanged,
            "{rtype}"
        );
        assert_eq!(
            record_writes(&mock),
            before,
            "{rtype}: an unchanged set wrote"
        );
    }
    // The names as the API spells them.
    let names: Vec<String> = mock
        .control()
        .rrsets()
        .iter()
        .map(|r| r.name.clone())
        .collect();
    for expected in ["rec", "@", "*", "xn--e1afmkfd", "_sip._tcp"] {
        assert!(names.iter().any(|n| n == expected), "{expected}: {names:?}");
    }
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.skipped.is_empty(), "{:?}", listing.skipped);
    for (name, rtype, texts) in &cases {
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        let wanted = rrset(name, *rtype, Some(300), &texts);
        assert!(
            listing.rrsets.contains(&wanted),
            "{name} {rtype} not listed"
        );
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(name), *rtype, Expect::Matches(&wanted))
                .await
                .unwrap(),
            DeleteOutcome::Deleted,
            "{rtype}"
        );
        assert!(mock.control().rrset(name, &rtype.to_string()).is_none());
    }
    assert!(mock.control().rrsets().is_empty());
}

/// Values the API returns in another valid spelling (names relative to the zone, upper case,
/// split TXT strings) read as canonical data and compare equal to the canonical form; writing
/// the same set back is `Unchanged` and leaves the provider's text alone.
#[tokio::test]
async fn hetzner_reads_provider_spellings() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for (rtype, provider, canonical) in [
        ("AAAA", "2001:0DB8:0000::0001", "2001:db8::1"),
        ("MX", "10 mail", "10 mail.example.org."),
        ("CNAME", "Target.Example.NET.", "target.example.net."),
        ("PTR", "foo._app._tcp", "foo._app._tcp.example.org."),
        ("SRV", "0 5 443 host", "0 5 443 host.example.org."),
        ("TLSA", "3 1 1 ABCD", "3 1 1 abcd"),
        ("TXT", "\"a\" \"b\"", "\"ab\""),
    ] {
        let name = format!("{}.example.org", rtype.to_lowercase());
        control.insert_rrset("example.org", &name, rtype, Some(600), &[provider]);
        let rtype: RecordType = rtype.parse().unwrap();
        let read = client
            .get_rrset(&zone(), &dn(&name), rtype)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            read,
            rrset(&name, rtype, Some(600), &[canonical]),
            "{rtype}"
        );
        let before = record_writes(&mock);
        assert_eq!(
            client
                .set_rrset(
                    &zone(),
                    &rrset(&name, rtype, None, &[canonical]),
                    Expect::Any
                )
                .await
                .unwrap(),
            SetOutcome::Unchanged
        );
        assert_eq!(record_writes(&mock), before);
        assert_eq!(stored(&mock, &name, &rtype.to_string()), [provider]);
    }
    // An unquoted TXT value is the value itself (the `Auto` rule).
    control.insert_rrset(
        "example.org",
        "raw.example.org",
        "TXT",
        Some(600),
        &["plain words"],
    );
    let read = client
        .get_rrset(&zone(), &dn("raw.example.org"), RecordType::TXT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        read.records(),
        [Txt::new("plain words").unwrap().to_data().unwrap()]
    );
}

#[tokio::test]
async fn hetzner_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset("example.org", REC, "A", Some(600), &["192.0.2.1"]);
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.9"]);
    let wrong = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    let wrong_ttl = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    for expect in [
        Expect::Absent,
        Expect::Matches(&wrong),
        Expect::Matches(&wrong_ttl),
    ] {
        let e = client
            .set_rrset(&zone(), &wanted, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{expect:?}: {e:?}");
        assert!(!e.is_retryable());
    }
    for expect in [Expect::Matches(&wrong), Expect::Matches(&wrong_ttl)] {
        let e = client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{expect:?}: {e:?}");
    }
    // An expectation about an rrset that does not exist.
    let missing = rrset(REC, RecordType::MX, None, &["10 mail.example.org."]);
    let e = client
        .set_rrset(&zone(), &missing, Expect::Matches(&missing))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::MX, Expect::Matches(&missing))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    // An rrset whose TTL is the zone's default reads without a TTL: an expected TTL fails.
    control.insert_rrset("example.org", "null.example.org", "A", None, &["192.0.2.1"]);
    let with_ttl = rrset(
        "null.example.org",
        RecordType::A,
        Some(3600),
        &["192.0.2.1"],
    );
    let e = client
        .set_rrset(&zone(), &with_ttl, Expect::Matches(&with_ttl))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(record_writes(&mock), 0);
    assert_eq!(stored(&mock, REC, "A"), ["192.0.2.1"]);

    // The expectation holds: with the TTL, and without one.
    let current = rrset(REC, RecordType::A, Some(600), &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&current))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &missing, Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    let no_ttl = rrset(REC, RecordType::A, None, &["192.0.2.9"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wrong, Expect::Matches(&no_ttl))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, REC, "A"), ["192.0.2.2"]);
}

/// `Expect::Any` replaces the records in one `set_records` request; the comments of the records
/// that stay and the rrset's labels survive; the TTL is kept unless one is requested, a `null`
/// one included, and a requested TTL is set with `change_ttl` after the records; a new rrset is
/// created with its records and the configured TTL in one request.
#[tokio::test]
async fn hetzner_set_replaces_and_keeps_what_the_model_does_not_carry() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(
        "example.org",
        REC,
        "A",
        Some(600),
        &["192.0.2.1", "192.0.2.2"],
    );
    control.update_rrset("example.org", REC, "A", |set| {
        set.records[0].comment = "web server 1".into();
        set.labels = vec![("env".into(), "prod".into())];
    });

    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.1", "192.0.2.9"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let set = control.rrset(REC, "A").unwrap();
    assert_eq!(set.ttl, Some(600), "the TTL is kept");
    assert_eq!(set.labels, [("env".to_owned(), "prod".to_owned())]);
    assert_eq!(set.values(), ["192.0.2.1", "192.0.2.9"]);
    assert_eq!(set.records[0].comment, "web server 1");
    let request = mock
        .log()
        .matching(Some("POST"), SET_RECORDS)
        .pop()
        .unwrap();
    assert_eq!(
        request.body_json().unwrap(),
        serde_json::json!({"records": [
            {"value": "192.0.2.1", "comment": "web server 1"},
            {"value": "192.0.2.9"}
        ]})
    );
    assert_eq!(mock.log().count(Some("POST"), CHANGE_TTL), 0);
    assert_eq!(mock.log().count(Some("POST"), RRSETS), 0);
    assert_eq!(mock.log().count(Some("POST"), ADD), 0);
    assert_eq!(mock.log().count(Some("POST"), REMOVE), 0);

    // A requested TTL alone is one `change_ttl`; the records are not sent again.
    let retuned = rrset(REC, RecordType::A, Some(120), &["192.0.2.1", "192.0.2.9"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &retuned, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(control.rrset(REC, "A").unwrap().ttl, Some(120));
    assert_eq!(mock.log().count(Some("POST"), SET_RECORDS), 1);
    let request = mock.log().matching(Some("POST"), CHANGE_TTL).pop().unwrap();
    assert_eq!(
        request.body_json().unwrap(),
        serde_json::json!({"ttl": 120})
    );
    assert!(
        request.path.ends_with("/rrsets/rec/A/actions/change_ttl"),
        "{}",
        request.path
    );

    // Records and TTL: the records first, then the TTL.
    mock.log().clear();
    let both = rrset(REC, RecordType::A, Some(300), &["192.0.2.9"]);
    client.set_rrset(&zone(), &both, Expect::Any).await.unwrap();
    let order: Vec<String> = mock
        .log()
        .entries()
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .map(|r| r.path)
        .collect();
    assert_eq!(order.len(), 2, "{order:?}");
    assert!(order[0].ends_with("/actions/set_records"), "{order:?}");
    assert!(order[1].ends_with("/actions/change_ttl"), "{order:?}");
    let set = control.rrset(REC, "A").unwrap();
    assert_eq!(set.ttl, Some(300));
    assert_eq!(set.records.len(), 1);
    assert_eq!(set.records[0].comment, "", "the kept record's comment");
    assert_eq!(set.labels, [("env".to_owned(), "prod".to_owned())]);
    // A requested TTL equal to the rrset's: only the records are sent.
    let same_ttl = rrset(REC, RecordType::A, Some(300), &["192.0.2.8"]);
    client
        .set_rrset(&zone(), &same_ttl, Expect::Any)
        .await
        .unwrap();
    assert_eq!(mock.log().count(Some("POST"), SET_RECORDS), 2);
    assert_eq!(mock.log().count(Some("POST"), CHANGE_TTL), 1);
    assert_eq!(stored(&mock, REC, "A"), ["192.0.2.8"]);

    // An rrset with the zone's default TTL keeps it; a requested TTL sets one.
    control.insert_rrset("example.org", "null.example.org", "A", None, &["192.0.2.1"]);
    let grown = rrset(
        "null.example.org",
        RecordType::A,
        None,
        &["192.0.2.1", "192.0.2.5"],
    );
    mock.log().clear();
    client
        .set_rrset(&zone(), &grown, Expect::Any)
        .await
        .unwrap();
    assert_eq!(control.rrset("null.example.org", "A").unwrap().ttl, None);
    assert_eq!(mock.log().count(Some("POST"), CHANGE_TTL), 0);
    assert_eq!(
        client
            .get_rrset(&zone(), &dn("null.example.org"), RecordType::A)
            .await
            .unwrap()
            .unwrap()
            .ttl(),
        Some(RrsetTtl::ProviderDefault)
    );
    let fixed = grown
        .clone()
        .with_ttl(Some(RrsetTtl::from_secs(600).unwrap()));
    client
        .set_rrset(&zone(), &fixed, Expect::Any)
        .await
        .unwrap();
    assert_eq!(
        control.rrset("null.example.org", "A").unwrap().ttl,
        Some(600)
    );
    assert_eq!(mock.log().count(Some("POST"), SET_RECORDS), 1);
    assert_eq!(mock.log().count(Some("POST"), CHANGE_TTL), 1);

    // A new rrset without a TTL gets the configured one, in the create.
    let fresh = rrset("fresh.example.org", RecordType::A, None, &["192.0.2.1"]);
    client
        .set_rrset(&zone(), &fresh, Expect::Any)
        .await
        .unwrap();
    assert_eq!(
        control.rrset("fresh.example.org", "A").unwrap().ttl,
        Some(60)
    );
    let post = mock.log().matching(Some("POST"), RRSETS).pop().unwrap();
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({
            "name": "fresh",
            "type": "A",
            "ttl": 60,
            "records": [{"value": "192.0.2.1"}]
        })
    );
    assert_eq!(mock.log().count(Some("POST"), CHANGE_TTL), 1);
}

/// `delete_rrset` with each expectation: deleted under a matching one, `NotPresent` without a
/// write when there is nothing, `Expect::Absent` refused before any request.
#[tokio::test]
async fn hetzner_delete_rrset_expectations() {
    let (mock, client) = setup().await;
    let a = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    client.set_rrset(&zone(), &a, Expect::Absent).await.unwrap();
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Matches(&a))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert_eq!(mock.log().count(Some("DELETE"), ANY_RRSET), 1);
    let before = record_writes(&mock);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
    assert_eq!(record_writes(&mock), before);
    let requests = mock.log().len();
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Absent)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(
        mock.log().len(),
        requests,
        "an invalid delete made a request"
    );
    // `Any` deletes whatever is there.
    mock.control().insert_rrset(
        "example.org",
        REC,
        "A",
        Some(600),
        &["192.0.2.1", "192.0.2.2"],
    );
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(mock.control().rrset(REC, "A").is_none());
}

/// SOA is read-only and the apex NS set belongs to the provider: writes are refused before any
/// request, reading them works, and a delegation below the apex is ordinary data. An rrset
/// with change protection is not changed: a write or a delete is `Rejected` after the read and
/// sends nothing, while a set that is already as requested is `Unchanged`.
#[tokio::test]
async fn hetzner_protected_sets_send_nothing() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let soa_text = "hydrogen.ns.hetzner.com. dns.hetzner.com. 2026111401 86400 10800 3600000 3600";
    control.insert_rrset("example.org", "@", "SOA", Some(3600), &[soa_text]);
    control.insert_rrset(
        "example.org",
        "@",
        "NS",
        Some(3600),
        &["hydrogen.ns.hetzner.com.", "oxygen.ns.hetzner.com."],
    );
    let soa = rrset("example.org", RecordType::SOA, None, &[soa_text]);
    let apex_ns = rrset("example.org", RecordType::NS, None, &["ns.example.com."]);
    let e = client
        .set_rrset(&zone(), &soa, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");
    let e = client
        .set_rrset(&zone(), &apex_ns, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &zone(), RecordType::NS, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
    assert_eq!(
        client
            .get_rrset(&zone(), &zone(), RecordType::SOA)
            .await
            .unwrap(),
        Some(rrset(
            "example.org",
            RecordType::SOA,
            Some(3600),
            &[soa_text]
        ))
    );
    assert_eq!(
        client
            .get_rrset(&zone(), &zone(), RecordType::NS)
            .await
            .unwrap()
            .unwrap()
            .records()
            .len(),
        2
    );
    let delegation = rrset(
        "sub.example.org",
        RecordType::NS,
        None,
        &["ns.example.com."],
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &delegation, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Created
    );

    // Change protection.
    control.insert_rrset("example.org", REC, "A", Some(600), &["192.0.2.1"]);
    control.update_rrset("example.org", REC, "A", |set| set.protected = true);
    let before = record_writes(&mock);
    for set in [
        rrset(REC, RecordType::A, None, &["192.0.2.2"]),
        rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]),
    ] {
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    }
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(record_writes(&mock), before);
    assert_eq!(
        client
            .set_rrset(
                &zone(),
                &rrset(REC, RecordType::A, None, &["192.0.2.1"]),
                Expect::Any
            )
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    assert_eq!(stored(&mock, REC, "A"), ["192.0.2.1"]);
}

/// The TTL range of the API, inclusive, is checked before any request.
#[tokio::test]
async fn hetzner_record_ttl_bounds() {
    let (mock, client) = setup().await;
    for ttl in [0, 59] {
        let set = rrset(REC, RecordType::A, Some(ttl), &["192.0.2.1"]);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{ttl}: {e:?}");
    }
    assert!(mock.log().is_empty());
    for ttl in [60, 2_147_483_647] {
        let set = rrset(REC, RecordType::A, Some(ttl), &["192.0.2.1"]);
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
        assert_eq!(mock.control().rrset(REC, "A").unwrap().ttl, Some(ttl));
    }
}

/// An rrset holds at most 50 records (`set_records`): a larger request is refused before any
/// request.
#[tokio::test]
async fn hetzner_record_level_record_limit() {
    let (mock, client) = setup().await;
    let texts: Vec<String> = (0..51).map(|i| format!("10.0.0.{i}")).collect();
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &refs),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty());
    client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &refs[..50]),
            Expect::Any,
        )
        .await
        .unwrap();
    assert_eq!(stored(&mock, REC, "A").len(), 50);
    client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &refs[1..]),
            Expect::Any,
        )
        .await
        .unwrap();
    assert_eq!(stored(&mock, REC, "A").len(), 50);
}

/// A value whose canonical text needs an escape is not sent (the API's escape handling is not
/// established); one the rrset already holds is written back exactly as the API returned it.
/// Non-canonical data can be written back, never introduced.
#[tokio::test]
async fn hetzner_escapes_and_non_canonical_data() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for text in ["\"say \\\"hi\\\"\"", "\"caf\\195\\169\"", "\"a\\\\b\""] {
        let set = rrset(REC, RecordType::TXT, None, &[text]);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{text}: {e:?}");
    }
    assert_eq!(record_writes(&mock), 0);

    // Held by the provider: kept verbatim while a plain value joins it.
    let held = "\"say \\\"hi\\\"\"";
    control.insert_rrset("example.org", REC, "TXT", Some(600), &[held]);
    let both = rrset(REC, RecordType::TXT, None, &[held, "\"plain\""]);
    assert_eq!(
        client.set_rrset(&zone(), &both, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, REC, "TXT"), [held, "\"plain\""]);

    // Provider text the parser refuses (a label of 64 octets, which the mock lets through):
    // carried as non-canonical data, written back unchanged.
    let odd = format!("{}.example.net.", "x".repeat(64));
    control.insert_rrset(
        "example.org",
        "odd.example.org",
        "NS",
        Some(600),
        &[odd.as_str()],
    );
    let listed = client
        .get_rrset(&zone(), &dn("odd.example.org"), RecordType::NS)
        .await
        .unwrap()
        .unwrap();
    assert!(!listed.records()[0].is_canonical());
    assert_eq!(listed.records()[0].as_str(), odd);
    let mut members = listed.records().to_vec();
    members.push(rd(RecordType::NS, "ns1.example.net."));
    let extended = RrSet::new(dn("odd.example.org"), RecordType::NS, None, members).unwrap();
    assert_eq!(
        client
            .set_rrset(&zone(), &extended, Expect::Matches(&listed))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        stored(&mock, "odd.example.org", "NS"),
        [odd.clone(), "ns1.example.net.".to_owned()]
    );
    // The only public way to build non-canonical data is to deserialize a stored set.
    let introduced: RrSet = serde_json::from_value(serde_json::json!({
        "name": "new.example.org.",
        "type": "A",
        "ttl": null,
        "records": [{"raw": "not an address"}]
    }))
    .unwrap();
    let before = record_writes(&mock);
    let e = client
        .set_rrset(&zone(), &introduced, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(record_writes(&mock), before);
}

/// The listing holds every rrset of every type, also outside the record-level list (CAA),
/// SOA and the apex NS set included; a value the parser refuses is non-canonical data; what
/// the model cannot hold (an unknown type name, an owner name that is not a valid name, two
/// records of a singleton type) is in `skipped`.
#[tokio::test(flavor = "current_thread")]
async fn hetzner_listing_reports_skipped_sets() {
    let (capture, _guard) = LogCapture::install();
    let (mock, client) = setup().await;
    let control = mock.control();
    let soa_text = "hydrogen.ns.hetzner.com. dns.hetzner.com. 2026111401 86400 10800 3600000 3600";
    control.insert_rrset("example.org", "@", "SOA", Some(3600), &[soa_text]);
    control.insert_rrset(
        "example.org",
        "@",
        "NS",
        Some(3600),
        &["hydrogen.ns.hetzner.com."],
    );
    control.insert_rrset("example.org", REC, "A", None, &["192.0.2.1", "192.0.2.2"]);
    control.insert_rrset("example.org", REC, "TXT", Some(600), &["\"v=spf1 -all\""]);
    control.insert_rrset(
        "example.org",
        "@",
        "CAA",
        Some(600),
        &["0 issue \"letsencrypt.org\""],
    );
    control.insert_rrset("example.org", "odd", "A", Some(600), &["not-an-address"]);
    control.insert_rrset("example.org", "w", "WIZARD", Some(600), &["magic"]);
    let long_label = "x".repeat(64);
    control.insert_rrset("example.org", &long_label, "A", Some(600), &["192.0.2.1"]);
    control.insert_rrset(
        "example.org",
        "c",
        "CNAME",
        Some(600),
        &["a.example.net.", "b.example.net."],
    );
    // Another zone's rrset is not part of the listing.
    control.add_zone("example.com", "primary");
    control.insert_rrset("example.com", "other", "A", Some(600), &["192.0.2.7"]);

    let listing = client.list_rrsets(&zone()).await.unwrap();
    let sets: Vec<(String, RecordType)> = listing
        .rrsets
        .iter()
        .map(|s| (s.name().to_string(), s.rtype()))
        .collect();
    assert_eq!(
        sets,
        [
            ("example.org.".to_owned(), RecordType::NS),
            ("example.org.".to_owned(), RecordType::SOA),
            ("example.org.".to_owned(), RecordType::CAA),
            ("odd.example.org.".to_owned(), RecordType::A),
            ("rec.example.org.".to_owned(), RecordType::A),
            ("rec.example.org.".to_owned(), RecordType::TXT),
        ]
    );
    let rec_a = listing
        .rrsets
        .iter()
        .find(|s| s.name() == &dn(REC) && s.rtype() == RecordType::A)
        .unwrap();
    assert_eq!(
        rec_a,
        &rrset(REC, RecordType::A, None, &["192.0.2.1", "192.0.2.2"])
            .with_ttl(Some(RrsetTtl::ProviderDefault))
    );
    let caa = listing
        .rrsets
        .iter()
        .find(|s| s.rtype() == RecordType::CAA)
        .unwrap();
    assert!(caa.records()[0].is_canonical(), "CAA parses");
    let odd = listing
        .rrsets
        .iter()
        .find(|s| s.name() == &dn("odd.example.org"))
        .unwrap();
    assert!(!odd.records()[0].is_canonical());
    assert_eq!(odd.records()[0].as_str(), "not-an-address");
    let mut skipped: Vec<(String, String, SkipReason)> = listing
        .skipped
        .iter()
        .map(|s| (s.name.to_string(), s.type_name.clone(), s.reason))
        .collect();
    skipped.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        skipped,
        [
            (
                "c.example.org.".to_owned(),
                "CNAME".to_owned(),
                SkipReason::NotPlainRecords
            ),
            (
                "example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::UnsupportedName
            ),
            (
                "w.example.org.".to_owned(),
                "WIZARD".to_owned(),
                SkipReason::UnknownType
            ),
        ]
    );
    // One `WARN` event for the listing, with the number of skipped sets.
    let warnings: Vec<_> = capture
        .entries()
        .into_iter()
        .filter(|e| e.target == "zonewright::rrsets" && e.level == tracing::Level::WARN)
        .collect();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert_eq!(warnings[0].field("skipped"), Some("3"));
    assert_eq!(warnings[0].field("provider"), Some("hetzner"));
    // One unfiltered listing.
    let lists = mock.log().matching(Some("GET"), RRSETS);
    assert_eq!(lists.len(), 1);
    let query = lists[0].query.clone().unwrap_or_default();
    assert!(
        !query.contains("name=") && !query.contains("type="),
        "{query}"
    );
}

/// The listing reads every page by number, at the largest page size.
#[tokio::test]
async fn hetzner_listing_reads_every_page() {
    let (mock, client) = setup().await;
    for i in 0..101 {
        mock.control().insert_rrset(
            "example.org",
            &format!("h{i}"),
            "A",
            Some(60),
            &["192.0.2.1"],
        );
    }
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(listing.rrsets.len(), 101);
    let lists = mock.log().matching(Some("GET"), RRSETS);
    assert_eq!(lists.len(), 3);
    for (i, request) in lists.iter().enumerate() {
        let query = request.query.clone().unwrap_or_default();
        assert!(query.contains("per_page=50"), "{query}");
        assert!(query.contains(&format!("page={}", i + 1)), "{query}");
    }
    // The same with the total unknown.
    mock.control().set_null_total(true);
    assert_eq!(client.list_rrsets(&zone()).await.unwrap().rrsets.len(), 101);
}

/// An rrset listing that stops short of its stated total, lacks its list or its pagination,
/// or is answered `404` for a zone that is gone is an error, never a shorter result.
#[tokio::test]
async fn hetzner_truncated_rrset_listing_is_protocol() {
    let (mock, client) = setup().await;
    let item = r#"{"id":"rec/A","name":"rec","type":"A","ttl":60,"labels":{},"protection":{"change":false},"zone":1001,"records":[{"value":"192.0.2.1"}]}"#;
    let short = format!(
        r#"{{"rrsets":[{item}],"meta":{{"pagination":{{"page":1,"per_page":50,"previous_page":null,"next_page":null,"last_page":null,"total_entries":3}}}}}}"#
    );
    let no_list = r#"{"meta":{"pagination":{"page":1,"per_page":50,"previous_page":null,"next_page":null,"last_page":null,"total_entries":0}}}"#;
    let no_meta = format!(r#"{{"rrsets":[{item}]}}"#);
    let empty_before_end = r#"{"rrsets":[],"meta":{"pagination":{"page":1,"per_page":50,"previous_page":null,"next_page":2,"last_page":2,"total_entries":null}}}"#;
    let no_ttl = format!(
        r#"{{"rrsets":[{}],"meta":{{"pagination":{{"page":1,"per_page":50,"previous_page":null,"next_page":null,"last_page":null,"total_entries":1}}}}}}"#,
        item.replace(r#""ttl":60,"#, "")
    );
    for body in [
        short.as_str(),
        no_list,
        no_meta.as_str(),
        empty_before_end,
        no_ttl.as_str(),
    ] {
        mock.faults()
            .push(Fault::on("GET", RRSETS).respond(200, body.to_owned()));
        let e = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    // The zone is gone: the cached identifier is not trusted, the zone is looked up again.
    mock.control().delete_zone("example.org");
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ZoneNotFound, "{e:?}");
}

/// A zone deleted and created again gets a new identifier: the listing and the record-level
/// operations look it up again and act on the new zone.
#[tokio::test]
async fn hetzner_record_level_stale_zone_id() {
    let (mock, client) = setup().await;
    let a = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    client.set_rrset(&zone(), &a, Expect::Absent).await.unwrap();
    let new_id = mock.control().recreate_zone("example.org", true);
    assert_eq!(
        client.list_rrsets(&zone()).await.unwrap().rrsets,
        std::slice::from_ref(&a)
    );
    let b = rrset(REC, RecordType::A, Some(300), &["192.0.2.2"]);
    mock.control().recreate_zone("example.org", true);
    assert_eq!(
        client
            .set_rrset(&zone(), &b, Expect::Matches(&a))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, REC, "A"), ["192.0.2.2"]);
    assert!(new_id > 0);
    mock.control().recreate_zone("example.org", true);
    assert_eq!(
        client
            .get_rrset(&zone(), &dn(REC), RecordType::A)
            .await
            .unwrap(),
        Some(b.clone())
    );
    mock.control().recreate_zone("example.org", true);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Matches(&b))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(mock.control().rrsets().is_empty());
}

/// Rrsets at other names (a longer name, a name below) and other types at the same name are
/// never touched by a create, a replacement or a delete.
#[tokio::test]
async fn hetzner_record_operations_leave_other_sets_alone() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let others = [
        ("xrec.example.org", "A"),
        ("a.rec.example.org", "A"),
        (REC, "TXT"),
        (REC, "MX"),
        (REC, "AAAA"),
    ];
    for (name, rtype) in others {
        let value = match rtype {
            "TXT" => "\"foreign\"",
            "MX" => "10 mail.example.org.",
            "AAAA" => "2001:db8::7",
            _ => "198.51.100.1",
        };
        control.insert_rrset("example.org", name, rtype, Some(900), &[value]);
    }
    let before: Vec<_> = others
        .iter()
        .map(|(name, rtype)| control.rrset(name, rtype).unwrap())
        .collect();
    let a = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    client.set_rrset(&zone(), &a, Expect::Absent).await.unwrap();
    let b = rrset(REC, RecordType::A, Some(120), &["192.0.2.2", "192.0.2.3"]);
    client.set_rrset(&zone(), &b, Expect::Any).await.unwrap();
    client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap();
    for ((name, rtype), before) in others.iter().zip(before) {
        assert_eq!(
            control.rrset(name, rtype).unwrap(),
            before,
            "{name} {rtype}"
        );
    }
    assert!(control.rrset(REC, "A").is_none());
    // An answer about another rrset (another type, another name) is never taken for ours.
    for wrong in [
        r#"{"rrset":{"id":"rec/TXT","name":"rec","type":"TXT","ttl":900,"labels":{},"protection":{"change":false},"zone":1001,"records":[{"value":"\"foreign\""}]}}"#,
        r#"{"rrset":{"id":"xrec/A","name":"xrec","type":"A","ttl":900,"labels":{},"protection":{"change":false},"zone":1001,"records":[{"value":"198.51.100.1"}]}}"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", "/v1/zones/*/rrsets/rec/A").respond(200, wrong));
        let e = client
            .set_rrset(&zone(), &a, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
        mock.faults()
            .push(Fault::on("GET", "/v1/zones/*/rrsets/rec/A").respond(200, wrong));
        let e = client
            .get_rrset(&zone(), &dn(REC), RecordType::A)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    }
    assert!(control.rrset(REC, "A").is_none());
    // Every write addressed the rrset `rec`/`A` only.
    for request in mock.log().entries() {
        if request.method.as_str() != "GET" && request.path.contains("/rrsets/") {
            assert!(request.path.contains("/rrsets/rec/A"), "{}", request.path);
        }
    }
}

/// Two clients sharing a `Context` create the same rrset at once, the first write delayed: the
/// second reads after the first wrote and its `Absent` fails. Without the name lock both would
/// read "no rrset" and the second create would meet the first one's rrset.
#[tokio::test]
async fn hetzner_concurrent_sets_are_serialized() {
    let mock = HetznerMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, TOKEN, &ctx);
    let b = client_with(&mock, TOKEN, &ctx);
    mock.faults()
        .push(Fault::on("POST", RRSETS).delay(Duration::from_millis(300)));
    let first = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    let second = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    let (zone, rec) = (zone(), dn(REC));
    let (ra, rb) = tokio::join!(
        a.set_rrset(&zone, &first, Expect::Absent),
        b.set_rrset(&zone, &second, Expect::Absent),
    );
    let mut kinds = [ra.map_err(|e| e.kind()), rb.map_err(|e| e.kind())];
    kinds.sort_by_key(|r| format!("{r:?}"));
    assert_eq!(
        kinds,
        [Err(ErrorKind::PreconditionFailed), Ok(SetOutcome::Created)]
    );
    assert_eq!(mock.log().count(Some("POST"), RRSETS), 1);
    // A delete and a set at once: whichever runs second sees the first one's result.
    let (rd_, rs) = tokio::join!(
        a.delete_rrset(&zone, &rec, RecordType::A, Expect::Any),
        b.set_rrset(&zone, &second, Expect::Any),
    );
    rd_.unwrap();
    rs.unwrap();
    let left = stored(&mock, REC, "A");
    assert!(left.is_empty() || left == ["192.0.2.2"], "{left:?}");
}

/// A create refused because the rrset appeared after the read is a retryable `Conflict`, and
/// nothing is overwritten (the mock's `409` is invented; the client decides by a new read). A
/// refusal with no rrset there afterwards is the refusal.
#[tokio::test]
async fn hetzner_record_create_race_is_conflict() {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("POST", RRSETS).pass().run(move || {
            hook.insert_rrset("example.org", REC, "A", Some(900), &["198.51.100.1"]);
        }));
    let set = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &set, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(stored(&mock, REC, "A"), ["198.51.100.1"]);
    assert_eq!(mock.log().count(Some("POST"), RRSETS), 1);
    // The repeat reads the new state: with `Absent` it fails, with `Any` it replaces.
    let e = client
        .set_rrset(&zone(), &set, Expect::Absent)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    // A refusal with nothing there afterwards is the provider's refusal.
    mock.faults().push(Fault::on("POST", RRSETS).respond(
        422,
        r#"{"error":{"code":"invalid_input","message":"invalid value","details":null}}"#,
    ));
    let other = rrset("other.example.org", RecordType::A, None, &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &other, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(mock.control().rrset("other.example.org", "A").is_none());
}

/// Every record-level write is sent once: a 502, a 429 and a 401 on the create, the record
/// replacement, the TTL change and the delete are the operation's error, with exactly one such
/// request each; the repeat starts with a read and converges.
#[tokio::test]
async fn hetzner_record_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let a = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    let b = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    let c = rrset(REC, RecordType::A, Some(600), &["192.0.2.2"]);
    for (method, path) in [
        ("POST", RRSETS),
        ("POST", SET_RECORDS),
        ("POST", CHANGE_TTL),
        ("DELETE", ANY_RRSET),
    ] {
        let mut sent = 0;
        for (fault, kind) in [
            (Fault::on(method, path).status(502), ErrorKind::Transient),
            (
                Fault::on(method, path).rate_limited("1"),
                ErrorKind::RateLimited,
            ),
            (Fault::on(method, path).status(401), ErrorKind::Auth),
        ] {
            mock.faults().push(fault);
            let result = match path {
                RRSETS => client.set_rrset(&zone(), &a, Expect::Any).await.map(|_| ()),
                SET_RECORDS => client.set_rrset(&zone(), &b, Expect::Any).await.map(|_| ()),
                CHANGE_TTL => client.set_rrset(&zone(), &c, Expect::Any).await.map(|_| ()),
                _ => client
                    .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
                    .await
                    .map(|_| ()),
            };
            let e = result.unwrap_err();
            assert_eq!(e.kind(), kind, "{method} {path}: {e:?}");
            sent += 1;
            assert_eq!(
                mock.log().count(Some(method), path),
                sent,
                "{method} {path}"
            );
        }
        // Without a fault the operation goes through: one more request of that kind.
        match path {
            RRSETS => assert_eq!(
                client.set_rrset(&zone(), &a, Expect::Any).await.unwrap(),
                SetOutcome::Created
            ),
            SET_RECORDS => assert_eq!(
                client.set_rrset(&zone(), &b, Expect::Any).await.unwrap(),
                SetOutcome::Replaced
            ),
            CHANGE_TTL => assert_eq!(
                client.set_rrset(&zone(), &c, Expect::Any).await.unwrap(),
                SetOutcome::Replaced
            ),
            _ => assert_eq!(
                client
                    .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            ),
        }
        assert_eq!(
            mock.log().count(Some(method), path),
            sent + 1,
            "{method} {path}"
        );
    }
    assert!(mock.control().rrsets().is_empty());
    // A write answered 502 that the API applied: the repeat finds the set as requested.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("POST", RRSETS)
            .run(move || hook.insert_rrset("example.org", REC, "A", Some(300), &["192.0.2.1"]))
            .status(502),
    );
    let e = client
        .set_rrset(&zone(), &a, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    let posts = mock.log().count(Some("POST"), RRSETS);
    assert_eq!(
        client.set_rrset(&zone(), &a, Expect::Any).await.unwrap(),
        SetOutcome::Unchanged
    );
    assert_eq!(mock.log().count(Some("POST"), RRSETS), posts);
}

/// A failure between the replacement of the records and the TTL change leaves the new records
/// with the old TTL; the repeat sends only the TTL change. A failed action changes nothing and
/// is `Rejected`.
#[tokio::test]
async fn hetzner_record_replacement_fails_part_way_and_converges() {
    let (mock, client) = setup().await;
    mock.control()
        .insert_rrset("example.org", REC, "A", Some(600), &["192.0.2.1"]);
    let wanted = rrset(REC, RecordType::A, Some(300), &["192.0.2.2"]);
    mock.faults()
        .push(Fault::on("POST", CHANGE_TTL).status(502));
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    let set = mock.control().rrset(REC, "A").unwrap();
    assert_eq!(set.values(), ["192.0.2.2"]);
    assert_eq!(set.ttl, Some(600));
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(mock.log().count(Some("POST"), SET_RECORDS), 1);
    assert_eq!(mock.log().count(Some("POST"), CHANGE_TTL), 2);
    assert_eq!(mock.control().rrset(REC, "A").unwrap().ttl, Some(300));

    mock.control()
        .fail_next_action("invalid_input", "the value is not valid");
    let other = rrset(REC, RecordType::A, None, &["192.0.2.3"]);
    let e = client
        .set_rrset(&zone(), &other, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(e.to_string().contains("the value is not valid"), "{e}");
    assert_eq!(stored(&mock, REC, "A"), ["192.0.2.2"]);
}

/// A replacement answered "not found" means that the rrset or the zone went away after the
/// read: `Conflict`, nothing written, and the repeat creates it. A delete answered "not found"
/// is done when a new read finds no rrset; a zone recreated with the rrset in it is a conflict.
#[tokio::test]
async fn hetzner_record_writes_not_found_read_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset("example.org", REC, "A", Some(600), &["192.0.2.1"]);
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("POST", SET_RECORDS).run(move || {
            hook.delete_rrset("example.org", REC, "A");
        }));
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(control.rrset(REC, "A").is_none());
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Created
    );

    let hook = control.clone();
    mock.faults()
        .push(Fault::on("DELETE", ANY_RRSET).run(move || {
            hook.delete_rrset("example.org", REC, "A");
        }));
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );

    control.insert_rrset("example.org", REC, "A", Some(600), &["192.0.2.1"]);
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("DELETE", ANY_RRSET).run(move || {
            hook.recreate_zone("example.org", true);
        }));
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(stored(&mock, REC, "A"), ["192.0.2.1"]);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(control.rrsets().is_empty());
}

/// The record-level operations on a zone in secondary mode are `Rejected` before any write.
#[tokio::test]
async fn hetzner_record_level_secondary_zone() {
    let (mock, client) = setup().await;
    let zone = dn("mirror.example.net");
    let set = rrset(
        "www.mirror.example.net",
        RecordType::A,
        None,
        &["192.0.2.1"],
    );
    let errors = [
        client.list_rrsets(&zone).await.unwrap_err(),
        client
            .get_rrset(&zone, set.name(), RecordType::A)
            .await
            .unwrap_err(),
        client
            .set_rrset(&zone, &set, Expect::Any)
            .await
            .unwrap_err(),
        client
            .delete_rrset(&zone, set.name(), RecordType::A, Expect::Any)
            .await
            .unwrap_err(),
    ];
    for e in errors {
        assert!(
            matches!(
                e,
                Error::Rejected {
                    status: Some(422),
                    ..
                }
            ),
            "{e:?}"
        );
    }
    assert_eq!(record_writes(&mock), 0);
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
            let report = client.check([&zone]).await.unwrap();
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
    if !cleanup.is_empty() {
        eprintln!("cleanup failed: {cleanup:?}");
    }
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}

/// A record-level round trip on an A rrset under a generated label (documentation addresses of
/// RFC 5737): create, read, replace with new records and a new TTL (`set_records` and then
/// `change_ttl`), unchanged repeat, list, delete. The cleanup deletes that rrset, the only one
/// the test wrote, also when the body failed.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_hetzner_record_round_trip() {
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
    let rec_name = zone.prepend(&format!("_zw-live-{tag:016x}")).unwrap();
    let records = {
        let (client, zone, rec_name) = (client.clone(), zone.clone(), rec_name.clone());
        tokio::spawn(async move {
            let first = RrSet::new(
                rec_name.clone(),
                RecordType::A,
                Some(RrsetTtl::from_secs(300).unwrap()),
                [rd(RecordType::A, "192.0.2.10")],
            )
            .unwrap();
            assert_eq!(
                client
                    .set_rrset(&zone, &first, Expect::Absent)
                    .await
                    .unwrap(),
                SetOutcome::Created
            );
            let read = client
                .get_rrset(&zone, &rec_name, RecordType::A)
                .await
                .unwrap();
            assert_eq!(read.as_ref(), Some(&first));
            let second = RrSet::new(
                rec_name.clone(),
                RecordType::A,
                Some(RrsetTtl::from_secs(600).unwrap()),
                [
                    rd(RecordType::A, "192.0.2.10"),
                    rd(RecordType::A, "192.0.2.11"),
                ],
            )
            .unwrap();
            assert_eq!(
                client
                    .set_rrset(&zone, &second, Expect::Matches(&first))
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                client
                    .set_rrset(&zone, &second, Expect::Matches(&second))
                    .await
                    .unwrap(),
                SetOutcome::Unchanged
            );
            let listing = client.list_rrsets(&zone).await.unwrap();
            assert!(listing.rrsets.contains(&second), "{listing:?}");
            assert_eq!(
                client
                    .delete_rrset(&zone, &rec_name, RecordType::A, Expect::Matches(&second))
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
            assert_eq!(
                client
                    .get_rrset(&zone, &rec_name, RecordType::A)
                    .await
                    .unwrap(),
                None
            );
        })
        .await
    };

    // Cleanup: the A rrset under the generated label, the only one the test wrote.
    let cleanup = client
        .delete_rrset(&zone, &rec_name, RecordType::A, Expect::Any)
        .await;
    if let Err(c) = &cleanup {
        eprintln!("cleanup failed: {c:?}");
    }
    if let Err(e) = records {
        std::panic::resume_unwind(e.into_panic());
    }
    if let Err(e) = cleanup {
        panic!("cleanup failed: {e}");
    }
}

/// The zone's default TTL (design section 3.6): a `null` TTL. A set created with it (no `ttl`
/// in the create), a switch from a number to it by `change_ttl` with `ttl: null` and back,
/// unchanged round trips in both states, expectations of each kind, the `ttl` setting's
/// spellings, and a TXT value added with it (no `ttl` in `add_records`).
#[tokio::test]
async fn hetzner_provider_default_ttl() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let default = Some(RrsetTtl::ProviderDefault);
    let set = |ttl: Option<RrsetTtl>| {
        rrset(REC, RecordType::A, None, &["192.0.2.1", "192.0.2.2"]).with_ttl(ttl)
    };

    // Created without a TTL.
    assert_eq!(
        client
            .set_rrset(&zone(), &set(default), Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    let create = mock.log().matching(Some("POST"), RRSETS).pop().unwrap();
    assert!(create.body_json().unwrap().get("ttl").is_none());
    assert_eq!(control.rrset(REC, "A").unwrap().ttl, None);
    let read = client
        .get_rrset(&zone(), &dn(REC), RecordType::A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, set(default));
    let before = writes(&mock);
    for wanted in [read.clone(), set(None)] {
        assert_eq!(
            client
                .set_rrset(&zone(), &wanted, Expect::Matches(&read))
                .await
                .unwrap(),
            SetOutcome::Unchanged
        );
    }
    let e = client
        .set_rrset(
            &zone(),
            &set(None),
            Expect::Matches(&set(Some(RrsetTtl::from_secs(60).unwrap()))),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed);
    assert_eq!(writes(&mock), before);

    // Default to explicit, and back: `change_ttl` with the number, then with `null`.
    let explicit = set(Some(RrsetTtl::from_secs(600).unwrap()));
    mock.log().clear();
    assert_eq!(
        client
            .set_rrset(&zone(), &explicit, Expect::Matches(&set(default)))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let change = mock.log().matching(Some("POST"), CHANGE_TTL);
    assert_eq!(change.len(), 1);
    assert_eq!(
        change[0].body_json().unwrap(),
        serde_json::json!({"ttl": 600})
    );
    assert_eq!(mock.log().count(Some("POST"), SET_RECORDS), 0);
    assert_eq!(control.rrset(REC, "A").unwrap().ttl, Some(600));
    let before = writes(&mock);
    assert_eq!(
        client
            .set_rrset(&zone(), &explicit, Expect::Matches(&explicit))
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    let e = client
        .set_rrset(&zone(), &explicit, Expect::Matches(&set(default)))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed);
    assert_eq!(writes(&mock), before);
    mock.log().clear();
    assert_eq!(
        client
            .set_rrset(&zone(), &set(default), Expect::Matches(&explicit))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let change = mock.log().matching(Some("POST"), CHANGE_TTL);
    assert_eq!(change.len(), 1);
    assert_eq!(
        change[0].body_json().unwrap(),
        serde_json::json!({"ttl": null})
    );
    assert_eq!(control.rrset(REC, "A").unwrap().ttl, None);

    // A TXT value added with the default creates the set without a TTL; later values keep it.
    client
        .add_txt_value(&zone(), &name(), &txt("AAA"), default)
        .await
        .unwrap();
    let add = mock.log().matching(Some("POST"), ADD).pop().unwrap();
    assert!(add.body_json().unwrap().get("ttl").is_none());
    client
        .add_txt_value(&zone(), &name(), &txt("BBB"), None)
        .await
        .unwrap();
    assert_eq!(control.rrset(NAME, "TXT").unwrap().ttl, None);

    // The setting: "provider_default" creates new sets without a TTL; a number keeps its
    // meaning.
    for (ttl, stored) in [
        (serde_json::json!("provider_default"), None),
        (serde_json::json!(300), Some(300)),
    ] {
        let mut settings: serde_json::Value = serde_json::from_str(&settings_json(&mock)).unwrap();
        settings["ttl"] = ttl.clone();
        let configured = AnyProvider::from_json(
            ProviderId::Hetzner,
            &settings.to_string(),
            &format!(r#"{{"api_token":"{TOKEN}"}}"#).into(),
            &context(),
        )
        .unwrap();
        let owner = format!("s{}.example.org", stored.unwrap_or(0));
        configured
            .set_rrset(
                &zone(),
                &rrset(&owner, RecordType::A, None, &["192.0.2.9"]),
                Expect::Absent,
            )
            .await
            .unwrap();
        assert_eq!(control.rrset(&owner, "A").unwrap().ttl, stored, "{ttl}");
    }
}

// ---- Link to the DNS mock ----------------------------------------------------------------------

#[cfg(feature = "inspector")]
mod dns_link {
    use std::sync::Mutex;

    use zonewright::{Expect, Provider, RecordType};
    use zonewright_mock::Fault;
    use zonewright_mock::changes::ChangeSource;
    use zonewright_mock::dns::{DnsMock, Role};
    use zonewright_mock::link::{LinkOptions, link};

    use super::{ACTION, NAME, add, rrset, setup};
    use crate::common::link::{ask, is_absent, rd, txt, txt_round_trip, values};

    /// A value written through the client is served over DNS once its action finished, and not
    /// while the action is still running.
    #[tokio::test]
    async fn hetzner_txt_value_is_served_over_dns() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = txt_round_trip(&mock, &client, &dns).await;

        // Three looks at the action: at each of them, before the mock answers, nothing new has
        // been published; the change is published by the look that finishes the action.
        mock.control().set_action_looks(3);
        let changes = mock.changes().clone();
        let start = changes.emitted();
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let hook_seen = seen.clone();
        mock.faults().push(
            Fault::on("GET", ACTION)
                .times(3)
                .run(move || hook_seen.lock().unwrap().push(changes.emitted())),
        );
        add(&client, "late").await.unwrap();
        assert_eq!(*seen.lock().unwrap(), [start, start, start]);
        assert_eq!(mock.changes().emitted(), start + 1);
        link.settled().await;
        assert_eq!(
            values(ask(dns.addr(), NAME, RecordType::TXT).await),
            [txt("late")]
        );
    }

    /// Names inside values are published fully qualified, also where the provider holds them
    /// relative to the zone; a zone that is not primary is not published.
    #[tokio::test]
    async fn hetzner_names_in_values_are_served_fully_qualified() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = link(&mock, &dns, LinkOptions::new());
        let zone = crate::common::dn("example.org");
        for set in [
            rrset(
                "alias.example.org",
                RecordType::CNAME,
                Some(300),
                &["target.example.net."],
            ),
            rrset(
                "example.org",
                RecordType::MX,
                Some(300),
                &["10 mail.example.org."],
            ),
        ] {
            client.set_rrset(&zone, &set, Expect::Any).await.unwrap();
        }
        // Spelled relative to the zone, as another writer may store them.
        let control = mock.control();
        control.insert_rrset("example.org", "rel", "MX", None, &["20 mx2"]);
        control.insert_rrset("example.org", "www", "CNAME", Some(600), &["web"]);
        control.insert_rrset("mirror.example.net", "www", "A", None, &["192.0.2.1"]);
        link.settled().await;
        assert_eq!(link.skipped(), 0);
        for (name, rtype, text) in [
            (
                "alias.example.org",
                RecordType::CNAME,
                "target.example.net.",
            ),
            ("example.org", RecordType::MX, "10 mail.example.org."),
            ("rel.example.org", RecordType::MX, "20 mx2.example.org."),
            ("www.example.org", RecordType::CNAME, "web.example.org."),
        ] {
            assert_eq!(
                values(ask(dns.addr(), name, rtype).await),
                [rd(rtype, text)],
                "{name} {rtype}"
            );
        }
        let published = mock.published();
        assert!(!published.zones.contains(&"mirror.example.net".to_owned()));
        assert!(published.rrsets.iter().all(|c| c.zone == "example.org"));
    }

    /// `reset` returns the mock to its seed: the record is gone from the mock and from DNS, the
    /// request log is empty, and the client works again.
    #[tokio::test]
    async fn hetzner_reset_returns_the_mock_to_its_seed() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = link(&mock, &dns, LinkOptions::new());
        add(&client, "before-reset").await.unwrap();
        link.settled().await;
        assert_eq!(
            values(ask(dns.addr(), NAME, RecordType::TXT).await),
            [txt("before-reset")]
        );
        mock.control().reset();
        link.settled().await;
        assert!(mock.control().rrsets().is_empty());
        assert!(mock.log().is_empty());
        let answer = ask(dns.addr(), NAME, RecordType::TXT).await;
        assert!(is_absent(&answer), "{answer:?}");
        add(&client, "after-reset").await.unwrap();
        link.settled().await;
        assert_eq!(
            values(ask(dns.addr(), NAME, RecordType::TXT).await),
            [txt("after-reset")]
        );
    }
}
