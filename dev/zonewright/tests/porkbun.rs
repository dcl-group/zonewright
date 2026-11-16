//! Tests of the Porkbun client (`porkbun`) against its mock.
#![cfg(feature = "porkbun")]
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
use zonewright::providers::porkbun::{Porkbun, PorkbunConfig, PorkbunCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl, SetOutcome,
    SkipReason, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::echo::{EchoServer, Echoed, Render};
use zonewright_mock::porkbun::{Paging, PorkbunMock, Seed};

use common::echo::{CANARY_KEY, CANARY_TOKEN, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The keys of the standard seed.
const KEY: &str = "pk1_test-only-key";
const SECRET: &str = "sk1_test-only-secret";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const PING: &str = "/api/json/v3/ping";
const LIST_ALL: &str = "/api/json/v3/domain/listAll";
const RETRIEVE: &str = "/api/json/v3/dns/retrieve/*";
const CREATE: &str = "/api/json/v3/dns/create/*";
const EDIT: &str = "/api/json/v3/dns/edit/*/*";
const DELETE: &str = "/api/json/v3/dns/delete/*/*";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings pointed at `base_url`.
fn settings(base_url: String) -> PorkbunConfig {
    let mut config = PorkbunConfig::default();
    config.base_url = base_url;
    config
}

fn credentials(key: &str, secret: &str) -> PorkbunCredentials {
    PorkbunCredentials::new(
        SecretString::from(key.to_owned()),
        SecretString::from(secret.to_owned()),
    )
}

fn client_with(mock: &PorkbunMock, key: &str, secret: &str, ctx: &Context) -> Porkbun {
    Porkbun::new(settings(mock.base_url()), credentials(key, secret), ctx).unwrap()
}

async fn setup() -> (PorkbunMock, Porkbun) {
    let mock = PorkbunMock::start(Seed::standard()).await;
    let client = client_with(&mock, KEY, SECRET, &context());
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
fn writes(mock: &PorkbunMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), CREATE)
        + log.count(Some("POST"), EDIT)
        + log.count(Some("POST"), DELETE)
}

/// A refusal body in the documented shape.
fn refusal(code: &str, message: &str) -> String {
    serde_json::json!({"status": "ERROR", "code": code, "message": message}).to_string()
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

assert_not_impl!(Porkbun: std::fmt::Display, serde::Serialize);
assert_not_impl!(PorkbunCredentials: std::fmt::Display, serde::Serialize);

/// The canaries of the echo tests: the API key and the secret API key.
const CANARIES: [&str; 2] = [CANARY_KEY, CANARY_TOKEN];

/// What the echo's listing answers: no record, a record with a foreign value, or a record with
/// the value `v1`.
#[derive(Clone, Copy)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
}

/// A renderer that answers the record listing like the API and every other request with
/// `errors`.
fn listing_then(errors: Render, existing: Existing) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method != Method::GET {
            return errors(e);
        }
        let record = |content: &str| {
            serde_json::json!([{
                "id": "1001", "name": NAME, "type": "TXT", "content": content,
                "ttl": "600", "prio": null, "notes": null
            }])
        };
        let records = match existing {
            Existing::Nothing => serde_json::json!([]),
            Existing::Foreign => record("foreign"),
            Existing::Ours => record("v1"),
        };
        let body = serde_json::json!({"status": "SUCCESS", "records": records});
        (StatusCode::OK, axum::Json(body)).into_response()
    })
}

/// A renderer that answers the ping and the domain lookup like the API and every other request
/// with `errors`.
fn ping_then(errors: Render) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.path.ends_with("/ping") {
            let body = serde_json::json!({
                "status": "SUCCESS", "yourIp": "127.0.0.1", "credentialsValid": true
            });
            return (StatusCode::OK, axum::Json(body)).into_response();
        }
        errors(e)
    })
}

fn echo_client(echo: &EchoServer, ctx: &Context) -> Porkbun {
    let config = settings(echo.url("/api/json/v3"));
    Porkbun::new(config, credentials(CANARY_KEY, CANARY_TOKEN), ctx).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Write {
    /// `add_txt_value`: a create.
    Add,
    /// `remove_txt_value` of the value the listing holds: a delete.
    Remove,
    /// `set_rrset` of the value the listing holds with another TTL: an edit.
    Edit,
}

/// Runs `write` against [`NAME`]; the outcome as text.
async fn run_write(client: &Porkbun, write: Write) -> Result<String, Error> {
    match write {
        Write::Add => add(client, "v1").await.map(|o| format!("{o:?}")),
        Write::Remove => remove(client, "v1").await.map(|o| format!("{o:?}")),
        Write::Edit => {
            let set = rr(NAME, RecordType::TXT, Some(900), &["\"v1\""]);
            client
                .set_rrset(&zone(), &set, Expect::Any)
                .await
                .map(|o| format!("{o:?}"))
        }
    }
}

/// `check` and a write against an echo that quotes every request back, both key headers
/// included: no canary in any error, `ZoneCheck::detail` or `Debug`, and the write's error shows
/// the redaction.
async fn echo_round(label: &str, client: &Porkbun, write: Write) {
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
    let text = match run_write(client, write).await {
        Ok(outcome) => panic!("{label}: the echo accepted a write: {outcome}"),
        Err(e) => format!("{e} | {e:?}"),
    };
    assert!(
        text.contains(REDACTED),
        "{label}: the echo did not reach the error: {text}"
    );
    texts.push(text);
    for text in &texts {
        assert_clean(label, text, &CANARIES);
    }
}

/// `check` and the writes against an echo, for every dialect. The reads carry both keys as
/// headers and the writes carry both in the body, so every echoed answer quotes both; five kinds
/// of request reach it: the ping, the domain lookup, the create, the edit and the delete.
#[tokio::test]
async fn porkbun_secret_echo() {
    let ctx = context();
    let echo = EchoServer::start(200).await;
    for dialect in dialects() {
        // The ping is the echo.
        for status in [400, 403] {
            let label = format!("{} {:?} {status} ping", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status));
            let client = echo_client(&echo, &ctx);
            echo_round(&label, &client, Write::Add).await;
            assert!(
                echo.log().count(Some("GET"), PING) > 0,
                "{label}: the ping did not reach the echo"
            );
        }
        // The ping is answered; the domain lookup is the echo.
        for status in [400, 403] {
            let label = format!("{} {:?} {status} domain", dialect.name, dialect.spelling);
            echo.reset(
                dialect
                    .echo(status)
                    .render_under("/api/json/v3/ping", ping_then(dialect.render.clone())),
            );
            let client = echo_client(&echo, &ctx);
            let e = client.check(&[zone()]).await.unwrap_err();
            let text = format!("{e} | {e:?} | {client:?}");
            assert!(text.contains(REDACTED), "{label}: {text}");
            assert_clean(&label, &text, &CANARIES);
            assert!(
                echo.log().count(Some("GET"), LIST_ALL) > 0,
                "{label}: the domain lookup did not reach the echo"
            );
        }
        // The listing answers normally, so the write itself reaches the echo: a create (with
        // and without a foreign record at the name) and a delete. A 500 to the delete, which
        // is retried with real back-off sleeps, is left out (the create's 500 covers the body).
        for (existing, write, statuses) in [
            (Existing::Nothing, Write::Add, [400, 403, 500].as_slice()),
            (Existing::Foreign, Write::Add, [400, 403, 500].as_slice()),
            (Existing::Ours, Write::Remove, [400, 403].as_slice()),
            (Existing::Ours, Write::Edit, [400, 403, 500].as_slice()),
        ] {
            for &status in statuses {
                let label = format!("{} {:?} {status} {write:?}", dialect.name, dialect.spelling);
                echo.reset(
                    dialect
                        .echo(status)
                        .render_under("/api/json/v3/ping", ping_then(dialect.render.clone()))
                        .render_under(
                            "/api/json/v3/dns/retrieve",
                            listing_then(dialect.render.clone(), existing),
                        ),
                );
                let client = echo_client(&echo, &ctx);
                let e = run_write(&client, write).await.unwrap_err();
                let text = format!("{e} | {e:?} | {client:?}");
                assert!(text.contains(REDACTED), "{label}: {text}");
                assert_clean(&label, &text, &CANARIES);
                let path = match write {
                    Write::Add => CREATE,
                    Write::Remove => DELETE,
                    Write::Edit => EDIT,
                };
                // Sent once (a delete answered 400 or 403 is not retried either), with both keys
                // in the body the echo quoted back.
                let sent = echo.log().matching(Some("POST"), path);
                assert_eq!(
                    sent.len(),
                    1,
                    "{label}: the write did not reach the echo once"
                );
                let body = sent[0].body_json().unwrap();
                assert_eq!(body["apikey"], serde_json::json!(CANARY_KEY), "{label}");
                assert_eq!(
                    body["secretapikey"],
                    serde_json::json!(CANARY_TOKEN),
                    "{label}"
                );
                // The reads carry the keys in headers only; the writes carry no key header.
                for entry in echo.log().entries() {
                    if entry.method == "GET" {
                        assert_clean(&label, &entry.body_str(), &CANARIES);
                    } else {
                        assert_eq!(entry.header("x-api-key"), None, "{label}");
                        assert_eq!(entry.header("x-secret-api-key"), None, "{label}");
                    }
                }
            }
        }
    }
}

/// An error body that quotes exactly one of the keys, in the `message` the client reads and in
/// the `code`: each is redacted, and neither becomes the provider code.
#[tokio::test]
async fn porkbun_secret_echo_of_each_key() {
    let (mock, client) = setup().await;
    for secret in [KEY, SECRET] {
        let body = serde_json::json!({
            "status": "ERROR", "code": "INVALID_INPUT",
            "message": format!("the request carried {secret} and was refused")
        })
        .to_string();
        mock.faults()
            .push(Fault::on("POST", CREATE).respond(400, body));
        let before = mock.log().count(Some("POST"), CREATE);
        let e = add(&client, "v1").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
        let text = format!("{e} | {e:?}");
        assert!(text.contains(REDACTED), "{text}");
        assert!(!text.contains(secret), "{text}");
        assert_eq!(mock.log().count(Some("POST"), CREATE), before + 1);
    }
    for secret in [KEY, SECRET] {
        let body = serde_json::json!({"status": "ERROR", "code": secret, "message": "no"});
        mock.faults()
            .push(Fault::on("POST", CREATE).respond(400, body.to_string()));
        let e = add(&client, "v1").await.unwrap_err();
        assert_eq!(e.provider_code(), None);
        assert!(!format!("{e} | {e:?}").contains(secret));
    }
}

/// A `TRACE` capture over a success, a refusal of the keys, a 500, a refusal of each write that
/// quotes its whole body (both keys), and a wrong key pair: the transport's events are there, and
/// no canary is, in any event, error or `Debug` output.
#[tokio::test(flavor = "current_thread")]
async fn porkbun_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.api_key = CANARY_KEY.into();
    seed.secret_api_key = CANARY_TOKEN.into();
    let mock = PorkbunMock::start(seed).await;
    let client = client_with(&mock, CANARY_KEY, CANARY_TOKEN, &context());
    let mut texts = Vec::new();

    client.check(&[zone()]).await.unwrap();
    add(&client, "v1").await.unwrap();
    let rrset = rr(NAME, RecordType::TXT, Some(900), &["\"v1\""]);
    client
        .set_rrset(&zone(), &rrset, Expect::Any)
        .await
        .unwrap();
    remove(&client, "v1").await.unwrap();

    mock.faults()
        .push(Fault::on("GET", RETRIEVE).always().respond(
            400,
            refusal("INVALID_API_KEYS_001", "Invalid API key. (001)"),
        ));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("POST", CREATE).status(500));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    // Each write answered with a refusal that quotes the whole request body, both keys in it.
    add(&client, "v1").await.unwrap();
    let quoted = |fields: serde_json::Value| {
        let mut body = serde_json::json!({"apikey": CANARY_KEY, "secretapikey": CANARY_TOKEN});
        body.as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let message = format!("refused request {body}");
        serde_json::json!({"status": "ERROR", "code": "INVALID_INPUT", "message": message})
            .to_string()
    };
    let cases = [
        (
            CREATE,
            Write::Add,
            quoted(serde_json::json!({"name": "_acme-challenge", "type": "TXT",
                                      "content": "v1", "ttl": 600})),
        ),
        (
            EDIT,
            Write::Edit,
            quoted(serde_json::json!({"name": "_acme-challenge", "type": "TXT",
                                      "content": "v1", "ttl": 900})),
        ),
        (DELETE, Write::Remove, quoted(serde_json::json!({}))),
    ];
    for (path, write, body) in cases {
        if matches!(write, Write::Add) {
            remove(&client, "v1").await.unwrap();
        }
        let before = mock.log().count(Some("POST"), path);
        mock.faults()
            .push(Fault::on("POST", path).respond(400, body));
        let e = run_write(&client, write).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{path}: {e:?}");
        assert_eq!(mock.log().count(Some("POST"), path), before + 1, "{path}");
        let text = format!("{e} | {e:?}");
        assert!(text.contains(REDACTED), "{path}: {text}");
        texts.push(text);
        if matches!(write, Write::Add) {
            add(&client, "v1").await.unwrap();
        }
    }

    let wrong = client_with(&mock, CANARY_TOKEN, CANARY_KEY, &context());
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
        assert_clean("porkbun logs and errors", text, &CANARIES);
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely ends
/// with the zone's text, the zone's text inside another name, and a sibling zone.
#[tokio::test]
async fn porkbun_name_outside_zone_sends_nothing() {
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

/// A value the capabilities do not accept and a TTL outside the documented range are refused
/// before any request.
#[tokio::test]
async fn porkbun_invalid_input_sends_nothing() {
    let (mock, client) = setup().await;
    for value in ["two words", "quo\"te", "back\\slash"] {
        let e = add(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
        let e = remove(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
    }
    // The documented minimum is 600 (lego sends 300).
    for ttl in [300, 599] {
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

/// `Created`, `Appended` for a second value, then `AlreadyPresent` without a write.
#[tokio::test]
async fn porkbun_add_is_idempotent() {
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
/// leaves the foreign records, their TTLs and notes as they were. A single foreign value is never
/// a reason to delete anything.
#[tokio::test]
async fn porkbun_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "foreign-1", 600);
    control.insert_record_with(
        "example.org",
        NAME,
        "TXT",
        "foreign-2",
        900,
        None,
        Some("n"),
    );
    let original = control.records();

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
    assert_eq!(control.txt_values(NAME), ["foreign-1", "foreign-2", "ours"]);
    // The value joins the rrset with its TTL as read: the smallest of its records.
    assert_eq!(control.records_at(NAME, "TXT")[2].ttl, 600);
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.records(), original);
    // Only the record with our value was named by a request, and never by name and type.
    assert_eq!(mock.log().count(Some("POST"), DELETE), 1);
    assert_eq!(
        mock.log()
            .count(None, "/api/json/v3/dns/deleteByNameType/**"),
        0
    );

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_record("example.org", other, "TXT", "foreign", 600);
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &ours)
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(control.txt_values(other), ["foreign"]);
}

/// Records of other types at the same name and TXT records at other names are not touched and
/// are not mistaken for ours.
#[tokio::test]
async fn porkbun_other_types_at_the_name_are_untouched() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "A", "192.0.2.1", 600);
    control.insert_record("example.org", NAME, "SPF", "AAA", 600);
    control.insert_record("example.org", "other.example.org", "TXT", "AAA", 600);
    let original = control.records();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(control.records(), original);
}

#[tokio::test]
async fn porkbun_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().records().is_empty());
    assert_eq!(mock.log().count(Some("POST"), DELETE), 1);
}

#[tokio::test]
async fn porkbun_remove_is_idempotent() {
    let (mock, client) = setup().await;
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
    assert!(mock.control().records().is_empty());
}

/// Every record with the value is removed (a duplicate made by a writer outside the process),
/// and nothing else.
#[tokio::test]
async fn porkbun_remove_deletes_every_copy_of_the_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "AAA", 600);
    control.insert_record("example.org", NAME, "TXT", "foreign", 600);
    control.insert_record("example.org", NAME, "TXT", "AAA", 600);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt_values(NAME), ["foreign"]);
    assert_eq!(mock.log().count(Some("POST"), DELETE), 2);
}

/// Two clients sharing a `Context` add to one name at once, the first write delayed: the second
/// waits for the lock and sees the first one's record. Without the name lock both would read "no
/// record" and both report `Created`.
#[tokio::test]
async fn porkbun_concurrent_adds_are_serialized() {
    let mock = PorkbunMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, KEY, SECRET, &ctx);
    let b = client_with(&mock, KEY, SECRET, &ctx);
    mock.faults()
        .push(Fault::on("POST", CREATE).delay(Duration::from_millis(300)));
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

/// A foreign value added between the read and the write is not lost: the create names only our
/// value.
#[tokio::test]
async fn porkbun_foreign_value_added_between_read_and_write_survives() {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    mock.faults().push(Fault::on("POST", CREATE).run(move || {
        hook.insert_record("example.org", NAME, "TXT", "foreign", 900);
    }));
    add(&client, "ours").await.unwrap();
    let mut values = mock.control().txt_values(NAME);
    values.sort();
    assert_eq!(values, ["foreign", "ours"]);
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(mock.control().txt_values(NAME), ["foreign"]);
    assert_eq!(mock.control().records()[0].ttl, 900);
}

/// Our value created by another writer between the read and the create: the provider refuses the
/// duplicate (`DUPLICATE_RECORD`), a new read finds the value, and the result is `Conflict`; the
/// repeat finds the value. A duplicate refusal that the read does not confirm is the refusal.
#[tokio::test]
async fn porkbun_duplicate_is_confirmed_by_a_read() {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    mock.faults().push(Fault::on("POST", CREATE).run(move || {
        hook.insert_record("example.org", NAME, "TXT", "AAA", 600);
    }));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("POST"), CREATE), 1);
    assert_eq!(mock.log().count(Some("GET"), RETRIEVE), 2);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);

    let body = serde_json::json!({
        "status": "ERROR", "code": "DUPLICATE_RECORD",
        "message": "A record with this exact name, type and content already exists.",
        "existingId": "1"
    });
    mock.faults()
        .push(Fault::on("POST", CREATE).respond(400, body.to_string()));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(
        e.provider_code().map(|c| c.as_str()),
        Some("DUPLICATE_RECORD")
    );

    // The same at the record level.
    let www = "www.example.org";
    let hook = mock.control().clone();
    mock.faults().push(Fault::on("POST", CREATE).run(move || {
        hook.insert_record("example.org", www, "A", "192.0.2.1", 600);
    }));
    let set = rr(www, RecordType::A, None, &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &set, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap(),
        SetOutcome::Unchanged
    );
}

/// The domain is deleted and created again between the read and the delete: the delete is
/// answered `INVALID_RECORD_ID`, and the removal never reports success for a value that is still
/// published. A record that is gone for another reason is a success.
#[tokio::test]
async fn porkbun_delete_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "AAA").await.unwrap();
    let id = control.records()[0].id;
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("POST", DELETE).run(move || hook.delete_record(id)));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.records().is_empty());

    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("POST", DELETE).run(move || hook.recreate_domain("example.org")));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(control.txt_values(NAME), ["AAA"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.records().is_empty());
}

/// Retry behavior: a create is sent once whatever happens (a 502, a 429, a refusal of the keys
/// and a refusal of the record are the operation's error, and the repeat starts with a read); a
/// repeated create could add a second copy of the value. The edit is sent once too.
#[tokio::test]
async fn porkbun_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let posts = || mock.log().count(Some("POST"), CREATE);

    mock.faults().push(Fault::on("POST", CREATE).status(502));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(posts(), 1);
    assert!(mock.control().records().is_empty());

    mock.faults()
        .push(Fault::on("POST", CREATE).rate_limited("1"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(posts(), 2);

    mock.faults().push(Fault::on("POST", CREATE).respond(
        400,
        refusal("INVALID_API_KEYS_001", "Invalid API key. (001)"),
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(posts(), 3);
    assert!(mock.control().records().is_empty());

    // The create is answered 502 but was applied: the repeat finds the value instead of
    // adding a second copy.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("POST", CREATE)
            .run(move || {
                hook.insert_record("example.org", NAME, "TXT", "AAA", 600);
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
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);

    // A create refused by the provider is not repeated either.
    mock.faults().push(
        Fault::on("POST", CREATE).respond(400, refusal("ZONE_RECORD_LIMIT", "The zone is full.")),
    );
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(posts(), 5);

    // An edit (a TTL change at the record level) answered 502 or 429 is not repeated.
    let edits = || mock.log().count(Some("POST"), EDIT);
    let retuned = rr(NAME, RecordType::TXT, Some(900), &["\"AAA\""]);
    mock.faults().push(Fault::on("POST", EDIT).status(502));
    let e = client
        .set_rrset(&zone(), &retuned, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(edits(), 1);
    mock.faults()
        .push(Fault::on("POST", EDIT).rate_limited("1"));
    let e = client
        .set_rrset(&zone(), &retuned, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(edits(), 2);
    assert_eq!(mock.control().records_at(NAME, "TXT")[0].ttl, 600);
}

/// The delete of one record by its identifier is the one write that is repeated: a 502 is
/// retried, and a retry that finds the record gone is a success. A rate limit with a long wait
/// and a refusal of the keys are not repeated.
#[tokio::test]
async fn porkbun_delete_by_id_is_retried() {
    let (mock, client) = setup().await;
    let deletes = || mock.log().count(Some("POST"), DELETE);
    add(&client, "AAA").await.unwrap();
    mock.faults().push(Fault::on("POST", DELETE).status(502));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(deletes(), 2);
    assert!(mock.control().records().is_empty());

    // The first delete is applied and its answer lost; the retry is answered
    // `INVALID_RECORD_ID`, and the new read finds the value gone.
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    let id = mock.control().records()[0].id;
    mock.faults().push(
        Fault::on("POST", DELETE)
            .run(move || hook.delete_record(id))
            .status(502),
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(deletes(), 4);

    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("POST", DELETE).rate_limited("120"));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
    assert_eq!(deletes(), 5);
    mock.faults().push(Fault::on("POST", DELETE).respond(
        400,
        refusal("INVALID_API_KEYS_001", "Invalid API key. (001)"),
    ));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(deletes(), 6);
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);
}

// ---- Requests, names and TTLs ------------------------------------------------------------------

/// The requests as the documentation describes them: reads by `GET` with both keys as headers
/// and no body; writes by `POST` with both keys as the first members of the body and no key
/// header; the create's fields with the name relative to the domain and an integer TTL; the
/// delete by identifier with the keys only.
#[tokio::test]
async fn porkbun_request_shapes() {
    let (mock, client) = setup().await;
    client.check(&[zone()]).await.unwrap();
    add(&client, "AAA").await.unwrap();
    remove(&client, "AAA").await.unwrap();
    let log = mock.log();
    let keys_first = format!(r#"{{"apikey":"{KEY}","secretapikey":"{SECRET}""#);
    for entry in log.entries() {
        if entry.method == "GET" {
            assert_eq!(entry.header("x-api-key"), Some(KEY), "{}", entry.path);
            assert_eq!(
                entry.header("x-secret-api-key"),
                Some(SECRET),
                "{}",
                entry.path
            );
            assert!(entry.body.is_empty(), "{}", entry.path);
        } else {
            assert_eq!(entry.method, "POST");
            assert_eq!(entry.header("x-api-key"), None, "{}", entry.path);
            assert_eq!(entry.header("x-secret-api-key"), None, "{}", entry.path);
            assert!(
                entry.body_str().starts_with(&keys_first),
                "{}",
                entry.body_str()
            );
        }
    }
    let ping = log.matching(Some("GET"), PING).pop().unwrap();
    assert_eq!(ping.query, None);
    let lookup = log.matching(Some("GET"), LIST_ALL).pop().unwrap();
    assert_eq!(lookup.query.as_deref(), Some("domain=example.org"));
    let list = log.matching(Some("GET"), RETRIEVE).pop().unwrap();
    assert_eq!(list.path, "/api/json/v3/dns/retrieve/example.org");
    let post = log.matching(Some("POST"), CREATE).pop().unwrap();
    assert_eq!(post.path, "/api/json/v3/dns/create/example.org");
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({
            "apikey": KEY, "secretapikey": SECRET,
            "name": "_acme-challenge", "type": "TXT", "content": "AAA", "ttl": 600
        })
    );
    let delete = log.matching(Some("POST"), DELETE).pop().unwrap();
    assert!(
        delete
            .path
            .starts_with("/api/json/v3/dns/delete/example.org/"),
        "{}",
        delete.path
    );
    assert_eq!(
        delete.body_json().unwrap(),
        serde_json::json!({"apikey": KEY, "secretapikey": SECRET})
    );

    // The apex is a blank name, a wildcard `*`.
    client
        .add_txt_value(&zone(), &zone(), &txt("apex"), None)
        .await
        .unwrap();
    client
        .add_txt_value(&zone(), &dn("*.example.org"), &txt("wild"), None)
        .await
        .unwrap();
    let names: Vec<serde_json::Value> = mock
        .log()
        .matching(Some("POST"), CREATE)
        .iter()
        .map(|r| r.body_json().unwrap()["name"].clone())
        .collect();
    assert_eq!(
        names,
        [
            serde_json::json!("_acme-challenge"),
            serde_json::json!(""),
            serde_json::json!("*")
        ]
    );
    assert_eq!(mock.control().txt_values("example.org"), ["apex"]);
    assert_eq!(mock.control().txt_values("*.example.org"), ["wild"]);
}

/// The TTL policy: a new rrset gets the caller's TTL or the configured one; a value joining an
/// existing rrset gets the rrset's TTL as read, whatever the caller asked; the configuration is
/// checked.
#[tokio::test]
async fn porkbun_ttl_policy() {
    let mock = PorkbunMock::start(Seed::standard()).await;
    let mut config = settings(mock.base_url());
    config.ttl = RrsetTtl::from_secs(1200).unwrap();
    let client = Porkbun::new(config, credentials(KEY, SECRET), &context()).unwrap();
    add(&client, "AAA").await.unwrap();
    client
        .add_txt_value(
            &zone(),
            &dn("b.example.org"),
            &txt("BBB"),
            Some(RrsetTtl::from_secs(3600).unwrap()),
        )
        .await
        .unwrap();
    client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("CCC"),
            Some(RrsetTtl::from_secs(3600).unwrap()),
        )
        .await
        .unwrap();
    let control = mock.control();
    let ttls: Vec<u32> = control
        .records_at(NAME, "TXT")
        .iter()
        .map(|r| r.ttl)
        .collect();
    assert_eq!(ttls, [1200, 1200]);
    assert_eq!(control.records_at("b.example.org", "TXT")[0].ttl, 3600);

    // The provider's default cannot be configured: every record has a TTL of its own.
    let mut config = settings(mock.base_url());
    config.ttl = RrsetTtl::ProviderDefault;
    let e = Porkbun::new(config, credentials(KEY, SECRET), &context()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
    // Nor can a write ask for it.
    let before = mock.log().len();
    let e = client
        .add_txt_value(
            &zone(),
            &dn("c.example.org"),
            &txt("DDD"),
            Some(RrsetTtl::ProviderDefault),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(mock.log().len(), before);
}

/// A record whose TTL the listing does not state reads without one, and a value added next to it
/// gets the configured TTL rather than none (without `ttl` the provider would apply the
/// account's minimum).
#[tokio::test]
async fn porkbun_unreported_ttl_takes_the_setting() {
    let (mock, client) = setup().await;
    let body = serde_json::json!({"status": "SUCCESS", "records": [{
        "id": "7", "name": NAME, "type": "TXT", "content": "foreign", "ttl": null, "prio": null
    }]});
    mock.faults()
        .push(Fault::on("GET", RETRIEVE).respond(200, body.to_string()));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    let post = mock.log().matching(Some("POST"), CREATE).pop().unwrap();
    assert_eq!(post.body_json().unwrap()["ttl"], serde_json::json!(600));
}

// ---- check and zones ---------------------------------------------------------------------------

/// `check` pings with the keys on every call, so keys revoked in between are noticed, and looks
/// every zone up afresh: a domain the account lacks is not found, one that is not opted in to API
/// access is not usable, one served elsewhere carries a warning.
#[tokio::test]
async fn porkbun_check_exercises_the_credentials() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_domain("example.net");
    control.insert_domain("example.com");
    control.set_api_access("example.net", false);
    control.set_not_local("example.com", true);
    let report = client
        .check(&[
            zone(),
            dn("missing.test"),
            dn("example.net"),
            dn("example.com"),
        ])
        .await
        .unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones[0].found && report.zones[0].detail.is_none());
    assert!(!report.zones[1].found && report.zones[1].detail.is_none());
    assert!(!report.zones[2].found);
    assert!(
        report.zones[2]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("API access")
    );
    assert!(report.zones[3].found);
    assert!(
        report.zones[3]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("not published")
    );
    client.check(&[]).await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), PING), 2);
    assert_eq!(mock.log().count(Some("GET"), LIST_ALL), 4);

    // A ping that does not confirm the keys: they were not taken.
    mock.faults()
        .push(Fault::on("GET", PING).respond(200, r#"{"status":"SUCCESS","yourIp":"127.0.0.1"}"#));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    // A key restricted by IP or scope: the transport's 403.
    mock.faults()
        .push(Fault::on("GET", PING).respond(403, refusal("IP_NOT_ALLOWED", "Not from this IP.")));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    // An answer about another domain is not taken for the one asked for.
    mock.faults().push(Fault::on("GET", LIST_ALL).respond(
        200,
        r#"{"status":"SUCCESS","count":1,"domains":[{"domain":"other.example","apiAccess":1,"notLocal":0}]}"#,
    ));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");

    let wrong = client_with(&mock, KEY, "wrong-secret", &context());
    let e = wrong.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(!format!("{e} {e:?} {wrong:?}").contains("wrong-secret"));
}

/// A domain that is not opted in to API access is refused with `API_ACCESS_DISABLED`:
/// `Forbidden` for every operation, nothing written.
#[tokio::test]
async fn porkbun_api_access_disabled_is_forbidden() {
    let (mock, client) = setup().await;
    mock.control().set_api_access("example.org", false);
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    assert!(format!("{e}").contains("API_ACCESS_DISABLED"), "{e}");
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// Every domain of the account, over pages of 1000 domains read by offset; a server that does
/// not advance or a count that disagrees with the page is `Protocol`.
#[tokio::test]
async fn porkbun_list_zones_pages_by_offset() {
    // A mock seeded with `count` domains: `example.org` and `count - 1` others.
    async fn with_domains(count: usize) -> (PorkbunMock, Porkbun) {
        let mut seed = Seed::standard();
        seed.domains
            .extend((1..count).map(|i| format!("d{i:04}.example")));
        let mock = PorkbunMock::start(seed).await;
        let client = client_with(&mock, KEY, SECRET, &context());
        (mock, client)
    }
    let starts = |mock: &PorkbunMock| -> Vec<Option<String>> {
        mock.log()
            .matching(Some("GET"), LIST_ALL)
            .into_iter()
            .map(|r| r.query)
            .collect()
    };
    let (mock, client) = with_domains(2500).await;
    let zones = client.list_zones().await.unwrap();
    assert_eq!(zones.len(), 2500);
    assert!(zones.iter().any(|z| z.name == zone()));
    assert_eq!(
        starts(&mock),
        [
            Some("start=0".to_owned()),
            Some("start=1000".to_owned()),
            Some("start=2000".to_owned())
        ]
    );
    // A server that answers the first page whatever the offset.
    mock.control().set_paging(Paging::IgnoreStart);
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");

    // A number of domains that fills its pages exactly: the empty page after them ends it.
    let (mock, client) = with_domains(2000).await;
    assert_eq!(client.list_zones().await.unwrap().len(), 2000);
    assert_eq!(
        starts(&mock),
        [
            Some("start=0".to_owned()),
            Some("start=1000".to_owned()),
            Some("start=2000".to_owned())
        ]
    );

    // One page: one request. A count that disagrees with the page is `Protocol`.
    let (mock, client) = setup().await;
    assert_eq!(client.list_zones().await.unwrap().len(), 1);
    assert_eq!(mock.log().count(Some("GET"), LIST_ALL), 1);
    mock.faults().push(Fault::on("GET", LIST_ALL).respond(
        200,
        r#"{"status":"SUCCESS","count":2,"domains":[{"domain":"example.org","apiAccess":1,"notLocal":0}]}"#,
    ));
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

// ---- Errors ------------------------------------------------------------------------------------

/// A domain the account lacks (`INVALID_DOMAIN`, or `DOMAIN_NOT_FOUND`) is `ZoneNotFound`.
#[tokio::test]
async fn porkbun_zone_not_found() {
    let (mock, client) = setup().await;
    let other = dn("example.net");
    let e = client
        .add_txt_value(&other, &dn("_acme-challenge.example.net"), &txt("v"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let e = client
        .remove_txt_value(&other, &dn("_acme-challenge.example.net"), &txt("v"))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let e = client.list_rrsets(&other).await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    // The domain is gone between the read and the create.
    mock.faults().push(
        Fault::on("POST", CREATE).respond(400, refusal("DOMAIN_NOT_FOUND", "Not in the account.")),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
}

/// A 429 on a read is waited out and retried; a long wait is `RateLimited` with the wait. An
/// answer with the code `RATE_LIMIT_EXCEEDED` is a rate limit whatever its status.
#[tokio::test]
async fn porkbun_rate_limit() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RETRIEVE).rate_limited("1"));
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), RETRIEVE), 2);
    mock.faults()
        .push(Fault::on("GET", RETRIEVE).rate_limited("120"));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
    mock.faults().push(
        Fault::on("POST", CREATE)
            .respond(400, refusal("RATE_LIMIT_EXCEEDED", "Slow down."))
            .header("retry-after", "30"),
    );
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(30)));
}

/// A 5xx on a read is retried; three in a row are `Transient`, which is retryable.
#[tokio::test]
async fn porkbun_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RETRIEVE).status(502));
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("GET", RETRIEVE).times(3).respond(
            500,
            refusal("DNS_READ_FAILED", "The current zone could not be read."),
        ));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("GET"), RETRIEVE), 5);
}

/// The provider's refusals are `Rejected` with the status and its code and message; a success
/// status with `status: ERROR` is a refusal too; an answer the client cannot interpret is
/// `Protocol`.
#[tokio::test]
async fn porkbun_refusals_are_rejected() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", CREATE).respond(
        400,
        refusal("RECORD_CONFLICT", "A CNAME record exists at this name."),
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(400));
            assert_eq!(
                detail.as_str(),
                "RECORD_CONFLICT: A CNAME record exists at this name."
            );
        }
        other => panic!("{other:?}"),
    }
    mock.faults().push(Fault::on("POST", CREATE).respond(
        200,
        refusal("INVALID_API_KEYS_001", "Invalid API key. (001)"),
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    for body in [
        r#"{"records":[]}"#,
        r#"{"status":"PENDING","records":[]}"#,
        r#"{"status":"SUCCESS"}"#,
        "<html>oops</html>",
    ] {
        mock.faults()
            .push(Fault::on("GET", RETRIEVE).respond(200, body));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    mock.faults()
        .push(Fault::on("GET", RETRIEVE).respond(204, ""));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert!(mock.control().records().is_empty());
}

/// A refusal carries the `code` of the error body as the provider code; the kind follows the
/// codes whose meaning the documentation states.
#[tokio::test]
async fn porkbun_refusal_carries_the_provider_code() {
    let (mock, client) = setup().await;
    mock.faults().push(
        Fault::on("POST", CREATE).respond(400, refusal("ZONE_RECORD_LIMIT", "The zone is full.")),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(
        e.provider_code().map(|c| c.as_str()),
        Some("ZONE_RECORD_LIMIT")
    );
    mock.faults().push(
        Fault::on("POST", CREATE).respond(400, refusal("INVALID_INPUT", "ttl is out of range.")),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(e.provider_code().map(|c| c.as_str()), Some("INVALID_INPUT"));
    mock.faults()
        .push(Fault::on("POST", CREATE).respond(400, r#"{"status":"ERROR","message":"refused"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(e.provider_code(), None);
}

/// A `code` that echoes either key is not carried, and the key appears nowhere in the error. Both
/// test keys fit the code's alphabet, so only the scrubber keeps them out.
#[tokio::test]
async fn porkbun_provider_code_never_carries_a_credential() {
    let (mock, client) = setup().await;
    for secret in [KEY, SECRET] {
        let body = serde_json::json!({"status": "ERROR", "code": secret, "message": "refused"});
        mock.faults()
            .push(Fault::on("POST", CREATE).respond(400, body.to_string()));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
        assert_eq!(e.provider_code(), None);
        let text = format!("{e} | {e:?}");
        assert!(!text.contains(secret), "{text}");
    }
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn porkbun_from_json_builds_the_client() {
    let mock = PorkbunMock::start(Seed::standard()).await;
    let ctx = context();
    let client = AnyProvider::from_json(
        ProviderId::Porkbun,
        &serde_json::json!({ "base_url": mock.base_url() }).to_string(),
        &SecretString::from(
            serde_json::json!({"api_key": KEY, "secret_api_key": SECRET, "other": 1}).to_string(),
        ),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Porkbun);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

/// The smallest configuration the shared test support uses to build a client without a request.
#[test]
fn porkbun_minimal_configuration_builds() {
    let credentials = r#"{"api_key":"pk1_test-only-key","secret_api_key":"sk1_test-only-secret"}"#;
    let client = AnyProvider::from_json(
        ProviderId::Porkbun,
        r#"{"base_url":"http://127.0.0.1:9/api/json/v3"}"#,
        &SecretString::from(credentials.to_owned()),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Porkbun);
    // The default endpoint is public, which the loopback-only test context refuses.
    AnyProvider::from_json(
        ProviderId::Porkbun,
        "{}",
        &SecretString::from(credentials.to_owned()),
        &context(),
    )
    .unwrap_err();
}

/// Keys pasted with surrounding whitespace are sent without it.
#[tokio::test]
async fn porkbun_keys_are_trimmed() {
    let mock = PorkbunMock::start(Seed::standard()).await;
    let client = client_with(
        &mock,
        &format!(" {KEY}\n"),
        &format!("{SECRET} "),
        &context(),
    );
    client.check(&[zone()]).await.unwrap();
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn porkbun_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || serde_json::json!({ "base_url": "http://127.0.0.1:1/api/json/v3" });
    let with = |key: &str, value: serde_json::Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let keys = serde_json::json!({"api_key": "pk", "secret_api_key": "sk"}).to_string();
    let cases = [
        (with("ttl", serde_json::json!(599)), keys.clone(), "ttl"),
        (
            with("ttl", serde_json::json!("provider_default")),
            keys.clone(),
            "ttl",
        ),
        (
            with(canary, serde_json::json!(canary)),
            keys.clone(),
            "unknown keys",
        ),
        (
            with(
                "base_url",
                serde_json::json!(format!("http://example.com/{canary}")),
            ),
            keys.clone(),
            "base_url",
        ),
        (
            with(
                "base_url",
                serde_json::json!(format!("https://u:{canary}@api.example.org")),
            ),
            keys.clone(),
            "base_url",
        ),
        (
            base(),
            serde_json::json!({"api_key": canary}).to_string(),
            "secret_api_key",
        ),
        (
            base(),
            serde_json::json!({"apikey": canary, "secretapikey": canary}).to_string(),
            "api_key",
        ),
        (
            base(),
            serde_json::json!({"api_key": "", "secret_api_key": canary}).to_string(),
            "api_key",
        ),
        (
            base(),
            serde_json::json!({"api_key": canary, "secret_api_key": " \n"}).to_string(),
            "secret_api_key",
        ),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::Porkbun,
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
    // A key with a character a header cannot carry is a configuration error.
    for (key, secret, named) in [
        ("bad\u{1}key", "sk", "api_key"),
        ("pk", "bad\u{1}secret", "secret_api_key"),
    ] {
        let e = Porkbun::new(
            settings("http://127.0.0.1:1/api/json/v3".into()),
            credentials(key, secret),
            &ctx,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config);
        let text = format!("{e}");
        assert!(text.contains(named) && !text.contains("bad"), "{text}");
    }
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round; the defaults of the metadata are those of the settings type.
#[test]
fn porkbun_config_keys_match_metadata() {
    let meta = ProviderId::Porkbun.meta();
    let settings = serde_json::to_value(PorkbunConfig::default()).unwrap();
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
    assert_eq!(secret, ["api_key", "secret_api_key"]);
    for field in meta.fields.iter().filter(|f| f.default.is_some()) {
        let value = &settings[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
    }
    assert_eq!(
        meta.default_propagation_timeout,
        Some(Duration::from_secs(600))
    );
    assert!(!meta.verified);
}

// ---- Record level (design sections 3.4, 3.6 and 12.3) ------------------------------------------

/// A record value in canonical text.
fn rdata(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap()
}

/// An rrset at `owner`.
fn rr(owner: &str, rtype: RecordType, ttl: Option<u32>, texts: &[&str]) -> RrSet {
    RrSet::new(
        dn(owner),
        rtype,
        ttl.map(|t| RrsetTtl::from_secs(t).unwrap()),
        texts.iter().map(|t| rdata(rtype, t)),
    )
    .unwrap()
}

/// The `content` of the records of `rtype` at `owner`, sorted.
fn stored(mock: &PorkbunMock, owner: &str, rtype: &str) -> Vec<String> {
    let mut values: Vec<String> = mock
        .control()
        .records_at(owner, rtype)
        .into_iter()
        .map(|r| r.content)
        .collect();
    values.sort();
    values
}

/// Every supported type through set, get and list with canonical equality: the apex, an IDN
/// name, a wildcard, a delegation, multi-value sets; and the `content` each type is stored with.
#[tokio::test]
async fn porkbun_record_round_trips() {
    let (mock, client) = setup().await;
    let sets = [
        rr(
            "example.org",
            RecordType::A,
            None,
            &["192.0.2.1", "192.0.2.2"],
        ),
        rr(
            "bücher.example.org",
            RecordType::A,
            Some(900),
            &["192.0.2.3"],
        ),
        rr("*.example.org", RecordType::AAAA, None, &["2001:db8::1"]),
        rr(
            "www.example.org",
            RecordType::CNAME,
            None,
            &["target.example.net."],
        ),
        rr(
            "sub.example.org",
            RecordType::NS,
            Some(3600),
            &["ns1.example.net.", "ns2.example.net."],
        ),
        rr(
            "example.org",
            RecordType::MX,
            None,
            &["10 mail.example.org.", "20 backup.example.net."],
        ),
        rr(
            "_sip._tcp.example.org",
            RecordType::SRV,
            None,
            &["1 5 5060 sip.example.org.", "2 0 5061 sip2.example.org."],
        ),
        rr(
            "example.org",
            RecordType::CAA,
            None,
            &[
                "0 issue \"letsencrypt.org\"",
                "128 iodef \"mailto:sec@example.org\"",
            ],
        ),
        rr(
            "_25._tcp.mail.example.org",
            RecordType::TLSA,
            None,
            &["3 1 1 0A1B2C"],
        ),
        rr("example.org", RecordType::TXT, None, &["\"v=1\"", "\"x\""]),
    ];
    let default_ttl = Some(RrsetTtl::from_secs(600).unwrap());
    for set in &sets {
        let label = format!("{} {}", set.name(), set.rtype());
        assert_eq!(
            client
                .set_rrset(&zone(), set, Expect::Absent)
                .await
                .unwrap(),
            SetOutcome::Created,
            "{label}"
        );
        let expected = set.clone().with_ttl(set.ttl().or(default_ttl));
        let got = client
            .get_rrset(&zone(), set.name(), set.rtype())
            .await
            .unwrap();
        assert_eq!(got.as_ref(), Some(&expected), "{label}");
        assert!(got.unwrap().records().iter().all(RecordData::is_canonical));
        let before = writes(&mock);
        assert_eq!(
            client.set_rrset(&zone(), set, Expect::Any).await.unwrap(),
            SetOutcome::Unchanged,
            "{label}"
        );
        assert_eq!(writes(&mock), before, "{label}");
    }
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.skipped.is_empty(), "{:?}", listing.skipped);
    assert_eq!(listing.rrsets.len(), sets.len());
    for set in &sets {
        let expected = set.clone().with_ttl(set.ttl().or(default_ttl));
        assert!(listing.rrsets.contains(&expected), "{expected:?}");
    }

    // The fields the API stores.
    let control = mock.control();
    let mx = control.records_at("example.org", "MX");
    assert!(
        mx.iter()
            .any(|r| r.content == "mail.example.org" && r.prio == Some(10))
    );
    let srv = control.records_at("_sip._tcp.example.org", "SRV");
    assert!(
        srv.iter()
            .any(|r| r.content == "5 5060 sip.example.org" && r.prio == Some(1))
    );
    assert_eq!(
        stored(&mock, "example.org", "CAA"),
        [
            "0 issue \"letsencrypt.org\"",
            "128 iodef \"mailto:sec@example.org\""
        ]
    );
    assert_eq!(
        stored(&mock, "_25._tcp.mail.example.org", "TLSA"),
        ["3 1 1 0a1b2c"]
    );
    assert_eq!(
        stored(&mock, "www.example.org", "CNAME"),
        ["target.example.net"]
    );
    assert_eq!(stored(&mock, "example.org", "TXT"), ["v=1", "x"]);
    assert_eq!(
        stored(&mock, "xn--bcher-kva.example.org", "A"),
        ["192.0.2.3"]
    );
    assert!(
        control
            .records()
            .iter()
            .any(|r| r.name == "*" && r.rtype == "AAAA")
    );
    // A, AAAA, CNAME, NS, CAA, TLSA and TXT carry no priority.
    assert!(
        control
            .records()
            .iter()
            .filter(|r| r.rtype != "MX" && r.rtype != "SRV")
            .all(|r| r.prio.is_none())
    );

    // A host name stated with a trailing dot by another writer reads as the same value.
    control.insert_record_with(
        "example.org",
        "other.example.org",
        "MX",
        "Mail.Example.org.",
        900,
        Some(10),
        None,
    );
    let other = rr(
        "other.example.org",
        RecordType::MX,
        Some(900),
        &["10 mail.example.org."],
    );
    assert_eq!(
        client
            .get_rrset(&zone(), &dn("other.example.org"), RecordType::MX)
            .await
            .unwrap(),
        Some(other.clone())
    );
    let before = writes(&mock);
    assert_eq!(
        client
            .set_rrset(&zone(), &other, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    assert_eq!(writes(&mock), before);
}

/// `Expect::Absent` on an existing set and `Expect::Matches` on a different or missing one are
/// `PreconditionFailed` and write nothing; an expectation that holds lets the write through.
#[tokio::test]
async fn porkbun_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", "www.example.org", "A", "192.0.2.1", 900);
    let original = control.records();
    let www = "www.example.org";
    let wanted = rr(www, RecordType::A, None, &["192.0.2.7"]);
    let other = rr(www, RecordType::A, None, &["192.0.2.2"]);
    let more = rr(www, RecordType::A, None, &["192.0.2.1", "192.0.2.2"]);
    let ttl = rr(www, RecordType::A, Some(600), &["192.0.2.1"]);
    for expect in [
        Expect::Absent,
        Expect::Matches(&other),
        Expect::Matches(&more),
        Expect::Matches(&ttl),
    ] {
        let e = client
            .set_rrset(&zone(), &wanted, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{expect:?}: {e:?}");
        assert!(!e.is_retryable());
    }
    for expect in [Expect::Matches(&other), Expect::Matches(&ttl)] {
        let e = client
            .delete_rrset(&zone(), &dn(www), RecordType::A, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{expect:?}: {e:?}");
    }
    let txt_set = rr(www, RecordType::TXT, None, &["\"v\""]);
    let e = client
        .set_rrset(&zone(), &txt_set, Expect::Matches(&txt_set))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(control.records(), original);

    let current = rr(www, RecordType::A, Some(900), &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&current))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.7"]);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Matches(&wanted))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
}

/// `Any` replaces whatever is there, creates before deletes; an equal set is `Unchanged`; a TTL
/// change alone edits the records in place with only the TTL, keeping their notes; a delete
/// removes every record and a repeat is `NotPresent`.
#[tokio::test]
async fn porkbun_set_any_replaces_and_delete_converges() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record_with("example.org", www, "A", "192.0.2.1", 600, None, Some("old"));
    control.insert_record_with(
        "example.org",
        www,
        "A",
        "192.0.2.2",
        600,
        None,
        Some("keep"),
    );
    let replaced = rr(www, RecordType::A, None, &["192.0.2.2", "192.0.2.3"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &replaced, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.2", "192.0.2.3"]);
    let order: Vec<String> = mock
        .log()
        .entries()
        .into_iter()
        .filter(|r| r.method == "POST")
        .map(|r| r.path.split('/').nth(5).unwrap_or_default().to_owned())
        .collect();
    assert_eq!(order, ["create", "delete"]);

    let before = writes(&mock);
    assert_eq!(
        client
            .set_rrset(&zone(), &replaced, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    assert_eq!(writes(&mock), before);

    let retuned = replaced
        .clone()
        .with_ttl(Some(RrsetTtl::from_secs(900).unwrap()));
    assert_eq!(
        client
            .set_rrset(&zone(), &retuned, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let edits = mock.log().matching(Some("POST"), EDIT);
    assert_eq!(edits.len(), 2);
    // The whole record goes out, the content as read and the new TTL; `notes` is left out.
    let mut bodies: Vec<serde_json::Value> = edits.iter().map(|e| e.body_json().unwrap()).collect();
    bodies.sort_by_key(|b| b["content"].to_string());
    assert_eq!(
        bodies,
        ["192.0.2.2", "192.0.2.3"].map(|content| serde_json::json!({
            "apikey": KEY, "secretapikey": SECRET,
            "name": "www", "type": "A", "content": content, "ttl": 900
        }))
    );
    let records = control.records_at(www, "A");
    assert!(records.iter().all(|r| r.ttl == 900));
    assert!(
        records
            .iter()
            .any(|r| r.content == "192.0.2.2" && r.notes.as_deref() == Some("keep"))
    );

    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(control.records_at(www, "A").is_empty());
    let before = writes(&mock);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(
        client
            .get_rrset(&zone(), &dn(www), RecordType::A)
            .await
            .unwrap(),
        None
    );
}

/// A CNAME is replaced in place by an edit of its `content`; a record removed between the read
/// and the edit is `Conflict`, and the repeat creates the value.
#[tokio::test]
async fn porkbun_cname_is_replaced_in_place() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let id = control.insert_record("example.org", www, "CNAME", "old.example.net", 900);
    let new = rr(www, RecordType::CNAME, None, &["new.example.net."]);
    assert_eq!(
        client.set_rrset(&zone(), &new, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    let records = control.records_at(www, "CNAME");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, id);
    assert_eq!(records[0].content, "new.example.net");
    assert_eq!(records[0].ttl, 900);
    let edit = mock.log().matching(Some("POST"), EDIT).pop().unwrap();
    assert_eq!(edit.path, format!("/api/json/v3/dns/edit/example.org/{id}"));
    assert_eq!(
        edit.body_json().unwrap(),
        serde_json::json!({
            "apikey": KEY, "secretapikey": SECRET,
            "name": "www", "type": "CNAME", "content": "new.example.net", "ttl": 900
        })
    );
    assert_eq!(mock.log().count(Some("POST"), CREATE), 0);
    assert_eq!(mock.log().count(Some("POST"), DELETE), 0);

    let hook = control.clone();
    mock.faults()
        .push(Fault::on("POST", EDIT).run(move || hook.delete_record(id)));
    let other = rr(www, RecordType::CNAME, None, &["other.example.net."]);
    let e = client
        .set_rrset(&zone(), &other, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(
        client
            .set_rrset(&zone(), &other, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    assert_eq!(stored(&mock, www, "CNAME"), ["other.example.net"]);
}

/// The provider refuses a second record with the same name, type and content, and the priority
/// of MX and SRV is outside the content: a plan that would create such a record (changing only
/// the priority of a value, or two values that differ only in priority) is refused after the read
/// and before any write, so it cannot leave a mixture. A delete of the rrset, then the set, does
/// it; a value whose content differs is replaced as usual.
#[tokio::test]
async fn porkbun_priority_change_is_refused_before_a_write() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record_with(
        "example.org",
        "@",
        "MX",
        "mail.example.org",
        600,
        Some(10),
        None,
    );
    let sip = "_sip._tcp.example.org";
    control.insert_record_with(
        "example.org",
        sip,
        "SRV",
        "5 5060 sip.example.org",
        600,
        Some(1),
        None,
    );
    let original = control.records();
    for set in [
        rr(
            "example.org",
            RecordType::MX,
            None,
            &["20 mail.example.org."],
        ),
        rr(
            "example.org",
            RecordType::MX,
            None,
            &["10 new.example.org.", "20 mail.example.org."],
        ),
        rr(
            "example.org",
            RecordType::MX,
            None,
            &["10 mail.example.org.", "20 mail.example.org."],
        ),
        rr(sip, RecordType::SRV, None, &["2 5 5060 sip.example.org."]),
    ] {
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{set:?}: {e:?}");
        assert!(!e.is_retryable());
    }
    // Two new values that differ only in priority, at a name without the type.
    let twins = rr(
        "other.example.org",
        RecordType::MX,
        None,
        &["10 mx.example.net.", "20 mx.example.net."],
    );
    let e = client
        .set_rrset(&zone(), &twins, Expect::Absent)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(control.records(), original);

    // Another weight is another content: replaced as usual, creates before deletes.
    let reweighted = rr(sip, RecordType::SRV, None, &["1 6 5060 sip.example.org."]);
    assert_eq!(
        client
            .set_rrset(&zone(), &reweighted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    // The documented way to change only a priority: delete the rrset, then set it.
    assert_eq!(
        client
            .delete_rrset(&zone(), &zone(), RecordType::MX, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    let moved = rr(
        "example.org",
        RecordType::MX,
        None,
        &["20 mail.example.org."],
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &moved, Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    assert_eq!(control.records_at("example.org", "MX")[0].prio, Some(20));
}

/// The read shows every record at the name, so a CNAME next to other data is refused after the
/// read and before any write, either way round.
#[tokio::test]
async fn porkbun_cname_and_other_data_are_refused_before_a_write() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", "a.example.org", "A", "192.0.2.1", 600);
    control.insert_record(
        "example.org",
        "c.example.org",
        "CNAME",
        "t.example.net",
        600,
    );
    let cname = rr(
        "a.example.org",
        RecordType::CNAME,
        None,
        &["t.example.net."],
    );
    let e = client
        .set_rrset(&zone(), &cname, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    let a = rr("c.example.org", RecordType::A, None, &["192.0.2.2"]);
    let e = client
        .set_rrset(&zone(), &a, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// Refusals before any request: the apex NS set is not writable, a type outside the list is
/// `UnsupportedRecordType` for every operation, a TTL below 600 and an expectation
/// about another name or type are `InvalidInput`, a name outside the zone is `NameOutsideZone`.
#[tokio::test]
async fn porkbun_record_refusals_send_nothing() {
    let (mock, client) = setup().await;
    let apex_ns = rr("example.org", RecordType::NS, None, &["ns1.example.net."]);
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

    for rtype in [
        RecordType::SOA,
        RecordType::PTR,
        RecordType::HTTPS,
        RecordType::ALIAS,
        RecordType::from_code(43),
    ] {
        let e = client.get_rrset(&zone(), &name(), rtype).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
        let e = client
            .delete_rrset(&zone(), &name(), rtype, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
    }
    for ttl in [300, 599] {
        let set = rr("www.example.org", RecordType::A, Some(ttl), &["192.0.2.1"]);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{ttl}: {e:?}");
    }
    let a = rr("www.example.org", RecordType::A, None, &["192.0.2.1"]);
    let txt_set = rr("www.example.org", RecordType::TXT, None, &["\"v\""]);
    let e = client
        .set_rrset(&zone(), &a, Expect::Matches(&txt_set))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    let e = client
        .delete_rrset(
            &zone(),
            &dn("www.example.org"),
            RecordType::A,
            Expect::Absent,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    for (zone, owner) in [
        ("example.org", "example.net"),
        ("example.org", "badexample.org"),
        ("a.example.org", "b.example.org"),
    ] {
        let set = rr(owner, RecordType::A, None, &["192.0.2.1"]);
        let e = client
            .set_rrset(&dn(zone), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NameOutsideZone, "{e:?}");
        let e = client
            .get_rrset(&dn(zone), &dn(owner), RecordType::A)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NameOutsideZone, "{e:?}");
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());

    // The bounds themselves are accepted.
    for ttl in [600, 2_147_483_647] {
        let set = rr("www.example.org", RecordType::A, Some(ttl), &["192.0.2.1"]);
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
        assert_eq!(
            mock.control().records_at("www.example.org", "A")[0].ttl,
            ttl
        );
    }
}

/// Values whose encoding at this API no source establishes are refused after the read and
/// nothing is written; such a value already at the provider is kept as it is and a plain value
/// joins it.
#[tokio::test]
async fn porkbun_values_without_an_encoding_are_refused() {
    let (mock, client) = setup().await;
    for set in [
        rr("www.example.org", RecordType::TXT, None, &["\"two words\""]),
        rr("www.example.org", RecordType::MX, None, &["0 ."]),
        rr("www.example.org", RecordType::SRV, None, &["0 0 0 ."]),
        rr("www.example.org", RecordType::CAA, None, &["0 issue \";\""]),
        rr(
            "www.example.org",
            RecordType::CAA,
            None,
            &["0 contactemail \"a@example.org\""],
        ),
    ] {
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{set:?}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);

    mock.control().insert_record(
        "example.org",
        "www.example.org",
        "TXT",
        "v=spf1 mx -all",
        600,
    );
    let read = client
        .get_rrset(&zone(), &dn("www.example.org"), RecordType::TXT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.records()[0].as_str(), "\"v=spf1 mx -all\"");
    let mut members = read.records().to_vec();
    members.push(rdata(RecordType::TXT, "\"plain\""));
    let both = RrSet::new(dn("www.example.org"), RecordType::TXT, None, members).unwrap();
    assert_eq!(
        client
            .set_rrset(&zone(), &both, Expect::Matches(&read))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        stored(&mock, "www.example.org", "TXT"),
        ["plain", "v=spf1 mx -all"]
    );
}

/// The listing reports every rrset the API lists with the smallest TTL of each; the provider's
/// default NS records are not among them; a type the model does not know, a name it cannot hold
/// and two CNAME records at one name are in `skipped`, an unparseable value is non-canonical
/// data, and a type outside the record-level list is listed.
#[tokio::test]
async fn porkbun_listing_reports_skipped_sets() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_zone_defaults("example.org");
    control.insert_record("example.org", "www.example.org", "A", "192.0.2.1", 900);
    control.insert_record("example.org", "www.example.org", "A", "192.0.2.2", 600);
    control.insert_record("example.org", "odd.example.org", "A", "not an address", 600);
    control.insert_record("example.org", "x.example.org", "WEIRD", "whatever", 600);
    control.insert_record(
        "example.org",
        "two.example.org",
        "CNAME",
        "a.example.net",
        600,
    );
    control.insert_record(
        "example.org",
        "two.example.org",
        "CNAME",
        "b.example.net",
        600,
    );
    control.insert_record("example.org", "bad name", "A", "192.0.2.9", 600);
    control.insert_record(
        "example.org",
        "example.org",
        "ALIAS",
        "host.example.net",
        600,
    );
    let listing = client.list_rrsets(&zone()).await.unwrap();

    let get = |owner: &str, rtype: RecordType| {
        listing
            .rrsets
            .iter()
            .find(|s| s.name() == &dn(owner) && s.rtype() == rtype)
            .cloned()
    };
    assert_eq!(
        get("www.example.org", RecordType::A),
        Some(rr(
            "www.example.org",
            RecordType::A,
            Some(600),
            &["192.0.2.1", "192.0.2.2"]
        ))
    );
    assert_eq!(get("example.org", RecordType::NS), None);
    let odd = get("odd.example.org", RecordType::A).unwrap();
    assert!(!odd.records()[0].is_canonical());
    assert_eq!(odd.records()[0].as_str(), "not an address");
    let alias = get("example.org", RecordType::ALIAS).unwrap();
    assert_eq!(alias.records()[0].as_str(), "host.example.net.");

    let mut skipped: Vec<(String, String, SkipReason)> = listing
        .skipped
        .iter()
        .map(|s| (s.name.to_string(), s.type_name.clone(), s.reason))
        .collect();
    skipped.sort_by_key(|s| format!("{s:?}"));
    let mut expected = vec![
        (
            "example.org.".to_owned(),
            "A".to_owned(),
            SkipReason::UnsupportedName,
        ),
        (
            "two.example.org.".to_owned(),
            "CNAME".to_owned(),
            SkipReason::NotPlainRecords,
        ),
        (
            "x.example.org.".to_owned(),
            "WEIRD".to_owned(),
            SkipReason::UnknownType,
        ),
    ];
    expected.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(skipped, expected);
    assert_eq!(listing.rrsets.len(), 3);
    assert_eq!(mock.log().count(Some("GET"), RETRIEVE), 1);
}

/// A listing or a read whose answer is not complete or not in the documented form is an error,
/// never a shorter result, and nothing is written after it.
#[tokio::test]
async fn porkbun_unreadable_listing_writes_nothing() {
    let (mock, client) = setup().await;
    let set = rr("www.example.org", RecordType::A, None, &["192.0.2.2"]);
    for body in [
        r#"{"status":"SUCCESS"}"#,
        r#"{"status":"SUCCESS","records":{}}"#,
        r#"{"status":"SUCCESS","records":[{"id":"1","name":"www.example.org","type":"A","content":"192.0.2.1","ttl":"600"}],"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", RETRIEVE).respond(200, body));
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
        mock.faults()
            .push(Fault::on("GET", RETRIEVE).respond(200, body));
        let e = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    // A record the layer wants to delete, listed without an identifier, is refused before any
    // write.
    mock.faults().push(Fault::on("GET", RETRIEVE).respond(
        200,
        r#"{"status":"SUCCESS","records":[{"name":"www.example.org","type":"A","content":"192.0.2.1","ttl":"600"}]}"#,
    ));
    let e = client
        .delete_rrset(&zone(), &dn("www.example.org"), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// A record whose name the listing states in a form other than a fully qualified name in the
/// zone is never taken for a record of the name, so it is never deleted.
#[tokio::test]
async fn porkbun_names_must_be_fully_qualified() {
    let (mock, client) = setup().await;
    let body = serde_json::json!({"status": "SUCCESS", "records": [
        {"id": "7", "name": "_acme-challenge", "type": "TXT", "content": "AAA", "ttl": "600"},
        {"id": "8", "name": "_acme-challenge.example.net", "type": "TXT", "content": "AAA",
         "ttl": "600"},
    ]});
    mock.faults()
        .push(Fault::on("GET", RETRIEVE).respond(200, body.to_string()));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    // Upper case and a trailing dot are the same name.
    mock.control()
        .insert_record("example.org", NAME, "TXT", "BBB", 600);
    let body = serde_json::json!({"status": "SUCCESS", "records": [
        {"id": mock.control().records()[0].id.to_string(), "name": "_ACME-challenge.Example.org.",
         "type": "TXT", "content": "BBB", "ttl": "600"},
    ]});
    mock.faults()
        .push(Fault::on("GET", RETRIEVE).respond(200, body.to_string()));
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().records().is_empty());
}

/// A record-level delete answered `INVALID_RECORD_ID` is done only when a new read no longer
/// finds the value.
#[tokio::test]
async fn porkbun_record_delete_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let id = control.insert_record("example.org", www, "A", "192.0.2.1", 600);
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("POST", DELETE).run(move || hook.delete_record(id)));
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    control.insert_record("example.org", www, "A", "192.0.2.1", 600);
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("POST", DELETE).run(move || hook.recreate_domain("example.org")));
    let e = client
        .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.1"]);
}

/// Two clients sharing a `Context` replace one rrset at once: the second waits for the lock and
/// sees the first one's records.
#[tokio::test]
async fn porkbun_concurrent_record_writes_are_serialized() {
    let mock = PorkbunMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, KEY, SECRET, &ctx);
    let b = client_with(&mock, KEY, SECRET, &ctx);
    mock.faults()
        .push(Fault::on("POST", CREATE).delay(Duration::from_millis(300)));
    let www = "www.example.org";
    let first = rr(www, RecordType::A, None, &["192.0.2.1"]);
    let second = rr(www, RecordType::A, None, &["192.0.2.2"]);
    let zone = zone();
    let (ra, rb) = tokio::join!(
        a.set_rrset(&zone, &first, Expect::Absent),
        b.set_rrset(&zone, &second, Expect::Absent),
    );
    let outcomes = [ra.is_ok(), rb.is_ok()];
    assert_eq!(outcomes.iter().filter(|ok| **ok).count(), 1, "{outcomes:?}");
    assert_eq!(mock.control().records_at(www, "A").len(), 1);
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

fn live_client() -> (Arc<AnyProvider>, DomainName) {
    let settings = live_env("ZONEWRIGHT_LIVE_PORKBUN_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_PORKBUN_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_PORKBUN_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = AnyProvider::from_json(
        ProviderId::Porkbun,
        &settings,
        &SecretString::from(credentials),
        &ctx,
    )
    .unwrap();
    (Arc::new(client), zone)
}

/// Adds and removes two values under a generated label in the zone the maintainer names, and
/// removes exactly the values it added afterwards, also when the body failed.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_porkbun_add_and_remove() {
    let (client, zone) = live_client();
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
                client.remove_txt_value(&zone, &name, b).await.unwrap(),
                RemoveOutcome::RrsetDeleted
            );
        })
    };
    let outcome = body.await;
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

/// Exercises what the client assumes and the documentation does not show, in the zone
/// `ZONEWRIGHT_LIVE_PORKBUN_ZONE` under names that start with `ZONEWRIGHT_LIVE_PORKBUN_PREFIX`
/// and a random tag:
///
/// - the keys are taken as the headers `X-API-Key` and `X-Secret-API-Key` by `GET /ping` (with
///   `credentialsValid: true`), `GET /domain/listAll` and `GET /dns/retrieve` (documented per
///   operation; the writes carry them in the body, as their request schemas require);
/// - `/dns/retrieve` states names fully qualified, the apex of a name and a wildcard included;
/// - the `content` forms the client writes are taken and read back as the same values: host
///   names without the trailing dot, MX and SRV with `prio`, SRV `weight port target`, CAA
///   `flags tag "value"`, TLSA `usage selector matching hex`, TXT the value itself;
/// - a TTL of 600 is accepted, and an edit of the whole record with a new `ttl` changes only the
///   TTL;
/// - a CNAME is replaced in place by an edit of the whole record with a new `content`;
/// - the client refuses, before any write, a replacement that changes only the priority of an MX
///   value (`DUPLICATE_RECORD` compares name, type and content), and a delete of the rrset
///   followed by the set does it;
/// - a delete of a record already deleted is answered `INVALID_RECORD_ID`, which the client
///   confirms by a new read.
///
/// Everything it created is deleted afterwards by name and type with the record-level
/// operations, also when a step failed; it touches nothing else.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn porkbun_live_assumptions() {
    let (client, zone) = live_client();
    let prefix = live_env("ZONEWRIGHT_LIVE_PORKBUN_PREFIX");
    let tag = format!("{prefix}-{:016x}", random_u64());
    let base = zone.prepend(&tag).unwrap();
    let owner = |label: &str| base.prepend(label).unwrap();
    let rd = |rtype: RecordType, text: &str| RecordData::parse(rtype, text).unwrap();
    let set = move |name: DomainName, rtype: RecordType, texts: &[String]| {
        RrSet::new(name, rtype, None, texts.iter().map(|t| rd(rtype, t))).unwrap()
    };
    let sets: Vec<RrSet> = vec![
        set(
            base.clone(),
            RecordType::MX,
            &[format!("10 mx.{base}"), format!("20 mx2.{base}")],
        ),
        set(
            owner("_sip._tcp"),
            RecordType::SRV,
            &[format!("10 20 5060 sip.{base}")],
        ),
        set(
            base.clone(),
            RecordType::CAA,
            &["0 issue \"letsencrypt.org\"".to_owned()],
        ),
        set(
            owner("_25._tcp"),
            RecordType::TLSA,
            &["3 1 1 0A1B2C3D".to_owned()],
        ),
        set(
            owner("alias"),
            RecordType::CNAME,
            &[format!("target.{base}")],
        ),
        set(owner("*"), RecordType::A, &["192.0.2.20".to_owned()]),
        set(owner("txt"), RecordType::TXT, &["\"zw-live\"".to_owned()]),
    ];
    let created: Vec<(DomainName, RecordType)> =
        sets.iter().map(|s| (s.name().clone(), s.rtype())).collect();
    let body = {
        let (client, zone, sets, base) = (client.clone(), zone.clone(), sets.clone(), base.clone());
        tokio::spawn(async move {
            let report = client.check([&zone]).await.unwrap();
            assert!(
                report.credentials_verified && report.zones[0].found,
                "{report:?}"
            );
            for set in &sets {
                let label = format!("{} {}", set.name(), set.rtype());
                assert_eq!(
                    client.set_rrset(&zone, set, Expect::Absent).await.unwrap(),
                    SetOutcome::Created,
                    "{label}"
                );
                let read = client
                    .get_rrset(&zone, set.name(), set.rtype())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(read.records(), set.records(), "{label}");
                assert_eq!(
                    read.ttl(),
                    Some(RrsetTtl::from_secs(600).unwrap()),
                    "{label}"
                );
            }
            let listing = client.list_rrsets(&zone).await.unwrap();
            for set in &sets {
                assert!(
                    listing
                        .rrsets
                        .iter()
                        .any(|s| s.name() == set.name() && s.records() == set.records()),
                    "{} {}",
                    set.name(),
                    set.rtype()
                );
            }
            // An edit of the TTL only.
            let retuned = sets[0]
                .clone()
                .with_ttl(Some(RrsetTtl::from_secs(900).unwrap()));
            assert_eq!(
                client
                    .set_rrset(&zone, &retuned, Expect::Any)
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                client
                    .get_rrset(&zone, retuned.name(), RecordType::MX)
                    .await
                    .unwrap()
                    .unwrap(),
                retuned
            );
            // The same exchange with another priority: refused before any write, done by a
            // delete of the rrset and a new set.
            let reprioritized = set(
                base.clone(),
                RecordType::MX,
                &[format!("30 mx.{base}"), format!("20 mx2.{base}")],
            );
            let e = client
                .set_rrset(&zone, &reprioritized, Expect::Any)
                .await
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
            assert_eq!(
                client
                    .get_rrset(&zone, &base, RecordType::MX)
                    .await
                    .unwrap()
                    .unwrap(),
                retuned
            );
            assert_eq!(
                client
                    .delete_rrset(&zone, &base, RecordType::MX, Expect::Matches(&retuned))
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
            assert_eq!(
                client
                    .set_rrset(&zone, &reprioritized, Expect::Absent)
                    .await
                    .unwrap(),
                SetOutcome::Created
            );
            // A CNAME replaced in place.
            let moved = set(
                base.prepend("alias").unwrap(),
                RecordType::CNAME,
                &[format!("other.{base}")],
            );
            assert_eq!(
                client.set_rrset(&zone, &moved, Expect::Any).await.unwrap(),
                SetOutcome::Replaced
            );
            // A delete raced by a second client of another context: one of them meets
            // `INVALID_RECORD_ID` and confirms by a read.
            let (settings, credentials) = (
                live_env("ZONEWRIGHT_LIVE_PORKBUN_SETTINGS"),
                live_env("ZONEWRIGHT_LIVE_PORKBUN_CREDENTIALS"),
            );
            let other_ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
            let other = AnyProvider::from_json(
                ProviderId::Porkbun,
                &settings,
                &SecretString::from(credentials),
                &other_ctx,
            )
            .unwrap();
            let txt_name = base.prepend("txt").unwrap();
            let (a, b) = tokio::join!(
                client.delete_rrset(&zone, &txt_name, RecordType::TXT, Expect::Any),
                other.delete_rrset(&zone, &txt_name, RecordType::TXT, Expect::Any),
            );
            for outcome in [a, b] {
                match outcome {
                    Ok(DeleteOutcome::Deleted | DeleteOutcome::NotPresent) => {}
                    other => panic!("unexpected outcome {other:?}"),
                }
            }
        })
    };
    let outcome = body.await;
    let mut cleanup = Vec::new();
    for (name, rtype) in &created {
        if let Err(e) = client.delete_rrset(&zone, name, *rtype, Expect::Any).await {
            cleanup.push(format!("{name} {rtype}: {e}"));
        }
    }
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}
