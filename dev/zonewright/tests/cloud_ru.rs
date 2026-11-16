//! Tests of the Cloud.ru client (`cloud_ru`) against its mock.
#![cfg(feature = "cloud_ru")]
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
use zonewright::providers::cloud_ru::{CloudRu, CloudRuConfig, CloudRuCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl, SetOutcome,
    SkipReason, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::cloud_ru::{CloudRuMock, NameStyle, Seed};
use zonewright_mock::echo::{DEFAULT_ISSUED_TOKEN, EchoServer, Echoed, Render};

use common::echo::{CANARY_KEY, CANARY_PASSWORD, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The project, access key ID and secret of the standard seed.
const PROJECT: &str = "0f1e2d3c-0000-4000-8000-000000000001";
const KEY_ID: &str = "zw-test-key-id";
const SECRET: &str = "test-only-secret";

/// The zone and the owner name most tests write to.
const ZONE: &str = "example.org";
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const TOKENS: &str = "/api/v1/auth/token";
const ZONES: &str = "/v1/publicZonesSole";
const RECORDS: &str = "/v1/publicRecordsSole";
const RECORD: &str = "/v1/publicRecordsSole/*";
const OPERATIONS: &str = "/v1/operations/*";

fn zone() -> DomainName {
    dn(ZONE)
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings for the standard seed, pointed at `mock`, with the shortest polling interval.
fn settings(mock: &CloudRuMock) -> CloudRuConfig {
    let mut config = CloudRuConfig::new(PROJECT.into(), KEY_ID.into());
    config.dns_url = mock.dns_url();
    config.iam_url = mock.iam_url();
    config.operation_poll_ms = 250;
    config
}

fn credentials(secret: &str) -> CloudRuCredentials {
    CloudRuCredentials::new(SecretString::from(secret.to_owned()))
}

fn client_with(mock: &CloudRuMock, secret: &str, ctx: &Context) -> CloudRu {
    CloudRu::new(settings(mock), credentials(secret), ctx).unwrap()
}

async fn setup() -> (CloudRuMock, CloudRu) {
    setup_with(Seed::standard()).await
}

async fn setup_with(seed: Seed) -> (CloudRuMock, CloudRu) {
    let mock = CloudRuMock::start(seed).await;
    let client = client_with(&mock, SECRET, &context());
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
fn writes(mock: &CloudRuMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), RECORDS)
        + log.count(Some("PATCH"), RECORD)
        + log.count(Some("DELETE"), RECORD)
}

/// The values at [`NAME`].
fn values(mock: &CloudRuMock) -> Vec<String> {
    mock.control().txt_values(NAME)
}

/// The owner name most record-level tests write to.
const REC: &str = "rec.example.org";

/// SPF, type code 99.
const SPF: RecordType = RecordType::from_code(99);

/// Canonical data of `rtype`.
fn rd(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap()
}

/// The rrset of `name` and `rtype` with `data`.
fn rrset_of(name: &str, rtype: RecordType, ttl: Option<u32>, data: Vec<RecordData>) -> RrSet {
    RrSet::new(
        dn(name),
        rtype,
        ttl.map(|t| RrsetTtl::from_secs(t).unwrap()),
        data,
    )
    .unwrap()
}

/// The rrset of `name` and `rtype` with `texts`, each parsed as canonical data.
fn rrset(name: &str, rtype: RecordType, ttl: Option<u32>, texts: &[&str]) -> RrSet {
    rrset_of(
        name,
        rtype,
        ttl,
        texts.iter().map(|t| rd(rtype, t)).collect(),
    )
}

/// TXT data holding `text` as the value itself.
fn txt_data(text: &str) -> RecordData {
    txt(text).to_data().unwrap()
}

/// SPF data holding `text` as one character-string, as the inspector would see it.
fn spf_data(text: &str) -> RecordData {
    let mut wire = vec![u8::try_from(text.len()).unwrap()];
    wire.extend_from_slice(text.as_bytes());
    RecordData::from_wire(SPF, &wire).unwrap()
}

/// The values of the record of `name` and `rtype` (lowercase) at the mock, sorted.
fn stored(mock: &CloudRuMock, name: &str, rtype: &str) -> Vec<String> {
    let mut values = mock
        .control()
        .record(name, rtype)
        .map(|r| r.values)
        .unwrap_or_default();
    values.sort_unstable();
    values
}

/// Number of record listings the mock answered.
fn listings(mock: &CloudRuMock) -> usize {
    mock.log().count(Some("GET"), RECORDS)
}

/// The standard mock with operations that are done in the write's answer, so that record-level
/// tests do not wait for polls.
async fn setup_records() -> (CloudRuMock, CloudRu) {
    let (mock, client) = setup().await;
    mock.control().set_operation_polls(0);
    (mock, client)
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

assert_not_impl!(CloudRu: std::fmt::Display, serde::Serialize);
assert_not_impl!(CloudRuCredentials: std::fmt::Display, serde::Serialize);

/// What the echo's DNS paths answer like the API before the request under test meets the echo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Write {
    /// No record: the add creates one (`POST`).
    Create,
    /// A record with a foreign value: the add updates it (`PATCH`).
    Update,
    /// A record with our value only: the removal deletes it (`DELETE`).
    Delete,
}

/// How the write's operation meets the echo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Poll {
    /// The write itself is answered by the echo.
    No,
    /// The write is accepted with an unfinished operation; its poll is answered by the echo.
    Echoed,
    /// The poll answers `200` with a finished operation whose error message is the echo text.
    OperationError,
}

/// `check` and a write against an echo that quotes every request back, for every dialect: no
/// canary, no issued token and no JWT in any error, `ZoneCheck::detail` or `Debug`, and the
/// write's error shows the redaction. Passes per dialect: the API echoes (the issued token in
/// `Authorization`); the token service echoes (the key ID and the secret in its body); and the
/// reads answer like the API so that each write (create, update, delete) and the poll of its
/// operation reach the echo, from the TXT value operations and from `set_rrset` and
/// `delete_rrset`.
#[tokio::test]
async fn cloud_ru_secret_echo() {
    // One server and one context for every case: each case reconfigures the server, and
    // every client reuses the context's pooled connection (see `EchoServer::reset`).
    let ctx = context();
    let echo = EchoServer::start(200).await;
    let secrets = [CANARY_PASSWORD, CANARY_KEY, DEFAULT_ISSUED_TOKEN];
    for dialect in dialects() {
        for status in [400, 401] {
            let label = format!("{} {:?} {status} api", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status));
            let client = echo_client(&echo, &echo.token_url(), &ctx);
            echo_round(&label, &client, Write::Create, &secrets).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
            assert!(echo.token_requests() > 0, "{label}: no token was issued");

            let label = format!("{} {:?} {status} iam", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status).token_path("/no-token-endpoint"));
            let client = echo_client(&echo, &echo.url(TOKENS), &ctx);
            echo_round(&label, &client, Write::Create, &secrets).await;
            assert!(
                echo.log().count(Some("POST"), TOKENS) > 0,
                "{label}: the token service was not reached"
            );
        }
        for status in [400, 403, 409, 422, 500] {
            for write in [Write::Create, Write::Update, Write::Delete] {
                // A poll answered 5xx is retried with back-off; the 4xx polls cover the path.
                let polls: &[Poll] = if status < 500 {
                    &[Poll::No, Poll::Echoed, Poll::OperationError]
                } else {
                    &[Poll::No]
                };
                for &poll in polls {
                    let label = format!(
                        "{} {:?} {status} {write:?} poll={poll:?}",
                        dialect.name, dialect.spelling
                    );
                    echo.reset(
                        dialect
                            .echo(status)
                            .render_under("/v1", reads_then(dialect.render.clone(), write, poll)),
                    );
                    let client = echo_client(&echo, &echo.token_url(), &ctx);
                    echo_round(&label, &client, write, &secrets).await;
                    assert_write_reached(&echo, &label, write, poll);
                    // The same write through the record level.
                    let label = format!("{label} record");
                    echo.reset(
                        dialect
                            .echo(status)
                            .render_under("/v1", reads_then(dialect.render.clone(), write, poll)),
                    );
                    let client = echo_client(&echo, &echo.token_url(), &ctx);
                    echo_round_at(&label, &client, write, true, &secrets).await;
                    assert_write_reached(&echo, &label, write, poll);
                }
            }
        }
    }
}

/// The echo received exactly one `write` request, and polls when the write was accepted.
fn assert_write_reached(echo: &EchoServer, label: &str, write: Write, poll: Poll) {
    let (method, path) = match write {
        Write::Create => ("POST", RECORDS),
        Write::Update => ("PATCH", RECORD),
        Write::Delete => ("DELETE", RECORD),
    };
    assert_eq!(
        echo.log().count(Some(method), path),
        1,
        "{label}: the write did not reach the echo"
    );
    if poll != Poll::No {
        assert!(
            echo.log().count(Some("GET"), OPERATIONS) > 0,
            "{label}: the operation was not polled"
        );
    }
}

/// A renderer that answers the reads like the API (one zone; no record, a TXT record with a
/// foreign value, or one with our value only) and the write or the poll with `errors`.
fn reads_then(errors: Render, write: Write, poll: Poll) -> Render {
    Arc::new(move |e: &Echoed| {
        let ok = |body: Value| (StatusCode::OK, axum::Json(body)).into_response();
        if e.method != Method::GET {
            return match poll {
                Poll::No => errors(e),
                Poll::Echoed | Poll::OperationError => {
                    ok(json!({"id": "00000000-0000-4000-8000-0000000000f1", "done": false}))
                }
            };
        }
        if e.path.starts_with("/v1/operations/") {
            return match poll {
                Poll::OperationError => ok(json!({
                    "id": "00000000-0000-4000-8000-0000000000f1",
                    "done": true,
                    "error": {"code": 3, "message": e.text, "details": []}
                })),
                Poll::No | Poll::Echoed => errors(e),
            };
        }
        if e.path.ends_with("/publicZonesSole") {
            return ok(json!({"zones": [{
                "id": "00000000-0000-4000-8000-000000000001",
                "projectId": PROJECT,
                "name": "example.org",
                "domain": "example.org."
            }]}));
        }
        let records = match write {
            Write::Create => json!([]),
            Write::Update | Write::Delete => json!([{
                "id": "00000000-0000-4000-8000-000000000002",
                "publicZoneId": "00000000-0000-4000-8000-000000000001",
                "name": "_acme-challenge",
                "type": "txt",
                "values": [if write == Write::Update { "foreign" } else { "v1" }],
                "ttl": "60"
            }]),
        };
        ok(json!({ "records": records }))
    })
}

fn echo_client(echo: &EchoServer, iam_url: &str, ctx: &Context) -> CloudRu {
    let mut config = CloudRuConfig::new(PROJECT.into(), CANARY_KEY.into());
    config.dns_url = echo.base_url();
    config.iam_url = iam_url.to_owned();
    config.operation_poll_ms = 250;
    CloudRu::new(config, credentials(CANARY_PASSWORD), ctx).unwrap()
}

async fn echo_round(label: &str, client: &CloudRu, write: Write, secrets: &[&str]) {
    echo_round_at(label, client, write, false, secrets).await;
}

/// [`echo_round`] with the write made by `set_rrset` / `delete_rrset` when `record` is true.
async fn echo_round_at(
    label: &str,
    client: &CloudRu,
    write: Write,
    record: bool,
    secrets: &[&str],
) {
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
    let set = RrSet::new(
        name(),
        RecordType::TXT,
        None,
        [txt("v1").to_data().unwrap()],
    )
    .unwrap();
    let result = match (record, write == Write::Delete) {
        (false, true) => remove(client, "v1").await.map(|o| format!("{o:?}")),
        (false, false) => add(client, "v1").await.map(|o| format!("{o:?}")),
        (true, true) => client
            .delete_rrset(&zone(), &name(), RecordType::TXT, Expect::Any)
            .await
            .map(|o| format!("{o:?}")),
        (true, false) => client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .map(|o| format!("{o:?}")),
    };
    let write = match result {
        Ok(outcome) => panic!("{label}: the echo accepted a write: {outcome}"),
        Err(e) => format!("{e} | {e:?}"),
    };
    assert!(
        write.contains(REDACTED),
        "{label}: the echo did not reach the error: {write}"
    );
    texts.push(write);
    for text in &texts {
        assert_clean(label, text, secrets);
    }
}

/// A `TRACE` capture over a success, a renewed token, repeated 401s, a 500, an operation error
/// and a secret the token service refuses: the transport's events are there, and no canary and
/// no issued token is.
#[tokio::test(flavor = "current_thread")]
async fn cloud_ru_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.key_id = CANARY_KEY.into();
    seed.secret = CANARY_PASSWORD.into();
    let mock = CloudRuMock::start(seed).await;
    let mut config = settings(&mock);
    config.key_id = CANARY_KEY.into();
    let client = CloudRu::new(config.clone(), credentials(CANARY_PASSWORD), &context()).unwrap();
    let mut texts = Vec::new();

    add(&client, "v1").await.unwrap();
    mock.control().revoke_tokens();
    add(&client, "v2").await.unwrap();

    mock.faults()
        .push(Fault::on("GET", RECORDS).always().status(401));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("PATCH", RECORD).status(500));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    mock.control().fail_next_operation("operation failed");
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    let wrong = CloudRu::new(config, credentials("wrong-secret"), &context()).unwrap();
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?} | {wrong:?} | {client:?}"));

    let entries = capture.entries();
    assert!(
        entries.iter().any(|e| e.target == "zonewright::http"),
        "the capture holds no transport event"
    );
    texts.push(capture.text());
    let tokens = mock.control().issued_tokens();
    assert!(tokens.len() >= 2);
    let mut secrets = vec![CANARY_PASSWORD, CANARY_KEY];
    secrets.extend(tokens.iter().map(String::as_str));
    for text in &texts {
        assert_clean("cloud_ru logs and errors", text, &secrets);
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request, token requests included: another
/// zone, a name that merely ends with the zone's text, the zone's text inside another name, and
/// a sibling zone.
#[tokio::test]
async fn cloud_ru_name_outside_zone_sends_nothing() {
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
    assert_eq!(mock.control().tokens_issued(), 0);
}

/// `Created`, `Appended` for a second value (the apex and the wildcard of one certificate share
/// a name), then `AlreadyPresent` without a write. One record holds both values.
#[tokio::test]
async fn cloud_ru_add_is_idempotent() {
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
    assert_eq!(values(&mock), ["AAA", "BBB"]);
    assert_eq!(
        mock.control().records().len(),
        1,
        "one record per name and type"
    );
    assert_eq!(mock.log().count(Some("POST"), RECORDS), 1);
    assert_eq!(mock.log().count(Some("PATCH"), RECORD), 1);
    assert!(
        mock.log().count(Some("GET"), OPERATIONS) >= 2,
        "operations polled"
    );
    assert_eq!(mock.control().tokens_issued(), 1, "token cached");
}

/// Removing an absent value next to foreign ones writes nothing; adding and removing our value
/// leaves the foreign values, the TTL, the description and the tags as they were. A single
/// foreign value is never a reason to delete the record.
#[tokio::test]
async fn cloud_ru_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record(ZONE, NAME, "txt", 600, &["foreign", "\"foreign-quoted\""]);
    control.set_attributes(NAME, "txt", Some("set by hand"), &["keep"]);
    control.insert_record(ZONE, "other.example.org", "txt", 300, &["ours"]);
    let original = control.record(NAME, "txt").unwrap();

    let ours = txt("ours");
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &ours, None)
            .await
            .unwrap(),
        AddOutcome::Appended
    );
    let during = control.record(NAME, "txt").unwrap();
    assert_eq!(during.ttl, 600);
    assert_eq!(during.description.as_deref(), Some("set by hand"));
    assert_eq!(during.tags, ["keep"]);
    let patch = mock.log().matching(Some("PATCH"), RECORD).pop().unwrap();
    let body = patch.body_json().unwrap();
    assert_eq!(body["description"], "set by hand");
    assert_eq!(body["tags"], json!(["keep"]));
    assert_eq!(body["ttl"], 600);
    assert_eq!(values(&mock), ["foreign", "\"foreign-quoted\"", "ours"]);
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.record(NAME, "txt").unwrap(), original);
    assert_eq!(control.txt_values("other.example.org"), ["ours"]);
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 0);

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_record(ZONE, other, "txt", 60, &["foreign"]);
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

#[tokio::test]
async fn cloud_ru_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().records().is_empty());
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 1);
    assert_eq!(mock.log().count(Some("PATCH"), RECORD), 0);
}

#[tokio::test]
async fn cloud_ru_remove_is_idempotent() {
    let (mock, client) = setup().await;
    // No record at all.
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
    for _ in 0..2 {
        assert_eq!(
            remove(&client, "BBB").await.unwrap(),
            RemoveOutcome::NotPresent
        );
    }
    assert!(mock.control().records().is_empty());
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 1);
}

/// Two clients sharing a `Context` add to one name at once, the first write delayed: both values
/// end up in the record. Without the name lock both would read "no record" and the second create
/// would be refused.
#[tokio::test]
async fn cloud_ru_concurrent_adds_are_serialized() {
    let mock = CloudRuMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, SECRET, &ctx);
    let b = client_with(&mock, SECRET, &ctx);
    mock.faults()
        .push(Fault::on("POST", RECORDS).delay(Duration::from_millis(300)));
    let (zone, name, aaa, bbb) = (zone(), name(), txt("AAA"), txt("BBB"));
    let (ra, rb) = tokio::join!(
        a.add_txt_value(&zone, &name, &aaa, None),
        b.add_txt_value(&zone, &name, &bbb, None),
    );
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [AddOutcome::Appended, AddOutcome::Created]);
    let mut values = values(&mock);
    values.sort();
    assert_eq!(values, ["AAA", "BBB"]);
}

/// The zone is deleted and created again under a new identifier while the client has the old
/// one cached. A read with the stale identifier is answered 404, the zone is looked up again and
/// the read repeated: a removal never reports `NotPresent` for a value that is there. A write
/// that meets the stale identifier fails cleanly with a retryable error and drops it; the next
/// operation succeeds.
#[tokio::test]
async fn cloud_ru_stale_zone_id() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for value in ["v1", "v2"] {
        add(&client, value).await.unwrap();
    }
    let lookups = || mock.log().count(Some("GET"), ZONES);
    assert_eq!(lookups(), 1);

    control.recreate_zone(ZONE);
    assert_eq!(remove(&client, "v1").await.unwrap(), RemoveOutcome::Removed);
    assert_eq!(lookups(), 2);
    control.recreate_zone(ZONE);
    assert_eq!(add(&client, "v3").await.unwrap(), AddOutcome::Appended);
    assert_eq!(values(&mock), ["v2", "v3"]);

    // The zone is recreated between the re-read and the write.
    let hook = control.clone();
    mock.faults().push(Fault::on("PATCH", RECORD).run(move || {
        hook.recreate_zone(ZONE);
    }));
    let e = add(&client, "v4").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(add(&client, "v4").await.unwrap(), AddOutcome::Appended);
    assert_eq!(values(&mock), ["v2", "v3", "v4"]);

    // `check` looks the zone up afresh and refreshes the cache.
    control.recreate_zone(ZONE);
    assert!(client.check(&[zone()]).await.unwrap().zones[0].found);
    let before = lookups();
    assert_eq!(add(&client, "v5").await.unwrap(), AddOutcome::Appended);
    assert_eq!(lookups(), before);
}

/// Record types the client does not offer, and SOA, are `UnsupportedRecordType` for every
/// record-level operation that names one, before any request.
#[tokio::test]
async fn cloud_ru_unsupported_record_types_send_nothing() {
    let (mock, client) = setup().await;
    for (rtype, text) in [
        (RecordType::PTR, "host.example.org."),
        (RecordType::TLSA, "3 1 1 0a1b"),
        (RecordType::DNAME, "target.example.net."),
        (
            RecordType::SOA,
            "ns.example.net. admin.example.net. 1 7200 3600 1209600 300",
        ),
    ] {
        let set = rrset(REC, rtype, None, &[text]);
        let errors = [
            client
                .set_rrset(&zone(), &set, Expect::Any)
                .await
                .unwrap_err(),
            client
                .delete_rrset(&zone(), &dn(REC), rtype, Expect::Any)
                .await
                .unwrap_err(),
            client
                .get_rrset(&zone(), &dn(REC), rtype)
                .await
                .unwrap_err(),
        ];
        for e in errors {
            assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
        }
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
    assert_eq!(mock.control().tokens_issued(), 0);
}

/// A create, an update and a delete of the record are each sent once whatever happens: a 502,
/// a 429 and a 401 are the operation's error, and the repeat starts with a read.
#[tokio::test]
async fn cloud_ru_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let inject = |method: &str, path: &str, status: u16| {
        let fault = Fault::on(method, path);
        mock.faults().push(if status == 429 {
            fault.rate_limited("1")
        } else {
            fault.status(status)
        });
    };
    let expected = |status: u16| match status {
        429 => ErrorKind::RateLimited,
        _ => ErrorKind::Transient,
    };
    let count = |method: &str, path: &str| mock.log().count(Some(method), path);
    for status in [502, 429, 401] {
        // Create.
        let before = count("POST", RECORDS);
        inject("POST", RECORDS, status);
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), expected(status), "{status}: {e:?}");
        assert_eq!(count("POST", RECORDS), before + 1, "{status}");
        assert!(mock.control().records().is_empty());
        assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);

        // Update that appends.
        let before = count("PATCH", RECORD);
        inject("PATCH", RECORD, status);
        let e = add(&client, "BBB").await.unwrap_err();
        assert_eq!(e.kind(), expected(status), "{status}: {e:?}");
        assert_eq!(count("PATCH", RECORD), before + 1, "{status}");
        assert_eq!(values(&mock), ["AAA"]);
        assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);

        // Update that removes.
        let before = count("PATCH", RECORD);
        inject("PATCH", RECORD, status);
        let e = remove(&client, "BBB").await.unwrap_err();
        assert_eq!(e.kind(), expected(status), "{status}: {e:?}");
        assert_eq!(count("PATCH", RECORD), before + 1, "{status}");
        assert_eq!(values(&mock), ["AAA", "BBB"]);
        assert_eq!(
            remove(&client, "BBB").await.unwrap(),
            RemoveOutcome::Removed
        );

        // Delete.
        let before = count("DELETE", RECORD);
        inject("DELETE", RECORD, status);
        let e = remove(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), expected(status), "{status}: {e:?}");
        assert_eq!(count("DELETE", RECORD), before + 1, "{status}");
        assert_eq!(values(&mock), ["AAA"]);
        assert_eq!(
            remove(&client, "AAA").await.unwrap(),
            RemoveOutcome::RrsetDeleted
        );
    }

    // The delete is answered 502 and not applied; meanwhile another writer adds a value. A
    // repeat of the delete would remove it.
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("DELETE", RECORD)
            .run(move || hook.append_txt(NAME, "foreign"))
            .status(502),
    );
    let before = count("DELETE", RECORD);
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(count("DELETE", RECORD), before + 1);
    assert_eq!(values(&mock), ["AAA", "foreign"]);
    // The repeat reads the new state and removes only our value.
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(values(&mock), ["foreign"]);
}

/// A delete answered 404 is a success only when a new read finds no record: removed meanwhile
/// by someone else, the record is gone; with the zone recreated (and the record in it) the value
/// is still published, and the answer is a retryable `Conflict`.
#[tokio::test]
async fn cloud_ru_delete_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", RECORD).run(move || {
        hook.delete_record(NAME, "txt");
    }));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.records().is_empty());

    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", RECORD).run(move || {
        hook.recreate_zone(ZONE);
    }));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(values(&mock), ["AAA"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.records().is_empty());
}

/// The zone's listing shows every record at the name, so a CNAME next to other data, or other
/// data next to a CNAME, is refused after the read and before the second read and any write
/// (RFC 1034 section 3.6.2). Wildcard owners are told apart from the name below which they
/// apply, and data at other names does not count.
#[tokio::test]
async fn cloud_ru_cname_next_to_other_data_is_refused() {
    let (mock, client) = setup_records().await;
    let control = mock.control();
    control.insert_record(ZONE, "www.example.org", "a", 300, &["192.0.2.1"]);
    control.insert_record(
        ZONE,
        "alias.example.org",
        "cname",
        300,
        &["target.example.net"],
    );
    control.insert_record(ZONE, "*.w.example.org", "a", 300, &["192.0.2.1"]);
    control.insert_record(ZONE, "v.example.org", "a", 300, &["192.0.2.1"]);
    let before = control.records();

    let refused = [
        rrset(
            "www.example.org",
            RecordType::CNAME,
            None,
            &["target.example.net."],
        ),
        rrset("alias.example.org", RecordType::A, None, &["192.0.2.2"]),
        rrset("alias.example.org", RecordType::TXT, None, &["\"v\""]),
        rrset(
            "*.w.example.org",
            RecordType::CNAME,
            None,
            &["target.example.net."],
        ),
    ];
    for set in &refused {
        let listed = listings(&mock);
        let e = client
            .set_rrset(&zone(), set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{set:?}: {e:?}");
        // One read, no second read before a write, no write.
        assert_eq!(listings(&mock), listed + 1, "{set:?}");
    }
    assert_eq!(writes(&mock), 0);
    assert_eq!(control.records(), before);

    // At names without the other kind of data the same writes go through: the wildcard below
    // `v` is not `v`, and `w` is not the wildcard below it.
    for set in [
        rrset(
            "*.v.example.org",
            RecordType::CNAME,
            None,
            &["target.example.net."],
        ),
        rrset(
            "w.example.org",
            RecordType::CNAME,
            None,
            &["target.example.net."],
        ),
        rrset(
            "new.example.org",
            RecordType::CNAME,
            None,
            &["target.example.net."],
        ),
        rrset("www2.example.org", RecordType::A, None, &["192.0.2.2"]),
    ] {
        assert_eq!(
            client.set_rrset(&zone(), &set, Expect::Any).await.unwrap(),
            SetOutcome::Created,
            "{set:?}"
        );
    }
}

// ---- The re-read before the write (design section 3.5) -----------------------------------------

/// A foreign value appears between the read and the re-read of an add that appends: nothing is
/// written, the answer is a retryable `Conflict`, and the repeat keeps the foreign value. Same
/// for a removal that leaves other values.
#[tokio::test]
async fn cloud_ru_reread_before_update() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("GET", RECORDS)
            .skip(1)
            .run(move || hook.append_txt(NAME, "foreign")),
    );
    let patches = mock.log().count(Some("PATCH"), RECORD);
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("PATCH"), RECORD), patches);
    assert_eq!(values(&mock), ["AAA", "foreign"]);
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    assert_eq!(values(&mock), ["AAA", "foreign", "BBB"]);

    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("GET", RECORDS)
            .skip(1)
            .run(move || hook.append_txt(NAME, "foreign2")),
    );
    let patches = mock.log().count(Some("PATCH"), RECORD);
    let e = remove(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(mock.log().count(Some("PATCH"), RECORD), patches);
    assert_eq!(values(&mock), ["AAA", "foreign", "BBB", "foreign2"]);
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(values(&mock), ["AAA", "foreign", "foreign2"]);
}

/// A foreign value appears between the read and the re-read of a removal of our last value: the
/// record is not deleted, and the repeat removes only our value.
#[tokio::test]
async fn cloud_ru_reread_before_delete() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("GET", RECORDS)
            .skip(1)
            .run(move || hook.append_txt(NAME, "foreign")),
    );
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 0);
    assert_eq!(values(&mock), ["AAA", "foreign"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(values(&mock), ["foreign"]);
}

/// A record appears between the read and the re-read of an add that would create one: nothing
/// is created, and the repeat appends to the new record.
#[tokio::test]
async fn cloud_ru_reread_before_create() {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("GET", RECORDS)
            .skip(1)
            .run(move || hook.append_txt(NAME, "foreign")),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(mock.log().count(Some("POST"), RECORDS), 0);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    assert_eq!(values(&mock), ["foreign", "AAA"]);
}

/// A record created by someone else after both reads makes the create fail; the client reads
/// again, finds the record and answers a retryable `Conflict`. A refusal with no record there is
/// the refusal.
#[tokio::test]
async fn cloud_ru_create_conflict_is_conflict() {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("POST", RECORDS).run(move || hook.append_txt(NAME, "foreign")));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(values(&mock), ["foreign"]);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);

    let other = dn("_acme-challenge.www.example.org");
    mock.faults().push(Fault::on("POST", RECORDS).respond(
        400,
        r#"{"code":3,"message":"values are invalid","details":[]}"#,
    ));
    let e = client
        .add_txt_value(&zone(), &other, &txt("AAA"), None)
        .await
        .unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(400));
            assert_eq!(detail.as_str(), "values are invalid");
        }
        other => panic!("{other:?}"),
    }
}

// ---- Operations (design section 3.7) -----------------------------------------------------------

/// The operation is polled until it is done; an operation done in the write's answer is not
/// polled; one that finishes with an error is `Rejected` with the provider's message and nothing
/// changed; a poll that keeps failing is `Transient`, and the repeat converges.
#[tokio::test]
async fn cloud_ru_operations_are_polled() {
    let (mock, client) = setup().await;
    let polls = || mock.log().count(Some("GET"), OPERATIONS);
    mock.control().set_operation_polls(3);
    add(&client, "AAA").await.unwrap();
    assert_eq!(polls(), 3);
    mock.control().set_operation_polls(0);
    add(&client, "BBB").await.unwrap();
    assert_eq!(polls(), 3, "done at once");

    mock.control().set_operation_polls(1);
    mock.control().fail_next_operation("quota exceeded");
    let e = add(&client, "CCC").await.unwrap_err();
    match &e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(*status, None);
            assert_eq!(detail.as_str(), "quota exceeded");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(values(&mock), ["AAA", "BBB"]);

    mock.faults()
        .push(Fault::on("GET", OPERATIONS).times(3).status(500));
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    // The write was accepted; its outcome is unknown to the client. A repeat converges.
    assert_eq!(
        add(&client, "CCC").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
}

/// A write the provider accepted (2xx) whose operation cannot be read is `Transient`, not
/// `Protocol`: the write may have happened, and a repeat converges.
#[tokio::test]
async fn cloud_ru_unreadable_operation_is_transient() {
    let (mock, client) = setup().await;
    // Not an operation at all; the create is not applied by the fault.
    mock.faults()
        .push(Fault::on("POST", RECORDS).respond(200, "<html>accepted</html>"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    // An operation whose identifier cannot go into a URL.
    mock.faults()
        .push(Fault::on("POST", RECORDS).respond(200, r#"{"id":"../../v1/x","done":false}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

/// An operation `error` without a code: empty, it is `OK` (Proto3 JSON omits a zero); with a
/// message, it is a refusal rather than a success.
#[tokio::test]
async fn cloud_ru_operation_error_without_code() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", OPERATIONS).respond(
        200,
        r#"{"id":"00000000-0000-4000-8000-0000000000aa","done":true,"error":{}}"#,
    ));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    mock.faults().push(Fault::on("GET", OPERATIONS).respond(
        200,
        r#"{"id":"00000000-0000-4000-8000-0000000000aa","done":true,"error":{"message":"quota exceeded"}}"#,
    ));
    let e = add(&client, "BBB").await.unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, None);
            assert_eq!(detail.as_str(), "quota exceeded");
        }
        other => panic!("{other:?}"),
    }
}

/// An operation that never finishes keeps the add waiting through look after look, and the
/// write is sent once. That the looks are bounded, and that the add then ends with `Transient`,
/// is the unit test `an_operation_that_keeps_running_is_transient_after_the_last_look` in
/// `src/providers/cloud_ru/api.rs` with a lowered bound: the production bound of 60 looks at the 250 ms floor takes 15
/// seconds.
#[tokio::test]
async fn cloud_ru_unfinished_operation_keeps_being_polled() {
    let (mock, client) = setup().await;
    mock.control().set_operation_polls(u32::MAX);
    let polled = async {
        let deadline = Instant::now() + Duration::from_secs(10);
        while mock.log().count(Some("GET"), OPERATIONS) < 3 {
            assert!(Instant::now() < deadline, "the client stopped polling");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::select! {
        outcome = add(&client, "AAA") => {
            panic!("the add ended while its operation was running: {outcome:?}")
        }
        () = polled => {}
    }
    assert_eq!(writes(&mock), 1);
}

/// A delete whose operation finishes with `NOT_FOUND` is treated like a delete answered 404:
/// done once a new read finds no record.
#[tokio::test]
async fn cloud_ru_delete_operation_not_found_reads_again() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("DELETE", RECORD)
            .run(move || hook.delete_record(NAME, "txt"))
            .respond(
                200,
                r#"{"id":"00000000-0000-4000-8000-0000000000aa","done":true,"error":{"code":5,"message":"record not found"}}"#,
            ),
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
}

// ---- Listings ----------------------------------------------------------------------------------

/// A listing page without its list field is an empty page: the OpenAPI marks the field optional
/// and Proto3 JSON omits an empty repeated field. A list given as `null` or as another type is
/// `Protocol`, never "empty". Either way no record is created over one the client could not see:
/// an empty page read over an existing record leads to a refused create, a new read and
/// `Conflict`.
#[tokio::test]
async fn cloud_ru_missing_list_is_protocol() {
    let (mock, client) = setup().await;
    mock.control().append_txt(NAME, "foreign");
    for (path, body) in [
        // The zones first: after a successful lookup the zone identifier is cached.
        (ZONES, r#"{"zones":null}"#),
        (ZONES, r#"{"zones":{}}"#),
        (ZONES, r#"{"zones":[],"nextPageToken":7}"#),
        (RECORDS, r#"{"records":null}"#),
        (RECORDS, r#"{"records":"none"}"#),
    ] {
        mock.faults()
            .push(Fault::on("GET", path).respond(200, body));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{path} {body}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);

    // An omitted list is an empty page: no zone, or no record.
    let other = DomainName::parse("example.net").unwrap();
    mock.faults()
        .push(Fault::on("GET", ZONES).respond(200, r#"{"nextPageToken":""}"#));
    let e = client
        .add_txt_value(&other, &dn("x.example.net"), &txt("AAA"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    // The read and the re-read see an empty zone; the create meets the existing record and is
    // refused; the new read finds it.
    mock.faults()
        .push(Fault::on("GET", RECORDS).times(2).respond(200, "{}"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(values(&mock), ["foreign"]);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
}

/// A listing whose pages do not end is an error, never a shorter result: a page token that does
/// not advance.
#[tokio::test]
async fn cloud_ru_truncated_listing_is_protocol() {
    let (mock, client) = setup().await;
    mock.faults().push(
        Fault::on("GET", ZONES)
            .times(2)
            .respond(200, r#"{"zones":[],"nextPageToken":"pg-same"}"#),
    );
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().push(
        Fault::on("GET", RECORDS)
            .times(2)
            .respond(200, r#"{"records":[],"nextPageToken":"pg-same"}"#),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// A record listing that holds a record of another zone, or one without `publicZoneId`, did
/// not honor its filter: `Protocol`, nothing written.
#[tokio::test]
async fn cloud_ru_listing_of_another_zone_is_protocol() {
    let (mock, client) = setup().await;
    let zone_id = mock.control().zone_id(ZONE);
    for zone_field in [json!("00000000-0000-4000-8000-0000000000ee"), Value::Null] {
        let mut record = json!({
            "id": "00000000-0000-4000-8000-0000000000aa",
            "name": "_acme-challenge",
            "type": "txt",
            "values": ["AAA"],
            "ttl": "60"
        });
        if !zone_field.is_null() {
            record["publicZoneId"] = zone_field.clone();
        }
        let body = json!({"records": [record]}).to_string();
        mock.faults()
            .push(Fault::on("GET", RECORDS).respond(200, body.clone()));
        let e = remove(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{zone_field}: {e:?}");
        mock.faults()
            .push(Fault::on("GET", RECORDS).respond(200, body));
        let e = add(&client, "BBB").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{zone_field}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);
    // The same record in the right zone is read.
    let body = json!({"records": [{
        "id": "00000000-0000-4000-8000-0000000000aa",
        "publicZoneId": zone_id,
        "name": "_acme-challenge",
        "type": "txt",
        "values": ["AAA"],
        "ttl": "60"
    }]})
    .to_string();
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(200, body));
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
}

/// Every page of the record listing is read: the TXT record on the last page is found.
#[tokio::test]
async fn cloud_ru_listings_read_every_page() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_page_size_cap(2);
    for i in 0..5 {
        control.insert_record(
            ZONE,
            &format!("host{i}.example.org"),
            "a",
            300,
            &["192.0.2.1"],
        );
    }
    control.insert_record(ZONE, NAME, "txt", 60, &["AAA"]);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    // Six records, two per page; the add reads once (nothing is written, so no re-read).
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 3);
}

/// Two TXT records for one name contradict the documented model: `Protocol`, nothing written.
#[tokio::test]
async fn cloud_ru_several_txt_records_are_protocol() {
    let (mock, client) = setup().await;
    mock.control().insert_record(ZONE, NAME, "txt", 60, &["a"]);
    mock.control().insert_record(ZONE, NAME, "txt", 60, &["b"]);
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let e = remove(&client, "a").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// Owner names are recognized in the relative form, as `@` for the zone itself, and in the
/// absolute form with a trailing dot; the client sends the relative form and `@`. A name
/// without a trailing dot that also reads as an absolute name inside the zone cannot be placed:
/// when either reading is the requested name, the operation is `Protocol` and writes nothing,
/// so a published value is never reported absent and no create goes to an occupied name.
#[tokio::test]
async fn cloud_ru_owner_names() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record(ZONE, NAME, "txt", 60, &["AAA"]);
    control.insert_record(ZONE, ZONE, "txt", 60, &["apex"]);
    for style in [NameStyle::Relative, NameStyle::Absolute] {
        control.set_name_style(style);
        assert_eq!(
            add(&client, "AAA").await.unwrap(),
            AddOutcome::AlreadyPresent,
            "{style:?}"
        );
        assert_eq!(
            client
                .add_txt_value(&zone(), &zone(), &txt("apex"), None)
                .await
                .unwrap(),
            AddOutcome::AlreadyPresent,
            "{style:?}"
        );
    }

    // The API spells absolute names without the dot: `_acme-challenge.example.org`.
    control.set_name_style(NameStyle::AbsoluteNoDot);
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let e = client
        .add_txt_value(&zone(), &zone(), &txt("x"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(values(&mock), ["AAA"]);

    // A relative name that ends with the zone's text is ambiguous in the same way.
    control.set_name_style(NameStyle::Relative);
    let deep = "_acme-challenge.example.org.example.org";
    control.insert_record(ZONE, deep, "txt", 60, &["BBB"]);
    let e = client
        .remove_txt_value(&zone(), &dn(deep), &txt("BBB"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
    control.delete_record(deep, "txt");

    let other = dn("_acme-challenge.www.example.org");
    client
        .add_txt_value(&zone(), &other, &txt("CCC"), None)
        .await
        .unwrap();
    control.delete_record(ZONE, "txt");
    client
        .add_txt_value(&zone(), &zone(), &txt("DDD"), None)
        .await
        .unwrap();
    let names: Vec<Value> = mock
        .log()
        .matching(Some("POST"), RECORDS)
        .iter()
        .map(|r| r.body_json().unwrap()["name"].clone())
        .collect();
    assert_eq!(names, [json!("_acme-challenge.www"), json!("@")]);
}

/// A record with the wildcard flag stands for the names below its owner, never for the owner
/// itself; a wildcard owner name is refused before any request.
#[tokio::test]
async fn cloud_ru_wildcards() {
    let (mock, client) = setup().await;
    let wildcard = json!({"records": [{
        "id": "00000000-0000-4000-8000-0000000000aa",
        "publicZoneId": mock.control().zone_id(ZONE),
        "name": "_acme-challenge",
        "type": "txt",
        "values": ["AAA"],
        "ttl": "60",
        "wildcard": true
    }]})
    .to_string();
    // The read, then the re-read.
    mock.faults()
        .push(Fault::on("GET", RECORDS).times(2).respond(200, wildcard));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(values(&mock), ["AAA"]);

    mock.log().clear();
    let e = client
        .add_txt_value(&zone(), &dn("*.example.org"), &txt("AAA"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty());
}

// ---- TXT records -------------------------------------------------------------------------------

/// The first value creates the record: the relative name, lowercase type, the configured TTL,
/// the value unquoted. A requested TTL is used for a new record only; an existing record keeps
/// its TTL.
#[tokio::test]
async fn cloud_ru_add_creates_record() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    let post = mock.log().matching(Some("POST"), RECORDS).pop().unwrap();
    let zone_id = mock.control().zone_id(ZONE);
    assert_eq!(
        post.body_json().unwrap(),
        json!({
            "publicZoneId": zone_id,
            "name": "_acme-challenge",
            "type": "txt",
            "values": ["AAA"],
            "ttl": 60
        })
    );
    assert_eq!(post.header("content-type"), Some("application/json"));
    assert!(
        post.header("authorization")
            .is_some_and(|h| h.starts_with("Bearer eyJ-mock-"))
    );
    assert_eq!(mock.control().record(NAME, "txt").unwrap().ttl, 60);

    let other = dn("_acme-challenge.www.example.org");
    let ttl = zonewright::RrsetTtl::from_secs(300).unwrap();
    client
        .add_txt_value(&zone(), &other, &txt("AAA"), Some(ttl))
        .await
        .unwrap();
    assert_eq!(
        mock.control().record(other.as_str(), "txt").unwrap().ttl,
        300
    );
    client
        .add_txt_value(&zone(), &other, &txt("BBB"), Some(ttl))
        .await
        .unwrap();
    mock.control()
        .insert_record(ZONE, "x.example.org", "txt", 3600, &["foreign"]);
    client
        .add_txt_value(&zone(), &dn("x.example.org"), &txt("AAA"), Some(ttl))
        .await
        .unwrap();
    assert_eq!(
        mock.control().record("x.example.org", "txt").unwrap().ttl,
        3600
    );
}

/// The TXT dialect: a quoted value is read as its content, an unquoted one as it is, and text
/// the dialect cannot decode is a foreign value written back unchanged.
#[tokio::test]
async fn cloud_ru_txt_dialect() {
    let (mock, client) = setup().await;
    let undecodable = "\"a\" b \"";
    mock.control()
        .insert_record(ZONE, NAME, "txt", 60, &["\"AAA\"", "BBB", undecodable]);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        add(&client, "BBB").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(add(&client, "CCC").await.unwrap(), AddOutcome::Appended);
    assert_eq!(values(&mock), ["\"AAA\"", "BBB", undecodable, "CCC"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(values(&mock), ["BBB", undecodable, "CCC"]);
    // Only plain values are accepted, before any request.
    mock.log().clear();
    let e = client
        .add_txt_value(&zone(), &name(), &Txt::new("a b").unwrap(), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty());
}

/// A read-only record refuses every write with `Rejected` before any write request; a value it
/// already holds is reported present, and an absent value not present.
#[tokio::test]
async fn cloud_ru_read_only_record_is_rejected() {
    let (mock, client) = setup().await;
    mock.control()
        .insert_record(ZONE, NAME, "txt", 60, &["AAA", "BBB"]);
    mock.control().set_read_only(NAME, "txt", true);
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        remove(&client, "CCC").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    mock.control().delete_record(NAME, "txt");
    mock.control()
        .insert_record(ZONE, NAME, "txt", 60, &["AAA"]);
    mock.control().set_read_only(NAME, "txt", true);
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// A TXT record with GSLB links is not an rrset: an add or a remove at its name is `Rejected`
/// after the read, whatever the values hold, and nothing is written (design section 3.4).
#[tokio::test]
async fn cloud_ru_gslb_txt_record_is_rejected() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record(ZONE, NAME, "txt", 60, &["AAA"]);
    control.set_gslb(
        NAME,
        "txt",
        Some(json!({
            "links": [{"fqdn": "server1.example.org", "isEnabled": true}],
            "balancingPolicy": "BALANCING_POLICY_ROUND_ROBIN"
        })),
    );
    let before = control.record(NAME, "txt").unwrap();
    for value in ["AAA", "BBB"] {
        let e = add(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{value}: {e:?}");
        let e = remove(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{value}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);
    assert_eq!(control.record(NAME, "txt").unwrap(), before);
    // GSLB data without links leaves the record an rrset.
    control.set_gslb(NAME, "txt", Some(json!({"links": []})));
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
}

#[tokio::test]
async fn cloud_ru_other_types_at_the_name_are_untouched() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record(ZONE, NAME, "a", 300, &["192.0.2.1"]);
    let before = control.record(NAME, "a").unwrap();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(control.record(NAME, "a").unwrap(), before);
    assert!(control.record(NAME, "txt").is_none());
}

// ---- Zones -------------------------------------------------------------------------------------

/// A zone the project does not have: `ZoneNotFound` for every operation, nothing written;
/// `check` reports it as not found.
#[tokio::test]
async fn cloud_ru_zone_not_found() {
    let (mock, client) = setup().await;
    let (other_zone, other_name) = (dn("example.net"), dn("x.example.net"));
    let e = client
        .add_txt_value(&other_zone, &other_name, &txt("A"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let e = client
        .remove_txt_value(&other_zone, &other_name, &txt("A"))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let report = client.check(&[zone(), other_zone]).await.unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones[0].found && !report.zones[1].found);
    assert_eq!(writes(&mock), 0);
}

/// Two zones of the project with one name: the client cannot tell which holds the records, so
/// every operation on the name is `Protocol`; `list_zones` lists the name but does not cache an
/// identifier for it.
#[tokio::test]
async fn cloud_ru_several_zones_with_one_name_are_protocol() {
    let (mock, client) = setup().await;
    mock.control().insert_zone(ZONE, PROJECT);
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let zones = client.list_zones().await.unwrap();
    assert_eq!(zones.len(), 1);
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// A read-only zone is reported as not usable by `check`, refused for writes, and left out of
/// `list_zones`.
#[tokio::test]
async fn cloud_ru_read_only_zone() {
    let (mock, client) = setup().await;
    mock.control().set_zone_read_only(ZONE, true);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    assert!(report.zones[0].detail.is_some());
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(client.list_zones().await.unwrap().is_empty());
    assert_eq!(writes(&mock), 0);
}

/// Every call of `check` exchanges the access key again, even with a valid token cached, and
/// reads the records of each zone it finds.
#[tokio::test]
async fn cloud_ru_check_exercises_the_credentials() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.control().tokens_issued(), 1);
    let report = client.check(&[]).await.unwrap();
    assert!(report.credentials_verified);
    assert_eq!(mock.control().tokens_issued(), 2);
    let reads = mock.log().count(Some("GET"), RECORDS);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert_eq!(mock.control().tokens_issued(), 3);
    assert_eq!(mock.log().count(Some("GET"), RECORDS), reads + 1);
}

/// A project the key cannot use is an error, never an empty result.
#[tokio::test]
async fn cloud_ru_foreign_project_is_forbidden() {
    let mock = CloudRuMock::start(Seed::standard()).await;
    let mut config = settings(&mock);
    config.project_id = "6f0d2b1e-0000-4000-8000-0000000000ff".into();
    let client = CloudRu::new(config, credentials(SECRET), &context()).unwrap();
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
}

/// The public zones of the project, every page, sorted; read-only and foreign ones left out.
#[tokio::test]
async fn cloud_ru_list_zones() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_page_size_cap(1);
    control.insert_zone("b.example.net", PROJECT);
    control.insert_zone("a.example.net", PROJECT);
    control.insert_zone("ro.example.net", PROJECT);
    control.set_zone_read_only("ro.example.net", true);
    let zones: Vec<String> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name.as_str().to_owned())
        .collect();
    assert_eq!(zones, ["a.example.net.", "b.example.net.", "example.org."]);
    assert_eq!(mock.log().count(Some("GET"), ZONES), 4);
    // The identifiers were cached: an add needs no zone lookup.
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONES), 4);
}

// ---- Tokens ------------------------------------------------------------------------------------

/// The token request carries the key ID and the secret as JSON, and no authorization header.
#[tokio::test]
async fn cloud_ru_token_request_shape() {
    let (mock, client) = setup().await;
    client.check(&[]).await.unwrap();
    let request = mock.log().matching(Some("POST"), TOKENS).pop().unwrap();
    assert_eq!(
        request.body_json().unwrap(),
        json!({"keyId": KEY_ID, "secret": SECRET})
    );
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(request.header("authorization"), None);
}

#[tokio::test]
async fn cloud_ru_token_is_cached() {
    let (mock, client) = setup().await;
    for i in 0..5 {
        add(&client, &format!("V{i}")).await.unwrap();
    }
    assert_eq!(mock.control().tokens_issued(), 1);
}

/// Concurrent operations of one client share one token request.
#[tokio::test]
async fn cloud_ru_token_single_flight() {
    let (mock, client) = setup().await;
    let client = Arc::new(client);
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..10 {
        let client = client.clone();
        tasks.spawn(async move {
            let name = dn(&format!("d{i}.example.org"));
            client
                .add_txt_value(&zone(), &name, &txt("AAA"), None)
                .await
                .unwrap();
        });
    }
    while let Some(done) = tasks.join_next().await {
        done.unwrap();
    }
    assert_eq!(mock.control().tokens_issued(), 1);
}

/// A revoked token is answered 401; the client obtains a new one and repeats the read.
#[tokio::test]
async fn cloud_ru_rejected_token_is_renewed() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    mock.control().revoke_tokens();
    remove(&client, "AAA").await.unwrap();
    assert_eq!(mock.control().tokens_issued(), 2);
}

/// A 401 for a freshly obtained token is `Auth`.
#[tokio::test]
async fn cloud_ru_repeated_401_is_auth() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RECORDS).times(5).status(401));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// A secret the token service refuses is `Auth` for every operation, and no DNS request is made
/// without a token; the error does not quote the secret.
#[tokio::test]
async fn cloud_ru_wrong_secret_is_auth() {
    let mock = CloudRuMock::start(Seed::standard()).await;
    let client = client_with(&mock, "wrong-canary-5", &context());
    let results = [
        client.check(&[zone()]).await.map(|_| ()),
        client.list_zones().await.map(|_| ()),
        add(&client, "A").await.map(|_| ()),
        remove(&client, "A").await.map(|_| ()),
    ];
    for result in results {
        let e = result.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
        assert!(!format!("{e} {e:?} {client:?}").contains("wrong-canary-5"));
    }
    assert_eq!(mock.log().count(None, "/v1/**"), 0);
    // A 400 from the token service is an authentication error too.
    mock.faults()
        .push(Fault::on("POST", TOKENS).respond(400, r#"{"code":3,"message":"bad key"}"#));
    let good = client_with(&mock, SECRET, &context());
    let e = good.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
}

// ---- Transport ---------------------------------------------------------------------------------

/// A short `Retry-After` on a read is waited out; a long one is `RateLimited` with the wait.
#[tokio::test]
async fn cloud_ru_rate_limit() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RECORDS).rate_limited("1"));
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("GET", RECORDS).rate_limited("120"));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
}

/// A 5xx on a read is retried; three in a row are `Transient`, which is retryable.
#[tokio::test]
async fn cloud_ru_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RECORDS).status(500));
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("GET", RECORDS).times(3).status(503));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(writes(&mock), 1);
}

/// Error answers are `Rejected` with the status and the `rpcStatus` message.
#[tokio::test]
async fn cloud_ru_refusals_are_rejected() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RECORDS).respond(
        400,
        r#"{"code":3,"message":"invalid page token","details":[]}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(400));
            assert_eq!(detail.as_str(), "invalid page token");
        }
        other => panic!("{other:?}"),
    }
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn cloud_ru_from_json_builds_the_client() {
    let mock = CloudRuMock::start(Seed::standard()).await;
    let settings = json!({
        "project_id": PROJECT,
        "key_id": KEY_ID,
        "operation_poll_ms": 250,
        "dns_url": mock.dns_url(),
        "iam_url": mock.iam_url(),
    })
    .to_string();
    let client = AnyProvider::from_json(
        ProviderId::CloudRu,
        &settings,
        &SecretString::from(format!("{{\"secret\": \"{SECRET}\", \"other\": 1}}")),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::CloudRu);
    assert!(client.check(&[zone()]).await.unwrap().zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn cloud_ru_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || {
        json!({
            "project_id": PROJECT,
            "key_id": KEY_ID,
            "dns_url": "http://127.0.0.1:1",
            "iam_url": "http://127.0.0.1:1/api/v1/auth/token",
        })
    };
    let with = |key: &str, value: Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let without = |key: &str| {
        let mut settings = base();
        settings.as_object_mut().unwrap().remove(key);
        settings
    };
    let secret = json!({"secret": "s"}).to_string();
    let cases = [
        (without("project_id"), secret.clone(), "project_id"),
        (without("key_id"), secret.clone(), "key_id"),
        (with(canary, json!(canary)), secret.clone(), "unknown keys"),
        (with("project_id", json!("")), secret.clone(), "project_id"),
        (
            with("project_id", json!(format!("{canary}\n"))),
            secret.clone(),
            "project_id",
        ),
        (
            with("key_id", json!(format!("{canary}\u{7}"))),
            secret.clone(),
            "key_id",
        ),
        (with("ttl", json!(30)), secret.clone(), "ttl"),
        (with("ttl", json!(86_401)), secret.clone(), "ttl"),
        (
            with("operation_poll_ms", json!(10)),
            secret.clone(),
            "operation_poll_ms",
        ),
        (
            with(
                "dns_url",
                json!(format!("https://u:{canary}@dns.example.org")),
            ),
            secret.clone(),
            "dns_url",
        ),
        (
            with(
                "iam_url",
                json!(format!("https://iam.example.org/?{canary}")),
            ),
            secret.clone(),
            "iam_url",
        ),
        (
            base(),
            json!({"secret": 5, canary: canary}).to_string(),
            "secret",
        ),
        (base(), json!({"password": canary}).to_string(), "secret"),
        (base(), json!({"secret": ""}).to_string(), "secret"),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::CloudRu,
            &settings.to_string(),
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{key}: {e:?}");
        let text = format!("{e} | {e:?}");
        assert!(text.contains(key), "{key}: {text}");
        assert!(!text.contains(canary), "{key}: {text}");
    }
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round; the defaults agree.
#[test]
fn cloud_ru_config_keys_match_metadata() {
    let meta = ProviderId::CloudRu.meta();
    let config = CloudRuConfig::new("p".into(), "k".into());
    let settings = serde_json::to_value(&config).unwrap();
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
    assert_eq!(secret, ["secret"]);
    let mut required: Vec<&str> = meta
        .fields
        .iter()
        .filter(|f| f.required)
        .map(|f| f.key)
        .collect();
    required.sort_unstable();
    assert_eq!(required, ["key_id", "project_id", "secret"]);
    for field in meta.fields.iter().filter(|f| f.default.is_some()) {
        let value = &settings[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
    }
    // The client's `Debug` shows the settings but not the key ID.
    let mock_free = CloudRu::new(
        {
            let mut c = CloudRuConfig::new("p".into(), "key-id-canary-77".into());
            c.dns_url = "http://127.0.0.1:1".into();
            c.iam_url = "http://127.0.0.1:1/token".into();
            c
        },
        credentials("s"),
        &context(),
    )
    .unwrap();
    let debug = format!("{mock_free:?}");
    assert!(
        debug.contains("project_id") && !debug.contains("key-id-canary-77"),
        "{debug}"
    );
}

// ---- Record level ------------------------------------------------------------------------------

/// Every type in the record-level list goes through set, get and list with canonical equality,
/// at an ordinary name, the apex, an internationalized name and wildcard names; is written in
/// the form of the provider's record types page (names without the final dot, TXT and SPF as
/// the text itself, a long TXT value as one string); is `Unchanged` on a repeat without a write;
/// and is deleted under an exact expectation.
#[tokio::test]
async fn cloud_ru_record_round_trips() {
    let (mock, client) = setup_records().await;
    let long = "k".repeat(300);
    let idn = dn("пример.example.org");
    let idn_name = idn.as_str().to_owned();
    let cases: Vec<(&str, RecordType, Vec<RecordData>, Vec<&str>)> = vec![
        (
            REC,
            RecordType::A,
            vec![
                rd(RecordType::A, "192.0.2.1"),
                rd(RecordType::A, "192.0.2.2"),
            ],
            vec!["192.0.2.1", "192.0.2.2"],
        ),
        (
            REC,
            RecordType::AAAA,
            vec![
                rd(RecordType::AAAA, "2001:db8::1"),
                rd(RecordType::AAAA, "2001:db8::2:1"),
            ],
            vec!["2001:db8::1", "2001:db8::2:1"],
        ),
        (
            REC,
            RecordType::CAA,
            vec![
                rd(RecordType::CAA, "0 issue \"ca.example.net\""),
                rd(RecordType::CAA, "128 iodef \"mailto:ops@example.org\""),
            ],
            vec![
                "0 issue \"ca.example.net\"",
                "128 iodef \"mailto:ops@example.org\"",
            ],
        ),
        (
            "cname.example.org",
            RecordType::CNAME,
            vec![rd(RecordType::CNAME, "target.example.net.")],
            vec!["target.example.net"],
        ),
        (
            REC,
            RecordType::MX,
            vec![
                rd(RecordType::MX, "10 mail.example.org."),
                rd(RecordType::MX, "20 mx2.example.net."),
            ],
            vec!["10 mail.example.org", "20 mx2.example.net"],
        ),
        (
            "nomail.example.org",
            RecordType::MX,
            vec![rd(RecordType::MX, "0 .")],
            vec!["0 ."],
        ),
        (
            "sub.example.org",
            RecordType::NS,
            vec![
                rd(RecordType::NS, "ns1.example.net."),
                rd(RecordType::NS, "ns2.example.net."),
            ],
            vec!["ns1.example.net", "ns2.example.net"],
        ),
        (
            REC,
            SPF,
            vec![spf_data("v=spf1 ip4:192.0.2.0/24 -all")],
            vec!["v=spf1 ip4:192.0.2.0/24 -all"],
        ),
        (
            "_sip._tcp.example.org",
            RecordType::SRV,
            vec![
                rd(RecordType::SRV, "10 20 5060 sip.example.org."),
                rd(RecordType::SRV, "0 5 5061 sip2.example.org."),
            ],
            vec!["0 5 5061 sip2.example.org", "10 20 5060 sip.example.org"],
        ),
        (
            REC,
            RecordType::TXT,
            vec![txt_data("v=spf1 mx -all"), txt_data(&long)],
            vec![long.as_str(), "v=spf1 mx -all"],
        ),
        (
            ZONE,
            RecordType::A,
            vec![rd(RecordType::A, "192.0.2.10")],
            vec!["192.0.2.10"],
        ),
        (
            ZONE,
            RecordType::MX,
            vec![rd(RecordType::MX, "10 mail.example.org.")],
            vec!["10 mail.example.org"],
        ),
        (
            ZONE,
            RecordType::TXT,
            vec![txt_data("apex-value")],
            vec!["apex-value"],
        ),
        (
            &idn_name,
            RecordType::A,
            vec![rd(RecordType::A, "192.0.2.20")],
            vec!["192.0.2.20"],
        ),
        (
            "*.wild.example.org",
            RecordType::A,
            vec![rd(RecordType::A, "192.0.2.50")],
            vec!["192.0.2.50"],
        ),
        (
            "*.example.org",
            RecordType::TXT,
            vec![txt_data("wild-apex")],
            vec!["wild-apex"],
        ),
    ];
    let api = |rtype: RecordType| {
        if rtype == SPF {
            "spf".to_owned()
        } else {
            rtype.to_string().to_lowercase()
        }
    };
    for (name, rtype, data, texts) in &cases {
        let wanted = rrset_of(name, *rtype, Some(300), data.clone());
        assert_eq!(
            client
                .set_rrset(&zone(), &wanted, Expect::Absent)
                .await
                .unwrap(),
            SetOutcome::Created,
            "{name} {rtype}"
        );
        let record = mock.control().record(name, &api(*rtype)).unwrap();
        assert_eq!(record.ttl, 300, "{name} {rtype}");
        assert_eq!(stored(&mock, name, &api(*rtype)), *texts, "{name} {rtype}");
        let read = client
            .get_rrset(&zone(), &dn(name), *rtype)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, wanted, "{name} {rtype}");
        assert!(read.records().iter().all(RecordData::is_canonical));
        let before = writes(&mock);
        assert_eq!(
            client
                .set_rrset(&zone(), &wanted, Expect::Matches(&read))
                .await
                .unwrap(),
            SetOutcome::Unchanged,
            "{name} {rtype}"
        );
        assert_eq!(
            writes(&mock),
            before,
            "{name} {rtype}: an unchanged set wrote"
        );
    }
    // The owner names as sent: relative, `@` for the zone, the wildcard as a flag.
    let posts: Vec<(Value, Value)> = mock
        .log()
        .matching(Some("POST"), RECORDS)
        .iter()
        .map(|r| {
            let body = r.body_json().unwrap();
            (body["name"].clone(), body["wildcard"].clone())
        })
        .collect();
    for expected in [
        (json!("rec"), Value::Null),
        (json!("@"), Value::Null),
        (json!("xn--e1afmkfd"), Value::Null),
        (json!("wild"), json!(true)),
        (json!("@"), json!(true)),
    ] {
        assert!(posts.contains(&expected), "{expected:?} not in {posts:?}");
    }

    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.skipped.is_empty(), "{:?}", listing.skipped);
    for (name, rtype, data, _) in &cases {
        let wanted = rrset_of(name, *rtype, Some(300), data.clone());
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
            "{name} {rtype}"
        );
        assert!(mock.control().record(name, &api(*rtype)).is_none());
    }
    assert!(mock.control().records().is_empty());
}

/// Values the API returns in another valid spelling read as canonical data and compare equal
/// to the canonical form; writing the same set back is `Unchanged` and leaves the provider's
/// text alone.
#[tokio::test]
async fn cloud_ru_reads_provider_spellings() {
    let (mock, client) = setup_records().await;
    let control = mock.control();
    for (rtype, provider, canonical) in [
        (
            "aaaa",
            "2001:0DB8:0000::0001",
            rd(RecordType::AAAA, "2001:db8::1"),
        ),
        (
            "mx",
            "10 MAIL.Example.org.",
            rd(RecordType::MX, "10 mail.example.org."),
        ),
        (
            "cname",
            "target.example.net.",
            rd(RecordType::CNAME, "target.example.net."),
        ),
        ("txt", "\"quoted words\"", txt_data("quoted words")),
        (
            "caa",
            "0 ISSUE \"ca.example.net\"",
            rd(RecordType::CAA, "0 issue \"ca.example.net\""),
        ),
        (
            "srv",
            "1 2 3 Target.example.org.",
            rd(RecordType::SRV, "1 2 3 target.example.org."),
        ),
    ] {
        let name = format!("{rtype}.example.org");
        control.insert_record(ZONE, &name, rtype, 600, &[provider]);
        let rtype: RecordType = rtype.parse().unwrap();
        let read = client
            .get_rrset(&zone(), &dn(&name), rtype)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            read,
            rrset_of(&name, rtype, Some(600), vec![canonical.clone()]),
            "{rtype}"
        );
        let before = writes(&mock);
        assert_eq!(
            client
                .set_rrset(
                    &zone(),
                    &rrset_of(&name, rtype, None, vec![canonical]),
                    Expect::Any
                )
                .await
                .unwrap(),
            SetOutcome::Unchanged
        );
        assert_eq!(writes(&mock), before);
        assert_eq!(
            stored(&mock, &name, &rtype.to_string().to_lowercase()),
            [provider]
        );
    }
}

#[tokio::test]
async fn cloud_ru_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup_records().await;
    let control = mock.control();
    control.insert_record(ZONE, REC, "a", 600, &["192.0.2.1"]);
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
    assert_eq!(writes(&mock), 0);
    assert_eq!(stored(&mock, REC, "a"), ["192.0.2.1"]);

    // The expectation holds: with the TTL, and without one.
    let current = rrset(REC, RecordType::A, Some(600), &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&current))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, REC, "a"), ["192.0.2.9"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &missing, Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
}

/// `Expect::Any` replaces the values; the TTL is kept unless one is requested; the description,
/// the tags and GSLB data without links travel back; a new record gets the configured TTL and
/// only the documented fields.
#[tokio::test]
async fn cloud_ru_set_replaces_and_keeps_what_the_model_does_not_carry() {
    let (mock, client) = setup_records().await;
    let control = mock.control();
    control.insert_record(ZONE, REC, "a", 600, &["192.0.2.1", "192.0.2.2"]);
    control.set_attributes(REC, "a", Some("set by hand"), &["team-a"]);
    let gslb = json!({"links": [], "balancingPolicy": "BALANCING_POLICY_ROUND_ROBIN"});
    control.set_gslb(REC, "a", Some(gslb.clone()));
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.2", "192.0.2.9"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let record = control.record(REC, "a").unwrap();
    assert_eq!(record.ttl, 600, "the TTL is kept");
    assert_eq!(record.values, ["192.0.2.2", "192.0.2.9"]);
    assert_eq!(record.description.as_deref(), Some("set by hand"));
    assert_eq!(record.tags, ["team-a"]);
    assert_eq!(record.gslb, Some(gslb.clone()));
    let patch = mock.log().matching(Some("PATCH"), RECORD).pop().unwrap();
    assert_eq!(
        patch.body_json().unwrap(),
        json!({
            "values": ["192.0.2.2", "192.0.2.9"],
            "ttl": 600,
            "description": "set by hand",
            "tags": ["team-a"],
            "gslbData": gslb
        })
    );

    // A requested TTL is applied.
    let retuned = rrset(REC, RecordType::A, Some(120), &["192.0.2.2", "192.0.2.9"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &retuned, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(control.record(REC, "a").unwrap().ttl, 120);
    assert_eq!(
        control.record(REC, "a").unwrap().description.as_deref(),
        Some("set by hand")
    );

    // A new record without a TTL gets the configured one.
    let fresh = rrset("fresh.example.org", RecordType::A, None, &["192.0.2.1"]);
    client
        .set_rrset(&zone(), &fresh, Expect::Any)
        .await
        .unwrap();
    let post = mock.log().matching(Some("POST"), RECORDS).pop().unwrap();
    assert_eq!(
        post.body_json().unwrap(),
        json!({
            "publicZoneId": control.zone_id(ZONE),
            "name": "fresh",
            "type": "a",
            "values": ["192.0.2.1"],
            "ttl": 60
        })
    );
}

/// `delete_rrset` with each expectation: `Matches` deletes, a missing rrset is `NotPresent`
/// without a write, `Absent` is refused before any request.
#[tokio::test]
async fn cloud_ru_delete_rrset_expectations() {
    let (mock, client) = setup_records().await;
    let a = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    client.set_rrset(&zone(), &a, Expect::Absent).await.unwrap();
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Matches(&a))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(mock.control().record(REC, "a").is_none());
    let before = writes(&mock);
    for expect in [Expect::Any, Expect::Any] {
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(REC), RecordType::A, expect)
                .await
                .unwrap(),
            DeleteOutcome::NotPresent
        );
    }
    assert_eq!(writes(&mock), before);
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

    mock.control()
        .insert_record(ZONE, REC, "a", 600, &["192.0.2.1", "192.0.2.2"]);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(mock.control().record(REC, "a").is_none());
}

/// SOA is not offered and the apex NS set belongs to the provider: writes are refused before
/// any request. A wildcard NS record is refused before any write. A read-only record reads like
/// any other and refuses every write after the read, without a second read or a write.
#[tokio::test]
async fn cloud_ru_protected_sets_send_nothing() {
    let (mock, client) = setup_records().await;
    let control = mock.control();
    let soa = rrset(
        ZONE,
        RecordType::SOA,
        None,
        &["ns.example.net. admin.example.net. 1 7200 3600 1209600 300"],
    );
    let apex_ns = rrset(ZONE, RecordType::NS, None, &["ns.example.com."]);
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

    // The apex NS set is read.
    control.insert_record(
        ZONE,
        ZONE,
        "ns",
        3600,
        &["ns1.example.net", "ns2.example.net"],
    );
    control.set_read_only(ZONE, "ns", true);
    assert_eq!(
        client
            .get_rrset(&zone(), &zone(), RecordType::NS)
            .await
            .unwrap(),
        Some(rrset(
            ZONE,
            RecordType::NS,
            Some(3600),
            &["ns1.example.net.", "ns2.example.net."]
        ))
    );

    // A wildcard NS record: refused after the read, nothing written.
    let wild_ns = rrset(
        "*.sub.example.org",
        RecordType::NS,
        None,
        &["ns.example.com."],
    );
    let e = client
        .set_rrset(&zone(), &wild_ns, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), 0);

    // A read-only record.
    control.insert_record(ZONE, REC, "a", 600, &["192.0.2.1"]);
    control.set_read_only(REC, "a", true);
    let current = rrset(REC, RecordType::A, Some(600), &["192.0.2.1"]);
    assert_eq!(
        client
            .get_rrset(&zone(), &dn(REC), RecordType::A)
            .await
            .unwrap(),
        Some(current.clone())
    );
    let reads = listings(&mock);
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.9"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Matches(&current))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(listings(&mock), reads + 2, "one read per operation");
    assert_eq!(writes(&mock), 0);
    // What it already holds is `Unchanged`.
    assert_eq!(
        client
            .set_rrset(&zone(), &current, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
}

/// The TTL range of the provider's limitations page, inclusive, is checked before any request.
#[tokio::test]
async fn cloud_ru_record_ttl_bounds() {
    let (mock, client) = setup_records().await;
    for ttl in [59, 86_401] {
        let set = rrset(REC, RecordType::A, Some(ttl), &["192.0.2.1"]);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{ttl}: {e:?}");
    }
    assert!(mock.log().is_empty());
    for ttl in [60, 86_400] {
        let set = rrset(REC, RecordType::A, Some(ttl), &["192.0.2.1"]);
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
        assert_eq!(mock.control().record(REC, "a").unwrap().ttl, u64::from(ttl));
    }
}

/// A value whose form the sources do not establish is not sent; one the record already holds is
/// written back exactly as the API returned it. Non-canonical data can be written back, never
/// introduced.
#[tokio::test]
async fn cloud_ru_unsendable_values_and_non_canonical_data() {
    let (mock, client) = setup_records().await;
    let control = mock.control();
    for set in [
        rrset_of(REC, RecordType::TXT, None, vec![txt_data("say \"hi\"")]),
        rrset_of(REC, RecordType::TXT, None, vec![txt_data("back\\slash")]),
        rrset_of(REC, RecordType::TXT, None, vec![txt_data("caf\u{e9}")]),
        rrset_of(REC, RecordType::TXT, None, vec![txt_data(" leading")]),
        rrset_of(
            REC,
            RecordType::TXT,
            None,
            vec![txt_data(&"k".repeat(65_001))],
        ),
        rrset_of(REC, SPF, None, vec![spf_data("v=spf1 \"x\" -all")]),
        rrset(REC, RecordType::CAA, None, &["1 issue \"ca.example.net\""]),
        rrset(REC, RecordType::CAA, None, &["0 tbs \"x\""]),
        rrset(REC, RecordType::SRV, None, &["0 0 0 ."]),
        rrset("c.example.org", RecordType::CNAME, None, &["."]),
    ] {
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{set:?}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);

    // Held by the provider: kept verbatim while a sendable value joins it.
    let held = "say \"hi\"";
    control.insert_record(ZONE, REC, "txt", 600, &[held]);
    let both = rrset_of(
        REC,
        RecordType::TXT,
        None,
        vec![txt_data(held), txt_data("plain words")],
    );
    assert_eq!(
        client.set_rrset(&zone(), &both, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        control.record(REC, "txt").unwrap().values,
        [held, "plain words"]
    );

    // Provider text the dialect cannot decode: non-canonical data, written back unchanged.
    let odd = "\"a\" b \"";
    control.insert_record(ZONE, "odd.example.org", "txt", 600, &[odd]);
    let listed = client
        .get_rrset(&zone(), &dn("odd.example.org"), RecordType::TXT)
        .await
        .unwrap()
        .unwrap();
    assert!(!listed.records()[0].is_canonical());
    assert_eq!(listed.records()[0].as_str(), odd);
    let mut members = listed.records().to_vec();
    members.push(txt_data("added"));
    let extended = RrSet::new(dn("odd.example.org"), RecordType::TXT, None, members).unwrap();
    assert_eq!(
        client
            .set_rrset(&zone(), &extended, Expect::Matches(&listed))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        control.record("odd.example.org", "txt").unwrap().values,
        [odd, "added"]
    );
    // The only public way to build non-canonical data is to deserialize a stored set.
    let introduced: RrSet = serde_json::from_value(json!({
        "name": "new.example.org.",
        "type": "A",
        "ttl": null,
        "records": [{"raw": "not an address"}]
    }))
    .unwrap();
    let before = writes(&mock);
    let e = client
        .set_rrset(&zone(), &introduced, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), before);
}

/// The listing holds every record of every type, also outside the record-level list (SOA) and
/// the apex NS set, with wildcard records under their `*` name; values the parser refuses are
/// non-canonical data; what the model cannot hold (a type name the crate does not know, a record
/// with GSLB links, an owner name that cannot be placed, two values of a singleton type) is in
/// `skipped`; a record without values is absent.
#[tokio::test(flavor = "current_thread")]
async fn cloud_ru_listing_reports_skipped_sets() {
    let (capture, _guard) = LogCapture::install();
    let (mock, client) = setup_records().await;
    let control = mock.control();
    let soa_text = "evo-cns01.cloud.ru., admin.cloud.ru, 2026070606, 3600, 3600, 3600, 3600";
    control.insert_record(ZONE, ZONE, "soa", 3600, &[soa_text]);
    control.insert_record(ZONE, ZONE, "ns", 3600, &["ns1.example.net"]);
    control.insert_record(ZONE, REC, "a", 600, &["192.0.2.1"]);
    control.insert_record(ZONE, REC, "txt", 600, &["v=spf1 -all"]);
    control.insert_record(ZONE, REC, "spf", 600, &["v=spf1 -all"]);
    control.insert_record(ZONE, "*.wild.example.org", "a", 600, &["192.0.2.9"]);
    control.insert_record(ZONE, "odd.example.org", "a", 600, &["not-an-address"]);
    control.insert_record(ZONE, "g.example.org", "gslb", 600, &["server1.example.org"]);
    control.insert_record(ZONE, "lb.example.org", "a", 600, &[]);
    control.set_gslb(
        "lb.example.org",
        "a",
        Some(json!({
            "links": [{"fqdn": "server1.example.org", "priority": "10", "isEnabled": true}],
            "balancingPolicy": "BALANCING_POLICY_ROUND_ROBIN"
        })),
    );
    // Listed as `x.example.org`: relative, or absolute without the dot.
    control.insert_record(ZONE, "x.example.org.example.org", "txt", 600, &["v"]);
    let long_label = format!("{}.example.org", "x".repeat(64));
    control.insert_record(ZONE, &long_label, "a", 600, &["192.0.2.1"]);
    control.insert_record(
        ZONE,
        "c.example.org",
        "cname",
        600,
        &["a.example.net", "b.example.net"],
    );
    control.insert_record(ZONE, "empty.example.org", "a", 600, &[]);

    let listing = client.list_rrsets(&zone()).await.unwrap();
    let sets: Vec<(String, RecordType)> = listing
        .rrsets
        .iter()
        .map(|s| (s.name().to_string(), s.rtype()))
        .collect();
    assert_eq!(
        sets,
        [
            ("*.wild.example.org.".to_owned(), RecordType::A),
            ("example.org.".to_owned(), RecordType::NS),
            ("example.org.".to_owned(), RecordType::SOA),
            ("odd.example.org.".to_owned(), RecordType::A),
            ("rec.example.org.".to_owned(), RecordType::A),
            ("rec.example.org.".to_owned(), RecordType::TXT),
            ("rec.example.org.".to_owned(), SPF),
        ]
    );
    assert_eq!(
        listing.rrsets[0],
        rrset(
            "*.wild.example.org",
            RecordType::A,
            Some(600),
            &["192.0.2.9"]
        )
    );
    assert!(!listing.rrsets[2].records()[0].is_canonical(), "SOA");
    assert!(!listing.rrsets[3].records()[0].is_canonical());
    assert_eq!(listing.rrsets[3].records()[0].as_str(), "not-an-address");
    assert_eq!(listing.rrsets[5].records(), [txt_data("v=spf1 -all")]);
    assert_eq!(listing.rrsets[6].records(), [spf_data("v=spf1 -all")]);
    let mut skipped: Vec<(String, String, SkipReason)> = listing
        .skipped
        .iter()
        .map(|s| (s.name.to_string(), s.type_name.clone(), s.reason))
        .collect();
    skipped.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(
        skipped,
        [
            (
                "c.example.org.".to_owned(),
                "cname".to_owned(),
                SkipReason::NotPlainRecords
            ),
            (
                "example.org.".to_owned(),
                "a".to_owned(),
                SkipReason::UnsupportedName
            ),
            (
                "example.org.".to_owned(),
                "txt".to_owned(),
                SkipReason::UnsupportedName
            ),
            (
                "g.example.org.".to_owned(),
                "gslb".to_owned(),
                SkipReason::UnknownType
            ),
            (
                "lb.example.org.".to_owned(),
                "a".to_owned(),
                SkipReason::NotPlainRecords
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
    assert_eq!(warnings[0].field("skipped"), Some("5"));
    assert_eq!(warnings[0].field("provider"), Some("cloud_ru"));
    assert_eq!(listings(&mock), 1);
}

/// A record whose name cannot be placed (the API spelling absolute names without the dot) fails
/// a read, a set and a delete at the requested name with `Protocol` and writes nothing, while
/// the listing reports it in `skipped` and does not fail.
#[tokio::test]
async fn cloud_ru_ambiguous_names_at_record_level() {
    let (mock, client) = setup_records().await;
    let control = mock.control();
    control.insert_record(ZONE, REC, "a", 600, &["192.0.2.1"]);
    control.set_name_style(NameStyle::AbsoluteNoDot);
    let e = client
        .get_rrset(&zone(), &dn(REC), RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.2"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.rrsets.is_empty());
    assert_eq!(listing.skipped.len(), 1);
    assert_eq!(listing.skipped[0].reason, SkipReason::UnsupportedName);
    assert_eq!(stored(&mock, REC, "a"), ["192.0.2.1"]);
}

/// The listing reads every page; a listing whose pages do not end is an error, never a shorter
/// result, and a write after such a read sends nothing.
#[tokio::test]
async fn cloud_ru_record_listing_is_complete_or_fails() {
    let (mock, client) = setup_records().await;
    let control = mock.control();
    control.set_page_size_cap(2);
    for i in 0..5 {
        control.insert_record(ZONE, &format!("h{i}.example.org"), "a", 60, &["192.0.2.1"]);
    }
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(listing.rrsets.len(), 5);
    assert_eq!(listings(&mock), 3);

    let page = r#"{"records":[],"nextPageToken":"pg-same"}"#;
    for _ in 0..2 {
        mock.faults()
            .push(Fault::on("GET", RECORDS).times(2).respond(200, page));
    }
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.9"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// Records at other names (a longer name, a name below, the wildcard below the name) and other
/// types at the same name are never touched by a set or a delete.
#[tokio::test]
async fn cloud_ru_record_operations_leave_other_sets_alone() {
    let (mock, client) = setup_records().await;
    let control = mock.control();
    let others = [
        ("xrec.example.org", "a", "198.51.100.1"),
        ("a.rec.example.org", "a", "198.51.100.1"),
        ("*.rec.example.org", "a", "198.51.100.1"),
        (REC, "txt", "foreign"),
        (REC, "mx", "10 mail.example.org"),
    ];
    for (name, rtype, value) in others {
        control.insert_record(ZONE, name, rtype, 900, &[value]);
    }
    let before: Vec<_> = others
        .iter()
        .map(|(name, rtype, _)| control.record(name, rtype).unwrap())
        .collect();
    let a = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    client.set_rrset(&zone(), &a, Expect::Absent).await.unwrap();
    let b = rrset(REC, RecordType::A, Some(120), &["192.0.2.2"]);
    client.set_rrset(&zone(), &b, Expect::Any).await.unwrap();
    client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap();
    for ((name, rtype, _), before) in others.iter().zip(before) {
        assert_eq!(
            control.record(name, rtype).unwrap(),
            before,
            "{name} {rtype}"
        );
    }
    assert!(control.record(REC, "a").is_none());
}

/// Two clients sharing a `Context` create the same rrset at once, the first write delayed: the
/// second reads after the first wrote and its `Absent` fails.
#[tokio::test]
async fn cloud_ru_concurrent_sets_are_serialized() {
    let mock = CloudRuMock::start(Seed::standard()).await;
    mock.control().set_operation_polls(0);
    let ctx = context();
    let a = client_with(&mock, SECRET, &ctx);
    let b = client_with(&mock, SECRET, &ctx);
    mock.faults()
        .push(Fault::on("POST", RECORDS).delay(Duration::from_millis(300)));
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
    assert_eq!(mock.log().count(Some("POST"), RECORDS), 1);
    // A delete and a set at once: whichever runs second sees the first one's result.
    let (deleted, set) = tokio::join!(
        a.delete_rrset(&zone, &rec, RecordType::A, Expect::Any),
        b.set_rrset(&zone, &second, Expect::Any),
    );
    deleted.unwrap();
    set.unwrap();
    let left = stored(&mock, REC, "a");
    assert!(left.is_empty() || left == ["192.0.2.2"], "{left:?}");
}

/// A record-level create, update and delete are each sent once whatever happens: a 502, a 429
/// and a 401 are the operation's error, nothing changes, and the repeat starts with a read.
#[tokio::test]
async fn cloud_ru_record_writes_are_sent_once() {
    let (mock, client) = setup_records().await;
    let inject = |method: &str, path: &str, status: u16| {
        let fault = Fault::on(method, path);
        mock.faults().push(if status == 429 {
            fault.rate_limited("1")
        } else {
            fault.status(status)
        });
    };
    let expected = |status: u16| match status {
        429 => ErrorKind::RateLimited,
        _ => ErrorKind::Transient,
    };
    let count = |method: &str, path: &str| mock.log().count(Some(method), path);
    let one = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    let two = rrset(REC, RecordType::A, None, &["192.0.2.1", "192.0.2.2"]);
    for status in [502, 429, 401] {
        let before = count("POST", RECORDS);
        inject("POST", RECORDS, status);
        let e = client
            .set_rrset(&zone(), &one, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected(status), "{status}: {e:?}");
        assert_eq!(count("POST", RECORDS), before + 1, "{status}");
        assert!(mock.control().records().is_empty());
        assert_eq!(
            client.set_rrset(&zone(), &one, Expect::Any).await.unwrap(),
            SetOutcome::Created
        );

        let before = count("PATCH", RECORD);
        inject("PATCH", RECORD, status);
        let e = client
            .set_rrset(&zone(), &two, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected(status), "{status}: {e:?}");
        assert_eq!(count("PATCH", RECORD), before + 1, "{status}");
        assert_eq!(stored(&mock, REC, "a"), ["192.0.2.1"]);
        assert_eq!(
            client.set_rrset(&zone(), &two, Expect::Any).await.unwrap(),
            SetOutcome::Replaced
        );

        let before = count("DELETE", RECORD);
        inject("DELETE", RECORD, status);
        let e = client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected(status), "{status}: {e:?}");
        assert_eq!(count("DELETE", RECORD), before + 1, "{status}");
        assert_eq!(stored(&mock, REC, "a"), ["192.0.2.1", "192.0.2.2"]);
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
                .await
                .unwrap(),
            DeleteOutcome::Deleted
        );
    }
}

/// The record read again immediately before the write: a change made between the two reads is
/// a retryable `Conflict` and nothing is written, for a create, an update and a delete; the
/// repeat reads the new state.
#[tokio::test]
async fn cloud_ru_record_reread_before_write() {
    let (mock, client) = setup_records().await;
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.2"]);

    // Create: the record appears.
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("GET", RECORDS).skip(1).run(move || {
            hook.insert_record(ZONE, REC, "a", 600, &["198.51.100.1"]);
        }));
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(writes(&mock), 0);
    assert_eq!(stored(&mock, REC, "a"), ["198.51.100.1"]);

    // Update: another writer changes the values.
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("GET", RECORDS).skip(1).run(move || {
            hook.set_values(REC, "a", &["198.51.100.1", "198.51.100.2"]);
        }));
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(stored(&mock, REC, "a"), ["198.51.100.1", "198.51.100.2"]);

    // Delete: another writer changes the values.
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("GET", RECORDS).skip(1).run(move || {
            hook.set_values(REC, "a", &["198.51.100.3"]);
        }));
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(stored(&mock, REC, "a"), ["198.51.100.3"]);

    // The repeat converges.
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, REC, "a"), ["192.0.2.2"]);
}

/// A create refused because the record appeared after both reads is a retryable `Conflict`, and
/// nothing is overwritten (the mock's 409 is invented; the client decides by a new read).
#[tokio::test]
async fn cloud_ru_record_create_race_is_conflict() {
    let (mock, client) = setup_records().await;
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("POST", RECORDS).pass().run(move || {
            hook.insert_record(ZONE, REC, "a", 900, &["198.51.100.1"]);
        }));
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.1"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(stored(&mock, REC, "a"), ["198.51.100.1"]);
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.1"]),
            Expect::Absent,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
}

/// A record with GSLB links is not an rrset: read, set and delete at its name and type are
/// `Rejected` after the read, and nothing is written.
#[tokio::test]
async fn cloud_ru_gslb_records_are_not_changed() {
    let (mock, client) = setup_records().await;
    let control = mock.control();
    control.insert_record(ZONE, REC, "a", 600, &[]);
    let gslb = json!({
        "links": [{"fqdn": "server1.example.org", "isEnabled": true}],
        "balancingPolicy": "BALANCING_POLICY_ROUND_ROBIN"
    });
    control.set_gslb(REC, "a", Some(gslb));
    let e = client
        .get_rrset(&zone(), &dn(REC), RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.1"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(writes(&mock), 0);
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
/// removes exactly the values it added afterwards, also when the body failed. Then a record-level
/// round trip (A and TXT rrsets) at another generated label, deleted afterwards whatever
/// happened. Prints what the API answers to a create of a record that exists, and the listing's
/// spelling of the records it created, which the documentation does not say.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_cloud_ru_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_CLOUD_RU_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_CLOUD_RU_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_CLOUD_RU_ZONE"));
    let build = |ctx: &Context| {
        AnyProvider::from_json(
            ProviderId::CloudRu,
            &settings,
            &SecretString::from(credentials.clone()),
            ctx,
        )
        .unwrap()
    };
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(build(&ctx));
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
    let mut outcome = body.await;

    // Record level, at a generated name nobody else uses.
    let rr_name = zone.prepend(&format!("_zw-live-{tag:016x}-rr")).unwrap();
    if outcome.is_ok() {
        let rr_body = tokio::spawn({
            let (client, zone, rr_name) = (client.clone(), zone.clone(), rr_name.clone());
            async move {
                let ttl = Some(RrsetTtl::from_secs(300).unwrap());
                let one = RrSet::new(
                    rr_name.clone(),
                    RecordType::A,
                    ttl,
                    [RecordData::parse(RecordType::A, "192.0.2.1").unwrap()],
                )
                .unwrap();
                let two = RrSet::new(
                    rr_name.clone(),
                    RecordType::A,
                    ttl,
                    ["192.0.2.1", "192.0.2.2"]
                        .map(|a| RecordData::parse(RecordType::A, a).unwrap()),
                )
                .unwrap();
                let text = RrSet::new(
                    rr_name.clone(),
                    RecordType::TXT,
                    ttl,
                    [Txt::new("zw live record").unwrap().to_data().unwrap()],
                )
                .unwrap();
                assert_eq!(
                    client.set_rrset(&zone, &one, Expect::Absent).await.unwrap(),
                    SetOutcome::Created
                );
                assert_eq!(
                    client
                        .get_rrset(&zone, &rr_name, RecordType::A)
                        .await
                        .unwrap(),
                    Some(one.clone())
                );
                assert_eq!(
                    client
                        .set_rrset(&zone, &two, Expect::Matches(&one))
                        .await
                        .unwrap(),
                    SetOutcome::Replaced
                );
                assert_eq!(
                    client.set_rrset(&zone, &two, Expect::Any).await.unwrap(),
                    SetOutcome::Unchanged
                );
                assert_eq!(
                    client
                        .set_rrset(&zone, &text, Expect::Absent)
                        .await
                        .unwrap(),
                    SetOutcome::Created
                );
                let listing = client.list_rrsets(&zone).await.unwrap();
                eprintln!(
                    "listing: {} rrsets, skipped {:?}",
                    listing.rrsets.len(),
                    listing.skipped
                );
                assert!(listing.rrsets.contains(&two), "{:?}", listing.rrsets);
                assert!(listing.rrsets.contains(&text), "{:?}", listing.rrsets);
                assert_eq!(
                    client
                        .delete_rrset(&zone, &rr_name, RecordType::A, Expect::Matches(&two))
                        .await
                        .unwrap(),
                    DeleteOutcome::Deleted
                );
                assert_eq!(
                    client
                        .delete_rrset(&zone, &rr_name, RecordType::TXT, Expect::Matches(&text))
                        .await
                        .unwrap(),
                    DeleteOutcome::Deleted
                );
            }
        });
        outcome = rr_body.await;
    }

    // Probe: two clients on separate contexts (so the name lock does not serialize them) add to
    // a fresh name at once; the second create meets the first one's record. Neither value may be
    // lost, and a refusal must be `Conflict`.
    let probe = zone.prepend(&format!("_zw-live-{tag:016x}-probe")).unwrap();
    let probe_values = [
        txt(&format!("zw-live-{tag:016x}-p")),
        txt(&format!("zw-live-{tag:016x}-q")),
    ];
    if outcome.is_ok() {
        let other_ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
        let second = build(&other_ctx);
        let (a, b) = tokio::join!(
            client.add_txt_value(&zone, &probe, &probe_values[0], None),
            second.add_txt_value(&zone, &probe, &probe_values[1], None),
        );
        eprintln!("duplicate-create probe: {a:?} / {b:?}");
        let probe_body = tokio::spawn({
            let (client, zone, probe, probe_values) = (
                client.clone(),
                zone.clone(),
                probe.clone(),
                probe_values.clone(),
            );
            async move {
                for result in [&a, &b] {
                    if let Err(e) = result {
                        assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
                    }
                }
                for value in &probe_values {
                    client
                        .add_txt_value(&zone, &probe, value, None)
                        .await
                        .unwrap();
                }
            }
        });
        outcome = probe_body.await;
    }

    // Cleanup: exactly the values this test added, with the value operations.
    let mut cleanup = Vec::new();
    for value in &values {
        if let Err(e) = client.remove_txt_value(&zone, &name, value).await {
            cleanup.push(format!("{e}"));
        }
    }
    for value in &probe_values {
        if let Err(e) = client.remove_txt_value(&zone, &probe, value).await {
            cleanup.push(format!("{e}"));
        }
    }
    // The record-level name is this test's own: whatever is left there was created by it.
    for rtype in [RecordType::A, RecordType::TXT] {
        if let Err(e) = client
            .delete_rrset(&zone, &rr_name, rtype, Expect::Any)
            .await
        {
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

/// A record-level round trip on its own: creates, reads, replaces, lists and deletes an A rrset
/// and a TXT rrset at a generated name in the zone the maintainer names, and deletes exactly
/// those two rrsets afterwards, also when the body failed. The name is new, so nothing else lives
/// there.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_cloud_ru_record_round_trip() {
    let settings = live_env("ZONEWRIGHT_LIVE_CLOUD_RU_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_CLOUD_RU_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_CLOUD_RU_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::CloudRu,
            &settings,
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap(),
    );
    let tag = random_u64();
    let name = zone
        .prepend(&format!("_zw-live-{tag:016x}-records"))
        .unwrap();
    let set = |rtype: RecordType, ttl: Option<u32>, data: Vec<RecordData>| {
        RrSet::new(
            name.clone(),
            rtype,
            ttl.map(|t| RrsetTtl::from_secs(t).unwrap()),
            data,
        )
        .unwrap()
    };
    let a1 = set(
        RecordType::A,
        Some(300),
        vec![
            rd(RecordType::A, "192.0.2.1"),
            rd(RecordType::A, "192.0.2.2"),
        ],
    );
    // No TTL: the replacement keeps the TTL as read.
    let a2 = set(
        RecordType::A,
        None,
        vec![
            rd(RecordType::A, "192.0.2.2"),
            rd(RecordType::A, "192.0.2.3"),
        ],
    );
    let text = set(
        RecordType::TXT,
        Some(120),
        vec![
            txt(&format!("zw-live-{tag:016x}-record"))
                .to_data()
                .unwrap(),
        ],
    );

    let body = {
        let (client, zone, name) = (client.clone(), zone.clone(), name.clone());
        let (a1, a2, text) = (a1.clone(), a2.clone(), text.clone());
        tokio::spawn(async move {
            assert_eq!(
                client.set_rrset(&zone, &a1, Expect::Absent).await.unwrap(),
                SetOutcome::Created
            );
            let read = client
                .get_rrset(&zone, &name, RecordType::A)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(read, a1);
            assert_eq!(
                client.set_rrset(&zone, &a1, Expect::Any).await.unwrap(),
                SetOutcome::Unchanged
            );
            assert_eq!(
                client
                    .set_rrset(&zone, &a2, Expect::Matches(&read))
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            let read = client
                .get_rrset(&zone, &name, RecordType::A)
                .await
                .unwrap()
                .unwrap();
            assert!(read.same_records(&a2));
            assert_eq!(read.ttl(), a1.ttl());
            assert_eq!(
                client
                    .set_rrset(&zone, &text, Expect::Absent)
                    .await
                    .unwrap(),
                SetOutcome::Created
            );
            let listing = client.list_rrsets(&zone).await.unwrap();
            assert!(listing.rrsets.contains(&read), "{:?}", listing.rrsets);
            assert!(listing.rrsets.contains(&text), "{:?}", listing.rrsets);
            assert_eq!(
                client
                    .delete_rrset(&zone, &name, RecordType::A, Expect::Matches(&read))
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
            assert_eq!(
                client.get_rrset(&zone, &name, RecordType::A).await.unwrap(),
                None
            );
            assert_eq!(
                client
                    .delete_rrset(&zone, &name, RecordType::TXT, Expect::Matches(&text))
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
        })
    };
    let outcome = body.await;

    // Cleanup: the two rrsets of the generated name, which only this test wrote to.
    let mut cleanup = Vec::new();
    for rtype in [RecordType::A, RecordType::TXT] {
        if let Err(e) = client.delete_rrset(&zone, &name, rtype, Expect::Any).await {
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
