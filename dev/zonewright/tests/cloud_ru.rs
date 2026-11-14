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
use std::time::Duration;

use secrecy::SecretString;
use serde_json::{Value, json};
use zonewright::providers::cloud_ru::{CloudRu, CloudRuConfig, CloudRuCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RemoveOutcome, RrSet, Txt,
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
/// operation reach the echo.
#[tokio::test]
async fn cloud_ru_secret_echo() {
    let secrets = [CANARY_PASSWORD, CANARY_KEY, DEFAULT_ISSUED_TOKEN];
    for dialect in dialects() {
        for status in [400, 401] {
            let label = format!("{} {:?} {status} api", dialect.name, dialect.spelling);
            let echo = dialect.echo(status).start().await;
            let client = echo_client(&echo, &echo.token_url());
            echo_round(&label, &client, Write::Create, &secrets).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
            assert!(echo.token_requests() > 0, "{label}: no token was issued");

            let label = format!("{} {:?} {status} iam", dialect.name, dialect.spelling);
            let echo = dialect
                .echo(status)
                .token_path("/no-token-endpoint")
                .start()
                .await;
            let client = echo_client(&echo, &echo.url(TOKENS));
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
                    let echo = dialect
                        .echo(status)
                        .render_under("/v1", reads_then(dialect.render.clone(), write, poll))
                        .start()
                        .await;
                    let client = echo_client(&echo, &echo.token_url());
                    echo_round(&label, &client, write, &secrets).await;
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
            }
        }
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

fn echo_client(echo: &EchoServer, iam_url: &str) -> CloudRu {
    let mut config = CloudRuConfig::new(PROJECT.into(), CANARY_KEY.into());
    config.dns_url = echo.base_url();
    config.iam_url = iam_url.to_owned();
    config.operation_poll_ms = 250;
    CloudRu::new(config, credentials(CANARY_PASSWORD), &context()).unwrap()
}

async fn echo_round(label: &str, client: &CloudRu, write: Write, secrets: &[&str]) {
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
    let result = if write == Write::Delete {
        remove(client, "v1").await.map(|o| format!("{o:?}"))
    } else {
        add(client, "v1").await.map(|o| format!("{o:?}"))
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

/// The record-level operations are not offered: `Unsupported`, and nothing is sent.
#[tokio::test]
async fn cloud_ru_unsupported_operations_send_nothing() {
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

/// An operation still running after the last of the 60 polls is `Transient`.
#[tokio::test]
async fn cloud_ru_unfinished_operation_is_transient() {
    let (mock, client) = setup().await;
    mock.control().set_operation_polls(1000);
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), OPERATIONS), 60);
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
    let ttl = zonewright::Ttl::from_secs(300).unwrap();
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
/// removes exactly the values it added afterwards, also when the body failed. Prints what the
/// API answers to a create of a record that exists, which the documentation does not say.
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
            let report = client.check(std::slice::from_ref(&zone)).await.unwrap();
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
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}
