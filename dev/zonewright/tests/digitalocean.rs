//! Tests of the DigitalOcean client (`digitalocean`) against its mock.
#![cfg(feature = "digitalocean")]
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
use zonewright::providers::digitalocean::{
    DigitalOcean, DigitalOceanConfig, DigitalOceanCredentials,
};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RemoveOutcome, RrSet, Ttl, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::digitalocean::{DigitalOceanMock, NameForm, Seed};
use zonewright_mock::echo::{EchoServer, Echoed, Render};

use common::echo::{CANARY_KEY, CANARY_TOKEN, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The token of the standard seed.
const TOKEN: &str = "test-only-token";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const ACCOUNT: &str = "/v2/account";
const DOMAINS: &str = "/v2/domains";
const DOMAIN: &str = "/v2/domains/*";
const RECORDS: &str = "/v2/domains/*/records";
const RECORD: &str = "/v2/domains/*/records/*";

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
fn settings(base_url: String) -> DigitalOceanConfig {
    let mut config = DigitalOceanConfig::default();
    config.base_url = base_url;
    config
}

fn credentials(token: &str) -> DigitalOceanCredentials {
    DigitalOceanCredentials::new(SecretString::from(token.to_owned()))
}

fn client_with(mock: &DigitalOceanMock, token: &str, ctx: &Context) -> DigitalOcean {
    DigitalOcean::new(settings(mock.base_url()), credentials(token), ctx).unwrap()
}

async fn setup() -> (DigitalOceanMock, DigitalOcean) {
    let mock = DigitalOceanMock::start(Seed::standard()).await;
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
fn writes(mock: &DigitalOceanMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), RECORDS) + log.count(Some("DELETE"), RECORD)
}

/// The settings JSON of `from_json` for `mock`.
fn settings_json(mock: &DigitalOceanMock) -> String {
    serde_json::json!({ "base_url": mock.base_url() }).to_string()
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

assert_not_impl!(DigitalOcean: std::fmt::Display, serde::Serialize);
assert_not_impl!(DigitalOceanCredentials: std::fmt::Display, serde::Serialize);

/// What the echo's listings answer: the account, no record, a record with a foreign value, or a
/// record with the value `v1`.
#[derive(Clone, Copy)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
}

/// A renderer that answers the listings like the API and every other request with `errors`.
fn listings_then(errors: Render, existing: Existing) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method != Method::GET {
            return errors(e);
        }
        let records = match existing {
            Existing::Nothing => serde_json::json!([]),
            Existing::Foreign => serde_json::json!([{
                "id": 1001, "type": "TXT", "name": "_acme-challenge", "data": "foreign", "ttl": 30
            }]),
            Existing::Ours => serde_json::json!([{
                "id": 1001, "type": "TXT", "name": "_acme-challenge", "data": "v1", "ttl": 30
            }]),
        };
        let count = records.as_array().map_or(0, Vec::len);
        let body = serde_json::json!({
            "domain_records": records, "links": {}, "meta": {"total": count}
        });
        (StatusCode::OK, axum::Json(body)).into_response()
    })
}

/// A renderer that answers the account like the API and every other request with `errors`.
fn account_then(errors: Render) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method == Method::GET && e.path.ends_with("/account") {
            let body = serde_json::json!({"account": {"status": "active"}});
            return (StatusCode::OK, axum::Json(body)).into_response();
        }
        errors(e)
    })
}

fn echo_client(echo: &EchoServer) -> DigitalOcean {
    let config = settings(echo.url("/v2"));
    DigitalOcean::new(config, credentials(CANARY_TOKEN), &context()).unwrap()
}

/// `check` and a write against an echo that quotes every request back: no canary in any error,
/// `ZoneCheck::detail` or `Debug`, and the write's error shows the redaction.
async fn echo_round(label: &str, client: &DigitalOcean, write: Write) {
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

#[derive(Clone, Copy, Debug)]
enum Write {
    Add,
    Remove,
}

/// `check` and the writes against an echo, for every dialect. Four kinds of request reach it:
/// the account read, the domain read, the create and the delete.
#[tokio::test]
async fn digitalocean_secret_echo() {
    for dialect in dialects() {
        // The account read is the echo.
        for status in [400, 401] {
            let label = format!("{} {:?} {status} account", dialect.name, dialect.spelling);
            let echo = dialect.echo(status).start().await;
            let client = echo_client(&echo);
            echo_round(&label, &client, Write::Add).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
        }
        // The account read is answered; the domain read is the echo.
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} domain", dialect.name, dialect.spelling);
            let echo = dialect
                .echo(status)
                .render_under("/v2/account", account_then(dialect.render.clone()))
                .start()
                .await;
            let client = echo_client(&echo);
            let e = client.check(&[zone()]).await.unwrap_err();
            let text = format!("{e} | {e:?} | {client:?}");
            assert_clean(&label, &text, &[CANARY_TOKEN]);
            assert!(
                echo.log().count(Some("GET"), DOMAIN) > 0,
                "{label}: the domain read did not reach the echo"
            );
        }
        // The account and the listings answer normally, so the write itself reaches the echo:
        // a create (with and without a foreign record at the name) and a delete. The account
        // read must not get the echo's status: a 500 to that idempotent read is retried with
        // real back-off sleeps and adds seconds per dialect, without coverage (its echo is
        // covered by the first loop, the 5xx body by the create's 500).
        for (existing, write, statuses) in [
            (
                Existing::Nothing,
                Write::Add,
                [400, 401, 403, 422, 500].as_slice(),
            ),
            (
                Existing::Foreign,
                Write::Add,
                [400, 401, 403, 422, 500].as_slice(),
            ),
            (
                Existing::Ours,
                Write::Remove,
                [400, 401, 403, 422].as_slice(),
            ),
        ] {
            for &status in statuses {
                let label = format!("{} {:?} {status} {write:?}", dialect.name, dialect.spelling);
                let echo = dialect
                    .echo(status)
                    .render_under("/v2/account", account_then(dialect.render.clone()))
                    .render_under(
                        "/v2/domains",
                        listings_then(dialect.render.clone(), existing),
                    )
                    .start()
                    .await;
                let client = echo_client(&echo);
                echo_round(&label, &client, write).await;
                let (method, path) = match write {
                    Write::Add => ("POST", RECORDS),
                    Write::Remove => ("DELETE", RECORD),
                };
                assert!(
                    echo.log().count(Some(method), path) >= 1,
                    "{label}: the write did not reach the echo"
                );
            }
        }
    }
}

/// A `TRACE` capture over a success, repeated 401s, a 500 and a wrong token: the transport's
/// events are there, and no canary is.
#[tokio::test(flavor = "current_thread")]
async fn digitalocean_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.token = CANARY_TOKEN.into();
    let mock = DigitalOceanMock::start(seed).await;
    let client = client_with(&mock, CANARY_TOKEN, &context());
    let mut texts = Vec::new();

    add(&client, "v1").await.unwrap();
    remove(&client, "v1").await.unwrap();

    mock.faults()
        .push(Fault::on("GET", RECORDS).always().status(401));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("POST", RECORDS).status(500));
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
        assert_clean(
            "digitalocean logs and errors",
            text,
            &[CANARY_TOKEN, CANARY_KEY],
        );
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely ends
/// with the zone's text, the zone's text inside another name, and a sibling zone.
#[tokio::test]
async fn digitalocean_name_outside_zone_sends_nothing() {
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
async fn digitalocean_invalid_input_sends_nothing() {
    let (mock, client) = setup().await;
    for value in ["two words", "quo\"te", "back\\slash"] {
        let e = add(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
        let e = remove(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
    }
    for ttl in [10, 29, 86_401] {
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
async fn digitalocean_add_is_idempotent() {
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
/// leaves the foreign records and their TTLs as they were. A single foreign value is never a
/// reason to delete anything.
#[tokio::test]
async fn digitalocean_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "foreign-1", 600);
    control.insert_record("example.org", NAME, "TXT", "foreign-2", 900);
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
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.records(), original);
    // Only the record with our value was named by a request.
    let deletes = mock.log().matching(Some("DELETE"), RECORD);
    assert_eq!(deletes.len(), 1);

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_record("example.org", other, "TXT", "foreign", 60);
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
async fn digitalocean_other_types_at_the_name_are_untouched() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "A", "192.0.2.1", 300);
    control.insert_record("example.org", NAME, "CNAME", "AAA", 300);
    control.insert_record("example.org", "other.example.org", "TXT", "AAA", 300);
    let original = control.records();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(control.records(), original);

    // The listing is filtered by type on the provider's side; a client that did not check the
    // type itself would take this answer's A record for our value.
    mock.faults().push(Fault::on("GET", RECORDS).respond(
        200,
        r#"{"domain_records":[{"id":1,"type":"A","name":"_acme-challenge","data":"AAA","ttl":30}],"links":{},"meta":{"total":1}}"#,
    ));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

#[tokio::test]
async fn digitalocean_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().records().is_empty());
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 1);
}

#[tokio::test]
async fn digitalocean_remove_is_idempotent() {
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
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert!(mock.control().records().is_empty());
}

/// Every record with the value is removed (a duplicate made by a writer outside the process),
/// and nothing else.
#[tokio::test]
async fn digitalocean_remove_deletes_every_copy_of_the_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "AAA", 30);
    control.insert_record("example.org", NAME, "TXT", "foreign", 30);
    control.insert_record("example.org", NAME, "TXT", "AAA", 30);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt_values(NAME), ["foreign"]);
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 2);
}

/// Two clients sharing a `Context` add to one name at once, the first write delayed: the second
/// waits for the lock and sees the first one's record. Without the name lock both would read "no
/// record" and both report `Created`.
#[tokio::test]
async fn digitalocean_concurrent_adds_are_serialized() {
    let mock = DigitalOceanMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, TOKEN, &ctx);
    let b = client_with(&mock, TOKEN, &ctx);
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
    let mut values = mock.control().txt_values(NAME);
    values.sort();
    assert_eq!(values, ["AAA", "BBB"]);
}

/// A foreign value added between the read and the write is not lost: the create names only our
/// value.
#[tokio::test]
async fn digitalocean_foreign_value_added_between_read_and_write_survives() {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    mock.faults().push(Fault::on("POST", RECORDS).run(move || {
        hook.insert_record("example.org", NAME, "TXT", "foreign", 600);
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
    assert_eq!(mock.control().records()[0].ttl, 600);
}

/// The domain is deleted and created again between the read and the delete: the delete is
/// answered 404, and the removal never reports success for a value that is still published. A
/// record that is gone for another reason is a success.
#[tokio::test]
async fn digitalocean_delete_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "AAA").await.unwrap();
    let id = control.records()[0].id;
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", RECORD).run(move || {
        hook.delete_record(id);
    }));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.records().is_empty());

    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", RECORD).run(move || {
        hook.recreate_domain("example.org");
    }));
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

/// The record-level operations are not offered: `Unsupported`, and nothing is sent.
#[tokio::test]
async fn digitalocean_unsupported_operations_send_nothing() {
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

/// Retry behavior: a create is sent once whatever happens (a 502, a 429 and a 401 are the
/// operation's error, and the repeat starts with a read); a repeated create could add a second
/// copy of the value.
#[tokio::test]
async fn digitalocean_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let posts = || mock.log().count(Some("POST"), RECORDS);

    mock.faults().push(Fault::on("POST", RECORDS).status(502));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(posts(), 1);
    assert!(mock.control().records().is_empty());

    mock.faults()
        .push(Fault::on("POST", RECORDS).rate_limited("1"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(posts(), 2);

    mock.faults().push(Fault::on("POST", RECORDS).status(401));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(posts(), 3);
    assert!(mock.control().records().is_empty());

    // The create is answered 502 but was applied: the repeat finds the value instead of
    // adding a second copy.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("POST", RECORDS)
            .run(move || {
                hook.insert_record("example.org", NAME, "TXT", "AAA", 30);
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
    mock.faults().push(Fault::on("POST", RECORDS).respond(
        422,
        r#"{"id":"unprocessable_entity","message":"ttl is too low","request_id":"r"}"#,
    ));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(posts(), 5);
}

/// The delete of one record by its identifier is the one write that is repeated: a 502 is
/// retried, and a retry that finds the record gone is a success. A rate limit with a long wait
/// and a rejected token are not repeated.
#[tokio::test]
async fn digitalocean_delete_by_id_is_retried() {
    let (mock, client) = setup().await;
    let deletes = || mock.log().count(Some("DELETE"), RECORD);
    add(&client, "AAA").await.unwrap();
    mock.faults().push(Fault::on("DELETE", RECORD).status(502));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(deletes(), 2);
    assert!(mock.control().records().is_empty());

    // The first delete is applied and its answer lost; the retry is answered 404, and the
    // new read finds the value gone.
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    let id = mock.control().records()[0].id;
    mock.faults().push(
        Fault::on("DELETE", RECORD)
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
        .push(Fault::on("DELETE", RECORD).rate_limited("120"));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
    assert_eq!(deletes(), 5);
    mock.faults().push(Fault::on("DELETE", RECORD).status(401));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(deletes(), 6);
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);
}

// ---- Requests, names and TTLs ------------------------------------------------------------------

/// The requests as the documentation and lego describe them: the token in `Authorization`, the
/// listing's filters, the create's four fields with the absolute name, the delete by identifier.
#[tokio::test]
async fn digitalocean_request_shapes() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let log = mock.log();
    let list = log.matching(Some("GET"), RECORDS).pop().unwrap();
    assert_eq!(list.path, "/v2/domains/example.org/records");
    assert_eq!(
        list.query.as_deref(),
        Some("type=TXT&name=_acme-challenge.example.org&per_page=200&page=1")
    );
    assert_eq!(list.header("authorization"), Some("Bearer test-only-token"));
    let post = log.matching(Some("POST"), RECORDS).pop().unwrap();
    assert_eq!(post.path, "/v2/domains/example.org/records");
    assert_eq!(post.header("authorization"), Some("Bearer test-only-token"));
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({
            "type": "TXT", "name": "_acme-challenge.example.org.", "data": "AAA", "ttl": 30
        })
    );
    let id = mock.control().records()[0].id;
    remove(&client, "AAA").await.unwrap();
    let delete = log.matching(Some("DELETE"), RECORD).pop().unwrap();
    assert_eq!(delete.path, format!("/v2/domains/example.org/records/{id}"));
    assert!(delete.body.is_empty());
}

/// The apex is written with the zone's own name and read back whatever the form of the name in
/// the answer: relative with `@`, or absolute.
#[tokio::test]
async fn digitalocean_names_in_either_form() {
    for form in [NameForm::Relative, NameForm::Absolute] {
        let (mock, client) = setup().await;
        mock.control().set_name_form(form);
        for (owner, stored) in [(zone(), "@"), (name(), "_acme-challenge")] {
            let add = |value: &'static str| {
                let (client, owner) = (&client, owner.clone());
                async move {
                    client
                        .add_txt_value(&zone(), &owner, &txt(value), None)
                        .await
                        .unwrap()
                }
            };
            assert_eq!(add("AAA").await, AddOutcome::Created, "{form:?} {owner}");
            assert_eq!(
                add("AAA").await,
                AddOutcome::AlreadyPresent,
                "{form:?} {owner}"
            );
            assert_eq!(add("BBB").await, AddOutcome::Appended, "{form:?} {owner}");
            assert!(
                mock.control()
                    .records()
                    .iter()
                    .any(|r| r.name == stored && r.data == "AAA"),
                "{form:?} {owner}: {:?}",
                mock.control().records()
            );
            assert_eq!(
                client
                    .remove_txt_value(&zone(), &owner, &txt("AAA"))
                    .await
                    .unwrap(),
                RemoveOutcome::Removed
            );
        }
        assert_eq!(mock.control().records().len(), 2);
    }
}

/// A listing filter that matches by substring returns neighbors (`x.<name>`, `<name>.x`): they
/// are skipped, so a value of a neighbor is neither taken for ours nor removed.
#[tokio::test]
async fn digitalocean_exact_name_match_ignores_noisy_filter() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_loose_filter(true);
    control.insert_record(
        "example.org",
        "x._acme-challenge.example.org",
        "TXT",
        "AAA",
        30,
    );
    control.insert_record(
        "example.org",
        "_acme-challenge.example.org.sub",
        "TXT",
        "AAA",
        30,
    );
    // A relative name that looks absolute is a different name.
    control.insert_record(
        "example.org",
        "_acme-challenge.example.org.example.org",
        "TXT",
        "AAA",
        30,
    );
    let original = control.records();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(control.txt_values(NAME), ["AAA"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(control.records(), original);
}

/// The TTL of a new record is the caller's, else the configured one; a value added to an
/// existing set gets the set's TTL as read (the smallest), whatever the caller asks.
#[tokio::test]
async fn digitalocean_ttl_policy() {
    let mock = DigitalOceanMock::start(Seed::standard()).await;
    let mut config = settings(mock.base_url());
    config.ttl = 77;
    let client = DigitalOcean::new(config, credentials(TOKEN), &context()).unwrap();
    let ttl = |name: &str| mock.control().txt_records(name)[0].ttl;
    let other = dn("a.example.org");
    let third = dn("b.example.org");
    client
        .add_txt_value(&zone(), &other, &txt("v"), None)
        .await
        .unwrap();
    assert_eq!(ttl("a.example.org"), 77);
    client
        .add_txt_value(
            &zone(),
            &third,
            &txt("v"),
            Some(Ttl::from_secs(120).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(ttl("b.example.org"), 120);

    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "foreign-1", 900);
    control.insert_record("example.org", NAME, "TXT", "foreign-2", 600);
    client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("ours"),
            Some(Ttl::from_secs(3000).unwrap()),
        )
        .await
        .unwrap();
    let ours = control
        .txt_records(NAME)
        .into_iter()
        .find(|r| r.data == "ours")
        .unwrap();
    assert_eq!(ours.ttl, 600);
}

/// A record whose TTL the API does not state gets a create without a TTL when it joins an
/// existing name, so the provider decides.
#[tokio::test]
async fn digitalocean_unreported_ttl_is_not_invented() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RECORDS).respond(
        200,
        r#"{"domain_records":[{"id":1,"type":"TXT","name":"_acme-challenge","data":"foreign","ttl":null}],"links":{},"meta":{"total":1}}"#,
    ));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    let post = mock.log().matching(Some("POST"), RECORDS).pop().unwrap();
    assert!(post.body_json().unwrap().get("ttl").is_none());
}

// ---- Listings ----------------------------------------------------------------------------------

/// Pages are fetched by number until the last one; the `next` link, which points at a foreign
/// host, is never requested. A value on the last page is found.
#[tokio::test]
async fn digitalocean_listing_pages_by_number() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_page_cap(1);
    control.insert_record("example.org", NAME, "TXT", "foreign-1", 30);
    control.insert_record("example.org", NAME, "TXT", "foreign-2", 30);
    control.insert_record("example.org", NAME, "TXT", "AAA", 30);
    control.insert_record("example.org", "other.example.org", "TXT", "AAA", 30);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    let gets = mock.log().matching(Some("GET"), RECORDS);
    let pages: Vec<_> = gets
        .iter()
        .map(|r| r.query.clone().unwrap())
        .map(|q| q.rsplit("page=").next().unwrap().to_owned())
        .collect();
    assert_eq!(pages, ["1", "2", "3"]);
    assert!(
        gets.iter()
            .all(|r| r.path == "/v2/domains/example.org/records")
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt_values(NAME), ["foreign-1", "foreign-2"]);
}

/// A listing that stops short of the total it states, lacks the total or the list, or has an
/// empty page before its end is an error, never a shorter result; nothing is written after it.
#[tokio::test]
async fn digitalocean_truncated_listing_is_protocol() {
    let (mock, client) = setup().await;
    let record = r#"{"id":1,"type":"TXT","name":"_acme-challenge","data":"foreign","ttl":30}"#;
    for body in [
        // Ends before the total.
        format!(r#"{{"domain_records":[{record}],"links":{{"pages":{{}}}},"meta":{{"total":3}}}}"#),
        // No total.
        format!(r#"{{"domain_records":[{record}],"links":{{}}}}"#),
        format!(r#"{{"domain_records":[{record}],"links":{{}},"meta":{{}}}}"#),
        // No list.
        r#"{"links":{},"meta":{"total":0}}"#.to_owned(),
        r#"{"domain_records":null,"links":{},"meta":{"total":0}}"#.to_owned(),
        // An empty page with a next link.
        r#"{"domain_records":[],"links":{"pages":{"next":"https://x.invalid/?page=2"}},"meta":{"total":1}}"#
            .to_owned(),
        // Not JSON.
        "<html>oops</html>".to_owned(),
    ] {
        mock.faults()
            .push(Fault::on("GET", RECORDS).respond(200, body.clone()));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
        mock.faults()
            .push(Fault::on("GET", RECORDS).respond(200, body.clone()));
        let e = remove(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);
    let zones = r#"{"domains":[{"name":"example.org"}],"links":{},"meta":{"total":3}}"#;
    mock.faults()
        .push(Fault::on("GET", DOMAINS).respond(200, zones));
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

#[tokio::test]
async fn digitalocean_list_zones_pages_by_number() {
    let (mock, client) = setup().await;
    mock.control().insert_domain("other.test");
    mock.control().insert_domain("third.test");
    mock.control().set_page_cap(1);
    let zones = client.list_zones().await.unwrap();
    let names: Vec<_> = zones
        .iter()
        .map(|z| z.name.without_dot().to_owned())
        .collect();
    assert_eq!(names, ["example.org", "other.test", "third.test"]);
    assert_eq!(mock.log().count(Some("GET"), DOMAINS), 3);
}

// ---- check -------------------------------------------------------------------------------------

/// `check` reads the account on every call, so a token revoked in between is noticed, and looks
/// every zone up afresh.
#[tokio::test]
async fn digitalocean_check_exercises_the_credentials() {
    let (mock, client) = setup().await;
    let report = client.check(&[zone(), dn("missing.test")]).await.unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones[0].found && report.zones[0].detail.is_none());
    assert!(!report.zones[1].found);
    client.check(&[]).await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ACCOUNT), 2);
    assert_eq!(mock.log().count(Some("GET"), DOMAIN), 2);

    // The account read is refused: the credentials are not accepted, and no zone is asked for.
    mock.faults().push(Fault::on("GET", ACCOUNT).status(401));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    mock.faults().push(Fault::on("GET", ACCOUNT).status(403));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    // Another refusal of the account read is the provider's refusal with its message, not an
    // answer in an unexpected form.
    mock.faults().push(Fault::on("GET", ACCOUNT).respond(
        400,
        r#"{"id":"bad_request","message":"refused","request_id":"r"}"#,
    ));
    let e = client.check(&[zone()]).await.unwrap_err();
    match &e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(*status, Some(400));
            assert_eq!(detail.as_str(), "bad_request: refused");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(mock.log().count(Some("GET"), DOMAIN), 2);
    // The same for the domain read.
    mock.faults().push(Fault::on("GET", DOMAIN).respond(
        400,
        r#"{"id":"bad_request","message":"refused","request_id":"r"}"#,
    ));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), DOMAIN), 3);

    // An answer about another domain is not taken for the one asked for.
    mock.faults().push(Fault::on("GET", DOMAIN).respond(
        200,
        r#"{"domain":{"name":"other.example","ttl":1800,"zone_file":null}}"#,
    ));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");

    let wrong = client_with(&mock, "wrong-token", &context());
    let e = wrong.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(!format!("{e} {e:?} {wrong:?}").contains("wrong-token"));
}

// ---- Errors ------------------------------------------------------------------------------------

#[tokio::test]
async fn digitalocean_zone_not_found() {
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
    // The domain is deleted between the read and the create.
    mock.faults().push(Fault::on("POST", RECORDS).status(404));
    let e = add(&client, "AAA").await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
}

#[tokio::test]
async fn digitalocean_rate_limit() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RECORDS).rate_limited("1"));
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 2);
    mock.faults()
        .push(Fault::on("GET", RECORDS).rate_limited("120"));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
}

/// A 5xx on a read is retried; three in a row are `Transient`, which is retryable.
#[tokio::test]
async fn digitalocean_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RECORDS).status(502));
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("GET", RECORDS).times(3).status(503));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 5);
}

/// The provider's refusals are `Rejected` with the status and its message; a status the client
/// cannot interpret is `Protocol`.
#[tokio::test]
async fn digitalocean_refusals_are_rejected() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", RECORDS).respond(
        422,
        r#"{"id":"unprocessable_entity","message":"ttl is too low","request_id":"r"}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(422));
            assert_eq!(detail.as_str(), "unprocessable_entity: ttl is too low");
        }
        other => panic!("{other:?}"),
    }
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(418, r#"{"id":"teapot","message":"no"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(204, ""));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    // An answer to a create without the record it created.
    mock.faults()
        .push(Fault::on("POST", RECORDS).respond(201, r#"{"domain_record":{}}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn digitalocean_from_json_builds_the_client() {
    let mock = DigitalOceanMock::start(Seed::standard()).await;
    let ctx = context();
    let client = AnyProvider::from_json(
        ProviderId::DigitalOcean,
        &settings_json(&mock),
        &SecretString::from(format!("{{\"api_token\": \"{TOKEN}\", \"other\": 1}}")),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::DigitalOcean);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

/// The smallest configuration the shared test support uses to build a client without a request.
#[test]
fn digitalocean_minimal_configuration_builds() {
    let client = AnyProvider::from_json(
        ProviderId::DigitalOcean,
        r#"{"base_url":"http://127.0.0.1:9/v2"}"#,
        &SecretString::from(r#"{"api_token":"test-only-token"}"#.to_owned()),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::DigitalOcean);
    AnyProvider::from_json(
        ProviderId::DigitalOcean,
        "{}",
        &SecretString::from(r#"{"api_token":"test-only-token"}"#.to_owned()),
        &context(),
    )
    .unwrap_err();
}

/// A token pasted with surrounding whitespace is sent without it.
#[tokio::test]
async fn digitalocean_token_is_trimmed() {
    let mock = DigitalOceanMock::start(Seed::standard()).await;
    let client = client_with(&mock, &format!(" {TOKEN}\n"), &context());
    client.check(&[zone()]).await.unwrap();
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn digitalocean_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || serde_json::json!({ "base_url": "http://127.0.0.1:1/v2" });
    let with = |key: &str, value: serde_json::Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let token = serde_json::json!({"api_token": "tk"}).to_string();
    let cases = [
        (with("ttl", serde_json::json!(10)), token.clone(), "ttl"),
        (with("ttl", serde_json::json!(86_401)), token.clone(), "ttl"),
        (
            with(canary, serde_json::json!(canary)),
            token.clone(),
            "unknown keys",
        ),
        (
            with("domain", serde_json::json!("x")),
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
            ProviderId::DigitalOcean,
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
    let e = DigitalOcean::new(
        DigitalOceanConfig::default(),
        credentials("bad\u{1}token"),
        &ctx,
    )
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
    assert!(!format!("{e}").contains("bad"));
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round; the defaults of the metadata are those of the settings type.
#[test]
fn digitalocean_config_keys_match_metadata() {
    let meta = ProviderId::DigitalOcean.meta();
    let settings = serde_json::to_value(DigitalOceanConfig::default()).unwrap();
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
    // Defaults that work: the metadata's TTL is accepted.
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
async fn live_digitalocean_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_DIGITALOCEAN_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_DIGITALOCEAN_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_DIGITALOCEAN_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::DigitalOcean,
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
