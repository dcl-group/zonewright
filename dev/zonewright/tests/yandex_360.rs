//! Tests of the Yandex 360 client (`yandex_360`) against its mock.
#![cfg(feature = "yandex_360")]
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
use zonewright::providers::yandex_360::{Yandex360, Yandex360Config, Yandex360Credentials};
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
use zonewright_mock::yandex_360::{NameForm, ORG_ID, Seed, Yandex360Mock};

use common::echo::{CANARY_KEY, CANARY_TOKEN, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The token of the standard seed.
const TOKEN: &str = "test-only-token";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const DOMAINS: &str = "/directory/v1/org/*/domains";
const RECORDS: &str = "/directory/v1/org/*/domains/*/dns";
const RECORD: &str = "/directory/v1/org/*/domains/*/dns/*";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings pointed at `base_url`, for the organization of the standard seed.
fn settings(base_url: String) -> Yandex360Config {
    let mut config = Yandex360Config::new(ORG_ID);
    config.base_url = base_url;
    config
}

fn credentials(token: &str) -> Yandex360Credentials {
    Yandex360Credentials::new(SecretString::from(token.to_owned()))
}

fn client_with(mock: &Yandex360Mock, token: &str, ctx: &Context) -> Yandex360 {
    Yandex360::new(settings(mock.base_url()), credentials(token), ctx).unwrap()
}

async fn setup() -> (Yandex360Mock, Yandex360) {
    let mock = Yandex360Mock::start(Seed::standard()).await;
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
fn writes(mock: &Yandex360Mock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), RECORDS) + log.count(Some("DELETE"), RECORD)
}

/// The settings JSON of `from_json` for `mock`.
fn settings_json(mock: &Yandex360Mock) -> String {
    serde_json::json!({ "base_url": mock.base_url(), "org_id": ORG_ID }).to_string()
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

assert_not_impl!(Yandex360: std::fmt::Display, serde::Serialize);
assert_not_impl!(Yandex360Credentials: std::fmt::Display, serde::Serialize);
// A config with a required key has no `Default` (design section 2.8).
assert_not_impl!(Yandex360Config: Default);

/// What the echo's record listings answer: no record, a record with a foreign value, a record
/// with the value `v1`, or a CNAME record.
#[derive(Clone, Copy)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
    Cname,
}

/// The domain listing as the API answers it: one delegated domain.
fn domains_answer() -> axum::response::Response {
    let body = serde_json::json!({
        "domains": [{"name": "example.org", "delegated": true}],
        "page": 1, "pages": 1, "perPage": 10, "total": 1
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// A renderer that answers the domain listing like the API and every other request with
/// `errors`.
fn domains_then(errors: Render) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method == Method::GET && e.path.ends_with("/domains") {
            return domains_answer();
        }
        errors(e)
    })
}

/// A renderer that answers the listings like the API and every other request with `errors`.
fn listings_then(errors: Render, existing: Existing) -> Render {
    let domains = domains_then(errors);
    Arc::new(move |e: &Echoed| {
        if e.method != Method::GET || e.path.ends_with("/domains") {
            return domains(e);
        }
        let records = match existing {
            Existing::Nothing => serde_json::json!([]),
            Existing::Foreign => serde_json::json!([{
                "recordId": 1001, "type": "TXT", "name": "_acme-challenge",
                "text": "foreign", "ttl": 300
            }]),
            Existing::Ours => serde_json::json!([{
                "recordId": 1001, "type": "TXT", "name": "_acme-challenge",
                "text": "v1", "ttl": 300
            }]),
            Existing::Cname => serde_json::json!([{
                "recordId": 1001, "type": "CNAME", "name": "_acme-challenge",
                "target": "old.example.net.", "ttl": 300
            }]),
        };
        let count = records.as_array().map_or(0, Vec::len);
        let body = serde_json::json!({
            "records": records, "page": 1, "pages": 1, "perPage": 50, "total": count
        });
        (StatusCode::OK, axum::Json(body)).into_response()
    })
}

fn echo_client(echo: &EchoServer, ctx: &Context) -> Yandex360 {
    let config = settings(echo.url(""));
    Yandex360::new(config, credentials(CANARY_TOKEN), ctx).unwrap()
}

/// `check` and a write against an echo that quotes every request back: no canary in any error,
/// `ZoneCheck::detail` or `Debug`, and the write's error shows the redaction.
async fn echo_round(label: &str, client: &Yandex360, write: Write) {
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
/// the domain listing, the record listing (the probe of `check` and the read of a write), the
/// create and the delete.
#[tokio::test]
async fn yandex_360_secret_echo() {
    // One server and one context for every case: each case reconfigures the server, and
    // every client reuses the context's pooled connection (see `EchoServer::reset`).
    let ctx = context();
    let echo = EchoServer::start(200).await;
    for dialect in dialects() {
        // The domain listing is the echo.
        for status in [400, 401] {
            let label = format!("{} {:?} {status} domains", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status));
            let client = echo_client(&echo, &ctx);
            echo_round(&label, &client, Write::Add).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
        }
        // The domain listing is answered; the record listing is the echo.
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} records", dialect.name, dialect.spelling);
            echo.reset(
                dialect
                    .echo(status)
                    .render_under("/directory", domains_then(dialect.render.clone())),
            );
            let client = echo_client(&echo, &ctx);
            let e = client.check(&[zone()]).await.unwrap_err();
            let text = format!("{e} | {e:?} | {client:?}");
            assert_clean(&label, &text, &[CANARY_TOKEN]);
            assert!(
                echo.log().count(Some("GET"), RECORDS) > 0,
                "{label}: the record listing did not reach the echo"
            );
        }
        // Both listings answer normally, so the write itself reaches the echo: a create (with
        // and without a foreign record at the name) and a delete. The listings must not get
        // the echo's status: a 500 to an idempotent read is retried with real back-off sleeps
        // and adds seconds per dialect, without coverage (the reads' echo is covered by the
        // loops above, the 5xx body by the create's 500).
        for (existing, write, statuses) in [
            (
                Existing::Nothing,
                Write::Add,
                [400, 401, 403, 500].as_slice(),
            ),
            (
                Existing::Foreign,
                Write::Add,
                [400, 401, 403, 500].as_slice(),
            ),
            (Existing::Ours, Write::Remove, [400, 401, 403].as_slice()),
        ] {
            for &status in statuses {
                let label = format!("{} {:?} {status} {write:?}", dialect.name, dialect.spelling);
                echo.reset(dialect.echo(status).render_under(
                    "/directory",
                    listings_then(dialect.render.clone(), existing),
                ));
                let client = echo_client(&echo, &ctx);
                echo_round(&label, &client, write).await;
                let (method, path) = match write {
                    Write::Add => ("POST", RECORDS),
                    Write::Remove => ("DELETE", RECORD),
                };
                assert_eq!(
                    echo.log().count(Some(method), path),
                    1,
                    "{label}: the write did not reach the echo exactly once"
                );
            }
        }
    }
}

/// A `TRACE` capture over a success, repeated 401s, a 500 and a wrong token: the transport's
/// events are there, and no canary is.
#[tokio::test(flavor = "current_thread")]
async fn yandex_360_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.token = CANARY_TOKEN.into();
    let mock = Yandex360Mock::start(seed).await;
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
            "yandex_360 logs and errors",
            text,
            &[CANARY_TOKEN, CANARY_KEY],
        );
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely ends
/// with the zone's text, the zone's text inside another name, and a sibling zone.
#[tokio::test]
async fn yandex_360_name_outside_zone_sends_nothing() {
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
async fn yandex_360_invalid_input_sends_nothing() {
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
async fn yandex_360_add_is_idempotent() {
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
async fn yandex_360_never_removes_foreign_value() {
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
async fn yandex_360_other_types_at_the_name_are_untouched() {
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

    // A record of another type that carries our value in its `text`: it is not a TXT record.
    mock.faults().push(Fault::on("GET", RECORDS).respond(
        200,
        r#"{"records":[{"recordId":1,"type":"A","name":"_acme-challenge","text":"AAA","ttl":300}],"page":1,"pages":1,"perPage":50,"total":1}"#,
    ));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

#[tokio::test]
async fn yandex_360_remove_last_value_deletes_rrset() {
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
async fn yandex_360_remove_is_idempotent() {
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
async fn yandex_360_remove_deletes_every_copy_of_the_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "AAA", 300);
    control.insert_record("example.org", NAME, "TXT", "foreign", 300);
    control.insert_record("example.org", NAME, "TXT", "AAA", 300);
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
async fn yandex_360_concurrent_adds_are_serialized() {
    let mock = Yandex360Mock::start(Seed::standard()).await;
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
async fn yandex_360_foreign_value_added_between_read_and_write_survives() {
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

/// The record is deleted by someone else, or the domain is deleted and created again, between
/// the read and the delete: the delete is answered 404, and the removal never reports success
/// for a value that is still published. A record that is gone for another reason is a success.
#[tokio::test]
async fn yandex_360_delete_not_found_reads_again() {
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

/// Retry behavior: a create is sent once whatever happens (a 502, a 429 and a 401 are the
/// operation's error, and the repeat starts with a read); a repeated create could add a second
/// copy of the value.
#[tokio::test]
async fn yandex_360_writes_are_sent_once() {
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
                hook.insert_record("example.org", NAME, "TXT", "AAA", 300);
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
        400,
        r#"{"code":400,"message":"ttl is too low","details":[]}"#,
    ));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(posts(), 5);
}

/// The delete of one record by its identifier is the one write that is repeated: a 502 is
/// retried, and a retry that finds the record gone is a success. A rate limit with a long wait
/// and a rejected token are not repeated.
#[tokio::test]
async fn yandex_360_delete_by_id_is_retried() {
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

/// The requests as the documentation and lego describe them: the token in `Authorization` with
/// the `OAuth` prefix, the organization in the path, the listing's paging, the create's four
/// fields with the name relative to the zone, the delete by identifier.
#[tokio::test]
async fn yandex_360_request_shapes() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let log = mock.log();
    let list = log.matching(Some("GET"), RECORDS).pop().unwrap();
    assert_eq!(
        list.path,
        "/directory/v1/org/7654321/domains/example.org/dns"
    );
    assert_eq!(list.query.as_deref(), Some("page=1&perPage=50"));
    assert_eq!(list.header("authorization"), Some("OAuth test-only-token"));
    let post = log.matching(Some("POST"), RECORDS).pop().unwrap();
    assert_eq!(
        post.path,
        "/directory/v1/org/7654321/domains/example.org/dns"
    );
    assert_eq!(post.header("authorization"), Some("OAuth test-only-token"));
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({
            "type": "TXT", "name": "_acme-challenge", "text": "AAA", "ttl": 300
        })
    );
    // A deeper name is written relative to the zone, all its labels.
    let deep = dn("_acme-challenge.www.example.org");
    client
        .add_txt_value(&zone(), &deep, &txt("BBB"), None)
        .await
        .unwrap();
    let post = log.matching(Some("POST"), RECORDS).pop().unwrap();
    assert_eq!(post.body_json().unwrap()["name"], "_acme-challenge.www");

    let id = mock.control().records()[0].id;
    remove(&client, "AAA").await.unwrap();
    let delete = log.matching(Some("DELETE"), RECORD).pop().unwrap();
    assert_eq!(
        delete.path,
        format!("/directory/v1/org/7654321/domains/example.org/dns/{id}")
    );
    assert_eq!(
        delete.header("authorization"),
        Some("OAuth test-only-token")
    );
    assert!(delete.body.is_empty());
}

/// Names read back in the forms the client can place: relative to the zone, or the full name
/// with a trailing dot. The full name without a trailing dot, which a listing cannot tell from a
/// relative name that repeats the zone, is `yandex_360_ambiguous_names_are_refused_not_guessed`.
#[tokio::test]
async fn yandex_360_names_in_either_form() {
    for form in [NameForm::Relative, NameForm::Absolute] {
        let (mock, client) = setup().await;
        mock.control().set_name_form(form);
        for (owner, stored) in [
            (dn("_acme-challenge.www.example.org"), "_acme-challenge.www"),
            (name(), "_acme-challenge"),
        ] {
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
                    .any(|r| r.name == stored && r.text == "AAA"),
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

/// The zone's own name: nothing is written there because the documentation does not say how,
/// and the add is refused before any request (design section 3.1), whether or not the value is
/// there already; a value found there (`@` or the full name) can be removed.
#[tokio::test]
async fn yandex_360_apex_is_read_but_not_written() {
    for form in [NameForm::Relative, NameForm::Absolute] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.set_name_form(form);
        control.insert_record("example.org", "example.org", "TXT", "foreign", 300);
        let add_at_apex = |value: &'static str| {
            let client = &client;
            async move {
                client
                    .add_txt_value(&zone(), &zone(), &txt(value), None)
                    .await
            }
        };
        for value in ["foreign", "new"] {
            let e = add_at_apex(value).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{form:?} {value}: {e:?}");
        }
        assert!(mock.log().is_empty(), "{form:?}");
        assert_eq!(
            client
                .remove_txt_value(&zone(), &zone(), &txt("foreign"))
                .await
                .unwrap(),
            RemoveOutcome::RrsetDeleted,
            "{form:?}"
        );
        assert!(control.records().is_empty());
    }
}

/// Names that merely look like ours are skipped: a neighbor below the name, a name with ours as
/// its tail, and a name that is ours only in the other spelling of a deeper name.
#[tokio::test]
async fn yandex_360_exact_name_match() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", "x._acme-challenge", "TXT", "AAA", 300);
    control.insert_record("example.org", "_acme-challenge.sub", "TXT", "AAA", 300);
    control.insert_record(
        "example.org",
        "_acme-challenge.example.org.sub",
        "TXT",
        "AAA",
        300,
    );
    control.insert_record("example.org", "acme-challenge", "TXT", "AAA", 300);
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
async fn yandex_360_ttl_policy() {
    let mock = Yandex360Mock::start(Seed::standard()).await;
    let mut config = settings(mock.base_url());
    config.ttl = RrsetTtl::from_secs(90).unwrap();
    let client = Yandex360::new(config, credentials(TOKEN), &context()).unwrap();
    let ttl = |name: &str| mock.control().txt_records(name)[0].ttl;
    let other = dn("a.example.org");
    let third = dn("b.example.org");
    client
        .add_txt_value(&zone(), &other, &txt("v"), None)
        .await
        .unwrap();
    assert_eq!(ttl("a.example.org"), 90);
    client
        .add_txt_value(
            &zone(),
            &third,
            &txt("v"),
            Some(RrsetTtl::from_secs(120).unwrap()),
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
            Some(RrsetTtl::from_secs(3000).unwrap()),
        )
        .await
        .unwrap();
    let ours = control
        .txt_records(NAME)
        .into_iter()
        .find(|r| r.text == "ours")
        .unwrap();
    assert_eq!(ours.ttl, 600);
}

/// The API requires a TTL: a record whose TTL the listing does not state joins the name with the
/// configured one.
#[tokio::test]
async fn yandex_360_unreported_ttl_is_the_configured_one() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RECORDS).respond(
        200,
        r#"{"records":[{"recordId":1,"type":"TXT","name":"_acme-challenge","text":"foreign"}],"page":1,"pages":1,"perPage":50,"total":1}"#,
    ));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    let post = mock.log().matching(Some("POST"), RECORDS).pop().unwrap();
    assert_eq!(post.body_json().unwrap()["ttl"], 300);
}

// ---- Listings ----------------------------------------------------------------------------------

/// Pages are fetched by number until the last one. A value on the last page is found.
#[tokio::test]
async fn yandex_360_listing_pages_by_number() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_page_cap(1);
    control.insert_record("example.org", NAME, "TXT", "foreign-1", 300);
    control.insert_record("example.org", NAME, "TXT", "foreign-2", 300);
    control.insert_record("example.org", NAME, "TXT", "AAA", 300);
    control.insert_record("example.org", "other.example.org", "TXT", "AAA", 300);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    let gets = mock.log().matching(Some("GET"), RECORDS);
    let queries: Vec<_> = gets.iter().map(|r| r.query.clone().unwrap()).collect();
    assert_eq!(
        queries,
        [
            "page=1&perPage=50",
            "page=2&perPage=50",
            "page=3&perPage=50",
            "page=4&perPage=50"
        ]
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt_values(NAME), ["foreign-1", "foreign-2"]);
}

/// A listing that stops short of the total it states, lacks the counts or the list, or has an
/// empty page before its end is an error, never a shorter result; nothing is written after it.
#[tokio::test]
async fn yandex_360_truncated_listing_is_protocol() {
    let (mock, client) = setup().await;
    let record =
        r#"{"recordId":1,"type":"TXT","name":"_acme-challenge","text":"foreign","ttl":300}"#;
    for body in [
        // Ends before the total.
        format!(r#"{{"records":[{record}],"page":1,"pages":1,"perPage":50,"total":3}}"#),
        // No total, no page count.
        format!(r#"{{"records":[{record}],"page":1,"pages":1}}"#),
        format!(r#"{{"records":[{record}],"page":1,"total":1}}"#),
        // No list.
        r#"{"page":1,"pages":1,"total":0}"#.to_owned(),
        r#"{"records":null,"page":1,"pages":1,"total":0}"#.to_owned(),
        // An empty page before the last.
        r#"{"records":[],"page":1,"pages":2,"total":1}"#.to_owned(),
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
    // A second page that ends short of the total.
    mock.faults().push(Fault::on("GET", RECORDS).respond(
        200,
        format!(r#"{{"records":[{record}],"page":1,"pages":2,"perPage":1,"total":2}}"#),
    ));
    mock.faults().push(Fault::on("GET", RECORDS).respond(
        200,
        r#"{"records":[],"page":2,"pages":2,"perPage":1,"total":2}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
    let zones = r#"{"domains":[{"name":"example.org","delegated":true}],"page":1,"pages":1,"perPage":10,"total":3}"#;
    mock.faults()
        .push(Fault::on("GET", DOMAINS).respond(200, zones));
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults()
        .push(Fault::on("GET", DOMAINS).respond(200, r#"{"page":1,"pages":1,"total":0}"#));
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// Domains come ten to a page at most (the documented maximum); the ones not delegated to Yandex
/// are not zones the client can manage.
#[tokio::test]
async fn yandex_360_list_zones_pages_and_skips_undelegated() {
    let (mock, client) = setup().await;
    mock.control().insert_domain("other.test", true);
    mock.control().insert_domain("parked.test", false);
    mock.control().insert_domain("third.test", true);
    mock.control().set_page_cap(1);
    let zones = client.list_zones().await.unwrap();
    let names: Vec<_> = zones
        .iter()
        .map(|z| z.name.without_dot().to_owned())
        .collect();
    assert_eq!(names, ["example.org", "other.test", "third.test"]);
    let gets = mock.log().matching(Some("GET"), DOMAINS);
    assert_eq!(gets.len(), 4);
    assert_eq!(gets[0].query.as_deref(), Some("page=1&perPage=10"));

    // A domain whose `delegated` is not stated is not taken for a delegated one.
    mock.faults().push(Fault::on("GET", DOMAINS).respond(
        200,
        r#"{"domains":[{"name":"example.org"}],"page":1,"pages":1,"perPage":10,"total":1}"#,
    ));
    assert!(client.list_zones().await.unwrap().is_empty());
}

// ---- check -------------------------------------------------------------------------------------

/// `check` reads the domain listing on every call, so a token revoked in between is noticed, and
/// reads the records of every zone afresh.
#[tokio::test]
async fn yandex_360_check_exercises_the_credentials() {
    let (mock, client) = setup().await;
    let report = client.check(&[zone(), dn("missing.test")]).await.unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones[0].found && report.zones[0].detail.is_none());
    assert!(!report.zones[1].found && report.zones[1].detail.is_none());
    client.check(&[]).await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), DOMAINS), 2);
    // The zone that exists is read; the one the organization lacks is not asked for.
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 1);
    assert_eq!(
        mock.log().matching(Some("GET"), RECORDS)[0]
            .query
            .as_deref(),
        Some("page=1&perPage=1")
    );

    // The domain listing is refused: the credentials are not accepted, and no zone is read.
    mock.faults().push(Fault::on("GET", DOMAINS).status(401));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    mock.faults().push(Fault::on("GET", DOMAINS).status(403));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    // Another refusal is the provider's refusal with its message, not an answer in an
    // unexpected form.
    mock.faults().push(
        Fault::on("GET", DOMAINS).respond(400, r#"{"code":400,"message":"refused","details":[]}"#),
    );
    let e = client.check(&[zone()]).await.unwrap_err();
    match &e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(*status, Some(400));
            assert_eq!(detail.as_str(), "refused");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 1);

    // The token may read domains but not manage DNS: the record read says so.
    mock.faults().push(Fault::on("GET", RECORDS).status(403));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    // The domain is gone between the two reads.
    mock.faults().push(Fault::on("GET", RECORDS).status(404));
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    // An answer that is not a listing.
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(200, r#"{"page":1}"#));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");

    let wrong = client_with(&mock, "wrong-token", &context());
    let e = wrong.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(!format!("{e} {e:?} {wrong:?}").contains("wrong-token"));

    // Another organization's ID: the provider refuses access.
    let mut config = settings(mock.base_url());
    config.org_id = "1111".into();
    let other = Yandex360::new(config, credentials(TOKEN), &context()).unwrap();
    let e = other.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
}

/// A domain that is not delegated to Yandex is reported as not found, with the reason, and its
/// records are not read.
#[tokio::test]
async fn yandex_360_check_reports_undelegated_domains() {
    let (mock, client) = setup().await;
    mock.control().insert_domain("parked.test", false);
    let report = client.check(&[dn("parked.test"), zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    let detail = report.zones[0].detail.as_ref().unwrap();
    assert!(detail.as_str().contains("not delegated"), "{detail:?}");
    assert!(report.zones[1].found);
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 1);
    // A domain whose `delegated` is not stated is not taken for a delegated one.
    mock.faults().push(Fault::on("GET", DOMAINS).respond(
        200,
        r#"{"domains":[{"name":"example.org"}],"page":1,"pages":1,"perPage":10,"total":1}"#,
    ));
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
}

// ---- Errors ------------------------------------------------------------------------------------

#[tokio::test]
async fn yandex_360_zone_not_found() {
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
async fn yandex_360_rate_limit() {
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
async fn yandex_360_server_errors_are_retried_then_transient() {
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
async fn yandex_360_refusals_are_rejected() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", RECORDS).respond(
        400,
        r#"{"code":400,"message":"ttl is too low","details":[]}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(400));
            assert_eq!(detail.as_str(), "ttl is too low");
        }
        other => panic!("{other:?}"),
    }
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(418, r#"{"message":"no"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(204, ""));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    // An answer to a create without the record it created.
    mock.faults()
        .push(Fault::on("POST", RECORDS).respond(200, "{}"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn yandex_360_from_json_builds_the_client() {
    let mock = Yandex360Mock::start(Seed::standard()).await;
    let ctx = context();
    let client = AnyProvider::from_json(
        ProviderId::Yandex360,
        &settings_json(&mock),
        &SecretString::from(format!("{{\"oauth_token\": \"{TOKEN}\", \"other\": 1}}")),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Yandex360);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

/// The smallest configuration the shared test support uses to build a client without a request.
#[test]
fn yandex_360_minimal_configuration_builds() {
    let client = AnyProvider::from_json(
        ProviderId::Yandex360,
        r#"{"org_id":"7654321","base_url":"http://127.0.0.1:9"}"#,
        &SecretString::from(r#"{"oauth_token":"test-only-token"}"#.to_owned()),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Yandex360);
    // The organization is required: a settings object without it is refused by name, not
    // read as an empty organization ID (design section 2.8).
    for settings in ["{}", r#"{"base_url":"http://127.0.0.1:9","ttl":300}"#] {
        let e = AnyProvider::from_json(
            ProviderId::Yandex360,
            settings,
            &SecretString::from(r#"{"oauth_token":"test-only-token"}"#.to_owned()),
            &context(),
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config);
        assert_eq!(
            e.to_string(),
            "invalid provider configuration: the settings lack the required key org_id",
            "{settings}"
        );
    }
}

/// A token pasted with surrounding whitespace is sent without it.
#[tokio::test]
async fn yandex_360_token_is_trimmed() {
    let mock = Yandex360Mock::start(Seed::standard()).await;
    let client = client_with(&mock, &format!(" {TOKEN}\n"), &context());
    client.check(&[zone()]).await.unwrap();
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn yandex_360_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || serde_json::json!({ "base_url": "http://127.0.0.1:1", "org_id": "7654321" });
    let with = |key: &str, value: serde_json::Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let token = serde_json::json!({"oauth_token": "tk"}).to_string();
    let cases = [
        (with("ttl", serde_json::json!(10)), token.clone(), "ttl"),
        (with("ttl", serde_json::json!(59)), token.clone(), "ttl"),
        (with("ttl", serde_json::json!(86_401)), token.clone(), "ttl"),
        (
            with("org_id", serde_json::json!("")),
            token.clone(),
            "org_id",
        ),
        (
            with("org_id", serde_json::json!(format!("1/../{canary}"))),
            token.clone(),
            "org_id",
        ),
        (
            with("org_id", serde_json::json!("12345678901234567890")),
            token.clone(),
            "org_id",
        ),
        (
            with(canary, serde_json::json!(canary)),
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
            serde_json::json!({"oauth_token": 5, canary: canary}).to_string(),
            "oauth_token",
        ),
        (
            base(),
            serde_json::json!({"token": canary}).to_string(),
            "oauth_token",
        ),
        (
            base(),
            serde_json::json!({"oauth_token": ""}).to_string(),
            "oauth_token",
        ),
        (
            base(),
            serde_json::json!({"oauth_token": "  \n"}).to_string(),
            "oauth_token",
        ),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::Yandex360,
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
    let e = Yandex360::new(
        Yandex360Config::new(ORG_ID),
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
fn yandex_360_config_keys_match_metadata() {
    let meta = ProviderId::Yandex360.meta();
    let settings = serde_json::to_value(Yandex360Config::new(ORG_ID)).unwrap();
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
    assert_eq!(secret, ["oauth_token"]);
    for field in meta.fields.iter().filter(|f| f.default.is_some()) {
        let value = &settings[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
    }
    let required: Vec<&str> = meta
        .fields
        .iter()
        .filter(|f| f.required)
        .map(|f| f.key)
        .collect();
    assert_eq!(required, ["org_id", "oauth_token"]);
    let caps = &meta.capabilities;
    assert!(caps.list_zones && caps.add_txt_value && caps.remove_txt_value);
    assert!(caps.list_rrsets && caps.get_rrset && caps.set_rrset && caps.delete_rrset);
}

// ---- Record level (design sections 3.4, 3.6 and 12.3) ------------------------------------------

/// The TTL a new set gets when the caller gives none: the configured default.
const DEFAULT_TTL: u32 = 300;

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

/// `set` with the configured default TTL when it has none.
fn with_default_ttl(set: &RrSet) -> RrSet {
    set.clone().with_ttl(
        set.ttl()
            .or(Some(RrsetTtl::from_secs(DEFAULT_TTL).unwrap())),
    )
}

/// Number of record write requests: creates, edits and deletes.
fn record_writes(mock: &Yandex360Mock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), RECORDS)
        + log.count(Some("POST"), RECORD)
        + log.count(Some("DELETE"), RECORD)
}

/// Number of edit requests.
fn edits(mock: &Yandex360Mock) -> usize {
    mock.log().count(Some("POST"), RECORD)
}

/// The main field of each record of `rtype` at `owner` (`address`, `target`, `exchange`, `value`
/// or `text`), sorted.
fn stored(mock: &Yandex360Mock, owner: &str, rtype: &str) -> Vec<String> {
    let mut values: Vec<String> = mock
        .control()
        .records_at(owner, rtype)
        .into_iter()
        .map(|r| {
            ["address", "target", "exchange", "value"]
                .iter()
                .find_map(|key| r.field(key).map(str::to_owned))
                .unwrap_or(r.text)
        })
        .collect();
    values.sort();
    values
}

/// Every supported type through set, get and list with canonical equality: the apex (written
/// `@`), an IDN name, a wildcard, multi-value sets and a TXT value of a full character-string;
/// the listing reads the same in both name forms.
#[tokio::test]
async fn yandex_360_record_round_trips() {
    let (mock, client) = setup().await;
    let long = format!("\"{}\"", "x".repeat(255));
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
            Some(600),
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
            Some(3600),
            &[
                "0 issue \"letsencrypt.org\"",
                "128 iodef \"mailto:sec@example.org\"",
            ],
        ),
        rr("example.org", RecordType::TXT, None, &[&long, "\"v=1\""]),
    ];
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
        let got = client
            .get_rrset(&zone(), set.name(), set.rtype())
            .await
            .unwrap();
        assert_eq!(got.as_ref(), Some(&with_default_ttl(set)), "{label}");
        assert!(got.unwrap().records().iter().all(RecordData::is_canonical));
        // A repeat changes nothing.
        let before = record_writes(&mock);
        assert_eq!(
            client.set_rrset(&zone(), set, Expect::Any).await.unwrap(),
            SetOutcome::Unchanged,
            "{label}"
        );
        assert_eq!(record_writes(&mock), before, "{label}");
    }
    for form in [NameForm::Relative, NameForm::Absolute] {
        mock.control().set_name_form(form);
        let listing = client.list_rrsets(&zone()).await.unwrap();
        assert!(listing.skipped.is_empty(), "{form:?} {:?}", listing.skipped);
        assert_eq!(listing.rrsets.len(), sets.len(), "{form:?}");
        for set in &sets {
            let expected = with_default_ttl(set);
            assert!(listing.rrsets.contains(&expected), "{form:?} {expected:?}");
            let got = client
                .get_rrset(&zone(), set.name(), set.rtype())
                .await
                .unwrap();
            assert_eq!(got, Some(expected), "{form:?}");
        }
    }
    mock.control().set_name_form(NameForm::Relative);

    // The fields the API stores.
    let control = mock.control();
    let apex: Vec<_> = control
        .records()
        .into_iter()
        .filter(|r| r.name == "@")
        .map(|r| r.rtype)
        .collect();
    assert_eq!(apex.len(), 8, "{apex:?}");
    let mx = control.records_at("example.org", "MX");
    assert!(
        mx.iter()
            .any(|r| r.field("exchange") == Some("mail.example.org.")
                && r.number("preference") == Some(10))
    );
    let srv = control.records_at("_sip._tcp.example.org", "SRV");
    assert!(
        srv.iter()
            .any(|r| r.field("target") == Some("sip.example.org.")
                && r.number("priority") == Some(1)
                && r.number("weight") == Some(5)
                && r.number("port") == Some(5060))
    );
    let caa = control.records_at("example.org", "CAA");
    assert!(
        caa.iter()
            .any(|r| r.field("value") == Some("\"letsencrypt.org\"")
                && r.number("flag") == Some(0)
                && r.field("tag") == Some("issue")
                && r.ttl == 3600)
    );
    assert_eq!(
        stored(&mock, "www.example.org", "CNAME"),
        ["target.example.net."]
    );
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
    assert!(
        control
            .records()
            .iter()
            .any(|r| r.rtype == "TXT" && r.text == "x".repeat(255))
    );

    // A host name stated without its trailing dot by another writer reads as the same value.
    control.insert_fields(
        "example.org",
        "other",
        "MX",
        serde_json::json!({"exchange": "Mail.Example.org", "preference": 10}),
        600,
    );
    let other = rr(
        "other.example.org",
        RecordType::MX,
        None,
        &["10 mail.example.org."],
    );
    assert_eq!(
        client
            .get_rrset(&zone(), &dn("other.example.org"), RecordType::MX)
            .await
            .unwrap(),
        Some(
            other
                .clone()
                .with_ttl(Some(RrsetTtl::from_secs(600).unwrap()))
        )
    );
    let before = record_writes(&mock);
    assert_eq!(
        client
            .set_rrset(&zone(), &other, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    assert_eq!(record_writes(&mock), before);
}

/// `Expect::Absent` on an existing set and `Expect::Matches` on a different or missing one are
/// `PreconditionFailed` and write nothing; an expectation that holds lets the write through.
#[tokio::test]
async fn yandex_360_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_fields(
        "example.org",
        www,
        "A",
        serde_json::json!({"address": "192.0.2.1"}),
        600,
    );
    let original = control.records();
    let wanted = rr(www, RecordType::A, None, &["192.0.2.7"]);
    let other = rr(www, RecordType::A, None, &["192.0.2.2"]);
    let more = rr(www, RecordType::A, None, &["192.0.2.1", "192.0.2.2"]);
    let ttl = rr(www, RecordType::A, Some(300), &["192.0.2.1"]);
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
    let txt = rr(www, RecordType::TXT, None, &["\"v\""]);
    let e = client
        .set_rrset(&zone(), &txt, Expect::Matches(&txt))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &dn(www), RecordType::TXT, Expect::Matches(&txt))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(record_writes(&mock), 0);
    assert_eq!(control.records(), original);

    // The expectation holds, with the TTL and without one.
    let current = rr(www, RecordType::A, Some(600), &["192.0.2.1"]);
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

/// `Any` replaces whatever is there; an equal set is `Unchanged` without a write; a TTL change
/// alone edits the records in place, keeping their values; a delete removes every record and a
/// repeat is `NotPresent`.
#[tokio::test]
async fn yandex_360_set_any_replaces_and_delete_converges() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    for address in ["192.0.2.1", "192.0.2.2"] {
        control.insert_fields(
            "example.org",
            www,
            "A",
            serde_json::json!({ "address": address }),
            600,
        );
    }
    let replaced = rr(www, RecordType::A, None, &["192.0.2.2", "192.0.2.3"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &replaced, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.2", "192.0.2.3"]);
    // The record that stays is not touched: one create, one delete, no edit.
    let log = mock.log();
    assert_eq!(log.count(Some("POST"), RECORDS), 1);
    assert_eq!(log.count(Some("DELETE"), RECORD), 1);
    assert_eq!(edits(&mock), 0);
    // The new record got the set's TTL as read.
    assert!(control.records_at(www, "A").iter().all(|r| r.ttl == 600));

    let before = record_writes(&mock);
    assert_eq!(
        client
            .set_rrset(&zone(), &replaced, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    assert_eq!(record_writes(&mock), before);

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
    assert_eq!(edits(&mock), 2);
    assert!(control.records_at(www, "A").iter().all(|r| r.ttl == 900));
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.2", "192.0.2.3"]);

    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(control.records_at(www, "A").is_empty());
    let before = record_writes(&mock);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
    assert_eq!(record_writes(&mock), before);
    assert_eq!(
        client
            .get_rrset(&zone(), &dn(www), RecordType::A)
            .await
            .unwrap(),
        None
    );
}

/// Refusals before any request: SOA, NS (also the apex NS set) and every type outside the list
/// are `UnsupportedRecordType`, a TTL outside 60 to 86400 and an expectation about another name
/// or type are `InvalidInput`, a name outside the zone is `NameOutsideZone`.
#[tokio::test]
async fn yandex_360_record_refusals_send_nothing() {
    let (mock, client) = setup().await;
    let soa = rr(
        "example.org",
        RecordType::SOA,
        None,
        &["dns1.yandex.net. hostmaster.example.org. 1 10800 3600 604800 1800"],
    );
    let apex_ns = rr("example.org", RecordType::NS, None, &["dns1.yandex.net."]);
    let sub_ns = rr(
        "sub.example.org",
        RecordType::NS,
        None,
        &["ns1.example.net."],
    );
    let tlsa = rr(
        "_443._tcp.example.org",
        RecordType::TLSA,
        None,
        &["3 1 1 0a1b"],
    );
    for set in [&soa, &apex_ns, &sub_ns, &tlsa] {
        let e = client
            .set_rrset(&zone(), set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{set:?}: {e:?}");
    }
    for rtype in [
        RecordType::SOA,
        RecordType::NS,
        RecordType::TLSA,
        RecordType::PTR,
        RecordType::from_code(43),
    ] {
        let e = client.get_rrset(&zone(), &zone(), rtype).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
        let e = client
            .delete_rrset(&zone(), &zone(), rtype, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
    }

    for ttl in [59, 86_401] {
        let set = rr("www.example.org", RecordType::A, Some(ttl), &["192.0.2.1"]);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{ttl}: {e:?}");
    }
    let a = rr("www.example.org", RecordType::A, None, &["192.0.2.1"]);
    let txt = rr("www.example.org", RecordType::TXT, None, &["\"v\""]);
    let e = client
        .set_rrset(&zone(), &a, Expect::Matches(&txt))
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
            .delete_rrset(&dn(zone), &dn(owner), RecordType::A, Expect::Any)
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
    for ttl in [60, 86_400] {
        let set = rr("www.example.org", RecordType::A, Some(ttl), &["192.0.2.1"]);
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
        assert_eq!(
            mock.control().records_at("www.example.org", "A")[0].ttl,
            ttl
        );
    }
}

/// Values whose encoding at this API no source establishes are refused after the read and
/// nothing is written; the same value already at the provider is kept as it is.
#[tokio::test]
async fn yandex_360_values_without_an_encoding_are_refused() {
    let (mock, client) = setup().await;
    for set in [
        rr("www.example.org", RecordType::TXT, None, &["\"two words\""]),
        rr("www.example.org", RecordType::MX, None, &["0 ."]),
        rr("www.example.org", RecordType::SRV, None, &["0 0 0 ."]),
        rr(
            "www.example.org",
            RecordType::CAA,
            None,
            &["0 issue \"a\\\"b\""],
        ),
        rr("www.example.org", RecordType::CAA, None, &["0 issue \"\""]),
    ] {
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{set:?}: {e:?}");
    }
    assert_eq!(record_writes(&mock), 0);

    // An SPF value with spaces written by someone else: listed, kept, and a value joins it.
    mock.control().insert_record(
        "example.org",
        "www.example.org",
        "TXT",
        "v=spf1 mx -all",
        300,
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

/// CAA records cannot be edited (the edit call has no CAA fields): a TTL change of CAA records
/// that stay is `InvalidInput` with nothing written; replacing the values creates and deletes.
#[tokio::test]
async fn yandex_360_caa_is_replaced_never_edited() {
    let (mock, client) = setup().await;
    let caa = rr(
        "example.org",
        RecordType::CAA,
        None,
        &["0 issue \"ca.example.net\""],
    );
    client
        .set_rrset(&zone(), &caa, Expect::Absent)
        .await
        .unwrap();
    let original = mock.control().records();
    let before = record_writes(&mock);
    let retuned = caa
        .clone()
        .with_ttl(Some(RrsetTtl::from_secs(900).unwrap()));
    let e = client
        .set_rrset(&zone(), &retuned, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(record_writes(&mock), before);
    assert_eq!(mock.control().records(), original);

    let next = rr(
        "example.org",
        RecordType::CAA,
        None,
        &["0 issue \"other.example.net\"", "0 issuewild \";\""],
    );
    assert_eq!(
        client.set_rrset(&zone(), &next, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        stored(&mock, "example.org", "CAA"),
        ["\";\"", "\"other.example.net\""]
    );
    assert_eq!(edits(&mock), 0);
    // A new value next to a kept one gets the set's TTL; a delete needs no edit either.
    assert_eq!(
        client
            .delete_rrset(&zone(), &zone(), RecordType::CAA, Expect::Matches(&next))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(mock.control().records().is_empty());
}

/// The listing reports every rrset of the domain with the smallest TTL of each; NS (whose value
/// field is not documented), a type the model does not know, a name it cannot hold and two CNAME
/// records at one name are in `skipped`; an unparseable value is non-canonical data.
#[tokio::test]
async fn yandex_360_listing_reports_skipped_sets() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let a = |owner: &str, address: &str, ttl: u32| {
        control.insert_fields(
            "example.org",
            owner,
            "A",
            serde_json::json!({ "address": address }),
            ttl,
        )
    };
    a("www", "192.0.2.1", 600);
    a("www", "192.0.2.2", 300);
    a("odd", "not an address", 300);
    a("bad name", "192.0.2.9", 300);
    for ns in ["dns1.yandex.net.", "dns2.yandex.net."] {
        control.insert_fields(
            "example.org",
            "@",
            "NS",
            serde_json::json!({ "target": ns }),
            3600,
        );
    }
    control.insert_record("example.org", "x", "WEIRD", "whatever", 300);
    for target in ["a.example.net.", "b.example.net."] {
        control.insert_fields(
            "example.org",
            "two",
            "CNAME",
            serde_json::json!({ "target": target }),
            300,
        );
    }
    control.insert_record(
        "example.org",
        "@",
        "TXT",
        "v=spf1 redirect=_spf.yandex.net",
        300,
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
            Some(300),
            &["192.0.2.1", "192.0.2.2"]
        ))
    );
    let odd = get("odd.example.org", RecordType::A).unwrap();
    assert!(!odd.records()[0].is_canonical());
    assert_eq!(odd.records()[0].as_str(), "not an address");
    assert_eq!(
        get("example.org", RecordType::TXT),
        Some(rr(
            "example.org",
            RecordType::TXT,
            Some(300),
            &["\"v=spf1 redirect=_spf.yandex.net\""]
        ))
    );

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
            "example.org.".to_owned(),
            "NS".to_owned(),
            SkipReason::NotPlainRecords,
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

    // The listing reads every page by number, and the absolute name form reads the same.
    control.set_page_cap(2);
    control.set_name_form(NameForm::Absolute);
    let paged = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(paged.rrsets, listing.rrsets);
    let gets = mock.log().matching(Some("GET"), RECORDS);
    assert!(
        gets.iter()
            .all(|r| r.path == "/directory/v1/org/7654321/domains/example.org/dns")
    );
    assert_eq!(
        gets.last().unwrap().query.as_deref(),
        Some("page=5&perPage=50")
    );
}

/// A listing or a read that stops short is an error, never a shorter result, and nothing is
/// written after a short read.
#[tokio::test]
async fn yandex_360_truncated_rrset_listing_is_protocol() {
    let (mock, client) = setup().await;
    let record = r#"{"recordId":1,"type":"A","name":"www","address":"192.0.2.1","ttl":300}"#;
    let body = format!(r#"{{"records":[{record}],"page":1,"pages":1,"perPage":50,"total":2}}"#);
    let short = || Fault::on("GET", RECORDS).respond(200, body.clone());
    mock.faults().push(short());
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().push(short());
    let e = client
        .get_rrset(&zone(), &dn("www.example.org"), RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let set = rr("www.example.org", RecordType::A, None, &["192.0.2.2"]);
    mock.faults().push(short());
    let e = client
        .set_rrset(&zone(), &set, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().push(short());
    let e = client
        .delete_rrset(&zone(), &dn("www.example.org"), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(record_writes(&mock), 0);
}

/// Records at other names and other types at the same name are untouched by every operation:
/// a TXT and an AAAA at the name, a name below it, a relative name that repeats the zone, and
/// an A record at the apex next to an A set at a name.
#[tokio::test]
async fn yandex_360_record_operations_touch_only_their_rrset() {
    for form in [NameForm::Relative, NameForm::Absolute] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.set_name_form(form);
        let www = "www.example.org";
        control.insert_record("example.org", "www", "TXT", "foreign", 300);
        control.insert_fields(
            "example.org",
            "www",
            "AAAA",
            serde_json::json!({"address": "2001:db8::1"}),
            300,
        );
        for owner in ["x.www", "www.example.org.sub", "@", "ww"] {
            control.insert_fields(
                "example.org",
                owner,
                "A",
                serde_json::json!({"address": "192.0.2.1"}),
                300,
            );
        }
        let others = control.records();

        let set = rr(www, RecordType::A, None, &["192.0.2.1"]);
        assert_eq!(
            client
                .set_rrset(&zone(), &set, Expect::Absent)
                .await
                .unwrap(),
            SetOutcome::Created,
            "{form:?}"
        );
        let set = rr(www, RecordType::A, None, &["192.0.2.5", "192.0.2.6"]);
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
        let set = set.with_ttl(Some(RrsetTtl::from_secs(60).unwrap()));
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
        assert_eq!(
            client
                .get_rrset(&zone(), &dn(www), RecordType::A)
                .await
                .unwrap(),
            Some(set.clone()),
            "{form:?}"
        );
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
                .await
                .unwrap(),
            DeleteOutcome::Deleted,
            "{form:?}"
        );
        assert_eq!(control.records(), others, "{form:?}");
    }
}

/// A replacement creates the missing records before it deletes the surplus ones. A failure part
/// way leaves a superset of the old values, never a subset, and a repeat sends only the rest.
#[tokio::test]
async fn yandex_360_replacement_creates_before_it_deletes() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    for address in ["192.0.2.1", "192.0.2.2"] {
        control.insert_fields(
            "example.org",
            www,
            "A",
            serde_json::json!({ "address": address }),
            300,
        );
    }
    let wanted = rr(www, RecordType::A, None, &["192.0.2.3", "192.0.2.4"]);

    // The second create fails: the old values are all there, with the first new one.
    mock.faults()
        .push(Fault::on("POST", RECORDS).skip(1).status(502));
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(
        stored(&mock, www, "A"),
        ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    );
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 0);

    // The first delete fails (not repeated): every wanted value is published, one old one too.
    mock.faults().push(Fault::on("DELETE", RECORD).status(401));
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(
        stored(&mock, www, "A"),
        ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]
    );

    // The repeat converges, then nothing is left to do.
    mock.log().clear();
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.3", "192.0.2.4"]);
    assert_eq!(mock.log().count(Some("POST"), RECORDS), 0);
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 2);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );

    // The order of the requests of one replacement.
    mock.log().clear();
    let next = rr(www, RecordType::A, None, &["192.0.2.5"]);
    client.set_rrset(&zone(), &next, Expect::Any).await.unwrap();
    let methods: Vec<String> = mock
        .log()
        .entries()
        .into_iter()
        .filter(|r| r.method != "GET")
        .map(|r| format!("{} {}", r.method, r.path.matches('/').count()))
        .collect();
    assert_eq!(methods, ["POST 7", "DELETE 8", "DELETE 8"]);
}

/// A CNAME is replaced in place by one edit, never by a second record next to the first; a
/// record that went away before the edit is `Conflict`, and the repeat creates it.
#[tokio::test]
async fn yandex_360_cname_is_replaced_in_place() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let id = control.insert_fields(
        "example.org",
        "www",
        "CNAME",
        serde_json::json!({"target": "old.example.net."}),
        600,
    );
    let new = rr(www, RecordType::CNAME, None, &["new.example.net."]);
    assert_eq!(
        client.set_rrset(&zone(), &new, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    let records = control.records_at(www, "CNAME");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, id);
    assert_eq!(records[0].field("target"), Some("new.example.net."));
    assert_eq!(records[0].ttl, 600);
    let edit = mock.log().matching(Some("POST"), RECORD).pop().unwrap();
    assert_eq!(
        edit.path,
        format!("/directory/v1/org/7654321/domains/example.org/dns/{id}")
    );
    assert_eq!(
        edit.body_json().unwrap(),
        serde_json::json!({
            "type": "CNAME", "name": "www", "ttl": 600, "target": "new.example.net."
        })
    );
    assert_eq!(mock.log().count(Some("POST"), RECORDS), 0);
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 0);

    let hook = control.clone();
    mock.faults()
        .push(Fault::on("POST", RECORD).run(move || hook.delete_record(id)));
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
    assert_eq!(stored(&mock, www, "CNAME"), ["other.example.net."]);
}

/// Per-record TTLs (design section 3.6): a set whose records disagree reads with the smallest;
/// a value added without a TTL gets it and the others keep theirs; a requested TTL is set on
/// every record that lacks it by an edit that sends the record's own value; a delete of a record
/// already gone counts as done.
#[tokio::test]
async fn yandex_360_record_ttls() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    for (address, ttl) in [("192.0.2.1", 600), ("192.0.2.2", 300)] {
        control.insert_fields(
            "example.org",
            "www",
            "A",
            serde_json::json!({ "address": address }),
            ttl,
        );
    }
    let read = client
        .get_rrset(&zone(), &dn(www), RecordType::A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.ttl(), Some(RrsetTtl::from_secs(300).unwrap()));

    let three = rr(
        www,
        RecordType::A,
        None,
        &["192.0.2.1", "192.0.2.2", "192.0.2.3"],
    );
    client
        .set_rrset(&zone(), &three, Expect::Any)
        .await
        .unwrap();
    let ttls = |control: &zonewright_mock::yandex_360::Control| {
        let mut t: Vec<(String, u32)> = control
            .records_at(www, "A")
            .into_iter()
            .map(|r| (r.field("address").unwrap().to_owned(), r.ttl))
            .collect();
        t.sort();
        t
    };
    assert_eq!(
        ttls(control),
        [
            ("192.0.2.1".to_owned(), 600),
            ("192.0.2.2".to_owned(), 300),
            ("192.0.2.3".to_owned(), 300)
        ]
    );
    // Equal members without a TTL: unchanged, the disagreeing TTLs stay.
    let before = record_writes(&mock);
    assert_eq!(
        client
            .set_rrset(&zone(), &three, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    assert_eq!(record_writes(&mock), before);

    // A requested TTL: one edit, for the record that lacks it, with its own value.
    let uniform = three
        .clone()
        .with_ttl(Some(RrsetTtl::from_secs(300).unwrap()));
    mock.log().clear();
    assert_eq!(
        client
            .set_rrset(&zone(), &uniform, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let edits = mock.log().matching(Some("POST"), RECORD);
    assert_eq!(edits.len(), 1);
    assert_eq!(
        edits[0].body_json().unwrap(),
        serde_json::json!({"type": "A", "name": "www", "ttl": 300, "address": "192.0.2.1"})
    );
    assert!(ttls(control).iter().all(|(_, ttl)| *ttl == 300));
    assert_eq!(
        client
            .set_rrset(&zone(), &uniform, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );

    // A record deleted by someone else between the read and the delete.
    let id = control.records_at(www, "A")[0].id;
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("DELETE", RECORD).run(move || hook.delete_record(id)));
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(control.records_at(www, "A").is_empty());
}

/// The domain is deleted and created again, with the records under new identifiers, between
/// the read and the delete of an rrset: the delete is answered 404 while the values are still
/// published, so the result is `Conflict`, not `Deleted` (design sections 3.5 and 3.8). The
/// repeat reads the new identifiers and deletes. The same holds for the surplus record of a
/// replacement.
#[tokio::test]
async fn yandex_360_record_delete_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let set = rr(www, RecordType::A, None, &["192.0.2.1", "192.0.2.2"]);
    client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();

    let hook = control.clone();
    mock.faults()
        .push(Fault::on("DELETE", RECORD).run(move || hook.recreate_domain("example.org")));
    let e = client
        .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.1", "192.0.2.2"]);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(stored(&mock, www, "A").is_empty());

    // A replacement whose surplus delete meets the recreated domain.
    client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("DELETE", RECORD).run(move || hook.recreate_domain("example.org")));
    let fewer = rr(www, RecordType::A, None, &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &fewer, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.1", "192.0.2.2"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &fewer, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.1"]);
}

/// The domain's listing shows every record at the name, so a CNAME next to other data, or other
/// data next to a CNAME, is refused after the read and before any write (RFC 1034 section
/// 3.6.2). Data at other names does not count, and an unchanged CNAME is not a write.
#[tokio::test]
async fn yandex_360_cname_next_to_other_data_is_refused() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", "www", "A", "192.0.2.1", 300);
    control.insert_record("example.org", "alias", "CNAME", "target.example.net.", 300);
    let before = control.records();

    let cname = rr(
        "www.example.org",
        RecordType::CNAME,
        None,
        &["target.example.net."],
    );
    let e = client
        .set_rrset(&zone(), &cname, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    let a = rr("alias.example.org", RecordType::A, None, &["192.0.2.2"]);
    let e = client
        .set_rrset(&zone(), &a, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(record_writes(&mock), 0);
    assert_eq!(control.records(), before);

    // At names without the other kind of data the same writes go through.
    let cname = rr(
        "new.example.org",
        RecordType::CNAME,
        None,
        &["target.example.net."],
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &cname, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    let a = rr("www2.example.org", RecordType::A, None, &["192.0.2.2"]);
    assert_eq!(
        client.set_rrset(&zone(), &a, Expect::Any).await.unwrap(),
        SetOutcome::Created
    );
}

/// Two clients sharing a `Context` write one name at once, the first create delayed: the
/// second reads after the first wrote, so its `Expect::Absent` fails.
#[tokio::test]
async fn yandex_360_concurrent_record_writes_are_serialized() {
    let mock = Yandex360Mock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, TOKEN, &ctx);
    let b = client_with(&mock, TOKEN, &ctx);
    mock.faults()
        .push(Fault::on("POST", RECORDS).delay(Duration::from_millis(300)));
    let first = rr("www.example.org", RecordType::A, None, &["192.0.2.1"]);
    let second = rr("www.example.org", RecordType::A, None, &["192.0.2.2"]);
    let zone = zone();
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
    assert_eq!(mock.control().records_at("www.example.org", "A").len(), 1);
}

/// Creates and edits are sent once whatever the answer (502, 429, 401); the delete of one
/// record by its identifier is repeated after a 502 only.
#[tokio::test]
async fn yandex_360_record_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let set = rr(www, RecordType::A, None, &["192.0.2.1"]);
    for (fault, kind) in [
        (Fault::on("POST", RECORDS).status(502), ErrorKind::Transient),
        (
            Fault::on("POST", RECORDS).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("POST", RECORDS).status(401), ErrorKind::Auth),
    ] {
        mock.log().clear();
        mock.faults().push(fault);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(mock.log().count(Some("POST"), RECORDS), 1);
        assert!(control.records().is_empty());
    }
    client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
    let retuned = set
        .clone()
        .with_ttl(Some(RrsetTtl::from_secs(600).unwrap()));
    for (fault, kind) in [
        (Fault::on("POST", RECORD).status(502), ErrorKind::Transient),
        (
            Fault::on("POST", RECORD).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("POST", RECORD).status(401), ErrorKind::Auth),
    ] {
        mock.log().clear();
        mock.faults().push(fault);
        let e = client
            .set_rrset(&zone(), &retuned, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(edits(&mock), 1);
    }
    for (fault, kind) in [
        (
            Fault::on("DELETE", RECORD).rate_limited("120"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("DELETE", RECORD).status(401), ErrorKind::Auth),
    ] {
        mock.log().clear();
        mock.faults().push(fault);
        let e = client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(mock.log().count(Some("DELETE"), RECORD), 1);
    }
    mock.log().clear();
    mock.faults().push(Fault::on("DELETE", RECORD).status(502));
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 2);
}

/// The record-level requests as the sources describe them: the listing's paging, the create with
/// the type's fields and the name relative to the domain, `@` for the apex, an IDN name in
/// Punycode.
#[tokio::test]
async fn yandex_360_record_request_shapes() {
    let (mock, client) = setup().await;
    let posted = |set: RrSet| {
        let (client, mock) = (&client, &mock);
        async move {
            client
                .set_rrset(&zone(), &set, Expect::Absent)
                .await
                .unwrap();
            let post = mock.log().matching(Some("POST"), RECORDS).pop().unwrap();
            assert_eq!(
                post.path,
                "/directory/v1/org/7654321/domains/example.org/dns"
            );
            assert_eq!(post.header("authorization"), Some("OAuth test-only-token"));
            post.body_json().unwrap()
        }
    };
    use serde_json::json;
    assert_eq!(
        posted(rr(
            "example.org",
            RecordType::MX,
            None,
            &["10 mail.example.org."]
        ))
        .await,
        json!({
            "type": "MX", "name": "@", "ttl": 300, "exchange": "mail.example.org.",
            "preference": 10
        })
    );
    let get = mock.log().matching(Some("GET"), RECORDS).pop().unwrap();
    assert_eq!(get.query.as_deref(), Some("page=1&perPage=50"));
    assert_eq!(
        posted(rr(
            "example.org",
            RecordType::CAA,
            Some(3600),
            &["0 issue \"ca.example.net\""]
        ))
        .await,
        json!({
            "type": "CAA", "name": "@", "ttl": 3600, "flag": 0, "tag": "issue",
            "value": "\"ca.example.net\""
        })
    );
    assert_eq!(
        posted(rr(
            "_sip._udp.example.org",
            RecordType::SRV,
            None,
            &["1 2 3 sip.example.org."]
        ))
        .await,
        json!({
            "type": "SRV", "name": "_sip._udp", "ttl": 300, "target": "sip.example.org.",
            "priority": 1, "weight": 2, "port": 3
        })
    );
    assert_eq!(
        posted(rr(
            "bücher.example.org",
            RecordType::AAAA,
            None,
            &["2001:db8::5"]
        ))
        .await,
        json!({"type": "AAAA", "name": "xn--bcher-kva", "ttl": 300, "address": "2001:db8::5"})
    );
    assert_eq!(
        posted(rr("example.org", RecordType::TXT, None, &["\"v=1\""])).await,
        json!({"type": "TXT", "name": "@", "ttl": 300, "text": "v=1"})
    );
}

/// What the echo answers for each record-level request kind.
#[derive(Clone, Copy, Debug)]
enum RecordWrite {
    /// A create: no record at the name.
    Create,
    /// An edit in place: a CNAME at the name.
    Update,
    /// A delete: a TXT record at the name.
    Delete,
    /// The domain's record listing itself is the echo.
    List,
}

/// The record-level requests against an echo, for every dialect: the create, the edit, the
/// delete and the listing. No canary in any error or `Debug`, and the error shows the
/// redaction.
#[tokio::test]
async fn yandex_360_secret_echo_record_level() {
    // One server and one context for every case: each case reconfigures the server, and
    // every client reuses the context's pooled connection (see `EchoServer::reset`).
    let ctx = context();
    let echo = EchoServer::start(200).await;
    for dialect in dialects() {
        for (kind, statuses) in [
            (RecordWrite::Create, [400, 401, 403, 500].as_slice()),
            (RecordWrite::Update, [400, 401, 403, 500].as_slice()),
            // A 5xx to these idempotent requests is retried with real back-off sleeps; the 5xx
            // body is covered by the create and the edit.
            (RecordWrite::Delete, [400, 401, 403].as_slice()),
            (RecordWrite::List, [400, 401, 403].as_slice()),
        ] {
            for &status in statuses {
                let label = format!("{} {:?} {status} {kind:?}", dialect.name, dialect.spelling);
                let existing = match kind {
                    RecordWrite::Create | RecordWrite::List => Existing::Nothing,
                    RecordWrite::Update => Existing::Cname,
                    RecordWrite::Delete => Existing::Ours,
                };
                let mut config = dialect.echo(status);
                if !matches!(kind, RecordWrite::List) {
                    config = config.render_under(
                        "/directory",
                        listings_then(dialect.render.clone(), existing),
                    );
                }
                echo.reset(config);
                let client = echo_client(&echo, &ctx);
                let result = match kind {
                    RecordWrite::Create => {
                        let set = rr(NAME, RecordType::A, None, &["192.0.2.1"]);
                        client
                            .set_rrset(&zone(), &set, Expect::Any)
                            .await
                            .map(|o| format!("{o:?}"))
                    }
                    RecordWrite::Update => {
                        let set = rr(NAME, RecordType::CNAME, None, &["new.example.net."]);
                        client
                            .set_rrset(&zone(), &set, Expect::Any)
                            .await
                            .map(|o| format!("{o:?}"))
                    }
                    RecordWrite::Delete => client
                        .delete_rrset(&zone(), &name(), RecordType::TXT, Expect::Any)
                        .await
                        .map(|o| format!("{o:?}")),
                    RecordWrite::List => client
                        .list_rrsets(&zone())
                        .await
                        .map(|l| format!("{} rrsets", l.rrsets.len())),
                };
                let text = match result {
                    Ok(outcome) => panic!("{label}: the echo accepted the request: {outcome}"),
                    Err(e) => format!("{e} | {e:?} | {client:?}"),
                };
                assert!(
                    text.contains(REDACTED),
                    "{label}: the echo did not reach the error: {text}"
                );
                assert_clean(&label, &text, &[CANARY_TOKEN]);
                let (method, path) = match kind {
                    RecordWrite::Create => ("POST", RECORDS),
                    RecordWrite::Update => ("POST", RECORD),
                    RecordWrite::Delete => ("DELETE", RECORD),
                    RecordWrite::List => ("GET", RECORDS),
                };
                let reached = echo.log().count(Some(method), path);
                if matches!(kind, RecordWrite::List) {
                    assert!(reached >= 1, "{label}: the request did not reach the echo");
                } else {
                    assert_eq!(reached, 1, "{label}: the write did not reach the echo once");
                }
            }
        }
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
/// removes exactly the values it added afterwards, also when the body failed. The zone must be
/// delegated to Yandex.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_yandex_360_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_YANDEX_360_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_YANDEX_360_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_YANDEX_360_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::Yandex360,
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
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}

/// A record-level round trip on a name it creates under a generated label in the zone the
/// maintainer names: create, read, list, replace, change the TTL, delete, for an A set and an MX
/// set (which shows whether the API takes an exchange with its trailing dot). Afterwards it
/// deletes the A and MX rrsets at that name, which only this test wrote, also when the body
/// failed. The zone must be delegated to Yandex.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_yandex_360_record_round_trip() {
    let settings = live_env("ZONEWRIGHT_LIVE_YANDEX_360_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_YANDEX_360_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_YANDEX_360_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::Yandex360,
            &settings,
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap(),
    );
    let tag = random_u64();
    let name = zone.prepend(&format!("zw-live-{tag:016x}")).unwrap();
    let set = |rtype: RecordType, ttl: Option<u32>, texts: &[&str]| {
        RrSet::new(
            name.clone(),
            rtype,
            ttl.map(|t| RrsetTtl::from_secs(t).unwrap()),
            texts.iter().map(|t| rdata(rtype, t)),
        )
        .unwrap()
    };
    let first = set(RecordType::A, Some(300), &["192.0.2.1", "192.0.2.2"]);
    let second = set(RecordType::A, None, &["192.0.2.2", "192.0.2.3"]);
    let third = set(RecordType::A, Some(600), &["192.0.2.2", "192.0.2.3"]);
    let exchange = format!("10 mail.{}", zone.as_str());
    let mx = set(RecordType::MX, Some(300), &[&exchange]);

    let body = {
        let (client, zone, name, mx) = (client.clone(), zone.clone(), name.clone(), mx.clone());
        tokio::spawn(async move {
            assert_eq!(
                client
                    .set_rrset(&zone, &first, Expect::Absent)
                    .await
                    .unwrap(),
                SetOutcome::Created
            );
            let read = client.get_rrset(&zone, &name, RecordType::A).await.unwrap();
            assert_eq!(read.as_ref(), Some(&first));
            let listing = client.list_rrsets(&zone).await.unwrap();
            assert!(listing.rrsets.contains(&first), "{listing:?}");
            assert_eq!(
                client
                    .set_rrset(&zone, &second, Expect::Matches(&first))
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                client.set_rrset(&zone, &second, Expect::Any).await.unwrap(),
                SetOutcome::Unchanged
            );
            assert_eq!(
                client.set_rrset(&zone, &third, Expect::Any).await.unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                client.get_rrset(&zone, &name, RecordType::A).await.unwrap(),
                Some(third.clone())
            );
            assert_eq!(
                client
                    .delete_rrset(&zone, &name, RecordType::A, Expect::Matches(&third))
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
            assert_eq!(
                client.get_rrset(&zone, &name, RecordType::A).await.unwrap(),
                None
            );
            assert_eq!(
                client.set_rrset(&zone, &mx, Expect::Absent).await.unwrap(),
                SetOutcome::Created
            );
            assert_eq!(
                client
                    .get_rrset(&zone, &name, RecordType::MX)
                    .await
                    .unwrap(),
                Some(mx.clone())
            );
            assert_eq!(
                client
                    .delete_rrset(&zone, &name, RecordType::MX, Expect::Matches(&mx))
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
        })
    };
    let outcome = body.await;

    // Cleanup: the A and MX rrsets at the generated name, which nothing but this test wrote.
    let mut cleanup = Vec::new();
    for rtype in [RecordType::A, RecordType::MX] {
        if let Err(e) = client.delete_rrset(&zone, &name, rtype, Expect::Any).await {
            cleanup.push(format!("{rtype}: {e}"));
        }
    }
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}

// ---- Name forms (relative, full, lookalike) ------------------------------------------------------

/// An A record whose relative name repeats the zone (owner `www.example.org.example.org`), next
/// to an MX record stated as `@`, which proves that the listing states names relative to the
/// zone. Returns the lookalike's identifier.
fn lookalike_in_relative_listing(mock: &Yandex360Mock) -> u64 {
    let control = mock.control();
    control.insert_fields(
        "example.org",
        "@",
        "MX",
        serde_json::json!({"exchange": "mx.example.net.", "preference": 10}),
        300,
    );
    control.insert_relative(
        "example.org",
        "www.example.org",
        "A",
        serde_json::json!({"address": "192.0.2.9"}),
        300,
    )
}

/// In a listing that states names relative to the zone, a record whose name repeats the zone
/// belongs to the name below it: get, set, delete and the zone listing at `www.example.org`
/// neither see nor touch it, and it is read back at its own name.
#[tokio::test]
async fn yandex_360_lookalike_name_is_its_own_rrset() {
    let (mock, client) = setup().await;
    let lookalike = lookalike_in_relative_listing(&mock);
    let www = dn("www.example.org");
    let deep = dn("www.example.org.example.org");
    assert_eq!(
        client
            .get_rrset(&zone(), &www, RecordType::A)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        client
            .get_rrset(&zone(), &deep, RecordType::A)
            .await
            .unwrap(),
        Some(rr(
            &deep.to_string(),
            RecordType::A,
            Some(300),
            &["192.0.2.9"]
        ))
    );
    assert_eq!(
        client
            .delete_rrset(&zone(), &www, RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
    assert_eq!(record_writes(&mock), 0);
    let set = rr("www.example.org", RecordType::A, Some(300), &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &set, Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.skipped.is_empty(), "{:?}", listing.skipped);
    assert!(listing.rrsets.contains(&set), "{:?}", listing.rrsets);
    let theirs = rr(&deep.to_string(), RecordType::A, Some(300), &["192.0.2.9"]);
    assert!(listing.rrsets.contains(&theirs), "{:?}", listing.rrsets);
    assert_eq!(
        client
            .delete_rrset(&zone(), &www, RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    let left: Vec<u64> = mock
        .control()
        .records()
        .iter()
        .filter(|r| r.rtype == "A")
        .map(|r| r.id)
        .collect();
    assert_eq!(left, [lookalike]);
}

/// The TXT value operations follow the same rule: a TXT record whose relative name repeats the
/// zone, holding our value, is not ours; the add creates our own, and the removes never delete
/// the lookalike.
#[tokio::test]
async fn yandex_360_txt_lookalike_name_is_not_ours() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_fields(
        "example.org",
        "@",
        "MX",
        serde_json::json!({"exchange": "mx.example.net.", "preference": 10}),
        300,
    );
    let lookalike = control.insert_relative(
        "example.org",
        "_acme-challenge.example.org",
        "TXT",
        serde_json::json!({"text": "AAA"}),
        300,
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    let txt: Vec<u64> = control
        .records()
        .iter()
        .filter(|r| r.rtype == "TXT")
        .map(|r| r.id)
        .collect();
    assert_eq!(txt, [lookalike]);
}

/// A listing in which every dotless name is also a name within the zone does not say whether
/// its names are relative or full. A record whose name reads as the operated name in one form
/// is then refused with `Protocol` before any write, for every operation that matches records
/// to that name; the zone listing reports it in `skipped` and never places it at a guessed
/// name. An operation on a name neither reading gives is unaffected.
#[tokio::test]
async fn yandex_360_ambiguous_names_are_refused_not_guessed() {
    // A relative name that repeats the zone, alone: it cannot be told from a full name.
    let (mock, client) = setup().await;
    mock.control().insert_relative(
        "example.org",
        "www.example.org",
        "A",
        serde_json::json!({"address": "192.0.2.9"}),
        300,
    );
    let before = mock.control().records();
    let set = rr("www.example.org", RecordType::A, Some(300), &["192.0.2.1"]);
    for owner in ["www.example.org", "www.example.org.example.org"] {
        let e = client
            .get_rrset(&zone(), &dn(owner), RecordType::A)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{owner} {e:?}");
        let e = client
            .delete_rrset(&zone(), &dn(owner), RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{owner} {e:?}");
    }
    for expect in [Expect::Any, Expect::Absent] {
        let e = client.set_rrset(&zone(), &set, expect).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    }
    assert_eq!(
        client
            .get_rrset(&zone(), &dn("mail.example.org"), RecordType::A)
            .await
            .unwrap(),
        None
    );
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.rrsets.is_empty(), "{:?}", listing.rrsets);
    let skipped: Vec<_> = listing
        .skipped
        .iter()
        .map(|s| (s.name.to_string(), s.type_name.clone(), s.reason))
        .collect();
    assert_eq!(
        skipped,
        [(
            "example.org.".to_owned(),
            "A".to_owned(),
            SkipReason::UnsupportedName
        )]
    );
    assert_eq!(record_writes(&mock), 0);
    assert_eq!(mock.control().records(), before);

    // Full names without a trailing dot: the same, for the record level and the TXT values,
    // the apex included. Stated relative, the same records are placed.
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_name_form(NameForm::Full);
    control.insert_fields(
        "example.org",
        "www",
        "A",
        serde_json::json!({"address": "192.0.2.1"}),
        300,
    );
    control.insert_record("example.org", "@", "TXT", "foreign", 300);
    control.insert_record("example.org", NAME, "TXT", "AAA", 300);
    let before = control.records();
    let e = client
        .get_rrset(&zone(), &dn("www.example.org"), RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    for e in [
        add(&client, "AAA").await.unwrap_err(),
        add(&client, "BBB").await.unwrap_err(),
    ] {
        assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    }
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let e = client
        .remove_txt_value(&zone(), &zone(), &txt("foreign"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.rrsets.is_empty(), "{:?}", listing.rrsets);
    // One per stated name and type: two TXT names and one A name.
    assert_eq!(listing.skipped.len(), 3, "{:?}", listing.skipped);
    assert!(
        listing
            .skipped
            .iter()
            .all(|s| s.reason == SkipReason::UnsupportedName && s.name == zone())
    );
    assert_eq!(writes(&mock) + record_writes(&mock), 0);
    assert_eq!(control.records(), before);
    control.set_name_form(NameForm::Relative);
    assert_eq!(
        client
            .get_rrset(&zone(), &dn("www.example.org"), RecordType::A)
            .await
            .unwrap(),
        Some(rr(
            "www.example.org",
            RecordType::A,
            Some(300),
            &["192.0.2.1"]
        ))
    );
}

/// A listing whose `total` changes between pages may have passed over a record: an error, not
/// a shorter listing.
#[tokio::test]
async fn yandex_360_listing_whose_total_changes_is_protocol() {
    let (mock, client) = setup().await;
    let record = |id: u32, name: &str| {
        format!(r#"{{"recordId":{id},"type":"A","name":"{name}","address":"192.0.2.1","ttl":300}}"#)
    };
    let first = format!(
        r#"{{"records":[{},{}],"page":1,"pages":2,"perPage":2,"total":3}}"#,
        record(1, "a"),
        record(2, "b")
    );
    let second = r#"{"records":[],"page":2,"pages":2,"perPage":2,"total":2}"#;
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(200, first));
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(200, second));
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}
