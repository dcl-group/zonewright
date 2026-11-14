//! Tests of the Timeweb Cloud client (`timeweb_cloud`) against its mock.
#![cfg(feature = "timeweb_cloud")]
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
use zonewright::providers::timeweb_cloud::{
    TimewebCloud, TimewebCloudConfig, TimewebCloudCredentials,
};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RemoveOutcome, RrSet, Ttl, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::echo::{EchoServer, Echoed, Render};
use zonewright_mock::timeweb_cloud::{Seed, SubdomainForm, TimewebCloudMock};

use common::echo::{CANARY_KEY, CANARY_TOKEN, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The token of the standard seed.
const TOKEN: &str = "test-only-token";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths: the listings (`v1`), the create and the delete (`v2`).
const DOMAINS: &str = "/api/v1/domains";
const RECORDS: &str = "/api/v1/domains/*/dns-records";
const CREATE: &str = "/api/v2/domains/*/dns-records";
const RECORD: &str = "/api/v2/domains/*/dns-records/*";

/// The listing of [`NAME`] and the listing of the zone, as paths.
const NAME_LISTING: &str = "/api/v1/domains/_acme-challenge.example.org/dns-records";
const ZONE_LISTING: &str = "/api/v1/domains/example.org/dns-records";

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
fn settings(base_url: String) -> TimewebCloudConfig {
    let mut config = TimewebCloudConfig::default();
    config.base_url = base_url;
    config
}

fn credentials(token: &str) -> TimewebCloudCredentials {
    TimewebCloudCredentials::new(SecretString::from(token.to_owned()))
}

fn client_with(mock: &TimewebCloudMock, token: &str, ctx: &Context) -> TimewebCloud {
    TimewebCloud::new(settings(mock.base_url()), credentials(token), ctx).unwrap()
}

async fn setup() -> (TimewebCloudMock, TimewebCloud) {
    let mock = TimewebCloudMock::start(Seed::standard()).await;
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
fn writes(mock: &TimewebCloudMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), CREATE) + log.count(Some("DELETE"), RECORD)
}

/// The settings JSON of `from_json` for `mock`.
fn settings_json(mock: &TimewebCloudMock) -> String {
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

assert_not_impl!(TimewebCloud: std::fmt::Display, serde::Serialize);
assert_not_impl!(TimewebCloudCredentials: std::fmt::Display, serde::Serialize);

/// What the echo's listings answer: no record, a record with a foreign value, or a record with
/// the value `v1`.
#[derive(Clone, Copy)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
}

/// A page of listing answers in the documented shape.
fn page(key: &str, items: serde_json::Value) -> Render {
    let count = items.as_array().map_or(0, Vec::len);
    let body = serde_json::json!({ "meta": {"total": count}, key: items });
    Arc::new(move |_: &Echoed| (StatusCode::OK, axum::Json(body.clone())).into_response())
}

/// A renderer that answers the reads named by `normal` like the API and every other request
/// with `errors`. `normal` has the `GET` paths: the domain listing (`domains`), and the record
/// listing, which `existing` fills.
fn answering(errors: Render, domains: bool, records: Option<Existing>) -> Render {
    let domain_page = page(
        "domains",
        serde_json::json!([{"id": 1, "fqdn": "example.org"}]),
    );
    let record_page = |existing: Existing| {
        let items = match existing {
            Existing::Nothing => serde_json::json!([]),
            Existing::Foreign => serde_json::json!([{
                "id": 1001, "type": "TXT", "ttl": 60,
                "data": {"subdomain": "_acme-challenge", "value": "foreign"}
            }]),
            Existing::Ours => serde_json::json!([{
                "id": 1001, "type": "TXT", "ttl": 60,
                "data": {"subdomain": "_acme-challenge", "value": "v1"}
            }]),
        };
        page("dns_records", items)
    };
    let record_page = records.map(record_page);
    Arc::new(move |e: &Echoed| {
        if e.method == Method::GET {
            if domains && e.path.ends_with("/v1/domains") {
                return domain_page(e);
            }
            if let Some(records) = &record_page
                && e.path.ends_with("/dns-records")
            {
                return records(e);
            }
        }
        errors(e)
    })
}

fn echo_client(echo: &EchoServer) -> TimewebCloud {
    let config = settings(echo.url("/api"));
    TimewebCloud::new(config, credentials(CANARY_TOKEN), &context()).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Write {
    Add,
    Remove,
}

/// `check` and a write against an echo that quotes every request back: no canary in any error,
/// `ZoneCheck::detail` or `Debug`, and the write's error shows the redaction.
async fn echo_round(label: &str, client: &TimewebCloud, write: Write) {
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

/// `check` and the writes against an echo, for every dialect. Five kinds of request reach it: the
/// domain listing (the credentials probe and `list_zones`), the zone read of `check`, the record
/// listing, the create and the delete.
#[tokio::test]
async fn timeweb_cloud_secret_echo() {
    for dialect in dialects() {
        // The credentials probe is the echo.
        for status in [400, 401] {
            let label = format!("{} {:?} {status} probe", dialect.name, dialect.spelling);
            let echo = dialect.echo(status).start().await;
            let client = echo_client(&echo);
            echo_round(&label, &client, Write::Add).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
            let e = client.list_zones().await.unwrap_err();
            assert_clean(&label, &format!("{e} | {e:?}"), &[CANARY_TOKEN]);
        }
        // The probe is answered; the zone read is the echo.
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} zone", dialect.name, dialect.spelling);
            let echo = dialect
                .echo(status)
                .render(answering(dialect.render.clone(), true, None))
                .start()
                .await;
            let client = echo_client(&echo);
            let e = client.check(&[zone()]).await.unwrap_err();
            let text = format!("{e} | {e:?} | {client:?}");
            assert_clean(&label, &text, &[CANARY_TOKEN]);
            assert!(
                echo.log().count(Some("GET"), RECORDS) > 0,
                "{label}: the zone read did not reach the echo"
            );
        }
        // The listings answer normally, so the write itself reaches the echo: a create (with
        // and without a foreign record at the name) and a delete. A 500 to an idempotent read
        // is retried with real back-off sleeps, which adds seconds per dialect without
        // coverage: the reads never get it, and neither does the delete.
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
                let echo = dialect
                    .echo(status)
                    .render(answering(dialect.render.clone(), true, Some(existing)))
                    .start()
                    .await;
                let client = echo_client(&echo);
                echo_round(&label, &client, write).await;
                let (method, path) = match write {
                    Write::Add => ("POST", CREATE),
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
async fn timeweb_cloud_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.token = CANARY_TOKEN.into();
    let mock = TimewebCloudMock::start(seed).await;
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

    mock.faults().push(Fault::on("POST", CREATE).status(500));
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
            "timeweb_cloud logs and errors",
            text,
            &[CANARY_TOKEN, CANARY_KEY],
        );
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely ends
/// with the zone's text, the zone's text inside another name, and a sibling zone.
#[tokio::test]
async fn timeweb_cloud_name_outside_zone_sends_nothing() {
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
async fn timeweb_cloud_invalid_input_sends_nothing() {
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
async fn timeweb_cloud_add_is_idempotent() {
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
    assert_eq!(mock.log().count(Some("POST"), CREATE), 2);
    assert_eq!(mock.control().txt_values(NAME), ["AAA", "BBB"]);
}

/// Removing an absent value next to foreign ones writes nothing; adding and removing our value
/// leaves the foreign records and their TTLs as they were. A single foreign value is never a
/// reason to delete anything.
#[tokio::test]
async fn timeweb_cloud_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "foreign-1", Some(600));
    control.insert_record("example.org", NAME, "TXT", "foreign-2", Some(900));
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
    let ours_id = original.len();
    let deletes = mock.log().matching(Some("DELETE"), RECORD);
    assert_eq!(deletes.len(), 1);
    assert!(
        original
            .iter()
            .all(|r| !deletes[0].path.ends_with(&format!("/{}", r.id))),
        "{ours_id}: the delete named a foreign record"
    );

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_record("example.org", other, "TXT", "foreign", Some(60));
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
async fn timeweb_cloud_other_types_at_the_name_are_untouched() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "A", "192.0.2.1", Some(300));
    control.insert_record("example.org", NAME, "CNAME", "AAA", Some(300));
    control.insert_record("example.org", "other.example.org", "TXT", "AAA", Some(300));
    let original = control.records();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(control.records(), original);
}

#[tokio::test]
async fn timeweb_cloud_remove_last_value_deletes_rrset() {
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
async fn timeweb_cloud_remove_is_idempotent() {
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
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 2);
}

/// Every record with the value is removed (a duplicate made by a writer outside the process),
/// and nothing else.
#[tokio::test]
async fn timeweb_cloud_remove_deletes_every_copy_of_the_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "AAA", Some(60));
    control.insert_record("example.org", NAME, "TXT", "foreign", Some(60));
    control.insert_record("example.org", NAME, "TXT", "AAA", Some(60));
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
async fn timeweb_cloud_concurrent_adds_are_serialized() {
    let mock = TimewebCloudMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, TOKEN, &ctx);
    let b = client_with(&mock, TOKEN, &ctx);
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
async fn timeweb_cloud_foreign_value_added_between_read_and_write_survives() {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    mock.faults().push(Fault::on("POST", CREATE).run(move || {
        hook.insert_record("example.org", NAME, "TXT", "foreign", Some(600));
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
    assert_eq!(mock.control().records()[0].ttl, Some(600));
}

/// The domain is deleted and created again between the read and the delete: the delete is
/// answered 404, and the removal never reports success for a value that is still published. A
/// record that is gone for another reason is a success.
#[tokio::test]
async fn timeweb_cloud_delete_not_found_reads_again() {
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
async fn timeweb_cloud_unsupported_operations_send_nothing() {
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
async fn timeweb_cloud_writes_are_sent_once() {
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

    mock.faults().push(Fault::on("POST", CREATE).status(401));
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
                hook.insert_record("example.org", NAME, "TXT", "AAA", Some(60));
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
    mock.faults().push(Fault::on("POST", CREATE).respond(
        400,
        r#"{"status_code":400,"error_code":"bad_request","message":"refused","response_id":"r"}"#,
    ));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(posts(), 5);
}

/// The delete of one record by its identifier is the one write that is repeated: a 502 is
/// retried, and a retry that finds the record gone is a success. A rate limit with a long wait
/// and a rejected token are not repeated.
#[tokio::test]
async fn timeweb_cloud_delete_by_id_is_retried() {
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

// ---- Names and subdomains ----------------------------------------------------------------------

/// The client keeps no memory: a client of another context removes a record it did not create,
/// found in the listing of the name.
#[tokio::test]
async fn timeweb_cloud_a_client_of_another_context_removes_the_record() {
    let mock = TimewebCloudMock::start(Seed::standard()).await;
    let a = client_with(&mock, TOKEN, &context());
    add(&a, "AAA").await.unwrap();
    let b = client_with(&mock, TOKEN, &context());
    assert_eq!(
        remove(&b, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().records().is_empty());
}

/// The API changes a record in place under the same identifier. A record this process created
/// and someone else then changed to another value is not ours any more and is not deleted.
#[tokio::test]
async fn timeweb_cloud_a_record_changed_in_place_is_not_removed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "AAA").await.unwrap();
    let id = control.records()[0].id;
    control.update_record(id, "foreign");
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 0);
    assert_eq!(control.txt_values(NAME), ["foreign"]);
}

/// A name that is not a subdomain yet: its listing is answered 404, the zone is looked up and
/// exists, so the name has no records. An add creates the record at the name; a removal sends no
/// write.
#[tokio::test]
async fn timeweb_cloud_a_name_that_is_not_a_subdomain_yet_has_no_records() {
    let (mock, client) = setup().await;
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    let paths: Vec<_> = mock
        .log()
        .matching(Some("GET"), RECORDS)
        .iter()
        .map(|r| (r.path.clone(), r.query.clone().unwrap()))
        .collect();
    assert_eq!(
        paths,
        [
            (NAME_LISTING.to_owned(), "limit=100&offset=0".to_owned()),
            (ZONE_LISTING.to_owned(), "limit=1&offset=0".to_owned()),
        ]
    );
    assert!(mock.control().subdomains().is_empty());
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.control().subdomains(), [NAME]);
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);
}

/// The provider refuses a create at a name it does not take as a subdomain: the zone exists, so
/// the refusal is the operation's error, with the provider's status; it is not repeated and
/// nothing is written. When the zone is gone too, the error is `ZoneNotFound`.
#[tokio::test]
async fn timeweb_cloud_a_create_answered_not_found_is_told_apart() {
    let (mock, client) = setup().await;
    mock.control().set_require_subdomain(true);
    let e = add(&client, "AAA").await.unwrap_err();
    match &e {
        Error::Rejected { status, .. } => assert_eq!(*status, Some(404)),
        other => panic!("{other:?}"),
    }
    assert_eq!(mock.log().count(Some("POST"), CREATE), 1);
    assert!(mock.control().records().is_empty());

    // The domain is deleted between the read and the create.
    mock.faults().push(Fault::on("POST", CREATE).status(404));
    mock.faults()
        .push(Fault::on("GET", ZONE_LISTING).skip(1).status(404));
    let e = add(&client, "AAA").await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    assert_eq!(mock.log().count(Some("POST"), CREATE), 2);
}

/// The listing of a name below the zone that states a record without a name cannot say whether
/// the record is at that name or at the zone itself: the operation fails and writes nothing.
/// The same record in the listing of the zone is at the zone.
#[tokio::test]
async fn timeweb_cloud_a_subdomain_listing_without_names_is_protocol() {
    let (mock, client) = setup().await;
    for stated in ["null", r#""""#, r#""@""#] {
        let body = format!(
            r#"{{"meta":{{"total":1}},"dns_records":[{{"id":7,"type":"TXT","ttl":60,"data":{{"subdomain":{stated},"value":"AAA"}}}}]}}"#
        );
        mock.faults()
            .push(Fault::on("GET", NAME_LISTING).respond(200, body.clone()));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{stated}: {e:?}");
        mock.faults()
            .push(Fault::on("GET", NAME_LISTING).respond(200, body.clone()));
        let e = remove(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{stated}: {e:?}");
        assert_eq!(writes(&mock), 0);

        mock.faults()
            .push(Fault::on("GET", ZONE_LISTING).respond(200, body.clone()));
        assert_eq!(
            client
                .add_txt_value(&zone(), &zone(), &txt("AAA"), None)
                .await
                .unwrap(),
            AddOutcome::AlreadyPresent,
            "{stated}"
        );
    }
}

// ---- Requests, names and TTLs ------------------------------------------------------------------

/// The requests as the documentation and lego describe them: the token in `Authorization`, the
/// listing of the name with its paging, the `v2` create at the name with `type` and `value` and
/// nothing else, the `v2` delete by identifier at the name. The apex is written at the domain.
/// The deprecated `v1` writes are never sent.
#[tokio::test]
async fn timeweb_cloud_request_shapes() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let log = mock.log();
    let list = log.matching(Some("GET"), RECORDS).remove(0);
    assert_eq!(list.path, NAME_LISTING);
    assert_eq!(list.query.as_deref(), Some("limit=100&offset=0"));
    assert_eq!(list.header("authorization"), Some("Bearer test-only-token"));
    let post = log.matching(Some("POST"), CREATE).pop().unwrap();
    assert_eq!(
        post.path,
        "/api/v2/domains/_acme-challenge.example.org/dns-records"
    );
    assert_eq!(post.header("authorization"), Some("Bearer test-only-token"));
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({ "type": "TXT", "value": "AAA" })
    );
    let id = mock.control().records()[0].id;
    remove(&client, "AAA").await.unwrap();
    let delete = log.matching(Some("DELETE"), RECORD).pop().unwrap();
    assert_eq!(
        delete.path,
        format!("/api/v2/domains/_acme-challenge.example.org/dns-records/{id}")
    );
    assert!(delete.body.is_empty());

    client
        .add_txt_value(&zone(), &zone(), &txt("AAA"), None)
        .await
        .unwrap();
    let list = log.matching(Some("GET"), RECORDS).pop().unwrap();
    assert_eq!(list.path, ZONE_LISTING);
    let post = log.matching(Some("POST"), CREATE).pop().unwrap();
    assert_eq!(post.path, "/api/v2/domains/example.org/dns-records");
    let id = mock.control().records()[0].id;
    client
        .remove_txt_value(&zone(), &zone(), &txt("AAA"))
        .await
        .unwrap();
    let delete = log.matching(Some("DELETE"), RECORD).pop().unwrap();
    assert_eq!(
        delete.path,
        format!("/api/v2/domains/example.org/dns-records/{id}")
    );
    assert!(mock.control().records().is_empty());

    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        assert_eq!(log.count(Some(method), "/api/v1/**"), 0, "{method}");
    }
}

/// Records are read back whatever the form of the stated name: relative, or the full name. The
/// apex is the zone's own name.
#[tokio::test]
async fn timeweb_cloud_names_in_either_form() {
    for form in [SubdomainForm::Relative, SubdomainForm::Full] {
        let (mock, client) = setup().await;
        mock.control().set_subdomain_form(form);
        for (owner, stored) in [(zone(), ""), (name(), "_acme-challenge")] {
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
                    .any(|r| r.subdomain == stored && r.value == "AAA"),
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

/// The listing has no filter: neighbors (`x.<name>`, `<name>.x`, the same label in another
/// zone-level position) come with it and are skipped, so a value of a neighbor is neither taken
/// for ours nor removed.
#[tokio::test]
async fn timeweb_cloud_exact_name_match_skips_neighbors() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record(
        "example.org",
        "x._acme-challenge.example.org",
        "TXT",
        "AAA",
        Some(60),
    );
    control.insert_record(
        "example.org",
        "_acme-challenge.example.org.sub",
        "TXT",
        "AAA",
        Some(60),
    );
    control.insert_record("example.org", "_acme-challenge", "A", "192.0.2.1", Some(60));
    control.insert_record("example.org", "example.org", "TXT", "AAA", Some(60));
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

/// No TTL is sent unless one is given or configured; the TTL of a new record is the caller's,
/// else the configured one; a value added to an existing set gets the set's TTL as read (the
/// smallest), whatever the caller asks.
#[tokio::test]
async fn timeweb_cloud_ttl_policy() {
    let mock = TimewebCloudMock::start(Seed::standard()).await;
    let plain = client_with(&mock, TOKEN, &context());
    let mut config = settings(mock.base_url());
    config.ttl = Some(120);
    let configured = TimewebCloud::new(config, credentials(TOKEN), &context()).unwrap();
    let ttl = |name: &str| mock.control().txt_records(name)[0].ttl;
    let on = |label: &str| dn(&format!("{label}.example.org"));

    plain
        .add_txt_value(&zone(), &on("a"), &txt("v"), None)
        .await
        .unwrap();
    assert_eq!(ttl("a.example.org"), None);
    let post = mock.log().matching(Some("POST"), CREATE).pop().unwrap();
    assert!(post.body_json().unwrap().get("ttl").is_none());

    configured
        .add_txt_value(&zone(), &on("b"), &txt("v"), None)
        .await
        .unwrap();
    assert_eq!(ttl("b.example.org"), Some(120));
    configured
        .add_txt_value(
            &zone(),
            &on("c"),
            &txt("v"),
            Some(Ttl::from_secs(300).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(ttl("c.example.org"), Some(300));

    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "foreign-1", Some(900));
    control.insert_record("example.org", NAME, "TXT", "foreign-2", Some(600));
    configured
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
        .find(|r| r.value == "ours")
        .unwrap();
    assert_eq!(ours.ttl, Some(600));
}

/// A record whose TTL the API does not state gets a create without a TTL when it joins an
/// existing name, even with a configured TTL, so the provider decides.
#[tokio::test]
async fn timeweb_cloud_unreported_ttl_is_not_invented() {
    let mock = TimewebCloudMock::start(Seed::standard()).await;
    let mut config = settings(mock.base_url());
    config.ttl = Some(120);
    let client = TimewebCloud::new(config, credentials(TOKEN), &context()).unwrap();
    mock.control()
        .insert_record("example.org", NAME, "TXT", "foreign", None);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    let post = mock.log().matching(Some("POST"), CREATE).pop().unwrap();
    assert!(post.body_json().unwrap().get("ttl").is_none());
}

/// Identifiers as whole floats are read and are deleted by their integer form; a record listed
/// without an identifier is never deleted, and the removal says why.
#[tokio::test]
async fn timeweb_cloud_identifiers_in_the_listing() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_float_ids(true);
    add(&client, "AAA").await.unwrap();
    let id = control.records()[0].id;
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    let delete = mock.log().matching(Some("DELETE"), RECORD).pop().unwrap();
    assert_eq!(
        delete.path,
        format!("/api/v2/domains/_acme-challenge.example.org/dns-records/{id}")
    );

    control.set_float_ids(false);
    let nameless = control.insert_record("example.org", NAME, "TXT", "BBB", Some(60));
    control.set_null_id(nameless);
    let before = mock.log().count(Some("DELETE"), RECORD);
    let e = remove(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), before);
    assert_eq!(control.txt_values(NAME), ["BBB"]);
    // The value is still seen, so it is not added again.
    assert_eq!(
        add(&client, "BBB").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
}

// ---- Listings ----------------------------------------------------------------------------------

/// Pages are fetched by offset until the total is reached. A value on the last page is found,
/// and a record with the value on a later page than a foreign one is the one removed.
#[tokio::test]
async fn timeweb_cloud_listing_pages_by_offset() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_page_cap(1);
    control.insert_record("example.org", NAME, "TXT", "foreign-1", Some(60));
    control.insert_record("example.org", NAME, "TXT", "foreign-2", Some(60));
    control.insert_record("example.org", NAME, "TXT", "AAA", Some(60));
    control.insert_record("example.org", &format!("x.{NAME}"), "TXT", "AAA", Some(60));
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    let gets = mock.log().matching(Some("GET"), RECORDS);
    let queries: Vec<_> = gets.iter().map(|r| r.query.clone().unwrap()).collect();
    assert_eq!(
        queries,
        [
            "limit=100&offset=0",
            "limit=100&offset=1",
            "limit=100&offset=2",
            "limit=100&offset=3"
        ]
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt_values(NAME), ["foreign-1", "foreign-2"]);
    assert_eq!(control.txt_values(&format!("x.{NAME}")), ["AAA"]);
}

/// A listing that stops short of the total it states, lacks the total or the list, or has an
/// empty page before its end is an error, never a shorter result; nothing is written after it.
#[tokio::test]
async fn timeweb_cloud_truncated_listing_is_protocol() {
    let (mock, client) = setup().await;
    let record = r#"{"id":1,"type":"TXT","ttl":60,"data":{"subdomain":"_acme-challenge","value":"foreign"}}"#;
    for body in [
        // Ends before the total.
        format!(r#"{{"meta":{{"total":3}},"dns_records":[{record}]}}"#),
        // No total.
        format!(r#"{{"dns_records":[{record}]}}"#),
        format!(r#"{{"meta":{{}},"dns_records":[{record}]}}"#),
        // No list.
        r#"{"meta":{"total":0}}"#.to_owned(),
        r#"{"meta":{"total":0},"dns_records":null}"#.to_owned(),
        // A record without its type.
        r#"{"meta":{"total":1},"dns_records":[{"id":1,"data":{"value":"x"}}]}"#.to_owned(),
        // An empty page before the end.
        r#"{"meta":{"total":1},"dns_records":[]}"#.to_owned(),
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
    let zones = r#"{"meta":{"total":3},"domains":[{"fqdn":"example.org"}]}"#;
    mock.faults()
        .push(Fault::on("GET", DOMAINS).respond(200, zones));
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

#[tokio::test]
async fn timeweb_cloud_list_zones_pages_by_offset() {
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
    let queries: Vec<_> = mock
        .log()
        .matching(Some("GET"), DOMAINS)
        .iter()
        .map(|r| r.query.clone().unwrap())
        .collect();
    assert_eq!(
        queries,
        [
            "limit=100&offset=0",
            "limit=100&offset=1",
            "limit=100&offset=2"
        ]
    );
}

/// A listing with more records than one page is read in full by a client that never saw the
/// records created: the identifiers come from the listing.
#[tokio::test]
async fn timeweb_cloud_a_new_client_finds_the_records_in_a_long_listing() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for i in 0..7 {
        control.insert_record("example.org", &format!("n{i}.{NAME}"), "TXT", "x", Some(60));
    }
    control.set_page_cap(3);
    add(&client, "AAA").await.unwrap();
    let again = client_with(&mock, TOKEN, &context());
    assert_eq!(
        add(&again, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        remove(&again, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.txt_values(NAME).is_empty());
    assert_eq!(control.records().len(), 7);
}

// ---- check -------------------------------------------------------------------------------------

/// `check` reads the account's domains on every call, so a token revoked in between is noticed,
/// and looks every zone up afresh.
#[tokio::test]
async fn timeweb_cloud_check_exercises_the_credentials() {
    let (mock, client) = setup().await;
    let report = client.check(&[zone(), dn("missing.test")]).await.unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones[0].found && report.zones[0].detail.is_none());
    assert!(!report.zones[1].found);
    client.check(&[]).await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), DOMAINS), 2);
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 2);

    // The credentials probe is refused: no zone is asked for.
    mock.faults().push(Fault::on("GET", DOMAINS).status(401));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    mock.faults().push(Fault::on("GET", DOMAINS).status(403));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    // Another refusal of the probe is the provider's refusal with its message, not an answer in
    // an unexpected form.
    mock.faults().push(Fault::on("GET", DOMAINS).respond(
        400,
        r#"{"status_code":400,"error_code":"bad_request","message":["refused","twice"],"response_id":"r"}"#,
    ));
    let e = client.check(&[zone()]).await.unwrap_err();
    match &e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(*status, Some(400));
            assert_eq!(detail.as_str(), "bad_request: refused; twice");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 2);
    // An answer to the probe that is not a listing is not a success.
    mock.faults()
        .push(Fault::on("GET", DOMAINS).respond(200, r#"{"ok":true}"#));
    let e = client.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    // The same for the zone read.
    mock.faults().push(Fault::on("GET", RECORDS).respond(
        400,
        r#"{"status_code":400,"error_code":"bad_request","message":"refused","response_id":"r"}"#,
    ));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");

    let wrong = client_with(&mock, "wrong-token", &context());
    let e = wrong.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(!format!("{e} {e:?} {wrong:?}").contains("wrong-token"));
}

// ---- Errors ------------------------------------------------------------------------------------

#[tokio::test]
async fn timeweb_cloud_zone_not_found() {
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
    // The zone itself as the name: no second lookup.
    let before = mock.log().count(Some("GET"), RECORDS);
    let e = client
        .add_txt_value(&other, &other, &txt("v"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), RECORDS), before + 1);
    assert_eq!(writes(&mock), 0);
}

#[tokio::test]
async fn timeweb_cloud_rate_limit() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RECORDS).rate_limited("1"));
    add(&client, "AAA").await.unwrap();
    // The listing of the name: the refused request and its repeat.
    assert_eq!(mock.log().count(Some("GET"), NAME_LISTING), 2);
    mock.faults()
        .push(Fault::on("GET", RECORDS).rate_limited("120"));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
}

/// A 5xx on a read is retried; three in a row are `Transient`, which is retryable.
#[tokio::test]
async fn timeweb_cloud_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RECORDS).status(502));
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("GET", RECORDS).times(3).status(503));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    // The listing of the name: two requests for the first add, three for the second.
    assert_eq!(mock.log().count(Some("GET"), NAME_LISTING), 5);
}

/// The provider's refusals are `Rejected` with the status and its message; a status the client
/// cannot interpret is `Protocol`.
#[tokio::test]
async fn timeweb_cloud_refusals_are_rejected() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", CREATE).respond(
        400,
        r#"{"status_code":400,"error_code":"bad_subdomain_name","message":["subdomain is wrong"],"response_id":"r"}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(400));
            assert_eq!(detail.as_str(), "bad_subdomain_name: subdomain is wrong");
        }
        other => panic!("{other:?}"),
    }
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(418, r#"{"error_code":"teapot","message":"no"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(204, ""));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    // An answer to a create without the record it created.
    mock.faults()
        .push(Fault::on("POST", CREATE).respond(201, r#"{"dns_record":{}}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults()
        .push(Fault::on("POST", CREATE).respond(201, "{}"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn timeweb_cloud_from_json_builds_the_client() {
    let mock = TimewebCloudMock::start(Seed::standard()).await;
    let ctx = context();
    let client = AnyProvider::from_json(
        ProviderId::TimewebCloud,
        &settings_json(&mock),
        &SecretString::from(format!("{{\"token\": \"{TOKEN}\", \"other\": 1}}")),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::TimewebCloud);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

/// The smallest configuration the shared test support uses to build a client without a request.
#[test]
fn timeweb_cloud_minimal_configuration_builds() {
    let client = AnyProvider::from_json(
        ProviderId::TimewebCloud,
        r#"{"base_url":"http://127.0.0.1:9/api"}"#,
        &SecretString::from(r#"{"token":"test-only-token"}"#.to_owned()),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::TimewebCloud);
    AnyProvider::from_json(
        ProviderId::TimewebCloud,
        "{}",
        &SecretString::from(r#"{"token":"test-only-token"}"#.to_owned()),
        &context(),
    )
    .unwrap_err();
}

/// A token pasted with surrounding whitespace is sent without it.
#[tokio::test]
async fn timeweb_cloud_token_is_trimmed() {
    let mock = TimewebCloudMock::start(Seed::standard()).await;
    let client = client_with(&mock, &format!(" {TOKEN}\n"), &context());
    client.check(&[zone()]).await.unwrap();
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn timeweb_cloud_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || serde_json::json!({ "base_url": "http://127.0.0.1:1/api" });
    let with = |key: &str, value: serde_json::Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let token = serde_json::json!({"token": "tk"}).to_string();
    let cases = [
        (with("ttl", serde_json::json!(10)), token.clone(), "ttl"),
        (with("ttl", serde_json::json!(86_401)), token.clone(), "ttl"),
        (with("ttl", serde_json::json!(0)), token.clone(), "ttl"),
        (
            with(canary, serde_json::json!(canary)),
            token.clone(),
            "unknown keys",
        ),
        (
            with("propagation_timeout_s", serde_json::json!(60)),
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
            serde_json::json!({"token": 5, canary: canary}).to_string(),
            "token",
        ),
        (
            base(),
            serde_json::json!({"api_token": canary}).to_string(),
            "token",
        ),
        (
            base(),
            serde_json::json!({"token": ""}).to_string(),
            "token",
        ),
        (
            base(),
            serde_json::json!({"token": "  \n"}).to_string(),
            "token",
        ),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::TimewebCloud,
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
    let e = TimewebCloud::new(
        TimewebCloudConfig::default(),
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
fn timeweb_cloud_config_keys_match_metadata() {
    let meta = ProviderId::TimewebCloud.meta();
    let settings = serde_json::to_value(TimewebCloudConfig::default()).unwrap();
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
    assert_eq!(secret, ["token"]);
    for field in meta.fields.iter().filter(|f| f.default.is_some()) {
        let value = &settings[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
    }
    // The TTL has no default: the provider chooses.
    assert!(settings["ttl"].is_null());
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

/// Adds and removes two values at a challenge name, `_acme-challenge` under a generated label,
/// in the zone the maintainer names, and removes exactly the values it added afterwards, also
/// when the body failed. The first add is what shows that the `v2` create accepts a name with an
/// underscore label that is not a subdomain yet.
///
/// The provider may keep the subdomain the create made after its last record is gone (the
/// `v2` create is documented to need one); this test does not delete subdomains, so look for
/// `_acme-challenge.zw-live-…` and `zw-live-…` in the zone's subdomains afterwards and report
/// what is there.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_timeweb_cloud_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_TIMEWEB_CLOUD_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_TIMEWEB_CLOUD_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_TIMEWEB_CLOUD_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::TimewebCloud,
            &settings,
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap(),
    );
    let tag = random_u64();
    let name = zone
        .prepend(&format!("zw-live-{tag:016x}"))
        .unwrap()
        .prepend("_acme-challenge")
        .unwrap();
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
