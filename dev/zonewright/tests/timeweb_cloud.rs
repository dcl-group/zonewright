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
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, SetOutcome, SkipReason,
    Ttl, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::echo::{EchoServer, Echoed, Render};
use zonewright_mock::timeweb_cloud::{ListingScope, Seed, SubdomainForm, TimewebCloudMock};

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
/// The answer about one domain, with its subdomains.
const DOMAIN: &str = "/api/v1/domains/*";

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

/// What the echo's listings answer: no record, a record with a foreign value, a record with
/// the value `v1`, or a CNAME record.
#[derive(Clone, Copy)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
    Cname,
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
            Existing::Cname => serde_json::json!([{
                "id": 1001, "type": "CNAME", "ttl": 60,
                "data": {"subdomain": "_acme-challenge", "value": "old.example.net"}
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
    assert!(caps.list_rrsets && caps.get_rrset && caps.set_rrset && caps.delete_rrset);
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
        ttl.map(|t| Ttl::from_secs(t).unwrap()),
        texts.iter().map(|t| rdata(rtype, t)),
    )
    .unwrap()
}

/// Number of record write requests: creates, updates and deletes.
fn record_writes(mock: &TimewebCloudMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), CREATE)
        + log.count(Some("PATCH"), RECORD)
        + log.count(Some("DELETE"), RECORD)
}

/// The values of the records of `rtype` at `owner`, sorted.
fn stored(mock: &TimewebCloudMock, owner: &str, rtype: &str) -> Vec<String> {
    let mut values: Vec<String> = mock
        .control()
        .records_at(owner, rtype)
        .into_iter()
        .map(|r| r.value)
        .collect();
    values.sort();
    values
}

/// Every supported type through set, get and list with canonical equality: the apex, an IDN
/// name, a wildcard, multi-value sets and a TXT value of a full character-string. The listing
/// is the same whichever form the provider states names in and whether or not the zone's own
/// listing holds the records of its subdomains.
#[tokio::test]
async fn timeweb_cloud_record_round_trips() {
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
            Some(300),
            &["192.0.2.3"],
        ),
        rr("*.example.org", RecordType::AAAA, None, &["2001:db8::1"]),
        rr(
            "www.example.org",
            RecordType::CNAME,
            Some(3600),
            &["target.example.net."],
        ),
        rr(
            "example.org",
            RecordType::MX,
            None,
            &["10 mail.example.org.", "20 backup.example.net."],
        ),
        rr("example.org", RecordType::TXT, None, &[&long, "\"v=1\""]),
        rr(
            "_acme-challenge.www.example.org",
            RecordType::TXT,
            Some(60),
            &["\"token\""],
        ),
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
        // A set without a TTL is created without one (the provider chooses) and reads so.
        let got = client
            .get_rrset(&zone(), set.name(), set.rtype())
            .await
            .unwrap();
        assert_eq!(got.as_ref(), Some(set), "{label}");
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
    let control = mock.control();
    for (form, scope) in [
        (SubdomainForm::Relative, ListingScope::Everything),
        (SubdomainForm::Full, ListingScope::Everything),
        (SubdomainForm::Relative, ListingScope::OwnName),
        (SubdomainForm::Full, ListingScope::OwnName),
    ] {
        control.set_subdomain_form(form);
        control.set_domain_listing_scope(scope);
        let listing = client.list_rrsets(&zone()).await.unwrap();
        assert!(listing.skipped.is_empty(), "{:?}", listing.skipped);
        let mut expected = sets.to_vec();
        expected.sort_by(|a, b| (a.name(), a.rtype()).cmp(&(b.name(), b.rtype())));
        assert_eq!(listing.rrsets, expected, "{form:?} {scope:?}");
        for set in &sets {
            assert_eq!(
                client
                    .get_rrset(&zone(), set.name(), set.rtype())
                    .await
                    .unwrap()
                    .as_ref(),
                Some(set),
                "{form:?} {scope:?}"
            );
        }
    }
    control.set_subdomain_form(SubdomainForm::Relative);
    control.set_domain_listing_scope(ListingScope::Everything);

    // The fields the API stores: host names without a trailing dot, the MX priority apart.
    let mx = control.records_at("example.org", "MX");
    assert!(
        mx.iter()
            .any(|r| r.value == "mail.example.org" && r.priority == Some(10))
    );
    assert!(
        mx.iter()
            .any(|r| r.value == "backup.example.net" && r.priority == Some(20))
    );
    assert_eq!(
        stored(&mock, "www.example.org", "CNAME"),
        ["target.example.net"]
    );
    assert_eq!(
        stored(&mock, "xn--bcher-kva.example.org", "A"),
        ["192.0.2.3"]
    );
    assert_eq!(stored(&mock, "*.example.org", "AAAA"), ["2001:db8::1"]);
    assert!(
        control
            .records()
            .iter()
            .any(|r| r.rtype == "TXT" && r.value == "x".repeat(255))
    );
    assert!(
        control
            .records()
            .iter()
            .filter(|r| r.rtype != "MX")
            .all(|r| r.priority.is_none())
    );

    // A host name stated with a trailing dot and in capitals by another writer reads as the
    // same value.
    control.insert_record_with(
        "example.org",
        "other.example.org",
        "MX",
        "Mail.Example.org.",
        Some(600),
        Some(10),
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
        Some(other.clone().with_ttl(Some(Ttl::from_secs(600).unwrap())))
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
async fn timeweb_cloud_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record(
        "example.org",
        "www.example.org",
        "A",
        "192.0.2.1",
        Some(600),
    );
    let original = control.records();
    let www = "www.example.org";
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
/// alone updates the records in place; a delete removes every record and a repeat is
/// `NotPresent`.
#[tokio::test]
async fn timeweb_cloud_set_any_replaces_and_delete_converges() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", www, "A", "192.0.2.1", Some(600));
    control.insert_record("example.org", www, "A", "192.0.2.2", Some(600));
    let replaced = rr(www, RecordType::A, None, &["192.0.2.2", "192.0.2.3"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &replaced, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.2", "192.0.2.3"]);
    // The record that stays is not touched: one create, one delete, no update. The new record
    // gets the set's TTL as read.
    let log = mock.log();
    assert_eq!(log.count(Some("POST"), CREATE), 1);
    assert_eq!(log.count(Some("DELETE"), RECORD), 1);
    assert_eq!(log.count(Some("PATCH"), RECORD), 0);
    assert!(
        control
            .records_at(www, "A")
            .iter()
            .all(|r| r.ttl == Some(600))
    );

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
        .with_ttl(Some(Ttl::from_secs(900).unwrap()));
    assert_eq!(
        client
            .set_rrset(&zone(), &retuned, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(mock.log().count(Some("PATCH"), RECORD), 2);
    assert!(
        control
            .records_at(www, "A")
            .iter()
            .all(|r| r.ttl == Some(900))
    );
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

/// Refusals before any request: SOA, NS (the apex set included), SRV and every type outside the
/// list are `UnsupportedRecordType` for every operation; a TTL outside 60 to 86400 and an
/// expectation about another name or type are `InvalidInput`; a name outside the zone is
/// `NameOutsideZone`.
#[tokio::test]
async fn timeweb_cloud_record_refusals_send_nothing() {
    let (mock, client) = setup().await;
    let soa = rr(
        "example.org",
        RecordType::SOA,
        None,
        &["ns1.example.net. hostmaster.example.org. 1 10800 3600 604800 1800"],
    );
    let apex_ns = rr("example.org", RecordType::NS, None, &["ns1.example.net."]);
    let srv = rr(
        "_sip._tcp.example.org",
        RecordType::SRV,
        None,
        &["1 5 5060 sip.example.org."],
    );
    let caa = rr(
        "example.org",
        RecordType::CAA,
        None,
        &["0 issue \"ca.example.net\""],
    );
    for set in [&soa, &apex_ns, &srv, &caa] {
        let e = client
            .set_rrset(&zone(), set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{set:?}: {e:?}");
    }
    for rtype in [
        RecordType::SOA,
        RecordType::NS,
        RecordType::SRV,
        RecordType::CAA,
        RecordType::TLSA,
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
    let e = client.list_rrsets(&DomainName::root()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());

    // The bounds themselves are accepted.
    for ttl in [60, 86_400] {
        let set = rr("www.example.org", RecordType::A, Some(ttl), &["192.0.2.1"]);
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
        assert_eq!(
            mock.control().records_at("www.example.org", "A")[0].ttl,
            Some(u64::from(ttl))
        );
    }
}

/// Values whose encoding at this API no source establishes are refused after the read and
/// nothing is written; the same value already at the provider is kept as it is.
#[tokio::test]
async fn timeweb_cloud_values_without_an_encoding_are_refused() {
    let (mock, client) = setup().await;
    for set in [
        rr("www.example.org", RecordType::TXT, None, &["\"two words\""]),
        rr("www.example.org", RecordType::TXT, None, &["\"quo\\\"te\""]),
        rr("www.example.org", RecordType::MX, None, &["0 ."]),
        rr(
            "www.example.org",
            RecordType::CNAME,
            None,
            &["a\\.b.example.net."],
        ),
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
        Some(300),
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

/// The listing reports every rrset the provider lists, with the smallest TTL of each; a type the
/// model does not know, a name it cannot hold and two CNAME records at one name are in
/// `skipped`; an unparseable value, and an SRV record, whose listing has no fields for its port
/// and target, are non-canonical data.
#[tokio::test]
async fn timeweb_cloud_listing_reports_skipped_sets() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record(
        "example.org",
        "www.example.org",
        "A",
        "192.0.2.1",
        Some(600),
    );
    control.insert_record(
        "example.org",
        "www.example.org",
        "A",
        "192.0.2.2",
        Some(300),
    );
    control.insert_record(
        "example.org",
        "odd.example.org",
        "A",
        "not an address",
        None,
    );
    control.insert_record(
        "example.org",
        "x.example.org",
        "WEIRD",
        "whatever",
        Some(300),
    );
    control.insert_record(
        "example.org",
        "two.example.org",
        "CNAME",
        "a.example.net",
        Some(300),
    );
    control.insert_record(
        "example.org",
        "two.example.org",
        "CNAME",
        "b.example.net",
        Some(300),
    );
    control.insert_record_with(
        "example.org",
        "_sip._tcp.example.org",
        "SRV",
        "sip.example.org",
        Some(300),
        Some(10),
    );
    control.insert_record("example.org", "bad name", "A", "192.0.2.9", Some(300));

    for scope in [ListingScope::Everything, ListingScope::OwnName] {
        control.set_domain_listing_scope(scope);
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
            )),
            "{scope:?}"
        );
        let odd = get("odd.example.org", RecordType::A).unwrap();
        assert!(!odd.records()[0].is_canonical());
        assert_eq!(odd.records()[0].as_str(), "not an address");
        assert_eq!(odd.ttl(), None);
        let srv = get("_sip._tcp.example.org", RecordType::SRV).unwrap();
        assert!(!srv.records()[0].is_canonical());
        assert_eq!(srv.records()[0].as_str(), "sip.example.org");

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
        assert_eq!(skipped, expected, "{scope:?}");
        assert_eq!(listing.rrsets.len(), 3, "{scope:?}");

        // Every page of every listing is read.
        control.set_page_cap(1);
        let paged = client.list_rrsets(&zone()).await.unwrap();
        assert_eq!(paged.rrsets, listing.rrsets, "{scope:?}");
        assert_eq!(paged.skipped.len(), listing.skipped.len(), "{scope:?}");
        control.set_page_cap(100);
    }
}

/// The zone's listing is read with the listing of every subdomain the domain's answer states, so
/// records the zone's own listing leaves out are found; the requests are exactly those. An
/// answer without its list of subdomains, a domain answered `404`, and a subdomain's listing
/// that states a record without a name are errors, never a shorter listing.
#[tokio::test]
async fn timeweb_cloud_listing_reads_every_subdomain() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_domain_listing_scope(ListingScope::OwnName);
    control.insert_record("example.org", "example.org", "A", "192.0.2.1", Some(600));
    control.insert_record("example.org", "a.example.org", "A", "192.0.2.2", Some(600));
    control.insert_record("example.org", "b.a.example.org", "TXT", "deep", Some(600));
    control.insert_subdomain("example.org", "empty.example.org");
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(
        listing.rrsets,
        [
            rr("a.example.org", RecordType::A, Some(600), &["192.0.2.2"]),
            rr("b.a.example.org", RecordType::TXT, Some(600), &["\"deep\""]),
            rr("example.org", RecordType::A, Some(600), &["192.0.2.1"]),
        ]
    );
    let gets: Vec<String> = mock
        .log()
        .entries()
        .into_iter()
        .map(|r| format!("{} {}", r.method, r.path))
        .collect();
    assert_eq!(
        gets,
        [
            "GET /api/v1/domains/example.org",
            "GET /api/v1/domains/example.org/dns-records",
            "GET /api/v1/domains/a.example.org/dns-records",
            "GET /api/v1/domains/b.a.example.org/dns-records",
            "GET /api/v1/domains/empty.example.org/dns-records",
        ]
    );

    mock.faults().push(
        Fault::on("GET", DOMAIN).respond(200, r#"{"domain":{"fqdn":"example.org"}}"#.to_owned()),
    );
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().push(Fault::on("GET", DOMAIN).respond(
        200,
        r#"{"domain":{"fqdn":"example.org","subdomains":[{"id":1}]}}"#.to_owned(),
    ));
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");

    let body = r#"{"meta":{"total":1},"dns_records":[
        {"id":7,"type":"A","ttl":60,"data":{"subdomain":null,"value":"192.0.2.9"}}]}"#;
    mock.faults().push(
        Fault::on("GET", "/api/v1/domains/a.example.org/dns-records").respond(200, body.to_owned()),
    );
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");

    let e = client
        .list_rrsets(&dn("missing.example"))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
}

/// A name whose stated form reads two ways (`a.example.org` relative to `example.org` is
/// `a.example.org.example.org.`, and as a full name `a.example.org.`) is placed where its own
/// listing shows it, so the zone's listing agrees with a read of the name, and a record shown by
/// two listings is listed once.
#[tokio::test]
async fn timeweb_cloud_listing_agrees_with_reads_on_ambiguous_names() {
    let (_mock, client) = setup().await;
    let odd = rr(
        "a.example.org.example.org",
        RecordType::A,
        Some(300),
        &["192.0.2.1"],
    );
    let plain = rr("a.example.org", RecordType::A, Some(300), &["192.0.2.2"]);
    for set in [&odd, &plain] {
        client
            .set_rrset(&zone(), set, Expect::Absent)
            .await
            .unwrap();
        assert_eq!(
            client
                .get_rrset(&zone(), set.name(), RecordType::A)
                .await
                .unwrap()
                .as_ref(),
            Some(set)
        );
    }
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(listing.rrsets, [plain, odd]);
    assert!(listing.skipped.is_empty(), "{:?}", listing.skipped);
}

/// A listing or a read that stops short is an error, never a shorter result, and nothing is
/// written after a short read.
#[tokio::test]
async fn timeweb_cloud_truncated_rrset_listing_is_protocol() {
    let (mock, client) = setup().await;
    let body = r#"{"meta":{"total":2},"dns_records":[
        {"id":1,"type":"A","ttl":60,"data":{"subdomain":"www","value":"192.0.2.1"}}]}"#;
    let short = || Fault::on("GET", RECORDS).respond(200, body.to_owned());
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

/// Records at other names (below the name, so in its listing, and merely ending with its text)
/// and other types at the same name are untouched by every operation, in either form of stated
/// names.
#[tokio::test]
async fn timeweb_cloud_record_operations_touch_only_their_rrset() {
    for form in [SubdomainForm::Relative, SubdomainForm::Full] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.set_subdomain_form(form);
        let www = "www.example.org";
        control.insert_record("example.org", www, "TXT", "foreign", Some(300));
        control.insert_record("example.org", www, "AAAA", "2001:db8::1", Some(300));
        control.insert_record(
            "example.org",
            "x.www.example.org",
            "A",
            "192.0.2.1",
            Some(300),
        );
        control.insert_record("example.org", "example.org", "A", "192.0.2.1", Some(300));
        control.insert_record(
            "example.org",
            "wwwx.example.org",
            "A",
            "192.0.2.1",
            Some(300),
        );
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
        let set = set.with_ttl(Some(Ttl::from_secs(60).unwrap()));
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
        assert_eq!(
            client
                .get_rrset(&zone(), &dn(www), RecordType::A)
                .await
                .unwrap(),
            Some(set),
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
        // The apex set is not mixed up with the records below it.
        let apex = rr("example.org", RecordType::A, None, &["192.0.2.7"]);
        client.set_rrset(&zone(), &apex, Expect::Any).await.unwrap();
        assert_eq!(stored(&mock, "example.org", "A"), ["192.0.2.7"], "{form:?}");
        assert_eq!(stored(&mock, "x.www.example.org", "A"), ["192.0.2.1"]);
        assert_eq!(stored(&mock, "wwwx.example.org", "A"), ["192.0.2.1"]);
    }
}

/// A replacement creates the missing records before it deletes the surplus ones. A failure part
/// way leaves a superset of the old values, never a subset, and a repeat sends only the rest.
#[tokio::test]
async fn timeweb_cloud_replacement_creates_before_it_deletes() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", www, "A", "192.0.2.1", Some(300));
    control.insert_record("example.org", www, "A", "192.0.2.2", Some(300));
    let wanted = rr(www, RecordType::A, None, &["192.0.2.3", "192.0.2.4"]);

    // The second create fails: the old values are all there, with the first new one.
    mock.faults()
        .push(Fault::on("POST", CREATE).skip(1).status(502));
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
    assert_eq!(mock.log().count(Some("POST"), CREATE), 0);
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
        .map(|r| r.method.to_string())
        .collect();
    assert_eq!(methods, ["POST", "DELETE", "DELETE"]);
}

/// A CNAME is replaced in place by one update, never by a second record next to the first, and
/// the update carries the record's TTL as read; a record that went away before the update is
/// `Conflict`, and the repeat creates it.
#[tokio::test]
async fn timeweb_cloud_cname_is_replaced_in_place() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let id = control.insert_record("example.org", www, "CNAME", "old.example.net", Some(300));
    let new = rr(www, RecordType::CNAME, None, &["new.example.net."]);
    assert_eq!(
        client.set_rrset(&zone(), &new, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    let records = control.records_at(www, "CNAME");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, id);
    assert_eq!(records[0].value, "new.example.net");
    assert_eq!(records[0].ttl, Some(300));
    let patch = mock.log().matching(Some("PATCH"), RECORD).pop().unwrap();
    assert_eq!(
        patch.path,
        format!("/api/v2/domains/www.example.org/dns-records/{id}")
    );
    assert_eq!(
        patch.body_json().unwrap(),
        serde_json::json!({"type": "CNAME", "value": "new.example.net", "ttl": 300})
    );
    assert_eq!(mock.log().count(Some("POST"), CREATE), 0);
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 0);

    let hook = control.clone();
    mock.faults()
        .push(Fault::on("PATCH", RECORD).run(move || hook.delete_record(id)));
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

/// Per-record TTLs (design section 3.6): a set whose records disagree reads with the smallest; a
/// value added without a TTL gets it and the others keep theirs; a requested TTL is set on every
/// record that lacks it, by an update that sends the record's value and priority back exactly as
/// listed; a delete of a record already gone counts as done.
#[tokio::test]
async fn timeweb_cloud_record_ttls() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", www, "A", "192.0.2.1", Some(600));
    control.insert_record("example.org", www, "A", "192.0.2.2", Some(300));
    let read = client
        .get_rrset(&zone(), &dn(www), RecordType::A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.ttl(), Some(Ttl::from_secs(300).unwrap()));

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
    let ttls = |control: &zonewright_mock::timeweb_cloud::Control| {
        let mut t: Vec<(String, Option<u64>)> = control
            .records_at(www, "A")
            .into_iter()
            .map(|r| (r.value, r.ttl))
            .collect();
        t.sort();
        t
    };
    assert_eq!(
        ttls(control),
        [
            ("192.0.2.1".to_owned(), Some(600)),
            ("192.0.2.2".to_owned(), Some(300)),
            ("192.0.2.3".to_owned(), Some(300))
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

    // A requested TTL: one update, for the record that lacks it.
    let uniform = three.clone().with_ttl(Some(Ttl::from_secs(300).unwrap()));
    mock.log().clear();
    assert_eq!(
        client
            .set_rrset(&zone(), &uniform, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let patches = mock.log().matching(Some("PATCH"), RECORD);
    assert_eq!(patches.len(), 1);
    assert_eq!(
        patches[0].body_json().unwrap(),
        serde_json::json!({"type": "A", "value": "192.0.2.1", "ttl": 300})
    );
    assert!(ttls(control).iter().all(|(_, ttl)| *ttl == Some(300)));
    assert_eq!(
        client
            .set_rrset(&zone(), &uniform, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );

    // An update writes back what the listing stated: an MX priority, a TXT value with spaces
    // and a host name spelled with a trailing dot, none of them re-encoded.
    control.insert_record_with(
        "example.org",
        www,
        "MX",
        "Mail.Example.org.",
        Some(600),
        Some(10),
    );
    control.insert_record("example.org", www, "TXT", "v=spf1 mx -all", Some(600));
    mock.log().clear();
    let mx = rr(www, RecordType::MX, Some(900), &["10 mail.example.org."]);
    client.set_rrset(&zone(), &mx, Expect::Any).await.unwrap();
    let spf = rr(www, RecordType::TXT, Some(900), &["\"v=spf1 mx -all\""]);
    client.set_rrset(&zone(), &spf, Expect::Any).await.unwrap();
    let bodies: Vec<serde_json::Value> = mock
        .log()
        .matching(Some("PATCH"), RECORD)
        .iter()
        .map(|r| r.body_json().unwrap())
        .collect();
    assert_eq!(
        bodies,
        [
            serde_json::json!({
                "type": "MX", "value": "Mail.Example.org.", "priority": 10, "ttl": 900
            }),
            serde_json::json!({"type": "TXT", "value": "v=spf1 mx -all", "ttl": 900}),
        ]
    );
    assert_eq!(mock.log().count(Some("POST"), CREATE), 0);
    assert_eq!(control.records_at(www, "MX")[0].priority, Some(10));
    assert_eq!(control.records_at(www, "TXT")[0].value, "v=spf1 mx -all");

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

    // The domain is created again under new identifiers between the read and a delete: the
    // value is still published, so the delete is not reported done.
    control.insert_record("example.org", www, "A", "192.0.2.1", Some(300));
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("DELETE", RECORD).run(move || hook.recreate_domain("example.org")));
    let e = client
        .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.1"]);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
}

/// A record listed without an identifier can be read and kept, but a write that would change
/// or delete it is refused, and nothing is written.
#[tokio::test]
async fn timeweb_cloud_records_without_identifiers_are_never_written() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let id = control.insert_record("example.org", www, "A", "192.0.2.1", Some(300));
    control.set_null_id(id);
    let read = client
        .get_rrset(&zone(), &dn(www), RecordType::A)
        .await
        .unwrap();
    assert_eq!(
        read,
        Some(rr(www, RecordType::A, Some(300), &["192.0.2.1"]))
    );
    let e = client
        .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let retuned = rr(www, RecordType::A, Some(600), &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &retuned, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(record_writes(&mock), 0);
    // Adding a value next to it writes only the new record.
    let more = rr(www, RecordType::A, None, &["192.0.2.1", "192.0.2.2"]);
    assert_eq!(
        client.set_rrset(&zone(), &more, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.1", "192.0.2.2"]);
}

/// Two clients sharing a `Context` write one name at once, the first create delayed: the
/// second reads after the first wrote, so its `Expect::Absent` fails.
#[tokio::test]
async fn timeweb_cloud_concurrent_record_writes_are_serialized() {
    let mock = TimewebCloudMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, TOKEN, &ctx);
    let b = client_with(&mock, TOKEN, &ctx);
    mock.faults()
        .push(Fault::on("POST", CREATE).delay(Duration::from_millis(300)));
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

/// Creates and updates are sent once whatever the answer (502, 429, 401); the delete of one
/// record by its identifier is repeated after a 502 only.
#[tokio::test]
async fn timeweb_cloud_record_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let set = rr(www, RecordType::A, None, &["192.0.2.1"]);
    for (fault, kind) in [
        (Fault::on("POST", CREATE).status(502), ErrorKind::Transient),
        (
            Fault::on("POST", CREATE).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("POST", CREATE).status(401), ErrorKind::Auth),
    ] {
        mock.log().clear();
        mock.faults().push(fault);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(mock.log().count(Some("POST"), CREATE), 1);
        assert!(control.records().is_empty());
    }
    client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
    let retuned = set.clone().with_ttl(Some(Ttl::from_secs(600).unwrap()));
    for (fault, kind) in [
        (Fault::on("PATCH", RECORD).status(502), ErrorKind::Transient),
        (
            Fault::on("PATCH", RECORD).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("PATCH", RECORD).status(401), ErrorKind::Auth),
    ] {
        mock.log().clear();
        mock.faults().push(fault);
        let e = client
            .set_rrset(&zone(), &retuned, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(mock.log().count(Some("PATCH"), RECORD), 1);
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

/// The record-level requests as the sources describe them: every call addressed to the owner
/// name, the read with `limit` and `offset`, the create with the type's fields, a host name
/// without its trailing dot, the TTL only when there is one, and no write to a `v1` path.
#[tokio::test]
async fn timeweb_cloud_record_request_shapes() {
    let (mock, client) = setup().await;
    let mx = rr(
        "example.org",
        RecordType::MX,
        None,
        &["10 mail.example.org."],
    );
    client
        .set_rrset(&zone(), &mx, Expect::Absent)
        .await
        .unwrap();
    let log = mock.log();
    let get = log.matching(Some("GET"), RECORDS).pop().unwrap();
    assert_eq!(get.path, "/api/v1/domains/example.org/dns-records");
    assert_eq!(get.query.as_deref(), Some("limit=100&offset=0"));
    let post = log.matching(Some("POST"), CREATE).pop().unwrap();
    assert_eq!(post.path, "/api/v2/domains/example.org/dns-records");
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({"type": "MX", "value": "mail.example.org", "priority": 10})
    );
    let cname = rr(
        "www.example.org",
        RecordType::CNAME,
        Some(3600),
        &["target.example.net."],
    );
    client
        .set_rrset(&zone(), &cname, Expect::Absent)
        .await
        .unwrap();
    let post = mock.log().matching(Some("POST"), CREATE).pop().unwrap();
    assert_eq!(post.path, "/api/v2/domains/www.example.org/dns-records");
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({"type": "CNAME", "value": "target.example.net", "ttl": 3600})
    );
    let aaaa = rr("v6.example.org", RecordType::AAAA, None, &["2001:db8::1"]);
    client
        .set_rrset(&zone(), &aaaa, Expect::Absent)
        .await
        .unwrap();
    let post = mock.log().matching(Some("POST"), CREATE).pop().unwrap();
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({"type": "AAAA", "value": "2001:db8::1"})
    );
    client
        .delete_rrset(
            &zone(),
            &dn("www.example.org"),
            RecordType::CNAME,
            Expect::Any,
        )
        .await
        .unwrap();
    let delete = mock.log().matching(Some("DELETE"), RECORD).pop().unwrap();
    assert!(
        delete
            .path
            .starts_with("/api/v2/domains/www.example.org/dns-records/"),
        "{}",
        delete.path
    );
    // The configured TTL for a new set.
    let mut config = settings(mock.base_url());
    config.ttl = Some(120);
    let configured = TimewebCloud::new(config, credentials(TOKEN), &context()).unwrap();
    let a = rr("a.example.org", RecordType::A, None, &["192.0.2.1"]);
    configured
        .set_rrset(&zone(), &a, Expect::Absent)
        .await
        .unwrap();
    let post = mock.log().matching(Some("POST"), CREATE).pop().unwrap();
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({"type": "A", "value": "192.0.2.1", "ttl": 120})
    );
    let entries = mock.log().entries();
    assert!(
        entries
            .iter()
            .filter(|r| r.method != "GET")
            .all(|r| r.path.starts_with("/api/v2/")),
        "{entries:?}"
    );
}

/// What the echo answers for each record-level request kind.
#[derive(Clone, Copy, Debug)]
enum RecordWrite {
    /// A create: no record at the name.
    Create,
    /// An update in place: a CNAME at the name.
    Update,
    /// A delete: a TXT record with our value at the name.
    Delete,
    /// The domain's answer, the first request of a zone listing, is the echo.
    List,
}

/// The record-level requests against an echo, for every dialect: the create, the update, the
/// delete and the domain's answer. No canary in any error or `Debug`, and the error shows the
/// redaction.
#[tokio::test]
async fn timeweb_cloud_secret_echo_record_level() {
    for dialect in dialects() {
        for (kind, statuses) in [
            (RecordWrite::Create, [400, 401, 403, 409, 500].as_slice()),
            (RecordWrite::Update, [400, 401, 403, 409, 500].as_slice()),
            // A 5xx to these idempotent requests is retried with real back-off sleeps; the 5xx
            // body is covered by the create and the update.
            (RecordWrite::Delete, [400, 401, 403].as_slice()),
            (RecordWrite::List, [400, 401, 403].as_slice()),
        ] {
            for &status in statuses {
                let label = format!("{} {:?} {status} {kind:?}", dialect.name, dialect.spelling);
                let existing = match kind {
                    RecordWrite::Create => Some(Existing::Nothing),
                    RecordWrite::Update => Some(Existing::Cname),
                    RecordWrite::Delete => Some(Existing::Ours),
                    RecordWrite::List => None,
                };
                let echo = dialect
                    .echo(status)
                    .render(answering(dialect.render.clone(), true, existing))
                    .start()
                    .await;
                let client = echo_client(&echo);
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
                    RecordWrite::Create => ("POST", CREATE),
                    RecordWrite::Update => ("PATCH", RECORD),
                    RecordWrite::Delete => ("DELETE", RECORD),
                    RecordWrite::List => ("GET", DOMAIN),
                };
                assert!(
                    echo.log().count(Some(method), path) >= 1,
                    "{label}: the request did not reach the echo"
                );
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

/// A record-level round trip on a name it creates under a generated label in the zone the
/// maintainer names: create, read, list, replace, change the TTL, delete. Afterwards it deletes
/// the A rrset at that name, which only this test wrote, also when the body failed. Like the
/// test above, it leaves the subdomain the create may have made; look for `zw-live-…` in the
/// zone's subdomains afterwards and report whether the listing found the records there.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_timeweb_cloud_record_round_trip() {
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
    let name = zone.prepend(&format!("zw-live-{tag:016x}")).unwrap();
    let set = |ttl: Option<u32>, texts: &[&str]| {
        RrSet::new(
            name.clone(),
            RecordType::A,
            ttl.map(|t| Ttl::from_secs(t).unwrap()),
            texts.iter().map(|t| rdata(RecordType::A, t)),
        )
        .unwrap()
    };
    let first = set(Some(300), &["192.0.2.1", "192.0.2.2"]);
    let second = set(None, &["192.0.2.2", "192.0.2.3"]);
    let third = set(Some(600), &["192.0.2.2", "192.0.2.3"]);

    let body = {
        let (client, zone, name) = (client.clone(), zone.clone(), name.clone());
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
        })
    };
    let outcome = body.await;

    // Cleanup: the A rrset at the generated name, which nothing but this test wrote.
    let cleanup = client
        .delete_rrset(&zone, &name, RecordType::A, Expect::Any)
        .await;
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_ok(), "cleanup failed: {cleanup:?}");
}
