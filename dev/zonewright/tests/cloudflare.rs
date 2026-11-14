//! Tests of the Cloudflare client (`cloudflare`) against its mock.
#![cfg(feature = "cloudflare")]
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
use zonewright::providers::cloudflare::{Cloudflare, CloudflareConfig, CloudflareCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RemoveOutcome, RrSet, Ttl, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::cloudflare::{CloudflareMock, Seed};
use zonewright_mock::echo::{EchoServer, Echoed, Render};

use common::echo::{CANARY_TOKEN, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The token of the standard seed.
const TOKEN: &str = "cf-test-token";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const ZONES: &str = "/client/v4/zones";
const RECORDS: &str = "/client/v4/zones/*/dns_records";
const RECORD: &str = "/client/v4/zones/*/dns_records/*";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings for the standard seed, pointed at `mock`.
fn settings(mock: &CloudflareMock) -> CloudflareConfig {
    let mut config = CloudflareConfig::default();
    config.base_url = mock.base_url();
    config
}

fn credentials(token: &str) -> CloudflareCredentials {
    CloudflareCredentials::new(SecretString::from(token.to_owned()))
}

fn client_with(mock: &CloudflareMock, token: &str, ctx: &Context) -> Cloudflare {
    Cloudflare::new(settings(mock), credentials(token), ctx).unwrap()
}

async fn setup() -> (CloudflareMock, Cloudflare) {
    let mock = CloudflareMock::start(Seed::standard()).await;
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
fn writes(mock: &CloudflareMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), RECORDS) + log.count(Some("DELETE"), RECORD)
}

/// The settings JSON of `from_json` for the standard seed.
fn settings_json(mock: &CloudflareMock) -> String {
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

assert_not_impl!(Cloudflare: std::fmt::Display, serde::Serialize);
assert_not_impl!(CloudflareCredentials: std::fmt::Display, serde::Serialize);

/// A renderer that answers the zone and record listings like the API (one zone and the given
/// TXT records) and every other request with `errors`.
fn listings_then(errors: Render, records: Vec<serde_json::Value>) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method != Method::GET {
            return errors(e);
        }
        let result = if e.path.ends_with("/zones") {
            serde_json::json!([{
                "id": "00000000000000000000000000000001",
                "name": "example.org",
                "status": "active"
            }])
        } else {
            serde_json::Value::Array(records.clone())
        };
        let body = serde_json::json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": result,
            "result_info": {"page": 1, "per_page": 100, "count": 1, "total_count": 1, "total_pages": 1},
        });
        (StatusCode::OK, axum::Json(body)).into_response()
    })
}

/// The record of the foreign value and the one of `v1`, as the API lists them.
fn echo_records(with_ours: bool) -> Vec<serde_json::Value> {
    let record = |id: &str, content: &str| {
        serde_json::json!({
            "id": id,
            "type": "TXT",
            "name": NAME,
            "content": content,
            "ttl": 120
        })
    };
    let mut records = vec![record("00000000000000000000000000000010", "\"foreign\"")];
    if with_ours {
        records.push(record("00000000000000000000000000000011", "\"v1\""));
    }
    records
}

/// The envelope the API puts its errors in, with the echoed request as the message.
fn envelope_errors() -> Render {
    Arc::new(|e: &Echoed| {
        let body = serde_json::json!({
            "success": false,
            "errors": [{"code": 1000, "message": e.text}],
            "messages": [],
            "result": null,
        });
        (e.status, axum::Json(body)).into_response()
    })
}

fn echo_client(echo: &EchoServer) -> Cloudflare {
    let mut config = CloudflareConfig::default();
    config.base_url = echo.url("/client/v4");
    Cloudflare::new(config, credentials(CANARY_TOKEN), &context()).unwrap()
}

/// What an echo round does for its write.
#[derive(Clone, Copy, Debug)]
enum Write {
    Add,
    Remove,
}

async fn echo_round(label: &str, client: &Cloudflare, write: Write) {
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
    let error = match result {
        Ok(outcome) => panic!("{label}: the echo accepted a write: {outcome}"),
        Err(e) => format!("{e} | {e:?}"),
    };
    assert!(
        error.contains(REDACTED),
        "{label}: the echo did not reach the error: {error}"
    );
    texts.push(error);
    for text in &texts {
        assert_clean(label, text, &[CANARY_TOKEN]);
    }
}

/// `check` and a write against an echo that quotes every request back, for every dialect: no
/// canary in any error, `ZoneCheck::detail` or `Debug`, and the write's error shows the
/// redaction. The writes reach their request: a create (the listings answer normally) and a
/// delete (the listing holds our value).
#[tokio::test]
async fn cloudflare_secret_echo() {
    let mut all = dialects();
    // The API's own error envelope, with the echo in `errors[].message`.
    all.push(common::echo::Dialect {
        name: "cloudflare_envelope",
        spelling: zonewright_mock::echo::Spelling::Verbatim,
        render: envelope_errors(),
    });
    for dialect in all {
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} read", dialect.name, dialect.spelling);
            let echo = dialect.echo(status).start().await;
            let client = echo_client(&echo);
            echo_round(&label, &client, Write::Add).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
        }
        for status in [400, 403, 422, 500] {
            for write in [Write::Add, Write::Remove] {
                // A 5xx to a delete by identifier is repeated by the transport, with back-off:
                // it adds time and no coverage.
                if status == 500 && matches!(write, Write::Remove) {
                    continue;
                }
                let label = format!(
                    "{} {:?} {status} write {write:?}",
                    dialect.name, dialect.spelling
                );
                let records = echo_records(matches!(write, Write::Remove));
                let echo = dialect
                    .echo(status)
                    .render_under(ZONES, listings_then(dialect.render.clone(), records))
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
async fn cloudflare_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.token = CANARY_TOKEN.into();
    let mock = CloudflareMock::start(seed).await;
    let client = client_with(&mock, CANARY_TOKEN, &context());
    let mut texts = Vec::new();

    add(&client, "v1").await.unwrap();

    mock.faults()
        .push(Fault::on("GET", RECORDS).always().status(401));
    let e = add(&client, "v2").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("POST", RECORDS).status(500));
    let e = add(&client, "v2").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    let wrong = client_with(&mock, "not-the-token", &context());
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
        assert_clean("cloudflare logs and errors", text, &[CANARY_TOKEN]);
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely
/// ends with the zone's text, the zone's text inside another name, and a sibling zone.
#[tokio::test]
async fn cloudflare_name_outside_zone_sends_nothing() {
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

/// `Created`, `Appended` for a second value (the apex and the wildcard of one certificate share
/// a name), then `AlreadyPresent` without a write.
#[tokio::test]
async fn cloudflare_add_is_idempotent() {
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
/// reason to delete anything. Another type at the name, and our value at another name, are not
/// touched.
#[tokio::test]
async fn cloudflare_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "\"foreign\"", 600);
    // A value the API returns unquoted.
    control.insert_record("example.org", NAME, "TXT", "raw-foreign", 1);
    control.insert_record("example.org", NAME, "MX", "10 mail.example.org", 300);
    control.insert_record("example.org", "other.example.org", "TXT", "\"AAA\"", 300);
    let original = control.records();

    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);

    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.records(), original);

    // Removing a value that a foreign record holds removes that record and nothing else: the
    // other TXT record, the other type and the other name stay.
    assert_eq!(
        remove(&client, "foreign").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt_values(NAME), ["raw-foreign"]);
    assert_eq!(control.records_of("other.example.org", "TXT").len(), 1);
    assert_eq!(control.records_of(NAME, "MX").len(), 1);
}

/// Removing the last value deletes its record, by identifier, and reports the rrset gone.
#[tokio::test]
async fn cloudflare_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let id = mock.control().records()[0].id.clone();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().records().is_empty());
    let deletes = mock.log().matching(Some("DELETE"), RECORD);
    assert_eq!(deletes.len(), 1);
    assert!(deletes[0].path.ends_with(&id), "{}", deletes[0].path);
}

#[tokio::test]
async fn cloudflare_remove_is_idempotent() {
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

/// If the provider holds several records with our value, removal removes all of them.
#[tokio::test]
async fn cloudflare_remove_deletes_every_record_with_the_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "\"dup\"", 120);
    control.insert_record("example.org", NAME, "TXT", "dup", 120);
    control.insert_record("example.org", NAME, "TXT", "\"keep\"", 120);
    assert_eq!(
        remove(&client, "dup").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt_values(NAME), ["keep"]);
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 2);
}

/// Two clients sharing a `Context` add to one name at once, the first write delayed: both values
/// end up in the rrset, one created and one appended. Without the name lock both would read "no
/// record" and both would report `Created`.
#[tokio::test]
async fn cloudflare_concurrent_adds_are_serialized() {
    let mock = CloudflareMock::start(Seed::standard()).await;
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

/// The zone is deleted and created again under a new identifier while the client has the old
/// one cached. A read with the stale identifier is answered 404, the zone is looked up again
/// and the read repeated: a removal never reports `NotPresent` for a value that is there. A
/// write that meets the stale identifier fails cleanly with a retryable error and drops it; the
/// next operation succeeds.
#[tokio::test]
async fn cloudflare_stale_zone_id() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for value in ["v1", "v2"] {
        add(&client, value).await.unwrap();
    }
    let lookups = || mock.log().count(Some("GET"), ZONES);
    assert_eq!(lookups(), 1);

    control.recreate_zone("example.org");
    assert_eq!(remove(&client, "v1").await.unwrap(), RemoveOutcome::Removed);
    assert_eq!(lookups(), 2);
    control.recreate_zone("example.org");
    assert_eq!(add(&client, "v3").await.unwrap(), AddOutcome::Appended);
    assert_eq!(control.txt_values(NAME), ["v2", "v3"]);

    // The zone is recreated between the read and the create.
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", RECORDS).run(move || {
        hook.recreate_zone("example.org");
    }));
    let e = add(&client, "v4").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(add(&client, "v4").await.unwrap(), AddOutcome::Appended);
    assert_eq!(control.txt_values(NAME), ["v2", "v3", "v4"]);
}

/// The record-level operations are not offered: `Unsupported`, and nothing is sent.
#[tokio::test]
async fn cloudflare_unsupported_operations_send_nothing() {
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
/// operation's error, and the repeat starts with a read). A delete of one record by its
/// identifier is repeated by the transport after a 5xx or a rate limit (design section 5.3),
/// and a 401 is not repeated.
#[tokio::test]
async fn cloudflare_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let posts = || mock.log().count(Some("POST"), RECORDS);
    for (i, (fault, kind)) in [
        (Fault::on("POST", RECORDS).status(502), ErrorKind::Transient),
        (
            Fault::on("POST", RECORDS).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("POST", RECORDS).status(401), ErrorKind::Auth),
    ]
    .into_iter()
    .enumerate()
    {
        mock.faults().push(fault);
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(posts(), i + 1, "{e:?}");
        assert!(mock.control().records().is_empty());
    }
    // A create that was not applied is applied by the operation's repeat.
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(posts(), 4);

    // A delete by identifier is idempotent: one 502 and one rate limit are repeated.
    mock.faults().push(Fault::on("DELETE", RECORD).status(502));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 2);
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("DELETE", RECORD).rate_limited("1"));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 4);
    // A rejected token is not repeated: static tokens do not renew.
    add(&client, "AAA").await.unwrap();
    mock.faults().push(Fault::on("DELETE", RECORD).status(401));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 5);
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);
}

/// A delete answered 404 is a success only when a new read, under a freshly looked-up zone,
/// finds no record with the value: removed meanwhile by someone else, it is gone; with the zone
/// recreated (and the record in it) the value is still published, and the answer is a
/// retryable `Conflict`.
#[tokio::test]
async fn cloudflare_delete_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", RECORD).run(move || {
        hook.delete_records(NAME, "TXT");
    }));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.records().is_empty());

    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", RECORD).run(move || {
        hook.recreate_zone("example.org");
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

// ---- TXT records -------------------------------------------------------------------------------

/// A create sends the documented body: type, the name in Punycode without the dot, the value
/// as a quoted character string, and the configured TTL.
#[tokio::test]
async fn cloudflare_add_creates_record() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    let posts = mock.log().matching(Some("POST"), RECORDS);
    assert_eq!(posts.len(), 1);
    assert_eq!(
        posts[0].body_json().unwrap(),
        serde_json::json!({"type": "TXT", "name": NAME, "content": "\"AAA\"", "ttl": 120})
    );
    assert_eq!(
        posts[0].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    let record = &mock.control().records()[0];
    assert_eq!((record.content.as_str(), record.ttl), ("\"AAA\"", 120));
    // The zone identifier was looked up once and cached.
    add(&client, "BBB").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONES), 1);
}

/// TTL policy (design section 3.6): the caller's TTL or the configured one for a new rrset; a
/// record added to an existing rrset takes the TTL of the set, and a set with an automatic
/// TTL gets an automatic one; the TTLs of other records are never changed.
#[tokio::test]
async fn cloudflare_ttl_policy() {
    let (mock, client) = setup().await;
    let control = mock.control();
    // A new rrset: the caller's TTL.
    client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("AAA"),
            Some(Ttl::from_secs(300).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(control.records()[0].ttl, 300);
    // An existing rrset: the TTL asked for the new value is ignored.
    client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("BBB"),
            Some(Ttl::from_secs(900).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(control.records()[1].ttl, 300);
    // The smallest TTL of the set is used.
    control.insert_record("example.org", NAME, "TXT", "\"low\"", 60);
    add(&client, "CCC").await.unwrap();
    assert_eq!(control.records()[3].ttl, 60);
    // A TTL outside the documented range is refused before any request.
    let before = mock.log().len();
    let e = client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("DDD"),
            Some(Ttl::from_secs(30).unwrap()),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(mock.log().len(), before);

    // An automatic set (TTL 1) stays automatic, and so does a client configured for it.
    let other = dn("_acme-challenge.auto.example.org");
    control.insert_record(
        "example.org",
        "_acme-challenge.auto.example.org",
        "TXT",
        "\"x\"",
        1,
    );
    client
        .add_txt_value(&zone(), &other, &txt("AAA"), None)
        .await
        .unwrap();
    assert_eq!(
        control.records_of("_acme-challenge.auto.example.org", "TXT")[1].ttl,
        1
    );
    let mut config = settings(&mock);
    config.ttl = 1;
    let auto = Cloudflare::new(config, credentials(TOKEN), &context()).unwrap();
    let fresh = dn("_acme-challenge.fresh.example.org");
    auto.add_txt_value(&zone(), &fresh, &txt("AAA"), None)
        .await
        .unwrap();
    assert_eq!(
        control.records_of("_acme-challenge.fresh.example.org", "TXT")[0].ttl,
        1
    );
    // The records created before kept theirs.
    assert_eq!(control.records()[2].ttl, 60);
}

/// The API's name filter is not trusted: records with other names and other types that an
/// answer carries are skipped.
#[tokio::test]
async fn cloudflare_exact_name_match_ignores_noisy_listing() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "\"foreign\"", 120);
    let body = serde_json::json!({
        "success": true, "errors": [], "messages": [],
        "result": [
            {"id": "a1", "type": "TXT", "name": format!("x.{NAME}"), "content": "\"AAA\"", "ttl": 120},
            {"id": "a2", "type": "TXT", "name": "_acme-challenge.example.org.evil.net", "content": "\"AAA\"", "ttl": 120},
            {"id": "a3", "type": "CNAME", "name": NAME, "content": "AAA", "ttl": 120},
            {"id": "a4", "type": "TXT", "name": NAME.to_uppercase(), "content": "\"foreign\"", "ttl": 120},
        ],
        "result_info": {"page": 1, "per_page": 100, "count": 4, "total_count": 4, "total_pages": 1},
    });
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(200, body.to_string()));
    // Neighbors carrying our value do not make it "present", and the upper-case spelling of the
    // owner name is the same name.
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    assert_eq!(control.txt_values(NAME), ["foreign", "AAA"]);
}

/// TXT dialect: values come back quoted or unquoted and are compared as data; ours is written
/// as a quoted character string. A quoted value that is split into strings equals the whole.
#[tokio::test]
async fn cloudflare_txt_dialect() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "\"AAA\"", 120);
    control.insert_record("example.org", NAME, "TXT", "BBB", 120);
    control.insert_record("example.org", NAME, "TXT", "\"CC\" \"CC\"", 120);
    for value in ["AAA", "BBB", "CCCC"] {
        assert_eq!(
            add(&client, value).await.unwrap(),
            AddOutcome::AlreadyPresent,
            "{value}"
        );
    }
    assert_eq!(writes(&mock), 0);
    // Values the client's dialect cannot carry are refused before any request.
    for bad in ["two words", "quo\"te", "back\\slash", "caf\u{e9}"] {
        let e = add(&client, bad).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad}: {e:?}");
    }
}

/// What the API answers to a create of a record that exists is not documented. The client does
/// not guess from an error code: a refused create is followed by a new read, and our value
/// found there (created by another writer after the operation's read) is a retryable
/// `Conflict`. The create was sent once, nothing was written by us, and the operation's repeat
/// reads the record and converges. A refusal with the value absent stays the refusal.
#[tokio::test]
async fn cloudflare_duplicate_create_is_conflict() {
    let (mock, client) = setup().await;
    let control = mock.control();
    // Another writer creates the same value between our read and our create.
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", RECORDS).run(move || {
        hook.insert_record("example.org", NAME, "TXT", "\"AAA\"", 120);
    }));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("POST"), RECORDS), 1);
    assert_eq!(
        mock.log().count(Some("GET"), RECORDS),
        2,
        "the refusal is read after"
    );
    assert_eq!(control.txt_values(NAME), ["AAA"]);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(mock.log().count(Some("POST"), RECORDS), 1);

    // The same refusal while the value is not there is the provider's refusal, as it said it.
    mock.faults().push(Fault::on("POST", RECORDS).respond(
        400,
        r#"{"success":false,"errors":[{"code":81058,"message":"An identical record already exists."}],"messages":[],"result":null}"#,
    ));
    let e = add(&client, "BBB").await.unwrap_err();
    match &e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(*status, Some(400));
            assert_eq!(
                detail.as_str(),
                "81058: An identical record already exists."
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(control.txt_values(NAME), ["AAA"]);
}

/// A 2xx answer whose envelope says `success: false` is a refusal, for a read and for a write.
#[tokio::test]
async fn cloudflare_success_false_is_rejected() {
    let (mock, client) = setup().await;
    let body = r#"{"success":false,"errors":[{"code":1001,"message":"nope"}],"messages":[],"result":null}"#;
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(200, body));
    let e = add(&client, "AAA").await.unwrap_err();
    match &e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(*status, Some(200));
            assert_eq!(detail.as_str(), "1001: nope");
        }
        other => panic!("{other:?}"),
    }
    mock.faults()
        .push(Fault::on("POST", RECORDS).respond(200, body));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(mock.control().records().is_empty());
}

/// Records are listed page by page, and the value is found on any page.
#[tokio::test]
async fn cloudflare_record_listing_reads_every_page() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_page_cap(1);
    control.insert_record("example.org", NAME, "TXT", "\"foreign-1\"", 120);
    control.insert_record("example.org", NAME, "TXT", "\"foreign-2\"", 120);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent,
        "the value is on page 3"
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt_values(NAME), ["foreign-1", "foreign-2"]);
    let gets = mock.log().matching(Some("GET"), RECORDS);
    assert!(
        gets.iter()
            .any(|r| r.query.as_deref().is_some_and(|q| q.contains("page=3")))
    );
}

/// A listing that is not complete is `Protocol`, never a shorter list, and nothing is written
/// after it: an empty page before the last, a page without the result list, a listing without
/// its page count, an answer that is not the envelope.
#[tokio::test]
async fn cloudflare_truncated_listing_is_protocol() {
    let (mock, client) = setup().await;
    mock.control()
        .insert_record("example.org", NAME, "TXT", "\"foreign\"", 120);
    let info = |pages: u32| serde_json::json!({"page": 1, "per_page": 100, "count": 0, "total_count": 3, "total_pages": pages});
    let bodies = [
        serde_json::json!({"success": true, "errors": [], "messages": [], "result": [], "result_info": info(2)}),
        serde_json::json!({"success": true, "errors": [], "messages": [], "result_info": info(1)}),
        serde_json::json!({"success": true, "errors": [], "messages": [], "result": null, "result_info": info(1)}),
        serde_json::json!({"success": true, "errors": [], "messages": [], "result": []}),
        serde_json::json!({"success": true, "errors": [], "messages": [], "result": [
            {"id": "a1", "type": "TXT", "name": NAME, "content": "\"x\"", "ttl": 120}
        ], "result_info": info(0)}),
        serde_json::json!({"unexpected": true}),
    ];
    for body in bodies {
        for write in [Write::Add, Write::Remove] {
            mock.faults()
                .push(Fault::on("GET", RECORDS).respond(200, body.to_string()));
            let e = match write {
                Write::Add => add(&client, "AAA").await.unwrap_err(),
                Write::Remove => remove(&client, "foreign").await.unwrap_err(),
            };
            assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
            assert_eq!(writes(&mock), 0, "{body}");
        }
    }
    // The same for the zone listing.
    mock.faults().push(Fault::on("GET", ZONES).respond(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"total_pages":2}}"#,
    ));
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    // Page 2 of 2 is empty after a non-empty page 1: the listing ended early.
    mock.control().set_page_cap(5);
    for i in 0..5 {
        mock.control().insert_zone(&format!("z{i}.example.net"));
    }
    mock.faults().push(Fault::on("GET", ZONES).skip(1).respond(
        200,
        r#"{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"total_pages":3}}"#,
    ));
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// An identifier the API returns that cannot go into a URL path is `Protocol`, and nothing is
/// requested with it.
#[tokio::test]
async fn cloudflare_unsafe_identifiers_are_protocol() {
    let (mock, client) = setup().await;
    let record = |id: &str| {
        serde_json::json!({
            "success": true, "errors": [], "messages": [],
            "result": [{"id": id, "type": "TXT", "name": NAME, "content": "\"AAA\"", "ttl": 120}],
            "result_info": {"page": 1, "per_page": 100, "count": 1, "total_count": 1, "total_pages": 1},
        })
    };
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(200, record("../../zones").to_string()));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(mock.log().count(Some("DELETE"), "/*"), 0);
    assert_eq!(writes(&mock), 0);
    mock.faults().push(Fault::on("GET", ZONES).respond(
        200,
        serde_json::json!({
            "success": true, "errors": [], "messages": [],
            "result": [{"id": "a/b", "name": "example.org", "status": "active"}],
            "result_info": {"page": 1, "per_page": 50, "count": 1, "total_count": 1, "total_pages": 1},
        })
        .to_string(),
    ));
    let fresh = client_with(&mock, TOKEN, &context());
    let e = fresh
        .add_txt_value(&zone(), &name(), &txt("A"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

// ---- Zones -------------------------------------------------------------------------------------

#[tokio::test]
async fn cloudflare_zone_not_found() {
    let (mock, client) = setup().await;
    let other = dn("example.net");
    let e = client
        .add_txt_value(&other, &dn("x.example.net"), &txt("A"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let e = client
        .remove_txt_value(&other, &dn("x.example.net"), &txt("A"))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    assert_eq!(writes(&mock), 0);
    // A zone whose name merely contains the asked one is not the zone.
    mock.control().insert_zone("badexample.org");
    mock.control().insert_zone("example.org.evil.net");
    let e = client
        .add_txt_value(&dn("xample.org"), &dn("x.xample.org"), &txt("A"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
}

/// The zone lookup takes only a zone whose name equals the asked one, whatever the API's name
/// filter lets through, and of two zones with that name the active one.
#[tokio::test]
async fn cloudflare_zone_lookup_matches_exactly_and_prefers_active() {
    let (mock, client) = setup().await;
    let real = mock.control().zone_id("example.org");
    let body = serde_json::json!({
        "success": true, "errors": [], "messages": [],
        "result": [
            {"id": "0000000000000000000000000000bad1", "name": "badexample.org", "status": "active"},
            {"id": "0000000000000000000000000000bad2", "name": "example.org.evil.net", "status": "active"},
            {"id": "0000000000000000000000000000bad3", "name": "example.org", "status": "pending"},
            {"id": real, "name": "EXAMPLE.org", "status": "active"},
        ],
        "result_info": {"page": 1, "per_page": 50, "count": 4, "total_count": 4, "total_pages": 1},
    });
    mock.faults()
        .push(Fault::on("GET", ZONES).respond(200, body.to_string()));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    for entry in mock.log().entries() {
        assert!(!entry.path.contains("bad"), "{}", entry.path);
    }
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);
}

/// The status of a stale zone identifier is not documented. A read refused under a cached
/// identifier (here `400` and `403`) makes the client look the zone up again and repeat the
/// read once; under a freshly looked-up identifier the refusal is the error, and nothing is
/// written in either case.
#[tokio::test]
async fn cloudflare_refused_read_under_cached_zone_id_looks_up_again() {
    let (mock, client) = setup().await;
    let refusal = r#"{"success":false,"errors":[{"code":7003,"message":"No route for the URI"}],"messages":[],"result":null}"#;
    let lookups = || mock.log().count(Some("GET"), ZONES);
    let reads = || mock.log().count(Some("GET"), RECORDS);
    add(&client, "v1").await.unwrap();
    assert_eq!(lookups(), 1);
    for status in [400, 403] {
        mock.faults()
            .push(Fault::on("GET", RECORDS).respond(status, refusal));
        assert_eq!(
            add(&client, "v1").await.unwrap(),
            AddOutcome::AlreadyPresent,
            "{status}"
        );
    }
    assert_eq!(lookups(), 3);
    assert_eq!(reads(), 5);

    let fresh = client_with(&mock, TOKEN, &context());
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(400, refusal));
    let e = add(&fresh, "v2").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!((lookups(), reads()), (4, 6));
    assert_eq!(writes(&mock), 1);
}

/// A zone that is not active is reported as unusable and writes to it are refused.
#[tokio::test]
async fn cloudflare_zone_not_active() {
    let (mock, client) = setup().await;
    mock.control().set_zone_status("example.org", "pending");
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    assert!(report.zones[0].detail.is_some());
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert!(client.list_zones().await.unwrap().is_empty());
}

/// `check` exercises the credentials on every call, with or without zones, and reports each
/// zone in the order given.
#[tokio::test]
async fn cloudflare_check_reports_zones() {
    let (mock, client) = setup().await;
    let report = client.check(&[]).await.unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones.is_empty());
    assert_eq!(mock.log().count(Some("GET"), ZONES), 1);
    let report = client.check(&[zone()]).await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONES), 3);
    assert!(report.credentials_verified);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.credentials_verified);
    assert_eq!(
        mock.log().count(Some("GET"), ZONES),
        5,
        "every call is a request"
    );

    let report = client.check(&[dn("example.net"), zone()]).await.unwrap();
    assert_eq!(report.zones.len(), 2);
    assert_eq!(report.zones[0].zone, dn("example.net"));
    assert!(!report.zones[0].found && report.zones[0].detail.is_none());
    assert!(report.zones[1].found);

    // A zone recreated since the last check is found under its new identifier.
    mock.control().recreate_zone("example.org");
    assert!(client.check(&[zone()]).await.unwrap().zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);

    // Wrong credentials are refused by the very first request, also with no zone asked for.
    let wrong = client_with(&mock, "wrong-token", &context());
    for zones in [vec![], vec![zone()]] {
        let e = wrong.check(&zones).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    }
    // A token that stops working is noticed: a static token has no cache that could hide it.
    mock.faults().push(Fault::on("GET", ZONES).status(401));
    let e = client.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
}

/// Every active zone the token sees, all pages, sorted and unique; inactive ones are left out.
#[tokio::test]
async fn cloudflare_list_zones_all_pages() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_page_cap(5);
    for i in 0..12 {
        control.insert_zone(&format!("zone{i:02}.example.net"));
    }
    control.set_zone_status("zone03.example.net", "pending");
    let zones = client.list_zones().await.unwrap();
    assert_eq!(zones.len(), 12, "{zones:?}");
    assert!(zones.iter().any(|z| z.name == zone()));
    assert!(!zones.iter().any(|z| z.name == dn("zone03.example.net")));
    assert!(zones.windows(2).all(|w| w[0].name < w[1].name));
    assert_eq!(mock.log().count(Some("GET"), ZONES), 3);
    // The identifiers of the listing are cached: a write needs no lookup.
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONES), 3);
    let wrong = client_with(&mock, "wrong", &context());
    assert_eq!(
        wrong.list_zones().await.unwrap_err().kind(),
        ErrorKind::Auth
    );
}

/// Names with non-ASCII labels are sent in Punycode, as the API documents.
#[tokio::test]
async fn cloudflare_internationalized_names_are_sent_in_punycode() {
    let mock = CloudflareMock::start(Seed {
        token: TOKEN.into(),
        zones: vec!["xn--e1afmkfd.example".into()],
    })
    .await;
    let client = client_with(&mock, TOKEN, &context());
    let zone = dn("пример.example");
    let name = dn("_acme-challenge.пример.example");
    assert_eq!(
        client
            .add_txt_value(&zone, &name, &txt("AAA"), None)
            .await
            .unwrap(),
        AddOutcome::Created
    );
    let posts = mock.log().matching(Some("POST"), RECORDS);
    assert_eq!(
        posts[0].body_json().unwrap()["name"],
        "_acme-challenge.xn--e1afmkfd.example"
    );
    assert_eq!(
        client
            .remove_txt_value(&zone, &name, &txt("AAA"))
            .await
            .unwrap(),
        RemoveOutcome::RrsetDeleted
    );
}

// ---- Transport ---------------------------------------------------------------------------------

/// A short `Retry-After` on a read is waited out; a long one is `RateLimited` with the wait.
#[tokio::test]
async fn cloudflare_rate_limit() {
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
async fn cloudflare_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RECORDS).status(500));
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("GET", RECORDS).times(3).status(503));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 5);
}

/// 401 and 403 are `Auth` and `Forbidden`; a refusal of the 4xx class is `Rejected` with the
/// status and the provider's `code: message`; any other status is `Protocol`.
#[tokio::test]
async fn cloudflare_status_mapping() {
    let (mock, client) = setup().await;
    let envelope = |code: i64, message: &str| {
        serde_json::json!({"success": false, "errors": [{"code": code, "message": message}],
            "messages": [], "result": null})
        .to_string()
    };
    mock.faults()
        .push(Fault::on("GET", ZONES).respond(401, envelope(10000, "Authentication error")));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(e.to_string().contains("10000: Authentication error"), "{e}");
    mock.faults()
        .push(Fault::on("GET", ZONES).respond(403, envelope(9109, "Unauthorized")));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    mock.faults().push(
        Fault::on("POST", RECORDS).respond(400, envelope(9005, "Content for A record is invalid")),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(400));
            assert_eq!(detail.as_str(), "9005: Content for A record is invalid");
        }
        other => panic!("{other:?}"),
    }
    mock.faults()
        .push(Fault::on("POST", RECORDS).respond(409, envelope(1, "conflict")));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(302, ""));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(mock.control().records().is_empty());
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn cloudflare_from_json_builds_the_client() {
    let mock = CloudflareMock::start(Seed::standard()).await;
    let ctx = context();
    let client = AnyProvider::from_json(
        ProviderId::Cloudflare,
        &settings_json(&mock),
        &SecretString::from(format!("{{\"api_token\": \"{TOKEN}\", \"other\": 1}}")),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Cloudflare);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &txt("AAA"), None)
            .await
            .unwrap(),
        AddOutcome::Created
    );
    // An empty settings object is the defaults: the public API, refused by the test context.
    let e = AnyProvider::from_json(
        ProviderId::Cloudflare,
        "{}",
        &SecretString::from(format!("{{\"api_token\": \"{TOKEN}\"}}")),
        &ctx,
    )
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
    assert!(e.to_string().contains("base_url"), "{e}");
    // A token with surrounding whitespace is used trimmed.
    let spaced = AnyProvider::from_json(
        ProviderId::Cloudflare,
        &settings_json(&mock),
        &SecretString::from(format!("{{\"api_token\": \"  {TOKEN}\\n\"}}")),
        &ctx,
    )
    .unwrap();
    assert!(spaced.check(&[]).await.unwrap().credentials_verified);
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn cloudflare_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || serde_json::json!({"base_url": "http://127.0.0.1:1/client/v4"});
    let with = |key: &str, value: serde_json::Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let token = serde_json::json!({"api_token": "tok"}).to_string();
    let cases = [
        (with("ttl", serde_json::json!(30)), token.clone(), "ttl"),
        (with("ttl", serde_json::json!(0)), token.clone(), "ttl"),
        (with("ttl", serde_json::json!(86401)), token.clone(), "ttl"),
        (
            with(
                "base_url",
                serde_json::json!(format!("https://u:{canary}@api.example.org")),
            ),
            token.clone(),
            "base_url",
        ),
        (
            with(
                "base_url",
                serde_json::json!(format!("http://api.example.org/?{canary}")),
            ),
            token.clone(),
            "base_url",
        ),
        (
            with(canary, serde_json::json!(canary)),
            token.clone(),
            "unknown keys",
        ),
        (
            base(),
            serde_json::json!({"api_token": 5, canary: canary}).to_string(),
            "api_token",
        ),
        (
            base(),
            serde_json::json!({"password": canary}).to_string(),
            "api_token",
        ),
        (
            base(),
            serde_json::json!({"api_token": ""}).to_string(),
            "api_token",
        ),
        (
            base(),
            serde_json::json!({"api_token": " \t"}).to_string(),
            "api_token",
        ),
        (
            base(),
            serde_json::json!({"api_token": format!("{canary}\nx")}).to_string(),
            "api_token",
        ),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::Cloudflare,
            &settings.to_string(),
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{key}: {e:?}");
        let text = format!("{e} | {e:?}");
        if key != "unknown keys" {
            assert!(text.contains(key), "{key}: {text}");
        }
        assert!(!text.contains(canary), "{key}: {text}");
    }
    // The automatic TTL and the documented bounds are accepted.
    for ttl in [1, 60, 120, 86_400] {
        AnyProvider::from_json(
            ProviderId::Cloudflare,
            &with("ttl", serde_json::json!(ttl)).to_string(),
            &SecretString::from(token.clone()),
            &ctx,
        )
        .unwrap_or_else(|e| panic!("ttl {ttl}: {e:?}"));
    }
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round; the defaults of the metadata are those of the settings type.
#[test]
fn cloudflare_config_keys_match_metadata() {
    let meta = ProviderId::Cloudflare.meta();
    let defaults = serde_json::to_value(CloudflareConfig::default()).unwrap();
    let mut settings_keys: Vec<&str> = defaults
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
        let value = &defaults[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
    }
}

/// The capabilities say what the client does: the value operations, `list_zones`, nothing at
/// record level, one record per value.
#[test]
fn cloudflare_capabilities_match_the_client() {
    use zonewright::{Operation, ValueGuarantee};
    let caps = &ProviderId::Cloudflare.meta().capabilities;
    for op in [
        Operation::Check,
        Operation::ListZones,
        Operation::AddTxtValue,
        Operation::RemoveTxtValue,
    ] {
        assert!(caps.supports(op), "{op}");
    }
    for op in [
        Operation::ListRrsets,
        Operation::GetRrset,
        Operation::SetRrset,
        Operation::DeleteRrset,
    ] {
        assert!(!caps.supports(op), "{op}");
    }
    assert_eq!(caps.txt_values, ValueGuarantee::PerValue);
    assert!(caps.txt_plain_only);
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
async fn live_cloudflare_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_CLOUDFLARE_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_CLOUDFLARE_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_CLOUDFLARE_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::Cloudflare,
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
