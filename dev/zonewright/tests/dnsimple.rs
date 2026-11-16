//! Tests of the DNSimple client (`dnsimple`) against its mock.
#![cfg(feature = "dnsimple")]
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
use zonewright::providers::dnsimple::{Dnsimple, DnsimpleConfig, DnsimpleCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl, SetOutcome,
    SkipReason, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::dnsimple::{DnsimpleMock, Extra, Paging, Seed};
use zonewright_mock::echo::{EchoServer, Echoed, Render};

use common::echo::{CANARY_KEY, CANARY_TOKEN, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The account token of the standard seed.
const TOKEN: &str = "test-only-token";

/// The account of the standard seed.
const ACCOUNT: u64 = 1010;

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const WHOAMI: &str = "/v2/whoami";
const ZONES: &str = "/v2/*/zones";
const ZONE: &str = "/v2/*/zones/*";
const RECORDS: &str = "/v2/*/zones/*/records";
const RECORD: &str = "/v2/*/zones/*/records/*";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings pointed at `base_url`, the account read from the token.
fn settings(base_url: String) -> DnsimpleConfig {
    let mut config = DnsimpleConfig::default();
    config.base_url = base_url;
    config
}

fn credentials(token: &str) -> DnsimpleCredentials {
    DnsimpleCredentials::new(SecretString::from(token.to_owned()))
}

fn client_with(mock: &DnsimpleMock, token: &str, ctx: &Context) -> Dnsimple {
    Dnsimple::new(settings(mock.base_url()), credentials(token), ctx).unwrap()
}

/// A client with `account_id` in its settings.
fn client_for_account(mock: &DnsimpleMock, token: &str, account: u64) -> Dnsimple {
    let mut config = settings(mock.base_url());
    config.account_id = Some(account);
    Dnsimple::new(config, credentials(token), &context()).unwrap()
}

async fn setup() -> (DnsimpleMock, Dnsimple) {
    let mock = DnsimpleMock::start(Seed::standard()).await;
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
fn writes(mock: &DnsimpleMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), RECORDS)
        + log.count(Some("PATCH"), RECORD)
        + log.count(Some("DELETE"), RECORD)
}

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

/// The contents of the records of `rtype` at `owner`, sorted.
fn stored(mock: &DnsimpleMock, owner: &str, rtype: &str) -> Vec<String> {
    let mut values: Vec<String> = mock
        .control()
        .records_at(owner, rtype)
        .into_iter()
        .map(|r| r.content)
        .collect();
    values.sort();
    values
}

/// A listing answer in the documented shape.
fn listing_body(records: &serde_json::Value, total: usize, page: usize, pages: usize) -> String {
    serde_json::json!({
        "data": records,
        "pagination": {
            "current_page": page, "per_page": 100, "total_entries": total, "total_pages": pages
        }
    })
    .to_string()
}

/// One record in the documented shape.
fn record_json(id: u64, rtype: &str, name: &str, content: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id, "zone_id": "example.org", "parent_id": null, "name": name,
        "content": content, "ttl": 120, "priority": null, "type": rtype,
        "regions": ["global"], "system_record": false,
        "created_at": "2016-01-07T17:45:13Z", "updated_at": "2016-01-07T17:45:13Z"
    })
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

assert_not_impl!(Dnsimple: std::fmt::Display, serde::Serialize);
assert_not_impl!(DnsimpleCredentials: std::fmt::Display, serde::Serialize);

/// What the echo's listings answer.
#[derive(Clone, Copy, Debug)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
    /// A CNAME at the name, for the in-place update of the record level.
    Cname,
}

/// A renderer that answers the zone and the record listings like the API and every other
/// request with `errors`.
fn zone_then(errors: Render, existing: Existing) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method != Method::GET {
            return errors(e);
        }
        if !e.path.ends_with("/records") {
            let body =
                serde_json::json!({"data": {"id": 1, "name": "example.org", "active": true}});
            return (StatusCode::OK, axum::Json(body)).into_response();
        }
        let records = match existing {
            Existing::Nothing => serde_json::json!([]),
            Existing::Foreign => {
                serde_json::json!([record_json(1001, "TXT", "_acme-challenge", "foreign")])
            }
            Existing::Ours => {
                serde_json::json!([record_json(1001, "TXT", "_acme-challenge", "v1")])
            }
            Existing::Cname => serde_json::json!([record_json(
                1001,
                "CNAME",
                "_acme-challenge",
                "old.example.net"
            )]),
        };
        let count = records.as_array().map_or(0, Vec::len);
        let body = listing_body(&records, count, 1, 1);
        (StatusCode::OK, [("content-type", "application/json")], body).into_response()
    })
}

/// A renderer that answers `whoami` like the API (an account token) and every other request
/// with `errors`.
fn whoami_then(errors: Render) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method == Method::GET && e.path.ends_with("/whoami") {
            let body = serde_json::json!({"data": {"user": null, "account": {"id": ACCOUNT}}});
            return (StatusCode::OK, axum::Json(body)).into_response();
        }
        errors(e)
    })
}

/// A client of the echo with `account_id` set, so that no request but `check` needs `whoami`.
fn echo_client(echo: &EchoServer, ctx: &Context) -> Dnsimple {
    let mut config = settings(echo.url("/v2"));
    config.account_id = Some(ACCOUNT);
    Dnsimple::new(config, credentials(CANARY_TOKEN), ctx).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Write {
    Add,
    Remove,
}

/// `check` and a write against an echo that quotes every request back: no canary in any error,
/// `ZoneCheck::detail` or `Debug`, and the write's error shows the redaction.
async fn echo_round(label: &str, client: &Dnsimple, write: Write) {
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

/// `check` and the TXT writes against an echo, for every dialect. Four kinds of request reach
/// it: the identity read, the zone read, the create and the delete; each is sent the number of
/// times the retry rule allows.
#[tokio::test]
async fn dnsimple_secret_echo() {
    // One server and one context for every case: each case reconfigures the server, and
    // every client reuses the context's pooled connection (see `EchoServer::reset`).
    let ctx = context();
    let echo = EchoServer::start(200).await;
    for dialect in dialects() {
        // The identity read is the echo.
        for status in [400, 401] {
            let label = format!("{} {:?} {status} whoami", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status));
            let client = echo_client(&echo, &ctx);
            echo_round(&label, &client, Write::Add).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
        }
        // The identity read is answered; the zone read is the echo.
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} zone", dialect.name, dialect.spelling);
            echo.reset(
                dialect
                    .echo(status)
                    .render_under(WHOAMI, whoami_then(dialect.render.clone())),
            );
            let client = echo_client(&echo, &ctx);
            let e = client.check(&[zone()]).await.unwrap_err();
            let text = format!("{e} | {e:?} | {client:?}");
            assert_clean(&label, &text, &[CANARY_TOKEN]);
            assert_eq!(
                echo.log().count(Some("GET"), ZONE),
                1,
                "{label}: the zone read did not reach the echo once"
            );
        }
        // The identity and the listings answer normally, so the write itself reaches the echo:
        // a create (with and without a foreign record at the name) and a delete. A 500 to an
        // idempotent read would be retried with real back-off sleeps, without coverage: the
        // reads are answered.
        for (existing, write, statuses) in [
            (
                Existing::Nothing,
                Write::Add,
                [400, 401, 402, 403, 412, 500].as_slice(),
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
                echo.reset(
                    dialect
                        .echo(status)
                        .render_under(WHOAMI, whoami_then(dialect.render.clone()))
                        .render_under(
                            "/v2/1010/zones",
                            zone_then(dialect.render.clone(), existing),
                        ),
                );
                let client = echo_client(&echo, &ctx);
                echo_round(&label, &client, write).await;
                let (method, path) = match write {
                    Write::Add => ("POST", RECORDS),
                    Write::Remove => ("DELETE", RECORD),
                };
                // A create is sent once; a delete is idempotent but none of these statuses is
                // retried.
                assert_eq!(
                    echo.log().count(Some(method), path),
                    1,
                    "{label}: the write did not reach the echo exactly once"
                );
            }
        }
    }
}

/// What the echo answers for each record-level request kind.
#[derive(Clone, Copy, Debug)]
enum RecordWrite {
    /// A create: no record at the name.
    Create,
    /// An update in place: a CNAME at the name.
    Update,
    /// A delete: a TXT record at the name.
    Delete,
    /// The zone listing itself is the echo.
    List,
}

/// The record-level requests against an echo, for every dialect: the create, the update, the
/// delete and the zone listing. No canary in any error or `Debug`, the error shows the
/// redaction, and each request reached the echo the expected number of times.
#[tokio::test]
async fn dnsimple_secret_echo_record_level() {
    let ctx = context();
    let echo = EchoServer::start(200).await;
    for dialect in dialects() {
        for (kind, statuses) in [
            (RecordWrite::Create, [400, 401, 403, 412, 500].as_slice()),
            (RecordWrite::Update, [400, 401, 403, 500].as_slice()),
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
                        "/v2/1010/zones",
                        zone_then(dialect.render.clone(), existing),
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
                    RecordWrite::Update => ("PATCH", RECORD),
                    RecordWrite::Delete => ("DELETE", RECORD),
                    RecordWrite::List => ("GET", RECORDS),
                };
                assert_eq!(
                    echo.log().count(Some(method), path),
                    1,
                    "{label}: the request did not reach the echo exactly once"
                );
            }
        }
    }
}

/// A `TRACE` capture over a success, repeated 401s, a 500 and a wrong token: the transport's
/// events are there, and no canary is.
#[tokio::test(flavor = "current_thread")]
async fn dnsimple_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.token = CANARY_TOKEN.into();
    let mock = DnsimpleMock::start(seed).await;
    let client = client_with(&mock, CANARY_TOKEN, &context());
    let mut texts = Vec::new();

    add(&client, "v1").await.unwrap();
    remove(&client, "v1").await.unwrap();
    client
        .set_rrset(
            &zone(),
            &rr("www.example.org", RecordType::A, None, &["192.0.2.1"]),
            Expect::Any,
        )
        .await
        .unwrap();

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
            "dnsimple logs and errors",
            text,
            &[CANARY_TOKEN, CANARY_KEY],
        );
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely ends
/// with the zone's text, the zone's text inside another name, and a sibling zone.
#[tokio::test]
async fn dnsimple_name_outside_zone_sends_nothing() {
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
        let set = RrSet::new(
            name.clone(),
            RecordType::A,
            None,
            [rdata(RecordType::A, "192.0.2.1")],
        )
        .unwrap();
        let e = client
            .set_rrset(&zone, &set, Expect::Any)
            .await
            .unwrap_err();
        assert!(matches!(e, Error::NameOutsideZone { .. }), "{e:?}");
        let e = client
            .delete_rrset(&zone, &name, RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert!(matches!(e, Error::NameOutsideZone { .. }), "{e:?}");
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
}

/// A value the capabilities do not accept and a TTL outside the range are refused before any
/// request.
#[tokio::test]
async fn dnsimple_invalid_input_sends_nothing() {
    let (mock, client) = setup().await;
    for value in ["two words", "quo\"te", "back\\slash"] {
        let e = add(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
        let e = remove(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
    }
    for ttl in [10, 59, 259_201] {
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
    let e = client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("v1"),
            Some(RrsetTtl::ProviderDefault),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
}

/// `Created`, `Appended` for a second value (the apex and the wildcard of one certificate share
/// a name), then `AlreadyPresent` without a write.
#[tokio::test]
async fn dnsimple_add_is_idempotent() {
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
async fn dnsimple_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "foreign-1", 600);
    control.insert_record("example.org", NAME, "TXT", "foreign-2", 900);
    let original = control.records();

    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    assert_eq!(control.txt_values(NAME), ["foreign-1", "foreign-2", "ours"]);
    // The value joined the set with the set's TTL as read (the smallest).
    assert_eq!(control.records_at(NAME, "TXT")[2].ttl, 600);
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.records(), original);
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 1);

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_record("example.org", other, "TXT", "foreign", 60);
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &txt("ours"))
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(control.txt_values(other), ["foreign"]);
}

/// Records of other types at the same name and TXT records at other names are not touched and
/// are not mistaken for ours, also when an answer holds them (the type filter is checked on the
/// client's side).
#[tokio::test]
async fn dnsimple_other_types_at_the_name_are_untouched() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "A", "192.0.2.1", 300);
    control.insert_record("example.org", "other.example.org", "TXT", "AAA", 300);
    let original = control.records();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(control.records(), original);

    // An answer with an A record of the value at the name: not ours.
    let body = listing_body(
        &serde_json::json!([record_json(1, "A", "_acme-challenge", "AAA")]),
        1,
        1,
        1,
    );
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(200, body));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

#[tokio::test]
async fn dnsimple_remove_last_value_deletes_rrset() {
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
async fn dnsimple_remove_is_idempotent() {
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
async fn dnsimple_remove_deletes_every_copy_of_the_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "AAA", 120);
    control.insert_record("example.org", NAME, "TXT", "foreign", 120);
    control.insert_record("example.org", NAME, "TXT", "AAA", 120);
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
async fn dnsimple_concurrent_adds_are_serialized() {
    let mock = DnsimpleMock::start(Seed::standard()).await;
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
async fn dnsimple_foreign_value_added_between_read_and_write_survives() {
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

/// The zone is deleted and created again between the read and the delete: the delete is
/// answered 404, and the removal never reports success for a value that is still published. A
/// record that is gone for another reason is a success.
#[tokio::test]
async fn dnsimple_delete_not_found_reads_again() {
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

/// Retry behavior: a create is sent once whatever happens (a 502, a 429, a 401 and a 400 are the
/// operation's error, and the repeat starts with a read); a repeated create could add a second
/// copy of the value.
#[tokio::test]
async fn dnsimple_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let posts = || mock.log().count(Some("POST"), RECORDS);

    for (fault, kind) in [
        (Fault::on("POST", RECORDS).status(502), ErrorKind::Transient),
        (
            Fault::on("POST", RECORDS).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("POST", RECORDS).status(401), ErrorKind::Auth),
        (Fault::on("POST", RECORDS).status(403), ErrorKind::Forbidden),
        (
            Fault::on("POST", RECORDS).respond(
                400,
                r#"{"message":"Validation failed","errors":{"content":["is invalid"]}}"#,
            ),
            ErrorKind::Rejected,
        ),
    ] {
        let before = posts();
        mock.faults().push(fault);
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(posts(), before + 1, "{e:?}");
        assert!(mock.control().records().is_empty());
    }

    // The create is answered 502 but was applied: the repeat finds the value instead of
    // adding a second copy.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("POST", RECORDS)
            .run(move || {
                hook.insert_record("example.org", NAME, "TXT", "AAA", 120);
            })
            .status(502),
    );
    let before = posts();
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(posts(), before + 1);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(posts(), before + 1);
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);
}

/// The delete of one record by its identifier is the one write that is repeated: a 502 is
/// retried, and a retry that finds the record gone is a success. A rate limit with a long wait,
/// a rejected token and a refusal are not repeated.
#[tokio::test]
async fn dnsimple_delete_by_id_is_retried() {
    let (mock, client) = setup().await;
    let deletes = || mock.log().count(Some("DELETE"), RECORD);
    add(&client, "AAA").await.unwrap();
    mock.faults().push(Fault::on("DELETE", RECORD).status(502));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(deletes(), 2);

    add(&client, "AAA").await.unwrap();
    for (fault, kind) in [
        (
            Fault::on("DELETE", RECORD).rate_limited("120"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("DELETE", RECORD).status(401), ErrorKind::Auth),
        (Fault::on("DELETE", RECORD).status(400), ErrorKind::Rejected),
    ] {
        let before = deletes();
        mock.faults().push(fault);
        let e = remove(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(deletes(), before + 1, "{e:?}");
        assert_eq!(mock.control().txt_values(NAME), ["AAA"]);
    }
}

// ---- The account -------------------------------------------------------------------------------

/// With an account token and no `account_id`, the account is read once with `whoami` and used
/// in every path; `check` reads the identity on every call.
#[tokio::test]
async fn dnsimple_account_is_read_once_from_the_token() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    add(&client, "BBB").await.unwrap();
    client.list_rrsets(&zone()).await.unwrap();
    client.list_zones().await.unwrap();
    remove(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), WHOAMI), 1);
    for request in mock.log().entries() {
        assert!(
            request.path == WHOAMI || request.path.starts_with("/v2/1010/zones"),
            "{}",
            request.path
        );
    }
    client.check(&[zone()]).await.unwrap();
    client.check(&[zone()]).await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), WHOAMI), 3);

    // A failed `whoami` is not remembered: the next call reads it again.
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", WHOAMI).status(401));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.log().count(Some("GET"), WHOAMI), 2);
}

/// A user token reaches every account of its user, and `whoami` names none: without
/// `account_id` every operation is `Error::Config` after the identity read and before any other
/// request; with it, the client works and reads the identity only in `check`.
#[tokio::test]
async fn dnsimple_user_token_needs_account_id() {
    let mut seed = Seed::standard();
    seed.user_tokens = vec!["test-only-user-token".into()];
    let mock = DnsimpleMock::start(seed).await;
    let client = client_with(&mock, "test-only-user-token", &context());
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
    assert!(e.to_string().contains("account_id"), "{e}");
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
    assert_eq!(mock.log().len(), mock.log().count(Some("GET"), WHOAMI));

    mock.log().clear();
    let client = client_for_account(&mock, "test-only-user-token", ACCOUNT);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.log().count(Some("GET"), WHOAMI), 0);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert_eq!(mock.log().count(Some("GET"), WHOAMI), 1);
}

/// `account_id` that is not the account of an account token is `Error::Config` in `check`; an
/// operation under another account is answered 404, the zone not visible.
#[tokio::test]
async fn dnsimple_configured_account_must_be_the_tokens() {
    let mock = DnsimpleMock::start(Seed::standard()).await;
    let client = client_for_account(&mock, TOKEN, 999);
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), ZONE), 0);
    let e = add(&client, "AAA").await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    assert!(mock.control().records().is_empty());

    let client = client_for_account(&mock, TOKEN, ACCOUNT);
    client.check(&[zone()]).await.unwrap();
}

// ---- Requests and answers ----------------------------------------------------------------------

/// The requests as the sources describe them: the identity, the listing filtered by type with
/// the documented maximum page size, the create with the relative name, `""` for the apex.
#[tokio::test]
async fn dnsimple_request_shapes() {
    let (mock, client) = setup().await;
    add(&client, "v1").await.unwrap();
    let log = mock.log();
    let get = log.matching(Some("GET"), RECORDS).pop().unwrap();
    assert_eq!(get.path, "/v2/1010/zones/example.org/records");
    assert_eq!(get.query.as_deref(), Some("type=TXT&per_page=100&page=1"));
    assert_eq!(
        get.headers.get("authorization").unwrap(),
        &format!("Bearer {TOKEN}")
    );
    let post = log.matching(Some("POST"), RECORDS).pop().unwrap();
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({"name": "_acme-challenge", "type": "TXT", "content": "v1", "ttl": 120})
    );
    assert_eq!(post.header("content-type"), Some("application/json"));
    client
        .add_txt_value(&zone(), &zone(), &txt("apex"), None)
        .await
        .unwrap();
    let post = mock.log().matching(Some("POST"), RECORDS).pop().unwrap();
    assert_eq!(post.body_json().unwrap()["name"], "");
    assert_eq!(mock.control().txt_values("example.org"), ["apex"]);
    let delete_path = {
        remove(&client, "v1").await.unwrap();
        mock.log()
            .matching(Some("DELETE"), RECORD)
            .pop()
            .unwrap()
            .path
    };
    assert!(delete_path.starts_with("/v2/1010/zones/example.org/records/"));
}

/// An answer may state TXT content wrapped in quotes (the form the provider publishes): the
/// values read the same, and a repeat neither writes nor removes the wrong record.
#[tokio::test]
async fn dnsimple_quoted_txt_answers_read_the_same() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_txt_quoted(true);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    control.insert_record("example.org", NAME, "TXT", "\"foreign\"", 120);
    assert_eq!(
        client
            .get_rrset(&zone(), &name(), RecordType::TXT)
            .await
            .unwrap(),
        Some(rr(
            NAME,
            RecordType::TXT,
            Some(120),
            &["\"AAA\"", "\"foreign\""]
        ))
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt_values(NAME), ["\"foreign\""]);
}

/// The TTL a value is written with: the configured one for a new set, the caller's when given,
/// the set's own when the name has TXT records.
#[tokio::test]
async fn dnsimple_ttl_policy() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.control().records()[0].ttl, 120);
    client
        .add_txt_value(
            &zone(),
            &dn("_acme-challenge.www.example.org"),
            &txt("v"),
            Some(RrsetTtl::from_secs(300).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        mock.control()
            .records_at("_acme-challenge.www.example.org", "TXT")[0]
            .ttl,
        300
    );
    let mut config = settings(mock.base_url());
    config.ttl = RrsetTtl::from_secs(3600).unwrap();
    let configured = Dnsimple::new(config, credentials(TOKEN), &context()).unwrap();
    configured
        .add_txt_value(&zone(), &dn("_x.example.org"), &txt("v"), None)
        .await
        .unwrap();
    assert_eq!(
        mock.control().records_at("_x.example.org", "TXT")[0].ttl,
        3600
    );
    // Joining a set takes the set's TTL.
    configured
        .add_txt_value(&zone(), &name(), &txt("BBB"), None)
        .await
        .unwrap();
    assert_eq!(mock.control().records_at(NAME, "TXT")[1].ttl, 120);
}

/// A listing reads every page by number, with the documented page size; a listing that is
/// short of its total, that repeats a page, answers another page or states too few pages is
/// `Error::Protocol`, and nothing is written after it.
#[tokio::test]
async fn dnsimple_listing_pages_by_number() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for i in 0..5 {
        control.insert_record("example.org", NAME, "TXT", &format!("v{i}"), 120);
    }
    control.set_page_cap(2);
    assert_eq!(
        add(&client, "v4").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    let gets = mock.log().matching(Some("GET"), RECORDS);
    let queries: Vec<String> = gets.iter().map(|r| r.query.clone().unwrap()).collect();
    assert_eq!(
        queries,
        [
            "type=TXT&per_page=100&page=1",
            "type=TXT&per_page=100&page=2",
            "type=TXT&per_page=100&page=3"
        ]
    );
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(listing.rrsets[0].records().len(), 5);

    for paging in [Paging::IgnorePage, Paging::OnePage] {
        control.set_paging(paging);
        let before = writes(&mock);
        let e = add(&client, "new").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{paging:?}: {e:?}");
        let e = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{paging:?}: {e:?}");
        assert_eq!(writes(&mock), before, "{paging:?}");
    }
    control.set_paging(Paging::Standard);

    // Answers built by hand: short of the total, another page than asked, an empty page before
    // the end, and a total that changes between pages.
    let one = serde_json::json!([record_json(1, "TXT", "_acme-challenge", "x")]);
    let other = serde_json::json!([record_json(2, "TXT", "_acme-challenge", "y")]);
    for bodies in [
        vec![listing_body(&one, 2, 1, 1)],
        vec![listing_body(&one, 1, 2, 1)],
        vec![
            listing_body(&one, 3, 1, 3),
            listing_body(&serde_json::json!([]), 3, 2, 3),
        ],
        vec![listing_body(&one, 2, 1, 2), listing_body(&other, 3, 2, 2)],
        vec![listing_body(&one, 2, 1, 2), listing_body(&one, 2, 2, 2)],
    ] {
        mock.faults().clear();
        for body in &bodies {
            mock.faults()
                .push(Fault::on("GET", RECORDS).respond(200, body.clone()));
        }
        let before = writes(&mock);
        let e = add(&client, "new").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{bodies:?}: {e:?}");
        assert_eq!(writes(&mock), before);
    }
    mock.faults().clear();
    // An empty listing may state no page at all.
    let empty = listing_body(&serde_json::json!([]), 0, 1, 0);
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(200, empty));
    assert_eq!(
        client
            .get_rrset(&zone(), &dn("none.example.org"), RecordType::A)
            .await
            .unwrap(),
        None
    );
}

/// `list_zones` reads every page of the account's zones.
#[tokio::test]
async fn dnsimple_list_zones_pages_by_number() {
    let (mock, client) = setup().await;
    for zone in ["b.example", "a.example", "c.example"] {
        mock.control().insert_zone(zone);
    }
    mock.control().set_page_cap(2);
    let zones: Vec<String> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name.to_string())
        .collect();
    assert_eq!(
        zones,
        ["a.example.", "b.example.", "c.example.", "example.org."]
    );
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);
}

/// `check` proves the token with `whoami`, reports a missing zone as not found, and warns about
/// a zone whose DNS services are off or that is a secondary zone; a wrong token is `Auth`.
#[tokio::test]
async fn dnsimple_check_exercises_the_credentials() {
    let (mock, client) = setup().await;
    mock.control().insert_zone("off.example");
    mock.control().set_zone_flags("off.example", false, false);
    mock.control().insert_zone("second.example");
    mock.control().set_zone_flags("second.example", true, true);
    let zones = [
        zone(),
        dn("missing.example"),
        dn("off.example"),
        dn("second.example"),
    ];
    let report = client.check(&zones).await.unwrap();
    assert!(report.credentials_verified);
    let found: Vec<bool> = report.zones.iter().map(|z| z.found).collect();
    assert_eq!(found, [true, false, true, true]);
    assert!(report.zones[0].detail.is_none());
    assert!(
        report.zones[2]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("disabled")
    );
    assert!(
        report.zones[3]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("secondary")
    );
    assert_eq!(mock.log().count(Some("GET"), WHOAMI), 1);

    let wrong = client_with(&mock, "wrong-token", &context());
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");

    // A zone answer about another zone is not taken for this one.
    mock.faults().push(Fault::on("GET", ZONE).respond(
        200,
        r#"{"data":{"id":9,"name":"example.net","active":true,"secondary":false}}"#,
    ));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// A write to a zone the account does not have is `ZoneNotFound` and writes nothing.
#[tokio::test]
async fn dnsimple_zone_not_found() {
    let (mock, client) = setup().await;
    let missing = dn("missing.example");
    let e = client
        .add_txt_value(
            &missing,
            &dn("_acme-challenge.missing.example"),
            &txt("v"),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let e = client.list_rrsets(&missing).await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    // The zone vanished between the read and the create.
    mock.faults().push(Fault::on("POST", RECORDS).status(404));
    let e = add(&client, "v").await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    assert!(mock.control().records().is_empty());
}

/// Refusals carry the provider's message and its field errors; a 402 or 412 is `Rejected`.
#[tokio::test]
async fn dnsimple_refusals_are_rejected() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", RECORDS).respond(
        400,
        r#"{"message":"Validation failed","errors":{"ttl":["is not a number"]}}"#,
    ));
    let e = add(&client, "v").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(e.to_string().contains("ttl: is not a number"), "{e}");
    assert_eq!(e.provider_code(), None);
    for status in [402, 412] {
        mock.faults()
            .push(Fault::on("POST", RECORDS).respond(status, r#"{"message":"plan limit"}"#));
        let e = add(&client, "v").await.unwrap_err();
        assert!(
            matches!(e, Error::Rejected { status: Some(s), .. } if s == status),
            "{e:?}"
        );
    }
    mock.faults()
        .push(Fault::on("GET", RECORDS).always().status(503));
    let e = add(&client, "v").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn dnsimple_from_json_builds_the_client() {
    let mock = DnsimpleMock::start(Seed::standard()).await;
    let settings =
        serde_json::json!({"base_url": mock.base_url(), "account_id": 1010, "ttl": 60}).to_string();
    let client = AnyProvider::from_json(
        ProviderId::Dnsimple,
        &settings,
        &SecretString::from(format!(r#"{{"api_token":"{TOKEN}"}}"#)),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Dnsimple);
    assert_eq!(add(&client, "v").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.control().records()[0].ttl, 60);
    assert_eq!(mock.log().count(Some("GET"), WHOAMI), 0);
}

/// Only the token is required; the defaults are the documented production endpoint, no account
/// and a TTL of 120.
#[test]
fn dnsimple_minimal_configuration_builds() {
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = AnyProvider::from_json(
        ProviderId::Dnsimple,
        "{}",
        &SecretString::from(r#"{"api_token":"t"}"#.to_owned()),
        &ctx,
    )
    .unwrap();
    let text = format!("{client:?}");
    assert!(text.contains("https://api.dnsimple.com/v2"), "{text}");
    let config = DnsimpleConfig::default();
    assert_eq!(config.account_id, None);
    assert_eq!(config.ttl, RrsetTtl::from_secs(120).unwrap());
}

/// Configuration errors name the key, never the value.
#[test]
fn dnsimple_config_errors_name_no_value() {
    // A context without `loopback_only`, so that the default endpoint is accepted.
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let build = |settings: &str, credentials: &str| {
        AnyProvider::from_json(
            ProviderId::Dnsimple,
            settings,
            &SecretString::from(credentials.to_owned()),
            &ctx,
        )
    };
    let token = r#"{"api_token":"t0ken-value"}"#;
    for (settings, credentials, key) in [
        (r#"{"ttl":59}"#, token, "ttl"),
        (r#"{"ttl":259201}"#, token, "ttl"),
        (r#"{"ttl":"provider_default"}"#, token, "ttl"),
        (r#"{"account_id":0}"#, token, "account_id"),
        (r#"{"account_id":9223372036854775808}"#, token, "account_id"),
        (r#"{"base_url":"not a url"}"#, token, "base_url"),
        ("{}", r#"{"api_token":"   "}"#, "api_token"),
        ("{}", r#"{"token":"t0ken-value"}"#, "api_token"),
    ] {
        let e = build(settings, credentials).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{settings} {e:?}");
        let text = format!("{e} | {e:?}");
        assert!(text.contains(key), "{settings}: {text}");
        assert!(!text.contains("t0ken-value"), "{text}");
    }
    let e = build(r#"{"account_id":"secret-ish"}"#, token).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
    assert!(!format!("{e:?}").contains("secret-ish"), "{e:?}");
}

/// The token is trimmed of surrounding whitespace before it is sent.
#[tokio::test]
async fn dnsimple_token_is_trimmed() {
    let mock = DnsimpleMock::start(Seed::standard()).await;
    let client = client_with(&mock, &format!("  {TOKEN}\n"), &context());
    client.check(&[zone()]).await.unwrap();
}

// ---- Record level ------------------------------------------------------------------------------

/// Every supported type through set, get and list with canonical equality: the apex, an IDN
/// name, a wildcard, a delegation, multi-value sets and a TXT value of a full character-string.
#[tokio::test]
async fn dnsimple_record_round_trips() {
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
        rr("example.org", RecordType::TXT, None, &[&long, "\"v=1\""]),
    ];
    let default_ttl = Some(RrsetTtl::from_secs(120).unwrap());
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

    // The members the API stores.
    let control = mock.control();
    let mx = control.records_at("example.org", "MX");
    assert!(
        mx.iter()
            .any(|r| r.content == "mail.example.org" && r.extra.priority == Some(10))
    );
    let srv = control.records_at("_sip._tcp.example.org", "SRV");
    assert!(
        srv.iter()
            .any(|r| r.content == "5 5060 sip.example.org" && r.extra.priority == Some(1))
    );
    assert_eq!(
        stored(&mock, "example.org", "CAA"),
        [
            "0 issue \"letsencrypt.org\"",
            "128 iodef \"mailto:sec@example.org\""
        ]
    );
    assert_eq!(
        stored(&mock, "www.example.org", "CNAME"),
        ["target.example.net"]
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
            .all(|r| r.extra.regions == ["global"])
    );

    // A host name stated with a trailing dot by another writer reads as the same value.
    control.insert_record_with(
        "example.org",
        "other.example.org",
        "MX",
        "Mail.Example.org.",
        600,
        Extra {
            priority: Some(10),
            ..Extra::default()
        },
    );
    let other = rr(
        "other.example.org",
        RecordType::MX,
        None,
        &["10 mail.example.org."],
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
async fn dnsimple_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", www, "A", "192.0.2.1", 600);
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
    let absent = rr(www, RecordType::TXT, None, &["\"v\""]);
    let e = client
        .set_rrset(&zone(), &absent, Expect::Matches(&absent))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(control.records(), original);

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
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
}

/// A replacement creates the missing values before it deletes the surplus; a TTL change alone
/// updates the records in place with only the TTL; a CNAME is replaced in place.
#[tokio::test]
async fn dnsimple_replacement_order_and_updates() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", www, "A", "192.0.2.1", 600);
    control.insert_record("example.org", www, "A", "192.0.2.2", 600);
    let replaced = rr(www, RecordType::A, None, &["192.0.2.2", "192.0.2.3"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &replaced, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let methods: Vec<String> = mock
        .log()
        .entries()
        .iter()
        .filter(|r| r.method != Method::GET)
        .map(|r| r.method.to_string())
        .collect();
    assert_eq!(methods, ["POST", "DELETE"]);
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.2", "192.0.2.3"]);

    mock.log().clear();
    let retuned = replaced
        .clone()
        .with_ttl(Some(RrsetTtl::from_secs(3600).unwrap()));
    client
        .set_rrset(&zone(), &retuned, Expect::Any)
        .await
        .unwrap();
    let patches = mock.log().matching(Some("PATCH"), RECORD);
    assert_eq!(patches.len(), 2);
    for patch in &patches {
        assert_eq!(patch.body_json().unwrap(), serde_json::json!({"ttl": 3600}));
    }
    assert!(control.records_at(www, "A").iter().all(|r| r.ttl == 3600));

    control.insert_record(
        "example.org",
        "alias.example.org",
        "CNAME",
        "old.example.net",
        600,
    );
    mock.log().clear();
    let cname = rr(
        "alias.example.org",
        RecordType::CNAME,
        None,
        &["new.example.net."],
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &cname, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let patches = mock.log().matching(Some("PATCH"), RECORD);
    assert_eq!(patches.len(), 1);
    assert_eq!(
        patches[0].body_json().unwrap(),
        serde_json::json!({"content": "new.example.net"})
    );
    assert_eq!(mock.log().count(Some("POST"), RECORDS), 0);
    assert_eq!(
        stored(&mock, "alias.example.org", "CNAME"),
        ["new.example.net"]
    );
}

/// The record-level create bodies with each type's members, the update keeping the regions it
/// does not send.
#[tokio::test]
async fn dnsimple_record_request_shapes() {
    let (mock, client) = setup().await;
    for (set, body) in [
        (
            rr(
                "example.org",
                RecordType::MX,
                None,
                &["10 mail.example.org."],
            ),
            serde_json::json!({
                "name": "", "type": "MX", "content": "mail.example.org", "ttl": 120,
                "priority": 10
            }),
        ),
        (
            rr(
                "_sip._udp.example.org",
                RecordType::SRV,
                Some(600),
                &["1 2 3 sip.example.org."],
            ),
            serde_json::json!({
                "name": "_sip._udp", "type": "SRV", "content": "2 3 sip.example.org", "ttl": 600,
                "priority": 1
            }),
        ),
        (
            rr(
                "example.org",
                RecordType::CAA,
                None,
                &["0 issue \"ca.example.net\""],
            ),
            serde_json::json!({
                "name": "", "type": "CAA", "content": "0 issue \"ca.example.net\"", "ttl": 120
            }),
        ),
    ] {
        client
            .set_rrset(&zone(), &set, Expect::Absent)
            .await
            .unwrap();
        let post = mock.log().matching(Some("POST"), RECORDS).pop().unwrap();
        assert_eq!(post.body_json().unwrap(), body);
    }
    mock.log().clear();
    client.list_rrsets(&zone()).await.unwrap();
    let list = mock.log().matching(Some("GET"), RECORDS).pop().unwrap();
    assert_eq!(list.query.as_deref(), Some("per_page=100&page=1"));
}

/// Records the provider marks as system records are listed and read, but a plan that would
/// change or delete one is refused before any write, and the TXT value layer does not delete
/// one either.
#[tokio::test]
async fn dnsimple_system_records_are_never_changed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_zone_defaults("example.org");
    let system = Extra {
        system: true,
        ..Extra::default()
    };
    control.insert_record_with(
        "example.org",
        "sys.example.org",
        "A",
        "192.0.2.1",
        600,
        system.clone(),
    );
    control.insert_record_with("example.org", NAME, "TXT", "AAA", 600, system);
    let original = control.records();

    let ns = client
        .get_rrset(&zone(), &zone(), RecordType::NS)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ns.records().len(), 4);
    for (set, expect) in [
        (
            rr("sys.example.org", RecordType::A, None, &["192.0.2.9"]),
            Expect::Any,
        ),
        (
            rr("sys.example.org", RecordType::A, Some(60), &["192.0.2.1"]),
            Expect::Any,
        ),
    ] {
        let e = client.set_rrset(&zone(), &set, expect).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    }
    let e = client
        .delete_rrset(&zone(), &dn("sys.example.org"), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    // The apex NS set and the SOA are refused before any request.
    mock.log().clear();
    let e = client
        .delete_rrset(&zone(), &zone(), RecordType::NS, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty());
    assert_eq!(writes(&mock), 0);
    assert_eq!(control.records(), original);
}

/// A record limited to some regions makes its name and type not one rrset: reads and writes
/// are refused before any write, and the listing reports the set as skipped.
#[tokio::test]
async fn dnsimple_regional_records_are_refused() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let regional = Extra {
        regions: vec!["SV1".into(), "IAD".into()],
        ..Extra::default()
    };
    control.insert_record("example.org", "geo.example.org", "A", "192.0.2.1", 600);
    control.insert_record_with(
        "example.org",
        "geo.example.org",
        "A",
        "192.0.2.2",
        600,
        regional.clone(),
    );
    control.insert_record_with("example.org", NAME, "TXT", "AAA", 600, regional);
    let original = control.records();

    let e = client
        .get_rrset(&zone(), &dn("geo.example.org"), RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let e = client
        .set_rrset(
            &zone(),
            &rr("geo.example.org", RecordType::A, None, &["192.0.2.3"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(control.records(), original);

    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.rrsets.is_empty(), "{:?}", listing.rrsets);
    let mut skipped: Vec<(String, String, SkipReason)> = listing
        .skipped
        .iter()
        .map(|s| (s.name.to_string(), s.type_name.clone(), s.reason))
        .collect();
    skipped.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(
        skipped,
        [
            (
                NAME.to_owned() + ".",
                "TXT".to_owned(),
                SkipReason::NotPlainRecords
            ),
            (
                "geo.example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::NotPlainRecords
            ),
        ]
    );
}

/// The listing carries the provider's system records, a value it cannot parse as non-canonical
/// data, and reports what the model cannot hold: an unknown type, a name in a form the API does
/// not document, two CNAME records at one name.
#[tokio::test]
async fn dnsimple_listing_reports_skipped_sets() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_zone_defaults("example.org");
    control.insert_record("example.org", "www.example.org", "A", "192.0.2.1", 600);
    control.insert_record("example.org", "www.example.org", "A", "192.0.2.2", 300);
    control.insert_record("example.org", "odd.example.org", "A", "not an address", 300);
    control.insert_record("example.org", "x.example.org", "POOL", "a.example.net", 300);
    control.insert_record(
        "example.org",
        "two.example.org",
        "CNAME",
        "a.example.net",
        300,
    );
    control.insert_record(
        "example.org",
        "two.example.org",
        "CNAME",
        "b.example.net",
        300,
    );
    control.insert_record("example.org", "bad name", "A", "192.0.2.9", 300);
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
    let ns = get("example.org", RecordType::NS).unwrap();
    assert_eq!(ns.records().len(), 4);
    assert_eq!(ns.records()[0].as_str(), "ns1.dnsimple-edge.com.");
    let soa = get("example.org", RecordType::SOA).unwrap();
    assert!(soa.records()[0].is_canonical());
    let odd = get("odd.example.org", RecordType::A).unwrap();
    assert!(!odd.records()[0].is_canonical());
    assert_eq!(odd.records()[0].as_str(), "not an address");

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
            "POOL".to_owned(),
            SkipReason::UnknownType,
        ),
    ];
    expected.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(skipped, expected);
    assert_eq!(listing.rrsets.len(), 4);

    // The listing reads every page by number.
    control.set_page_cap(2);
    let paged = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(paged.rrsets, listing.rrsets);
}

/// Values the client has no established encoding for are refused before any write; a value the
/// provider holds already is never re-encoded.
#[tokio::test]
async fn dnsimple_values_without_an_encoding_are_refused() {
    let (mock, client) = setup().await;
    for set in [
        rr("example.org", RecordType::MX, None, &["0 ."]),
        rr("t.example.org", RecordType::TXT, None, &["\"two words\""]),
        rr(
            "example.org",
            RecordType::CAA,
            None,
            &["1 issue \"ca.example.net\""],
        ),
        rr(
            "example.org",
            RecordType::CAA,
            None,
            &["0 issue \"ca.example.net; a=1\""],
        ),
    ] {
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{set:?}: {e:?}");
    }
    let e = client
        .set_rrset(
            &zone(),
            &rr("t.example.org", RecordType::TLSA, None, &["3 1 1 0a1b"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// Record writes that carry no condition are sent once for every failing status; the delete by
/// identifier is retried after a 502 only.
#[tokio::test]
async fn dnsimple_record_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let set = rr(www, RecordType::A, None, &["192.0.2.1"]);
    let statuses = || {
        [
            (502, ErrorKind::Transient),
            (429, ErrorKind::RateLimited),
            (401, ErrorKind::Auth),
            (403, ErrorKind::Forbidden),
            (400, ErrorKind::Rejected),
        ]
    };
    for (status, kind) in statuses() {
        mock.log().clear();
        let fault = Fault::on("POST", RECORDS);
        mock.faults().push(if status == 429 {
            fault.rate_limited("1")
        } else {
            fault.status(status)
        });
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{status}: {e:?}");
        assert_eq!(mock.log().count(Some("POST"), RECORDS), 1, "{status}");
        assert!(control.records().is_empty());
    }
    client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
    let retuned = set
        .clone()
        .with_ttl(Some(RrsetTtl::from_secs(600).unwrap()));
    for (status, kind) in statuses() {
        mock.log().clear();
        let fault = Fault::on("PATCH", RECORD);
        mock.faults().push(if status == 429 {
            fault.rate_limited("1")
        } else {
            fault.status(status)
        });
        let e = client
            .set_rrset(&zone(), &retuned, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{status}: {e:?}");
        assert_eq!(mock.log().count(Some("PATCH"), RECORD), 1, "{status}");
    }
    // An update answered 404: the record went away, nothing was written.
    mock.faults().push(Fault::on("PATCH", RECORD).status(404));
    let e = client
        .set_rrset(&zone(), &retuned, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    for (fault, kind) in [
        (
            Fault::on("DELETE", RECORD).rate_limited("120"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("DELETE", RECORD).status(401), ErrorKind::Auth),
        (Fault::on("DELETE", RECORD).status(400), ErrorKind::Rejected),
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

/// A record delete answered 404 reads again: gone is done, found again under a new identifier
/// is `Conflict`.
#[tokio::test]
async fn dnsimple_record_delete_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", www, "A", "192.0.2.1", 600);
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", RECORD).run(move || {
        hook.recreate_zone("example.org");
    }));
    let e = client
        .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.1"]);
    let id = control.records()[0].id;
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", RECORD).run(move || {
        hook.delete_record(id);
    }));
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
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

/// The live client and zone from `ZONEWRIGHT_LIVE_DNSIMPLE_SETTINGS`, `..._CREDENTIALS` and
/// `..._ZONE`.
fn live_client() -> (Arc<AnyProvider>, DomainName) {
    let settings = live_env("ZONEWRIGHT_LIVE_DNSIMPLE_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_DNSIMPLE_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_DNSIMPLE_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = AnyProvider::from_json(
        ProviderId::Dnsimple,
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
async fn live_dnsimple_add_and_remove() {
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

/// An rrset of one value for the live tests.
fn live_set(name: DomainName, rtype: RecordType, ttl: Option<u32>, text: &str) -> RrSet {
    RrSet::new(
        name,
        rtype,
        ttl.map(|t| RrsetTtl::from_secs(t).unwrap()),
        [rdata(rtype, text)],
    )
    .unwrap()
}

/// Exercises, in the zone `ZONEWRIGHT_LIVE_DNSIMPLE_ZONE` and under a label made from
/// `ZONEWRIGHT_LIVE_DNSIMPLE_PREFIX` and a random tag, every behavior the client assumes without
/// a source (the client's comments marked "Assumption"):
///
/// - the answer to `whoami` for the configured token, and the account check of `check`;
/// - `per_page=100` on the zone and record listings (`list_zones`, `list_rrsets`);
/// - a TTL of 60, the lower bound of the client's range;
/// - host names written without a trailing dot and read back as the same absolute names (CNAME,
///   MX, SRV with `<weight> <port> <target>` and `priority`);
/// - CAA written as `0 issue "letsencrypt.org"` and read back equal;
/// - TXT written unquoted and read back equal, whether the API answers it quoted or not;
/// - a wildcard name relative to the zone (`*.<label>`);
/// - records created without `regions` read as published everywhere (else every read fails);
/// - `total_entries` counting the records under the `type` filter (else the reads fail);
/// - a TTL change by PATCH with only `ttl`, and a CNAME changed in place by PATCH with only
///   `content`.
///
/// Everything it created is deleted afterwards by name and type, also when a step failed; it
/// touches nothing else.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn dnsimple_live_assumptions() {
    let (client, zone) = live_client();
    let prefix = live_env("ZONEWRIGHT_LIVE_DNSIMPLE_PREFIX");
    let base = zone
        .prepend(&format!("{prefix}-{:016x}", random_u64()))
        .unwrap();
    let owner = |label: &str| base.prepend(label).unwrap();
    let sets = vec![
        live_set(base.clone(), RecordType::A, Some(60), "192.0.2.10"),
        live_set(base.clone(), RecordType::MX, None, &format!("10 mx.{base}")),
        live_set(
            owner("_sip._tcp"),
            RecordType::SRV,
            None,
            &format!("10 20 5060 sip.{base}"),
        ),
        live_set(
            base.clone(),
            RecordType::CAA,
            None,
            "0 issue \"letsencrypt.org\"",
        ),
        live_set(
            owner("alias"),
            RecordType::CNAME,
            None,
            &format!("target.{base}"),
        ),
        live_set(owner("txt"), RecordType::TXT, None, "\"zw-live-value\""),
        live_set(owner("*"), RecordType::A, None, "192.0.2.20"),
    ];
    let created: Vec<(DomainName, RecordType)> =
        sets.iter().map(|s| (s.name().clone(), s.rtype())).collect();
    let body = {
        let (client, zone, sets, base) = (client.clone(), zone.clone(), sets.clone(), base.clone());
        tokio::spawn(async move {
            let report = client.check([&zone]).await.unwrap();
            assert!(report.zones[0].found, "{report:?}");
            let zones = client.list_zones().await.unwrap();
            assert!(zones.iter().any(|z| z.name == zone), "{zones:?}");
            for set in &sets {
                assert_eq!(
                    client.set_rrset(&zone, set, Expect::Absent).await.unwrap(),
                    SetOutcome::Created,
                    "{} {}",
                    set.name(),
                    set.rtype()
                );
                let read = client
                    .get_rrset(&zone, set.name(), set.rtype())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    read.records(),
                    set.records(),
                    "{} {}",
                    set.name(),
                    set.rtype()
                );
                assert_eq!(
                    client.set_rrset(&zone, set, Expect::Any).await.unwrap(),
                    SetOutcome::Unchanged
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
            // A TTL change and a CNAME changed in place.
            let a = live_set(base.clone(), RecordType::A, Some(3600), "192.0.2.10");
            assert_eq!(
                client.set_rrset(&zone, &a, Expect::Any).await.unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                client.get_rrset(&zone, &base, RecordType::A).await.unwrap(),
                Some(a)
            );
            let alias = live_set(
                base.prepend("alias").unwrap(),
                RecordType::CNAME,
                None,
                &format!("other.{base}"),
            );
            client.set_rrset(&zone, &alias, Expect::Any).await.unwrap();
            assert_eq!(
                client
                    .get_rrset(&zone, alias.name(), RecordType::CNAME)
                    .await
                    .unwrap()
                    .unwrap()
                    .records(),
                alias.records()
            );
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
