//! Tests of the OVHcloud client (`ovh`) against its mock.
#![cfg(feature = "ovh")]
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
use zonewright::providers::ovh::{Ovh, OvhConfig, OvhCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl, SetOutcome,
    SkipReason, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::changes::ChangeSource as _;
use zonewright_mock::echo::{EchoServer, Echoed, Render};
use zonewright_mock::ovh::{OvhMock, Seed};

use common::echo::{LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The keys of the standard seed.
const AK: &str = "test-only-ak";
const AS: &str = "test-only-as";
const CK: &str = "test-only-ck";

/// Canary credentials for the secret tests: the shared canaries' characters without
/// whitespace, which neither key may contain (a header value loses surrounding whitespace in
/// transit while the signature covers it).
const CANARY_AS: &str = "cAnaryAQ7x\"Za\'&Yb<Xc>Wd\\Ve~Uf*Tg=Sh+z/w@v";
const CANARY_CK: &str = "cAnaryCQ9w\"Qa\'&Rb<Sc>Td\\Ue~Vf*Wg=Xh@p/q+r";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const TIME: &str = "/1.0/auth/time";
const ZONES: &str = "/1.0/domain/zone";
const RECORDS: &str = "/1.0/domain/zone/*/record";
const RECORD: &str = "/1.0/domain/zone/*/record/*";
const REFRESH: &str = "/1.0/domain/zone/*/refresh";

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
fn settings(base_url: String) -> OvhConfig {
    let mut config = OvhConfig::new(AK);
    config.base_url = Some(base_url);
    // Reads of a record that is not readable yet are repeated without a noticeable wait.
    config.read_retry_ms = 1;
    config
}

fn credentials(secret: &str, consumer: &str) -> OvhCredentials {
    OvhCredentials::new(
        SecretString::from(secret.to_owned()),
        SecretString::from(consumer.to_owned()),
    )
}

fn client_with(mock: &OvhMock, ctx: &Context) -> Ovh {
    Ovh::new(settings(mock.base_url()), credentials(AS, CK), ctx).unwrap()
}

async fn setup() -> (OvhMock, Ovh) {
    let mock = OvhMock::start(Seed::standard()).await;
    let client = client_with(&mock, &context());
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

/// Number of record write requests the mock received (the refresh is not one).
fn writes(mock: &OvhMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), RECORDS)
        + log.count(Some("PUT"), RECORD)
        + log.count(Some("DELETE"), RECORD)
}

/// Number of refreshes the mock received.
fn refreshes(mock: &OvhMock) -> usize {
    mock.log().count(Some("POST"), REFRESH)
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

/// The `target` of the staged records of `rtype` at `owner`, sorted.
fn stored(mock: &OvhMock, owner: &str, rtype: &str) -> Vec<String> {
    let mut values: Vec<String> = mock
        .control()
        .records_at(owner, rtype)
        .into_iter()
        .map(|r| r.target)
        .collect();
    values.sort();
    values
}

/// The values of the published TXT rrset at [`NAME`], sorted, as a DNS server would serve them.
fn published_txt(mock: &OvhMock) -> Vec<String> {
    let mut values = mock.control().published_txt_values(NAME);
    values.sort();
    values
}

/// The zone has no staged change that is not published.
fn settled(mock: &OvhMock) -> bool {
    !mock.control().pending("example.org")
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

assert_not_impl!(Ovh: std::fmt::Display, serde::Serialize);
assert_not_impl!(OvhCredentials: std::fmt::Display, serde::Serialize);

/// What the echo's record listings answer: one record with identifier 1001, or none.
#[derive(Clone, Copy, Debug)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
    /// An A record, for the update of the record level.
    Address,
}

/// A renderer that answers `/auth/time` like the API.
fn time() -> Render {
    Arc::new(|_: &Echoed| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (StatusCode::OK, axum::Json(serde_json::json!(now))).into_response()
    })
}

fn json_ok(value: serde_json::Value) -> axum::response::Response {
    (StatusCode::OK, axum::Json(value)).into_response()
}

/// A renderer that answers the zone listing, the record listing and the record reads like the
/// API, the refresh too unless `refresh` (the refresh is the echo), and every other request with
/// `errors`.
fn reads_then(errors: Render, existing: Existing, refresh: bool) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method == Method::POST && e.path.ends_with("/refresh") && !refresh {
            return json_ok(serde_json::Value::Null);
        }
        if e.method != Method::GET {
            return errors(e);
        }
        if e.path == ZONES {
            return json_ok(serde_json::json!(["example.org"]));
        }
        let record = match existing {
            Existing::Nothing => None,
            Existing::Foreign => Some(("TXT", "_acme-challenge", "\"foreign\"")),
            Existing::Ours => Some(("TXT", "_acme-challenge", "\"v1\"")),
            Existing::Address => Some(("A", "_acme-challenge", "192.0.2.1")),
        };
        if e.path.ends_with("/record") {
            return json_ok(serde_json::json!(record.map_or(vec![], |_| vec![1001])));
        }
        match record {
            Some((field_type, sub, target)) if e.path.ends_with("/record/1001") => {
                json_ok(serde_json::json!({
                    "id": 1001, "zone": "example.org", "subDomain": sub,
                    "fieldType": field_type, "target": target, "ttl": 600
                }))
            }
            _ => errors(e),
        }
    })
}

/// A renderer that answers the zone listing like the API and every other request with
/// `errors`.
fn zones_then(errors: Render) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method == Method::GET && e.path == ZONES {
            return json_ok(serde_json::json!(["example.org"]));
        }
        errors(e)
    })
}

/// A client of the echo with the canaries as its secrets.
fn echo_client(echo: &EchoServer, ctx: &Context) -> Ovh {
    Ovh::new(
        settings(echo.url("/1.0")),
        credentials(CANARY_AS, CANARY_CK),
        ctx,
    )
    .unwrap()
}

/// What a case of the secret test drives.
#[derive(Clone, Copy, Debug)]
enum Drive {
    Add,
    Remove,
    SetA,
    RetuneA,
    DeleteTxt,
    List,
    Check,
}

async fn drive(client: &Ovh, what: Drive) -> Result<String, Error> {
    match what {
        Drive::Add => add(client, "v1").await.map(|o| format!("{o:?}")),
        Drive::Remove => remove(client, "v1").await.map(|o| format!("{o:?}")),
        Drive::SetA => client
            .set_rrset(
                &zone(),
                &rr(NAME, RecordType::A, None, &["192.0.2.9"]),
                Expect::Any,
            )
            .await
            .map(|o| format!("{o:?}")),
        Drive::RetuneA => client
            .set_rrset(
                &zone(),
                &rr(NAME, RecordType::A, Some(3600), &["192.0.2.1"]),
                Expect::Any,
            )
            .await
            .map(|o| format!("{o:?}")),
        Drive::DeleteTxt => client
            .delete_rrset(&zone(), &name(), RecordType::TXT, Expect::Any)
            .await
            .map(|o| format!("{o:?}")),
        Drive::List => client
            .list_rrsets(&zone())
            .await
            .map(|l| format!("{} rrsets", l.rrsets.len())),
        Drive::Check => client.check(&[zone()]).await.map(|r| format!("{r:?}")),
    }
}

/// Every kind of signed request against an echo that quotes it back, headers included (the
/// consumer key travels in `X-Ovh-Consumer`), for every dialect: the zone listing, the record
/// listing, a create, an update, a delete, and the refresh after an operation that changed
/// nothing. No canary in any error or `Debug`, the error shows the redaction, and the request
/// reached the echo the number of times the retry rule allows.
#[tokio::test]
async fn ovh_secret_echo() {
    let ctx = context();
    let echo = EchoServer::start(200).await;
    for dialect in dialects() {
        let cases: [(Drive, Existing, &str, &str, &[u16]); 9] = [
            (
                Drive::Check,
                Existing::Nothing,
                "GET",
                ZONES,
                &[400, 401, 403, 404],
            ),
            (
                Drive::List,
                Existing::Nothing,
                "GET",
                RECORDS,
                &[400, 401, 403],
            ),
            (
                Drive::Add,
                Existing::Nothing,
                "POST",
                RECORDS,
                &[400, 401, 403, 404, 500],
            ),
            (
                Drive::Add,
                Existing::Foreign,
                "POST",
                RECORDS,
                &[400, 401, 403, 500],
            ),
            (
                Drive::Remove,
                Existing::Ours,
                "DELETE",
                RECORD,
                &[400, 401, 403],
            ),
            (
                Drive::SetA,
                Existing::Nothing,
                "POST",
                RECORDS,
                &[400, 401, 403],
            ),
            (
                Drive::RetuneA,
                Existing::Address,
                "PUT",
                RECORD,
                &[400, 401, 403, 500],
            ),
            (
                Drive::DeleteTxt,
                Existing::Ours,
                "DELETE",
                RECORD,
                &[400, 401, 403],
            ),
            // `AlreadyPresent`: only the refresh reaches the echo.
            (
                Drive::Add,
                Existing::Ours,
                "POST",
                REFRESH,
                &[400, 401, 403, 404],
            ),
        ];
        for (what, existing, method, path, statuses) in cases {
            for &status in statuses {
                let label = format!(
                    "{} {:?} {status} {what:?} {existing:?}",
                    dialect.name, dialect.spelling
                );
                let config = dialect.echo(status).render_under(TIME, time());
                let config = match what {
                    Drive::Check => config,
                    Drive::List => config.render_under(ZONES, zones_then(dialect.render.clone())),
                    _ => config.render_under(
                        ZONES,
                        reads_then(dialect.render.clone(), existing, path == REFRESH),
                    ),
                };
                echo.reset(config);
                let client = echo_client(&echo, &ctx);
                let text = match drive(&client, what).await {
                    Ok(outcome) => panic!("{label}: the echo accepted the request: {outcome}"),
                    Err(e) => format!("{e} | {e:?} | {client:?}"),
                };
                assert!(
                    text.contains(REDACTED),
                    "{label}: the echo did not reach the error: {text}"
                );
                assert_clean(&label, &text, &[CANARY_CK, CANARY_AS]);
                assert_eq!(
                    echo.log().count(Some(method), path),
                    1,
                    "{label}: the request did not reach the echo exactly once"
                );
                // The consumer key reached the echo; the application secret never did.
                assert!(echo.log().contains(CANARY_CK), "{label}");
                assert!(!echo.log().contains(CANARY_AS), "{label}");
            }
        }
    }
}

/// A `TRACE` capture over successes, repeated 403s, a 500 and a wrong consumer key: the
/// transport's events are there, and no canary is.
#[tokio::test(flavor = "current_thread")]
async fn ovh_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.application_secret = CANARY_AS.into();
    seed.consumer_key = CANARY_CK.into();
    let mock = OvhMock::start(seed).await;
    let ctx = context();
    let client = Ovh::new(
        settings(mock.base_url()),
        credentials(CANARY_AS, CANARY_CK),
        &ctx,
    )
    .unwrap();
    let mut texts = vec![format!("{client:?}")];

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
    client.list_rrsets(&zone()).await.unwrap();

    mock.faults()
        .push(Fault::on("GET", RECORDS).always().status(403));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("POST", RECORDS).status(500));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    let wrong = Ovh::new(
        settings(mock.base_url()),
        credentials(CANARY_AS, "wrong-consumer-key"),
        &ctx,
    )
    .unwrap();
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    texts.push(format!("{e} | {e:?} | {wrong:?}"));

    let entries = capture.entries();
    assert!(
        entries.iter().any(|e| e.target == "zonewright::http"),
        "the capture holds no transport event"
    );
    texts.push(capture.text());
    for text in &texts {
        assert_clean("ovh logs and errors", text, &[CANARY_CK, CANARY_AS]);
    }
}

/// A refusal carries the `class` of the error body as the provider code.
#[tokio::test]
async fn ovh_refusal_carries_the_provider_code() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", RECORDS).respond(
        400,
        r#"{"class":"Client::BadRequest","message":"Invalid target"}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(
        e.provider_code().map(|c| c.as_str()),
        Some("Client::BadRequest")
    );
    assert!(e.to_string().contains("Invalid target"), "{e}");
    mock.faults()
        .push(Fault::on("POST", RECORDS).respond(400, r#"{"message":"refused"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(e.provider_code(), None);
}

/// A `class` that echoes a secret is not carried, and the secret appears nowhere in the error.
/// Both test secrets fit the code's alphabet, so only the scrubber keeps them out.
#[tokio::test]
async fn ovh_provider_code_never_carries_a_credential() {
    let (mock, client) = setup().await;
    for secret in [AS, CK] {
        let body = serde_json::json!({"class": secret, "message": "refused"});
        mock.faults()
            .push(Fault::on("POST", RECORDS).respond(400, body.to_string()));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
        assert_eq!(e.provider_code(), None);
        let text = format!("{e} | {e:?}");
        assert!(!text.contains(secret), "{text}");
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely ends
/// with the zone's text, the zone's text inside another name, and a sibling zone.
#[tokio::test]
async fn ovh_name_outside_zone_sends_nothing() {
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
/// request, the refresh included.
#[tokio::test]
async fn ovh_invalid_input_sends_nothing() {
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

/// `Created`, `Appended` for a second value, then `AlreadyPresent` without a record write; every
/// operation ends with a refresh, so what the mock publishes is what was added.
#[tokio::test]
async fn ovh_add_is_idempotent() {
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
    assert_eq!(refreshes(&mock), 4);
    assert_eq!(mock.control().txt_values(NAME), ["\"AAA\"", "\"BBB\""]);
    assert_eq!(published_txt(&mock), ["\"AAA\"", "\"BBB\""]);
}

/// Removing an absent value next to foreign ones writes nothing; adding and removing our value
/// leaves the foreign records and their TTLs as they were. A single foreign value is never a
/// reason to delete anything.
#[tokio::test]
async fn ovh_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "TXT", "\"foreign-1\"", Some(600));
    control.insert_record("example.org", NAME, "TXT", "\"foreign-2\"", Some(900));
    let original = control.records();

    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        control.txt_values(NAME),
        ["\"foreign-1\"", "\"foreign-2\"", "\"ours\""]
    );
    // The value joined the set with the set's TTL as read (the smallest).
    assert_eq!(control.records_at(NAME, "TXT")[2].ttl, Some(600));
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.records(), original);
    assert_eq!(control.published_records(), original);
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 1);

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_record("example.org", other, "TXT", "\"foreign\"", Some(60));
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &txt("ours"))
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(control.txt_values(other), ["\"foreign\""]);
}

/// Records of other types at the same name and TXT records at names the filter's pattern also
/// matches are not touched and not mistaken for ours.
#[tokio::test]
async fn ovh_other_types_and_names_are_untouched() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", NAME, "A", "192.0.2.1", Some(300));
    // `_` is a pattern character: `_acme-challenge` also matches `xacme-challenge`.
    control.insert_record(
        "example.org",
        "xacme-challenge.example.org",
        "TXT",
        "\"AAA\"",
        Some(300),
    );
    let original = control.records();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(control.records(), original);
}

#[tokio::test]
async fn ovh_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().records().is_empty());
    assert!(mock.control().published_records().is_empty());
    assert_eq!(mock.log().count(Some("DELETE"), RECORD), 1);
}

#[tokio::test]
async fn ovh_remove_is_idempotent() {
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
    assert!(settled(&mock));
}

/// Two clients sharing a `Context` add to one name at once, the first write delayed: the second
/// waits for the lock and sees the first one's record.
#[tokio::test]
async fn ovh_concurrent_adds_are_serialized() {
    let mock = OvhMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, &ctx);
    let b = client_with(&mock, &ctx);
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
    assert_eq!(published_txt(&mock), ["\"AAA\"", "\"BBB\""]);
}

/// A foreign value added between the read and the write is not lost: the create names only our
/// value.
#[tokio::test]
async fn ovh_foreign_value_added_between_read_and_write_survives() {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    mock.faults().push(Fault::on("POST", RECORDS).run(move || {
        hook.insert_record("example.org", NAME, "TXT", "\"foreign\"", Some(600));
    }));
    add(&client, "ours").await.unwrap();
    assert_eq!(published_txt(&mock), ["\"foreign\"", "\"ours\""]);
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(published_txt(&mock), ["\"foreign\""]);
}

/// The zone is deleted and created again between the read and the delete: the delete is
/// answered 404, and the removal never reports success for a value that is still there. A
/// record that is gone for another reason is a success.
#[tokio::test]
async fn ovh_delete_not_found_reads_again() {
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
    assert_eq!(control.txt_values(NAME), ["\"AAA\""]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.records().is_empty());
}

/// Retry behavior: a create is sent once whatever happens (a 502, a 429, a 401, a 403 and a 400
/// are the operation's error, and the repeat starts with a read); the delete by identifier is
/// repeated after a 502 only. After each failed write the zone is refreshed.
#[tokio::test]
async fn ovh_writes_are_sent_once() {
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
            Fault::on("POST", RECORDS)
                .respond(400, r#"{"class":"Client::BadRequest","message":"Invalid"}"#),
            ErrorKind::Rejected,
        ),
    ] {
        let (before, refreshed) = (posts(), refreshes(&mock));
        mock.faults().push(fault);
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(posts(), before + 1, "{e:?}");
        assert_eq!(refreshes(&mock), refreshed + 1, "{e:?}");
        assert!(mock.control().records().is_empty());
    }

    // The create is answered 502 but was applied: the repeat finds the value instead of adding
    // a second copy, and its refresh publishes it.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("POST", RECORDS)
            .run(move || {
                hook.stage_record("example.org", NAME, "TXT", "\"AAA\"", Some(120));
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
    assert_eq!(published_txt(&mock), ["\"AAA\""]);

    // The delete: a 502 is retried; a rate limit with a long wait, a rejected key and a refusal
    // are not.
    let deletes = || mock.log().count(Some("DELETE"), RECORD);
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
        assert_eq!(mock.control().txt_values(NAME), ["\"AAA\""]);
    }
    mock.faults().push(Fault::on("DELETE", RECORD).status(502));
    let before = deletes();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(deletes(), before + 2);
    assert!(settled(&mock));
}

// ---- Staged changes and the refresh ------------------------------------------------------------

/// A record write is staged, and only the refresh at the end of the operation publishes it: the
/// mock reports one change per operation, with the API as its origin.
#[tokio::test]
async fn ovh_changes_are_published_by_the_refresh() {
    let (mock, client) = setup().await;
    let mut changes = mock.changes().subscribe();
    let hook = mock.control().clone();
    // When the create arrives nothing is published yet; after the operation everything is.
    mock.faults().push(Fault::on("POST", REFRESH).run(move || {
        assert!(hook.pending("example.org"));
        assert!(hook.published_txt_values(NAME).is_empty());
    }));
    add(&client, "AAA").await.unwrap();
    assert!(settled(&mock));
    assert_eq!(published_txt(&mock), ["\"AAA\""]);
    let change = changes.try_next().unwrap();
    assert_eq!(change.name, NAME);
    assert_eq!(change.origin, zonewright_mock::changes::Origin::Api);
    assert!(changes.try_next().is_none());
    let order: Vec<String> = mock
        .log()
        .entries()
        .iter()
        .filter(|r| r.method != Method::GET)
        .map(|r| format!("{} {}", r.method, r.path.rsplit('/').next().unwrap_or("")))
        .collect();
    assert_eq!(order, ["POST record", "POST refresh"]);
}

/// A refresh that fails after the record write succeeded: the operation fails, says that the
/// change is stored but not published, and nothing is undone. The repeat finds the value, writes
/// nothing, and publishes it with its refresh.
#[tokio::test]
async fn ovh_failed_refresh_is_reported_and_repeated() {
    let (mock, client) = setup().await;
    for (fault, kind) in [
        (
            Fault::on("POST", REFRESH).respond(
                403,
                r#"{"class":"Client::Forbidden","message":"User not granted for this request"}"#,
            ),
            ErrorKind::Forbidden,
        ),
        (
            Fault::on("POST", REFRESH).respond(
                400,
                r#"{"class":"Client::BadRequest","message":"Zone is locked"}"#,
            ),
            ErrorKind::Rejected,
        ),
    ] {
        mock.control().reset();
        mock.faults().push(fault);
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert!(e.to_string().contains("not published"), "{e}");
        mock.faults().clear();
        assert_eq!(mock.control().txt_values(NAME), ["\"AAA\""]);
        assert!(published_txt(&mock).is_empty());
        assert!(!settled(&mock));
        let before = writes(&mock);
        assert_eq!(
            add(&client, "AAA").await.unwrap(),
            AddOutcome::AlreadyPresent
        );
        assert_eq!(writes(&mock), before);
        assert_eq!(published_txt(&mock), ["\"AAA\""]);
        assert!(settled(&mock));
    }
    // A refresh refused with a long wait: the kind has no text of its own, so no notice; the
    // repeat converges all the same.
    mock.control().reset();
    mock.faults()
        .push(Fault::on("POST", REFRESH).rate_limited("120"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert!(!settled(&mock));
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert!(settled(&mock));
    // The refresh is idempotent: a 503 is repeated by the transport.
    mock.faults().push(Fault::on("POST", REFRESH).status(503));
    let before = refreshes(&mock);
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    assert_eq!(refreshes(&mock), before + 2);
    assert_eq!(published_txt(&mock), ["\"AAA\"", "\"BBB\""]);
}

/// A changed value staged by another writer that did not refresh is published by the next
/// operation in the zone, even one that writes nothing: a refresh covers the whole zone. An
/// operation that fails after it reached the provider refreshes; one that fails before any
/// request does not, and reads refresh only while this client owes the zone a refresh.
#[tokio::test]
async fn ovh_refresh_covers_the_zone() {
    let (mock, client) = setup().await;
    mock.control().stage_record(
        "example.org",
        "other.example.org",
        "A",
        "192.0.2.1",
        Some(300),
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert!(settled(&mock));
    assert_eq!(mock.control().published_records().len(), 1);

    mock.log().clear();
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(400, r#"{"message":"no"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(refreshes(&mock), 1);
    mock.log().clear();
    let e = add(&client, "two words").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty());
    // Reads without a refresh owed do not refresh.
    client
        .get_rrset(&zone(), &name(), RecordType::TXT)
        .await
        .unwrap();
    client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(refreshes(&mock), 0);
}

/// A replacement that fails part-way is refreshed too, so that what the listing shows is what is
/// published; its error is the operation's.
#[tokio::test]
async fn ovh_failure_after_a_write_refreshes() {
    let (mock, client) = setup().await;
    let www = "www.example.org";
    mock.control()
        .insert_record("example.org", www, "A", "192.0.2.1", Some(600));
    mock.faults().push(Fault::on("DELETE", RECORD).status(400));
    let e = client
        .set_rrset(
            &zone(),
            &rr(www, RecordType::A, None, &["192.0.2.2"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(refreshes(&mock), 1);
    assert!(settled(&mock));
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.1", "192.0.2.2"]);
    // The repeat completes the replacement.
    assert_eq!(
        client
            .set_rrset(
                &zone(),
                &rr(www, RecordType::A, None, &["192.0.2.2"]),
                Expect::Any
            )
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.2"]);
    assert!(settled(&mock));
}

/// A replacement under `Expect::Absent` whose refresh failed is stored but not published; its
/// repeat, by this client or by a new one that knows nothing of it, reads the stored set and
/// fails with `PreconditionFailed`, and refreshes first, so that the refusal describes what is
/// served.
#[tokio::test]
async fn ovh_failed_refresh_then_failed_expectation_publishes() {
    let (mock, client) = setup().await;
    let www = "www.example.org";
    let set = rr(www, RecordType::A, None, &["192.0.2.7"]);
    mock.faults().push(Fault::on("POST", REFRESH).respond(
        403,
        r#"{"class":"Client::Forbidden","message":"User not granted"}"#,
    ));
    let e = client
        .set_rrset(&zone(), &set, Expect::Absent)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    assert!(e.to_string().contains("not published"), "{e}");
    assert!(!settled(&mock));
    for repeat in [&client, &client_with(&mock, &context())] {
        let e = repeat
            .set_rrset(&zone(), &set, Expect::Absent)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
        assert!(settled(&mock));
    }
    assert_eq!(
        mock.control()
            .published_records()
            .iter()
            .map(|r| r.target.as_str())
            .collect::<Vec<_>>(),
        ["192.0.2.7"]
    );
}

/// The same for a delete under `Expect::Matches`: the record is gone from the listing but still
/// served until the repeat's refusal refreshes the zone.
#[tokio::test]
async fn ovh_failed_refresh_then_failed_delete_expectation_publishes() {
    let (mock, client) = setup().await;
    let www = "www.example.org";
    mock.control()
        .insert_record("example.org", www, "A", "192.0.2.1", Some(600));
    let current = rr(www, RecordType::A, Some(600), &["192.0.2.1"]);
    mock.faults().push(
        Fault::on("POST", REFRESH).respond(400, r#"{"class":"Client::BadRequest","message":"x"}"#),
    );
    let e = client
        .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Matches(&current))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(mock.control().records().is_empty());
    assert_eq!(mock.control().published_records().len(), 1);
    let e = client
        .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Matches(&current))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert!(settled(&mock));
    assert!(mock.control().published_records().is_empty());
}

/// An operation dropped after its record write and before its refresh answered: the client
/// owes the zone a refresh, and its next operation there sends it, a read before reading and a
/// write on any exit, also one refused before any request.
#[tokio::test]
async fn ovh_dropped_operation_is_published_by_the_next_one() {
    let (mock, client) = setup().await;
    // The refresh is held long enough for the operation to be dropped, and never applied.
    let hold = || {
        Fault::on("POST", REFRESH)
            .delay(Duration::from_secs(30))
            .status(503)
    };
    mock.faults().push(hold());
    let dropped = tokio::time::timeout(Duration::from_millis(200), add(&client, "AAA")).await;
    assert!(dropped.is_err(), "the operation was not dropped");
    assert_eq!(mock.control().txt_values(NAME), ["\"AAA\""]);
    assert!(!settled(&mock));
    let before = refreshes(&mock);
    assert!(
        client
            .get_rrset(&zone(), &name(), RecordType::TXT)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(refreshes(&mock), before + 1);
    assert!(settled(&mock));
    // Nothing owed any more: a read does not refresh.
    client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(refreshes(&mock), before + 1);

    mock.faults().push(hold());
    let dropped = tokio::time::timeout(Duration::from_millis(200), add(&client, "BBB")).await;
    assert!(dropped.is_err(), "the operation was not dropped");
    assert!(!settled(&mock));
    let e = add(&client, "two words").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(settled(&mock));
    assert_eq!(published_txt(&mock), ["\"AAA\"", "\"BBB\""]);
}

/// The application secret, which is never sent, is still withheld when an answer states it, in
/// `message` or in a `details` value.
#[tokio::test]
async fn ovh_application_secret_in_an_answer_is_redacted() {
    let mut seed = Seed::standard();
    seed.application_secret = CANARY_AS.into();
    seed.consumer_key = CANARY_CK.into();
    let mock = OvhMock::start(seed).await;
    let client = Ovh::new(
        settings(mock.base_url()),
        credentials(CANARY_AS, CANARY_CK),
        &context(),
    )
    .unwrap();
    for body in [
        serde_json::json!({"class": "Client::BadRequest", "message": CANARY_AS}),
        serde_json::json!({
            "class": "Client::BadRequest", "message": "refused",
            "details": {"secret": CANARY_AS, "key": CANARY_CK}
        }),
    ] {
        mock.faults()
            .push(Fault::on("POST", RECORDS).respond(400, body.to_string()));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
        let text = format!("{e} | {e:?}");
        assert!(text.contains(REDACTED), "{text}");
        assert_clean("ovh secret in an answer", &text, &[CANARY_AS, CANARY_CK]);
    }
}

// ---- Authentication ----------------------------------------------------------------------------

/// Every API request carries the application key, the consumer key, a timestamp and a
/// signature the mock checks; `/auth/time` is read once per client, unsigned, and the
/// timestamp follows the provider's clock even when the local clock is far off.
#[tokio::test]
async fn ovh_requests_are_signed_with_the_server_clock() {
    let (mock, client) = setup().await;
    mock.control().set_clock_offset(-7200);
    add(&client, "AAA").await.unwrap();
    remove(&client, "AAA").await.unwrap();
    client.list_zones().await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), TIME), 1);
    let entries = mock.log().entries();
    let time = entries.iter().find(|r| r.path == TIME).unwrap();
    for header in [
        "x-ovh-application",
        "x-ovh-consumer",
        "x-ovh-signature",
        "x-ovh-timestamp",
    ] {
        assert!(time.header(header).is_none(), "{header}");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for request in entries.iter().filter(|r| r.path != TIME) {
        assert_eq!(request.status, Some(200), "{}", request.path);
        assert_eq!(request.header("x-ovh-application"), Some(AK));
        assert_eq!(request.header("x-ovh-consumer"), Some(CK));
        assert!(
            request
                .header("x-ovh-signature")
                .unwrap()
                .starts_with("$1$")
        );
        let stamp: u64 = request.header("x-ovh-timestamp").unwrap().parse().unwrap();
        assert!(
            now - 7200 - 5 <= stamp && stamp <= now - 7200 + 5,
            "{stamp}"
        );
        assert!(request.header("authorization").is_none());
    }
    assert!(!mock.log().contains(AS));

    // A second client reads the clock again; a failed read is not remembered.
    let other = client_with(&mock, &context());
    mock.faults().push(Fault::on("GET", TIME).status(400));
    let e = other.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    other.list_zones().await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), TIME), 3);
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);
}

/// A wrong application secret makes every signature wrong, and a wrong consumer key is refused:
/// both are the mock's 403 (`Forbidden`), and nothing is written.
#[tokio::test]
async fn ovh_wrong_keys_are_refused() {
    let mock = OvhMock::start(Seed::standard()).await;
    let ctx = context();
    for (secret, consumer) in [("wrong-secret", CK), (AS, "wrong-consumer")] {
        let client = Ovh::new(
            settings(mock.base_url()),
            credentials(secret, consumer),
            &ctx,
        )
        .unwrap();
        let e = client.check(&[zone()]).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    }
    let mut config = settings(mock.base_url());
    config.application_key = "other-ak".into();
    let client = Ovh::new(config, credentials(AS, CK), &ctx).unwrap();
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    assert!(mock.control().records().is_empty());
}

// ---- Requests and answers ----------------------------------------------------------------------

/// The requests as the sources describe them: the listing filtered by type and relative name
/// (by type only at the apex), one read per identifier, the create with the relative name and
/// without `subDomain` at the apex, the delete by identifier, the refresh without a body.
#[tokio::test]
async fn ovh_request_shapes() {
    let (mock, client) = setup().await;
    add(&client, "v1").await.unwrap();
    let log = mock.log();
    let list = log.matching(Some("GET"), RECORDS).pop().unwrap();
    assert_eq!(list.path, "/1.0/domain/zone/example.org/record");
    assert_eq!(
        list.query.as_deref(),
        Some("fieldType=TXT&subDomain=_acme-challenge")
    );
    let post = log.matching(Some("POST"), RECORDS).pop().unwrap();
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({"fieldType": "TXT", "subDomain": "_acme-challenge", "target": "v1", "ttl": 120})
    );
    assert_eq!(post.header("content-type"), Some("application/json"));
    let refresh = log.matching(Some("POST"), REFRESH).pop().unwrap();
    assert_eq!(refresh.path, "/1.0/domain/zone/example.org/refresh");
    assert!(refresh.body.is_empty());

    client
        .add_txt_value(&zone(), &zone(), &txt("apex"), None)
        .await
        .unwrap();
    let list = mock.log().matching(Some("GET"), RECORDS).pop().unwrap();
    assert_eq!(list.query.as_deref(), Some("fieldType=TXT"));
    let post = mock.log().matching(Some("POST"), RECORDS).pop().unwrap();
    assert_eq!(
        post.body_json().unwrap(),
        serde_json::json!({"fieldType": "TXT", "target": "apex", "ttl": 120})
    );
    assert_eq!(mock.control().txt_values("example.org"), ["\"apex\""]);

    remove(&client, "v1").await.unwrap();
    let delete = mock.log().matching(Some("DELETE"), RECORD).pop().unwrap();
    let id = delete
        .path
        .rsplit('/')
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(
        mock.log()
            .matching(Some("GET"), RECORD)
            .iter()
            .any(|r| r.path.ends_with(&format!("/{id}")))
    );
}

/// An answer may state TXT content quoted or not, the apex as `null` or `""`, and a create
/// answer may lack the identifier: the values read the same, and a repeat neither writes nor
/// removes the wrong record.
#[tokio::test]
async fn ovh_answer_forms_read_the_same() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_create_without_id(true);
    control.set_apex_null(true);
    for quoting in [true, false] {
        control.set_txt_quoting(quoting);
        for owner in [zone(), name()] {
            assert_eq!(
                client
                    .add_txt_value(&zone(), &owner, &txt("AAA"), None)
                    .await
                    .unwrap(),
                AddOutcome::Created
            );
            assert_eq!(
                client
                    .add_txt_value(&zone(), &owner, &txt("AAA"), None)
                    .await
                    .unwrap(),
                AddOutcome::AlreadyPresent
            );
            assert_eq!(
                client
                    .get_rrset(&zone(), &owner, RecordType::TXT)
                    .await
                    .unwrap(),
                Some(
                    RrSet::new(
                        owner.clone(),
                        RecordType::TXT,
                        Some(RrsetTtl::from_secs(120).unwrap()),
                        [rdata(RecordType::TXT, "\"AAA\"")]
                    )
                    .unwrap()
                )
            );
            assert_eq!(
                client
                    .remove_txt_value(&zone(), &owner, &txt("AAA"))
                    .await
                    .unwrap(),
                RemoveOutcome::RrsetDeleted
            );
        }
    }
    assert!(control.records().is_empty());
}

/// A record whose read answers `404` while the listing still holds it is read again after a
/// pause (the provider makes a new record readable after a delay); a record the listing no
/// longer holds is left out of the read.
#[tokio::test]
async fn ovh_listed_record_not_yet_readable_is_read_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_read_lag(1);
    add(&client, "AAA").await.unwrap();
    let reads = mock.log().count(Some("GET"), RECORD);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(mock.log().count(Some("GET"), RECORD), reads + 2);

    // Deleted between the listing and the read: left out after one new listing, without a
    // second read.
    control.set_read_lag(0);
    let id = control.records()[0].id;
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("GET", RECORD).run(move || hook.delete_record(id)));
    mock.log().clear();
    assert_eq!(
        client
            .get_rrset(&zone(), &name(), RecordType::TXT)
            .await
            .unwrap(),
        None
    );
    assert_eq!(mock.log().count(Some("GET"), RECORD), 1);
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 2);
}

/// A listed record that stays unreadable ends the read with `Transient` after the bounded
/// attempts, and nothing is written.
#[tokio::test]
async fn ovh_listed_record_that_stays_unreadable_is_transient() {
    let (mock, client) = setup().await;
    mock.control().set_read_lag(10);
    add(&client, "AAA").await.unwrap();
    mock.log().clear();
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    // Four reads, each 404 followed by a listing that still holds the record.
    assert_eq!(mock.log().count(Some("GET"), RECORD), 4);
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 5);
    assert_eq!(writes(&mock), 0);
}

/// Odd listings: a repeated identifier, more records than the client reads one by one, and a
/// record of the filtered read that does not state its name are `Error::Protocol`, and nothing
/// is written after them.
#[tokio::test]
async fn ovh_odd_listings_are_protocol_errors() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let id = control.insert_record("example.org", NAME, "TXT", "\"x\"", Some(120));
    for body in [
        format!("[{id},{id}]"),
        serde_json::json!((1..=1001).collect::<Vec<u64>>()).to_string(),
    ] {
        mock.faults()
            .push(Fault::on("GET", RECORDS).respond(200, body.clone()));
        let e = add(&client, "new").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    mock.faults().push(Fault::on("GET", RECORD).respond(
        200,
        format!(r#"{{"id":{id},"zone":"example.org","fieldType":"TXT","target":"x","ttl":120}}"#),
    ));
    let e = add(&client, "new").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().push(Fault::on("GET", RECORD).respond(
        200,
        format!(
            r#"{{"id":{},"subDomain":"_acme-challenge","fieldType":"TXT","target":"x"}}"#,
            id + 1
        ),
    ));
    let e = add(&client, "new").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// The TTL a value is written with: the configured one for a new set, the caller's when given,
/// the set's own when the name has TXT records.
#[tokio::test]
async fn ovh_ttl_policy() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.control().records()[0].ttl, Some(120));
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
        Some(300)
    );
    let mut config = settings(mock.base_url());
    config.ttl = RrsetTtl::from_secs(3600).unwrap();
    let configured = Ovh::new(config, credentials(AS, CK), &context()).unwrap();
    configured
        .add_txt_value(&zone(), &dn("_x.example.org"), &txt("v"), None)
        .await
        .unwrap();
    assert_eq!(
        mock.control().records_at("_x.example.org", "TXT")[0].ttl,
        Some(3600)
    );
    // Joining a set takes the set's TTL.
    configured
        .add_txt_value(&zone(), &name(), &txt("BBB"), None)
        .await
        .unwrap();
    assert_eq!(mock.control().records_at(NAME, "TXT")[1].ttl, Some(120));
    // A record with a TTL of 0 or none is read without a TTL; a value joining it, or a record
    // created by a replacement next to it, takes the same form (`0`, or no `ttl` member), never
    // the configured TTL, so that the rrset does not get two TTLs.
    let control = mock.control();
    for (owner, form) in [
        ("_z.example.org", Some(0)),
        ("_n.example.org", None),
        ("z.example.org", Some(0)),
        ("n.example.org", None),
    ] {
        let rtype = if owner.starts_with('_') { "TXT" } else { "A" };
        let first = if rtype == "TXT" { "\"a\"" } else { "192.0.2.1" };
        control.insert_record("example.org", owner, rtype, first, form);
        let set = client
            .get_rrset(&zone(), &dn(owner), rtype.parse().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(set.ttl(), None, "{owner}");
        mock.log().clear();
        if rtype == "TXT" {
            configured
                .add_txt_value(&zone(), &dn(owner), &txt("b"), None)
                .await
                .unwrap();
        } else {
            configured
                .set_rrset(
                    &zone(),
                    &rr(owner, RecordType::A, None, &["192.0.2.1", "192.0.2.2"]),
                    Expect::Any,
                )
                .await
                .unwrap();
        }
        let post = mock.log().matching(Some("POST"), RECORDS).pop().unwrap();
        assert_eq!(
            post.body_json().unwrap().get("ttl").cloned(),
            form.map(serde_json::Value::from),
            "{owner}"
        );
        assert_eq!(control.records_at(owner, rtype)[1].ttl, form, "{owner}");
    }
}

/// `check` lists the zones with signed requests and reports each as found or not; `list_zones`
/// returns them all.
#[tokio::test]
async fn ovh_check_and_list_zones() {
    let (mock, client) = setup().await;
    mock.control().insert_zone("b.example");
    let report = client
        .check(&[zone(), dn("missing.example"), dn("b.example")])
        .await
        .unwrap();
    assert!(report.credentials_verified);
    let found: Vec<bool> = report.zones.iter().map(|z| z.found).collect();
    assert_eq!(found, [true, false, true]);
    let zones: Vec<String> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name.to_string())
        .collect();
    assert_eq!(zones, ["b.example.", "example.org."]);
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);
}

/// A `404` is `ZoneNotFound` only when the zone listing confirms it; with the zone listed, the
/// refusal is returned as it is. Nothing is written.
#[tokio::test]
async fn ovh_zone_not_found() {
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
    // A 404 for a zone that is listed: the refusal as it is.
    mock.faults().push(
        Fault::on("POST", RECORDS)
            .respond(404, r#"{"class":"Client::NotFound","message":"Unknown"}"#),
    );
    let e = add(&client, "v").await.unwrap_err();
    assert!(
        matches!(
            e,
            Error::Rejected {
                status: Some(404),
                ..
            }
        ),
        "{e:?}"
    );
    assert!(mock.control().records().is_empty());
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn ovh_from_json_builds_the_client() {
    let mock = OvhMock::start(Seed::standard()).await;
    let settings = serde_json::json!({
        "application_key": AK, "base_url": mock.base_url(), "ttl": 60
    })
    .to_string();
    let client = AnyProvider::from_json(
        ProviderId::Ovh,
        &settings,
        &SecretString::from(
            serde_json::json!({"application_secret": AS, "consumer_key": CK, "other": 1})
                .to_string(),
        ),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Ovh);
    assert_eq!(add(&client, "v").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.control().records()[0].ttl, Some(60));
}

/// The application key and the two secrets are required; the defaults are the EU endpoint and
/// a TTL of 120. Each named endpoint builds a client without a request.
#[test]
fn ovh_minimal_configuration_builds() {
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let credentials = r#"{"application_secret":"s","consumer_key":"c"}"#;
    for endpoint in [None, Some("ovh-eu"), Some("ovh-ca"), Some("ovh-us")] {
        let mut settings = serde_json::json!({"application_key": "k"});
        if let Some(endpoint) = endpoint {
            settings["endpoint"] = endpoint.into();
        }
        let client = Ovh::new(
            serde_json::from_value(settings).unwrap(),
            serde_json::from_str(credentials).unwrap(),
            &ctx,
        )
        .unwrap();
        let text = format!("{client:?}");
        assert!(!text.contains("\"s\"") && !text.contains("\"c\""), "{text}");
    }
    let client = AnyProvider::from_json(
        ProviderId::Ovh,
        r#"{"application_key":"k"}"#,
        &SecretString::from(credentials.to_owned()),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Ovh);
    let config = OvhConfig::new("k");
    assert_eq!(config.endpoint, "ovh-eu");
    assert_eq!(config.base_url, None);
    assert_eq!(config.ttl, RrsetTtl::from_secs(120).unwrap());
}

/// Configuration errors name the key, never the value.
#[test]
fn ovh_config_errors_name_no_value() {
    // A context without `loopback_only`, so that the default endpoints are accepted.
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let build = |settings: &str, credentials: &str| {
        AnyProvider::from_json(
            ProviderId::Ovh,
            settings,
            &SecretString::from(credentials.to_owned()),
            &ctx,
        )
    };
    let keys = r#"{"application_secret":"s3cret-value","consumer_key":"c0nsumer-value"}"#;
    for (settings, credentials, key) in [
        (r#"{"application_key":"k","ttl":59}"#, keys, "ttl"),
        (r#"{"application_key":"k","ttl":86401}"#, keys, "ttl"),
        (
            r#"{"application_key":"k","ttl":"provider_default"}"#,
            keys,
            "ttl",
        ),
        (
            r#"{"application_key":"k","endpoint":"kimsufi-eu"}"#,
            keys,
            "endpoint",
        ),
        (
            r#"{"application_key":"k","base_url":"not a url"}"#,
            keys,
            "base_url",
        ),
        (r#"{"application_key":"  "}"#, keys, "application_key"),
        (
            r#"{"application_key":"k"}"#,
            r#"{"application_secret":"","consumer_key":"c0nsumer-value"}"#,
            "application_secret",
        ),
        (
            r#"{"application_key":"k"}"#,
            r#"{"application_secret":"s3cret-value","consumer_key":"c0nsumer\nvalue"}"#,
            "consumer_key",
        ),
        (
            r#"{"application_key":"k"}"#,
            r#"{"consumer_key":"c0nsumer-value"}"#,
            "application_secret",
        ),
        (
            r#"{"application_key":"k"}"#,
            r#"{"application_secret":"s3cret-value","consumer_key":" c0nsumer-value"}"#,
            "consumer_key",
        ),
        (
            r#"{"application_key":"k"}"#,
            r#"{"application_secret":"s3cret-value\t","consumer_key":"c0nsumer-value"}"#,
            "application_secret",
        ),
        (
            r#"{"application_key":"k","read_retry_ms":0}"#,
            keys,
            "read_retry_ms",
        ),
    ] {
        let e = build(settings, credentials).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{settings} {e:?}");
        let text = format!("{e} | {e:?}");
        assert!(text.contains(key), "{settings}: {text}");
        assert!(
            !text.contains("s3cret-value") && !text.contains("c0nsumer"),
            "{text}"
        );
    }
    let e = build("{}", keys).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
}

// ---- Record level ------------------------------------------------------------------------------

/// Every supported type through set, get and list with canonical equality: the apex, an IDN
/// name, a wildcard, a delegation, multi-value sets and a TXT value of a full character-string.
/// What is published equals what is read.
#[tokio::test]
async fn ovh_record_round_trips() {
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
        rr(
            "_25._tcp.mail.example.org",
            RecordType::TLSA,
            None,
            &["3 1 1 0a1b2c3d"],
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
    assert!(settled(&mock));
    assert_eq!(
        stored(&mock, "example.org", "MX"),
        ["10 mail.example.org.", "20 backup.example.net."]
    );
    assert_eq!(
        stored(&mock, "xn--bcher-kva.example.org", "A"),
        ["192.0.2.3"]
    );
    assert!(
        mock.control()
            .records()
            .iter()
            .any(|r| r.sub_domain == "*" && r.field_type == "AAAA")
    );
    // What is published is what was written.
    let published = mock.published();
    let apex_txt = published
        .rrsets
        .iter()
        .find(|c| c.name == "example.org" && c.rtype == "TXT")
        .and_then(|c| c.rrset.clone())
        .unwrap();
    let mut values = apex_txt.values.clone();
    values.sort();
    let mut expected = vec![long.clone(), "\"v=1\"".to_owned()];
    expected.sort();
    assert_eq!(values, expected);
}

/// `Expect::Absent` on an existing set and `Expect::Matches` on a different or missing one are
/// `PreconditionFailed` and write nothing; an expectation that holds lets the write through.
#[tokio::test]
async fn ovh_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", www, "A", "192.0.2.1", Some(600));
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
    assert_eq!(writes(&mock), 0);
    assert_eq!(control.records(), original);
    // Each refused operation read the zone and then refreshed it, so that a refusal describes
    // a published state (nothing was staged here).
    assert!(settled(&mock));

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
    assert!(settled(&mock));
}

/// A replacement creates the missing values before it deletes the surplus; a TTL change updates
/// the records in place with the target and the name as read; a CNAME is replaced in place.
#[tokio::test]
async fn ovh_replacement_order_and_updates() {
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
    let methods: Vec<String> = mock
        .log()
        .entries()
        .iter()
        .filter(|r| r.method != Method::GET)
        .map(|r| format!("{} {}", r.method, r.path.rsplit('/').next().unwrap_or("")))
        .collect();
    assert_eq!(methods[0], "POST record");
    assert!(methods[1].starts_with("DELETE "));
    assert_eq!(methods[2], "POST refresh");
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.2", "192.0.2.3"]);

    mock.log().clear();
    let retuned = replaced
        .clone()
        .with_ttl(Some(RrsetTtl::from_secs(3600).unwrap()));
    client
        .set_rrset(&zone(), &retuned, Expect::Any)
        .await
        .unwrap();
    let puts = mock.log().matching(Some("PUT"), RECORD);
    assert_eq!(puts.len(), 2);
    let mut bodies: Vec<serde_json::Value> = puts.iter().map(|p| p.body_json().unwrap()).collect();
    bodies.sort_by_key(|b| b.to_string());
    assert_eq!(
        bodies,
        [
            serde_json::json!({"subDomain": "www", "target": "192.0.2.2", "ttl": 3600}),
            serde_json::json!({"subDomain": "www", "target": "192.0.2.3", "ttl": 3600}),
        ]
    );
    assert!(
        control
            .records_at(www, "A")
            .iter()
            .all(|r| r.ttl == Some(3600))
    );

    control.insert_record(
        "example.org",
        "example.org",
        "CNAME",
        "old.example.net.",
        None,
    );
    mock.log().clear();
    // An apex CNAME read without a TTL: the update leaves out the name and the TTL.
    let cname = rr(
        "example.org",
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
    let puts = mock.log().matching(Some("PUT"), RECORD);
    assert_eq!(puts.len(), 1);
    assert_eq!(
        puts[0].body_json().unwrap(),
        serde_json::json!({"target": "new.example.net."})
    );
    assert_eq!(mock.log().count(Some("POST"), RECORDS), 0);
    assert_eq!(stored(&mock, "example.org", "CNAME"), ["new.example.net."]);
    assert!(settled(&mock));
}

/// The record-level create bodies with each type's `target`, and the listing request without
/// filters.
#[tokio::test]
async fn ovh_record_request_shapes() {
    let (mock, client) = setup().await;
    for (set, body) in [
        (
            rr(
                "example.org",
                RecordType::MX,
                None,
                &["10 mail.example.org."],
            ),
            serde_json::json!({"fieldType": "MX", "target": "10 mail.example.org.", "ttl": 120}),
        ),
        (
            rr(
                "_sip._udp.example.org",
                RecordType::SRV,
                Some(600),
                &["1 2 3 sip.example.org."],
            ),
            serde_json::json!({
                "fieldType": "SRV", "subDomain": "_sip._udp", "target": "1 2 3 sip.example.org.",
                "ttl": 600
            }),
        ),
        (
            rr(
                "example.org",
                RecordType::CAA,
                None,
                &["0 issue \"ca.example.net\""],
            ),
            serde_json::json!({"fieldType": "CAA", "target": "0 issue \"ca.example.net\"", "ttl": 120}),
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
    assert_eq!(list.query, None);
}

/// The listing carries a value it cannot parse as non-canonical data and types outside the
/// record-level list, and reports what the model cannot hold: an unknown type, a name in a form
/// the sources do not describe, two CNAME records at one name.
#[tokio::test]
async fn ovh_listing_reports_skipped_sets() {
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
        Some(300),
    );
    control.insert_record(
        "example.org",
        "x.example.org",
        "DKIM",
        "v=DKIM1;k=rsa",
        Some(300),
    );
    control.insert_record(
        "example.org",
        "ptr.example.org",
        "PTR",
        "host.example.net.",
        Some(300),
    );
    control.insert_record(
        "example.org",
        "two.example.org",
        "CNAME",
        "a.example.net.",
        Some(300),
    );
    control.insert_record(
        "example.org",
        "two.example.org",
        "CNAME",
        "b.example.net.",
        Some(300),
    );
    control.insert_record("example.org", "bad name", "A", "192.0.2.9", Some(300));
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
    let ptr = get("ptr.example.org", RecordType::PTR).unwrap();
    assert_eq!(ptr.records()[0].as_str(), "host.example.net.");

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
            "DKIM".to_owned(),
            SkipReason::UnknownType,
        ),
    ];
    expected.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(skipped, expected);
    assert_eq!(listing.rrsets.len(), 3);
    // One listing request and one read per record.
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 1);
    assert_eq!(mock.log().count(Some("GET"), RECORD), 8);
}

/// Values the client has no established encoding for are refused before any write.
#[tokio::test]
async fn ovh_values_without_an_encoding_are_refused() {
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
            &rr("p.example.org", RecordType::PTR, None, &["h.example.net."]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// Record writes that carry no condition are sent once for every failing status; an update
/// answered 404 is `Conflict` when the record is gone, the refusal otherwise.
#[tokio::test]
async fn ovh_record_writes_are_sent_once() {
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
        let fault = Fault::on("PUT", RECORD);
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
        assert_eq!(mock.log().count(Some("PUT"), RECORD), 1, "{status}");
    }
    // An update answered 404 for a record that is still there: the refusal.
    mock.faults()
        .push(Fault::on("PUT", RECORD).respond(404, r#"{"message":"nope"}"#));
    let e = client
        .set_rrset(&zone(), &retuned, Expect::Any)
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            Error::Rejected {
                status: Some(404),
                ..
            }
        ),
        "{e:?}"
    );
    // An update answered 404 because the record went away: `Conflict`.
    let id = control.records()[0].id;
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("PUT", RECORD).run(move || hook.delete_record(id)));
    let e = client
        .set_rrset(&zone(), &retuned, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
}

/// A record delete answered 404 reads again: gone is done, found again under a new identifier
/// is `Conflict`.
#[tokio::test]
async fn ovh_record_delete_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", www, "A", "192.0.2.1", Some(600));
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("DELETE", RECORD).run(move || hook.recreate_zone("example.org")));
    let e = client
        .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(stored(&mock, www, "A"), ["192.0.2.1"]);
    let id = control.records()[0].id;
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

/// The live client and zone from `ZONEWRIGHT_LIVE_OVH_SETTINGS`, `..._CREDENTIALS` and
/// `..._ZONE`.
fn live_client() -> (Arc<AnyProvider>, DomainName) {
    let settings = live_env("ZONEWRIGHT_LIVE_OVH_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_OVH_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_OVH_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = AnyProvider::from_json(
        ProviderId::Ovh,
        &settings,
        &SecretString::from(credentials),
        &ctx,
    )
    .unwrap();
    (Arc::new(client), zone)
}

/// Adds and removes two values under a generated label in the zone the maintainer names, and
/// removes exactly the values it added afterwards, also when the body failed. Every operation
/// refreshes the zone, which publishes whatever else is staged in it: run it on a zone with
/// nothing staged.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_ovh_add_and_remove() {
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

/// Exercises, in the zone `ZONEWRIGHT_LIVE_OVH_ZONE` and under a label made from
/// `ZONEWRIGHT_LIVE_OVH_PREFIX` and a random tag, every behavior the client assumes without a
/// source (the client's comments marked "Assumption"):
///
/// - `/auth/time` and the signature over the full URL with the query string (every call);
/// - the `subDomain` filter never dropping a record whose name equals it, also with `_` and `*`
///   in the name, and the `fieldType` filter matching the type exactly;
/// - the answer forms of `subDomain` (a name relative to the zone), of TXT (quoted or not) and
///   of host names (with or without a trailing dot, never relative);
/// - a TTL of 60, the lower bound of the client's range, and the PUT that changes a TTL with
///   `target` and `ttl` (and `subDomain` as read);
/// - a refresh of a zone without staged changes succeeding (the repeat of an add);
/// - CAA written as `0 issue "letsencrypt.org"`, TLSA as its zone-file text, MX and SRV with a
///   trailing dot, all read back equal;
/// - a TTL of 86400, the upper bound of the client's range;
/// - the apex form of `subDomain` (`null` or `""`): a value of its own added to the apex TXT set,
///   read back, and removed, without touching the set's other values;
/// - no listing lag after a create: an add repeated at once is `AlreadyPresent`, not a
///   duplicate.
///
/// Not exercised: that the record endpoints report the staged state (every write refreshes, and
/// a lookup at the zone's name servers is outside the test); a PUT without `ttl` (sent only for
/// a record read with `ttl` `null`, which the client never creates outside such a set); the
/// served TTL of a record created with `0` or without `ttl`.
///
/// Everything it created is deleted afterwards by name and type (the apex value by value), also
/// when a step failed. Every operation refreshes the zone, which publishes whatever else is
/// staged in it: run it on a zone with nothing staged.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn ovh_live_assumptions() {
    let (client, zone) = live_client();
    let prefix = live_env("ZONEWRIGHT_LIVE_OVH_PREFIX");
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
        live_set(owner("_25._tcp"), RecordType::TLSA, None, "3 1 1 0a1b2c3d"),
        live_set(
            owner("alias"),
            RecordType::CNAME,
            None,
            &format!("target.{base}"),
        ),
        live_set(owner("_txt"), RecordType::TXT, None, "\"zw-live-value\""),
        live_set(owner("*"), RecordType::A, None, "192.0.2.20"),
        live_set(owner("ttl-max"), RecordType::A, Some(86_400), "192.0.2.30"),
    ];
    let apex_value = txt(&format!("zw-live-apex-{:016x}", random_u64()));
    let created: Vec<(DomainName, RecordType)> =
        sets.iter().map(|s| (s.name().clone(), s.rtype())).collect();
    let body = {
        let (client, zone, sets, base, apex_value) = (
            client.clone(),
            zone.clone(),
            sets.clone(),
            base.clone(),
            apex_value.clone(),
        );
        tokio::spawn(async move {
            let report = client.check([&zone]).await.unwrap();
            assert!(report.zones[0].found, "{report:?}");
            // The apex: our own value only, read back through the apex form of `subDomain`.
            client
                .add_txt_value(&zone, &zone, &apex_value, None)
                .await
                .unwrap();
            let apex = client
                .get_rrset(&zone, &zone, RecordType::TXT)
                .await
                .unwrap()
                .unwrap();
            assert!(
                apex.records()
                    .iter()
                    .any(|r| Txt::from_data(r).ok().as_ref() == Some(&apex_value)),
                "{apex:?}"
            );
            assert_ne!(
                client
                    .remove_txt_value(&zone, &zone, &apex_value)
                    .await
                    .unwrap(),
                RemoveOutcome::NotPresent
            );
            // No listing lag: an add repeated at once finds the value.
            let lag = base.prepend("_lag").unwrap();
            let value = txt("zw-live-lag");
            client
                .add_txt_value(&zone, &lag, &value, None)
                .await
                .unwrap();
            assert_eq!(
                client
                    .add_txt_value(&zone, &lag, &value, None)
                    .await
                    .unwrap(),
                AddOutcome::AlreadyPresent
            );
            assert_eq!(
                client.remove_txt_value(&zone, &lag, &value).await.unwrap(),
                RemoveOutcome::RrsetDeleted
            );
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
            // A TTL change by PUT.
            let a = live_set(base.clone(), RecordType::A, Some(3600), "192.0.2.10");
            assert_eq!(
                client.set_rrset(&zone, &a, Expect::Any).await.unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                client.get_rrset(&zone, &base, RecordType::A).await.unwrap(),
                Some(a)
            );
            // The repeat of an add refreshes a zone without staged changes.
            let txt_name = base.prepend("_txt").unwrap();
            assert_eq!(
                client
                    .add_txt_value(&zone, &txt_name, &txt("zw-live-value"), None)
                    .await
                    .unwrap(),
                AddOutcome::AlreadyPresent
            );
        })
    };
    let outcome = body.await;
    let mut cleanup = Vec::new();
    if let Err(e) = client.remove_txt_value(&zone, &zone, &apex_value).await {
        cleanup.push(format!("apex value: {e}"));
    }
    let lag = base.prepend("_lag").unwrap();
    if let Err(e) = client
        .remove_txt_value(&zone, &lag, &txt("zw-live-lag"))
        .await
    {
        cleanup.push(format!("{lag}: {e}"));
    }
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
