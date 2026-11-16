//! Tests of the Gandi client (`gandi`) against its mock (`zonewright_mock::gandi`). No network;
//! the fixtures are synthetic.
#![cfg(feature = "gandi")]
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
use zonewright::providers::gandi::{Gandi, GandiConfig, GandiCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl, SetOutcome,
    SkipReason, Txt,
};
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::echo::{EchoServer, Echoed, Render};
use zonewright_mock::gandi::{GandiMock, Paging, PatchReading, Seed};
use zonewright_mock::{Fault, MockServer};

use common::echo::{CANARY_KEY, CANARY_TOKEN, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

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

assert_not_impl!(Gandi: std::fmt::Display, serde::Serialize);
assert_not_impl!(GandiCredentials: std::fmt::Display, serde::Serialize);

// ---- Fixtures ----------------------------------------------------------------------------------

/// The token of the standard seed.
const TOKEN: &str = "test-only-token";

/// The zone of the standard seed.
const ZONE: &str = "example.org";

/// The owner name most tests write to, and its name relative to the zone.
const NAME: &str = "_acme-challenge.example.org";
const RR: &str = "_acme-challenge";

/// The owner name the record-level tests write to, and its name relative to the zone.
const REC: &str = "rec.example.org";
const REC_RR: &str = "rec";

/// Fault patterns of the mock's paths.
const DOMAINS: &str = "/v5/livedns/domains";
const DOMAIN: &str = "/v5/livedns/domains/*";
const RECORDS: &str = "/v5/livedns/domains/*/records";
const TXT_RRSET: &str = "/v5/livedns/domains/*/records/*/TXT";
const A_RRSET: &str = "/v5/livedns/domains/*/records/*/A";
const ANY_RRSET: &str = "/v5/livedns/domains/*/records/*/*";

fn zone() -> DomainName {
    dn(ZONE)
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// `value` in double quotes: how the client writes a TXT value.
fn q(value: &str) -> String {
    format!("\"{value}\"")
}

fn client_at(base_url: String, token: &str, ctx: &Context) -> Gandi {
    let mut config = GandiConfig::default();
    config.base_url = base_url;
    Gandi::new(
        config,
        GandiCredentials::new(SecretString::from(token.to_owned())),
        ctx,
    )
    .unwrap()
}

fn client_with(mock: &GandiMock, token: &str, ctx: &Context) -> Gandi {
    client_at(mock.base_url(), token, ctx)
}

async fn setup() -> (GandiMock, Gandi) {
    let mock = GandiMock::start(Seed::standard()).await;
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
fn writes(mock: &MockServer) -> usize {
    let log = mock.log();
    ["POST", "PUT", "PATCH", "DELETE"]
        .iter()
        .map(|method| log.count(Some(method), ANY_RRSET))
        .sum()
}

fn rd(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap()
}

/// An rrset of canonical texts.
fn rrset(name: &str, rtype: RecordType, ttl: Option<u32>, texts: &[&str]) -> RrSet {
    RrSet::new(
        dn(name),
        rtype,
        ttl.map(|t| RrsetTtl::from_secs(t).unwrap()),
        texts.iter().map(|t| rd(rtype, t)),
    )
    .unwrap()
}

/// The TXT values the mock holds at [`NAME`].
fn txt_values(mock: &GandiMock) -> Vec<String> {
    mock.control().values(ZONE, RR, "TXT")
}

/// The JSON body of the last request of `method` to `path`.
fn last_body(mock: &GandiMock, method: &str, path: &str) -> Value {
    mock.log()
        .matching(Some(method), path)
        .pop()
        .unwrap()
        .body_json()
        .unwrap()
}

// ---- Secrets (design section 12.2) -------------------------------------------------------------

/// What the echo's rrset read answers: no rrset, an rrset with a foreign value, or one with the
/// value `v1`.
#[derive(Clone, Copy, Debug)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
}

fn ok(body: Value) -> axum::response::Response {
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// Which requests the echo answers like the API; the others are the echo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answered {
    /// None: the probe of `check` is the echo.
    Nothing,
    /// The domain listing (the probe): the domain read is the echo.
    Probe,
    /// The domain listing, the domain and the rrset reads: the request of the operation is the
    /// echo.
    Reads,
}

/// A renderer that answers like the API what `answered` says, and every other request with
/// `errors`.
fn answering(errors: Render, existing: Existing, answered: Answered) -> Render {
    Arc::new(move |e: &Echoed| {
        if answered == Answered::Nothing || e.method != Method::GET {
            return errors(e);
        }
        let segments: Vec<&str> = e.path.trim_start_matches('/').split('/').collect();
        if answered == Answered::Probe && segments.len() != 3 {
            return errors(e);
        }
        match segments.as_slice() {
            ["v5", "livedns", "domains"] => ok(json!([{ "fqdn": ZONE }])),
            ["v5", "livedns", "domains", _] => ok(json!({ "fqdn": ZONE })),
            ["v5", "livedns", "domains", _, "records", _, rtype] => {
                let value = match existing {
                    Existing::Nothing => {
                        return (
                            StatusCode::NOT_FOUND,
                            axum::Json(json!({"code": 404, "message": "not found"})),
                        )
                            .into_response();
                    }
                    Existing::Foreign => q("foreign"),
                    Existing::Ours => q("v1"),
                };
                ok(json!({
                    "rrset_name": RR, "rrset_type": rtype, "rrset_ttl": 300,
                    "rrset_values": [value]
                }))
            }
            _ => errors(e),
        }
    })
}

/// An operation against the echo.
#[derive(Clone, Copy, Debug)]
enum Op {
    Add,
    Remove,
    List,
    Set,
    Delete,
}

/// `check` and the operation against an echo that quotes every request back: no canary in any
/// error, `ZoneCheck::detail` or `Debug`, and the operation's error shows the redaction.
async fn echo_round(label: &str, client: &Gandi, op: Op) {
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
    let ours = rrset(NAME, RecordType::TXT, None, &["\"v1\""]);
    let result = match op {
        Op::Add => add(client, "v1").await.map(|o| format!("{o:?}")),
        Op::Remove => remove(client, "v1").await.map(|o| format!("{o:?}")),
        Op::List => client.list_rrsets(&zone()).await.map(|l| format!("{l:?}")),
        Op::Set => client
            .set_rrset(&zone(), &ours, Expect::Any)
            .await
            .map(|o| format!("{o:?}")),
        Op::Delete => client
            .delete_rrset(&zone(), &name(), RecordType::TXT, Expect::Any)
            .await
            .map(|o| format!("{o:?}")),
    };
    let text = match result {
        Ok(outcome) => panic!("{label}: the echo accepted the operation: {outcome}"),
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

/// `check` and every kind of request against an echo, for every dialect: the probe, the domain
/// read, the listing, the create, the value-level change (add and remove), the replacement and
/// the delete. Reads are not given a 5xx: the transport repeats them, which would add seconds per
/// dialect without coverage. A create is not given a `409`: the documented answer to a create of
/// an existing rrset becomes a constant `Conflict`.
#[tokio::test]
async fn gandi_secret_echo() {
    let ctx = context();
    let echo = EchoServer::start(200).await;
    let client = || client_at(echo.url("/v5/livedns"), CANARY_TOKEN, &ctx);
    for dialect in dialects() {
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} probe", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status).render_under(
                "/v5/livedns",
                answering(dialect.render.clone(), Existing::Nothing, Answered::Nothing),
            ));
            echo_round(&label, &client(), Op::Add).await;
            assert!(
                echo.log().count(Some("GET"), DOMAINS) > 0,
                "{label}: the probe did not reach the echo"
            );
        }
        for status in [400, 401, 403, 422] {
            let label = format!("{} {:?} {status} domain", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status).render_under(
                "/v5/livedns",
                answering(dialect.render.clone(), Existing::Nothing, Answered::Probe),
            ));
            let client = client();
            let e = client.check(&[zone()]).await.unwrap_err();
            let text = format!("{e} | {e:?} | {client:?}");
            assert!(text.contains(REDACTED), "{label}: {text}");
            assert_clean(&label, &text, &[CANARY_TOKEN]);
            assert_eq!(echo.log().count(Some("GET"), DOMAIN), 1, "{label}");
        }
        for (existing, op, method, path, statuses) in [
            (
                Existing::Nothing,
                Op::Add,
                "POST",
                TXT_RRSET,
                [400, 401, 403, 422, 500].as_slice(),
            ),
            (
                Existing::Foreign,
                Op::Add,
                "PATCH",
                TXT_RRSET,
                [400, 401, 403, 409, 422, 500].as_slice(),
            ),
            (
                Existing::Ours,
                Op::Remove,
                "PATCH",
                TXT_RRSET,
                [400, 401, 403, 409, 422, 500].as_slice(),
            ),
            (
                Existing::Nothing,
                Op::List,
                "GET",
                RECORDS,
                [400, 401, 403, 422].as_slice(),
            ),
            (
                Existing::Nothing,
                Op::Set,
                "POST",
                TXT_RRSET,
                [400, 401, 403, 422, 500].as_slice(),
            ),
            (
                Existing::Foreign,
                Op::Set,
                "PUT",
                TXT_RRSET,
                [400, 401, 403, 409, 422, 500].as_slice(),
            ),
            (
                Existing::Foreign,
                Op::Delete,
                "DELETE",
                TXT_RRSET,
                [400, 401, 403, 409, 422, 500].as_slice(),
            ),
        ] {
            for &status in statuses {
                let label = format!(
                    "{} {:?} {status} {op:?} {existing:?}",
                    dialect.name, dialect.spelling
                );
                echo.reset(dialect.echo(status).render_under(
                    "/v5/livedns",
                    answering(dialect.render.clone(), existing, Answered::Reads),
                ));
                echo_round(&label, &client(), op).await;
                assert_eq!(
                    echo.log().count(Some(method), path),
                    1,
                    "{label}: the request did not reach the echo exactly once"
                );
            }
        }
    }
}

/// A `TRACE` capture over successes, a 401, a 500 and a wrong token: the transport's events are
/// there, and no canary is.
#[tokio::test(flavor = "current_thread")]
async fn gandi_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.tokens = vec![CANARY_TOKEN.into()];
    let mock = GandiMock::start(seed).await;
    let client = client_with(&mock, CANARY_TOKEN, &context());
    let mut texts = Vec::new();

    client.check(&[zone()]).await.unwrap();
    add(&client, "v1").await.unwrap();
    add(&client, "v2").await.unwrap();
    remove(&client, "v1").await.unwrap();
    let set = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    client
        .set_rrset(&zone(), &set, Expect::Absent)
        .await
        .unwrap();
    client.list_rrsets(&zone()).await.unwrap();
    client.list_zones().await.unwrap();
    client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap();

    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).always().status(401));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults()
        .push(Fault::on("PATCH", TXT_RRSET).status(500));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    // An unknown bearer token is a 403 (the reference: "In case the bearer token has expired,
    // does not have enought permission or does not exists").
    let wrong = client_with(&mock, CANARY_KEY, &context());
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    texts.push(format!("{e} | {e:?} | {wrong:?} | {client:?}"));

    let entries = capture.entries();
    assert!(
        entries.iter().any(|e| e.target == "zonewright::http"),
        "the capture holds no transport event"
    );
    texts.push(capture.text());
    for text in &texts {
        assert_clean("gandi logs and errors", text, &[CANARY_TOKEN, CANARY_KEY]);
    }
}

/// The token travels in `Authorization: Bearer <token>`, and only there: never in a path or a
/// query.
#[tokio::test]
async fn gandi_token_is_sent_as_bearer() {
    let (mock, client) = setup().await;
    client.check(&[zone()]).await.unwrap();
    add(&client, "v1").await.unwrap();
    add(&client, "v2").await.unwrap();
    let entries = mock.log().entries();
    assert!(!entries.is_empty());
    for entry in entries {
        assert_eq!(
            entry.header("authorization"),
            Some("Bearer test-only-token"),
            "{entry:?}"
        );
        assert!(!entry.path.contains(TOKEN));
        assert!(!entry.query.as_deref().unwrap_or("").contains(TOKEN));
    }
}

/// A refusal carries the `code` of the documented error body (`cause`, `code`, `message`,
/// `object`); its kind does not change.
#[tokio::test]
async fn gandi_refusal_carries_the_provider_code() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", TXT_RRSET).respond(
        400,
        r#"{"cause":"Bad Request","code":400,"message":"invalid value","object":"HTTPBadRequest"}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(e.provider_code().map(|c| c.as_str()), Some("400"));
    assert!(e.to_string().contains("invalid value"), "{e}");

    add(&client, "AAA").await.unwrap();
    mock.faults().push(
        Fault::on("PATCH", TXT_RRSET).respond(422, r#"{"code":4221,"message":"not accepted"}"#),
    );
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(e.provider_code().map(|c| c.as_str()), Some("4221"));

    // A body without a code gives none.
    mock.faults()
        .push(Fault::on("PATCH", TXT_RRSET).respond(400, r#"{"message":"no code"}"#));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.provider_code(), None);
}

/// A code that echoes the token is not carried, and the token appears nowhere in the error. The
/// token is a number here, so it fits the code's alphabet and only the scrubber keeps it out.
#[tokio::test]
async fn gandi_provider_code_never_carries_a_credential() {
    let token = "731948265013";
    let mut seed = Seed::standard();
    seed.tokens = vec![token.into()];
    let mock = GandiMock::start(seed).await;
    let client = client_with(&mock, token, &context());
    let body = format!(r#"{{"code":{token},"message":"m"}}"#);
    mock.faults()
        .push(Fault::on("POST", TXT_RRSET).respond(400, body.clone()));
    let created = add(&client, "AAA").await.unwrap_err();
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("PATCH", TXT_RRSET).respond(422, body));
    let patched = add(&client, "BBB").await.unwrap_err();
    for e in [created, patched] {
        assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
        assert_eq!(e.provider_code(), None);
        let text = format!("{e} | {e:?}");
        assert!(!text.contains(token), "{text}");
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request, by every mutating operation: another
/// zone, a name that merely ends with the zone's text, the zone's text inside another name, and
/// a sibling zone.
#[tokio::test]
async fn gandi_name_outside_zone_sends_nothing() {
    let (mock, client) = setup().await;
    let value = txt("v1");
    for (zone, name) in [
        ("example.org", "example.net"),
        ("example.org", "badexample.org"),
        ("example.org", "example.org.evil.net"),
        ("a.example.org", "b.example.org"),
    ] {
        let (zone, name) = (dn(zone), dn(name));
        let set = RrSet::new(
            name.clone(),
            RecordType::TXT,
            None,
            [value.to_data().unwrap()],
        )
        .unwrap();
        let errors = [
            client
                .add_txt_value(&zone, &name, &value, None)
                .await
                .unwrap_err(),
            client
                .remove_txt_value(&zone, &name, &value)
                .await
                .unwrap_err(),
            client
                .set_rrset(&zone, &set, Expect::Any)
                .await
                .unwrap_err(),
            client
                .delete_rrset(&zone, &name, RecordType::TXT, Expect::Any)
                .await
                .unwrap_err(),
        ];
        for e in errors {
            assert!(matches!(e, Error::NameOutsideZone { .. }), "{e:?}");
        }
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
}

/// A value the capabilities do not accept, a TTL outside 300 to 2592000 and a type outside the
/// record types are refused before any request.
#[tokio::test]
async fn gandi_invalid_input_sends_nothing() {
    let (mock, client) = setup().await;
    let long = "x".repeat(256);
    for value in [
        "quo\"te",
        "back\\slash",
        "",
        "tab\there",
        "caf\u{e9}",
        long.as_str(),
    ] {
        let e = add(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
        let e = remove(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
    }
    for ttl in [
        Some(RrsetTtl::ProviderDefault),
        RrsetTtl::from_secs(299).ok(),
        RrsetTtl::from_secs(2_592_001).ok(),
    ] {
        let e = client
            .add_txt_value(&zone(), &name(), &txt("v1"), ttl)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{ttl:?}: {e:?}");
    }
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, Some(60), &["192.0.2.1"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    for rtype in [RecordType::CAA, RecordType::SOA, RecordType::TLSA] {
        let e = client
            .get_rrset(&zone(), &dn(REC), rtype)
            .await
            .unwrap_err();
        assert!(
            matches!(e, Error::UnsupportedRecordType { .. }),
            "{rtype}: {e:?}"
        );
    }
    // The NS set at the apex is the provider's.
    let e = client
        .set_rrset(
            &zone(),
            &rrset(ZONE, RecordType::NS, None, &["ns1.example.net."]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
}

/// `Created`, `Appended` for a second value (the apex and the wildcard of one certificate share
/// a name), then `AlreadyPresent` without a write.
#[tokio::test]
async fn gandi_add_is_idempotent() {
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
    assert_eq!(txt_values(&mock), [q("AAA"), q("BBB")]);
}

/// Removing an absent value next to foreign ones writes nothing; adding and removing our value
/// sends only our value and leaves the foreign values (one quoted, one bare, one the client does
/// not read) and the TTL as they were. A single foreign value is never a reason to delete the
/// rrset.
#[tokio::test]
async fn gandi_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let foreign = [
        "\"foreign value\"",
        "bare-foreign",
        "\"esc\\\"aped\"",
        "two words",
    ];
    control.insert_rrset(ZONE, RR, "TXT", Some(600), &foreign);
    let original = control.rrset(ZONE, RR, "TXT").unwrap();

    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        last_body(&mock, "PATCH", TXT_RRSET),
        json!({ "add_rrset_values": [q("ours")], "rrset_ttl": 600 })
    );
    let during = control.rrset(ZONE, RR, "TXT").unwrap();
    assert_eq!(during.ttl, Some(600));
    let mut expected: Vec<String> = foreign.iter().map(|v| (*v).to_owned()).collect();
    expected.push(q("ours"));
    assert_eq!(during.values, expected);

    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(
        last_body(&mock, "PATCH", TXT_RRSET),
        json!({ "remove_rrset_values": [q("ours")], "rrset_ttl": 600 })
    );
    assert_eq!(control.rrset(ZONE, RR, "TXT").unwrap(), original);
    assert_eq!(mock.log().count(Some("PUT"), ANY_RRSET), 0);
    assert_eq!(mock.log().count(Some("DELETE"), ANY_RRSET), 0);

    // A single foreign value: nothing is deleted.
    control.insert_rrset(
        ZONE,
        "_acme-challenge.www",
        "TXT",
        Some(300),
        &["\"foreign\""],
    );
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(
                &zone(),
                &dn("_acme-challenge.www.example.org"),
                &txt("ours")
            )
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(
        control.values(ZONE, "_acme-challenge.www", "TXT"),
        [q("foreign")]
    );
}

/// The last value is removed with the value-level change, which leaves no rrset (`204`); no
/// `DELETE` is sent.
#[tokio::test]
async fn gandi_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().rrsets().is_empty());
    assert_eq!(mock.log().count(Some("PATCH"), TXT_RRSET), 1);
    assert_eq!(mock.log().count(Some("DELETE"), TXT_RRSET), 0);
}

#[tokio::test]
async fn gandi_remove_is_idempotent() {
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
    assert!(mock.control().rrsets().is_empty());
}

/// Two clients sharing a `Context` add to one name at once, the first create delayed: both
/// values end up in the rrset. Without the name lock both would read "no rrset" and the second
/// create would be refused.
#[tokio::test]
async fn gandi_concurrent_adds_are_serialized() {
    let mock = GandiMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, TOKEN, &ctx);
    let b = client_with(&mock, TOKEN, &ctx);
    mock.faults()
        .push(Fault::on("POST", TXT_RRSET).delay(Duration::from_millis(300)));
    let (zone, name, aaa, bbb) = (zone(), name(), txt("AAA"), txt("BBB"));
    let (ra, rb) = tokio::join!(
        a.add_txt_value(&zone, &name, &aaa, None),
        b.add_txt_value(&zone, &name, &bbb, None),
    );
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [AddOutcome::Appended, AddOutcome::Created]);
    let mut values = txt_values(&mock);
    values.sort();
    assert_eq!(values, [q("AAA"), q("BBB")]);
}

/// Every write is sent once: a 502, a 429 and a 401 on the create, the value-level add and
/// remove, the replacement and the delete are the operation's error, with exactly one such
/// request each; the repeat starts with a read and converges.
#[tokio::test]
async fn gandi_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let faults = |method: &str, path: &str| {
        [
            (Fault::on(method, path).status(502), ErrorKind::Transient),
            (
                Fault::on(method, path).rate_limited("1"),
                ErrorKind::RateLimited,
            ),
            (Fault::on(method, path).status(401), ErrorKind::Auth),
        ]
    };
    // The create of the TXT rrset, the add of a second value, the remove of a value.
    for (method, op, value) in [
        ("POST", "add", "AAA"),
        ("PATCH", "add", "BBB"),
        ("PATCH", "remove", "AAA"),
    ] {
        if (method, op) == ("PATCH", "add") {
            add(&client, "AAA").await.unwrap();
        }
        if op == "remove" {
            add(&client, "BBB").await.unwrap();
        }
        let mut sent = mock.log().count(Some(method), TXT_RRSET);
        for (fault, kind) in faults(method, TXT_RRSET) {
            mock.faults().push(fault);
            let e = match op {
                "add" => add(&client, value).await.map(drop),
                _ => remove(&client, value).await.map(drop),
            }
            .unwrap_err();
            assert_eq!(e.kind(), kind, "{method} {op}: {e:?}");
            sent += 1;
            assert_eq!(
                mock.log().count(Some(method), TXT_RRSET),
                sent,
                "{method} {op}"
            );
        }
    }
    assert_eq!(txt_values(&mock), [q("AAA"), q("BBB")]);

    // The remove is answered 502 and not applied; meanwhile another writer adds a value. The
    // repeat reads the new state and removes only our value.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("PATCH", TXT_RRSET)
            .run(move || {
                hook.edit_rrset(ZONE, RR, "TXT", |rrset| rrset.values.push(q("foreign")));
            })
            .status(502),
    );
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(txt_values(&mock), [q("BBB"), q("foreign")]);

    // The record level: a create, a replacement and a delete.
    let set = |texts: &[&str]| rrset(REC, RecordType::A, None, texts);
    let control = mock.control();
    for (method, ..) in [("POST", ()), ("PUT", ()), ("DELETE", ())] {
        for (fault, kind) in faults(method, A_RRSET) {
            control.delete_rrset(ZONE, REC_RR, "A");
            if method != "POST" {
                control.insert_rrset(ZONE, REC_RR, "A", Some(300), &["192.0.2.1"]);
            }
            let sent = mock.log().count(Some(method), A_RRSET);
            mock.faults().push(fault);
            let e = match method {
                "POST" => client
                    .set_rrset(&zone(), &set(&["192.0.2.1"]), Expect::Any)
                    .await
                    .map(drop),
                "PUT" => client
                    .set_rrset(&zone(), &set(&["192.0.2.2"]), Expect::Any)
                    .await
                    .map(drop),
                _ => client
                    .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
                    .await
                    .map(drop),
            }
            .unwrap_err();
            assert_eq!(e.kind(), kind, "{method}: {e:?}");
            assert_eq!(
                mock.log().count(Some(method), A_RRSET),
                sent + 1,
                "{method}"
            );
            let expected: Vec<String> = if method == "POST" {
                Vec::new()
            } else {
                vec!["192.0.2.1".to_owned()]
            };
            assert_eq!(control.values(ZONE, REC_RR, "A"), expected, "{method}");
        }
    }
}

/// A create that meets an rrset another writer created after the read is `Conflict`, both for
/// the documented `409` (other values) and for the documented `200` (the same values); nothing
/// is overwritten, and the repeat converges.
#[tokio::test]
async fn gandi_create_race_is_conflict() {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("POST", TXT_RRSET).run(move || {
            hook.insert_rrset(ZONE, RR, "TXT", Some(300), &["\"foreign\""]);
        }));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(txt_values(&mock), [q("foreign")]);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    assert_eq!(txt_values(&mock), [q("foreign"), q("AAA")]);

    mock.control().delete_rrset(ZONE, RR, "TXT");
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("POST", TXT_RRSET).run(move || {
            hook.insert_rrset(ZONE, RR, "TXT", Some(300), &["\"AAA\""]);
        }));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );

    // The record level.
    let hook = mock.control().clone();
    mock.faults().push(Fault::on("POST", A_RRSET).run(move || {
        hook.insert_rrset(ZONE, REC_RR, "A", Some(600), &["192.0.2.9"]);
    }));
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(mock.control().values(ZONE, REC_RR, "A"), ["192.0.2.9"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
}

/// A value-level add or a replacement of an rrset that went away after the read is `Conflict`
/// with nothing written; the repeat creates the rrset.
#[tokio::test]
async fn gandi_write_to_a_vanished_rrset_is_conflict() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("PATCH", TXT_RRSET).run(move || hook.delete_rrset(ZONE, RR, "TXT")));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(mock.control().rrsets().is_empty());
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Created);

    // A `204` after an add is an answer the client cannot interpret.
    mock.faults()
        .push(Fault::on("PATCH", TXT_RRSET).respond(204, ""));
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");

    // A replacement answered 404.
    mock.control()
        .insert_rrset(ZONE, REC_RR, "A", Some(300), &["192.0.2.1"]);
    mock.faults()
        .push(Fault::on("PUT", A_RRSET).respond(404, r#"{"code":404,"message":"not found"}"#));
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.2"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
}

/// A removal answered 404 counts as done only when a new read no longer finds the value; a
/// delete answered 404 only when a new read finds no rrset. Otherwise the result is a retryable
/// `Conflict`.
#[tokio::test]
async fn gandi_not_found_on_a_removal_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("PATCH", TXT_RRSET).run(move || hook.delete_rrset(ZONE, RR, "TXT")));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );

    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(
        Fault::on("PATCH", TXT_RRSET)
            .run(move || {
                hook.delete_rrset(ZONE, RR, "TXT");
                hook.insert_rrset(ZONE, RR, "TXT", Some(300), &["\"AAA\""]);
            })
            .respond(404, r#"{"code":404,"message":"not found"}"#),
    );
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );

    // The record level's delete.
    control.insert_rrset(ZONE, REC_RR, "A", Some(300), &["192.0.2.1"]);
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("DELETE", A_RRSET).run(move || hook.delete_rrset(ZONE, REC_RR, "A")));
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    control.insert_rrset(ZONE, REC_RR, "A", Some(300), &["192.0.2.1"]);
    mock.faults()
        .push(Fault::on("DELETE", A_RRSET).respond(404, r#"{"code":404,"message":"not found"}"#));
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(control.values(ZONE, REC_RR, "A"), ["192.0.2.1"]);
}

/// `Expect::Absent` on an existing set and `Expect::Matches` on a changed one are
/// `PreconditionFailed` and write nothing; `Expect::Absent` on a delete is `InvalidInput`.
#[tokio::test]
async fn gandi_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZONE, REC_RR, "A", Some(600), &["192.0.2.1"]);
    let current = rrset(REC, RecordType::A, Some(600), &["192.0.2.1"]);
    let stale = rrset(REC, RecordType::A, Some(600), &["192.0.2.9"]);
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    for expect in [Expect::Absent, Expect::Matches(&stale)] {
        let e = client
            .set_rrset(&zone(), &wanted, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    }
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Matches(&stale))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    let other_ttl = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Matches(&other_ttl))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Absent)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    control.delete_rrset(ZONE, REC_RR, "A");
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Matches(&current))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(writes(&mock), 0);
    control.insert_rrset(ZONE, REC_RR, "A", Some(600), &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&current))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    // The TTL is kept: the write sends the rrset's.
    assert_eq!(last_body(&mock, "PUT", A_RRSET)["rrset_ttl"], 600);
}

/// The listing holds every rrset of the zone, values canonical where the text has the form of
/// its type; a value with a name without the trailing dot is non-canonical. What the model
/// cannot hold is skipped: an unknown type, a name the crate cannot hold, two records of a
/// singleton type. One `WARN` event names the number of skipped sets.
#[tokio::test(flavor = "current_thread")]
async fn gandi_listing_reports_skipped_sets() {
    let (capture, _guard) = LogCapture::install();
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(
        ZONE,
        "@",
        "NS",
        Some(10_800),
        &["ns1.example.net.", "ns2.example.net."],
    );
    control.insert_rrset(ZONE, "@", "MX", None, &["10 spool.mail.gandi.net."]);
    control.insert_rrset(ZONE, REC_RR, "A", Some(300), &["192.0.2.1", "192.0.2.2"]);
    control.insert_rrset(ZONE, REC_RR, "TXT", Some(600), &["\"v=spf1 ?all\""]);
    control.insert_rrset(ZONE, "odd", "A", Some(600), &["not-an-address"]);
    control.insert_rrset(ZONE, "rel", "CNAME", Some(600), &["www.example.net"]);
    control.insert_rrset(ZONE, "w", "WIZARD", Some(600), &["magic"]);
    let long_label = "x".repeat(64);
    control.insert_rrset(ZONE, &long_label, "A", Some(600), &["192.0.2.1"]);
    control.insert_rrset(
        ZONE,
        "c",
        "CNAME",
        Some(600),
        &["a.example.net.", "b.example.net."],
    );
    // A type outside the record-level types is listed all the same (design section 3.4).
    control.insert_rrset(
        ZONE,
        "caa",
        "CAA",
        Some(600),
        &["0 issue \"ca.example.net\""],
    );
    // Another domain's rrset is not part of the listing.
    control.insert_zone("example.com");
    control.insert_rrset("example.com", "other", "A", Some(600), &["192.0.2.7"]);

    let listing = client.list_rrsets(&zone()).await.unwrap();
    let sets: Vec<(String, RecordType)> = listing
        .rrsets
        .iter()
        .map(|s| (s.name().to_string(), s.rtype()))
        .collect();
    assert_eq!(
        sets,
        [
            ("caa.example.org.".to_owned(), RecordType::CAA),
            ("example.org.".to_owned(), RecordType::NS),
            ("example.org.".to_owned(), RecordType::MX),
            ("odd.example.org.".to_owned(), RecordType::A),
            ("rec.example.org.".to_owned(), RecordType::A),
            ("rec.example.org.".to_owned(), RecordType::TXT),
            ("rel.example.org.".to_owned(), RecordType::CNAME),
        ]
    );
    let find = |name: &str, rtype: RecordType| {
        listing
            .rrsets
            .iter()
            .find(|s| s.name() == &dn(name) && s.rtype() == rtype)
            .unwrap()
    };
    assert_eq!(
        find(REC, RecordType::A),
        &rrset(REC, RecordType::A, Some(300), &["192.0.2.1", "192.0.2.2"])
    );
    assert_eq!(
        find(REC, RecordType::TXT),
        &rrset(REC, RecordType::TXT, Some(600), &["\"v=spf1 ?all\""])
    );
    assert_eq!(
        find(ZONE, RecordType::NS),
        &rrset(
            ZONE,
            RecordType::NS,
            Some(10_800),
            &["ns1.example.net.", "ns2.example.net."]
        )
    );
    // No `rrset_ttl` in the answer: no TTL stated.
    assert_eq!(
        find(ZONE, RecordType::MX),
        &rrset(ZONE, RecordType::MX, None, &["10 spool.mail.gandi.net."])
    );
    assert_eq!(
        find("caa.example.org", RecordType::CAA).records(),
        [rd(RecordType::CAA, "0 issue \"ca.example.net\"")]
    );
    for (owner, rtype, text) in [
        ("odd.example.org", RecordType::A, "not-an-address"),
        ("rel.example.org", RecordType::CNAME, "www.example.net"),
    ] {
        let record = &find(owner, rtype).records()[0];
        assert!(!record.is_canonical(), "{owner}");
        assert_eq!(record.as_str(), text);
    }
    let mut skipped: Vec<(String, String, SkipReason)> = listing
        .skipped
        .iter()
        .map(|s| (s.name.to_string(), s.type_name.clone(), s.reason))
        .collect();
    skipped.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        skipped,
        [
            (
                "c.example.org.".to_owned(),
                "CNAME".to_owned(),
                SkipReason::NotPlainRecords
            ),
            (
                "example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::UnsupportedName
            ),
            (
                "w.example.org.".to_owned(),
                "WIZARD".to_owned(),
                SkipReason::UnknownType
            ),
        ]
    );
    let warnings: Vec<_> = capture
        .entries()
        .into_iter()
        .filter(|e| e.target == "zonewright::rrsets" && e.level == tracing::Level::WARN)
        .collect();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert_eq!(warnings[0].field("skipped"), Some("3"));
    assert_eq!(warnings[0].field("provider"), Some("gandi"));
    // One page, then the empty page that ends the listing.
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 2);
}

// ---- TXT values --------------------------------------------------------------------------------

/// The first value creates the rrset with `POST`: the zone without the trailing dot and the
/// relative name in the path (`@` as `%40` at the apex), the configured TTL, the value quoted.
/// A later value is added with `PATCH`, without a TTL.
#[tokio::test]
async fn gandi_request_shapes() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    let create = mock.log().matching(Some("POST"), TXT_RRSET).pop().unwrap();
    assert_eq!(
        create.path,
        "/v5/livedns/domains/example.org/records/_acme-challenge/TXT"
    );
    assert_eq!(create.header("content-type"), Some("application/json"));
    assert_eq!(
        create.body_json().unwrap(),
        json!({ "rrset_values": [q("AAA")], "rrset_ttl": 300 })
    );
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    let patch = mock.log().matching(Some("PATCH"), TXT_RRSET).pop().unwrap();
    assert_eq!(
        patch.body_json().unwrap(),
        json!({ "add_rrset_values": [q("BBB")], "rrset_ttl": 300 })
    );

    // A requested TTL for a new rrset; the apex.
    client
        .add_txt_value(
            &zone(),
            &zone(),
            &txt("apex"),
            RrsetTtl::from_secs(900).ok(),
        )
        .await
        .unwrap();
    let create = mock.log().matching(Some("POST"), TXT_RRSET).pop().unwrap();
    assert_eq!(
        create.path,
        "/v5/livedns/domains/example.org/records/%40/TXT"
    );
    assert_eq!(create.body_json().unwrap()["rrset_ttl"], 900);
    assert_eq!(mock.control().values(ZONE, "@", "TXT"), [q("apex")]);

    // The configured TTL.
    let mut config = GandiConfig::default();
    config.base_url = mock.base_url();
    config.ttl = RrsetTtl::from_secs(3600).unwrap();
    let client = Gandi::new(
        config,
        GandiCredentials::new(SecretString::from(TOKEN.to_owned())),
        &context(),
    )
    .unwrap();
    client
        .add_txt_value(&zone(), &dn("x.example.org"), &txt("v"), None)
        .await
        .unwrap();
    assert_eq!(
        mock.control().rrset(ZONE, "x", "TXT").unwrap().ttl,
        Some(3600)
    );
}

/// TXT text is read quoted (one string or several) or bare; text the rule leaves undecided is
/// never a value of ours, and a value spelled bare is removed by its own text.
#[tokio::test]
async fn gandi_txt_dialect() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(
        ZONE,
        RR,
        "TXT",
        Some(300),
        &["bare", "\"quo\" \"ted\"", "two words"],
    );
    assert_eq!(
        add(&client, "bare").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        add(&client, "quoted").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    // `two words` is not the value `twowords`, nor the value `two words`: bare text with a
    // space is undecided.
    assert_eq!(
        add(&client, "twowords").await.unwrap(),
        AddOutcome::Appended
    );
    assert_eq!(
        add(&client, "two words").await.unwrap(),
        AddOutcome::Appended
    );
    assert_eq!(
        last_body(&mock, "PATCH", TXT_RRSET)["add_rrset_values"],
        json!([q("two words")])
    );
    assert_eq!(
        remove(&client, "bare").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(
        last_body(&mock, "PATCH", TXT_RRSET),
        json!({ "remove_rrset_values": ["bare"], "rrset_ttl": 300 })
    );
    let set = client
        .get_rrset(&zone(), &name(), RecordType::TXT)
        .await
        .unwrap()
        .unwrap();
    let texts: Vec<String> = set
        .records()
        .iter()
        .map(|r| r.as_str().to_owned())
        .collect();
    assert!(texts.contains(&"\"quoted\"".to_owned()), "{texts:?}");
    assert!(texts.contains(&"\"twowords\"".to_owned()), "{texts:?}");
    let raw = set.records().iter().find(|r| !r.is_canonical()).unwrap();
    assert_eq!(raw.as_str(), "two words");
}

// ---- Zones -------------------------------------------------------------------------------------

/// `check` reads one page of the domain listing (`per_page=1`, with `sharing_id` when set) and
/// looks every zone up; a missing zone is reported as not found.
#[tokio::test]
async fn gandi_check_reports_zones() {
    let (mock, client) = setup().await;
    let report = client
        .check(&[zone(), dn("missing.example.net")])
        .await
        .unwrap();
    assert!(report.credentials_verified);
    let found: Vec<bool> = report.zones.iter().map(|z| z.found).collect();
    assert_eq!(found, [true, false]);
    let probe = mock.log().matching(Some("GET"), DOMAINS);
    assert_eq!(probe.len(), 1);
    assert_eq!(probe[0].query.as_deref(), Some("per_page=1"));
    assert_eq!(mock.log().count(Some("GET"), DOMAIN), 2);

    let report = client.check(&[]).await.unwrap();
    assert!(report.credentials_verified);

    let mut config = GandiConfig::default();
    config.base_url = mock.base_url();
    config.sharing_id = Some("org-1".to_owned());
    let shared = Gandi::new(
        config,
        GandiCredentials::new(SecretString::from(TOKEN.to_owned())),
        &context(),
    )
    .unwrap();
    mock.log().clear();
    shared.check(&[zone()]).await.unwrap();
    let probe = mock.log().matching(Some("GET"), DOMAINS);
    assert_eq!(
        probe[0].query.as_deref(),
        Some("per_page=1&sharing_id=org-1")
    );

    let wrong = client_with(&mock, "wrong-token", &context());
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    mock.faults()
        .push(Fault::on("GET", DOMAINS).respond(401, r#"{"code":401,"message":"no"}"#));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
}

/// Every domain, all pages; with `sharing_id`, the organization's domains only. A listing that
/// ends before its `Total-Count` is `Protocol`.
#[tokio::test]
async fn gandi_list_zones_reads_every_page() {
    let (mock, client) = setup().await;
    for i in 0..4 {
        mock.control().insert_zone(&format!("z{i}.example.net"));
    }
    mock.control()
        .insert_zone_of(Some("org-1"), "shared.example.com");
    mock.control().set_page_size(2);
    let zones: Vec<String> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name.to_string())
        .collect();
    assert_eq!(
        zones,
        [
            "example.org.",
            "z0.example.net.",
            "z1.example.net.",
            "z2.example.net.",
            "z3.example.net."
        ]
    );
    let queries: Vec<String> = mock
        .log()
        .matching(Some("GET"), DOMAINS)
        .iter()
        .map(|r| r.query.clone().unwrap_or_default())
        .collect();
    assert_eq!(queries, ["page=1", "page=2", "page=3"]);

    let mut config = GandiConfig::default();
    config.base_url = mock.base_url();
    config.sharing_id = Some("org-1".to_owned());
    let shared = Gandi::new(
        config,
        GandiCredentials::new(SecretString::from(TOKEN.to_owned())),
        &context(),
    )
    .unwrap();
    let zones: Vec<String> = shared
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name.to_string())
        .collect();
    assert_eq!(zones, ["shared.example.com."]);

    mock.faults().push(
        Fault::on("GET", DOMAINS)
            .skip(1)
            .respond(200, "[]")
            .header("Total-Count", "5"),
    );
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().push(
        Fault::on("GET", DOMAINS)
            .respond(200, "[]")
            .header("Total-Count", "many"),
    );
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// The rrset listing ends correctly under every reading of the paging the documentation allows:
/// a `Total-Count` that counts the page only still gives the whole listing, read until an empty
/// page; a server that ignores `page` and answers the same page again is `Protocol`, not an
/// endless loop; a listing without the header ends on the empty page; a listing that fits one
/// page costs one more request, for the empty page.
#[tokio::test]
async fn gandi_listing_ends_under_every_paging_reading() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for i in 0..5 {
        control.insert_rrset(ZONE, &format!("h{i}"), "A", Some(300), &["192.0.2.1"]);
        control.insert_zone(&format!("z{i}.example.net"));
    }
    control.set_page_size(2);
    assert_eq!(client.list_rrsets(&zone()).await.unwrap().rrsets.len(), 5);
    let queries = |mock: &GandiMock| -> Vec<String> {
        mock.log()
            .matching(Some("GET"), RECORDS)
            .iter()
            .map(|r| r.query.clone().unwrap_or_default())
            .collect()
    };
    assert_eq!(queries(&mock), ["page=1", "page=2", "page=3"]);

    control.set_paging(Paging::PageCount);
    mock.log().clear();
    assert_eq!(client.list_rrsets(&zone()).await.unwrap().rrsets.len(), 5);
    assert_eq!(client.list_zones().await.unwrap().len(), 6);
    assert_eq!(queries(&mock), ["page=1", "page=2", "page=3", "page=4"]);

    control.set_paging(Paging::IgnorePage);
    for e in [
        client.list_rrsets(&zone()).await.unwrap_err(),
        client.list_zones().await.unwrap_err(),
    ] {
        assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
        assert!(e.to_string().contains("repeated"), "{e}");
    }

    control.set_paging(Paging::Total);
    control.set_page_size(100);
    mock.log().clear();
    assert_eq!(client.list_rrsets(&zone()).await.unwrap().rrsets.len(), 5);
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 2);

    // Without the header the empty page ends the listing.
    mock.log().clear();
    mock.faults().push(Fault::on("GET", RECORDS).respond(
        200,
        r#"[{"rrset_name":"h","rrset_type":"A","rrset_values":["192.0.2.1"]}]"#,
    ));
    mock.faults()
        .push(Fault::on("GET", RECORDS).respond(200, "[]"));
    assert_eq!(client.list_rrsets(&zone()).await.unwrap().rrsets.len(), 1);
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 2);
}

/// The answer to a read of one rrset may leave out `rrset_name` and `rrset_type`, which the path
/// states; another name or type is `Protocol`, and so is an answer without `rrset_values`. In a
/// listing an item without a name or a type is `Protocol`.
#[tokio::test]
async fn gandi_single_rrset_answer_may_omit_name_and_type() {
    let (mock, client) = setup().await;
    for body in [
        r#"{"rrset_values":["\"v1\""],"rrset_ttl":300}"#,
        r#"{"rrset_name":"_ACME-challenge","rrset_values":["\"v1\""]}"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", TXT_RRSET).respond(200, body));
        assert_eq!(
            add(&client, "v1").await.unwrap(),
            AddOutcome::AlreadyPresent,
            "{body}"
        );
    }
    for body in [
        r#"{"rrset_name":"other","rrset_values":[]}"#,
        r#"{"rrset_type":"A","rrset_values":[]}"#,
        r#"{"rrset_name":"_acme-challenge","rrset_type":"TXT"}"#,
        r#"{"rrset_values":"v1"}"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", TXT_RRSET).respond(200, body));
        let e = add(&client, "v1").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    for body in [
        r#"[{"rrset_type":"A","rrset_values":[]}]"#,
        r#"[{"rrset_name":"a","rrset_values":[]}]"#,
        r#"{"rrset_name":"a"}"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", RECORDS).respond(200, body));
        let e = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);
}

/// A zone the API does not know is `ZoneNotFound` for reads and writes, after the rrset read
/// answered 404 and the domain read confirmed it; nothing is written.
#[tokio::test]
async fn gandi_zone_not_found() {
    let (mock, client) = setup().await;
    let zone = dn("missing.example.net");
    let name = dn("_acme-challenge.missing.example.net");
    let set = RrSet::new(
        name.clone(),
        RecordType::TXT,
        None,
        [txt("v").to_data().unwrap()],
    )
    .unwrap();
    let errors = [
        client
            .add_txt_value(&zone, &name, &txt("v"), None)
            .await
            .unwrap_err(),
        client
            .remove_txt_value(&zone, &name, &txt("v"))
            .await
            .unwrap_err(),
        client.list_rrsets(&zone).await.unwrap_err(),
        client
            .get_rrset(&zone, &name, RecordType::TXT)
            .await
            .unwrap_err(),
        client
            .set_rrset(&zone, &set, Expect::Any)
            .await
            .unwrap_err(),
    ];
    for e in errors {
        assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    }
    assert_eq!(writes(&mock), 0);
}

// ---- Transport ---------------------------------------------------------------------------------

/// A throttled read is retried and succeeds. (A throttled write is reported, not repeated:
/// `gandi_writes_are_sent_once`.)
#[tokio::test]
async fn gandi_rate_limit() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).rate_limited("0"));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.log().count(Some("GET"), TXT_RRSET), 2);
}

/// A 5xx on a read is retried, then `Transient`.
#[tokio::test]
async fn gandi_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).times(3).status(503));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), TXT_RRSET), 3);
    assert_eq!(writes(&mock), 0);
}

/// Refusals: a 400 with the error body is `Rejected` with its message, a 403 is `Forbidden`, an
/// unexpected status is `Protocol`, an answer of an rrset other than the one asked for is
/// `Protocol`.
#[tokio::test]
async fn gandi_refusals_are_classified() {
    let (mock, client) = setup().await;
    mock.faults().push(
        Fault::on("GET", TXT_RRSET).respond(400, r#"{"code":400,"message":"name is not valid"}"#),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert!(
        matches!(
            e,
            Error::Rejected {
                status: Some(400),
                ..
            }
        ),
        "{e:?}"
    );
    assert!(e.to_string().contains("name is not valid"), "{e}");
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).respond(403, r#"{"message":"no access"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).respond(418, "teapot"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().push(Fault::on("GET", TXT_RRSET).respond(
        200,
        r#"{"rrset_name":"other","rrset_type":"TXT","rrset_values":[]}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn gandi_from_json_builds_the_client() {
    let (mock, _) = setup().await;
    let settings = json!({ "base_url": mock.base_url(), "ttl": 600 }).to_string();
    let credentials = format!(r#"{{"personal_access_token":"{TOKEN}"}}"#);
    let client = AnyProvider::from_json(
        ProviderId::Gandi,
        &settings,
        &SecretString::from(credentials.clone()),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Gandi);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        mock.control().rrset(ZONE, RR, "TXT").unwrap().ttl,
        Some(600)
    );
    // A minimal configuration: the credentials alone.
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = AnyProvider::from_json(
        ProviderId::Gandi,
        "{}",
        &SecretString::from(credentials),
        &ctx,
    )
    .unwrap();
    assert!(format!("{client:?}").contains("https://api.gandi.net/v5/livedns"));
}

/// Configuration errors name the key and never the value.
#[test]
fn gandi_config_errors_name_no_value() {
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let canary = "canary-Value-9d1e";
    let token = json!({ "personal_access_token": canary });
    for (settings, credentials, key) in [
        (json!({"ttl": 0}), token.clone(), "ttl"),
        (json!({"ttl": 299}), token.clone(), "ttl"),
        (json!({"ttl": 2_592_001}), token.clone(), "ttl"),
        (json!({"ttl": "provider_default"}), token.clone(), "ttl"),
        (
            json!({"base_url": format!("https://user:{canary}@example.net/v5/livedns")}),
            token.clone(),
            "base_url",
        ),
        (
            json!({"sharing_id": format!("{canary}/x")}),
            token.clone(),
            "sharing_id",
        ),
        (json!({"sharing_id": ""}), token.clone(), "sharing_id"),
        (
            json!({}),
            json!({"personal_access_token": "  "}),
            "personal_access_token",
        ),
        (
            json!({}),
            json!({"api_key": canary}),
            "personal_access_token",
        ),
        (json!({"zz": canary}), token.clone(), "line"),
    ] {
        let e = AnyProvider::from_json(
            ProviderId::Gandi,
            &settings.to_string(),
            &SecretString::from(credentials.to_string()),
            &ctx,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{settings}");
        let text = format!("{e} | {e:?}");
        assert!(text.contains(key), "{settings}: {text}");
        assert!(!text.contains(canary), "{settings}: {text}");
    }
    let e = AnyProvider::from_json(
        ProviderId::Gandi,
        "{}",
        &SecretString::from(json!({ "personal_access_token": format!("{canary}\nx") }).to_string()),
        &ctx,
    )
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
    assert!(!format!("{e} | {e:?}").contains(canary));
}

// ---- Record level ------------------------------------------------------------------------------

/// Every record type of the capabilities is written in its documented form, read back
/// canonical, and an identical repeat is `Unchanged` without a write; a change is one `PUT`
/// carrying the values and the TTL.
#[tokio::test]
async fn gandi_record_round_trips() {
    let (mock, client) = setup().await;
    for (owner, rr, rtype, texts) in [
        (
            "a.example.org",
            "a",
            RecordType::A,
            vec!["192.0.2.1", "192.0.2.2"],
        ),
        ("a.example.org", "a", RecordType::AAAA, vec!["2001:db8::1"]),
        (
            "alias.example.org",
            "alias",
            RecordType::CNAME,
            vec!["target.example.net."],
        ),
        (
            "example.org",
            "@",
            RecordType::MX,
            vec!["10 mail.example.org.", "20 mx2.example.net."],
        ),
        (
            "sub.example.org",
            "sub",
            RecordType::NS,
            vec!["ns1.example.net.", "ns2.example.net."],
        ),
        (
            "_sip._tcp.example.org",
            "_sip._tcp",
            RecordType::SRV,
            vec!["10 20 5060 sip.example.org."],
        ),
        (
            "t.example.org",
            "t",
            RecordType::TXT,
            vec!["\"v=spf1 include:_mailcust.gandi.net ?all\"", "\"plain\""],
        ),
    ] {
        let set = rrset(owner, rtype, None, &texts);
        assert_eq!(
            client
                .set_rrset(&zone(), &set, Expect::Absent)
                .await
                .unwrap(),
            SetOutcome::Created,
            "{rtype}"
        );
        let stored = mock.control().rrset(ZONE, rr, &rtype.to_string()).unwrap();
        // The values of a set travel in the set's (sorted) order.
        let mut sent = stored.values.clone();
        sent.sort();
        let mut expected = texts.clone();
        expected.sort();
        assert_eq!(sent, expected, "{rtype}");
        assert_eq!(stored.ttl, Some(300), "{rtype}");
        let read = client
            .get_rrset(&zone(), &dn(owner), rtype)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, rrset(owner, rtype, Some(300), &texts), "{rtype}");
        let before = writes(&mock);
        assert_eq!(
            client
                .set_rrset(&zone(), &read, Expect::Matches(&read))
                .await
                .unwrap(),
            SetOutcome::Unchanged,
            "{rtype}"
        );
        assert_eq!(writes(&mock), before, "{rtype}");
    }
    let changed = rrset("a.example.org", RecordType::A, Some(900), &["192.0.2.3"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &changed, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let put = mock.log().matching(Some("PUT"), A_RRSET).pop().unwrap();
    assert_eq!(put.path, "/v5/livedns/domains/example.org/records/a/A");
    assert_eq!(
        put.body_json().unwrap(),
        json!({ "rrset_values": ["192.0.2.3"], "rrset_ttl": 900 })
    );
    assert_eq!(
        client
            .delete_rrset(
                &zone(),
                &dn("a.example.org"),
                RecordType::A,
                Expect::Matches(&changed)
            )
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn("a.example.org"), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
    assert!(mock.control().rrset(ZONE, "a", "A").is_none());
}

/// What the client reads as non-canonical (a name without the trailing dot) is written back
/// exactly as read when a set keeps it; it cannot be introduced. Data whose encoding no source
/// establishes is refused after the read with nothing written: a TXT value with a quote, one
/// over 255 octets, a null MX.
#[tokio::test]
async fn gandi_escapes_and_non_canonical_data() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZONE, "@", "MX", Some(600), &["10 mail.example.org"]);
    let listed = client
        .get_rrset(&zone(), &zone(), RecordType::MX)
        .await
        .unwrap()
        .unwrap();
    assert!(!listed.records()[0].is_canonical());
    // The set as read, with a value added: the odd value travels back as it was.
    let mut records = listed.records().to_vec();
    records.push(rd(RecordType::MX, "20 mx2.example.net."));
    let grown = RrSet::new(zone(), RecordType::MX, None, records).unwrap();
    assert_eq!(
        client
            .set_rrset(&zone(), &grown, Expect::Matches(&listed))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        control.values(ZONE, "@", "MX"),
        ["10 mail.example.org", "20 mx2.example.net."]
    );
    assert_eq!(control.rrset(ZONE, "@", "MX").unwrap().ttl, Some(600));

    let before = writes(&mock);
    let long = format!("\"{}\"", "x".repeat(256));
    for set in [
        rrset(REC, RecordType::TXT, None, &["\"quo\\\"te\""]),
        rrset(REC, RecordType::TXT, None, &[long.as_str()]),
        rrset(REC, RecordType::MX, None, &["0 ."]),
        rrset(REC, RecordType::CNAME, None, &["we\\.ird.example.org."]),
    ] {
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{set:?}: {e:?}");
    }
    // Non-canonical data the rrset at the provider does not hold cannot be introduced.
    let elsewhere = RrSet::new(dn(REC), RecordType::MX, None, listed.records().to_vec()).unwrap();
    let e = client
        .set_rrset(&zone(), &elsewhere, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), before);

    // A foreign TXT value with an escape is kept by a value-level add.
    control.insert_rrset(ZONE, RR, "TXT", Some(300), &["\"say \\\"hi\\\"\""]);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    assert_eq!(txt_values(&mock), ["\"say \\\"hi\\\"\"", &q("ours")]);
}

/// An rrset read without `rrset_ttl` reads with no TTL stated; a write that does not ask for one
/// sends the `ttl` setting (the client always sends a TTL).
#[tokio::test]
async fn gandi_record_ttl() {
    let (mock, client) = setup().await;
    mock.control()
        .insert_rrset(ZONE, REC_RR, "A", None, &["192.0.2.1"]);
    let read = client
        .get_rrset(&zone(), &dn(REC), RecordType::A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.ttl(), None);
    client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.1", "192.0.2.2"]),
            Expect::Matches(&read),
        )
        .await
        .unwrap();
    assert_eq!(last_body(&mock, "PUT", A_RRSET)["rrset_ttl"], 300);
    // The bounds of the reference.
    for (ttl, ok) in [
        (300, true),
        (2_592_000, true),
        (299, false),
        (2_592_001, false),
    ] {
        let result = client
            .set_rrset(
                &zone(),
                &rrset(REC, RecordType::A, Some(ttl), &["192.0.2.1"]),
                Expect::Any,
            )
            .await;
        assert_eq!(result.is_ok(), ok, "{ttl}: {result:?}");
    }
}

/// Two record-level writes to one name from clients sharing a `Context`, the first create
/// delayed: the second waits, reads the created set and replaces it.
#[tokio::test]
async fn gandi_concurrent_sets_are_serialized() {
    let mock = GandiMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, TOKEN, &ctx);
    let b = client_with(&mock, TOKEN, &ctx);
    mock.faults()
        .push(Fault::on("POST", A_RRSET).delay(Duration::from_millis(300)));
    let first = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    let second = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    let zone = zone();
    let (ra, rb) = tokio::join!(
        a.set_rrset(&zone, &first, Expect::Any),
        b.set_rrset(&zone, &second, Expect::Any),
    );
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [SetOutcome::Created, SetOutcome::Replaced]);
    assert_eq!(mock.log().count(Some("POST"), A_RRSET), 1);
}

// ---- The value-level change where the reference is silent -------------------------------------

/// The `PATCH` carries the TTL the read stated, for an add and for a remove; when the read stated
/// none, it carries none.
#[tokio::test]
async fn gandi_patch_carries_the_ttl_read() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZONE, RR, "TXT", Some(7200), &["\"foreign\""]);
    add(&client, "ours").await.unwrap();
    assert_eq!(last_body(&mock, "PATCH", TXT_RRSET)["rrset_ttl"], 7200);
    remove(&client, "ours").await.unwrap();
    assert_eq!(last_body(&mock, "PATCH", TXT_RRSET)["rrset_ttl"], 7200);

    control.insert_rrset(ZONE, RR, "TXT", None, &["\"foreign\""]);
    add(&client, "ours").await.unwrap();
    assert_eq!(
        last_body(&mock, "PATCH", TXT_RRSET),
        json!({ "add_rrset_values": [q("ours")] })
    );
}

/// Under every reading of the `PATCH` the documentation allows, an add and a remove next to a
/// foreign value leave the foreign value and the rrset's TTL as they were.
#[tokio::test]
async fn gandi_patch_readings_keep_foreign_values_and_the_ttl() {
    for reading in [
        PatchReading::Lenient,
        PatchReading::TtlReset,
        PatchReading::DuplicateAddRefused,
        PatchReading::AbsentRemoveRefused,
        PatchReading::MissingCreated,
    ] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.set_patch(reading);
        control.insert_rrset(ZONE, RR, "TXT", Some(600), &["\"foreign\"", "bare"]);
        let original = control.rrset(ZONE, RR, "TXT").unwrap();
        assert_eq!(
            add(&client, "ours").await.unwrap(),
            AddOutcome::Appended,
            "{reading:?}"
        );
        assert_eq!(
            control.rrset(ZONE, RR, "TXT").unwrap().ttl,
            Some(600),
            "{reading:?}"
        );
        assert_eq!(
            remove(&client, "ours").await.unwrap(),
            RemoveOutcome::Removed,
            "{reading:?}"
        );
        assert_eq!(
            control.rrset(ZONE, RR, "TXT").unwrap(),
            original,
            "{reading:?}"
        );
    }
}

/// When another writer changes the rrset between the read and the `PATCH`, the client either
/// ends in the right state or returns the provider's refusal: it never removes or overwrites
/// another value, and never reports a change that did not happen.
#[tokio::test]
async fn gandi_patch_races_fail_safely() {
    // A duplicate add: the value arrived meanwhile.
    for (reading, expect_ok) in [
        (PatchReading::Lenient, true),
        (PatchReading::DuplicateAddRefused, false),
    ] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.set_patch(reading);
        control.insert_rrset(ZONE, RR, "TXT", Some(600), &["\"foreign\""]);
        let hook = control.clone();
        mock.faults()
            .push(Fault::on("PATCH", TXT_RRSET).run(move || {
                hook.edit_rrset(ZONE, RR, "TXT", |rrset| rrset.values.push(q("ours")));
            }));
        let result = add(&client, "ours").await;
        match result {
            Ok(outcome) => {
                assert!(expect_ok, "{reading:?}");
                assert_eq!(outcome, AddOutcome::Appended);
            }
            Err(e) => {
                assert!(!expect_ok, "{reading:?}: {e:?}");
                assert_eq!(e.kind(), ErrorKind::Rejected, "{reading:?}: {e:?}");
            }
        }
        assert_eq!(txt_values(&mock), [q("foreign"), q("ours")], "{reading:?}");
        assert_eq!(control.rrset(ZONE, RR, "TXT").unwrap().ttl, Some(600));
        assert_eq!(
            add(&client, "ours").await.unwrap(),
            AddOutcome::AlreadyPresent
        );
    }
    // An absent remove: the value left meanwhile.
    for (reading, expect_ok) in [
        (PatchReading::Lenient, true),
        (PatchReading::AbsentRemoveRefused, false),
    ] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.set_patch(reading);
        control.insert_rrset(ZONE, RR, "TXT", Some(600), &["\"foreign\"", "\"ours\""]);
        let hook = control.clone();
        mock.faults()
            .push(Fault::on("PATCH", TXT_RRSET).run(move || {
                hook.edit_rrset(ZONE, RR, "TXT", |rrset| {
                    rrset.values.retain(|v| v != "\"ours\"")
                });
            }));
        let result = remove(&client, "ours").await;
        assert_eq!(result.is_ok(), expect_ok, "{reading:?}: {result:?}");
        if let Err(e) = result {
            assert_eq!(e.kind(), ErrorKind::Rejected, "{reading:?}: {e:?}");
        }
        assert_eq!(txt_values(&mock), [q("foreign")], "{reading:?}");
        assert_eq!(
            remove(&client, "ours").await.unwrap(),
            RemoveOutcome::NotPresent
        );
    }
    // A missing rrset: deleted meanwhile by its owner. A server that answers `404` gives
    // `Conflict`; one that creates the rrset holds our value afterwards, with the TTL sent.
    for reading in [PatchReading::Lenient, PatchReading::MissingCreated] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.set_patch(reading);
        control.insert_rrset(ZONE, RR, "TXT", Some(600), &["\"foreign\""]);
        let hook = control.clone();
        mock.faults()
            .push(Fault::on("PATCH", TXT_RRSET).run(move || hook.delete_rrset(ZONE, RR, "TXT")));
        let result = add(&client, "ours").await;
        match reading {
            PatchReading::Lenient => {
                assert_eq!(result.unwrap_err().kind(), ErrorKind::Conflict);
                assert!(control.rrsets().is_empty());
                assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Created);
            }
            _ => {
                assert_eq!(result.unwrap(), AddOutcome::Appended);
                let rrset = control.rrset(ZONE, RR, "TXT").unwrap();
                assert_eq!(rrset.values, [q("ours")]);
                assert_eq!(rrset.ttl, Some(600));
            }
        }
    }
}

/// A `200` to a `PATCH` is a success only when the rrset it states shows the change; an answer
/// without the values is confirmed by a read. A create answered with a status the reference does
/// not give for it is `Protocol`.
#[tokio::test]
async fn gandi_write_answers_are_checked() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZONE, RR, "TXT", Some(300), &["\"foreign\""]);
    // The answer states an rrset without the value added: nothing is claimed.
    mock.faults().push(Fault::on("PATCH", TXT_RRSET).respond(
        200,
        r#"{"rrset_name":"_acme-challenge","rrset_type":"TXT","rrset_values":["\"foreign\""]}"#,
    ));
    let e = add(&client, "ours").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    // A respelled value counts.
    mock.faults().push(
        Fault::on("PATCH", TXT_RRSET).respond(200, r#"{"rrset_values":["\"foreign\"","ours"]}"#),
    );
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    assert_eq!(txt_values(&mock), [q("foreign")]);
    // An answer without values is confirmed by a read: the value is not there.
    let reads = mock.log().count(Some("GET"), TXT_RRSET);
    mock.faults()
        .push(Fault::on("PATCH", TXT_RRSET).respond(200, r#"{"message":"ok"}"#));
    let e = add(&client, "ours").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), TXT_RRSET), reads + 2);
    // Without a fault the change is applied and the answer shows it.
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);

    // A remove whose answer still holds the value.
    mock.faults().push(
        Fault::on("PATCH", TXT_RRSET)
            .respond(200, r#"{"rrset_values":["\"foreign\"","\"ours\""]}"#),
    );
    let e = remove(&client, "ours").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    // An answer without values, the value gone after all: a success after the read.
    let hook = control.clone();
    mock.faults().push(
        Fault::on("PATCH", TXT_RRSET)
            .run(move || {
                hook.edit_rrset(ZONE, RR, "TXT", |rrset| {
                    rrset.values.retain(|v| v != "\"ours\"")
                });
            })
            .respond(200, "{}"),
    );
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(txt_values(&mock), [q("foreign")]);

    // A create answered `202`: not a documented "created".
    mock.faults()
        .push(Fault::on("POST", A_RRSET).respond(202, r#"{"message":"accepted"}"#));
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.1"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
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
    let settings = live_env("ZONEWRIGHT_LIVE_GANDI_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_GANDI_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_GANDI_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = AnyProvider::from_json(
        ProviderId::Gandi,
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
async fn live_gandi_add_and_remove() {
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
                client.remove_txt_value(&zone, &name, a).await.unwrap(),
                RemoveOutcome::NotPresent
            );
            assert_eq!(
                client.remove_txt_value(&zone, &name, b).await.unwrap(),
                RemoveOutcome::RrsetDeleted
            );
            assert_eq!(
                client
                    .get_rrset(&zone, &name, RecordType::TXT)
                    .await
                    .unwrap(),
                None
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

/// A record-level round trip on an A rrset under a generated label (documentation addresses of
/// RFC 5737): create, read, replace with new records and a new TTL, unchanged repeat, list,
/// delete. The cleanup deletes that rrset, the only one the test wrote, also when the body
/// failed.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_gandi_record_round_trip() {
    let (client, zone) = live_client();
    let tag = random_u64();
    let rec_name = zone.prepend(&format!("zw-live-{tag:016x}")).unwrap();
    let records = {
        let (client, zone, rec_name) = (client.clone(), zone.clone(), rec_name.clone());
        tokio::spawn(async move {
            let first = RrSet::new(
                rec_name.clone(),
                RecordType::A,
                Some(RrsetTtl::from_secs(300).unwrap()),
                [rd(RecordType::A, "192.0.2.10")],
            )
            .unwrap();
            assert_eq!(
                client
                    .set_rrset(&zone, &first, Expect::Absent)
                    .await
                    .unwrap(),
                SetOutcome::Created
            );
            let read = client
                .get_rrset(&zone, &rec_name, RecordType::A)
                .await
                .unwrap();
            assert_eq!(read.as_ref(), Some(&first));
            let second = RrSet::new(
                rec_name.clone(),
                RecordType::A,
                Some(RrsetTtl::from_secs(600).unwrap()),
                [
                    rd(RecordType::A, "192.0.2.10"),
                    rd(RecordType::A, "192.0.2.11"),
                ],
            )
            .unwrap();
            assert_eq!(
                client
                    .set_rrset(&zone, &second, Expect::Matches(&first))
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                client
                    .set_rrset(&zone, &second, Expect::Matches(&second))
                    .await
                    .unwrap(),
                SetOutcome::Unchanged
            );
            let listing = client.list_rrsets(&zone).await.unwrap();
            assert!(listing.rrsets.contains(&second), "{listing:?}");
            assert_eq!(
                client
                    .delete_rrset(&zone, &rec_name, RecordType::A, Expect::Matches(&second))
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
        })
        .await
    };
    let cleanup = client
        .delete_rrset(&zone, &rec_name, RecordType::A, Expect::Any)
        .await;
    if let Err(e) = records {
        std::panic::resume_unwind(e.into_panic());
    }
    if let Err(e) = cleanup {
        panic!("cleanup failed: {e}");
    }
}

/// The live check of what the client assumes and no source settles. In the zone of
/// `ZONEWRIGHT_LIVE_GANDI_ZONE`, under owner names that start with the label prefix of
/// `ZONEWRIGHT_LIVE_GANDI_PREFIX` followed by a random tag, it creates, reads back and deletes:
///
/// - MX, NS (below the apex), SRV, CNAME and TXT sets: their value forms, each read back equal to
///   what was sent (canonical: names keep their trailing dot, TXT comes back as quoted text) and
///   repeated as `Unchanged`;
/// - an A set at a wildcard owner (`*` in the path as `%2A`);
/// - TXT values through the value operations: the create, a `PATCH` add with the TTL read (the
///   TTL must stay as it was, and the answer must state the rrset with the value), a `PATCH`
///   remove of one value, and a `PATCH` remove of the last value, which must leave no rrset;
/// - a set created by one client while another, on a separate `Context`, creates the same name
///   and type: the second create meets an existing rrset and must give `Created`, `Replaced` or
///   `Conflict`, never `Rejected`;
/// - `check` of the zone and of a name that is not a domain of the account: the domain read
///   answers a missing domain with `404` (`found == false`), not an error;
/// - `get_rrset` of an rrset that does not exist in an existing zone answers `None` (rrset `404`
///   followed by the domain read), and of a zone that does not exist `ZoneNotFound`;
/// - every set it created is found by `list_rrsets`, which pages by `page` until an empty page.
///
/// Everything it created is deleted afterwards by name and type, also when a step failed; it
/// touches nothing else.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn gandi_live_assumptions() {
    let (client, zone) = live_client();
    let prefix = live_env("ZONEWRIGHT_LIVE_GANDI_PREFIX");
    let tag = format!("{prefix}-{:016x}", random_u64());
    let base = zone.prepend(&tag).unwrap();
    let owner = |label: &str| base.prepend(label).unwrap();
    let wildcard = owner("*");
    let raced = owner("race");
    let values_name = owner("_values");
    let sets: Vec<RrSet> = vec![
        RrSet::new(
            base.clone(),
            RecordType::MX,
            None,
            [rd(RecordType::MX, &format!("10 mx.{base}"))],
        )
        .unwrap(),
        RrSet::new(
            owner("deleg"),
            RecordType::NS,
            None,
            [rd(RecordType::NS, "ns1.example.net.")],
        )
        .unwrap(),
        RrSet::new(
            owner("_sip._tcp"),
            RecordType::SRV,
            None,
            [rd(RecordType::SRV, &format!("10 20 5060 sip.{base}"))],
        )
        .unwrap(),
        RrSet::new(
            owner("alias"),
            RecordType::CNAME,
            None,
            [rd(RecordType::CNAME, &format!("target.{base}"))],
        )
        .unwrap(),
        RrSet::new(
            owner("txt"),
            RecordType::TXT,
            None,
            [rd(RecordType::TXT, "\"two words\"")],
        )
        .unwrap(),
        RrSet::new(
            wildcard.clone(),
            RecordType::A,
            None,
            [rd(RecordType::A, "192.0.2.20")],
        )
        .unwrap(),
    ];
    let mut created: Vec<(DomainName, RecordType)> =
        sets.iter().map(|s| (s.name().clone(), s.rtype())).collect();
    created.push((raced.clone(), RecordType::A));
    created.push((values_name.clone(), RecordType::TXT));
    let body = {
        let (client, zone, sets, raced, values_name) = (
            client.clone(),
            zone.clone(),
            sets.clone(),
            raced.clone(),
            values_name.clone(),
        );
        tokio::spawn(async move {
            let missing = dn(&format!("{}.invalid", random_u64()));
            let report = client.check([&zone, &missing]).await.unwrap();
            assert!(report.zones[0].found, "{report:?}");
            assert!(!report.zones[1].found, "{report:?}");
            let e = client
                .get_rrset(&missing, &missing, RecordType::A)
                .await
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::ZoneNotFound, "{e:?}");
            assert_eq!(
                client
                    .get_rrset(&zone, &owner_of(&zone, "absent"), RecordType::A)
                    .await
                    .unwrap(),
                None
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
                    client
                        .set_rrset(&zone, set, Expect::Matches(&read))
                        .await
                        .unwrap(),
                    SetOutcome::Unchanged,
                    "{} {}",
                    set.name(),
                    set.rtype()
                );
            }
            // The value-level calls: a create, an add that keeps the TTL, a remove of one value,
            // a remove of the last value that leaves no rrset.
            let (a, b) = (txt("zw-live-a"), txt("zw-live-b"));
            let ttl = RrsetTtl::from_secs(600).ok();
            assert_eq!(
                client
                    .add_txt_value(&zone, &values_name, &a, ttl)
                    .await
                    .unwrap(),
                AddOutcome::Created
            );
            assert_eq!(
                client
                    .add_txt_value(&zone, &values_name, &b, None)
                    .await
                    .unwrap(),
                AddOutcome::Appended
            );
            let read = client
                .get_rrset(&zone, &values_name, RecordType::TXT)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(read.ttl(), ttl, "the add changed the TTL");
            assert_eq!(read.records().len(), 2, "{read:?}");
            assert_eq!(
                client
                    .remove_txt_value(&zone, &values_name, &a)
                    .await
                    .unwrap(),
                RemoveOutcome::Removed
            );
            assert_eq!(
                client
                    .remove_txt_value(&zone, &values_name, &b)
                    .await
                    .unwrap(),
                RemoveOutcome::RrsetDeleted
            );
            assert_eq!(
                client
                    .get_rrset(&zone, &values_name, RecordType::TXT)
                    .await
                    .unwrap(),
                None
            );
            // Two creates of one name and type from clients that do not share a lock.
            let other_ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
            let other = AnyProvider::from_json(
                ProviderId::Gandi,
                &live_env("ZONEWRIGHT_LIVE_GANDI_SETTINGS"),
                &SecretString::from(live_env("ZONEWRIGHT_LIVE_GANDI_CREDENTIALS")),
                &other_ctx,
            )
            .unwrap();
            let first = RrSet::new(
                raced.clone(),
                RecordType::A,
                None,
                [rd(RecordType::A, "192.0.2.21")],
            )
            .unwrap();
            let second = RrSet::new(
                raced.clone(),
                RecordType::A,
                None,
                [rd(RecordType::A, "192.0.2.22")],
            )
            .unwrap();
            let (a, b) = tokio::join!(
                client.set_rrset(&zone, &first, Expect::Any),
                other.set_rrset(&zone, &second, Expect::Any),
            );
            for outcome in [a, b] {
                match outcome {
                    Ok(SetOutcome::Created | SetOutcome::Replaced) => {}
                    Err(e) => assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}"),
                    Ok(other) => panic!("unexpected outcome {other:?}"),
                }
            }
            let listing = client.list_rrsets(&zone).await.unwrap();
            for set in &sets {
                assert!(
                    listing
                        .rrsets
                        .iter()
                        .any(|l| l.name() == set.name() && l.rtype() == set.rtype()),
                    "{} {} is missing from the listing",
                    set.name(),
                    set.rtype()
                );
            }
        })
        .await
    };
    let mut cleanup = Vec::new();
    for (name, rtype) in &created {
        if let Err(e) = client.delete_rrset(&zone, name, *rtype, Expect::Any).await {
            cleanup.push(format!("{name} {rtype}: {e}"));
        }
    }
    if let Err(e) = body {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}

/// `label` below `zone`.
fn owner_of(zone: &DomainName, label: &str) -> DomainName {
    zone.prepend(&format!("zw-live-{label}-{:016x}", random_u64()))
        .unwrap()
}

// ---- Link to the DNS mock ----------------------------------------------------------------------

#[cfg(feature = "inspector")]
mod dns_link {
    use zonewright::{Expect, Provider, RecordType};
    use zonewright_mock::changes::ChangeSource;
    use zonewright_mock::dns::{DnsMock, Role};
    use zonewright_mock::link::{LinkOptions, link};

    use super::{NAME, add, rrset, setup};
    use crate::common::link::{ask, is_absent, rd, txt, txt_round_trip, values};

    /// A value written through the client is served over DNS, and gone when removed.
    #[tokio::test]
    async fn gandi_txt_value_is_served_over_dns() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        txt_round_trip(&mock, &client, &dns).await;
    }

    /// Names inside values are published fully qualified.
    #[tokio::test]
    async fn gandi_names_in_values_are_served_fully_qualified() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = link(&mock, &dns, LinkOptions::new());
        let zone = crate::common::dn("example.org");
        for set in [
            rrset(
                "alias.example.org",
                RecordType::CNAME,
                Some(300),
                &["target.example.net."],
            ),
            rrset(
                "example.org",
                RecordType::MX,
                Some(300),
                &["10 mail.example.org."],
            ),
        ] {
            client.set_rrset(&zone, &set, Expect::Any).await.unwrap();
        }
        link.settled().await;
        assert_eq!(link.skipped(), 0);
        for (name, rtype, text) in [
            (
                "alias.example.org",
                RecordType::CNAME,
                "target.example.net.",
            ),
            ("example.org", RecordType::MX, "10 mail.example.org."),
        ] {
            assert_eq!(
                values(ask(dns.addr(), name, rtype).await),
                [rd(rtype, text)],
                "{name} {rtype}"
            );
        }
        assert!(mock.published().zones.contains(&"example.org".to_owned()));
    }

    /// `reset` returns the mock to its seed: the record is gone from the mock and from DNS, the
    /// request log is empty, and the client works again.
    #[tokio::test]
    async fn gandi_reset_returns_the_mock_to_its_seed() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = link(&mock, &dns, LinkOptions::new());
        add(&client, "before-reset").await.unwrap();
        link.settled().await;
        assert_eq!(
            values(ask(dns.addr(), NAME, RecordType::TXT).await),
            [txt("before-reset")]
        );
        mock.control().reset();
        link.settled().await;
        assert!(mock.control().rrsets().is_empty());
        assert!(mock.log().is_empty());
        let answer = ask(dns.addr(), NAME, RecordType::TXT).await;
        assert!(is_absent(&answer), "{answer:?}");
        add(&client, "after-reset").await.unwrap();
        link.settled().await;
        assert_eq!(
            values(ask(dns.addr(), NAME, RecordType::TXT).await),
            [txt("after-reset")]
        );
    }
}
