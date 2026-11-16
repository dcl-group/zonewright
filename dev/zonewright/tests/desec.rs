//! Tests of the deSEC client (`desec`) against its mock (`zonewright_mock::desec`). No network;
//! fixtures are synthetic. The live tests at the end are `#[ignore]` and run only by the
//! maintainer.
#![cfg(feature = "desec")]
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
use zonewright::providers::desec::{Desec, DesecConfig, DesecCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl, SetOutcome,
    SkipReason, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::desec::{DesecMock, Paging, Seed};
use zonewright_mock::echo::{EchoServer, Echoed, Render};

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

assert_not_impl!(Desec: std::fmt::Display, serde::Serialize);
assert_not_impl!(DesecCredentials: std::fmt::Display, serde::Serialize);

// ---- Fixtures ----------------------------------------------------------------------------------

/// The token of the standard seed.
const TOKEN: &str = "test-only-token";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// The owner name the record-level tests write to.
const REC: &str = "rec.example.org";

/// Path patterns of the mock.
const DOMAINS: &str = "/api/v1/domains/";
const DOMAIN: &str = "/api/v1/domains/*/";
const RRSETS: &str = "/api/v1/domains/*/rrsets/";
const TXT_RRSET: &str = "/api/v1/domains/*/rrsets/*/TXT/";
const ANY_RRSET: &str = "/api/v1/domains/*/rrsets/*/*/";
const REC_A: &str = "/api/v1/domains/*/rrsets/rec/A/";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// The record content of a TXT value as the API holds it.
fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

fn client_at(base_url: String, token: &str, ctx: &Context) -> Desec {
    let mut config = DesecConfig::default();
    config.base_url = base_url;
    Desec::new(
        config,
        DesecCredentials::new(SecretString::from(token.to_owned())),
        ctx,
    )
    .unwrap()
}

fn client_with(mock: &DesecMock, token: &str, ctx: &Context) -> Desec {
    client_at(mock.base_url(), token, ctx)
}

async fn setup() -> (DesecMock, Desec) {
    let mock = DesecMock::start(Seed::standard()).await;
    let client = client_with(&mock, TOKEN, &context());
    (mock, client)
}

async fn add(client: &impl Provider, value: &str) -> Result<AddOutcome, Error> {
    client
        .add_txt_value(&zone(), &name(), &txt(value), None)
        .await
}

async fn remove(client: &impl Provider, value: &str) -> Result<RemoveOutcome, Error> {
    client.remove_txt_value(&zone(), &name(), &txt(value)).await
}

/// Number of write requests the mock received: creates, changes and deletes.
fn writes(mock: &DesecMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), RRSETS)
        + log.count(Some("PATCH"), ANY_RRSET)
        + log.count(Some("PUT"), ANY_RRSET)
        + log.count(Some("DELETE"), ANY_RRSET)
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

/// The TXT contents the mock holds at [`NAME`].
fn stored_txt(mock: &DesecMock) -> Vec<String> {
    mock.control().records(NAME, "TXT")
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

fn ok(body: Value) -> axum::response::Response {
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// A renderer that answers like the API what `answered` says, and every other request with
/// `errors`.
fn answering(errors: Render, existing: Existing, answered: Answered) -> Render {
    Arc::new(move |e: &Echoed| {
        if answered == Answered::Nothing || e.method != Method::GET {
            return errors(e);
        }
        let path = e.path.trim_start_matches('/').trim_end_matches('/');
        let segments: Vec<&str> = path.split('/').collect();
        if answered == Answered::Probe && segments.len() != 3 {
            return errors(e);
        }
        match segments.as_slice() {
            ["api", "v1", "domains"] => ok(json!([{"name": "example.org", "minimum_ttl": 3600}])),
            ["api", "v1", "domains", zone] => ok(json!({"name": zone, "minimum_ttl": 3600})),
            ["api", "v1", "domains", _, "rrsets", subname, rtype] => {
                let value = match existing {
                    Existing::Nothing => {
                        return (
                            StatusCode::NOT_FOUND,
                            axum::Json(json!({"detail": "Not found."})),
                        )
                            .into_response();
                    }
                    Existing::Foreign => "\"foreign\"",
                    Existing::Ours => "\"v1\"",
                };
                ok(json!({
                    "subname": subname, "type": rtype, "ttl": 3600, "records": [value]
                }))
            }
            _ => errors(e),
        }
    })
}

fn echo_client(echo: &EchoServer, ctx: &Context) -> Desec {
    client_at(echo.url("/api/v1"), CANARY_TOKEN, ctx)
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
async fn echo_round(label: &str, client: &Desec, op: Op) {
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

/// `check` and every kind of request against an echo that repeats the token, for every dialect:
/// the probe, the domain read, the rrset read, the listing, the create (and the reads that follow
/// a refused create), the change and the delete. Reads are not given a 5xx: the transport
/// repeats them, which would add seconds per dialect without coverage.
#[tokio::test]
async fn desec_secret_echo() {
    let ctx = context();
    let echo = EchoServer::start(200).await;
    for dialect in dialects() {
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} probe", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status).render_under(
                "/api/v1",
                answering(dialect.render.clone(), Existing::Nothing, Answered::Nothing),
            ));
            let client = echo_client(&echo, &ctx);
            echo_round(&label, &client, Op::Add).await;
            assert!(
                echo.log().count(Some("GET"), DOMAINS) > 0,
                "{label}: the probe did not reach the echo"
            );
        }
        for status in [400, 401, 403, 422] {
            let label = format!("{} {:?} {status} domain", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status).render_under(
                "/api/v1",
                answering(dialect.render.clone(), Existing::Nothing, Answered::Probe),
            ));
            let client = echo_client(&echo, &ctx);
            let e = client.check(&[zone()]).await.unwrap_err();
            let text = format!("{e} | {e:?} | {client:?}");
            assert!(text.contains(REDACTED), "{label}: {text}");
            assert_clean(&label, &text, &[CANARY_TOKEN]);
            assert_eq!(echo.log().count(Some("GET"), DOMAIN), 1, "{label}");
        }
        for (existing, op, statuses) in [
            (
                Existing::Nothing,
                Op::Add,
                [400, 401, 403, 409, 422, 500].as_slice(),
            ),
            (
                Existing::Foreign,
                Op::Add,
                [400, 401, 403, 409, 422, 500].as_slice(),
            ),
            (
                Existing::Ours,
                Op::Remove,
                [400, 401, 403, 422, 500].as_slice(),
            ),
            (Existing::Nothing, Op::List, [400, 401, 403, 422].as_slice()),
            (
                Existing::Nothing,
                Op::Set,
                [400, 401, 403, 409, 422, 500].as_slice(),
            ),
            (
                Existing::Foreign,
                Op::Set,
                [400, 401, 403, 409, 422, 500].as_slice(),
            ),
            (
                Existing::Foreign,
                Op::Delete,
                [400, 401, 403, 422, 500].as_slice(),
            ),
        ] {
            for &status in statuses {
                let label = format!(
                    "{} {:?} {status} {op:?} {existing:?}",
                    dialect.name, dialect.spelling
                );
                echo.reset(dialect.echo(status).render_under(
                    "/api/v1",
                    answering(dialect.render.clone(), existing, Answered::Reads),
                ));
                let client = echo_client(&echo, &ctx);
                echo_round(&label, &client, op).await;
                let (method, path) = match (op, existing) {
                    (Op::Add | Op::Set, Existing::Nothing) => ("POST", RRSETS),
                    (Op::Add | Op::Set, _) => ("PATCH", ANY_RRSET),
                    (Op::Remove | Op::Delete, _) => ("DELETE", ANY_RRSET),
                    (Op::List, _) => ("GET", RRSETS),
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

/// A `TRACE` capture over successes, a 401, a 500 and a wrong token: the transport's events are
/// there, and no canary is.
#[tokio::test(flavor = "current_thread")]
async fn desec_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.tokens = vec![CANARY_TOKEN.into()];
    let mock = DesecMock::start(seed).await;
    let client = client_with(&mock, CANARY_TOKEN, &context());
    let mut texts = Vec::new();

    client.check(&[zone()]).await.unwrap();
    add(&client, "v1").await.unwrap();
    add(&client, "v2").await.unwrap();
    remove(&client, "v1").await.unwrap();
    let set = rrset(REC, RecordType::A, Some(3600), &["192.0.2.1"]);
    client
        .set_rrset(&zone(), &set, Expect::Absent)
        .await
        .unwrap();
    client.list_rrsets(&zone()).await.unwrap();
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
        assert_clean("desec logs and errors", text, &[CANARY_TOKEN, CANARY_KEY]);
    }
}

/// The token travels in `Authorization: Token <token>`, and only there: never in a path or a
/// query.
#[tokio::test]
async fn desec_token_is_sent_in_the_authorization_header() {
    let (mock, client) = setup().await;
    client.check(&[zone()]).await.unwrap();
    add(&client, "v1").await.unwrap();
    client.list_rrsets(&zone()).await.unwrap();
    let entries = mock.log().entries();
    assert!(!entries.is_empty());
    for entry in entries {
        assert_eq!(
            entry.header("authorization"),
            Some("Token test-only-token"),
            "{entry:?}"
        );
        assert!(!entry.path.contains(TOKEN));
        assert!(!entry.query.as_deref().unwrap_or("").contains(TOKEN));
        assert!(!entry.body_str().contains(TOKEN));
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request, by every mutating operation.
#[tokio::test]
async fn desec_name_outside_zone_sends_nothing() {
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

/// `Created`, `Appended` for a second value, then `AlreadyPresent` without a write.
#[tokio::test]
async fn desec_add_is_idempotent() {
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
    assert_eq!(stored_txt(&mock), [quoted("AAA"), quoted("BBB")]);
}

/// Removing an absent value next to foreign ones writes nothing; adding and removing our value
/// leaves the foreign records (one with two strings, one the client does not read) and the TTL
/// as they were. A single foreign value is never a reason to delete the rrset.
#[tokio::test]
async fn desec_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let foreign = ["\"foreign\"", "\"two\" \"strings\"", "unquoted-foreign"];
    control.insert_rrset("example.org", NAME, "TXT", 7200, &foreign);
    let original = control.rrset(NAME, "TXT").unwrap();

    let ours = txt("ours");
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &ours)
            .await
            .unwrap(),
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
    let during = control.rrset(NAME, "TXT").unwrap();
    assert_eq!(during.ttl, 7200);
    let mut expected: Vec<String> = foreign.iter().map(|s| (*s).to_owned()).collect();
    expected.push(quoted("ours"));
    assert_eq!(during.records, expected);
    let patch = mock.log().matching(Some("PATCH"), TXT_RRSET).pop().unwrap();
    assert_eq!(
        patch.body_json().unwrap(),
        json!({"ttl": 7200, "records": expected})
    );
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &ours)
            .await
            .unwrap(),
        RemoveOutcome::Removed
    );
    let after = control.rrset(NAME, "TXT").unwrap();
    assert_eq!(after.records, original.records);
    assert_eq!(after.ttl, original.ttl);
    // "two" + "strings" is the value "twostrings", not ours either.
    assert_eq!(
        remove(&client, "two").await.unwrap(),
        RemoveOutcome::NotPresent
    );

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_rrset("example.org", other, "TXT", 3600, &["\"foreign\""]);
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &ours)
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(control.records(other, "TXT"), ["\"foreign\""]);
}

#[tokio::test]
async fn desec_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().rrset(NAME, "TXT").is_none());
    assert_eq!(mock.log().count(Some("DELETE"), TXT_RRSET), 1);
    assert_eq!(mock.log().count(Some("PATCH"), TXT_RRSET), 0);
}

#[tokio::test]
async fn desec_remove_is_idempotent() {
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
    assert!(mock.control().rrset(NAME, "TXT").is_none());
}

/// Two clients sharing a `Context` add to one name at once, the first create delayed: both
/// values end up in the rrset. Without the name lock both would read "no rrset" and the second
/// create would be refused.
#[tokio::test]
async fn desec_concurrent_adds_are_serialized() {
    let mock = DesecMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, TOKEN, &ctx);
    let b = client_with(&mock, TOKEN, &ctx);
    mock.faults()
        .push(Fault::on("POST", RRSETS).delay(Duration::from_millis(300)));
    let (zone, name, aaa, bbb) = (zone(), name(), txt("AAA"), txt("BBB"));
    let (ra, rb) = tokio::join!(
        a.add_txt_value(&zone, &name, &aaa, None),
        b.add_txt_value(&zone, &name, &bbb, None),
    );
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [AddOutcome::Appended, AddOutcome::Created]);
    let mut values = stored_txt(&mock);
    values.sort();
    assert_eq!(values, [quoted("AAA"), quoted("BBB")]);
}

/// Every write is sent once: a 502, a 429 and a 401 on the create, the change and the delete are
/// the operation's error, with exactly one such request each; the repeat starts with a read and
/// converges. A repeated delete could remove a value another writer added after the read.
#[tokio::test]
async fn desec_writes_are_sent_once() {
    let (mock, client) = setup().await;
    for (method, path, op) in [
        ("POST", RRSETS, "add"),
        ("PATCH", TXT_RRSET, "add"),
        ("DELETE", TXT_RRSET, "remove"),
    ] {
        if method == "PATCH" {
            add(&client, "AAA").await.unwrap();
        }
        let mut sent = mock.log().count(Some(method), path);
        for (fault, kind) in [
            (Fault::on(method, path).status(502), ErrorKind::Transient),
            (
                Fault::on(method, path).rate_limited("1"),
                ErrorKind::RateLimited,
            ),
            (Fault::on(method, path).status(401), ErrorKind::Auth),
        ] {
            mock.faults().push(fault);
            let value = if method == "DELETE" { "AAA" } else { "BBB" };
            let e = match op {
                "add" => add(&client, value).await.map(drop),
                _ => remove(&client, value).await.map(drop),
            }
            .unwrap_err();
            assert_eq!(e.kind(), kind, "{method}: {e:?}");
            sent += 1;
            assert_eq!(mock.log().count(Some(method), path), sent, "{method}");
        }
    }
    assert_eq!(stored_txt(&mock), [quoted("AAA")]);

    // The delete is answered 502 and not applied; meanwhile another writer adds a value. The
    // repeat reads the new state and removes only our value.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("DELETE", TXT_RRSET)
            .run(move || {
                hook.edit_rrset(NAME, "TXT", |rrset| rrset.records.push(quoted("foreign")));
            })
            .status(502),
    );
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(stored_txt(&mock), [quoted("AAA"), quoted("foreign")]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(stored_txt(&mock), [quoted("foreign")]);

    // The record level: a create, a change and a delete are each sent once for a 502, a 429 and
    // a 401, and each failed write leaves the rrset as it was.
    let set = |texts: &[&str]| rrset(REC, RecordType::A, None, texts);
    let creates = || {
        mock.log()
            .matching(Some("POST"), RRSETS)
            .iter()
            .filter(|r| r.body_str().contains("\"A\""))
            .count()
    };
    for status in [502, 429, 401] {
        let control = mock.control();
        control.delete_rrset(REC, "A");
        let expected = match status {
            429 => ErrorKind::RateLimited,
            401 => ErrorKind::Auth,
            _ => ErrorKind::Transient,
        };
        let inject = |method: &str, path: &str| {
            if status == 429 {
                mock.faults()
                    .push(Fault::on(method, path).rate_limited("1"));
            } else {
                mock.faults().push(Fault::on(method, path).status(status));
            }
        };
        let posts = creates();
        inject("POST", RRSETS);
        let e = client
            .set_rrset(&zone(), &set(&["192.0.2.1"]), Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected, "{status}: {e:?}");
        assert_eq!(creates(), posts + 1);
        assert!(control.rrset(REC, "A").is_none());
        client
            .set_rrset(&zone(), &set(&["192.0.2.1"]), Expect::Absent)
            .await
            .unwrap();

        let patches = mock.log().count(Some("PATCH"), REC_A);
        inject("PATCH", REC_A);
        let e = client
            .set_rrset(&zone(), &set(&["192.0.2.2"]), Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected, "{status}: {e:?}");
        assert_eq!(mock.log().count(Some("PATCH"), REC_A), patches + 1);
        assert_eq!(control.records(REC, "A"), ["192.0.2.1"]);

        let deletes = mock.log().count(Some("DELETE"), REC_A);
        inject("DELETE", REC_A);
        let e = client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected, "{status}: {e:?}");
        assert_eq!(mock.log().count(Some("DELETE"), REC_A), deletes + 1);
        assert_eq!(control.records(REC, "A"), ["192.0.2.1"]);
    }
}

/// `Expect::Absent` on an existing set and `Expect::Matches` on a changed one are
/// `PreconditionFailed` and write nothing; `Expect::Absent` on a delete is `InvalidInput`.
#[tokio::test]
async fn desec_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset("example.org", REC, "A", 7200, &["192.0.2.1"]);
    let current = rrset(REC, RecordType::A, Some(7200), &["192.0.2.1"]);
    let stale = rrset(REC, RecordType::A, Some(7200), &["192.0.2.9"]);
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Absent)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Matches(&stale))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Matches(&stale))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    let other_ttl = rrset(REC, RecordType::A, Some(3600), &["192.0.2.1"]);
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
    control.delete_rrset(REC, "A");
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Matches(&current))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    control.insert_rrset("example.org", REC, "A", 7200, &["192.0.2.1"]);
    assert_eq!(writes(&mock), 0);
    assert_eq!(control.records(REC, "A"), ["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&current))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(control.records(REC, "A"), ["192.0.2.2"]);
    assert_eq!(control.rrset(REC, "A").unwrap().ttl, 7200);
}

/// The listing holds every rrset of the zone, the apex NS included, values canonical where the
/// content has the documented form; what the model cannot hold is skipped: an unknown type, a
/// name the crate cannot hold, two records of a singleton type. A type outside the record-level
/// list is listed; content outside the documented form is non-canonical. One `WARN` event names
/// the number of skipped sets. Every listing request carries `cursor`.
#[tokio::test]
async fn desec_listing_reports_skipped_sets() {
    let (capture, _guard) = LogCapture::install();
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset("example.org", REC, "A", 3600, &["192.0.2.1", "192.0.2.2"]);
    control.insert_rrset("example.org", REC, "TXT", 7200, &["\"v=spf1 -all\""]);
    control.insert_rrset(
        "example.org",
        "example.org",
        "MX",
        3600,
        &["10 mail.example.org."],
    );
    control.insert_rrset(
        "example.org",
        "dotless.example.org",
        "MX",
        3600,
        &["10 mail"],
    );
    control.insert_rrset(
        "example.org",
        "h.example.org",
        "HINFO",
        3600,
        &["\"PC\" \"Linux\""],
    );
    control.insert_rrset("example.org", "w.example.org", "WIZARD", 3600, &["magic"]);
    let long_label = format!("{}.example.org", "x".repeat(64));
    control.insert_rrset("example.org", &long_label, "A", 3600, &["192.0.2.1"]);
    control.insert_rrset(
        "example.org",
        "c.example.org",
        "CNAME",
        3600,
        &["a.example.net.", "b.example.net."],
    );
    control.insert_zone("example.com");
    control.insert_rrset(
        "example.com",
        "other.example.com",
        "A",
        3600,
        &["192.0.2.7"],
    );

    let listing = client.list_rrsets(&zone()).await.unwrap();
    let sets: Vec<(String, RecordType)> = listing
        .rrsets
        .iter()
        .map(|s| (s.name().to_string(), s.rtype()))
        .collect();
    assert_eq!(
        sets,
        [
            ("dotless.example.org.".to_owned(), RecordType::MX),
            ("example.org.".to_owned(), RecordType::NS),
            ("example.org.".to_owned(), RecordType::MX),
            (
                "h.example.org.".to_owned(),
                "HINFO".parse::<RecordType>().unwrap()
            ),
            ("rec.example.org.".to_owned(), RecordType::A),
            ("rec.example.org.".to_owned(), RecordType::TXT),
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
        &rrset(REC, RecordType::A, Some(3600), &["192.0.2.1", "192.0.2.2"])
    );
    assert_eq!(
        find(REC, RecordType::TXT),
        &rrset(REC, RecordType::TXT, Some(7200), &["\"v=spf1 -all\""])
    );
    assert_eq!(
        find("example.org", RecordType::NS),
        &rrset(
            "example.org",
            RecordType::NS,
            Some(3600),
            &["ns1.desec.io.", "ns2.desec.org."]
        )
    );
    let dotless = find("dotless.example.org", RecordType::MX);
    assert!(!dotless.records()[0].is_canonical());
    assert_eq!(dotless.records()[0].as_str(), "10 mail");
    assert!(
        !find("h.example.org", "HINFO".parse::<RecordType>().unwrap()).records()[0].is_canonical()
    );
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
    // One page, no `next` link: one request, with the empty cursor of the first page.
    let requests = mock.log().matching(Some("GET"), RRSETS);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].query.as_deref(), Some("cursor="));
}

// ---- TXT values --------------------------------------------------------------------------------

/// The first value creates the rrset with `POST …/rrsets/`: the subname, the type, the
/// configured TTL, the value quoted. Later values change the rrset with `PATCH`, carrying every
/// record and the TTL as read. The apex is `@` in a path and `""` in a body; a wildcard owner's
/// `*` is percent-encoded; an internationalized name travels as A-labels.
#[tokio::test]
async fn desec_request_shapes() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    let create = mock.log().matching(Some("POST"), RRSETS).pop().unwrap();
    assert_eq!(create.path, "/api/v1/domains/example.org/rrsets/");
    assert_eq!(
        create.body_json().unwrap(),
        json!({"subname": "_acme-challenge", "type": "TXT", "ttl": 3600, "records": ["\"AAA\""]})
    );
    mock.control()
        .edit_rrset(NAME, "TXT", |rrset| rrset.ttl = 7200);
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    let read = mock.log().matching(Some("GET"), TXT_RRSET).pop().unwrap();
    assert_eq!(
        read.path,
        "/api/v1/domains/example.org/rrsets/_acme-challenge/TXT/"
    );
    let patch = mock.log().matching(Some("PATCH"), TXT_RRSET).pop().unwrap();
    assert_eq!(patch.path, read.path);
    assert_eq!(
        patch.body_json().unwrap(),
        json!({"ttl": 7200, "records": ["\"AAA\"", "\"BBB\""]})
    );
    // The TTL of a new rrset: the caller's, else the setting.
    client
        .add_txt_value(
            &zone(),
            &dn("_acme-challenge.www.example.org"),
            &txt("CCC"),
            Some(RrsetTtl::from_secs(43200).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        mock.control()
            .rrset("_acme-challenge.www.example.org", "TXT")
            .unwrap()
            .ttl,
        43200
    );
    // The apex.
    let apex = rrset("example.org", RecordType::A, None, &["192.0.2.1"]);
    client.set_rrset(&zone(), &apex, Expect::Any).await.unwrap();
    let create = mock.log().matching(Some("POST"), RRSETS).pop().unwrap();
    assert_eq!(create.body_json().unwrap()["subname"], "");
    let apex = rrset("example.org", RecordType::A, None, &["192.0.2.2"]);
    client.set_rrset(&zone(), &apex, Expect::Any).await.unwrap();
    let patch = mock.log().matching(Some("PATCH"), ANY_RRSET).pop().unwrap();
    assert_eq!(patch.path, "/api/v1/domains/example.org/rrsets/@/A/");
    assert_eq!(mock.control().records("example.org", "A"), ["192.0.2.2"]);
    // A wildcard and an internationalized name.
    let wildcard = rrset("*.example.org", RecordType::A, None, &["192.0.2.1"]);
    client
        .set_rrset(&zone(), &wildcard, Expect::Any)
        .await
        .unwrap();
    let wild = rrset("*.example.org", RecordType::A, None, &["192.0.2.3"]);
    client.set_rrset(&zone(), &wild, Expect::Any).await.unwrap();
    let last = mock.log().matching(Some("PATCH"), ANY_RRSET).pop().unwrap();
    assert_eq!(last.path, "/api/v1/domains/example.org/rrsets/%2A/A/");
    assert_eq!(mock.control().records("*.example.org", "A"), ["192.0.2.3"]);
    let idn = dn("_acme-challenge.пример.example.org");
    client
        .add_txt_value(&zone(), &idn, &txt("DDD"), None)
        .await
        .unwrap();
    let last = mock.log().matching(Some("POST"), RRSETS).pop().unwrap();
    assert_eq!(
        last.body_json().unwrap()["subname"],
        "_acme-challenge.xn--e1afmkfd"
    );
}

/// Values of any bytes are accepted by the TXT value operations (`txt_plain_only` is false):
/// written as quoted presentation text with escapes, read back by the same rule, also when the
/// API stores them re-split or with other escapes.
#[tokio::test]
async fn desec_txt_values_of_any_bytes() {
    let (mock, client) = setup().await;
    let long = "x".repeat(300);
    for value in ["two words", "quo\"te", "back\\slash", "ключ", long.as_str()] {
        assert_eq!(
            add(&client, value).await.unwrap(),
            AddOutcome::Created,
            "{value}"
        );
        assert_eq!(
            add(&client, value).await.unwrap(),
            AddOutcome::AlreadyPresent,
            "{value}"
        );
        let read = client
            .get_rrset(&zone(), &name(), RecordType::TXT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.records(), [txt(value).to_data().unwrap()], "{value}");
        assert_eq!(
            remove(&client, value).await.unwrap(),
            RemoveOutcome::RrsetDeleted,
            "{value}"
        );
    }
    let stored = mock
        .log()
        .matching(Some("POST"), RRSETS)
        .iter()
        .map(|r| {
            r.body_json().unwrap()["records"][0]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(stored[1], "\"quo\\\"te\"");
    assert_eq!(stored[2], "\"back\\\\slash\"");
    assert_eq!(stored[3], "\"\\208\\186\\208\\187\\209\\142\\209\\135\"");
    assert_eq!(
        stored[4],
        format!("\"{}\" \"{}\"", "x".repeat(255), "x".repeat(45))
    );
    // Another writer's spelling of our value: one long string, an escape of a plain byte.
    mock.control()
        .insert_rrset("example.org", NAME, "TXT", 3600, &["\"a\\098c\""]);
    assert_eq!(
        add(&client, "abc").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        remove(&client, "abc").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
}

/// A create that meets an rrset another writer created after the read is a retryable
/// `Conflict`: the API answers it with `400`, which it also answers for invalid content, so after
/// any refused create the client reads again, and only an rrset found there makes the refusal a
/// `Conflict`. A refusal with nothing there afterwards is the provider's refusal with its
/// message.
#[tokio::test]
async fn desec_create_race_is_conflict() {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("POST", RRSETS).pass().run(move || {
            hook.insert_rrset("example.org", NAME, "TXT", 3600, &["\"foreign\""]);
        }));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(stored_txt(&mock), [quoted("foreign")]);
    // The read of the operation, and the read after the refused create.
    assert_eq!(mock.log().count(Some("GET"), TXT_RRSET), 2);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    assert_eq!(stored_txt(&mock), [quoted("foreign"), quoted("AAA")]);

    // The API refuses the content (the zone's minimum TTL): `Rejected` with the message.
    mock.log().clear();
    let low = rrset(REC, RecordType::A, Some(60), &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &low, Expect::Any)
        .await
        .unwrap_err();
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
    assert!(
        e.to_string().contains("greater than or equal to 3600"),
        "{e}"
    );
    assert_eq!(mock.log().count(Some("GET"), REC_A), 2);
    assert!(mock.control().rrset(REC, "A").is_none());
}

/// A change answered 404 means the rrset went away after the read: `Conflict`, nothing written,
/// and the repeat creates it.
#[tokio::test]
async fn desec_change_of_a_vanished_rrset_is_conflict() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("PATCH", TXT_RRSET)
            .pass()
            .run(move || hook.delete_rrset(NAME, "TXT")),
    );
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(mock.control().rrset(NAME, "TXT").is_none());
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Created);
}

/// A delete is answered `204` also when the rrset is gone: a removal that meets an rrset another
/// writer deleted meanwhile succeeds. A delete answered `404` (the domain went away) is
/// followed by a read, which reports the missing zone.
#[tokio::test]
async fn desec_delete_answers() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("DELETE", TXT_RRSET)
            .pass()
            .run(move || hook.delete_rrset(NAME, "TXT")),
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("DELETE", TXT_RRSET)
            .pass()
            .run(move || hook.remove_zone("example.org")),
    );
    let e = remove(&client, "AAA").await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
}

// ---- Zones -------------------------------------------------------------------------------------

/// `check` verifies the token with the first page of the domain listing and looks every zone
/// up.
#[tokio::test]
async fn desec_check_reports_zones() {
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
    assert_eq!(probe[0].query.as_deref(), Some("cursor="));
    assert_eq!(mock.log().count(Some("GET"), DOMAIN), 2);
    let report = client.check(&[]).await.unwrap();
    assert!(report.credentials_verified);
    let wrong = client_with(&mock, "wrong-token", &context());
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
}

/// Every domain, all pages, by the cursor of the `next` link.
#[tokio::test]
async fn desec_list_zones_reads_every_page() {
    let (mock, client) = setup().await;
    for i in 0..4 {
        mock.control().insert_zone(&format!("z{i}.example.net"));
    }
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
    let cursors: Vec<String> = mock
        .log()
        .matching(Some("GET"), DOMAINS)
        .iter()
        .map(|r| r.query.clone().unwrap_or_default())
        .collect();
    assert_eq!(cursors, ["cursor=", "cursor=p2", "cursor=p4"]);
}

/// The rrset listing reads every page and ends at the page without a `next` link, at an empty
/// page, and refuses a server that pages oddly: one that ignores the cursor and answers the
/// same page again, one whose `next` link repeats the cursor just used, and one whose `next`
/// link has no cursor are `Protocol`, never an endless loop or a shorter result.
#[tokio::test]
async fn desec_listing_ends_under_every_paging_reading() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for i in 0..5 {
        control.insert_rrset(
            "example.org",
            &format!("h{i}.example.org"),
            "A",
            3600,
            &["192.0.2.1"],
        );
    }
    control.set_page_size(2);
    // Five rrsets and the apex NS: three pages.
    assert_eq!(client.list_rrsets(&zone()).await.unwrap().rrsets.len(), 6);
    let cursors: Vec<String> = mock
        .log()
        .matching(Some("GET"), RRSETS)
        .iter()
        .map(|r| r.query.clone().unwrap_or_default())
        .collect();
    assert_eq!(cursors, ["cursor=", "cursor=p2", "cursor=p4"]);

    for i in 0..4 {
        control.insert_zone(&format!("z{i}.example.net"));
    }
    for (paging, text) in [
        (Paging::IgnoreCursor, "repeated"),
        (Paging::RepeatCursor, "did not advance"),
        (Paging::NoCursorInLink, "Link header"),
    ] {
        control.set_paging(paging);
        let errors = [
            client.list_rrsets(&zone()).await.unwrap_err(),
            client.list_zones().await.unwrap_err(),
        ];
        for e in errors {
            assert_eq!(e.kind(), ErrorKind::Protocol, "{paging:?}: {e:?}");
            assert!(e.to_string().contains(text), "{paging:?}: {e}");
        }
    }
    control.set_paging(Paging::Documented);

    // An empty page with a `next` link ends the listing.
    mock.faults()
        .push(Fault::on("GET", RRSETS).respond(200, "[]").header(
            "link",
            "<http://127.0.0.1/api/v1/domains/example.org/rrsets/?cursor=p2>; rel=\"next\"",
        ));
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.rrsets.is_empty());
}

/// The answer to a read of one rrset may leave out `subname`, `name` and `type`, which the path
/// states; a stated owner or type other than the one asked for is `Protocol`. In a listing, an
/// item without its owner or type is `Protocol`.
#[tokio::test]
async fn desec_single_rrset_answer_may_omit_name_and_type() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).respond(200, r#"{"ttl":3600,"records":["\"v1\""]}"#));
    assert_eq!(
        add(&client, "v1").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    for body in [
        r#"{"subname":"other","ttl":3600,"records":[]}"#,
        r#"{"name":"other.example.org.","ttl":3600,"records":[]}"#,
        r#"{"type":"A","ttl":3600,"records":[]}"#,
        r#"{"subname":"_acme-challenge","type":"TXT","ttl":3600}"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", TXT_RRSET).respond(200, body));
        let e = add(&client, "v1").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    for body in [
        r#"[{"subname":"a","ttl":3600,"records":["192.0.2.1"]}]"#,
        r#"[{"type":"A","ttl":3600,"records":["192.0.2.1"]}]"#,
        r#"{"detail":"not a list"}"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", RRSETS).respond(200, body));
        let e = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    // A listing item with `subname` only.
    mock.faults().push(Fault::on("GET", RRSETS).respond(
        200,
        r#"[{"subname":"a","type":"A","ttl":3600,"records":["192.0.2.1"]}]"#,
    ));
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(
        listing.rrsets,
        [rrset(
            "a.example.org",
            RecordType::A,
            Some(3600),
            &["192.0.2.1"]
        )]
    );
    assert_eq!(writes(&mock), 0);
}

/// A zone the account does not own is `ZoneNotFound` for reads and writes, after the rrset
/// read answered 404 and the domain read confirmed it; nothing is written.
#[tokio::test]
async fn desec_zone_not_found() {
    let (mock, client) = setup().await;
    let zone = dn("missing.example.net");
    let name = dn("_acme-challenge.missing.example.net");
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
    ];
    for e in errors {
        assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    }
    assert_eq!(writes(&mock), 0);
}

// ---- Transport ---------------------------------------------------------------------------------

/// The provider's throttling (`429` with `Retry-After`): a read with a short wait is repeated
/// after it and succeeds; a read with a wait beyond the transport's inline limit and a throttled
/// write end with `RateLimited` carrying the wait, the write sent once.
#[tokio::test]
async fn desec_throttled_requests() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).rate_limited("0"));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.log().count(Some("GET"), TXT_RRSET), 2);

    mock.log().clear();
    mock.control().set_throttled(Some(120));
    let e = add(&client, "BBB").await.unwrap_err();
    assert!(
        matches!(e, Error::RateLimited { retry_after: Some(wait), .. } if wait == Duration::from_secs(120)),
        "{e:?}"
    );
    assert_eq!(mock.log().count(Some("GET"), TXT_RRSET), 1);
    assert_eq!(writes(&mock), 0);
    mock.control().set_throttled(None);

    mock.faults()
        .push(Fault::on("PATCH", TXT_RRSET).rate_limited("7"));
    let e = add(&client, "BBB").await.unwrap_err();
    assert!(
        matches!(e, Error::RateLimited { retry_after: Some(wait), .. } if wait == Duration::from_secs(7)),
        "{e:?}"
    );
    assert_eq!(mock.log().count(Some("PATCH"), TXT_RRSET), 1);
    assert_eq!(stored_txt(&mock), [quoted("AAA")]);
}

/// A 5xx on a read is retried, then `Transient`.
#[tokio::test]
async fn desec_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).times(3).status(503));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), TXT_RRSET), 3);
    assert_eq!(writes(&mock), 0);
}

/// Refusals: a 400 is `Rejected` with the provider's message (`detail`, or the strings of a
/// body keyed by field); a 403 is `Forbidden`; another status is `Protocol`.
#[tokio::test]
async fn desec_refusals_are_classified() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).respond(400, r#"{"detail":"subname is not valid"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert!(
        matches!(
            e,
            Error::Rejected {
                status: Some(400),
                code: None,
                ..
            }
        ),
        "{e:?}"
    );
    assert!(e.to_string().contains("subname is not valid"), "{e}");
    mock.faults().push(
        Fault::on("POST", RRSETS).respond(400, r#"{"records":["Record content is malformed."]}"#),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(
        e.to_string().contains("Record content is malformed."),
        "{e}"
    );
    mock.faults().push(Fault::on("GET", TXT_RRSET).respond(
        403,
        r#"{"detail":"You do not have permission to perform this action."}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).respond(409, r#"{"detail":"odd"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 1);
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn desec_from_json_builds_the_client() {
    let (mock, _) = setup().await;
    let settings = json!({ "base_url": mock.base_url(), "ttl": 7200 }).to_string();
    let client = AnyProvider::from_json(
        ProviderId::Desec,
        &settings,
        &SecretString::from(format!(r#"{{"api_token":"{TOKEN}"}}"#)),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Desec);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.control().rrset(NAME, "TXT").unwrap().ttl, 7200);
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = AnyProvider::from_json(
        ProviderId::Desec,
        "{}",
        &SecretString::from(format!(r#"{{"api_token":"{TOKEN}"}}"#)),
        &ctx,
    )
    .unwrap();
    assert!(format!("{client:?}").contains("https://desec.io/api/v1"));
}

/// Configuration errors name the key and never the value.
#[test]
fn desec_config_errors_name_no_value() {
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let canary = "canary-Value-9d1e";
    for (settings, credentials, key) in [
        (json!({"ttl": 0}), json!({"api_token": canary}), "ttl"),
        (json!({"ttl": 86401}), json!({"api_token": canary}), "ttl"),
        (
            json!({"ttl": "provider_default"}),
            json!({"api_token": canary}),
            "ttl",
        ),
        (
            json!({"base_url": format!("https://user:{canary}@example.net/api/v1")}),
            json!({"api_token": canary}),
            "base_url",
        ),
        (json!({}), json!({"api_token": "  "}), "api_token"),
        (json!({}), json!({"token": canary}), "api_token"),
        (json!({"zz": canary}), json!({"api_token": canary}), "line"),
    ] {
        let e = AnyProvider::from_json(
            ProviderId::Desec,
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
        ProviderId::Desec,
        "{}",
        &SecretString::from(json!({ "api_token": format!("{canary}\nx") }).to_string()),
        &ctx,
    )
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
    assert!(!format!("{e} | {e:?}").contains(canary));
}

// ---- Record level ------------------------------------------------------------------------------

/// Every record type of the capabilities is written in presentation format, read back
/// canonical, and an identical repeat is `Unchanged` without a write; the TTL is the rrset's.
#[tokio::test]
async fn desec_record_round_trips() {
    let (mock, client) = setup().await;
    for (owner, rtype, texts) in [
        (
            "a.example.org",
            RecordType::A,
            vec!["192.0.2.1", "192.0.2.2"],
        ),
        ("a.example.org", RecordType::AAAA, vec!["2001:db8::1"]),
        (
            "www.example.org",
            RecordType::CNAME,
            vec!["target.example.net."],
        ),
        (
            "d.example.org",
            RecordType::DNAME,
            vec!["target.example.net."],
        ),
        (
            "sub.example.org",
            RecordType::NS,
            vec!["ns1.example.net.", "ns2.example.net."],
        ),
        ("p.example.org", RecordType::PTR, vec!["host.example.net."]),
        (
            "example.org",
            RecordType::MX,
            vec!["10 mx1.example.org.", "20 mx2.example.org."],
        ),
        (
            "_sip._tcp.example.org",
            RecordType::SRV,
            vec!["10 20 5060 sip.example.org."],
        ),
        (
            "example.org",
            RecordType::CAA,
            vec![
                "0 issue \"letsencrypt.org\"",
                "128 iodef \"mailto:sec@example.org\"",
            ],
        ),
        (
            "_443._tcp.www.example.org",
            RecordType::TLSA,
            vec!["3 1 1 0a1b2c3d"],
        ),
        ("s.example.org", RecordType::SSHFP, vec!["4 2 0a1b2c3d"]),
        ("example.org", RecordType::HTTPS, vec!["1 . alpn=\"h2,h3\""]),
        (
            "_x.example.org",
            RecordType::SVCB,
            vec!["1 svc.example.net. port=8443"],
        ),
        (
            "t.example.org",
            RecordType::TXT,
            vec!["\"v=spf1 include:example.net -all\""],
        ),
    ] {
        let set = rrset(owner, rtype, Some(7200), &texts);
        assert_eq!(
            client
                .set_rrset(&zone(), &set, Expect::Absent)
                .await
                .unwrap(),
            SetOutcome::Created,
            "{owner} {rtype}"
        );
        let expected: Vec<String> = set
            .records()
            .iter()
            .map(|r| r.as_str().to_owned())
            .collect();
        assert_eq!(
            mock.control().records(owner, &rtype.to_string()),
            expected,
            "{owner} {rtype}"
        );
        let read = client
            .get_rrset(&zone(), &dn(owner), rtype)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, set, "{owner} {rtype}");
        let before = writes(&mock);
        assert_eq!(
            client
                .set_rrset(&zone(), &set, Expect::Matches(&read))
                .await
                .unwrap(),
            SetOutcome::Unchanged
        );
        assert_eq!(writes(&mock), before);
        let longer = set
            .clone()
            .with_ttl(Some(RrsetTtl::from_secs(86400).unwrap()));
        assert_eq!(
            client
                .set_rrset(&zone(), &longer, Expect::Any)
                .await
                .unwrap(),
            SetOutcome::Replaced
        );
        assert_eq!(
            mock.control().rrset(owner, &rtype.to_string()).unwrap().ttl,
            86400
        );
        let first = rd(rtype, texts[0]);
        let fewer = RrSet::new(dn(owner), rtype, None, [first]).unwrap();
        assert_eq!(
            client
                .set_rrset(&zone(), &fewer, Expect::Any)
                .await
                .unwrap(),
            if texts.len() > 1 {
                SetOutcome::Replaced
            } else {
                SetOutcome::Unchanged
            }
        );
        assert_eq!(
            mock.control().rrset(owner, &rtype.to_string()).unwrap().ttl,
            86400
        );
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(owner), rtype, Expect::Any)
                .await
                .unwrap(),
            DeleteOutcome::Deleted
        );
        assert!(mock.control().rrset(owner, &rtype.to_string()).is_none());
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(owner), rtype, Expect::Any)
                .await
                .unwrap(),
            DeleteOutcome::NotPresent
        );
    }
}

/// The API's canonical forms read as the same value: an IPv6 address the API rewrote, names in
/// upper case. A set equal to them is `Unchanged`.
#[tokio::test]
async fn desec_reads_provider_spellings() {
    let (mock, client) = setup().await;
    mock.control()
        .insert_rrset("example.org", REC, "AAAA", 3600, &["2001:DB8:0:0::1"]);
    mock.control().insert_rrset(
        "example.org",
        "example.org",
        "MX",
        3600,
        &["10 MX1.Example.org."],
    );
    for (owner, rtype, text) in [
        (REC, RecordType::AAAA, "2001:db8::1"),
        ("example.org", RecordType::MX, "10 mx1.example.org."),
    ] {
        let wanted = rrset(owner, rtype, Some(3600), &[text]);
        let read = client
            .get_rrset(&zone(), &dn(owner), rtype)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, wanted);
        assert_eq!(
            client
                .set_rrset(&zone(), &wanted, Expect::Any)
                .await
                .unwrap(),
            SetOutcome::Unchanged
        );
    }
    assert_eq!(writes(&mock), 0);
}

/// Values of another type than TXT whose canonical text needs an escape are not sent
/// (`InvalidInput` after the read, nothing written); a foreign record the client cannot read is
/// non-canonical and replaced, never matched.
#[tokio::test]
async fn desec_escapes_and_non_canonical_data() {
    let (mock, client) = setup().await;
    let set = rrset(REC, RecordType::CAA, None, &["0 issue \"a\\\\b\""]);
    let e = client
        .set_rrset(&zone(), &set, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), 0);

    mock.control().insert_rrset(
        "example.org",
        REC,
        "MX",
        3600,
        &["10 mail.example.org.", "20 mail"],
    );
    let read = client
        .get_rrset(&zone(), &dn(REC), RecordType::MX)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        read.records().iter().filter(|r| r.is_canonical()).count(),
        1
    );
    let wanted = rrset(REC, RecordType::MX, None, &["10 mail.example.org."]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(mock.control().records(REC, "MX"), ["10 mail.example.org."]);
}

/// The apex NS set is refused before any request; types outside the capabilities (SOA, which
/// the API does not show, the DNSSEC types the provider manages, ALIAS) are
/// `UnsupportedRecordType`, and nothing is sent.
#[tokio::test]
async fn desec_protected_sets_send_nothing() {
    let (mock, client) = setup().await;
    let apex_ns = rrset("example.org", RecordType::NS, None, &["ns1.example.net."]);
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
    for (rtype, text) in [
        (
            RecordType::SOA,
            "ns1.example.net. hostmaster.example.org. 1 7200 3600 1209600 300",
        ),
        (RecordType::ALIAS, "target.example.net."),
        ("DS".parse::<RecordType>().unwrap(), "\\# 4 0a000001"),
    ] {
        let set = rrset(REC, rtype, None, &[text]);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
        let e = client
            .get_rrset(&zone(), &dn(REC), rtype)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
}

/// A TTL below the zone's minimum is the provider's refusal (`Rejected`), after the read and with
/// one write; the client's own range (1 to 86400) is refused before any request.
#[tokio::test]
async fn desec_record_ttl_bounds() {
    let (mock, client) = setup().await;
    let set = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &set, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(writes(&mock), 1);
    mock.control().set_minimum_ttl(60);
    client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
    for ttl in [0, 86_401] {
        let bad = RrSet::new(
            dn(REC),
            RecordType::A,
            Some(RrsetTtl::from_secs(ttl).unwrap()),
            [rd(RecordType::A, "192.0.2.1")],
        )
        .unwrap();
        let e = client
            .set_rrset(&zone(), &bad, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{ttl}: {e:?}");
    }
    assert_eq!(writes(&mock), 2);
}

/// Two `set_rrset` calls on one name from two clients sharing a `Context` do not interleave.
#[tokio::test]
async fn desec_concurrent_sets_are_serialized() {
    let mock = DesecMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, TOKEN, &ctx);
    let b = client_with(&mock, TOKEN, &ctx);
    mock.faults()
        .push(Fault::on("POST", RRSETS).delay(Duration::from_millis(300)));
    let first = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    let second = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    let zone = zone();
    let (ra, rb) = tokio::join!(
        a.set_rrset(&zone, &first, Expect::Absent),
        b.set_rrset(&zone, &second, Expect::Any),
    );
    let mut outcomes = [format!("{:?}", ra.unwrap()), format!("{:?}", rb.unwrap())];
    outcomes.sort();
    assert_eq!(outcomes, ["Created", "Replaced"]);
    assert_eq!(mock.control().records(REC, "A"), ["192.0.2.2"]);
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
    async fn desec_txt_value_is_served_over_dns() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        txt_round_trip(&mock, &client, &dns).await;
    }

    /// Names inside values are published fully qualified.
    #[tokio::test]
    async fn desec_names_in_values_are_served() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = link(&mock, &dns, LinkOptions::new());
        let zone = crate::common::dn("example.org");
        let set = rrset(
            "example.org",
            RecordType::MX,
            Some(3600),
            &["10 mail.example.org."],
        );
        client.set_rrset(&zone, &set, Expect::Any).await.unwrap();
        link.settled().await;
        assert_eq!(link.skipped(), 0);
        assert_eq!(
            values(ask(dns.addr(), "example.org", RecordType::MX).await),
            [rd(RecordType::MX, "10 mail.example.org.")]
        );
        assert!(mock.published().zones.contains(&"example.org".to_owned()));
    }

    /// `reset` returns the mock to its seed: the record is gone from the mock and from DNS, the
    /// request log is empty, and the client works again.
    #[tokio::test]
    async fn desec_reset_returns_the_mock_to_its_seed() {
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
        assert!(mock.control().rrset(NAME, "TXT").is_none());
        assert_eq!(mock.control().rrsets().len(), 1, "the apex NS of the seed");
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
    let settings = live_env("ZONEWRIGHT_LIVE_DESEC_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_DESEC_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_DESEC_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = AnyProvider::from_json(
        ProviderId::Desec,
        &settings,
        &SecretString::from(credentials),
        &ctx,
    )
    .unwrap();
    (Arc::new(client), zone)
}

/// Adds and removes two values under a generated label in the zone the maintainer names, and
/// removes exactly the values it added afterwards, also when the body failed. Mind the
/// provider's write limit of 15 per minute per domain.
#[tokio::test]
#[ignore = "live API; run only by the maintainer"]
async fn live_desec_add_and_remove() {
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

/// A record-level round trip on an A rrset under a generated label: create, read, replace with
/// new records and a new TTL, unchanged repeat, list, delete. The cleanup deletes that rrset,
/// the only one the test wrote, also when the body failed. TTLs are 3600 and 7200, at or above
/// the usual `minimum_ttl` of a domain.
#[tokio::test]
#[ignore = "live API; run only by the maintainer"]
async fn live_desec_record_round_trip() {
    let (client, zone) = live_client();
    let rec_name = zone
        .prepend(&format!("zw-live-{:016x}", random_u64()))
        .unwrap();
    let records = {
        let (client, zone, rec_name) = (client.clone(), zone.clone(), rec_name.clone());
        tokio::spawn(async move {
            let first = RrSet::new(
                rec_name.clone(),
                RecordType::A,
                Some(RrsetTtl::from_secs(3600).unwrap()),
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
                Some(RrsetTtl::from_secs(7200).unwrap()),
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
/// `ZONEWRIGHT_LIVE_DESEC_ZONE`, under owner names that start with the label prefix of
/// `ZONEWRIGHT_LIVE_DESEC_PREFIX` followed by a random tag, it creates, reads back and deletes:
///
/// - one set of every type of the capabilities other than A (CAA, CNAME, DNAME, HTTPS, MX, NS,
///   PTR, SRV, SSHFP, SVCB, TLSA, AAAA and TXT): each read back equal to what was sent and
///   repeated as `Unchanged`, which shows that the API's canonical form of each type reads as
///   the crate's (assumed for every type but the documented AAAA example);
/// - TXT values with a space, a quote, a backslash, non-ASCII bytes and more than 255 octets,
///   added and removed with the value operations (the escapes the documentation gives);
/// - an A set at a wildcard owner (`*` in the path as `%2A`, assumed to be decoded);
/// - a set created by one client while another, on a separate `Context`, creates the same name
///   and type: the second create meets an existing rrset (documented `400`) and the client's new
///   read must give `Created`, `Replaced` or `Conflict`, never `Rejected`;
/// - a change (`PATCH`) of a set that a second client deleted meanwhile: assumed `404`, so
///   `Conflict` (or `Created` if the API creates it); never `Rejected`;
/// - `check` of the zone and of a name the account does not own; every created set is found by
///   `list_rrsets`, which pages when the zone holds more than 500 rrsets.
///
/// Everything it created is deleted afterwards by name and type, also when a step failed; it
/// touches nothing else. It sends about 50 writes: run it with the provider's limit of 15 writes
/// per minute per domain in mind (the client reports `RateLimited`, it does not wait).
#[tokio::test]
#[ignore = "live API; run only by the maintainer"]
async fn desec_live_assumptions() {
    let (client, zone) = live_client();
    let prefix = live_env("ZONEWRIGHT_LIVE_DESEC_PREFIX");
    let tag = format!("{prefix}-{:016x}", random_u64());
    let base = zone.prepend(&tag).unwrap();
    let owner = |label: &str| base.prepend(label).unwrap();
    let set = |name: DomainName, rtype: RecordType, text: &str| {
        RrSet::new(name, rtype, None, [rd(rtype, text)]).unwrap()
    };
    let sets: Vec<RrSet> = vec![
        set(base.clone(), RecordType::MX, &format!("10 mx.{base}")),
        set(
            owner("_sip._tcp"),
            RecordType::SRV,
            &format!("10 20 5060 sip.{base}"),
        ),
        set(base.clone(), RecordType::CAA, "0 issue \"letsencrypt.org\""),
        set(owner("alias"), RecordType::CNAME, &format!("target.{base}")),
        set(owner("dn"), RecordType::DNAME, &format!("target.{base}")),
        set(owner("deleg"), RecordType::NS, "ns1.example.net."),
        set(owner("p"), RecordType::PTR, &format!("host.{base}")),
        set(
            owner("s"),
            RecordType::SSHFP,
            "4 2 0a1b2c3d0a1b2c3d0a1b2c3d0a1b2c3d0a1b2c3d0a1b2c3d0a1b2c3d0a1b2c3d",
        ),
        set(
            owner("_443._tcp"),
            RecordType::TLSA,
            "3 1 1 0a1b2c3d0a1b2c3d0a1b2c3d0a1b2c3d0a1b2c3d0a1b2c3d0a1b2c3d0a1b2c3d",
        ),
        set(
            owner("h"),
            RecordType::HTTPS,
            "1 . alpn=\"h2,h3\" port=8443",
        ),
        set(
            owner("_svc"),
            RecordType::SVCB,
            &format!("1 svc.{base} port=8443"),
        ),
        set(owner("v6"), RecordType::AAAA, "2001:db8::1"),
        set(owner("txt"), RecordType::TXT, "\"two words\""),
        set(base.prepend("*").unwrap(), RecordType::A, "192.0.2.20"),
    ];
    let values_name = owner("_values");
    let long = "y".repeat(300);
    let values: Vec<Txt> = [
        "with space",
        "quo\"te",
        "back\\slash",
        "ключ",
        long.as_str(),
    ]
    .into_iter()
    .map(txt)
    .collect();
    let raced = owner("race");
    let vanished = owner("vanish");
    let mut created: Vec<(DomainName, RecordType)> =
        sets.iter().map(|s| (s.name().clone(), s.rtype())).collect();
    created.push((raced.clone(), RecordType::A));
    created.push((vanished.clone(), RecordType::A));
    created.push((values_name.clone(), RecordType::TXT));
    let body = {
        let (client, zone, sets, values, values_name, raced, vanished) = (
            client.clone(),
            zone.clone(),
            sets.clone(),
            values.clone(),
            values_name.clone(),
            raced.clone(),
            vanished.clone(),
        );
        tokio::spawn(async move {
            let report = client
                .check([&zone, &dn("zw-not-owned.invalid")])
                .await
                .unwrap();
            assert!(report.zones[0].found, "{report:?}");
            assert!(!report.zones[1].found, "{report:?}");
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
            for value in &values {
                client
                    .add_txt_value(&zone, &values_name, value, None)
                    .await
                    .unwrap();
                assert_eq!(
                    client
                        .add_txt_value(&zone, &values_name, value, None)
                        .await
                        .unwrap(),
                    AddOutcome::AlreadyPresent,
                    "{value:?}"
                );
            }
            for value in &values {
                let outcome = client
                    .remove_txt_value(&zone, &values_name, value)
                    .await
                    .unwrap();
                assert_ne!(outcome, RemoveOutcome::NotPresent, "{value:?}");
            }
            let (settings, credentials) = (
                live_env("ZONEWRIGHT_LIVE_DESEC_SETTINGS"),
                live_env("ZONEWRIGHT_LIVE_DESEC_CREDENTIALS"),
            );
            let other_ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
            let other = AnyProvider::from_json(
                ProviderId::Desec,
                &settings,
                &SecretString::from(credentials),
                &other_ctx,
            )
            .unwrap();
            let race_a = set(raced.clone(), RecordType::A, "192.0.2.21");
            let race_b = set(raced.clone(), RecordType::A, "192.0.2.22");
            let (a, b) = tokio::join!(
                client.set_rrset(&zone, &race_a, Expect::Any),
                other.set_rrset(&zone, &race_b, Expect::Any),
            );
            for outcome in [a, b] {
                match outcome {
                    Ok(SetOutcome::Created | SetOutcome::Replaced) => {}
                    Err(e) => assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}"),
                    Ok(outcome) => panic!("unexpected outcome {outcome:?}"),
                }
            }
            // A change of a set deleted meanwhile by another client.
            client
                .set_rrset(
                    &zone,
                    &set(vanished.clone(), RecordType::A, "192.0.2.30"),
                    Expect::Absent,
                )
                .await
                .unwrap();
            let changed_set = set(vanished.clone(), RecordType::A, "192.0.2.31");
            let (changed, deleted) = tokio::join!(
                client.set_rrset(&zone, &changed_set, Expect::Any),
                other.delete_rrset(&zone, &vanished, RecordType::A, Expect::Any),
            );
            deleted.unwrap();
            match changed {
                Ok(SetOutcome::Replaced | SetOutcome::Created) => {}
                Err(e) => assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}"),
                Ok(outcome) => panic!("unexpected outcome {outcome:?}"),
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
