//! The test cases the Gcore and EdgeCenter clients share: both serve the DNS API v2 (EdgeCenter's
//! a fork of Gcore's), run on one shared implementation, and are tested against one mock core.
//!
//! Each case is generic over a [`Family`], which says what differs: the provider, its mock and
//! client types, its default endpoint and the members its answers spell differently. The
//! provider test files (`tests/gcore.rs`, `tests/edgecenter.rs`) define the `#[tokio::test]`
//! functions, with the names `tests/conformance.rs` requires, each calling one case here, and
//! keep the cases of their own.
// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::future::Future;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;
use serde_json::{Value, json};
use zonewright::{
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl, SetOutcome,
    SkipReason, Txt,
};
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::changes::ChangeSource;
use zonewright_mock::echo::{EchoServer, Echoed, Render};
use zonewright_mock::gcore::{Control, Paging, Record, Seed};
use zonewright_mock::{Fault, MockServer};

use super::echo::{CANARY_KEY, CANARY_TOKEN, LogCapture, REDACTED, assert_clean, dialects};
use super::{context, dn};

/// What differs between the providers of the API, for the shared cases.
pub trait Family: 'static {
    /// The provider's mock.
    type Mock: Deref<Target = MockServer> + ChangeSource + Send + Sync;
    /// The provider's client.
    type Client: Provider + std::fmt::Debug + Send + Sync;
    /// The provider.
    const ID: ProviderId;
    /// The prefix of the live tests' environment variables (`ZONEWRIGHT_LIVE_GCORE`).
    const LIVE: &'static str;
    /// The default endpoint of the settings.
    const DEFAULT_URL: &'static str;
    /// The member of an rrset that selects answers per query (`pickers`, `filters`).
    const SELECTION: &'static str;
    /// The zone's answer is wrapped in `{"zone": …}`.
    const ZONE_WRAPPED: bool;
    /// Starts the mock.
    fn start(seed: Seed) -> impl Future<Output = Self::Mock> + Send;
    /// The mock's control.
    fn control(mock: &Self::Mock) -> &Control;
    /// The mock's API endpoint.
    fn base_url(mock: &Self::Mock) -> String;
    /// A client at `base_url` with `token`, without request spacing.
    fn client(base_url: String, token: &str, ctx: &Context) -> Self::Client;
}

// ---- Fixtures ----------------------------------------------------------------------------------

/// The token of the standard seed.
const TOKEN: &str = "test-only-token";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// The owner name the record-level tests write to.
const REC: &str = "rec.example.org";

/// Fault patterns of the mock's paths.
const ZONES: &str = "/dns/v2/zones";
const ZONE: &str = "/dns/v2/zones/*";
const RRSETS: &str = "/dns/v2/zones/*/rrsets";
const TXT_RRSET: &str = "/dns/v2/zones/*/*/TXT";
const ANY_RRSET: &str = "/dns/v2/zones/*/*/*";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// The `content` of one TXT record holding `value`.
fn txt_content(value: &str) -> Value {
    json!([value])
}

/// A client of `F` at `mock` with `token`.
fn client_with<F: Family>(mock: &F::Mock, token: &str, ctx: &Context) -> F::Client {
    F::client(F::base_url(mock), token, ctx)
}

async fn setup<F: Family>() -> (F::Mock, F::Client) {
    let mock = F::start(Seed::standard()).await;
    let client = client_with::<F>(&mock, TOKEN, &context());
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

/// Number of write requests the mock received: creates, replacements and deletes.
fn writes<F: Family>(mock: &F::Mock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), ANY_RRSET)
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

/// The `content` arrays the mock holds for `name` and `rtype`, enabled or not.
fn stored<F: Family>(mock: &F::Mock, name: &str, rtype: &str) -> Vec<Value> {
    F::control(mock)
        .contents(name, rtype)
        .into_iter()
        .map(|(content, _)| content)
        .collect()
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
    /// The zone listing (the probe): the zone read is the echo.
    Probe,
    /// The zone listing, the zone and the rrset reads: the request of the operation is the echo.
    Reads,
}

/// A renderer that answers like the API what `answered` says, in `F`'s spelling, and every other
/// request with `errors`.
fn answering<F: Family>(errors: Render, existing: Existing, answered: Answered) -> Render {
    Arc::new(move |e: &Echoed| {
        if answered == Answered::Nothing || e.method != Method::GET {
            return errors(e);
        }
        let segments: Vec<&str> = e.path.trim_start_matches('/').split('/').collect();
        if answered == Answered::Probe && segments.len() != 3 {
            return errors(e);
        }
        let zone = json!({"name": "example.org", "enabled": true});
        match segments.as_slice() {
            ["dns", "v2", "zones"] => ok(json!({
                "zones": [zone],
                "total_amount": 1
            })),
            ["dns", "v2", "zones", _] if F::ZONE_WRAPPED => ok(json!({ "zone": zone })),
            ["dns", "v2", "zones", _] => ok(zone),
            ["dns", "v2", "zones", _, _, rtype] => {
                let value = match existing {
                    Existing::Nothing => {
                        return (
                            StatusCode::NOT_FOUND,
                            axum::Json(json!({"error": "not found"})),
                        )
                            .into_response();
                    }
                    Existing::Foreign => "foreign",
                    Existing::Ours => "v1",
                };
                let mut rrset = json!({
                    "name": NAME, "type": rtype, "ttl": 300, "meta": {},
                    "resource_records": [{"id": 1, "content": [value], "enabled": true}]
                });
                rrset[F::SELECTION] = json!([]);
                ok(rrset)
            }
            _ => errors(e),
        }
    })
}

fn echo_client<F: Family>(echo: &EchoServer, ctx: &Context) -> F::Client {
    F::client(echo.url("/dns"), CANARY_TOKEN, ctx)
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

impl Op {
    /// The method and path pattern of the request that is the echo.
    fn request(self) -> (&'static str, &'static str) {
        match self {
            Op::Add | Op::Set => ("POST", ANY_RRSET),
            Op::Remove | Op::Delete => ("DELETE", ANY_RRSET),
            Op::List => ("GET", RRSETS),
        }
    }
}

/// `check` and the operation against an echo that quotes every request back: no canary in any
/// error, `ZoneCheck::detail` or `Debug`, and the operation's error shows the redaction.
async fn echo_round(label: &str, client: &(impl Provider + std::fmt::Debug), op: Op) {
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

/// `check` and every kind of request against an echo, for every dialect: the probe, the zone
/// read, the rrset read, the listing, the create (and the read that follows a refused create),
/// the replacement and the delete. Reads are not given a 5xx: the transport repeats them, which
/// would add seconds per dialect without coverage.
pub async fn secret_echo<F: Family>() {
    // One server and one context for every case: each case reconfigures the server, and every
    // client reuses the context's pooled connection (see `EchoServer::reset`).
    let ctx = context();
    let echo = EchoServer::start(200).await;
    for dialect in dialects() {
        // The probe, and every request after it, is the echo.
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} probe", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status).render_under(
                "/dns",
                answering::<F>(dialect.render.clone(), Existing::Nothing, Answered::Nothing),
            ));
            let client = echo_client::<F>(&echo, &ctx);
            echo_round(&label, &client, Op::Add).await;
            assert!(
                echo.log().count(Some("GET"), ZONES) > 0,
                "{label}: the probe did not reach the echo"
            );
        }
        // The probe is answered; the zone read is the echo.
        for status in [400, 401, 403, 422] {
            let label = format!("{} {:?} {status} zone", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status).render_under(
                "/dns",
                answering::<F>(dialect.render.clone(), Existing::Nothing, Answered::Probe),
            ));
            let client = echo_client::<F>(&echo, &ctx);
            let e = client.check(&[zone()]).await.unwrap_err();
            let text = format!("{e} | {e:?} | {client:?}");
            assert!(text.contains(REDACTED), "{label}: {text}");
            assert_clean(&label, &text, &[CANARY_TOKEN]);
            assert_eq!(echo.log().count(Some("GET"), ZONE), 1, "{label}");
        }
        // The reads are answered; the request of the operation is the echo.
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
                    "/dns",
                    answering::<F>(dialect.render.clone(), existing, Answered::Reads),
                ));
                let client = echo_client::<F>(&echo, &ctx);
                echo_round(&label, &client, op).await;
                let (method, path) = match (op, existing) {
                    (Op::Add | Op::Set, Existing::Foreign) => ("PUT", ANY_RRSET),
                    _ => op.request(),
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
pub async fn no_secret_in_logs<F: Family>() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.tokens = vec![CANARY_TOKEN.into()];
    let mock = F::start(seed).await;
    let client = client_with::<F>(&mock, CANARY_TOKEN, &context());
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

    mock.faults().push(Fault::on("PUT", TXT_RRSET).status(500));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    let wrong = client_with::<F>(&mock, CANARY_KEY, &context());
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
            &format!("{} logs and errors", F::ID),
            text,
            &[CANARY_TOKEN, CANARY_KEY],
        );
    }
}

/// The token travels in `Authorization: APIKey <token>`, and only there: never in a path or a
/// query.
pub async fn token_is_sent_as_apikey<F: Family>() {
    let (mock, client) = setup::<F>().await;
    client.check(&[zone()]).await.unwrap();
    add(&client, "v1").await.unwrap();
    let entries = mock.log().entries();
    assert!(!entries.is_empty());
    for entry in entries {
        assert_eq!(
            entry.header("authorization"),
            Some("APIKey test-only-token"),
            "{entry:?}"
        );
        assert!(!entry.path.contains(TOKEN));
        assert!(!entry.query.as_deref().unwrap_or("").contains(TOKEN));
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request, by every mutating operation: another
/// zone, a name that merely ends with the zone's text, the zone's text inside another name, and
/// a sibling zone.
pub async fn name_outside_zone_sends_nothing<F: Family>() {
    let (mock, client) = setup::<F>().await;
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

/// A value the capabilities do not accept and a TTL outside the range are refused before any
/// request.
pub async fn invalid_input_sends_nothing<F: Family>() {
    let (mock, client) = setup::<F>().await;
    for value in ["two words", "quo\"te", "back\\slash"] {
        let e = add(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
        let e = remove(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
    }
    for ttl in [Some(RrsetTtl::ProviderDefault), RrsetTtl::from_secs(0).ok()] {
        let e = client
            .add_txt_value(&zone(), &name(), &txt("v1"), ttl)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{ttl:?}: {e:?}");
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
}

/// `Created`, `Appended` for a second value (the apex and the wildcard of one certificate share
/// a name), then `AlreadyPresent` without a write.
pub async fn add_is_idempotent<F: Family>() {
    let (mock, client) = setup::<F>().await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    let before = writes::<F>(&mock);
    assert_eq!(
        add(&client, "BBB").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(writes::<F>(&mock), before);
    assert_eq!(F::control(&mock).txt_values(NAME), ["AAA", "BBB"]);
}

/// Removing an absent value next to foreign ones writes nothing; adding and removing our value
/// leaves the foreign records (a disabled one, one with metadata, one in a form the client
/// does not read) and the TTL as they were. A single foreign value is never a reason to delete
/// the rrset.
pub async fn never_removes_foreign_value<F: Family>() {
    let (mock, client) = setup::<F>().await;
    let control = F::control(&mock);
    control.insert_rrset(
        "example.org",
        NAME,
        "TXT",
        600,
        &[
            txt_content("foreign"),
            txt_content("foreign-disabled"),
            json!(["two", "strings"]),
        ],
    );
    control.set_enabled(NAME, "TXT", &txt_content("foreign-disabled"), false);
    control.edit_rrset(NAME, "TXT", |rrset| {
        rrset.records[0].meta = Some(serde_json::Map::from_iter([(
            "notes".to_owned(),
            json!("set by hand"),
        )]));
    });
    let original = control.rrset(NAME, "TXT").unwrap();

    let ours = txt("ours");
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &ours)
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes::<F>(&mock), 0);
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &ours, None)
            .await
            .unwrap(),
        AddOutcome::Appended
    );
    let during = control.rrset(NAME, "TXT").unwrap();
    assert_eq!(during.ttl, 600);
    assert_eq!(
        control.txt_values(NAME),
        [
            "foreign",
            "foreign-disabled",
            "[\"two\",\"strings\"]",
            "ours"
        ]
    );
    let put = mock.log().matching(Some("PUT"), TXT_RRSET).pop().unwrap();
    let body = put.body_json().unwrap();
    assert_eq!(body["ttl"], 600);
    assert_eq!(body["resource_records"][0]["meta"]["notes"], "set by hand");
    assert_eq!(body["resource_records"][1]["enabled"], false);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &ours)
            .await
            .unwrap(),
        RemoveOutcome::Removed
    );
    let after = control.rrset(NAME, "TXT").unwrap();
    let strip = |records: &[Record]| -> Vec<String> {
        records
            .iter()
            .map(|r| {
                // The mock answers a record without metadata with `{}`, which travels back.
                let meta = r.meta.clone().filter(|m| !m.is_empty());
                format!("{:?} {} {meta:?}", r.content, r.enabled)
            })
            .collect()
    };
    assert_eq!(strip(&after.records), strip(&original.records));
    assert_eq!(after.ttl, original.ttl);

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_rrset("example.org", other, "TXT", 60, &[txt_content("foreign")]);
    let before = writes::<F>(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &ours)
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes::<F>(&mock), before);
    assert_eq!(control.txt_values(other), ["foreign"]);
}

pub async fn remove_last_value_deletes_rrset<F: Family>() {
    let (mock, client) = setup::<F>().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(F::control(&mock).rrsets().is_empty());
    assert_eq!(mock.log().count(Some("DELETE"), TXT_RRSET), 1);
    assert_eq!(mock.log().count(Some("PUT"), TXT_RRSET), 0);
}

pub async fn remove_is_idempotent<F: Family>() {
    let (mock, client) = setup::<F>().await;
    // No rrset at all.
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
    let before = writes::<F>(&mock);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes::<F>(&mock), before);
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert!(F::control(&mock).rrsets().is_empty());
}

/// Two clients sharing a `Context` add to one name at once, the first create delayed: both
/// values end up in the rrset. Without the name lock both would read "no rrset" and the second
/// create would be refused.
pub async fn concurrent_adds_are_serialized<F: Family>() {
    let mock = F::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with::<F>(&mock, TOKEN, &ctx);
    let b = client_with::<F>(&mock, TOKEN, &ctx);
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
    let mut values = F::control(&mock).txt_values(NAME);
    values.sort();
    assert_eq!(values, ["AAA", "BBB"]);
}

/// Every write is sent once: a 502, a 429 and a 401 on the create, the replacement and the
/// delete are the operation's error, with exactly one such request each; the repeat starts with
/// a read and converges. A repeated delete could remove a value another writer added after the
/// read.
pub async fn writes_are_sent_once<F: Family>() {
    let (mock, client) = setup::<F>().await;
    for (method, op) in [("POST", "add"), ("PUT", "add"), ("DELETE", "remove")] {
        if method == "PUT" {
            add(&client, "AAA").await.unwrap();
        }
        let mut sent = mock.log().count(Some(method), TXT_RRSET);
        for (fault, kind) in [
            (
                Fault::on(method, TXT_RRSET).status(502),
                ErrorKind::Transient,
            ),
            (
                Fault::on(method, TXT_RRSET).rate_limited("1"),
                ErrorKind::RateLimited,
            ),
            (Fault::on(method, TXT_RRSET).status(401), ErrorKind::Auth),
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
            assert_eq!(mock.log().count(Some(method), TXT_RRSET), sent, "{method}");
        }
    }
    assert_eq!(F::control(&mock).txt_values(NAME), ["AAA"]);

    // The delete is answered 502 and not applied; meanwhile another writer adds a value. The
    // repeat reads the new state and removes only our value.
    let hook = F::control(&mock).clone();
    mock.faults().push(
        Fault::on("DELETE", TXT_RRSET)
            .run(move || {
                hook.edit_rrset(NAME, "TXT", |rrset| {
                    let mut extra = rrset.records[0].clone();
                    extra.content = vec![json!("foreign")];
                    rrset.records.push(extra);
                });
            })
            .status(502),
    );
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(F::control(&mock).txt_values(NAME), ["AAA", "foreign"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(F::control(&mock).txt_values(NAME), ["foreign"]);

    // The record level: a create, a replacement and a delete are each sent once for a 502, a
    // 429 and a 401, and each failed write leaves the rrset as it was.
    let set = |texts: &[&str]| rrset(REC, RecordType::A, None, texts);
    let a_rrset = "/dns/v2/zones/*/*/A";
    for status in [502, 429, 401] {
        let control = F::control(&mock);
        control.delete_rrset(REC, "A");
        let expected = match status {
            429 => ErrorKind::RateLimited,
            401 => ErrorKind::Auth,
            _ => ErrorKind::Transient,
        };
        let inject = |method: &str| {
            if status == 429 {
                mock.faults()
                    .push(Fault::on(method, a_rrset).rate_limited("1"));
            } else {
                mock.faults()
                    .push(Fault::on(method, a_rrset).status(status));
            }
        };
        let posts = mock.log().count(Some("POST"), a_rrset);
        inject("POST");
        let e = client
            .set_rrset(&zone(), &set(&["192.0.2.1"]), Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected, "{status}: {e:?}");
        assert_eq!(mock.log().count(Some("POST"), a_rrset), posts + 1);
        assert!(control.rrset(REC, "A").is_none());
        client
            .set_rrset(&zone(), &set(&["192.0.2.1"]), Expect::Absent)
            .await
            .unwrap();

        let puts = mock.log().count(Some("PUT"), a_rrset);
        inject("PUT");
        let e = client
            .set_rrset(&zone(), &set(&["192.0.2.2"]), Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected, "{status}: {e:?}");
        assert_eq!(mock.log().count(Some("PUT"), a_rrset), puts + 1);
        assert_eq!(stored::<F>(&mock, REC, "A"), [json!(["192.0.2.1"])]);

        let deletes = mock.log().count(Some("DELETE"), a_rrset);
        inject("DELETE");
        let e = client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected, "{status}: {e:?}");
        assert_eq!(mock.log().count(Some("DELETE"), a_rrset), deletes + 1);
        assert_eq!(stored::<F>(&mock, REC, "A"), [json!(["192.0.2.1"])]);
    }
}

/// A delete answered 404 is a success only when a new read finds no rrset: removed meanwhile by
/// someone else, the rrset is gone; created again meanwhile, its value is still published, and
/// the answer is a retryable `Conflict`.
pub async fn delete_not_found_reads_again<F: Family>() {
    let (mock, client) = setup::<F>().await;
    let control = F::control(&mock);
    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("DELETE", TXT_RRSET).run(move || hook.delete_rrset(NAME, "TXT")));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.rrsets().is_empty());

    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(
        Fault::on("DELETE", TXT_RRSET)
            .run(move || {
                hook.delete_rrset(NAME, "TXT");
                hook.insert_rrset("example.org", NAME, "TXT", 300, &[json!(["AAA"])]);
            })
            .respond(404, r#"{"error":"rrset not found"}"#),
    );
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(control.txt_values(NAME), ["AAA"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.rrsets().is_empty());
}

/// `Expect::Absent` on an existing set and `Expect::Matches` on a changed one are
/// `PreconditionFailed` and write nothing; `Expect::Absent` on a delete is `InvalidInput`.
pub async fn failed_expectation_is_precondition_failed<F: Family>() {
    let (mock, client) = setup::<F>().await;
    let control = F::control(&mock);
    control.insert_rrset("example.org", REC, "A", 600, &[json!(["192.0.2.1"])]);
    let current = rrset(REC, RecordType::A, Some(600), &["192.0.2.1"]);
    let stale = rrset(REC, RecordType::A, Some(600), &["192.0.2.9"]);
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
    // A TTL in the expectation is compared too.
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
    // An expectation of a set that is not there.
    control.delete_rrset(REC, "A");
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Matches(&current))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    control.insert_rrset("example.org", REC, "A", 600, &[json!(["192.0.2.1"])]);
    assert_eq!(writes::<F>(&mock), 0);
    assert_eq!(stored::<F>(&mock, REC, "A"), [json!(["192.0.2.1"])]);
    // The expectation that holds goes through.
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&current))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
}

/// The listing holds every rrset of the zone, the provider's SOA and apex NS included, values
/// canonical where the content has the documented form; what the model cannot hold is skipped:
/// a dynamic rrset (pickers, metadata), an unknown type, a name the crate cannot hold, two
/// records of a singleton type. Disabled records are left out. One `WARN` event names the
/// number of skipped sets.
pub async fn listing_reports_skipped_sets<F: Family>() {
    let (capture, _guard) = LogCapture::install();
    let (mock, client) = setup::<F>().await;
    let control = F::control(&mock);
    control.insert_rrset(
        "example.org",
        "example.org",
        "SOA",
        3600,
        &[json!([
            "ns1.example.net",
            "hostmaster.example.org",
            1,
            7200,
            3600,
            1_209_600,
            300
        ])],
    );
    control.insert_rrset(
        "example.org",
        "example.org",
        "NS",
        3600,
        &[json!(["ns1.example.net"]), json!(["ns2.example.net"])],
    );
    control.insert_rrset(
        "example.org",
        REC,
        "A",
        300,
        &[
            json!(["192.0.2.1"]),
            json!(["192.0.2.2"]),
            json!(["192.0.2.3"]),
        ],
    );
    control.set_enabled(REC, "A", &json!(["192.0.2.3"]), false);
    control.insert_rrset("example.org", REC, "TXT", 600, &[json!(["v=spf1 -all"])]);
    control.insert_rrset(
        "example.org",
        "example.org",
        "MX",
        600,
        &[json!([10, "mail.example.org"])],
    );
    control.insert_rrset(
        "example.org",
        "odd.example.org",
        "A",
        600,
        &[json!(["not-an-address"])],
    );
    control.insert_rrset(
        "example.org",
        "w.example.org",
        "WIZARD",
        600,
        &[json!(["magic"])],
    );
    let long_label = format!("{}.example.org", "x".repeat(64));
    control.insert_rrset(
        "example.org",
        &long_label,
        "A",
        600,
        &[json!(["192.0.2.1"])],
    );
    control.insert_rrset(
        "example.org",
        "c.example.org",
        "CNAME",
        600,
        &[json!(["a.example.net"]), json!(["b.example.net"])],
    );
    control.insert_rrset(
        "example.org",
        "geo.example.org",
        "A",
        600,
        &[json!(["192.0.2.5"]), json!(["192.0.2.6"])],
    );
    control.edit_rrset("geo.example.org", "A", |rrset| {
        rrset.selection = vec![json!({"type": "geodns", "strict": true})];
    });
    control.insert_rrset(
        "example.org",
        "cdn.example.org",
        "CNAME",
        600,
        &[json!(["x.example.net"])],
    );
    control.edit_rrset("cdn.example.org", "CNAME", |rrset| {
        rrset.meta.insert("geodns_link".to_owned(), json!("link-1"));
    });
    control.insert_rrset(
        "example.org",
        "fs.example.org",
        "A",
        600,
        &[json!(["192.0.2.8"])],
    );
    control.edit_rrset("fs.example.org", "A", |rrset| rrset.filter_set_id = Some(3));
    // A type outside the record-level types is listed all the same (design section 3.4).
    control.insert_rrset(
        "example.org",
        "d.example.org",
        "DNAME",
        600,
        &[json!(["other.example.net"])],
    );
    // Another zone's rrset is not part of the listing.
    control.insert_zone("example.com");
    control.insert_rrset(
        "example.com",
        "other.example.com",
        "A",
        600,
        &[json!(["192.0.2.7"])],
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
            ("d.example.org.".to_owned(), RecordType::DNAME),
            ("example.org.".to_owned(), RecordType::NS),
            ("example.org.".to_owned(), RecordType::SOA),
            ("example.org.".to_owned(), RecordType::MX),
            ("odd.example.org.".to_owned(), RecordType::A),
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
        &rrset(REC, RecordType::A, Some(300), &["192.0.2.1", "192.0.2.2"])
    );
    assert_eq!(
        find(REC, RecordType::TXT),
        &rrset(REC, RecordType::TXT, Some(600), &["\"v=spf1 -all\""])
    );
    assert_eq!(
        find("example.org", RecordType::NS),
        &rrset(
            "example.org",
            RecordType::NS,
            Some(3600),
            &["ns1.example.net.", "ns2.example.net."]
        )
    );
    assert_eq!(
        find("example.org", RecordType::MX),
        &rrset(
            "example.org",
            RecordType::MX,
            Some(600),
            &["10 mail.example.org."]
        )
    );
    let odd = find("odd.example.org", RecordType::A);
    assert!(!odd.records()[0].is_canonical());
    assert_eq!(odd.records()[0].as_str(), "[\"not-an-address\"]");
    // One element per field, as the specs' rule says: read like any other type.
    assert_eq!(
        find("example.org", RecordType::SOA).records()[0],
        rd(
            RecordType::SOA,
            "ns1.example.net. hostmaster.example.org. 1 7200 3600 1209600 300"
        )
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
                "cdn.example.org.".to_owned(),
                "CNAME".to_owned(),
                SkipReason::NotPlainRecords
            ),
            (
                "example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::UnsupportedName
            ),
            (
                "fs.example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::NotPlainRecords
            ),
            (
                "geo.example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::NotPlainRecords
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
    assert_eq!(warnings[0].field("skipped"), Some("6"));
    assert_eq!(warnings[0].field("provider"), Some(F::ID.as_str()));
    assert_eq!(
        find("d.example.org", RecordType::DNAME),
        &rrset(
            "d.example.org",
            RecordType::DNAME,
            Some(600),
            &["other.example.net."]
        )
    );
    // One page, then the empty page that ends the listing.
    assert_eq!(mock.log().count(Some("GET"), RRSETS), 2);
}

// ---- TXT values --------------------------------------------------------------------------------

/// The first value creates the rrset with `POST`: the full name without the trailing dot in the
/// path, the configured TTL, the value as the one string of `content`, the record enabled.
/// Later values replace the rrset with `PUT`, carrying every record and the TTL as read.
pub async fn request_shapes<F: Family>() {
    let (mock, client) = setup::<F>().await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    let create = mock.log().matching(Some("POST"), TXT_RRSET).pop().unwrap();
    assert_eq!(
        create.path,
        "/dns/v2/zones/example.org/_acme-challenge.example.org/TXT"
    );
    assert_eq!(
        create.body_json().unwrap(),
        json!({"ttl": 300, "resource_records": [{"content": ["AAA"], "enabled": true}]})
    );
    F::control(&mock).edit_rrset(NAME, "TXT", |rrset| rrset.ttl = 120);
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    let put = mock.log().matching(Some("PUT"), TXT_RRSET).pop().unwrap();
    assert_eq!(
        put.body_json().unwrap(),
        json!({"ttl": 120, "resource_records": [
            {"content": ["AAA"], "enabled": true, "meta": {}},
            {"content": ["BBB"], "enabled": true}
        ]})
    );
    // The TTL of a new rrset: the caller's, else the setting.
    client
        .add_txt_value(
            &zone(),
            &dn("_acme-challenge.www.example.org"),
            &txt("CCC"),
            Some(RrsetTtl::from_secs(60).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        F::control(&mock)
            .rrset("_acme-challenge.www.example.org", "TXT")
            .unwrap()
            .ttl,
        60
    );
    // A wildcard and an internationalized name travel as A-labels, `*` percent-encoded.
    let idn = dn("_acme-challenge.пример.example.org");
    client
        .add_txt_value(&zone(), &idn, &txt("DDD"), None)
        .await
        .unwrap();
    let last = mock.log().matching(Some("POST"), TXT_RRSET).pop().unwrap();
    assert_eq!(
        last.path,
        "/dns/v2/zones/example.org/_acme-challenge.xn--e1afmkfd.example.org/TXT"
    );
    let wildcard = rrset("*.example.org", RecordType::A, None, &["192.0.2.1"]);
    client
        .set_rrset(&zone(), &wildcard, Expect::Any)
        .await
        .unwrap();
    let last = mock
        .log()
        .matching(Some("POST"), "/dns/v2/zones/*/*/A")
        .pop()
        .unwrap();
    assert_eq!(last.path, "/dns/v2/zones/example.org/%2A.example.org/A");
    assert_eq!(
        F::control(&mock).rrset("*.example.org", "A").unwrap().name,
        "*.example.org"
    );
}

/// A value being added that a disabled record holds is enabled instead of duplicated; a removal
/// leaves a disabled record with the value in place.
pub async fn add_enables_disabled_same_value<F: Family>() {
    let (mock, client) = setup::<F>().await;
    let control = F::control(&mock);
    control.insert_rrset(
        "example.org",
        NAME,
        "TXT",
        300,
        &[txt_content("AAA"), txt_content("other")],
    );
    control.set_enabled(NAME, "TXT", &txt_content("AAA"), false);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        control.contents(NAME, "TXT"),
        [(txt_content("AAA"), true), (txt_content("other"), true)]
    );
    control.set_enabled(NAME, "TXT", &txt_content("AAA"), false);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(
        control.contents(NAME, "TXT"),
        [(txt_content("AAA"), false), (txt_content("other"), true)]
    );
}

/// A dynamic rrset (pickers or filters, rrset metadata, or a non-zero `filter_set_id`, the last
/// an assumption of the client) is never read or written as an rrset: the TXT value operations
/// and the record level fail with `Rejected` after the read and write nothing. A zero
/// `filter_set_id` is a plain rrset.
pub async fn dynamic_rrsets_are_not_written<F: Family>() {
    let (mock, client) = setup::<F>().await;
    let control = F::control(&mock);
    control.insert_rrset("example.org", NAME, "TXT", 300, &[txt_content("foreign")]);
    control.edit_rrset(NAME, "TXT", |rrset| {
        rrset.selection = vec![json!({"type": "weighted_shuffle"})];
    });
    for e in [
        add(&client, "AAA").await.unwrap_err(),
        remove(&client, "foreign").await.unwrap_err(),
        client
            .get_rrset(&zone(), &name(), RecordType::TXT)
            .await
            .unwrap_err(),
        client
            .set_rrset(
                &zone(),
                &rrset(NAME, RecordType::TXT, None, &["\"x\""]),
                Expect::Any,
            )
            .await
            .unwrap_err(),
        client
            .delete_rrset(&zone(), &name(), RecordType::TXT, Expect::Any)
            .await
            .unwrap_err(),
    ] {
        assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    }
    control.edit_rrset(NAME, "TXT", |rrset| {
        rrset.selection.clear();
        rrset
            .meta
            .insert("failover".to_owned(), json!({"protocol": "ICMP"}));
    });
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    control.edit_rrset(NAME, "TXT", |rrset| {
        rrset.meta.clear();
        rrset.filter_set_id = Some(7);
    });
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let e = client
        .get_rrset(&zone(), &name(), RecordType::TXT)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(writes::<F>(&mock), 0);
    control.edit_rrset(NAME, "TXT", |rrset| rrset.filter_set_id = Some(0));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
}

/// TXT content in another form than one string is never a value of ours.
pub async fn txt_dialect<F: Family>() {
    let (mock, client) = setup::<F>().await;
    let control = F::control(&mock);
    control.insert_rrset(
        "example.org",
        NAME,
        "TXT",
        300,
        &[json!(["AAA", "BBB"]), json!([42])],
    );
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(add(&client, "AAABBB").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        stored::<F>(&mock, NAME, "TXT"),
        [json!(["AAA", "BBB"]), json!([42]), json!(["AAABBB"])]
    );
    // The record level reads the same records: the foreign forms are non-canonical data.
    let set = client
        .get_rrset(&zone(), &name(), RecordType::TXT)
        .await
        .unwrap()
        .unwrap();
    let canonical: Vec<bool> = set.records().iter().map(RecordData::is_canonical).collect();
    assert_eq!(canonical.iter().filter(|c| **c).count(), 1);
    assert!(set.records().contains(&txt("AAABBB").to_data().unwrap()));
}

/// A create that meets an rrset another writer created after the read is a retryable
/// `Conflict`: neither provider documents what such a create is answered with (the mock answers
/// `400` as Gcore, `409` as EdgeCenter), so after any refused create the client reads again, and
/// only an rrset found there makes the refusal a `Conflict`. A refusal with nothing there
/// afterwards, `409` included, is the provider's refusal with its message.
pub async fn create_race_is_conflict<F: Family>() {
    let (mock, client) = setup::<F>().await;
    let hook = F::control(&mock).clone();
    mock.faults()
        .push(Fault::on("POST", TXT_RRSET).pass().run(move || {
            hook.insert_rrset("example.org", NAME, "TXT", 300, &[json!(["foreign"])]);
        }));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(F::control(&mock).txt_values(NAME), ["foreign"]);
    // The read of the operation, and the read after the refused create.
    assert_eq!(mock.log().count(Some("GET"), TXT_RRSET), 2);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    assert_eq!(F::control(&mock).txt_values(NAME), ["foreign", "AAA"]);

    let a_rrset = "/dns/v2/zones/*/*/A";
    for status in [400, 409] {
        mock.log().clear();
        mock.faults().push(
            Fault::on("POST", a_rrset).respond(status, r#"{"error":"the request is not valid"}"#),
        );
        let e = client
            .set_rrset(
                &zone(),
                &rrset(REC, RecordType::A, None, &["192.0.2.1"]),
                Expect::Any,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(e, Error::Rejected { status: Some(s), .. } if s == status),
            "{e:?}"
        );
        assert!(e.to_string().contains("the request is not valid"), "{e}");
        assert_eq!(mock.log().count(Some("GET"), a_rrset), 2, "{status}");
        assert!(F::control(&mock).rrset(REC, "A").is_none());
    }
}

/// A replacement answered 404 means the rrset went away after the read: `Conflict`, nothing
/// written, and the repeat creates it.
pub async fn replacement_of_a_vanished_rrset_is_conflict<F: Family>() {
    let (mock, client) = setup::<F>().await;
    add(&client, "AAA").await.unwrap();
    let hook = F::control(&mock).clone();
    mock.faults()
        .push(Fault::on("PUT", TXT_RRSET).run(move || hook.delete_rrset(NAME, "TXT")));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(F::control(&mock).rrsets().is_empty());
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Created);
}

// ---- Zones -------------------------------------------------------------------------------------

/// `check` verifies the token with one page of the zone listing and looks every zone up: found,
/// missing, or disabled (found, with a remark).
pub async fn check_reports_zones<F: Family>() {
    let (mock, client) = setup::<F>().await;
    F::control(&mock).insert_zone("off.example.net");
    F::control(&mock).set_zone_enabled("off.example.net", false);
    let report = client
        .check(&[zone(), dn("missing.example.net"), dn("off.example.net")])
        .await
        .unwrap();
    assert!(report.credentials_verified);
    let found: Vec<bool> = report.zones.iter().map(|z| z.found).collect();
    assert_eq!(found, [true, false, true]);
    assert!(report.zones[0].detail.is_none());
    assert!(
        report.zones[2]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("disabled")
    );
    let probe = mock.log().matching(Some("GET"), ZONES);
    assert_eq!(probe.len(), 1);
    assert_eq!(probe[0].query.as_deref(), Some("limit=1"));
    assert_eq!(mock.log().count(Some("GET"), ZONE), 3);

    // No zone at all: the token is still verified.
    let report = client.check(&[]).await.unwrap();
    assert!(report.credentials_verified);

    let wrong = client_with::<F>(&mock, "wrong-token", &context());
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
}

/// Every zone, all pages, by offset; a listing that ends before its total is `Protocol`.
pub async fn list_zones_reads_every_page<F: Family>() {
    let (mock, client) = setup::<F>().await;
    for i in 0..4 {
        F::control(&mock).insert_zone(&format!("z{i}.example.net"));
    }
    F::control(&mock).set_page_size(2);
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
    let offsets: Vec<String> = mock
        .log()
        .matching(Some("GET"), ZONES)
        .iter()
        .map(|r| r.query.clone().unwrap_or_default())
        .collect();
    assert_eq!(offsets, ["offset=0", "offset=2", "offset=4"]);

    mock.faults().push(
        Fault::on("GET", ZONES)
            .skip(1)
            .respond(200, r#"{"zones":[],"total_amount":5}"#),
    );
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// The rrset listing reads every page; a listing that ends before its total is `Protocol`.
pub async fn listing_reads_every_page<F: Family>() {
    let (mock, client) = setup::<F>().await;
    for i in 0..5 {
        F::control(&mock).insert_rrset(
            "example.org",
            &format!("h{i}.example.org"),
            "A",
            300,
            &[json!(["192.0.2.1"])],
        );
    }
    F::control(&mock).set_page_size(2);
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(listing.rrsets.len(), 5);
    assert_eq!(mock.log().count(Some("GET"), RRSETS), 3);
    mock.faults().push(
        Fault::on("GET", RRSETS)
            .skip(1)
            .respond(200, r#"{"rrsets":null,"total_amount":5}"#),
    );
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// The listing ends correctly under every reading of the paging members the documentation
/// allows: a `total_amount` that counts the page only (the Gcore spec does not describe it) still
/// gives the whole listing, read until an empty page; a server that ignores `offset` and answers
/// the same page again is `Protocol`, not an endless loop; a listing that fits one page costs one
/// more request, for the empty page.
pub async fn listing_ends_under_every_paging_reading<F: Family>() {
    let (mock, client) = setup::<F>().await;
    let control = F::control(&mock);
    for i in 0..5 {
        control.insert_rrset(
            "example.org",
            &format!("h{i}.example.org"),
            "A",
            300,
            &[json!(["192.0.2.1"])],
        );
        control.insert_zone(&format!("z{i}.example.net"));
    }
    control.set_page_size(2);
    control.set_paging(Paging::PageCount);
    assert_eq!(client.list_rrsets(&zone()).await.unwrap().rrsets.len(), 5);
    assert_eq!(client.list_zones().await.unwrap().len(), 6);
    let offsets: Vec<String> = mock
        .log()
        .matching(Some("GET"), RRSETS)
        .iter()
        .map(|r| r.query.clone().unwrap_or_default())
        .collect();
    assert_eq!(offsets, ["offset=0", "offset=2", "offset=4", "offset=5"]);

    control.set_paging(Paging::IgnoreOffset);
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
    assert_eq!(mock.log().count(Some("GET"), RRSETS), 2);
}

/// The answer to a read of one rrset may leave out `name` and `type`, which the path states
/// (the EdgeCenter spec marks no member of `OutputRRSet` required); a name or a type other than
/// the one asked for is `Protocol`. In a listing, where they are the only identification, an item
/// without them is `Protocol`.
pub async fn single_rrset_answer_may_omit_name_and_type<F: Family>() {
    let (mock, client) = setup::<F>().await;
    mock.faults().push(Fault::on("GET", TXT_RRSET).respond(
        200,
        r#"{"ttl":300,"resource_records":[{"content":["v1"]}]}"#,
    ));
    assert_eq!(
        add(&client, "v1").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    mock.faults().push(Fault::on("GET", TXT_RRSET).respond(
        200,
        r#"{"name":"_acme-challenge.example.org","ttl":300,"resource_records":[{"content":["v1"]}]}"#,
    ));
    assert_eq!(
        add(&client, "v1").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    for body in [
        r#"{"name":"other.example.org","ttl":300,"resource_records":[]}"#,
        r#"{"type":"A","ttl":300,"resource_records":[]}"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", TXT_RRSET).respond(200, body));
        let e = add(&client, "v1").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    for body in [
        r#"{"rrsets":[{"type":"A","ttl":300,"resource_records":[]}],"total_amount":1}"#,
        r#"{"rrsets":[{"name":"a.example.org","ttl":300,"resource_records":[]}],"total_amount":1}"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", RRSETS).respond(200, body));
        let e = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    assert_eq!(writes::<F>(&mock), 0);
}

/// A zone the API does not know is `ZoneNotFound` for reads and writes, after the rrset read
/// answered 404 and the zone read confirmed it; nothing is written.
pub async fn zone_not_found<F: Family>() {
    let (mock, client) = setup::<F>().await;
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
    assert_eq!(writes::<F>(&mock), 0);
}

// ---- Transport ---------------------------------------------------------------------------------

/// A throttled read is retried and succeeds. (A throttled write is reported, not repeated:
/// `writes_are_sent_once`.)
pub async fn rate_limit<F: Family>() {
    let (mock, client) = setup::<F>().await;
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).rate_limited("0"));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.log().count(Some("GET"), TXT_RRSET), 2);
}

/// A 5xx on a read is retried, then `Transient`.
pub async fn server_errors_are_retried_then_transient<F: Family>() {
    let (mock, client) = setup::<F>().await;
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).times(3).status(503));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), TXT_RRSET), 3);
    assert_eq!(writes::<F>(&mock), 0);
}

/// Refusals: a 400 with the error body is `Rejected` with its message, a 403 is `Forbidden`, an
/// answer of an rrset other than the one asked for is `Protocol`.
pub async fn refusals_are_classified<F: Family>() {
    let (mock, client) = setup::<F>().await;
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).respond(400, r#"{"error":"rrset name is not valid"}"#));
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
    assert!(e.to_string().contains("rrset name is not valid"), "{e}");
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).respond(403, r#"{"error":"no access"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    mock.faults().push(Fault::on("GET", TXT_RRSET).respond(
        200,
        r#"{"name":"other.example.org","type":"TXT","ttl":300,"resource_records":[]}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults()
        .push(Fault::on("GET", TXT_RRSET).respond(200, r#"{"name":"x","type":"TXT"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes::<F>(&mock), 0);
}

// ---- Configuration -----------------------------------------------------------------------------

pub async fn from_json_builds_the_client<F: Family>() {
    let (mock, _) = setup::<F>().await;
    let settings = json!({ "base_url": F::base_url(&mock) }).to_string();
    let client = AnyProvider::from_json(
        F::ID,
        &settings,
        &SecretString::from(format!(r#"{{"api_token":"{TOKEN}"}}"#)),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), F::ID);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    // A minimal configuration: the credentials alone.
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = AnyProvider::from_json(
        F::ID,
        "{}",
        &SecretString::from(format!(r#"{{"api_token":"{TOKEN}"}}"#)),
        &ctx,
    )
    .unwrap();
    assert!(format!("{client:?}").contains(F::DEFAULT_URL));
}

/// Configuration errors name the key and never the value.
pub fn config_errors_name_no_value<F: Family>() {
    // Without `loopback_only`, so that the default endpoint is accepted.
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let canary = "canary-Value-9d1e";
    for (settings, credentials, key) in [
        (json!({"ttl": 0}), json!({"api_token": canary}), "ttl"),
        (
            json!({"ttl": "provider_default"}),
            json!({"api_token": canary}),
            "ttl",
        ),
        (
            json!({"base_url": format!("https://user:{canary}@example.net/dns")}),
            json!({"api_token": canary}),
            "base_url",
        ),
        (json!({}), json!({"api_token": "  "}), "api_token"),
        (json!({}), json!({"token": canary}), "api_token"),
        (json!({"zz": canary}), json!({"api_token": canary}), "line"),
    ] {
        let e = AnyProvider::from_json(
            F::ID,
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
    // A token with a character a header cannot carry is refused, without the token.
    let e = AnyProvider::from_json(
        F::ID,
        "{}",
        &SecretString::from(json!({ "api_token": format!("{canary}\nx") }).to_string()),
        &ctx,
    )
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
    assert!(!format!("{e} | {e:?}").contains(canary));
}

// ---- Record level ------------------------------------------------------------------------------

/// Every record type of the capabilities is written in the documented content form, read back
/// canonical, and an identical repeat is `Unchanged` without a write; the TTL is the rrset's.
pub async fn record_round_trips<F: Family>() {
    let (mock, client) = setup::<F>().await;
    for (owner, rtype, texts, wire) in [
        (
            "a.example.org",
            RecordType::A,
            vec!["192.0.2.1", "192.0.2.2"],
            json!([["192.0.2.1"], ["192.0.2.2"]]),
        ),
        (
            "a.example.org",
            RecordType::AAAA,
            vec!["2001:db8::1"],
            json!([["2001:db8::1"]]),
        ),
        (
            "www.example.org",
            RecordType::CNAME,
            vec!["target.example.net."],
            json!([["target.example.net"]]),
        ),
        (
            "sub.example.org",
            RecordType::NS,
            vec!["ns1.example.net.", "ns2.example.net."],
            json!([["ns1.example.net"], ["ns2.example.net"]]),
        ),
        (
            "example.org",
            RecordType::MX,
            vec!["10 mx1.example.org.", "20 mx2.example.org."],
            json!([[10, "mx1.example.org"], [20, "mx2.example.org"]]),
        ),
        (
            "_sip._tcp.example.org",
            RecordType::SRV,
            vec!["10 20 5060 sip.example.org."],
            json!([[10, 20, 5060, "sip.example.org"]]),
        ),
        (
            "example.org",
            RecordType::CAA,
            vec![
                "0 issue \"letsencrypt.org\"",
                "128 iodef \"mailto:sec@example.org\"",
            ],
            json!([
                [0, "issue", "letsencrypt.org"],
                [128, "iodef", "mailto:sec@example.org"]
            ]),
        ),
        (
            "t.example.org",
            RecordType::TXT,
            vec!["\"v=spf1 include:example.net -all\""],
            json!([["v=spf1 include:example.net -all"]]),
        ),
    ] {
        let set = rrset(owner, rtype, Some(600), &texts);
        assert_eq!(
            client
                .set_rrset(&zone(), &set, Expect::Absent)
                .await
                .unwrap(),
            SetOutcome::Created,
            "{owner} {rtype}"
        );
        let Value::Array(expected) = wire else {
            panic!("not an array")
        };
        assert_eq!(
            stored::<F>(&mock, owner, &rtype.to_string()),
            expected,
            "{owner} {rtype}"
        );
        let read = client
            .get_rrset(&zone(), &dn(owner), rtype)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, set, "{owner} {rtype}");
        let before = writes::<F>(&mock);
        assert_eq!(
            client
                .set_rrset(&zone(), &set, Expect::Matches(&read))
                .await
                .unwrap(),
            SetOutcome::Unchanged
        );
        assert_eq!(writes::<F>(&mock), before);
        // A new TTL alone is a replacement with every record kept.
        let longer = set
            .clone()
            .with_ttl(Some(RrsetTtl::from_secs(1200).unwrap()));
        assert_eq!(
            client
                .set_rrset(&zone(), &longer, Expect::Any)
                .await
                .unwrap(),
            SetOutcome::Replaced
        );
        assert_eq!(
            F::control(&mock)
                .rrset(owner, &rtype.to_string())
                .unwrap()
                .ttl,
            1200
        );
        // Without a TTL the existing one is kept.
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
            F::control(&mock)
                .rrset(owner, &rtype.to_string())
                .unwrap()
                .ttl,
            1200
        );
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(owner), rtype, Expect::Any)
                .await
                .unwrap(),
            DeleteOutcome::Deleted
        );
        assert!(F::control(&mock).rrset(owner, &rtype.to_string()).is_none());
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(owner), rtype, Expect::Any)
                .await
                .unwrap(),
            DeleteOutcome::NotPresent
        );
    }
}

/// Spellings another writer may store: names with a trailing dot, numbers as strings. Both read
/// as the same canonical value, and a set equal to them is `Unchanged`.
pub async fn reads_provider_spellings<F: Family>() {
    let (mock, client) = setup::<F>().await;
    F::control(&mock).insert_rrset(
        "example.org",
        "example.org",
        "MX",
        300,
        &[
            json!(["10", "mx1.example.org."]),
            json!([20, "mx2.example.org"]),
        ],
    );
    let wanted = rrset(
        "example.org",
        RecordType::MX,
        Some(300),
        &["10 mx1.example.org.", "20 mx2.example.org."],
    );
    let read = client
        .get_rrset(&zone(), &zone(), RecordType::MX)
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
    assert_eq!(writes::<F>(&mock), 0);
}

/// Values whose encoding no source establishes are not sent (`InvalidInput` after the read,
/// nothing written), unless the rrset holds them already, in which case they are written back as
/// read; non-canonical members are replaced, never matched.
pub async fn escapes_and_non_canonical_data<F: Family>() {
    let (mock, client) = setup::<F>().await;
    for (rtype, text) in [
        (RecordType::TXT, "\"quo\\\"te\""),
        (RecordType::TXT, "\" padded\""),
        (RecordType::CAA, "0 issue \"a\\\\b\""),
        (RecordType::MX, "0 ."),
    ] {
        let set = rrset(REC, rtype, None, &[text]);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{rtype} {text}: {e:?}");
    }
    assert_eq!(writes::<F>(&mock), 0);

    // A foreign record whose content the client cannot read is kept when a value is added.
    F::control(&mock).insert_rrset(
        "example.org",
        REC,
        "A",
        300,
        &[json!(["192.0.2.1"]), json!(["192.0.2.x"])],
    );
    let read = client
        .get_rrset(&zone(), &dn(REC), RecordType::A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        read.records().iter().filter(|r| r.is_canonical()).count(),
        1
    );
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored::<F>(&mock, REC, "A"), [json!(["192.0.2.1"])]);
}

/// The provider's own rrsets: SOA is not writable and the apex NS set is refused, before any
/// request; types outside the capabilities are `UnsupportedRecordType`, and nothing is sent.
pub async fn protected_sets_send_nothing<F: Family>() {
    let (mock, client) = setup::<F>().await;
    let soa = rrset(
        "example.org",
        RecordType::SOA,
        None,
        &["ns1.example.net. hostmaster.example.org. 1 7200 3600 1209600 300"],
    );
    let e = client
        .set_rrset(&zone(), &soa, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");
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
        (RecordType::PTR, "host.example.net."),
        (RecordType::TLSA, "3 1 1 0a1b"),
        (RecordType::HTTPS, "1 . alpn=h2"),
        (RecordType::DNAME, "target.example.net."),
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

/// A TTL the account's plan refuses is the provider's refusal (`Rejected`), after the read and
/// with one write; the client's own range is refused before any request.
pub async fn record_ttl_bounds<F: Family>() {
    let (mock, client) = setup::<F>().await;
    F::control(&mock).set_min_ttl(60);
    let set = rrset(REC, RecordType::A, Some(30), &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &set, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(writes::<F>(&mock), 1);
    let zero = RrSet::new(
        dn(REC),
        RecordType::A,
        Some(RrsetTtl::from_secs(0).unwrap()),
        [rd(RecordType::A, "192.0.2.1")],
    )
    .unwrap();
    let e = client
        .set_rrset(&zone(), &zero, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes::<F>(&mock), 1);
}

/// Two `set_rrset` calls on one name from two clients sharing a `Context` do not interleave:
/// the second reads what the first wrote.
pub async fn concurrent_sets_are_serialized<F: Family>() {
    let mock = F::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with::<F>(&mock, TOKEN, &ctx);
    let b = client_with::<F>(&mock, TOKEN, &ctx);
    mock.faults()
        .push(Fault::on("POST", "/dns/v2/zones/*/*/A").delay(Duration::from_millis(300)));
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
    assert_eq!(stored::<F>(&mock, REC, "A"), [json!(["192.0.2.2"])]);
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

fn live_client<F: Family>() -> (Arc<AnyProvider>, DomainName) {
    let settings = live_env(&format!("{}_SETTINGS", F::LIVE));
    let credentials = live_env(&format!("{}_CREDENTIALS", F::LIVE));
    let zone = dn(&live_env(&format!("{}_ZONE", F::LIVE)));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client =
        AnyProvider::from_json(F::ID, &settings, &SecretString::from(credentials), &ctx).unwrap();
    (Arc::new(client), zone)
}

/// Adds and removes two values under a generated label in the zone the maintainer names, and
/// removes exactly the values it added afterwards, also when the body failed.
pub async fn live_add_and_remove<F: Family>() {
    let (client, zone) = live_client::<F>();
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

/// A record-level round trip on an A rrset under a generated label (documentation addresses of
/// RFC 5737): create, read, replace with new records and a new TTL, unchanged repeat, list,
/// delete. The cleanup deletes that rrset, the only one the test wrote, also when the body
/// failed.
pub async fn live_record_round_trip<F: Family>() {
    let (client, zone) = live_client::<F>();
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
    // Cleanup: the A rrset under the generated label, the only one the test wrote.
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
/// `<LIVE>_ZONE`, under owner names that start with the label prefix of `<LIVE>_PREFIX` followed
/// by a random tag, it creates, reads back and deletes:
///
/// - MX, SRV and CAA sets: their `content` forms (`[10, "host"]`, `[prio, weight, port,
///   "target"]`, `[0, "issue", "value"]`), each read back equal to what was sent and repeated as
///   `Unchanged`, which also shows that names in `content` come back without a trailing dot or
///   with one, both read as absolute;
/// - a CNAME and a TXT value with a space inside (one string, the value itself);
/// - an A set at a wildcard owner (`*` in the path as `%2A`);
/// - a set created by one client while another, on a separate `Context`, creates the same name
///   and type: the second create meets an existing rrset, and the client's handling (a new read,
///   `Conflict` when it finds the set) must give `Created`, `Replaced` or `Conflict`, never
///   `Rejected`. The raw status of that refused create is not visible through the public API: it
///   is in the transport's `DEBUG` event (`status`), to be read with a `tracing` subscriber;
/// - `check` of the zone: the zone answer, flat or wrapped, is read;
/// - every set it created is found by `list_rrsets`; with more sets in the zone than one page of
///   the server holds, this pages, and a listing that ends early or repeats a page fails;
/// - reading the sets at all shows that a plain rrset carries no non-zero `filter_set_id` and no
///   rrset metadata (either would make the client refuse it).
///
/// Everything it created is deleted afterwards by name and type, also when a step failed; it
/// touches nothing else.
pub async fn live_assumptions<F: Family>() {
    let (client, zone) = live_client::<F>();
    let prefix = live_env(&format!("{}_PREFIX", F::LIVE));
    let tag = format!("{prefix}-{:016x}", random_u64());
    let owner = |label: &str| {
        zone.prepend(&tag)
            .and_then(|base| base.prepend(label))
            .unwrap()
    };
    let base = zone.prepend(&tag).unwrap();
    let wildcard = base.prepend("*").unwrap();
    let raced = owner("race");
    let sets: Vec<RrSet> = vec![
        RrSet::new(
            base.clone(),
            RecordType::MX,
            None,
            [rd(RecordType::MX, &format!("10 mx.{base}"))],
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
            base.clone(),
            RecordType::CAA,
            None,
            [rd(RecordType::CAA, "0 issue \"letsencrypt.org\"")],
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
    let body = {
        let (client, zone, sets, raced) =
            (client.clone(), zone.clone(), sets.clone(), raced.clone());
        tokio::spawn(async move {
            let report = client.check([&zone]).await.unwrap();
            assert!(report.zones[0].found, "{report:?}");
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
            // Two creates of one name and type from clients that do not share a lock.
            let (settings, credentials) = (
                live_env(&format!("{}_SETTINGS", F::LIVE)),
                live_env(&format!("{}_CREDENTIALS", F::LIVE)),
            );
            let other_ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
            let other = AnyProvider::from_json(
                F::ID,
                &settings,
                &SecretString::from(credentials),
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
    // Cleanup: exactly the sets this test created, by name and type.
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

// ---- Link to the DNS mock ----------------------------------------------------------------------

#[cfg(feature = "inspector")]
pub mod dns_link {
    use zonewright::{Expect, Provider, RecordType};
    use zonewright_mock::changes::ChangeSource;
    use zonewright_mock::dns::{DnsMock, Role};
    use zonewright_mock::link::{LinkOptions, link};

    use super::{Family, NAME, add, rrset, setup};
    use crate::common::link::{ask, is_absent, rd, txt, txt_round_trip, values};

    /// A value written through the client is served over DNS, and gone when removed.
    pub async fn txt_value_is_served_over_dns<F: Family>() {
        let (mock, client) = setup::<F>().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        txt_round_trip(&mock, &client, &dns).await;
    }

    /// Names inside values are published fully qualified, also where the API holds them without
    /// the trailing dot.
    pub async fn names_in_values_are_served_fully_qualified<F: Family>() {
        let (mock, client) = setup::<F>().await;
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
    pub async fn reset_returns_the_mock_to_its_seed<F: Family>() {
        let (mock, client) = setup::<F>().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = link(&mock, &dns, LinkOptions::new());
        add(&client, "before-reset").await.unwrap();
        link.settled().await;
        assert_eq!(
            values(ask(dns.addr(), NAME, RecordType::TXT).await),
            [txt("before-reset")]
        );
        F::control(&mock).reset();
        link.settled().await;
        assert!(F::control(&mock).rrsets().is_empty());
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
