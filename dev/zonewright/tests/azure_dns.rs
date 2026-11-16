//! Tests of the Azure DNS client (`azure_dns`) against its mock (`zonewright_mock::azure_dns`).
//! No network; fixtures are synthetic. The live tests at the end are `#[ignore]` and run only by
//! the maintainer.
#![cfg(feature = "azure_dns")]
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
use zonewright::providers::azure_dns::{AzureDns, AzureDnsConfig, AzureDnsCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl, SetOutcome,
    SkipReason, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::azure_dns::{AzureDnsMock, Paging, Seed};
use zonewright_mock::echo::{EchoServer, Echoed, Render};

use common::echo::{
    CANARY_KEY, CANARY_PASSWORD, Dialect, LogCapture, REDACTED, assert_clean, dialects,
};
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

assert_not_impl!(AzureDns: std::fmt::Display, serde::Serialize);
assert_not_impl!(AzureDnsCredentials: std::fmt::Display, serde::Serialize);

// ---- Fixtures ----------------------------------------------------------------------------------

/// The client secret of the standard seed.
const SECRET: &str = "test-only-secret";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// The owner name the record-level tests write to.
const REC: &str = "rec.example.org";

/// Path patterns of the mock.
const TOKEN_PATH: &str = "/*/oauth2/v2.0/token";
const ZONES: &str = "/subscriptions/*/resourceGroups/*/providers/Microsoft.Network/dnsZones";
const ZONE: &str = "/subscriptions/*/resourceGroups/*/providers/Microsoft.Network/dnsZones/*";
const RECORDSETS: &str =
    "/subscriptions/*/resourceGroups/*/providers/Microsoft.Network/dnsZones/*/recordsets";
const TXT_SET: &str =
    "/subscriptions/*/resourceGroups/*/providers/Microsoft.Network/dnsZones/*/TXT/*";
const ANY_SET: &str =
    "/subscriptions/*/resourceGroups/*/providers/Microsoft.Network/dnsZones/*/*/*";
const REC_A: &str =
    "/subscriptions/*/resourceGroups/*/providers/Microsoft.Network/dnsZones/*/A/rec";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// A TXT record object of one string.
fn txt_record(value: &str) -> Value {
    json!({ "value": [value] })
}

fn config_for(seed: &Seed, login: String, management: String) -> AzureDnsConfig {
    let mut config = AzureDnsConfig::new(
        seed.tenant_id.clone(),
        seed.client_id.clone(),
        seed.subscription_id.clone(),
        seed.resource_group.clone(),
    );
    config.login_url = login;
    config.management_url = management;
    config
}

fn client_for(mock: &AzureDnsMock, seed: &Seed, secret: &str, ctx: &Context) -> AzureDns {
    AzureDns::new(
        config_for(seed, mock.login_url(), mock.management_url()),
        AzureDnsCredentials::new(SecretString::from(secret.to_owned())),
        ctx,
    )
    .unwrap()
}

async fn setup() -> (AzureDnsMock, AzureDns) {
    let mock = AzureDnsMock::start(Seed::standard()).await;
    let client = client_for(&mock, &Seed::standard(), SECRET, &context());
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

/// Number of write requests the mock received: `PUT` and `DELETE` of record sets.
fn writes(mock: &AzureDnsMock) -> usize {
    let log = mock.log();
    log.count(Some("PUT"), ANY_SET) + log.count(Some("DELETE"), ANY_SET)
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

/// Every `PUT` and `DELETE` of a record set the server received carried exactly one condition:
/// `If-Match` or `If-None-Match` (a `DELETE` only `If-Match`).
fn assert_conditional(log: &zonewright_mock::RequestLog) {
    for entry in log.entries() {
        let write = entry.matches(Some("PUT"), ANY_SET) || entry.matches(Some("DELETE"), ANY_SET);
        if !write {
            continue;
        }
        let matched = entry.header("if-match").is_some();
        let none = entry.header("if-none-match") == Some("*");
        assert!(
            matched != none,
            "a write without exactly one condition: {entry:?}"
        );
        if entry.method == Method::DELETE {
            assert!(matched, "a delete without If-Match: {entry:?}");
        }
    }
}

/// The strings of the TXT records at [`NAME`].
fn stored_txt(mock: &AzureDnsMock) -> Vec<Vec<String>> {
    mock.control().txt(NAME)
}

fn strings(values: &[&str]) -> Vec<Vec<String>> {
    values.iter().map(|v| vec![(*v).to_owned()]).collect()
}

// ---- Secrets (design section 12.2) -------------------------------------------------------------

/// What the echo's record set read answers: no record set, one with a foreign value, or one
/// with the value `v1`.
#[derive(Clone, Copy, Debug)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
}

/// Which requests the echo answers like the API; the others are the echo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answered {
    /// None: the zone listing of `check` is the echo.
    Nothing,
    /// The zone listing, the zone and the record set reads: the request of the operation is
    /// the echo.
    Reads,
}

fn ok(body: Value) -> axum::response::Response {
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// A renderer that answers like the API what `answered` says, and every other request with
/// `errors`.
fn answering(errors: Render, existing: Existing, answered: Answered) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method != Method::GET {
            return errors(e);
        }
        let segments: Vec<&str> = e.path.trim_matches('/').split('/').collect();
        match (answered, segments.get(7..).unwrap_or_default()) {
            (Answered::Reads, []) => ok(json!({ "value": [{ "name": "example.org" }] })),
            (Answered::Reads, [zone]) => ok(json!({ "name": zone })),
            (Answered::Reads, [_, rtype, set]) => {
                let value = match existing {
                    Existing::Nothing => {
                        return (
                            StatusCode::NOT_FOUND,
                            axum::Json(json!({"error": {"code": "NotFound", "message": "x"}})),
                        )
                            .into_response();
                    }
                    Existing::Foreign => "foreign",
                    Existing::Ours => "v1",
                };
                ok(json!({
                    "name": set, "type": format!("Microsoft.Network/dnsZones/{rtype}"),
                    "etag": "e-1",
                    "properties": { "TTL": 3600, "TXTRecords": [{ "value": [value] }] },
                }))
            }
            _ => errors(e),
        }
    })
}

/// A client of the echo: Resource Manager below `/`, the identity platform below
/// `/echo-token`, which the echo answers with a token unless the case says otherwise.
fn echo_client(echo: &EchoServer, ctx: &Context) -> AzureDns {
    let seed = Seed::standard();
    AzureDns::new(
        config_for(&seed, echo.url("/echo-token"), echo.url("")),
        AzureDnsCredentials::new(SecretString::from(CANARY_PASSWORD.to_owned())),
        ctx,
    )
    .unwrap()
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

async fn run(client: &AzureDns, op: Op) -> Result<String, Error> {
    let ours = rrset(NAME, RecordType::TXT, None, &["\"v1\""]);
    match op {
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
    }
}

/// The canaries of the echo tests: the client secret and the token the echo issues.
fn echo_secrets(echo: &EchoServer) -> [String; 2] {
    [CANARY_PASSWORD.to_owned(), echo.issued_token().to_owned()]
}

fn assert_echo_clean(label: &str, text: &str, echo: &EchoServer) {
    let secrets = echo_secrets(echo);
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    assert_clean(label, text, &secrets);
}

/// Every case of one dialect, on a server of its own.
async fn echo_dialect(dialect: Dialect) {
    let ctx = context();
    let echo = EchoServer::start(200).await;
    // The token endpoint repeats the token request, client secret included.
    for status in [400, 401, 403] {
        let label = format!("{} {:?} {status} token", dialect.name, dialect.spelling);
        echo.reset(dialect.echo(status).token_path("/no-token-endpoint"));
        let client = echo_client(&echo, &ctx);
        let e = client.check(&[zone()]).await.unwrap_err();
        let text = format!("{e} | {e:?} | {client:?}");
        assert!(text.contains(REDACTED), "{label}: {text}");
        assert_echo_clean(&label, &text, &echo);
        assert_eq!(
            echo.log()
                .count(Some("POST"), "/echo-token/*/oauth2/v2.0/token"),
            1,
            "{label}"
        );
    }
    // The zone listing of `check`, with a token the echo issued.
    for status in [400, 401, 403, 404] {
        let label = format!("{} {:?} {status} zones", dialect.name, dialect.spelling);
        echo.reset(dialect.echo(status).render(answering(
            dialect.render.clone(),
            Existing::Nothing,
            Answered::Nothing,
        )));
        let client = echo_client(&echo, &ctx);
        let e = client.check(&[zone()]).await.unwrap_err();
        let text = format!("{e} | {e:?} | {client:?}");
        assert!(text.contains(REDACTED), "{label}: {text}");
        assert_echo_clean(&label, &text, &echo);
        // The token `check` obtained is cached, so a 401 replaces it once for the read.
        let expected = if status == 401 { 2 } else { 1 };
        assert_eq!(echo.log().count(Some("GET"), ZONES), expected, "{label}");
    }
    // The request of each operation. A 401 to a write is not repeated and ends in a constant
    // text (the cached token was refused), so it is covered by the reads.
    for (existing, op, statuses) in [
        (
            Existing::Nothing,
            Op::Add,
            [400, 403, 404, 409, 412, 500].as_slice(),
        ),
        (
            Existing::Foreign,
            Op::Add,
            [400, 403, 409, 412, 500].as_slice(),
        ),
        (Existing::Ours, Op::Remove, [400, 403, 412, 500].as_slice()),
        (Existing::Nothing, Op::List, [400, 401, 403].as_slice()),
        (Existing::Foreign, Op::Set, [400, 403, 412, 500].as_slice()),
        (Existing::Foreign, Op::Delete, [400, 403, 412].as_slice()),
    ] {
        for &status in statuses {
            let label = format!(
                "{} {:?} {status} {op:?} {existing:?}",
                dialect.name, dialect.spelling
            );
            echo.reset(dialect.echo(status).render(answering(
                dialect.render.clone(),
                existing,
                Answered::Reads,
            )));
            let client = echo_client(&echo, &ctx);
            let report = client.check(&[zone()]).await.unwrap();
            assert!(report.zones[0].found, "{label}");
            let text = match run(&client, op).await {
                Ok(outcome) => panic!("{label}: the echo accepted the operation: {outcome}"),
                Err(e) => format!("{e} | {e:?} | {client:?}"),
            };
            assert!(
                text.contains(REDACTED),
                "{label}: the echo did not reach the error: {text}"
            );
            assert_echo_clean(&label, &text, &echo);
            let (method, path) = match (op, existing) {
                (Op::Add | Op::Set, _) => ("PUT", TXT_SET),
                (Op::Remove | Op::Delete, _) => ("DELETE", TXT_SET),
                (Op::List, _) => ("GET", RECORDSETS),
            };
            // A refused cached token is replaced once for a read.
            let expected = if matches!(op, Op::List) && status == 401 {
                2
            } else {
                1
            };
            assert_eq!(
                echo.log().count(Some(method), path),
                expected,
                "{label}: the request did not reach the echo exactly once"
            );
            assert_conditional(echo.log());
        }
    }
}

/// The token request, `check` and every kind of request against an echo that repeats it, for
/// every dialect, each on a server of its own: the token endpoint answering with the client
/// secret echoed, the zone listing, and the write (or listing) of each operation. Every error
/// shows the redaction marker, no canary appears, and each echoed request was sent once.
#[tokio::test]
async fn azure_dns_secret_echo() {
    let tasks: Vec<_> = dialects()
        .into_iter()
        .map(|dialect| tokio::spawn(echo_dialect(dialect)))
        .collect();
    for task in tasks {
        if let Err(e) = task.await {
            std::panic::resume_unwind(e.into_panic());
        }
    }
}

/// A `TRACE` capture over successes, a 401 with a token the mock no longer accepts, a 500, an
/// expired token and a wrong secret: the transport's events are there, and no canary and no
/// issued token is.
#[tokio::test(flavor = "current_thread")]
async fn azure_dns_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.client_secret = CANARY_PASSWORD.into();
    let mock = AzureDnsMock::start(seed.clone()).await;
    let client = client_for(&mock, &seed, CANARY_PASSWORD, &context());
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
        .push(Fault::on("GET", TXT_SET).always().status(401));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("PUT", TXT_SET).status(500));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    mock.control().expire_tokens();
    add(&client, "v3").await.unwrap();

    let wrong = client_for(&mock, &seed, CANARY_KEY, &context());
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
            "azure_dns logs and errors",
            text,
            &[CANARY_PASSWORD, CANARY_KEY],
        );
        assert!(
            !text.contains("azure-mock-token"),
            "an issued token leaks: {text}"
        );
    }
    assert_conditional(mock.log());
}

/// The token request is the documented form at `/{tenant}/oauth2/v2.0/token` without an
/// `Authorization` header; every Resource Manager request carries the token as `Bearer` and
/// `api-version=2018-05-01`, and no secret in a path or a query.
#[tokio::test]
async fn azure_dns_request_shapes() {
    let (mock, client) = setup().await;
    client.check(&[zone()]).await.unwrap();
    add(&client, "v1").await.unwrap();
    client.list_rrsets(&zone()).await.unwrap();
    let entries = mock.log().entries();
    let token = entries
        .iter()
        .find(|e| e.matches(Some("POST"), TOKEN_PATH))
        .unwrap();
    assert_eq!(token.path, "/test-tenant.example/oauth2/v2.0/token");
    assert_eq!(token.header("authorization"), None);
    assert!(
        token
            .header("content-type")
            .unwrap()
            .starts_with("application/x-www-form-urlencoded")
    );
    assert_eq!(
        token.body_str(),
        "client_id=zw-test-client&scope=https%3A%2F%2Fmanagement.azure.com%2F%2F.default\
         &client_secret=test-only-secret&grant_type=client_credentials"
    );
    let api: Vec<_> = entries
        .iter()
        .filter(|e| e.path.starts_with("/subscriptions/"))
        .collect();
    assert!(api.len() >= 4, "{api:?}");
    for entry in api {
        assert_eq!(
            entry.header("authorization"),
            Some("Bearer azure-mock-token-1"),
            "{entry:?}"
        );
        assert_eq!(
            entry.query.as_deref(),
            Some("api-version=2018-05-01"),
            "{entry:?}"
        );
        assert!(entry.path.starts_with(
            "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/zw-test-rg/\
             providers/Microsoft.Network/dnsZones"
        ));
        assert!(!entry.contains(SECRET), "{entry:?}");
    }
    // The create carries `If-None-Match: *`, the documented body and the configured TTL.
    let put = mock.log().matching(Some("PUT"), TXT_SET).pop().unwrap();
    assert_eq!(put.header("if-none-match"), Some("*"));
    assert_eq!(put.header("if-match"), None);
    assert_eq!(
        put.body_json().unwrap(),
        json!({"properties": {"TTL": 60, "TXTRecords": [{"value": ["v1"]}]}})
    );
    assert!(
        put.path
            .ends_with("/dnsZones/example.org/TXT/_acme-challenge")
    );
    // A change carries `If-Match` with the etag read.
    let etag = mock.control().rrset(NAME, "TXT").unwrap().etag;
    add(&client, "v2").await.unwrap();
    let put = mock.log().matching(Some("PUT"), TXT_SET).pop().unwrap();
    assert_eq!(put.header("if-match"), Some(etag.as_str()));
    assert_eq!(put.header("if-none-match"), None);
    // Removing one of two values rewrites the set under its etag; removing the last deletes it
    // under the etag read just before.
    let etag = mock.control().rrset(NAME, "TXT").unwrap().etag;
    remove(&client, "v1").await.unwrap();
    let put = mock.log().matching(Some("PUT"), TXT_SET).pop().unwrap();
    assert_eq!(put.header("if-match"), Some(etag.as_str()));
    let etag = mock.control().rrset(NAME, "TXT").unwrap().etag;
    remove(&client, "v2").await.unwrap();
    let delete = mock.log().matching(Some("DELETE"), TXT_SET).pop().unwrap();
    assert_eq!(delete.header("if-match"), Some(etag.as_str()));
    assert_eq!(delete.header("if-none-match"), None);
    // The apex is `@` in a path.
    let apex = rrset(
        "example.org",
        RecordType::MX,
        None,
        &["10 mail.example.org."],
    );
    client.set_rrset(&zone(), &apex, Expect::Any).await.unwrap();
    let put = mock.log().matching(Some("PUT"), ANY_SET).pop().unwrap();
    assert!(put.path.ends_with("/dnsZones/example.org/MX/@"), "{put:?}");
    assert_conditional(mock.log());
}

/// One token serves every request until it is refused or due; `check` always obtains a new
/// one. A token the service refuses is replaced once for a read; for a write the operation
/// ends with `Transient` and its repeat obtains a new one.
#[tokio::test]
async fn azure_dns_token_is_cached_and_renewed() {
    let (mock, client) = setup().await;
    add(&client, "v1").await.unwrap();
    add(&client, "v2").await.unwrap();
    client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(mock.control().tokens_issued(), 1);
    client.check(&[zone()]).await.unwrap();
    assert_eq!(mock.control().tokens_issued(), 2);

    mock.control().expire_tokens();
    client
        .get_rrset(&zone(), &name(), RecordType::TXT)
        .await
        .unwrap();
    assert_eq!(mock.control().tokens_issued(), 3);

    // A write refused for its cached token is not repeated.
    mock.faults().push(Fault::on("PUT", TXT_SET).status(401));
    let puts = mock.log().count(Some("PUT"), TXT_SET);
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("PUT"), TXT_SET), puts + 1);
    assert_eq!(add(&client, "v3").await.unwrap(), AddOutcome::Appended);
    assert_eq!(mock.control().tokens_issued(), 4);
    assert_conditional(mock.log());
}

/// A wrong secret (`401 invalid_client`), another tenant and a scope the endpoint refuses
/// (`400`) are `Auth`, with the identity platform's description.
#[tokio::test]
async fn azure_dns_token_refusals_are_auth() {
    let mock = AzureDnsMock::start(Seed::standard()).await;
    let seed = Seed::standard();
    let wrong = client_for(&mock, &seed, "not-the-secret", &context());
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(e.to_string().contains("AADSTS7000215"), "{e}");
    let mut other = seed.clone();
    other.tenant_id = "other-tenant.example".into();
    let e = client_for(&mock, &other, SECRET, &context())
        .check(&[zone()])
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    let mut config = config_for(&seed, mock.login_url(), mock.management_url());
    config.scope = "https://management.azure.com/.default".into();
    let client = AzureDns::new(
        config,
        AzureDnsCredentials::new(SecretString::from(SECRET)),
        &context(),
    )
    .unwrap();
    let e = add(&client, "v1").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(e.to_string().contains("AADSTS70011"), "{e}");
    assert_eq!(writes(&mock), 0);
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request, token requests included.
#[tokio::test]
async fn azure_dns_name_outside_zone_sends_nothing() {
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
async fn azure_dns_add_is_idempotent() {
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
    assert_eq!(stored_txt(&mock), strings(&["AAA", "BBB"]));
    assert_conditional(mock.log());
}

/// Removing an absent value next to foreign ones writes nothing; adding and removing our value
/// leaves the foreign records (one with two strings, one outside the client's rule), the TTL and
/// the metadata as they were. A single foreign value is never a reason to delete the set.
#[tokio::test]
async fn azure_dns_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let foreign = json!([
        {"value": ["foreign"]},
        {"value": ["two", "strings"]},
        {"value": ["quo\"ted"]},
    ]);
    control.insert_rrset(NAME, "TXT", 7200, foreign.clone());
    control.edit_rrset(NAME, "TXT", |set| {
        set.properties
            .insert("metadata".into(), json!({"owner": "someone"}));
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
    assert_eq!(writes(&mock), 0);
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &ours, None)
            .await
            .unwrap(),
        AddOutcome::Appended
    );
    let during = control.rrset(NAME, "TXT").unwrap();
    assert_eq!(during.ttl(), Some(7200));
    let mut expected = foreign.as_array().unwrap().clone();
    expected.push(txt_record("ours"));
    assert_eq!(
        during.properties["TXTRecords"],
        Value::Array(expected.clone())
    );
    let put = mock.log().matching(Some("PUT"), TXT_SET).pop().unwrap();
    assert_eq!(
        put.body_json().unwrap(),
        json!({"properties": {
            "TTL": 7200, "metadata": {"owner": "someone"}, "TXTRecords": expected,
        }})
    );
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &ours)
            .await
            .unwrap(),
        RemoveOutcome::Removed
    );
    let after = control.rrset(NAME, "TXT").unwrap();
    assert_eq!(after.properties, original.properties);
    // "two" + "strings" is the value "twostrings", not "two".
    assert_eq!(
        remove(&client, "two").await.unwrap(),
        RemoveOutcome::NotPresent
    );

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_rrset(other, "TXT", 3600, json!([{"value": ["foreign"]}]));
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &ours)
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(control.txt(other), strings(&["foreign"]));
    assert_conditional(mock.log());
}

#[tokio::test]
async fn azure_dns_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().rrset(NAME, "TXT").is_none());
    assert_eq!(mock.log().count(Some("DELETE"), TXT_SET), 1);
    assert_eq!(mock.log().count(Some("PUT"), TXT_SET), 1);
    assert_conditional(mock.log());
}

#[tokio::test]
async fn azure_dns_remove_is_idempotent() {
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
    assert_conditional(mock.log());
}

/// Two clients sharing a `Context` add to one name at once, the first create delayed: both
/// values end up in the record set, without a refused condition.
#[tokio::test]
async fn azure_dns_concurrent_adds_are_serialized() {
    let mock = AzureDnsMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_for(&mock, &Seed::standard(), SECRET, &ctx);
    let b = client_for(&mock, &Seed::standard(), SECRET, &ctx);
    mock.faults()
        .push(Fault::on("PUT", TXT_SET).delay(Duration::from_millis(300)));
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
    assert_eq!(values, strings(&["AAA", "BBB"]));
    assert_eq!(mock.log().count(Some("PUT"), TXT_SET), 2);
    assert_conditional(mock.log());
}

/// Another writer changes the record set between the client's read and its write: the service
/// refuses the conditional write, the client reads again, sees another etag, and runs the
/// operation once more; the foreign value is kept. When the record set changes before every
/// write, the second refusal is `Conflict` and nothing of ours was written. The same for a
/// create meeting a record set created meanwhile, for a delete, and for `set_rrset`. The status
/// of a failed condition is not documented: the cases run under several, since the client
/// decides by its new read, not by the status.
#[tokio::test]
async fn azure_dns_concurrent_change_is_conflict() {
    for (status, code) in [
        (412, "PreconditionFailed"),
        (409, "Conflict"),
        (400, "BadRequest"),
    ] {
        concurrent_change(status, code).await;
    }
}

async fn concurrent_change(status: u16, code: &str) {
    let (mock, client) = setup().await;
    mock.control().set_failed_condition(status, code);
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("PUT", TXT_SET).pass().run(move || {
            hook.edit_rrset(NAME, "TXT", |set| {
                set.properties.insert(
                    "TXTRecords".into(),
                    json!([{"value": ["AAA"]}, {"value": ["foreign"]}]),
                );
            });
        }));
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    assert_eq!(stored_txt(&mock), strings(&["AAA", "foreign", "BBB"]));
    // Two PUTs: the refused one and the repeat; three reads of the set.
    assert_eq!(mock.log().count(Some("PUT"), TXT_SET), 3);

    // A change before every write: `Conflict` after the repeat.
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("PUT", TXT_SET).pass().always().run(move || {
            hook.edit_rrset(NAME, "TXT", |_| {});
        }));
    let puts = mock.log().count(Some("PUT"), TXT_SET);
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("PUT"), TXT_SET), puts + 2);
    assert_eq!(stored_txt(&mock), strings(&["AAA", "foreign", "BBB"]));
    // Removing one of three values is a rewrite, refused the same way.
    let puts = mock.log().count(Some("PUT"), TXT_SET);
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(mock.log().count(Some("PUT"), TXT_SET), puts + 2);
    assert_eq!(stored_txt(&mock), strings(&["AAA", "foreign", "BBB"]));
    mock.faults().clear();

    // The record level, and a delete under a changed set.
    mock.control()
        .insert_rrset(REC, "A", 3600, json!([{"ipv4Address": "192.0.2.1"}]));
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("DELETE", REC_A).pass().always().run(move || {
            hook.edit_rrset(REC, "A", |_| {});
        }));
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(mock.log().count(Some("DELETE"), REC_A), 2);
    assert!(mock.control().rrset(REC, "A").is_some());
    mock.faults().clear();

    // A create meets a record set another writer created after the read.
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("PUT", "**/TXT/other").pass().run(move || {
            hook.insert_rrset(
                "other.example.org",
                "TXT",
                300,
                json!([{"value": ["foreign"]}]),
            );
        }));
    let other = dn("other.example.org");
    assert_eq!(
        client
            .add_txt_value(&zone(), &other, &txt("ours"), None)
            .await
            .unwrap(),
        AddOutcome::Appended
    );
    assert_eq!(
        mock.control().txt("other.example.org"),
        strings(&["foreign", "ours"])
    );
    assert_eq!(
        mock.control()
            .rrset("other.example.org", "TXT")
            .unwrap()
            .ttl(),
        Some(300)
    );

    // `set_rrset` replacing a set another writer changes after the read: the repeat reads the
    // change; `Expect::Any` then writes over it, `Expect::Matches` of the first state fails.
    let first = rrset(REC, RecordType::A, Some(3600), &["192.0.2.1"]);
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    let changed = || {
        let hook = mock.control().clone();
        Fault::on("PUT", REC_A).pass().run(move || {
            hook.edit_rrset(REC, "A", |set| {
                set.properties
                    .insert("ARecords".into(), json!([{"ipv4Address": "192.0.2.9"}]));
            });
        })
    };
    mock.faults().push(changed());
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Matches(&first))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(
        mock.control().rrset(REC, "A").unwrap().records(),
        [json!({"ipv4Address": "192.0.2.9"})]
    );
    mock.control()
        .insert_rrset(REC, "A", 3600, json!([{"ipv4Address": "192.0.2.1"}]));
    mock.faults().push(changed());
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        mock.control().rrset(REC, "A").unwrap().records(),
        [json!({"ipv4Address": "192.0.2.2"})]
    );
    // `set_rrset` creating a set another writer creates after the read.
    let created = || {
        let hook = mock.control().clone();
        Fault::on("PUT", "**/A/new").pass().run(move || {
            hook.insert_rrset(
                "new.example.org",
                "A",
                600,
                json!([{"ipv4Address": "192.0.2.7"}]),
            );
        })
    };
    let new = rrset("new.example.org", RecordType::A, None, &["192.0.2.8"]);
    mock.faults().push(created());
    let e = client
        .set_rrset(&zone(), &new, Expect::Absent)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(
        mock.control()
            .rrset("new.example.org", "A")
            .unwrap()
            .records(),
        [json!({"ipv4Address": "192.0.2.7"})]
    );
    mock.control().delete_rrset("new.example.org", "A");
    mock.faults().push(created());
    assert_eq!(
        client.set_rrset(&zone(), &new, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        mock.control().rrset("new.example.org", "A").unwrap().ttl(),
        Some(600)
    );
    assert_conditional(mock.log());
}

/// Every write is sent once: a 502, a 429 (throttled, and the documented lock of another
/// operation) and a 401 on the create, the change and the delete are the operation's error,
/// with exactly one such request each; the repeat starts with a read and converges.
#[tokio::test]
async fn azure_dns_writes_are_sent_once() {
    let (mock, client) = setup().await;
    for (method, op) in [("PUT", "create"), ("PUT", "change"), ("DELETE", "remove")] {
        if op == "change" {
            add(&client, "AAA").await.unwrap();
        }
        let mut sent = mock.log().count(Some(method), TXT_SET);
        for (fault, kind) in [
            (Fault::on(method, TXT_SET).status(502), ErrorKind::Transient),
            (
                Fault::on(method, TXT_SET).rate_limited("1"),
                ErrorKind::RateLimited,
            ),
            (Fault::on(method, TXT_SET).status(401), ErrorKind::Transient),
        ] {
            mock.faults().push(fault);
            let e = match op {
                "remove" => remove(&client, "AAA").await.map(drop),
                _ => add(&client, "BBB").await.map(drop),
            }
            .unwrap_err();
            assert_eq!(e.kind(), kind, "{op}: {e:?}");
            sent += 1;
            assert_eq!(mock.log().count(Some(method), TXT_SET), sent, "{op}");
        }
        // The documented lock of another operation: `429` with its code.
        mock.control().set_locked(Some(2));
        let e = match op {
            "remove" => remove(&client, "AAA").await.map(drop),
            _ => add(&client, "BBB").await.map(drop),
        }
        .unwrap_err();
        assert!(
            matches!(
                e,
                Error::RateLimited {
                    retry_after: Some(d),
                    ..
                } if d == Duration::from_secs(2)
            ),
            "{op}: {e:?}"
        );
        assert_eq!(mock.log().count(Some(method), TXT_SET), sent + 1, "{op}");
        mock.control().set_locked(None);
        if op == "create" {
            assert!(mock.control().rrset(NAME, "TXT").is_none());
        }
    }
    assert_eq!(stored_txt(&mock), strings(&["AAA"]));

    // The delete is answered 502 and not applied; meanwhile another writer adds a value. The
    // repeat reads the new state and removes only our value.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("DELETE", TXT_SET)
            .run(move || {
                hook.edit_rrset(NAME, "TXT", |set| {
                    set.properties.insert(
                        "TXTRecords".into(),
                        json!([{"value": ["AAA"]}, {"value": ["foreign"]}]),
                    );
                });
            })
            .status(502),
    );
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(stored_txt(&mock), strings(&["foreign"]));

    // The record level: a create, a change and a delete are each sent once for a 502, a 429, a
    // 401 and a refusal the new read does not explain, and leave the record set as it was.
    let set = |texts: &[&str]| rrset(REC, RecordType::A, None, texts);
    for status in [502, 429, 401, 400] {
        let control = mock.control();
        control.delete_rrset(REC, "A");
        let expected = match status {
            429 => ErrorKind::RateLimited,
            400 => ErrorKind::Rejected,
            _ => ErrorKind::Transient,
        };
        let inject = |method: &str| {
            let fault = Fault::on(method, REC_A);
            mock.faults().push(match status {
                429 => fault.rate_limited("1"),
                400 => fault.respond(
                    400,
                    r#"{"error":{"code":"BadRequest","message":"refused"}}"#,
                ),
                _ => fault.status(status),
            });
        };
        let puts = mock.log().count(Some("PUT"), REC_A);
        inject("PUT");
        let e = client
            .set_rrset(&zone(), &set(&["192.0.2.1"]), Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected, "{status}: {e:?}");
        assert_eq!(mock.log().count(Some("PUT"), REC_A), puts + 1);
        assert!(control.rrset(REC, "A").is_none());
        client
            .set_rrset(&zone(), &set(&["192.0.2.1"]), Expect::Absent)
            .await
            .unwrap();

        let puts = mock.log().count(Some("PUT"), REC_A);
        inject("PUT");
        let e = client
            .set_rrset(&zone(), &set(&["192.0.2.2"]), Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected, "{status}: {e:?}");
        assert_eq!(mock.log().count(Some("PUT"), REC_A), puts + 1);
        assert_eq!(
            control.rrset(REC, "A").unwrap().records(),
            [json!({"ipv4Address": "192.0.2.1"})]
        );

        let deletes = mock.log().count(Some("DELETE"), REC_A);
        inject("DELETE");
        let e = client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), expected, "{status}: {e:?}");
        assert_eq!(mock.log().count(Some("DELETE"), REC_A), deletes + 1);
        assert!(control.rrset(REC, "A").is_some());
    }
    assert_conditional(mock.log());
}

/// `Expect::Absent` on an existing set and `Expect::Matches` on a changed one are
/// `PreconditionFailed` and write nothing; `Expect::Absent` on a delete is `InvalidInput`.
#[tokio::test]
async fn azure_dns_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(REC, "A", 7200, json!([{"ipv4Address": "192.0.2.1"}]));
    let current = rrset(REC, RecordType::A, Some(7200), &["192.0.2.1"]);
    let stale = rrset(REC, RecordType::A, Some(7200), &["192.0.2.9"]);
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    for e in [
        client
            .set_rrset(&zone(), &wanted, Expect::Absent)
            .await
            .unwrap_err(),
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&stale))
            .await
            .unwrap_err(),
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Matches(&stale))
            .await
            .unwrap_err(),
        client
            .set_rrset(
                &zone(),
                &wanted,
                Expect::Matches(&rrset(REC, RecordType::A, Some(3600), &["192.0.2.1"])),
            )
            .await
            .unwrap_err(),
    ] {
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    }
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
    assert_eq!(writes(&mock), 0);
    control.insert_rrset(REC, "A", 7200, json!([{"ipv4Address": "192.0.2.1"}]));
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&current))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let set = control.rrset(REC, "A").unwrap();
    assert_eq!(set.records(), [json!({"ipv4Address": "192.0.2.2"})]);
    assert_eq!(set.ttl(), Some(7200));
    assert_conditional(mock.log());
}

/// The listing holds every record set of the zone, the apex SOA and NS included, values
/// canonical where the record has the documented form; an alias is skipped as not plain, a name
/// the crate cannot hold as an unsupported name, and two records of a singleton type cannot be
/// one rrset. Content outside the client's rule is non-canonical. One `WARN` event names the
/// number of skipped sets.
#[tokio::test]
async fn azure_dns_listing_reports_skipped_sets() {
    let (capture, _guard) = LogCapture::install();
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(
        REC,
        "A",
        3600,
        json!([{"ipv4Address": "192.0.2.1"}, {"ipv4Address": "192.0.2.2"}]),
    );
    control.insert_rrset(
        REC,
        "TXT",
        7200,
        json!([{"value": ["v=spf1 -all"]}, {"value": ["a\\b"]}]),
    );
    control.insert_alias(
        "www.example.org",
        "A",
        60,
        "/subscriptions/x/resourceGroups/y/providers/Microsoft.Network/trafficManagerProfiles/z",
    );
    control.insert_rrset(
        "bad name.example.org",
        "A",
        60,
        json!([{"ipv4Address": "192.0.2.3"}]),
    );
    control.insert_rrset(
        "c.example.org",
        "CNAME",
        60,
        json!({"cname": "target.example.net"}),
    );
    // An empty record set lists as nothing.
    control.insert_rrset("empty.example.org", "TXT", 60, json!([]));
    // A type the stable API version does not have (the preview version's DS): its record
    // property is not documented for this version.
    control.insert_rrset("ds.example.org", "TXT", 60, json!([{"value": ["x"]}]));
    control.edit_rrset("ds.example.org", "TXT", |set| set.rtype = "DS".into());

    let listing = client.list_rrsets(&zone()).await.unwrap();
    let find = |name: &str, rtype: RecordType| {
        listing
            .rrsets
            .iter()
            .find(|s| s.name() == &dn(name) && s.rtype() == rtype)
            .cloned()
    };
    assert_eq!(
        find(REC, RecordType::A),
        Some(rrset(
            REC,
            RecordType::A,
            Some(3600),
            &["192.0.2.1", "192.0.2.2"]
        ))
    );
    let txt_set = find(REC, RecordType::TXT).unwrap();
    assert_eq!(txt_set.ttl(), Some(RrsetTtl::from_secs(7200).unwrap()));
    assert!(
        txt_set
            .records()
            .contains(&rd(RecordType::TXT, "\"v=spf1 -all\""))
    );
    assert_eq!(
        txt_set
            .records()
            .iter()
            .filter(|r| !r.is_canonical())
            .count(),
        1
    );
    assert!(find("example.org", RecordType::SOA).is_some());
    let ns = find("example.org", RecordType::NS).unwrap();
    assert_eq!(ns.records().len(), 4);
    assert!(
        ns.records()
            .contains(&rd(RecordType::NS, "ns1.dns-one.example."))
    );
    assert_eq!(
        find("c.example.org", RecordType::CNAME),
        Some(rrset(
            "c.example.org",
            RecordType::CNAME,
            Some(60),
            &["target.example.net."]
        ))
    );
    assert!(find("empty.example.org", RecordType::TXT).is_none());
    let skipped: Vec<(String, String, SkipReason)> = listing
        .skipped
        .iter()
        .map(|s| (s.name.to_string(), s.type_name.clone(), s.reason))
        .collect();
    assert_eq!(skipped.len(), 3, "{skipped:?}");
    assert!(skipped.contains(&(
        "ds.example.org.".to_owned(),
        "DS".to_owned(),
        SkipReason::NotPlainRecords
    )));
    assert!(skipped.contains(&(
        "www.example.org.".to_owned(),
        "A".to_owned(),
        SkipReason::NotPlainRecords
    )));
    assert!(skipped.contains(&(
        "example.org.".to_owned(),
        "A".to_owned(),
        SkipReason::UnsupportedName
    )));
    let warnings: Vec<_> = capture
        .entries()
        .into_iter()
        .filter(|e| e.level == tracing::Level::WARN && e.target == "zonewright::rrsets")
        .collect();
    assert_eq!(warnings.len(), 1, "{}", capture.text());
    assert_eq!(warnings[0].field("skipped"), Some("3"));

    // Two records in a CNAME property that holds one object: an answer the client cannot read.
    control.insert_rrset(
        "c.example.org",
        "CNAME",
        60,
        json!([{"cname": "a.example.net"}, {"cname": "b.example.net"}]),
    );
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// An alias record set is refused by every operation on its name and type after the read,
/// before any write; a record set with a property the client does not know is read but not
/// written.
#[tokio::test]
async fn azure_dns_protected_sets_send_nothing() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_alias("www.example.org", "A", 60, "/subscriptions/x/resource");
    let www = dn("www.example.org");
    let set = rrset("www.example.org", RecordType::A, None, &["192.0.2.1"]);
    for e in [
        client
            .get_rrset(&zone(), &www, RecordType::A)
            .await
            .unwrap_err(),
        client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err(),
        client
            .delete_rrset(&zone(), &www, RecordType::A, Expect::Any)
            .await
            .unwrap_err(),
    ] {
        assert!(matches!(e, Error::Rejected { status: None, .. }), "{e:?}");
    }
    control.insert_rrset(NAME, "TXT", 60, json!([{"value": ["foreign"]}]));
    control.edit_rrset(NAME, "TXT", |set| {
        set.properties
            .insert("futureFeature".into(), json!({"x": 1}));
    });
    let read = client
        .get_rrset(&zone(), &name(), RecordType::TXT)
        .await
        .unwrap();
    assert!(read.is_some());
    let e = add(&client, "ours").await.unwrap_err();
    assert!(matches!(e, Error::Rejected { status: None, .. }), "{e:?}");
    let e = client
        .set_rrset(
            &zone(),
            &rrset(NAME, RecordType::TXT, None, &["\"x\""]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Rejected { status: None, .. }), "{e:?}");
    assert_eq!(writes(&mock), 0);

    // The apex NS and SOA are not written.
    let ns = rrset("example.org", RecordType::NS, None, &["ns.example.net."]);
    let e = client
        .set_rrset(&zone(), &ns, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &zone(), RecordType::SOA, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");
    let e = client
        .get_rrset(&zone(), &zone(), RecordType::TLSA)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// A refusal carries `error.code` of the `CloudError` as the provider code, after the new read
/// shows that no concurrent change explains it.
#[tokio::test]
async fn azure_dns_refusal_carries_the_provider_code() {
    let (mock, client) = setup().await;
    // The mock refuses a CNAME next to other data with its code.
    mock.control()
        .insert_rrset(REC, "A", 60, json!([{"ipv4Address": "192.0.2.1"}]));
    let cname = rrset(REC, RecordType::CNAME, None, &["target.example.net."]);
    let e = client
        .set_rrset(&zone(), &cname, Expect::Any)
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            Error::Rejected {
                status: Some(409),
                ..
            }
        ),
        "{e:?}"
    );
    assert_eq!(e.provider_code().map(|c| c.as_str()), Some("Conflict"));
    // A refusal the documentation leaves open, injected.
    mock.faults().push(Fault::on("PUT", TXT_SET).respond(
        400,
        r#"{"error":{"code":"InvalidTxtRecord","message":"The TXT record is not valid.","details":[]}}"#,
    ));
    let e = add(&client, "v1").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(
        e.provider_code().map(|c| c.as_str()),
        Some("InvalidTxtRecord")
    );
    assert!(
        e.to_string().contains("The TXT record is not valid."),
        "{e}"
    );
    assert_conditional(mock.log());
}

/// A code that holds the client secret, in any spelling the scrubber knows, is dropped; the
/// message is scrubbed.
#[tokio::test]
async fn azure_dns_provider_code_never_carries_a_credential() {
    let secret = "zwSecretCode42";
    let mut seed = Seed::standard();
    seed.client_secret = secret.into();
    let mock = AzureDnsMock::start(seed.clone()).await;
    let client = client_for(&mock, &seed, secret, &context());
    for code in [secret.to_owned(), secret.to_uppercase(), hex(secret)] {
        mock.faults().push(Fault::on("PUT", TXT_SET).respond(
            400,
            json!({"error": {"code": code, "message": format!("bad {secret}")}}).to_string(),
        ));
        let e = add(&client, "v1").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
        assert_eq!(e.provider_code(), None, "{code}: {e:?}");
        let text = format!("{e} | {e:?}");
        assert!(text.contains(REDACTED), "{text}");
        assert!(!text.contains(secret), "{text}");
    }
    assert_conditional(mock.log());
}

fn hex(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

// ---- Zones -------------------------------------------------------------------------------------

/// `check` obtains a new token and lists the zones of the resource group; `list_zones` reads
/// every page.
#[tokio::test]
async fn azure_dns_check_and_list_zones() {
    let (mock, client) = setup().await;
    for zone in ["b.example", "a.example", "c.example"] {
        mock.control().insert_zone(zone);
    }
    mock.control().set_page_size(1);
    let report = client
        .check(&[zone(), dn("missing.example")])
        .await
        .unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones[0].found);
    assert!(!report.zones[1].found);
    assert_eq!(mock.log().count(Some("POST"), TOKEN_PATH), 1);
    assert_eq!(mock.log().count(Some("GET"), ZONES), 4);
    let zones: Vec<String> = client
        .list_zones()
        .await
        .unwrap()
        .iter()
        .map(|z| z.name.to_string())
        .collect();
    assert_eq!(
        zones,
        ["a.example.", "b.example.", "c.example.", "example.org."]
    );
    // Every page after the first carries `$skipToken`, spelled as the documentation does.
    let pages = mock.log().matching(Some("GET"), ZONES);
    assert!(
        pages
            .iter()
            .any(|p| p.query.as_deref() == Some("api-version=2018-05-01&$skipToken=2")),
        "{pages:?}"
    );
}

/// The listings end under every paging reading the documentation allows, and fail on the
/// readings that would not end: a link without `$skipToken`, a token that does not advance, a
/// page that repeats.
#[tokio::test]
async fn azure_dns_listing_ends_under_every_paging_reading() {
    let (mock, client) = setup().await;
    for i in 0..5 {
        mock.control().insert_rrset(
            &format!("h{i}.example.org"),
            "A",
            60,
            json!([{"ipv4Address": "192.0.2.1"}]),
        );
    }
    mock.control().set_page_size(2);
    // SOA, NS and five A sets: four pages.
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(listing.rrsets.len(), 7);
    assert_eq!(mock.log().count(Some("GET"), RECORDSETS), 4);
    mock.control().set_paging(Paging::EmptyLastPage);
    assert_eq!(client.list_rrsets(&zone()).await.unwrap().rrsets.len(), 7);
    // An empty page that carries a `nextLink` is not the end.
    mock.control().set_paging(Paging::EmptyPageBetween);
    assert_eq!(client.list_rrsets(&zone()).await.unwrap().rrsets.len(), 7);
    // The zone listing pages the same way: five zones, pages of two.
    for zone in ["a.example", "b.example", "c.example", "d.example"] {
        mock.control().insert_zone(zone);
    }
    for (paging, text) in [
        (Paging::IgnoreToken, "repeated a page"),
        (Paging::RepeatToken, "did not advance"),
        (Paging::NoTokenInLink, "nextLink"),
    ] {
        mock.control().set_paging(paging);
        let e = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{paging:?}: {e:?}");
        assert!(e.to_string().contains(text), "{paging:?}: {e}");
        let e = client.list_zones().await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{paging:?}: {e:?}");
        assert!(e.to_string().contains(text), "{paging:?}: {e}");
    }
    mock.control().set_paging(Paging::EmptyPageBetween);
    assert_eq!(client.list_zones().await.unwrap().len(), 5);
}

/// A zone the resource group does not hold is `ZoneNotFound` for the reads and the writes; a
/// zone removed between the read and the write is found out by the new read after the refusal.
#[tokio::test]
async fn azure_dns_zone_not_found() {
    let (mock, client) = setup().await;
    let other = dn("other.example");
    let e = client
        .get_rrset(&other, &dn("www.other.example"), RecordType::A)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    // The record set read, then the zone read that tells the two apart.
    assert_eq!(mock.log().count(Some("GET"), ZONE), 1);
    let e = client.list_rrsets(&other).await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let e = client
        .add_txt_value(
            &other,
            &dn("_acme-challenge.other.example"),
            &txt("v"),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("PUT", TXT_SET)
            .pass()
            .run(move || hook.remove_zone("example.org")),
    );
    let e = add(&client, "v1").await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    assert_eq!(writes(&mock), 1);
    assert_conditional(mock.log());
}

/// Throttled reads are repeated after `Retry-After`; a throttle longer than the transport waits
/// is `RateLimited`. A 5xx to a read is repeated and then `Transient`.
#[tokio::test]
async fn azure_dns_throttled_and_failing_reads() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", TXT_SET).rate_limited("0"));
    assert!(
        client
            .get_rrset(&zone(), &name(), RecordType::TXT)
            .await
            .unwrap()
            .is_none()
    );
    mock.control().set_throttled(Some(120));
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert!(
        matches!(e, Error::RateLimited { retry_after: Some(d), .. } if d == Duration::from_secs(120)),
        "{e:?}"
    );
    mock.control().set_throttled(None);
    mock.log().clear();
    mock.faults()
        .push(Fault::on("GET", RECORDSETS).times(3).status(503));
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), RECORDSETS), 3);
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn azure_dns_from_json_builds_the_client() {
    let (mock, _) = setup().await;
    let seed = Seed::standard();
    let settings = json!({
        "tenant_id": seed.tenant_id, "client_id": seed.client_id,
        "subscription_id": seed.subscription_id, "resource_group": seed.resource_group,
        "management_url": mock.management_url(), "login_url": mock.login_url(), "ttl": 7200,
    })
    .to_string();
    let client = AnyProvider::from_json(
        ProviderId::AzureDns,
        &settings,
        &SecretString::from(json!({ "client_secret": SECRET }).to_string()),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::AzureDns);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.control().rrset(NAME, "TXT").unwrap().ttl(), Some(7200));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let minimal = json!({
        "tenant_id": "t", "client_id": "c", "subscription_id": "s", "resource_group": "g",
    });
    let client = AnyProvider::from_json(
        ProviderId::AzureDns,
        &minimal.to_string(),
        &SecretString::from(json!({ "client_secret": SECRET }).to_string()),
        &ctx,
    )
    .unwrap();
    let debug = format!("{client:?}");
    assert!(debug.contains("https://management.azure.com"), "{debug}");
    assert!(
        debug.contains("https://login.microsoftonline.com"),
        "{debug}"
    );
    assert!(
        debug.contains("https://management.azure.com//.default"),
        "{debug}"
    );
    assert!(!debug.contains(SECRET), "{debug}");
    assert_conditional(mock.log());
}

/// Configuration errors name the key and never the value.
#[test]
fn azure_dns_config_errors_name_no_value() {
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let canary = "canary-Value-9d1e";
    let base = json!({
        "tenant_id": "t", "client_id": "c", "subscription_id": "s", "resource_group": "g",
    });
    let with = |key: &str, value: Value| {
        let mut settings = base.clone();
        settings[key] = value;
        settings
    };
    for (settings, credentials, key) in [
        (
            with("ttl", json!(0)),
            json!({"client_secret": canary}),
            "ttl",
        ),
        (
            with("ttl", json!("provider_default")),
            json!({"client_secret": canary}),
            "ttl",
        ),
        (
            with("tenant_id", json!(format!("{canary}/x"))),
            json!({"client_secret": canary}),
            "tenant_id",
        ),
        (
            with("subscription_id", json!(format!("{canary} x"))),
            json!({"client_secret": canary}),
            "subscription_id",
        ),
        (
            with("resource_group", json!(format!("{canary}/x"))),
            json!({"client_secret": canary}),
            "resource_group",
        ),
        (
            with("client_id", json!(format!("{canary} x"))),
            json!({"client_secret": canary}),
            "client_id",
        ),
        (
            with("scope", json!(format!("{canary} x"))),
            json!({"client_secret": canary}),
            "scope",
        ),
        (
            with(
                "management_url",
                json!(format!("https://user:{canary}@example.net")),
            ),
            json!({"client_secret": canary}),
            "management_url",
        ),
        (
            with("login_url", json!(format!("http://{canary}.example.net"))),
            json!({"client_secret": canary}),
            "login_url",
        ),
        (base.clone(), json!({"client_secret": ""}), "client_secret"),
        (base.clone(), json!({"secret": canary}), "client_secret"),
        (
            with("zz", json!(canary)),
            json!({"client_secret": canary}),
            "line",
        ),
    ] {
        let e = AnyProvider::from_json(
            ProviderId::AzureDns,
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
}

// ---- Record level ------------------------------------------------------------------------------

/// Every writable type is written in the documented form, read back canonical, and an identical
/// repeat is `Unchanged` without a write; the TTL is the record set's, a new set gets the
/// configured one, and a replacement keeps the `metadata`.
#[tokio::test]
async fn azure_dns_record_round_trips() {
    let (mock, client) = setup().await;
    let long = format!("\"{}\" \"{}\"", "x".repeat(255), "x".repeat(45));
    let sets = [
        rrset(REC, RecordType::A, Some(300), &["192.0.2.1", "192.0.2.2"]),
        rrset(REC, RecordType::AAAA, None, &["2001:db8::1"]),
        rrset(
            REC,
            RecordType::CAA,
            None,
            &[
                "0 issue \"letsencrypt.org\"",
                "128 iodef \"mailto:x@example.org\"",
            ],
        ),
        rrset(
            "alias.example.org",
            RecordType::CNAME,
            None,
            &["target.example.net."],
        ),
        rrset(
            REC,
            RecordType::MX,
            None,
            &["10 mail.example.org.", "20 mx2.example.net."],
        ),
        rrset(
            "deleg.example.org",
            RecordType::NS,
            None,
            &["ns1.example.net."],
        ),
        rrset(
            "1.example.org",
            RecordType::PTR,
            None,
            &["host.example.org."],
        ),
        rrset(
            "_sip._tcp.example.org",
            RecordType::SRV,
            None,
            &["10 20 5060 sip.example.org."],
        ),
        rrset(
            REC,
            RecordType::TXT,
            None,
            &["\"v=spf1 include:example.net -all\"", &long],
        ),
        rrset("*.wild.example.org", RecordType::A, None, &["192.0.2.9"]),
    ];
    for set in &sets {
        let what = format!("{} {}", set.name(), set.rtype());
        assert_eq!(
            client
                .set_rrset(&zone(), set, Expect::Absent)
                .await
                .unwrap(),
            SetOutcome::Created,
            "{what}"
        );
        let read = client
            .get_rrset(&zone(), set.name(), set.rtype())
            .await
            .unwrap()
            .unwrap();
        assert!(set.same_records(&read), "{what}: {read:?}");
        let ttl = set.ttl().unwrap_or(RrsetTtl::from_secs(60).unwrap());
        assert_eq!(read.ttl(), Some(ttl), "{what}");
        let before = writes(&mock);
        assert_eq!(
            client
                .set_rrset(&zone(), &read, Expect::Matches(&read))
                .await
                .unwrap(),
            SetOutcome::Unchanged,
            "{what}"
        );
        assert_eq!(writes(&mock), before, "{what}");
    }
    let stored = mock.control().rrset(REC, "TXT").unwrap();
    assert_eq!(
        stored.records()[1],
        json!({"value": ["x".repeat(255), "x".repeat(45)]})
    );
    assert!(mock.control().rrset("*.wild.example.org", "A").is_some());
    let listing = client.list_rrsets(&zone()).await.unwrap();
    for set in &sets {
        let ttl = set.ttl().or(Some(RrsetTtl::from_secs(60).unwrap()));
        assert!(
            listing.rrsets.contains(&set.clone().with_ttl(ttl)),
            "{set:?} {listing:?}"
        );
    }

    // A replacement keeps the metadata and states the TTL as read.
    mock.control().edit_rrset(REC, "A", |set| {
        set.properties
            .insert("metadata".into(), json!({"team": "dns"}));
    });
    let replaced = rrset(REC, RecordType::A, None, &["192.0.2.3"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &replaced, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let stored = mock.control().rrset(REC, "A").unwrap();
    assert_eq!(stored.properties["metadata"], json!({"team": "dns"}));
    assert_eq!(stored.ttl(), Some(300));
    let put = mock.log().matching(Some("PUT"), REC_A).pop().unwrap();
    assert_eq!(
        put.body_json().unwrap(),
        json!({"properties": {
            "TTL": 300, "metadata": {"team": "dns"}, "ARecords": [{"ipv4Address": "192.0.2.3"}],
        }})
    );
    assert_eq!(
        client
            .delete_rrset(
                &zone(),
                &dn(REC),
                RecordType::A,
                Expect::Matches(&stored_a())
            )
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(mock.control().rrset(REC, "A").is_none());
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
    assert_conditional(mock.log());
}

fn stored_a() -> RrSet {
    rrset(REC, RecordType::A, Some(300), &["192.0.2.3"])
}

/// TXT values with spaces and longer than 255 octets are sent as split strings; a value with
/// `"`, `\` or bytes outside printable ASCII is refused before any request, by both levels.
#[tokio::test]
async fn azure_dns_txt_values_and_their_rule() {
    let (mock, client) = setup().await;
    let long = "y".repeat(300);
    assert_eq!(
        add(&client, "with space").await.unwrap(),
        AddOutcome::Created
    );
    assert_eq!(add(&client, &long).await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        stored_txt(&mock),
        [
            vec!["with space".to_owned()],
            vec!["y".repeat(255), "y".repeat(45)],
        ]
    );
    assert_eq!(
        add(&client, &long).await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        remove(&client, &long).await.unwrap(),
        RemoveOutcome::Removed
    );
    let before = mock.log().len();
    for value in ["quo\"te", "back\\slash", "ключ", ""] {
        let e = client
            .add_txt_value(&zone(), &name(), &Txt::new(value).unwrap(), None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
    }
    assert_eq!(mock.log().len(), before);
    let set = RrSet::new(
        dn(REC),
        RecordType::TXT,
        None,
        [Txt::new("quo\"te").unwrap().to_data().unwrap()],
    )
    .unwrap();
    let e = client
        .set_rrset(&zone(), &set, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), 3);
    assert_conditional(mock.log());
}

/// A TXT record set without records (kept by the service for its metadata) takes an added value
/// under its etag, metadata kept.
#[tokio::test]
async fn azure_dns_empty_txt_set_is_written_into() {
    let (mock, client) = setup().await;
    mock.control().insert_rrset(NAME, "TXT", 900, json!([]));
    mock.control().edit_rrset(NAME, "TXT", |set| {
        set.properties.insert("metadata".into(), json!({"k": "v"}));
    });
    let etag = mock.control().rrset(NAME, "TXT").unwrap().etag;
    assert_eq!(add(&client, "v1").await.unwrap(), AddOutcome::Created);
    let put = mock.log().matching(Some("PUT"), TXT_SET).pop().unwrap();
    assert_eq!(put.header("if-match"), Some(etag.as_str()));
    let stored = mock.control().rrset(NAME, "TXT").unwrap();
    assert_eq!(stored.properties["metadata"], json!({"k": "v"}));
    assert_eq!(stored.ttl(), Some(60));
    assert_eq!(stored_txt(&mock), strings(&["v1"]));
    assert_conditional(mock.log());
}

/// Two `set_rrset` calls on one name from two clients sharing a `Context` do not interleave.
#[tokio::test]
async fn azure_dns_concurrent_sets_are_serialized() {
    let mock = AzureDnsMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_for(&mock, &Seed::standard(), SECRET, &ctx);
    let b = client_for(&mock, &Seed::standard(), SECRET, &ctx);
    mock.faults()
        .push(Fault::on("PUT", REC_A).delay(Duration::from_millis(300)));
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
    assert_eq!(
        mock.control().rrset(REC, "A").unwrap().records(),
        [json!({"ipv4Address": "192.0.2.2"})]
    );
    assert_conditional(mock.log());
}

// ---- Conditions and their edges ----------------------------------------------------------------

/// A record set read without an etag, or with an empty one, is never written: every operation
/// that would write ends in `Protocol` before any `PUT` or `DELETE`.
#[tokio::test]
async fn azure_dns_set_without_etag_is_not_written() {
    for etag in [None, Some("")] {
        let (mock, client) = setup().await;
        let answer = |name: &str, rtype: &str, key: &str, records: Value| {
            let mut body = json!({
                "name": name,
                "type": format!("Microsoft.Network/dnsZones/{rtype}"),
                "properties": { "TTL": 60, key: records },
            });
            if let Some(etag) = etag {
                body["etag"] = Value::from(etag);
            }
            body.to_string()
        };
        let txt_answer = answer(
            "_acme-challenge",
            "TXT",
            "TXTRecords",
            json!([{"value": ["v1"]}]),
        );
        let a_answer = answer(
            "rec",
            "A",
            "ARecords",
            json!([{"ipv4Address": "192.0.2.1"}]),
        );
        let mut errors = Vec::new();
        mock.faults()
            .push(Fault::on("GET", TXT_SET).respond(200, txt_answer.clone()));
        errors.push(add(&client, "v2").await.unwrap_err());
        mock.faults()
            .push(Fault::on("GET", TXT_SET).respond(200, txt_answer.clone()));
        errors.push(remove(&client, "v1").await.unwrap_err());
        mock.faults()
            .push(Fault::on("GET", REC_A).respond(200, a_answer.clone()));
        errors.push(
            client
                .set_rrset(
                    &zone(),
                    &rrset(REC, RecordType::A, None, &["192.0.2.2"]),
                    Expect::Any,
                )
                .await
                .unwrap_err(),
        );
        mock.faults()
            .push(Fault::on("GET", REC_A).respond(200, a_answer.clone()));
        errors.push(
            client
                .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
                .await
                .unwrap_err(),
        );
        for e in errors {
            assert_eq!(e.kind(), ErrorKind::Protocol, "{etag:?}: {e:?}");
        }
        assert_eq!(writes(&mock), 0, "{etag:?}");
    }
}

/// Removing the last value deletes the record set under its etag. When another writer adds a
/// value before the `DELETE` arrives, the service refuses it, the new read shows the foreign
/// value, and the repeat rewrites the set without ours: the foreign value stays. When the set
/// changes before every `DELETE`, the result is `Conflict` and the set is intact.
#[tokio::test]
async fn azure_dns_last_value_delete_racing_a_foreign_add() {
    let (mock, client) = setup().await;
    add(&client, "v1").await.unwrap();
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("DELETE", TXT_SET).pass().run(move || {
            hook.edit_rrset(NAME, "TXT", |set| {
                set.properties.insert(
                    "TXTRecords".into(),
                    json!([{"value": ["v1"]}, {"value": ["foreign"]}]),
                );
            });
        }));
    assert_eq!(remove(&client, "v1").await.unwrap(), RemoveOutcome::Removed);
    assert_eq!(stored_txt(&mock), strings(&["foreign"]));
    assert_eq!(mock.log().count(Some("DELETE"), TXT_SET), 1);
    assert_eq!(mock.log().count(Some("PUT"), TXT_SET), 2);

    mock.control().delete_rrset(NAME, "TXT");
    add(&client, "v1").await.unwrap();
    let hook = mock.control().clone();
    mock.faults()
        .push(Fault::on("DELETE", TXT_SET).pass().always().run(move || {
            hook.edit_rrset(NAME, "TXT", |_| {});
        }));
    let deletes = mock.log().count(Some("DELETE"), TXT_SET);
    let e = remove(&client, "v1").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(mock.log().count(Some("DELETE"), TXT_SET), deletes + 2);
    assert_eq!(stored_txt(&mock), strings(&["v1"]));
    assert_conditional(mock.log());
}

/// The answers a write can meet when the state changed under it: a `DELETE` answered `204`
/// because the set vanished meanwhile is done; a `DELETE` meeting a zone removed meanwhile is
/// `ZoneNotFound`; a `PUT` with `If-Match` on a set removed meanwhile is refused, and the
/// repeat creates the set.
#[tokio::test]
async fn azure_dns_writes_meet_a_changed_state() {
    let (mock, client) = setup().await;
    add(&client, "v1").await.unwrap();
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("DELETE", TXT_SET)
            .pass()
            .run(move || hook.delete_rrset(NAME, "TXT")),
    );
    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    mock.control()
        .insert_rrset(REC, "A", 60, json!([{"ipv4Address": "192.0.2.1"}]));
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("DELETE", REC_A)
            .pass()
            .run(move || hook.delete_rrset(REC, "A")),
    );
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );

    // A replace whose set another writer removed: refused, read again, created.
    add(&client, "v1").await.unwrap();
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("PUT", TXT_SET)
            .pass()
            .run(move || hook.delete_rrset(NAME, "TXT")),
    );
    let puts = mock.log().count(Some("PUT"), TXT_SET);
    assert_eq!(add(&client, "v2").await.unwrap(), AddOutcome::Created);
    assert_eq!(stored_txt(&mock), strings(&["v2"]));
    assert_eq!(mock.log().count(Some("PUT"), TXT_SET), puts + 2);
    let puts = mock.log().matching(Some("PUT"), TXT_SET);
    assert!(puts[puts.len() - 2].header("if-match").is_some());
    assert_eq!(puts[puts.len() - 1].header("if-none-match"), Some("*"));

    // A delete meeting a zone removed meanwhile.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("DELETE", TXT_SET)
            .pass()
            .run(move || hook.remove_zone("example.org")),
    );
    let e = remove(&client, "v2").await.unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    assert_conditional(mock.log());
}

/// A replacement sends exactly `TTL`, the kept `metadata` and the type's records: an empty
/// `targetResource`, a `null` `metadata` and empty lists of other types carry nothing and are
/// left out; the read-only `fqdn` and `provisioningState` are never sent.
#[tokio::test]
async fn azure_dns_replacement_body_is_exact() {
    let (mock, client) = setup().await;
    mock.control()
        .insert_rrset(NAME, "TXT", 60, json!([{"value": ["foreign"]}]));
    mock.control().edit_rrset(NAME, "TXT", |set| {
        set.properties.insert("targetResource".into(), json!({}));
        set.properties.insert("metadata".into(), Value::Null);
        set.properties.insert("ARecords".into(), json!([]));
        set.properties.insert("CNAMERecord".into(), Value::Null);
    });
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    let put = mock.log().matching(Some("PUT"), TXT_SET).pop().unwrap();
    assert_eq!(
        put.body_json().unwrap(),
        json!({"properties": {
            "TTL": 60, "TXTRecords": [{"value": ["foreign"]}, {"value": ["ours"]}],
        }})
    );
    assert_conditional(mock.log());
}

/// The etag goes back byte for byte, a quoted and a weak one included; one that cannot be a
/// header value is `Protocol` with nothing written.
#[tokio::test]
async fn azure_dns_etag_spellings() {
    let (mock, client) = setup().await;
    add(&client, "v1").await.unwrap();
    for (etag, value) in [("\"q-1\"", "v2"), ("W/\"w-1\"", "v3")] {
        mock.control().set_etag(NAME, "TXT", etag);
        assert_eq!(add(&client, value).await.unwrap(), AddOutcome::Appended);
        let put = mock.log().matching(Some("PUT"), TXT_SET).pop().unwrap();
        assert_eq!(put.header("if-match"), Some(etag));
    }
    mock.control().set_etag(NAME, "TXT", "bad\netag");
    let before = writes(&mock);
    let e = add(&client, "v4").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), before);
    assert_conditional(mock.log());
}

/// More writes sent once: the lock of another operation at the record level, the rewrite that
/// removes one value, a `500` on the last-value delete, a `503`, and a write that times out.
#[tokio::test]
async fn azure_dns_more_writes_are_sent_once() {
    let (mock, client) = setup().await;
    mock.control().set_locked(Some(1));
    let puts = mock.log().count(Some("PUT"), REC_A);
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.1"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(mock.log().count(Some("PUT"), REC_A), puts + 1);
    mock.control().set_locked(None);

    add(&client, "AAA").await.unwrap();
    add(&client, "BBB").await.unwrap();
    mock.faults().push(Fault::on("PUT", TXT_SET).status(503));
    let puts = mock.log().count(Some("PUT"), TXT_SET);
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("PUT"), TXT_SET), puts + 1);
    remove(&client, "AAA").await.unwrap();

    mock.faults().push(Fault::on("DELETE", TXT_SET).status(500));
    let e = remove(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("DELETE"), TXT_SET), 1);
    assert_eq!(stored_txt(&mock), strings(&["BBB"]));

    // A write that times out is not repeated.
    let mut options = zonewright::ContextOptions::default();
    options.loopback_only = true;
    options.request_timeout = Duration::from_millis(300);
    let ctx = Context::new(options).unwrap();
    let slow = client_for(&mock, &Seed::standard(), SECRET, &ctx);
    mock.faults()
        .push(Fault::on("PUT", TXT_SET).delay(Duration::from_millis(1500)));
    let puts = mock.log().count(Some("PUT"), TXT_SET);
    let e = add(&slow, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("PUT"), TXT_SET), puts + 1);
    assert_conditional(mock.log());
}

/// The answers of the token endpoint the client reads: an empty token and a token of another
/// type are `Protocol`; `expires_in` as text is read; a `5xx` is repeated, then `Transient`.
/// The credentials type prints no secret.
#[tokio::test]
async fn azure_dns_token_answers() {
    let (mock, client) = setup().await;
    for body in [
        json!({"access_token": "", "token_type": "Bearer", "expires_in": 3599}),
        json!({"access_token": "t", "token_type": "MAC", "expires_in": 3599}),
        json!({"token_type": "Bearer"}),
    ] {
        mock.faults()
            .push(Fault::on("POST", TOKEN_PATH).respond(200, body.to_string()));
        let e = client.check(&[zone()]).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    // `expires_in` as text: the token (one the mock issued to another client) is used.
    let other = client_for(&mock, &Seed::standard(), SECRET, &context());
    other.check(&[zone()]).await.unwrap();
    mock.faults().push(Fault::on("POST", TOKEN_PATH).respond(
        200,
        json!({"access_token": "azure-mock-token-1", "token_type": "Bearer", "expires_in": "3599"})
            .to_string(),
    ));
    client.list_zones().await.unwrap();
    mock.log().clear();
    mock.faults()
        .push(Fault::on("POST", TOKEN_PATH).times(3).status(503));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("POST"), TOKEN_PATH), 3);
    let credentials = AzureDnsCredentials::new(SecretString::from(SECRET));
    assert!(!format!("{credentials:?}").contains(SECRET));
}

/// A listing whose `nextLink` names another host still reads every page from the configured
/// endpoint, with the link's `$skipToken`: the other host gets no request.
#[tokio::test]
async fn azure_dns_next_link_host_is_never_requested() {
    let (mock, client) = setup().await;
    let other = AzureDnsMock::start(Seed::standard()).await;
    for i in 0..5 {
        mock.control().insert_rrset(
            &format!("h{i}.example.org"),
            "A",
            60,
            json!([{"ipv4Address": "192.0.2.1"}]),
        );
    }
    mock.control().set_page_size(2);
    mock.control().set_link_base(Some(&other.management_url()));
    assert_eq!(client.list_rrsets(&zone()).await.unwrap().rrsets.len(), 7);
    assert!(other.log().is_empty(), "{:?}", other.log().entries());
    let pages = mock.log().matching(Some("GET"), RECORDSETS);
    assert_eq!(pages.len(), 4);
    assert_eq!(
        pages[1].query.as_deref(),
        Some("api-version=2018-05-01&$skipToken=2")
    );
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
    async fn azure_dns_txt_value_is_served_over_dns() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        txt_round_trip(&mock, &client, &dns).await;
    }

    /// Names inside values are published fully qualified.
    #[tokio::test]
    async fn azure_dns_names_in_values_are_served() {
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
    async fn azure_dns_reset_returns_the_mock_to_its_seed() {
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
        assert_eq!(
            mock.control().rrsets().len(),
            2,
            "the apex SOA and NS of the seed"
        );
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

/// A client from `ZONEWRIGHT_LIVE_AZURE_DNS_SETTINGS` and `…_CREDENTIALS` (the settings and
/// credentials JSON objects) on a context of its own.
fn live_client() -> Arc<AnyProvider> {
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = AnyProvider::from_json(
        ProviderId::AzureDns,
        &live_env("ZONEWRIGHT_LIVE_AZURE_DNS_SETTINGS"),
        &SecretString::from(live_env("ZONEWRIGHT_LIVE_AZURE_DNS_CREDENTIALS")),
        &ctx,
    )
    .unwrap();
    Arc::new(client)
}

/// The live check of what the client assumes and no source settles. In the zone of
/// `ZONEWRIGHT_LIVE_AZURE_DNS_ZONE`, under owner names that start with the label prefix of
/// `ZONEWRIGHT_LIVE_AZURE_DNS_PREFIX` followed by a random tag, it:
///
/// - checks the zone and a zone the resource group does not hold (`check`);
/// - reads a record set that does not exist (`404` read as "none") and a record set in a zone
///   the resource group does not hold (the zone read's `404` read as `ZoneNotFound`);
/// - adds and removes TXT values with a space and of 300 octets (a space stands for itself; the
///   client splits the strings) and reads them back;
/// - creates, reads back and repeats as `Unchanged` one set of every writable type: names in
///   records written without the trailing dot and read back as absolute, CAA values, a wildcard
///   owner (`*` in the path as `%2A`, assumed to be decoded);
/// - adds values to one name from two clients on separate contexts at once: every add that
///   succeeds is in the record set afterwards, and the others end in `Conflict`, never in a lost
///   value (the service enforces `If-Match` and `If-None-Match: *`);
/// - lists the zone and finds every set it created.
///
/// Not covered: the status of a failed condition (the client does not depend on it: it reads
/// again after any refusal), and the answer to a delete of a record set that changed.
///
/// Everything it created is deleted afterwards by name and type, also when a step failed; what
/// the cleanup could not remove is listed in the failure. It touches nothing else.
#[tokio::test]
#[ignore = "live API; run only by the maintainer"]
async fn azure_dns_live_assumptions() {
    let client = live_client();
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_AZURE_DNS_ZONE"));
    let prefix = live_env("ZONEWRIGHT_LIVE_AZURE_DNS_PREFIX");
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
        set(owner("deleg"), RecordType::NS, "ns1.example.net."),
        set(owner("p"), RecordType::PTR, &format!("host.{base}")),
        set(owner("v6"), RecordType::AAAA, "2001:db8::1"),
        set(owner("txt"), RecordType::TXT, "\"two words\""),
        set(base.prepend("*").unwrap(), RecordType::A, "192.0.2.20"),
    ];
    let values_name = owner("_values");
    let raced = owner("_race");
    let mut created: Vec<(DomainName, RecordType)> =
        sets.iter().map(|s| (s.name().clone(), s.rtype())).collect();
    created.push((values_name.clone(), RecordType::TXT));
    created.push((raced.clone(), RecordType::TXT));
    let body = {
        let (client, zone, sets, values_name, raced, tag) = (
            client.clone(),
            zone.clone(),
            sets.clone(),
            values_name.clone(),
            raced.clone(),
            tag.clone(),
        );
        tokio::spawn(async move {
            let (c, z) = (&*client, &zone);
            let not_held = dn("zw-not-held.invalid");
            let report = c.check([z, &not_held]).await.unwrap();
            assert!(report.zones[0].found, "{report:?}");
            assert!(!report.zones[1].found, "{report:?}");
            assert_eq!(
                c.get_rrset(z, &values_name, RecordType::TXT).await.unwrap(),
                None
            );
            let e = c
                .get_rrset(&not_held, &not_held, RecordType::A)
                .await
                .unwrap_err();
            assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");

            let long = "y".repeat(300);
            for value in ["with space", long.as_str()] {
                c.add_txt_value(z, &values_name, &txt(value), None)
                    .await
                    .unwrap();
            }
            let read = c
                .get_rrset(z, &values_name, RecordType::TXT)
                .await
                .unwrap()
                .unwrap();
            let expected = RrSet::new(
                values_name.clone(),
                RecordType::TXT,
                None,
                [
                    txt("with space").to_data().unwrap(),
                    txt(&long).to_data().unwrap(),
                ],
            )
            .unwrap();
            assert!(read.same_records(&expected), "{read:?}");
            assert!(
                read.records().iter().all(RecordData::is_canonical),
                "{read:?}"
            );
            for value in ["with space", long.as_str()] {
                c.remove_txt_value(z, &values_name, &txt(value))
                    .await
                    .unwrap();
            }

            for set in &sets {
                let what = format!("{} {}", set.name(), set.rtype());
                assert_eq!(
                    c.set_rrset(z, set, Expect::Absent).await.unwrap(),
                    SetOutcome::Created,
                    "{what}"
                );
                let read = c
                    .get_rrset(z, set.name(), set.rtype())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(set.same_records(&read), "{what}: {read:?}");
                assert_eq!(
                    c.set_rrset(z, &read, Expect::Matches(&read)).await.unwrap(),
                    SetOutcome::Unchanged,
                    "{what}"
                );
            }

            // Two clients on separate contexts: the per-name lock does not serialize them,
            // only the service's conditions do.
            let other = live_client();
            let adds = |client: Arc<AnyProvider>, side: &'static str| {
                let (zone, raced, tag) = (zone.clone(), raced.clone(), tag.clone());
                async move {
                    let mut out = Vec::new();
                    for i in 0..3 {
                        let value = txt(&format!("zw-live-{tag}-{side}{i}"));
                        let result = client.add_txt_value(&zone, &raced, &value, None).await;
                        out.push((value, result));
                    }
                    out
                }
            };
            let (a, b) = tokio::join!(adds(client.clone(), "a"), adds(other, "b"));
            let read = c
                .get_rrset(z, &raced, RecordType::TXT)
                .await
                .unwrap()
                .unwrap();
            for (value, result) in a.into_iter().chain(b) {
                match result {
                    Ok(_) => assert!(
                        read.contains(&value.to_data().unwrap()),
                        "{value:?} was lost: {read:?}"
                    ),
                    Err(e) => assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}"),
                }
            }

            let listing = c.list_rrsets(z).await.unwrap();
            for set in &sets {
                assert!(
                    listing
                        .rrsets
                        .iter()
                        .any(|s| s.name() == set.name() && s.same_records(set)),
                    "{set:?}"
                );
            }
        })
        .await
    };
    let mut left = Vec::new();
    for (name, rtype) in &created {
        if let Err(e) = client.delete_rrset(&zone, name, *rtype, Expect::Any).await {
            left.push(format!("{name} {rtype}: {e}"));
        }
    }
    if let Err(e) = body {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(left.is_empty(), "cleanup left: {left:?}");
}
