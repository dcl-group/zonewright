//! Tests of the Google Cloud DNS client (`google_cloud`) against its mock.
#![cfg(feature = "google_cloud")]
// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use secrecy::SecretString;
use serde_json::{Value, json};
use zonewright::providers::google_cloud::{
    GoogleCloud, GoogleCloudConfig, GoogleCloudCredentials, ServiceAccountKey,
};
use zonewright::{
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl, SetOutcome,
    SkipReason, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::echo::{DEFAULT_ISSUED_TOKEN, Echo, EchoServer, Echoed, Render};
use zonewright_mock::google_cloud::{
    AdditionOfExisting, GoogleCloudMock, Seed, SeedZone, other_test_key, test_key,
};

use common::echo::{CANARY_KEY, CANARY_USER, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The zone most tests write to (`ZONE`) and the owner name (`NAME`).
const ZONE: &str = "example.org";
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const ZONES: &str = "/dns/v1/projects/*/managedZones";
const ZONE_GET: &str = "/dns/v1/projects/*/managedZones/*";
const RRSETS: &str = "/dns/v1/projects/*/managedZones/*/rrsets";
const CHANGES: &str = "/dns/v1/projects/*/managedZones/*/changes";
const CHANGE_GET: &str = "/dns/v1/projects/*/managedZones/*/changes/*";
const TOKEN: &str = "/token";

fn zone() -> DomainName {
    dn(ZONE)
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings for `mock`, project lookup, the shortest polling interval.
fn settings(mock: &GoogleCloudMock) -> GoogleCloudConfig {
    let mut config = GoogleCloudConfig::new("zw-test-project".into());
    config.dns_url = mock.dns_url();
    config.token_url = mock.token_url();
    config.change_poll_ms = 250;
    config
}

/// Credentials from the key file `key`.
fn credentials_from(key: Value) -> GoogleCloudCredentials {
    serde_json::from_value(json!({ "service_account_key": key })).unwrap()
}

/// The standard seed's credentials with `private_pem`.
fn credentials(private_pem: &str) -> GoogleCloudCredentials {
    credentials_from(Seed::standard().key_file(private_pem))
}

fn client_with(mock: &GoogleCloudMock, ctx: &Context) -> GoogleCloud {
    GoogleCloud::new(settings(mock), credentials(&test_key().private_pem), ctx).unwrap()
}

async fn setup() -> (GoogleCloudMock, GoogleCloud) {
    setup_with(Seed::standard()).await
}

async fn setup_with(seed: Seed) -> (GoogleCloudMock, GoogleCloud) {
    let mock = GoogleCloudMock::start(seed).await;
    let client = client_with(&mock, &context());
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

/// Number of changes the mock received.
fn writes(mock: &GoogleCloudMock) -> usize {
    mock.log().count(Some("POST"), CHANGES)
}

/// Number of `managedZones.list` requests.
fn lookups(mock: &GoogleCloudMock) -> usize {
    mock.log().count(Some("GET"), ZONES)
}

/// The body of the last change.
fn last_change(mock: &GoogleCloudMock) -> Value {
    mock.log()
        .matching(Some("POST"), CHANGES)
        .pop()
        .unwrap()
        .body_json()
        .unwrap()
}

/// The TXT rrdatas at `NAME`.
fn data(mock: &GoogleCloudMock) -> Vec<String> {
    mock.control().txt(ZONE, NAME)
}

/// The rrsets other than the apex NS and SOA every zone has.
fn user_rrsets(mock: &GoogleCloudMock) -> Vec<zonewright_mock::google_cloud::Rrset> {
    mock.control()
        .rrsets()
        .into_iter()
        .filter(|r| !(r.name == "example.org." && matches!(r.rtype.as_str(), "NS" | "SOA")))
        .collect()
}

/// The owner name of most record-level tests.
const REC: &str = "rec.example.org";

/// Canonical data of type `rtype`.
fn rd(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap()
}

fn rrset(name: &str, rtype: RecordType, ttl: Option<u32>, texts: &[&str]) -> RrSet {
    RrSet::new(
        dn(name),
        rtype,
        ttl.map(|t| RrsetTtl::from_secs(t).unwrap()),
        texts.iter().map(|t| rd(rtype, t)),
    )
    .unwrap()
}

/// The rrdatas of the rrset `name` / `rtype` at the mock, in order.
fn stored(mock: &GoogleCloudMock, name: &str, rtype: &str) -> Vec<String> {
    mock.control()
        .rrset(ZONE, name, rtype)
        .map(|r| r.rrdatas)
        .unwrap_or_default()
}

// ---- Secrets (design section 12.2) -------------------------------------------------------------

/// Neither client type nor credentials types can be printed with `Display` or serialized.
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

assert_not_impl!(GoogleCloud: std::fmt::Display, serde::Serialize);
assert_not_impl!(GoogleCloudCredentials: std::fmt::Display, serde::Serialize);
assert_not_impl!(ServiceAccountKey: std::fmt::Display, serde::Serialize);

/// The key file of the echo tests: canary identifiers and a generated private key.
fn canary_key() -> Value {
    let mut key = Seed::standard().key_file(&test_key().private_pem);
    key["client_email"] = json!(CANARY_USER);
    key["private_key_id"] = json!(CANARY_KEY);
    key
}

fn echo_client(echo: &EchoServer, token_url: &str, ctx: &Context) -> GoogleCloud {
    let mut config = GoogleCloudConfig::new("zw-test-project".into());
    config.dns_url = echo.url("/dns/v1");
    config.token_url = token_url.to_owned();
    config.change_poll_ms = 250;
    GoogleCloud::new(config, credentials_from(canary_key()), ctx).unwrap()
}

/// `check` and a write against an echo that quotes every request back, for every dialect: no
/// canary, no issued token and no JWT in any error, `ZoneCheck::detail` or `Debug`, and the
/// write's error shows the redaction. Passes per dialect: the API echoes (the issued token in
/// `Authorization`); the token endpoint echoes (the signed JWT in the form body); and the reads
/// answer like the API so that the change (an addition, or a deletion and an addition) and the
/// look at a pending change reach the echo.
#[tokio::test]
async fn google_cloud_secret_echo() {
    let ctx = context();
    let echo = EchoServer::start(200).await;
    let secrets = [CANARY_KEY, CANARY_USER, DEFAULT_ISSUED_TOKEN];
    for dialect in dialects() {
        for status in [400, 401] {
            let label = format!("{} {:?} {status} api", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status));
            let client = echo_client(&echo, &echo.token_url(), &ctx);
            echo_round(&label, &client, &secrets, false).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
            assert!(echo.token_requests() > 0, "{label}: no token was issued");

            let label = format!("{} {:?} {status} token", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status).token_path("/no-token-endpoint"));
            let client = echo_client(&echo, &echo.url(TOKEN), &ctx);
            echo_round(&label, &client, &secrets, false).await;
            let token_requests = echo.log().matching(Some("POST"), TOKEN);
            assert!(
                !token_requests.is_empty(),
                "{label}: the token endpoint was not reached"
            );
            assert!(token_requests[0].body_str().contains("eyJ"), "{label}");
        }
        for status in [400, 403, 404, 409, 412, 500] {
            for existing in [false, true] {
                // A look answered 5xx is retried with back-off; the 4xx looks cover the path.
                let polls: &[bool] = if status < 500 {
                    &[false, true]
                } else {
                    &[false]
                };
                for &poll in polls {
                    let label = format!(
                        "{} {:?} {status} write existing={existing} poll={poll}",
                        dialect.name, dialect.spelling
                    );
                    echo.reset(dialect.echo(status).render_under(
                        "/dns/v1/projects",
                        reads_then(dialect.render.clone(), existing, poll),
                    ));
                    let client = echo_client(&echo, &echo.token_url(), &ctx);
                    echo_round(&label, &client, &secrets, status < 500).await;
                    assert_eq!(
                        echo.log().count(Some("POST"), CHANGES),
                        2,
                        "{label}: the changes did not reach the echo"
                    );
                    if poll {
                        assert!(
                            echo.log().count(Some("GET"), CHANGE_GET) > 0,
                            "{label}: the change was not looked at"
                        );
                    }
                }
            }
        }
    }

    // The key ID and the e-mail travel only inside the signed JWT (the `kid` of its header, the
    // `iss` of its claims), base64url-encoded. A token endpoint that quotes the decoded JWT back
    // in its error puts them in plain text: they are redacted too.
    for status in [400, 401] {
        let label = format!("{status} token decoded jwt");
        echo.reset(
            Echo::new(status)
                .token_path("/no-token-endpoint")
                .render_under(TOKEN, decoded_jwt(status)),
        );
        let client = echo_client(&echo, &echo.url(TOKEN), &ctx);
        let mut texts = Vec::new();
        match client.check(&[zone()]).await {
            Ok(report) => panic!("{label}: check passed without a token: {report:?}"),
            Err(e) => texts.push(format!("{e} | {e:?}")),
        }
        match add(&client, "v1").await {
            Ok(outcome) => panic!("{label}: the echo accepted a write: {outcome:?}"),
            Err(e) => texts.push(format!("{e} | {e:?}")),
        }
        assert!(
            echo.log().count(Some("POST"), TOKEN) >= 2,
            "{label}: the token endpoint was not reached"
        );
        for text in &texts {
            assert!(
                text.contains(REDACTED),
                "{label}: the decoded JWT did not reach the error: {text}"
            );
            assert_clean(&label, text, &secrets);
        }
    }
}

/// A renderer for the token path that decodes the JWT of the form body and answers `status`
/// with its header and claims, in plain text, as the error description.
fn decoded_jwt(status: u16) -> Render {
    Arc::new(move |e: &Echoed| {
        let assertion = e
            .body
            .split('&')
            .find_map(|pair| pair.strip_prefix("assertion="))
            .unwrap();
        let parts: Vec<Value> = assertion
            .split('.')
            .take(2)
            .map(|part| {
                let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(part)
                    .unwrap();
                serde_json::from_slice(&raw).unwrap()
            })
            .collect();
        let kid = parts[0]["kid"].as_str().unwrap();
        let iss = parts[1]["iss"].as_str().unwrap();
        assert_eq!((kid, iss), (CANARY_KEY, CANARY_USER));
        (
            StatusCode::from_u16(status).unwrap(),
            axum::Json(json!({
                "error": "invalid_grant",
                "error_description": format!("cannot accept the JWT of key {kid} for {iss}"),
            })),
        )
            .into_response()
    })
}

/// A renderer that answers the reads like the API (one public managed zone; no rrset, or a TXT
/// rrset with a foreign value) and every other request, the rrset listing of the whole zone
/// included, with `errors`; with `poll`, the change is accepted as pending, and the look at it
/// then meets the echo.
fn reads_then(errors: Render, existing: bool, poll: bool) -> Render {
    Arc::new(move |e: &Echoed| {
        let ok = |body: Value| (StatusCode::OK, axum::Json(body)).into_response();
        if e.method == Method::POST {
            return if poll {
                ok(json!({"kind": "dns#change", "id": "17", "status": "pending"}))
            } else {
                errors(e)
            };
        }
        if e.path.ends_with("/managedZones") {
            return ok(json!({"managedZones": [{
                "id": "1000000000000000001",
                "name": "example-org",
                "dnsName": "example.org.",
                "visibility": "public"
            }]}));
        }
        if e.path.ends_with("/rrsets") {
            let filtered = e.query.as_deref().is_some_and(|q| q.contains("name="));
            if !filtered {
                return errors(e);
            }
            return if existing {
                ok(json!({"rrsets": [{
                    "kind": "dns#resourceRecordSet",
                    "name": "_acme-challenge.example.org.",
                    "type": "TXT",
                    "ttl": 60,
                    "rrdatas": ["\"foreign\""]
                }]}))
            } else {
                ok(json!({}))
            };
        }
        errors(e)
    })
}

async fn echo_round(label: &str, client: &GoogleCloud, secrets: &[&str], list: bool) {
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
    let write = match add(client, "v1").await {
        Ok(outcome) => panic!("{label}: the echo accepted a write: {outcome:?}"),
        Err(e) => format!("{e} | {e:?}"),
    };
    assert!(
        write.contains(REDACTED),
        "{label}: the echo did not reach the error: {write}"
    );
    texts.push(write);
    let set = RrSet::new(
        name(),
        RecordType::TXT,
        None,
        [Txt::new("v1 record").unwrap().to_data().unwrap()],
    )
    .unwrap();
    let write = match client.set_rrset(&zone(), &set, Expect::Any).await {
        Ok(outcome) => panic!("{label}: the echo accepted a record-level write: {outcome:?}"),
        Err(e) => format!("{e} | {e:?}"),
    };
    assert!(
        write.contains(REDACTED),
        "{label}: the echo did not reach the record-level error: {write}"
    );
    texts.push(write);
    if list {
        match client.list_rrsets(&zone()).await {
            Ok(listing) => panic!("{label}: the echo answered a listing: {listing:?}"),
            Err(e) => texts.push(format!("{e} | {e:?}")),
        }
    }
    for text in &texts {
        assert_clean(label, text, secrets);
    }
}

/// A `TRACE` capture over a success, a renewed token, repeated 401s, a 500 and a key the token
/// endpoint refuses: the transport's events are there, and no canary, issued token or JWT is.
#[tokio::test(flavor = "current_thread")]
async fn google_cloud_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.client_email = CANARY_USER.into();
    seed.private_key_id = CANARY_KEY.into();
    let mock = GoogleCloudMock::start(seed).await;
    let client =
        GoogleCloud::new(settings(&mock), credentials_from(canary_key()), &context()).unwrap();
    let mut texts = Vec::new();

    add(&client, "v1").await.unwrap();
    mock.control().revoke_tokens();
    add(&client, "v2").await.unwrap();
    let a = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    client.set_rrset(&zone(), &a, Expect::Absent).await.unwrap();
    client.list_rrsets(&zone()).await.unwrap();
    client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Matches(&a))
        .await
        .unwrap();

    mock.faults()
        .push(Fault::on("GET", RRSETS).always().status(401));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("POST", CHANGES).status(500));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    let mut key = canary_key();
    key["private_key"] = json!(other_test_key().private_pem);
    let wrong = GoogleCloud::new(settings(&mock), credentials_from(key), &context()).unwrap();
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?} | {wrong:?} | {client:?}"));

    let entries = capture.entries();
    assert!(
        entries.iter().any(|e| e.target == "zonewright::http"),
        "the capture holds no transport event"
    );
    texts.push(capture.text());
    let tokens = mock.control().issued_tokens();
    assert!(tokens.len() >= 2);
    let mut secrets = vec![CANARY_KEY, CANARY_USER];
    secrets.extend(tokens.iter().map(String::as_str));
    for text in &texts {
        assert_clean("google_cloud logs and errors", text, &secrets);
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request, token requests included.
#[tokio::test]
async fn google_cloud_name_outside_zone_sends_nothing() {
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
            [rd(RecordType::A, "192.0.2.1")],
        )
        .unwrap();
        let errors = [
            client
                .set_rrset(&zone, &set, Expect::Any)
                .await
                .unwrap_err(),
            client
                .delete_rrset(&zone, &name, RecordType::A, Expect::Any)
                .await
                .unwrap_err(),
            client
                .get_rrset(&zone, &name, RecordType::A)
                .await
                .unwrap_err(),
        ];
        for e in errors {
            assert!(matches!(e, Error::NameOutsideZone { .. }), "{e:?}");
        }
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
    assert_eq!(mock.control().tokens_issued(), 0);
}

/// `Created`, `Appended` for a second value, then `AlreadyPresent` without a write.
#[tokio::test]
async fn google_cloud_add_is_idempotent() {
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
    assert_eq!(data(&mock), ["\"AAA\"", "\"BBB\""]);
    // The public managed zone was used, not the private one of the same name listed before it.
    let sets = user_rrsets(&mock);
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].zone_id, mock.control().zone_id(ZONE));
    assert_eq!(mock.control().tokens_issued(), 1, "the token is cached");
}

/// Removing an absent value next to a foreign one writes nothing; adding and removing our value
/// leaves the foreign value (in its own spelling), the TTL and the members the model does not
/// carry as they were. The change repeats the rrset exactly as it was read. A single foreign
/// value is never a reason to delete the rrset.
#[tokio::test]
async fn google_cloud_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZONE, NAME, "TXT", 600, &["foreign"]);
    let original = control.rrset(ZONE, NAME, "TXT").unwrap();

    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    let during = control.rrset(ZONE, NAME, "TXT").unwrap();
    assert_eq!(during.ttl, Some(600));
    assert_eq!(during.rrdatas, ["foreign", "\"ours\""]);
    let body = last_change(&mock);
    let read = json!({
        "kind": "dns#resourceRecordSet",
        "name": "_acme-challenge.example.org.",
        "type": "TXT",
        "ttl": 600,
        "rrdatas": ["foreign"]
    });
    assert_eq!(body["deletions"], json!([read]));
    assert_eq!(
        body["additions"],
        json!([{
            "kind": "dns#resourceRecordSet",
            "name": "_acme-challenge.example.org.",
            "type": "TXT",
            "ttl": 600,
            "rrdatas": ["foreign", "\"ours\""]
        }])
    );
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.rrset(ZONE, NAME, "TXT").unwrap(), original);

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_rrset(ZONE, other, "TXT", 60, &["\"foreign\""]);
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &txt("ours"))
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(control.txt(ZONE, other), ["\"foreign\""]);
    // The foreign value is ours by value when its text is ours: both spellings read alike.
    assert_eq!(
        client
            .add_txt_value(&zone(), &dn(other), &txt("foreign"), None)
            .await
            .unwrap(),
        AddOutcome::AlreadyPresent
    );
}

/// The last value is removed with a deletion of the rrset and no addition.
#[tokio::test]
async fn google_cloud_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(user_rrsets(&mock).is_empty());
    let body = last_change(&mock);
    assert_eq!(body["deletions"].as_array().unwrap().len(), 1);
    assert_eq!(body["additions"], json!([]));
}

#[tokio::test]
async fn google_cloud_remove_is_idempotent() {
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
    assert!(user_rrsets(&mock).is_empty());
}

/// Two clients sharing a `Context` add to one name at once, the first change delayed: both
/// values end up in the rrset, and neither change was refused.
#[tokio::test]
async fn google_cloud_concurrent_adds_are_serialized() {
    let mock = GoogleCloudMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, &ctx);
    let b = client_with(&mock, &ctx);
    mock.faults()
        .push(Fault::on("POST", CHANGES).delay(Duration::from_millis(300)));
    let (zone, name, aaa, bbb) = (zone(), name(), txt("AAA"), txt("BBB"));
    let (ra, rb) = tokio::join!(
        a.add_txt_value(&zone, &name, &aaa, None),
        b.add_txt_value(&zone, &name, &bbb, None),
    );
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [AddOutcome::Appended, AddOutcome::Created]);
    let mut values = data(&mock);
    values.sort();
    assert_eq!(values, ["\"AAA\"", "\"BBB\""]);
    assert_eq!(writes(&mock), 2);
}

/// A foreign change between the read and the change is not lost, whatever status the provider
/// answers the failed deletion match, or the addition of an rrset created meanwhile, with: the
/// change is refused, the client reads again and repeats the operation once; a second refusal is
/// a retryable `Conflict` with nothing written. A `404` also makes the client look the zone up
/// again before the new read.
#[tokio::test]
async fn google_cloud_concurrent_change_is_conflict() {
    for status in [412u16, 400, 409, 404] {
        let (mock, client) = setup().await;
        mock.control().set_precondition_status(status);
        mock.control()
            .set_addition_of_existing(AdditionOfExisting::Refuse(status));
        add(&client, "AAA").await.unwrap();

        // One foreign change: the repeat succeeds and keeps it.
        let hook = mock.control().clone();
        mock.faults().push(Fault::on("POST", CHANGES).run(move || {
            hook.append_txt(ZONE, NAME, "foreign1");
        }));
        let looked_up = lookups(&mock);
        assert_eq!(
            add(&client, "BBB").await.unwrap(),
            AddOutcome::Appended,
            "{status}"
        );
        assert_eq!(
            lookups(&mock),
            looked_up + usize::from(status == 404),
            "{status}: the zone is looked up again after a 404 only"
        );
        assert_eq!(data(&mock), ["\"AAA\"", "foreign1", "\"BBB\""], "{status}");

        // A foreign change before each of the two changes: `Conflict`, nothing of ours written.
        let hook = mock.control().clone();
        let n = Arc::new(std::sync::atomic::AtomicU32::new(0));
        mock.faults()
            .push(Fault::on("POST", CHANGES).times(2).run(move || {
                let i = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                hook.append_txt(ZONE, NAME, &format!("foreign-r{i}"));
            }));
        let before = writes(&mock);
        let e = add(&client, "CCC").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Conflict, "{status} {e:?}");
        assert!(e.is_retryable());
        assert_eq!(writes(&mock), before + 2, "{status}");
        assert_eq!(
            data(&mock),
            ["\"AAA\"", "foreign1", "\"BBB\"", "foreign-r0", "foreign-r1"],
            "{status}"
        );

        // A removal meets a foreign change: the foreign value survives, ours goes.
        let hook = mock.control().clone();
        mock.faults().push(Fault::on("POST", CHANGES).run(move || {
            hook.append_txt(ZONE, NAME, "foreign2");
        }));
        assert_eq!(
            remove(&client, "AAA").await.unwrap(),
            RemoveOutcome::Removed,
            "{status}"
        );
        assert_eq!(
            data(&mock),
            [
                "foreign1",
                "\"BBB\"",
                "foreign-r0",
                "foreign-r1",
                "foreign2"
            ],
            "{status}"
        );

        // Values merely reordered by someone else: the exact match fails, the repeat succeeds.
        let hook = mock.control().clone();
        mock.faults().push(Fault::on("POST", CHANGES).run(move || {
            hook.edit_rrset(ZONE, NAME, "TXT", |set| set.rrdatas.reverse());
        }));
        assert_eq!(
            add(&client, "DDD").await.unwrap(),
            AddOutcome::Appended,
            "{status}"
        );

        // An rrset created by someone else between the read and our addition.
        let other = "_acme-challenge.www.example.org";
        let hook = mock.control().clone();
        mock.faults().push(Fault::on("POST", CHANGES).run(move || {
            hook.append_txt(ZONE, other, "foreign3");
        }));
        assert_eq!(
            client
                .add_txt_value(&zone(), &dn(other), &txt("EEE"), None)
                .await
                .unwrap(),
            AddOutcome::Appended,
            "{status}"
        );
        assert_eq!(mock.control().txt(ZONE, other), ["foreign3", "\"EEE\""]);

        // The last value is about to be deleted when someone adds another: it survives.
        let lone = "_acme-challenge.lone.example.org";
        client
            .add_txt_value(&zone(), &dn(lone), &txt("FFF"), None)
            .await
            .unwrap();
        let hook = mock.control().clone();
        mock.faults().push(Fault::on("POST", CHANGES).run(move || {
            hook.append_txt(ZONE, lone, "foreign4");
        }));
        assert_eq!(
            client
                .remove_txt_value(&zone(), &dn(lone), &txt("FFF"))
                .await
                .unwrap(),
            RemoveOutcome::Removed,
            "{status}"
        );
        assert_eq!(mock.control().txt(ZONE, lone), ["foreign4"]);
    }
}

/// The other reading of the undocumented answer to an addition of an rrset that exists: the
/// service applies it as a replacement. An rrset another writer creates between the client's
/// read and its addition is then replaced, and the client reports `Created`: the other writer's
/// value is lost and nothing reports it. No client code can detect it, since the API offers no
/// other condition on the absence of an rrset; the guarantee for a new rrset rests on the
/// refusal (`src/providers/google_cloud/rrset.rs`, "A new rrset"), which the ignored test
/// `live_google_cloud_change_semantics` settles. An rrset that exists at the read stays
/// protected by the deletion match under either reading.
#[tokio::test]
async fn google_cloud_addition_of_an_existing_rrset_under_the_other_reading() {
    let (mock, client) = setup().await;
    mock.control()
        .set_addition_of_existing(AdditionOfExisting::Replace);
    let other = "_acme-challenge.www.example.org";
    let hook = mock.control().clone();
    mock.faults().push(Fault::on("POST", CHANGES).run(move || {
        hook.append_txt(ZONE, other, "foreign");
    }));
    assert_eq!(
        client
            .add_txt_value(&zone(), &dn(other), &txt("ours"), None)
            .await
            .unwrap(),
        AddOutcome::Created
    );
    assert_eq!(
        mock.control().txt(ZONE, other),
        ["\"ours\""],
        "the foreign value is gone"
    );

    // An rrset that existed at the read: the deletion match keeps the foreign value.
    add(&client, "AAA").await.unwrap();
    let hook = mock.control().clone();
    mock.faults().push(Fault::on("POST", CHANGES).run(move || {
        hook.append_txt(ZONE, NAME, "foreign");
    }));
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    assert_eq!(data(&mock), ["\"AAA\"", "foreign", "\"BBB\""]);
}

/// A refusal is decided by the new read, not by its body: a body without a reason and a body
/// that is not JSON still end in a repeat that keeps the foreign value, and with the refusal
/// returned as it is when nothing changed.
#[tokio::test]
async fn google_cloud_conflict_is_decided_by_the_read() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    for (status, body) in [
        (
            412u16,
            r#"{"error":{"code":412,"message":"Precondition not met"}}"#,
        ),
        (400, "<html>bad request</html>"),
        (409, ""),
    ] {
        let hook = mock.control().clone();
        let value = format!("foreign-{status}");
        mock.faults().push(
            Fault::on("POST", CHANGES)
                .run(move || hook.append_txt(ZONE, NAME, &value))
                .respond(status, body),
        );
        let ours = format!("ours-{status}");
        assert_eq!(
            add(&client, &ours).await.unwrap(),
            AddOutcome::Appended,
            "{status}"
        );
        let held = data(&mock);
        assert!(held.contains(&format!("foreign-{status}")), "{held:?}");
        assert!(held.contains(&format!("\"{ours}\"")), "{held:?}");
        // Nothing changed: the refusal is the error, with no code where the body has none.
        mock.faults()
            .push(Fault::on("POST", CHANGES).respond(status, body));
        let e = add(&client, "never").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{status}: {e:?}");
        assert_eq!(e.provider_code(), None, "{status}");
    }
}

/// A resource quota (`quotaExceeded`) answered with 413 or 429 is a permanent refusal: `Rejected`
/// with the status and the reason, not waited out, not repeated; a 413 or 429 with another reason
/// stays a rate limit.
#[tokio::test]
async fn google_cloud_resource_quota_is_a_refusal() {
    let (mock, client) = setup().await;
    let quota = |status: u16| {
        format!(
            r#"{{"error":{{"code":{status},"message":"Quota exceeded for quota metric 'rrsets per zone'","errors":[{{"domain":"global","reason":"quotaExceeded"}}]}}}}"#
        )
    };
    for status in [413u16, 429] {
        mock.faults()
            .push(Fault::on("POST", CHANGES).respond(status, quota(status)));
        let before = writes(&mock);
        let e = add(&client, "AAA").await.unwrap_err();
        match &e {
            Error::Rejected {
                status: got, code, ..
            } => {
                assert_eq!(*got, Some(status));
                assert_eq!(code.as_ref().map(|c| c.as_str()), Some("quotaExceeded"));
            }
            other => panic!("{status}: {other:?}"),
        }
        assert!(!e.is_retryable());
        assert_eq!(writes(&mock), before + 1, "{status}");
        // On a read: refused at once, not repeated.
        mock.faults()
            .push(Fault::on("GET", RRSETS).respond(status, quota(status)));
        let reads = mock.log().count(Some("GET"), RRSETS);
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{status}: {e:?}");
        assert_eq!(mock.log().count(Some("GET"), RRSETS), reads + 1, "{status}");
    }
    // Another reason: a rate limit, written once.
    for status in [413u16, 429] {
        mock.faults().push(Fault::on("POST", CHANGES).respond(
            status,
            r#"{"error":{"code":429,"message":"slow down","errors":[{"reason":"rateLimitExceeded"}]}}"#,
        ));
        let before = writes(&mock);
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::RateLimited, "{status}: {e:?}");
        assert_eq!(writes(&mock), before + 1, "{status}");
    }
    assert!(data(&mock).is_empty());
}

/// More ways a change can fail, each sent once: a 503, a dropped connection, an answer slower
/// than the request timeout, the removal of one of several values, and a change the provider
/// applied whose answer was lost (a 502 after the change). The repeat converges every time.
#[tokio::test]
async fn google_cloud_more_writes_are_sent_once() {
    let mock = GoogleCloudMock::start(Seed::standard()).await;
    let mut options = zonewright::ContextOptions::default();
    options.loopback_only = true;
    options.request_timeout = Duration::from_millis(700);
    let ctx = Context::new(options).unwrap();
    let client = client_with(&mock, &ctx);

    // 503 on a create, a dropped connection on an update.
    mock.faults().push(Fault::on("POST", CHANGES).status(503));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(writes(&mock), 1);
    assert!(data(&mock).is_empty());
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    mock.faults()
        .push(Fault::on("POST", CHANGES).drop_connection());
    let before = writes(&mock);
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(writes(&mock), before + 1);
    assert_eq!(data(&mock), ["\"AAA\""]);
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);

    // The removal of one of two values (a deletion and an addition) answered 502.
    mock.faults().push(Fault::on("POST", CHANGES).status(502));
    let before = writes(&mock);
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(writes(&mock), before + 1);
    assert_eq!(data(&mock), ["\"AAA\"", "\"BBB\""]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );

    // Applied, answer lost: the change takes effect, the client gets a 502.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("POST", CHANGES)
            .run(move || hook.append_txt(ZONE, NAME, "\"CCC\""))
            .status(502),
    );
    let before = writes(&mock);
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(
        add(&client, "CCC").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(writes(&mock), before + 1, "the repeat writes nothing");

    // An answer slower than the request timeout: sent once, the outcome unknown; whether the
    // mock applied it after the client gave up, the repeat converges.
    mock.faults()
        .push(Fault::on("POST", CHANGES).delay(Duration::from_millis(1200)));
    let before = writes(&mock);
    let e = add(&client, "DDD").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(writes(&mock), before + 1);
    tokio::time::sleep(Duration::from_millis(700)).await;
    let outcome = add(&client, "DDD").await.unwrap();
    assert!(
        matches!(outcome, AddOutcome::AlreadyPresent | AddOutcome::Appended),
        "{outcome:?}"
    );
    let held = data(&mock);
    assert_eq!(
        held.iter().filter(|v| *v == "\"DDD\"").count(),
        1,
        "{held:?}"
    );
}

/// The managed zone is deleted and created again under a new ID while the client has the old
/// one cached. A read answered 404 looks the zone up again and repeats the read: a removal
/// never reports `NotPresent` for a value that is there. A change that meets the stale ID is
/// refused, the new read finds the zone under its new ID, and the operation runs once more.
#[tokio::test]
async fn google_cloud_stale_zone_id() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for value in ["v1", "v2"] {
        add(&client, value).await.unwrap();
    }
    assert_eq!(lookups(&mock), 1);

    control.recreate_zone(ZONE);
    assert_eq!(remove(&client, "v1").await.unwrap(), RemoveOutcome::Removed);
    assert_eq!(lookups(&mock), 2);
    control.recreate_zone(ZONE);
    assert_eq!(add(&client, "v3").await.unwrap(), AddOutcome::Appended);
    assert_eq!(data(&mock), ["\"v2\"", "\"v3\""]);

    // The zone is recreated between the read and the change.
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", CHANGES).run(move || {
        hook.recreate_zone(ZONE);
    }));
    assert_eq!(add(&client, "v4").await.unwrap(), AddOutcome::Appended);
    assert_eq!(data(&mock), ["\"v2\"", "\"v3\"", "\"v4\""]);
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", CHANGES).run(move || {
        hook.recreate_zone(ZONE);
    }));
    assert_eq!(remove(&client, "v4").await.unwrap(), RemoveOutcome::Removed);
    assert_eq!(data(&mock), ["\"v2\"", "\"v3\""]);
    // The zone is addressed by its ID, which changed each time.
    let paths: Vec<String> = mock
        .log()
        .matching(Some("POST"), CHANGES)
        .into_iter()
        .map(|r| r.path)
        .collect();
    assert!(
        paths.iter().all(|p| !p.contains("example-org")),
        "{paths:?}"
    );
}

/// Every operation is offered; a record type outside the record-level list (types the supported
/// record types page lists without a form a source shows, and others) is
/// `UnsupportedRecordType` for get, set and delete, before any request.
#[tokio::test]
async fn google_cloud_unsupported_operations_send_nothing() {
    let (mock, client) = setup().await;
    let caps = client.capabilities();
    for operation in [
        zonewright::Operation::ListRrsets,
        zonewright::Operation::GetRrset,
        zonewright::Operation::SetRrset,
        zonewright::Operation::DeleteRrset,
        zonewright::Operation::AddTxtValue,
        zonewright::Operation::RemoveTxtValue,
        zonewright::Operation::ListZones,
    ] {
        assert!(caps.supports(operation), "{operation}");
    }
    let unknown = RecordData::parse(RecordType::from_code(65_280), "\\# 1 00").unwrap();
    for (rtype, data) in [
        (RecordType::PTR, rd(RecordType::PTR, "host.example.net.")),
        (RecordType::HTTPS, rd(RecordType::HTTPS, "1 . alpn=\"h2\"")),
        (RecordType::SSHFP, rd(RecordType::SSHFP, "1 1 abcd")),
        (
            RecordType::DNAME,
            rd(RecordType::DNAME, "target.example.net."),
        ),
        (RecordType::from_code(65_280), unknown),
    ] {
        let set = RrSet::new(dn(REC), rtype, None, [data]).unwrap();
        let errors = [
            client
                .get_rrset(&zone(), &dn(REC), rtype)
                .await
                .unwrap_err(),
            client
                .set_rrset(&zone(), &set, Expect::Any)
                .await
                .unwrap_err(),
            client
                .delete_rrset(&zone(), &dn(REC), rtype, Expect::Any)
                .await
                .unwrap_err(),
        ];
        for e in errors {
            assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
        }
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
}

/// Every change is sent exactly once, whatever happens: a 502, a 429, a 413 (the quota page's
/// status) and a 401 each end the operation, which a repeat starts again with a read.
#[tokio::test]
async fn google_cloud_writes_are_sent_once() {
    let (mock, client) = setup().await;
    for status in [502u16, 429, 413, 401] {
        for step in ["create", "update", "delete"] {
            if step != "create" {
                add(&client, "AAA").await.unwrap();
            }
            let fault = Fault::on("POST", CHANGES);
            mock.faults().push(if status == 429 {
                fault.rate_limited("1")
            } else {
                fault.status(status)
            });
            let before = writes(&mock);
            let state = data(&mock);
            let e = match step {
                "create" => add(&client, "AAA").await.unwrap_err(),
                "update" => add(&client, "BBB").await.unwrap_err(),
                _ => remove(&client, "AAA").await.unwrap_err(),
            };
            let expected = match status {
                429 | 413 => ErrorKind::RateLimited,
                _ => ErrorKind::Transient,
            };
            assert_eq!(e.kind(), expected, "{status} {step}: {e:?}");
            assert_eq!(writes(&mock), before + 1, "{status} {step}");
            assert_eq!(data(&mock), state, "{status} {step}");
            match step {
                "create" => assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created),
                "update" => {
                    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
                    remove(&client, "BBB").await.unwrap();
                }
                _ => {}
            }
            remove(&client, "AAA").await.unwrap();
            assert!(user_rrsets(&mock).is_empty(), "{status} {step}");
        }
    }
}

// ---- Changes and rrsets ------------------------------------------------------------------------

/// The first value creates the rrset: the name absolute with the trailing dot, the configured
/// TTL as a number, the value quoted; no deletion. The read lists the rrsets of one name and
/// type.
#[tokio::test]
async fn google_cloud_add_creates_rrset() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        last_change(&mock),
        json!({
            "additions": [{
                "name": "_acme-challenge.example.org.",
                "type": "TXT",
                "ttl": 120,
                "rrdatas": ["\"AAA\""]
            }],
            "deletions": []
        })
    );
    let read = mock.log().matching(Some("GET"), RRSETS).pop().unwrap();
    assert_eq!(
        read.query.as_deref(),
        Some("name=_acme-challenge.example.org.&type=TXT")
    );
    let lookup = mock.log().matching(Some("GET"), ZONES).pop().unwrap();
    assert_eq!(lookup.query.as_deref(), Some("dnsName=example.org."));

    // A TTL given by the caller is used for a new rrset only.
    let other = dn("_acme-challenge.www.example.org");
    client
        .add_txt_value(
            &zone(),
            &other,
            &txt("BBB"),
            Some(RrsetTtl::from_secs(300).unwrap()),
        )
        .await
        .unwrap();
    client
        .add_txt_value(
            &zone(),
            &other,
            &txt("CCC"),
            Some(RrsetTtl::from_secs(900).unwrap()),
        )
        .await
        .unwrap();
    let set = mock
        .control()
        .rrset(ZONE, "_acme-challenge.www.example.org", "TXT")
        .unwrap();
    assert_eq!(set.ttl, Some(300));

    // A value that is not plain is refused before any request.
    let requests = mock.log().len();
    let e = add(&client, "two words").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(mock.log().len(), requests);

    // The zone apex is its DNS name.
    client
        .add_txt_value(&zone(), &zone(), &txt("apex"), None)
        .await
        .unwrap();
    assert_eq!(last_change(&mock)["additions"][0]["name"], "example.org.");
    assert_eq!(mock.control().txt(ZONE, ZONE), ["\"apex\""]);
}

/// A refusal carries the `reason` of the error body; the kinds do not change.
#[tokio::test]
async fn google_cloud_refusal_carries_the_provider_code() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", CHANGES).respond(
        400,
        r#"{"error":{"code":400,"message":"Invalid value for 'entity.change.additions[0].rrdata[0]'","status":"INVALID_ARGUMENT","errors":[{"domain":"global","reason":"invalidValue","message":"m"}]}}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(e.provider_code().map(|c| c.as_str()), Some("invalidValue"));
    assert!(e.to_string().contains("entity.change.additions"), "{e}");
    // The mock's own refusal: a CNAME at the apex.
    let cname = rrset(ZONE, RecordType::CNAME, None, &["target.example.net."]);
    let e = client
        .set_rrset(&zone(), &cname, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(
        e.provider_code().map(|c| c.as_str()),
        Some("recordTypeDisallowedAtZoneApex")
    );
    mock.faults().push(
        Fault::on("POST", CHANGES).respond(400, r#"{"error":{"code":400,"message":"invalid"}}"#),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(e.provider_code(), None);
}

/// A reason that echoes the key ID or the service account's e-mail is not carried, and neither
/// appears in the error. A code holds letters, digits and `_ - . :` only, so the identifiers
/// here are of that form.
#[tokio::test]
async fn google_cloud_provider_code_never_carries_a_credential() {
    let mut seed = Seed::standard();
    seed.private_key_id = "keyid5566778899aabb".into();
    seed.client_email = "zw-sa.code-test".into();
    let mock = GoogleCloudMock::start(seed.clone()).await;
    let client = GoogleCloud::new(
        settings(&mock),
        credentials_from(seed.key_file(&test_key().private_pem)),
        &context(),
    )
    .unwrap();
    for secret in [&seed.private_key_id, &seed.client_email] {
        let body = format!(
            r#"{{"error":{{"code":400,"message":"refused","errors":[{{"reason":"{secret}"}}]}}}}"#
        );
        mock.faults()
            .push(Fault::on("POST", CHANGES).respond(400, body));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
        assert_eq!(e.provider_code(), None, "{secret}");
        let text = format!("{e} | {e:?}");
        assert!(!text.contains(secret.as_str()), "{text}");
    }
}

/// A pending change is looked at until it is done; a change done at once is not looked at; a
/// look that keeps failing, and a status the client does not know, are `Transient`, and a repeat
/// converges.
#[tokio::test]
async fn google_cloud_changes_are_polled() {
    let (mock, client) = setup().await;
    mock.control().set_change_polls(3);
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), CHANGE_GET), 3);
    let change = mock.log().matching(Some("POST"), CHANGES).pop().unwrap();
    let look = mock.log().matching(Some("GET"), CHANGE_GET).pop().unwrap();
    assert!(
        look.path.starts_with(&format!("{}/", change.path)),
        "the change is looked at below its zone: {}",
        look.path
    );
    mock.control().set_change_polls(0);
    add(&client, "BBB").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), CHANGE_GET), 3, "done at once");

    mock.control().set_change_polls(1);
    mock.faults()
        .push(Fault::on("GET", CHANGE_GET).times(3).status(500));
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    // The change was accepted; its outcome is unknown to the client. A repeat converges.
    assert_eq!(
        add(&client, "CCC").await.unwrap(),
        AddOutcome::AlreadyPresent
    );

    for answer in [
        r#"{"kind":"dns#change","id":"9","status":"failed"}"#,
        r#"{"kind":"dns#change","id":"9"}"#,
        r#"{"kind":"dns#change","status":"pending"}"#,
        "not json",
    ] {
        mock.faults()
            .push(Fault::on("POST", CHANGES).respond(200, answer));
        let e = add(&client, "DDD").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient, "{answer}: {e:?}");
    }
}

/// A change that stays pending keeps the add waiting through look after look, and the change is
/// sent once. That the looks are bounded, and that the add then ends with `Transient`, is the
/// unit test `a_change_that_stays_pending_is_transient_after_the_last_look` in
/// `src/providers/google_cloud/api.rs` with a lowered bound.
#[tokio::test]
async fn google_cloud_pending_change_keeps_being_polled() {
    let (mock, client) = setup().await;
    mock.control().set_change_polls(u32::MAX);
    let polled = async {
        let deadline = Instant::now() + Duration::from_secs(10);
        while mock.log().count(Some("GET"), CHANGE_GET) < 3 {
            assert!(Instant::now() < deadline, "the client stopped polling");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::select! {
        outcome = add(&client, "AAA") => {
            panic!("the add ended while its change was pending: {outcome:?}")
        }
        () = polled => {}
    }
    assert_eq!(writes(&mock), 1);
}

/// An rrset with a routing policy, or with DNSSEC signatures, is not plain records: the TXT
/// value operations and `get_rrset` fail with `Rejected` after the read and write nothing; the
/// listing reports it as skipped.
#[tokio::test]
async fn google_cloud_sets_that_are_not_plain_are_refused() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZONE, NAME, "TXT", 60, &["\"foreign\""]);
    control.edit_rrset(ZONE, NAME, "TXT", |set| {
        set.routing_policy = Some(json!({"geo": {"items": []}}));
        set.rrdatas.clear();
    });
    control.insert_rrset(ZONE, REC, "A", 60, &["192.0.2.1"]);
    control.edit_rrset(ZONE, REC, "A", |set| {
        set.signature_rrdatas =
            vec!["A 13 3 60 20260101000000 20250101000000 1 example.org. AA==".into()];
    });
    for e in [
        add(&client, "AAA").await.unwrap_err(),
        remove(&client, "AAA").await.unwrap_err(),
        client
            .get_rrset(&zone(), &dn(REC), RecordType::A)
            .await
            .unwrap_err(),
        client
            .set_rrset(
                &zone(),
                &rrset(REC, RecordType::A, None, &["192.0.2.2"]),
                Expect::Any,
            )
            .await
            .unwrap_err(),
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap_err(),
    ] {
        assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
        assert_eq!(e.provider_code(), None);
    }
    assert_eq!(writes(&mock), 0);
    let listing = client.list_rrsets(&zone()).await.unwrap();
    let mut skipped: Vec<(String, String, SkipReason)> = listing
        .skipped
        .iter()
        .map(|s| (s.name.to_string(), s.type_name.clone(), s.reason))
        .collect();
    skipped.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(
        skipped,
        [
            (
                "_acme-challenge.example.org.".to_owned(),
                "TXT".to_owned(),
                SkipReason::NotPlainRecords
            ),
            (
                "rec.example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::NotPlainRecords
            ),
        ]
    );
}

/// The TXT dialect: quoted character-strings are joined, an unquoted string is read as itself,
/// and data the rule cannot decode is a foreign value written back unchanged.
#[tokio::test]
async fn google_cloud_txt_dialect() {
    let (mock, client) = setup().await;
    mock.control().insert_rrset(
        ZONE,
        NAME,
        "TXT",
        60,
        &["\"ab\" \"c\"", "plain", "\"open", "two words"],
    );
    for value in ["abc", "plain"] {
        assert_eq!(
            add(&client, value).await.unwrap(),
            AddOutcome::AlreadyPresent,
            "{value}"
        );
    }
    assert_eq!(
        remove(&client, "abc").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(data(&mock), ["plain", "\"open", "two words"]);
    assert_eq!(
        remove(&client, "two").await.unwrap(),
        RemoveOutcome::NotPresent
    );
}

/// Only a public managed zone is used: a zone held as a private zone only is not found, with a
/// detail; two public zones of one name are `Config`, and `check` says why.
#[tokio::test]
async fn google_cloud_zone_selection() {
    let mut seed = Seed::standard();
    seed.zones = vec![SeedZone {
        name: "example-org-private".into(),
        dns_name: "example.org.".into(),
        public: false,
    }];
    let (mock, client) = setup_with(seed).await;
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    assert!(
        report.zones[0]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("private"),
        "{report:?}"
    );
    let e = add(&client, "A").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ZoneNotFound, "{e:?}");

    mock.control().insert_zone("example-org-a", ZONE, true);
    mock.control().insert_zone("example-org-b", ZONE, true);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    assert!(
        report.zones[0]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("managed_zones"),
        "{report:?}"
    );
    let e = add(&client, "A").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
    assert_eq!(writes(&mock), 0);

    // A lookup answered with a zone of another name is not taken.
    mock.faults().push(Fault::on("GET", ZONES).respond(
        200,
        r#"{"managedZones":[{"id":"5","name":"other","dnsName":"example.net.","visibility":"public"}]}"#,
    ));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// Managed zones configured by name or ID are used after they were verified against the zone's
/// DNS name, without a project-wide lookup; one of another name is `Config`; a private one is
/// not found.
#[tokio::test]
async fn google_cloud_configured_managed_zones() {
    let mock = GoogleCloudMock::start(Seed::standard()).await;
    let id = mock.control().zone_id(ZONE);
    for configured in ["example-org".to_owned(), id.clone()] {
        let mut config = settings(&mock);
        config.managed_zones = Some(
            [(ZONE.to_owned(), configured.clone())]
                .into_iter()
                .collect(),
        );
        let client = GoogleCloud::new(
            config.clone(),
            credentials(&test_key().private_pem),
            &context(),
        )
        .unwrap();
        mock.control().reset();
        assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
        assert_eq!(lookups(&mock), 0);
        let gets: Vec<String> = mock
            .log()
            .matching(Some("GET"), ZONE_GET)
            .into_iter()
            .map(|r| r.path)
            .collect();
        assert_eq!(gets.len(), 1, "{gets:?}");
        assert!(gets[0].ends_with(&format!("/{configured}")), "{gets:?}");
        assert_eq!(
            client
                .list_zones()
                .await
                .unwrap()
                .into_iter()
                .map(|z| z.name)
                .collect::<Vec<_>>(),
            [zone()]
        );
    }

    // From stored configuration, `managed_zones` as an object or as its JSON text.
    for managed in [
        json!({ ZONE: "example-org" }),
        json!(json!({ ZONE: "example-org" }).to_string()),
    ] {
        let settings = json!({
            "project_id": "zw-test-project",
            "managed_zones": managed,
            "dns_url": mock.dns_url(),
            "token_url": mock.token_url(),
        });
        let creds =
            json!({"service_account_key": Seed::standard().key_file(&test_key().private_pem)});
        let any = AnyProvider::from_json(
            ProviderId::GoogleCloud,
            &settings.to_string(),
            &SecretString::from(creds.to_string()),
            &context(),
        )
        .unwrap();
        assert!(any.check(&[zone()]).await.unwrap().zones[0].found);
    }

    // A managed zone of another name, a private one, and one that does not exist.
    mock.control()
        .insert_zone("example-net", "example.net", true);
    for (configured, kind) in [
        ("example-net", Some(ErrorKind::Config)),
        ("example-org-private", None),
        ("missing-zone", None),
    ] {
        let mut config = settings(&mock);
        config.managed_zones = Some(
            [(ZONE.to_owned(), configured.to_owned())]
                .into_iter()
                .collect(),
        );
        let client =
            GoogleCloud::new(config, credentials(&test_key().private_pem), &context()).unwrap();
        let e = add(&client, "BBB").await.unwrap_err();
        assert_eq!(
            e.kind(),
            kind.unwrap_or(ErrorKind::ZoneNotFound),
            "{configured}: {e:?}"
        );
        if kind.is_none() {
            let report = client.check(&[zone()]).await.unwrap();
            assert!(!report.zones[0].found, "{configured}");
            assert!(report.zones[0].detail.is_some(), "{configured}");
        }
    }
}

#[tokio::test]
async fn google_cloud_check_reports_zones() {
    let (mock, client) = setup().await;
    let report = client
        .check(&[zone(), dn("missing.example")])
        .await
        .unwrap();
    assert!(report.credentials_verified);
    assert_eq!(report.zones.len(), 2);
    assert_eq!(report.zones[0].zone, zone());
    assert!(report.zones[0].found);
    assert!(report.zones[0].detail.is_none());
    assert!(!report.zones[1].found);
    // Without zones the credentials are still verified: a token is obtained.
    let (mock2, client2) = setup().await;
    let report = client2.check(&[]).await.unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones.is_empty());
    assert_eq!(mock2.control().tokens_issued(), 1);
    // A cached token proves nothing about the key now: every `check` exchanges a new JWT.
    client2.check(&[]).await.unwrap();
    assert_eq!(mock2.control().tokens_issued(), 2);
    add(&client2, "AAA").await.unwrap();
    assert_eq!(
        mock2.control().tokens_issued(),
        2,
        "the new token is cached"
    );
    // `check` looks zones up afresh every time.
    client.check(&[zone()]).await.unwrap();
    assert_eq!(lookups(&mock), 3);
}

/// `list_zones` returns the public managed zones of the project, all pages, once each, sorted;
/// the IDs are cached. A listing that cannot be read whole is an error.
#[tokio::test]
async fn google_cloud_list_zones_public_all_pages() {
    let mut seed = Seed::standard();
    seed.zones.push(SeedZone {
        name: "private-example".into(),
        dns_name: "private.example.".into(),
        public: false,
    });
    seed.zones.push(SeedZone {
        name: "example-net".into(),
        dns_name: "example.net.".into(),
        public: true,
    });
    let (mock, client) = setup_with(seed).await;
    mock.control().set_zone_page_size(1);
    let zones: Vec<DomainName> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name)
        .collect();
    assert_eq!(zones, [dn("example.net"), zone()]);
    assert_eq!(lookups(&mock), 4);
    let queries: Vec<String> = mock
        .log()
        .matching(Some("GET"), ZONES)
        .into_iter()
        .map(|r| r.query.unwrap_or_default())
        .collect();
    assert_eq!(queries, ["", "pageToken=1", "pageToken=2", "pageToken=3"]);
    add(&client, "AAA").await.unwrap();
    assert_eq!(lookups(&mock), 4, "the zone was cached");

    mock.faults().push(
        Fault::on("GET", ZONES)
            .skip(1)
            .respond(200, r#"{"managedZones":[{"id":"#),
    );
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().push(
        Fault::on("GET", ZONES)
            .always()
            .respond(200, r#"{"managedZones":[],"nextPageToken":"same"}"#),
    );
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().clear();
    mock.faults()
        .push(Fault::on("GET", ZONES).respond(200, "{}"));
    assert!(client.list_zones().await.unwrap().is_empty());
}

#[tokio::test]
async fn google_cloud_zone_not_found() {
    let (mock, client) = setup().await;
    let missing = dn("example.net");
    let name = dn("_acme-challenge.example.net");
    let e = client
        .add_txt_value(&missing, &name, &txt("A"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let e = client
        .remove_txt_value(&missing, &name, &txt("A"))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    assert_eq!(writes(&mock), 0);
}

// ---- Authentication ----------------------------------------------------------------------------

fn decode_part(part: &str) -> Value {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The token request: a form with the grant type and the assertion. The JWT: `alg` RS256, `typ`
/// and `kid` in the header; `iss`, `scope`, `aud` (the token URL), `iat` and `exp` one hour later
/// in the claims; the mock verified its signature. The API gets the access token as a bearer
/// token, and the token request carries none.
#[tokio::test]
async fn google_cloud_jwt_and_token_request_shape() {
    let (mock, client) = setup().await;
    client.check(&[zone()]).await.unwrap();
    let request = mock.log().matching(Some("POST"), TOKEN).pop().unwrap();
    assert_eq!(
        request.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    let body = request.body_str().into_owned();
    let pairs: Vec<&str> = body.split('&').collect();
    assert_eq!(pairs.len(), 2, "{body}");
    assert_eq!(
        pairs[0],
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
    );
    let jwt = pairs[1].strip_prefix("assertion=").unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(
        decode_part(parts[0]),
        json!({"alg": "RS256", "typ": "JWT", "kid": "0123456789abcdef0123456789abcdef01234567"})
    );
    let claims = decode_part(parts[1]);
    assert_eq!(
        claims["iss"],
        "zw-test@zw-test-project.iam.gserviceaccount.test"
    );
    assert_eq!(
        claims["scope"],
        "https://www.googleapis.com/auth/ndev.clouddns.readwrite"
    );
    assert_eq!(claims["aud"], mock.token_url());
    let (iat, exp) = (
        claims["iat"].as_i64().unwrap(),
        claims["exp"].as_i64().unwrap(),
    );
    assert_eq!(exp - iat, 3600);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!((iat - now).abs() < 60);
    let api = mock.log().matching(Some("GET"), ZONES).pop().unwrap();
    assert_eq!(
        api.header("authorization").unwrap(),
        format!("Bearer {}", mock.control().issued_tokens()[0])
    );
    assert!(request.header("authorization").is_none());

    // A key file without `private_key_id` gives a JWT without `kid`.
    let mut key = Seed::standard().key_file(&test_key().private_pem);
    key.as_object_mut().unwrap().remove("private_key_id");
    let client = GoogleCloud::new(settings(&mock), credentials_from(key), &context()).unwrap();
    client.check(&[]).await.unwrap();
    let request = mock.log().matching(Some("POST"), TOKEN).pop().unwrap();
    let body = request.body_str().into_owned();
    let jwt = body.split("assertion=").nth(1).unwrap();
    assert_eq!(
        decode_part(jwt.split('.').next().unwrap()),
        json!({"alg": "RS256", "typ": "JWT"})
    );
}

#[tokio::test]
async fn google_cloud_token_is_cached() {
    let (mock, client) = setup().await;
    for i in 0..5 {
        add(&client, &format!("V{i}")).await.unwrap();
    }
    assert_eq!(mock.control().tokens_issued(), 1);
}

/// A token whose stated lifetime is already over is renewed before the next request.
#[tokio::test]
async fn google_cloud_token_is_renewed_before_expiry() {
    let (mock, client) = setup().await;
    mock.control().set_token_ttl(0);
    add(&client, "A1").await.unwrap();
    add(&client, "A2").await.unwrap();
    let api_requests = mock.log().count(None, "/dns/**");
    assert!(api_requests >= 4);
    assert_eq!(mock.control().tokens_issued(), api_requests);
}

/// A revoked token is answered 401; the client signs a new JWT, obtains a new token and repeats
/// the read.
#[tokio::test]
async fn google_cloud_rejected_token_is_renewed() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    mock.control().revoke_tokens();
    add(&client, "BBB").await.unwrap();
    assert_eq!(mock.control().tokens_issued(), 2);
}

/// A 401 for a freshly obtained token is `Auth`, and nothing is written.
#[tokio::test]
async fn google_cloud_repeated_401_is_auth() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RRSETS).times(5).status(401));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// A key the token endpoint does not accept (another key pair, another service account) is
/// `Auth`, and the DNS API is never contacted. A 400 of the token endpoint is
/// `Auth` with its description.
#[tokio::test]
async fn google_cloud_wrong_key_is_auth() {
    let mock = GoogleCloudMock::start(Seed::standard()).await;
    let seed = Seed::standard();
    let wrong = [seed.key_file(&other_test_key().private_pem), {
        let mut k = seed.key_file(&test_key().private_pem);
        k["client_email"] = json!("other@zw-test-project.iam.gserviceaccount.test");
        k
    }];
    for key in wrong {
        let client = GoogleCloud::new(settings(&mock), credentials_from(key), &context()).unwrap();
        let e = client.check(&[zone()]).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    }
    assert_eq!(mock.log().count(None, "/dns/**"), 0);

    let client = client_with(&mock, &context());
    mock.faults().push(Fault::on("POST", TOKEN).respond(
        400,
        r#"{"error":"invalid_grant","error_description":"Invalid JWT Signature."}"#,
    ));
    let e = client.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(e.to_string().contains("Invalid JWT Signature."), "{e}");
    mock.faults()
        .push(Fault::on("POST", TOKEN).respond(200, r#"{"token_type":"Bearer"}"#));
    let e = client.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

// ---- Transport ---------------------------------------------------------------------------------

/// A short `Retry-After` on a read is waited out, and so is a 413, the quota page's status; a
/// long wait is `RateLimited` with the wait.
#[tokio::test]
async fn google_cloud_rate_limit() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RRSETS).rate_limited("1"));
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), RRSETS), 2);
    mock.faults().push(Fault::on("GET", RRSETS).status(413));
    add(&client, "BBB").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), RRSETS), 4);
    mock.faults()
        .push(Fault::on("GET", RRSETS).rate_limited("120"));
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
}

/// A 5xx on a read is retried; three in a row are `Transient`, which is retryable.
#[tokio::test]
async fn google_cloud_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RRSETS).status(500));
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("GET", RRSETS).times(3).status(503));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("GET"), RRSETS), 5);
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn google_cloud_from_json_builds_the_client() {
    let mock = GoogleCloudMock::start(Seed::standard()).await;
    let settings = json!({
        "project_id": "zw-test-project",
        "dns_url": mock.dns_url(),
        "token_url": mock.token_url(),
    });
    let key = Seed::standard().key_file(&test_key().private_pem);
    // The key file as an object and as its JSON text (a form field); unknown keys are ignored.
    for key in [key.clone(), json!(key.to_string())] {
        let creds = json!({"service_account_key": key, "other": 1});
        let client = AnyProvider::from_json(
            ProviderId::GoogleCloud,
            &settings.to_string(),
            &SecretString::from(creds.to_string()),
            &context(),
        )
        .unwrap();
        assert_eq!(client.id(), ProviderId::GoogleCloud);
        assert!(client.check(&[zone()]).await.unwrap().zones[0].found);
    }
    // The key file's own `token_uri` is not used: the setting is.
    let token_requests = mock.log().count(Some("POST"), TOKEN);
    assert_eq!(token_requests, 2);
}

/// Configuration errors are `Config`, name the key and never repeat a value; malformed key
/// material is a fixed text.
#[test]
fn google_cloud_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || {
        json!({
            "project_id": "zw-test-project",
            "dns_url": "http://127.0.0.1:1/dns/v1",
            "token_url": "http://127.0.0.1:1/token",
        })
    };
    let with = |key: &str, value: Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let key = |field: &str, value: Value| {
        let mut key = Seed::standard().key_file(&test_key().private_pem);
        key[field] = value;
        json!({"service_account_key": key}).to_string()
    };
    let good = key("private_key_id", json!("0123456789abcdef"));
    let truncated: String = test_key().private_pem.chars().take(400).collect();
    let ec = {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = aws_lc_rs::signature::EcdsaKeyPair::generate_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        zonewright_mock::google_cloud::pem("PRIVATE KEY", pkcs8.as_ref())
    };
    let cases = [
        (
            {
                let mut s = base();
                s.as_object_mut().unwrap().remove("project_id");
                s
            },
            good.clone(),
            "settings",
        ),
        (with(canary, json!(canary)), good.clone(), "settings"),
        (
            with("project_id", json!(format!("{canary}/x"))),
            good.clone(),
            "project_id",
        ),
        (with("project_id", json!("")), good.clone(), "project_id"),
        (
            with(
                "managed_zones",
                json!({ format!("{canary} not a name"): "zone-a" }),
            ),
            good.clone(),
            "managed_zones",
        ),
        (
            with(
                "managed_zones",
                json!({ "example.org": format!("{canary}/x") }),
            ),
            good.clone(),
            "managed_zones",
        ),
        (with("ttl", json!(0)), good.clone(), "ttl"),
        (
            with("change_poll_ms", json!(10)),
            good.clone(),
            "change_poll_ms",
        ),
        (
            with(
                "dns_url",
                json!(format!("https://u:{canary}@api.example.org")),
            ),
            good.clone(),
            "dns_url",
        ),
        (
            with(
                "token_url",
                json!(format!("https://oauth.example.org/?{canary}")),
            ),
            good.clone(),
            "token_url",
        ),
        (
            base(),
            json!({"service_account_key": canary}).to_string(),
            "service_account_key",
        ),
        (
            base(),
            json!({"secret": canary}).to_string(),
            "service_account_key",
        ),
        (
            base(),
            key("type", json!("authorized_user")),
            "service_account_key",
        ),
        (
            base(),
            key("client_email", json!("")),
            "service_account_key.client_email",
        ),
        (
            base(),
            key(
                "private_key",
                json!(format!(
                    "{canary}\n-----BEGIN PRIVATE KEY-----\n{canary}\n-----END PRIVATE KEY-----\n"
                )),
            ),
            "service_account_key.private_key",
        ),
        (
            base(),
            key("private_key", json!(ec)),
            "service_account_key.private_key",
        ),
        (
            base(),
            key("private_key", json!(truncated)),
            "service_account_key.private_key",
        ),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::GoogleCloud,
            &settings.to_string(),
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{key}: {e:?}");
        let text = format!("{e} | {e:?}");
        assert!(text.contains(key), "{key}: {text}");
        assert!(!text.contains(canary), "{key}: {text}");
        assert!(!text.contains("MII"), "{key}: key material in {text}");
    }
    AnyProvider::from_json(
        ProviderId::GoogleCloud,
        &base().to_string(),
        &SecretString::from(good),
        &ctx,
    )
    .unwrap();
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round; the metadata's defaults are those of the settings type.
#[test]
fn google_cloud_config_keys_match_metadata() {
    let meta = ProviderId::GoogleCloud.meta();
    let settings = serde_json::to_value(GoogleCloudConfig::new("p".into())).unwrap();
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
    assert_eq!(secret, ["service_account_key"]);
    for field in meta.fields.iter().filter(|f| f.default.is_some()) {
        let value = &settings[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
    }
    let caps = &meta.capabilities;
    assert!(caps.add_txt_value && caps.remove_txt_value && caps.list_zones);
    assert_eq!(caps.txt_values, zonewright::ValueGuarantee::Conditional);
    assert_eq!(caps.preconditions, zonewright::Preconditions::Atomic);
    assert_eq!(
        meta.default_propagation_timeout,
        Some(Duration::from_secs(180))
    );
}

// ---- Record level ------------------------------------------------------------------------------

/// Every writable type in the record-level list goes through set, get and list with canonical
/// equality (a wildcard, the apex, a long TXT value and multi-value sets among them), is
/// written as its canonical text with the name absolute, is `Unchanged` on a repeat without a
/// change, and is deleted under an exact expectation.
#[tokio::test]
async fn google_cloud_record_round_trips() {
    let (mock, client) = setup().await;
    let long = Txt::new("k".repeat(300)).unwrap().to_data().unwrap();
    let cases: Vec<(&str, RecordType, Vec<String>)> = vec![
        (
            REC,
            RecordType::A,
            vec!["192.0.2.1".into(), "192.0.2.2".into()],
        ),
        (REC, RecordType::AAAA, vec!["2001:db8::1".into()]),
        (
            "*.wild.example.org",
            RecordType::A,
            vec!["192.0.2.3".into()],
        ),
        (
            ZONE,
            RecordType::MX,
            vec!["10 mx1.example.org.".into(), "20 mx2.example.net.".into()],
        ),
        (
            ZONE,
            RecordType::CAA,
            vec![
                "0 issue \"letsencrypt.org\"".into(),
                "0 iodef \"mailto:a@example.org\"".into(),
            ],
        ),
        (
            "alias.example.org",
            RecordType::CNAME,
            vec!["target.example.net.".into()],
        ),
        (
            "sub.example.org",
            RecordType::NS,
            vec!["ns1.example.net.".into(), "ns2.example.net.".into()],
        ),
        (
            "_sip._tcp.example.org",
            RecordType::SRV,
            vec!["10 60 5060 sip.example.org.".into()],
        ),
        (
            "_25._tcp.example.org",
            RecordType::TLSA,
            vec!["3 1 1 0a1b2c".into()],
        ),
        (
            "txt.example.org",
            RecordType::TXT,
            vec!["\"v=spf1 -all\"".into(), long.as_str().to_owned()],
        ),
    ];
    for (owner, rtype, texts) in &cases {
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        let set = rrset(owner, *rtype, Some(300), &texts);
        assert_eq!(
            client
                .set_rrset(&zone(), &set, Expect::Absent)
                .await
                .unwrap(),
            SetOutcome::Created,
            "{owner} {rtype}"
        );
        let addition = &last_change(&mock)["additions"][0];
        assert_eq!(addition["name"], dn(owner).as_str(), "{owner} {rtype}");
        assert_eq!(addition["ttl"], 300);
        let sent: Vec<&str> = addition["rrdatas"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let canonical: Vec<String> = set
            .records()
            .iter()
            .map(|r| r.as_str().to_owned())
            .collect();
        assert_eq!(sent, canonical, "{owner} {rtype}");
        let read = client
            .get_rrset(&zone(), &dn(owner), *rtype)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, set, "{owner} {rtype}");
        let before = writes(&mock);
        assert_eq!(
            client.set_rrset(&zone(), &set, Expect::Any).await.unwrap(),
            SetOutcome::Unchanged,
            "{owner} {rtype}"
        );
        assert_eq!(writes(&mock), before);
    }
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.skipped.is_empty(), "{:?}", listing.skipped);
    for (owner, rtype, texts) in &cases {
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        let set = rrset(owner, *rtype, Some(300), &texts);
        assert!(listing.rrsets.contains(&set), "{owner} {rtype}");
    }
    // The apex NS and SOA of the zone are listed too.
    assert!(
        listing
            .rrsets
            .iter()
            .any(|s| s.name() == &zone() && s.rtype() == RecordType::SOA)
    );
    for (owner, rtype, texts) in &cases {
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        let set = rrset(owner, *rtype, Some(300), &texts);
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(owner), *rtype, Expect::Matches(&set))
                .await
                .unwrap(),
            DeleteOutcome::Deleted,
            "{owner} {rtype}"
        );
    }
    assert!(user_rrsets(&mock).is_empty());
}

/// A value the client cannot send is refused after the read and before any change: escapes,
/// and TXT over 1000 characters. A value the rrset holds already is written back as read, so a
/// foreign value of that kind does not block a change next to it.
#[tokio::test]
async fn google_cloud_escapes_and_long_txt_are_not_sent() {
    let (mock, client) = setup().await;
    for set in [
        RrSet::new(
            dn(REC),
            RecordType::TXT,
            None,
            [Txt::new("say \"hi\"").unwrap().to_data().unwrap()],
        )
        .unwrap(),
        RrSet::new(
            dn(REC),
            RecordType::TXT,
            None,
            [Txt::new("x".repeat(1000)).unwrap().to_data().unwrap()],
        )
        .unwrap(),
        rrset(REC, RecordType::CAA, None, &["0 issue \"a\\\\b\""]),
    ] {
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{set:?}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);
    mock.control()
        .insert_rrset(ZONE, REC, "TXT", 60, &["\"say \\\"hi\\\"\""]);
    let held = client
        .get_rrset(&zone(), &dn(REC), RecordType::TXT)
        .await
        .unwrap()
        .unwrap();
    let mut records: Vec<RecordData> = held.records().to_vec();
    records.push(Txt::new("next").unwrap().to_data().unwrap());
    let next = RrSet::new(dn(REC), RecordType::TXT, None, records).unwrap();
    assert_eq!(
        client.set_rrset(&zone(), &next, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        stored(&mock, REC, "TXT"),
        ["\"say \\\"hi\\\"\"", "\"next\""]
    );
}

#[tokio::test]
async fn google_cloud_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZONE, REC, "A", 600, &["192.0.2.1"]);
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.9"]);
    let wrong = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    let wrong_ttl = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    for expect in [
        Expect::Absent,
        Expect::Matches(&wrong),
        Expect::Matches(&wrong_ttl),
    ] {
        let e = client
            .set_rrset(&zone(), &wanted, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{expect:?}: {e:?}");
        assert!(!e.is_retryable());
    }
    for expect in [Expect::Matches(&wrong), Expect::Matches(&wrong_ttl)] {
        let e = client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{expect:?}: {e:?}");
    }
    let missing = rrset(REC, RecordType::MX, None, &["10 mail.example.org."]);
    let e = client
        .set_rrset(&zone(), &missing, Expect::Matches(&missing))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::MX, Expect::Matches(&missing))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(stored(&mock, REC, "A"), ["192.0.2.1"]);

    // The expectation holds: with the TTL, and without one.
    let current = rrset(REC, RecordType::A, Some(600), &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&current))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &missing, Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
}

/// `Expect::Any` replaces the data; the change repeats the rrset exactly as read in its
/// deletion and keeps every other member in its addition, the TTL unless one is requested; a
/// new rrset gets the configured TTL.
#[tokio::test]
async fn google_cloud_set_replaces_and_keeps_the_rest() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZONE, REC, "A", 600, &["192.0.2.1", "192.0.2.2"]);
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.2", "192.0.2.9"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let body = last_change(&mock);
    let read = json!({
        "kind": "dns#resourceRecordSet",
        "name": "rec.example.org.",
        "type": "A",
        "ttl": 600,
        "rrdatas": ["192.0.2.1", "192.0.2.2"]
    });
    assert_eq!(body["deletions"], json!([read]));
    assert_eq!(
        body["additions"],
        json!([{
            "kind": "dns#resourceRecordSet",
            "name": "rec.example.org.",
            "type": "A",
            "ttl": 600,
            "rrdatas": ["192.0.2.2", "192.0.2.9"]
        }])
    );
    assert_eq!(control.rrset(ZONE, REC, "A").unwrap().ttl, Some(600));

    // A requested TTL is applied.
    let retuned = rrset(REC, RecordType::A, Some(120), &["192.0.2.2", "192.0.2.9"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &retuned, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(last_change(&mock)["additions"][0]["ttl"], json!(120));

    // A new rrset without a TTL gets the configured one.
    let fresh = rrset("fresh.example.org", RecordType::A, None, &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &fresh, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    assert_eq!(
        last_change(&mock),
        json!({
            "additions": [{"name": "fresh.example.org.", "type": "A", "ttl": 120, "rrdatas": ["192.0.2.1"]}],
            "deletions": []
        })
    );

    // A member the client does not know is written back unchanged: the answer is served by a
    // fault, so the mock's own schema check refuses the change, and the request shows it.
    mock.faults().push(Fault::on("GET", RRSETS).respond(
        200,
        r#"{"rrsets":[{"kind":"dns#resourceRecordSet","name":"rec.example.org.","type":"A","ttl":120,"rrdatas":["192.0.2.2","192.0.2.9"],"healthCheck":"x"}]}"#,
    ));
    let before = writes(&mock);
    // The change with the unknown member is refused; the new read finds the rrset as the mock
    // holds it (without the member), so the layer runs once more and replaces it.
    assert_eq!(
        client
            .set_rrset(
                &zone(),
                &rrset(REC, RecordType::A, None, &["192.0.2.7"]),
                Expect::Any,
            )
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(writes(&mock), before + 2);
    let body = mock.log().matching(Some("POST"), CHANGES)[before]
        .body_json()
        .unwrap();
    assert_eq!(body["additions"][0]["healthCheck"], "x");
    assert_eq!(body["deletions"][0]["healthCheck"], "x");
}

/// `delete_rrset` with each expectation: a deletion only, `NotPresent` without a change, and
/// `Absent` refused before any request.
#[tokio::test]
async fn google_cloud_delete_rrset_expectations() {
    let (mock, client) = setup().await;
    let a = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    client.set_rrset(&zone(), &a, Expect::Absent).await.unwrap();
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Matches(&a))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert_eq!(
        last_change(&mock),
        json!({
            "additions": [],
            "deletions": [{
                "kind": "dns#resourceRecordSet",
                "name": "rec.example.org.", "type": "A", "ttl": 300, "rrdatas": ["192.0.2.1"]
            }]
        })
    );
    let before = writes(&mock);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    let requests = mock.log().len();
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Absent)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(
        mock.log().len(),
        requests,
        "an invalid delete made a request"
    );
}

/// SOA is read-only and the apex NS rrset belongs to the provider: writes are refused before any
/// request; reading them works, and a delegation below the apex is ordinary data.
#[tokio::test]
async fn google_cloud_protected_sets_send_nothing() {
    let (mock, client) = setup().await;
    let soa = client
        .get_rrset(&zone(), &zone(), RecordType::SOA)
        .await
        .unwrap()
        .unwrap();
    let apex_ns = rrset(ZONE, RecordType::NS, None, &["ns.example.com."]);
    let requests = mock.log().len();
    let errors = [
        (
            client
                .set_rrset(&zone(), &soa, Expect::Any)
                .await
                .unwrap_err(),
            ErrorKind::UnsupportedRecordType,
        ),
        (
            client
                .delete_rrset(&zone(), &zone(), RecordType::SOA, Expect::Any)
                .await
                .unwrap_err(),
            ErrorKind::UnsupportedRecordType,
        ),
        (
            client
                .set_rrset(&zone(), &apex_ns, Expect::Any)
                .await
                .unwrap_err(),
            ErrorKind::InvalidInput,
        ),
        (
            client
                .delete_rrset(&zone(), &zone(), RecordType::NS, Expect::Any)
                .await
                .unwrap_err(),
            ErrorKind::InvalidInput,
        ),
    ];
    for (e, kind) in errors {
        assert_eq!(e.kind(), kind, "{e:?}");
    }
    assert_eq!(mock.log().len(), requests);
    let read = client
        .get_rrset(&zone(), &zone(), RecordType::NS)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.records().len(), 4);
}

/// The listing: every rrset of every type, all pages; what the model cannot hold is skipped
/// with a reason, and one `WARN` event per listing says how many.
#[tokio::test(flavor = "current_thread")]
async fn google_cloud_listing_reports_skipped_sets() {
    let (capture, _guard) = LogCapture::install();
    let (mock, client) = setup().await;
    let control = mock.control();
    control.set_rrset_page_size(2);
    control.insert_rrset(ZONE, REC, "A", 600, &["192.0.2.1"]);
    control.insert_rrset(ZONE, REC, "TXT", 600, &["\"v=spf1 -all\""]);
    control.insert_rrset(ZONE, "odd.example.org", "A", 600, &["not-an-address"]);
    control.insert_rrset(ZONE, "mx.example.org", "MX", 600, &["10 mail"]);
    control.insert_rrset(ZONE, "w.example.org", "WIZARD", 600, &["magic"]);
    control.insert_rrset(ZONE, "ptr.example.org", "PTR", 600, &["host.example.net."]);
    let long_label = format!("{}.example.org", "x".repeat(64));
    control.insert_rrset(ZONE, &long_label, "A", 600, &["192.0.2.1"]);
    control.insert_rrset(
        ZONE,
        "c.example.org",
        "CNAME",
        600,
        &["a.example.net.", "b.example.net."],
    );
    control.insert_rrset(ZONE, "geo.example.org", "A", 600, &[]);
    control.edit_rrset(ZONE, "geo.example.org", "A", |set| {
        set.routing_policy = Some(json!({"wrr": {"items": []}}));
    });

    let listing = client.list_rrsets(&zone()).await.unwrap();
    let sets: Vec<(String, RecordType)> = listing
        .rrsets
        .iter()
        .map(|s| (s.name().to_string(), s.rtype()))
        .collect();
    assert_eq!(
        sets,
        [
            ("example.org.".to_owned(), RecordType::NS),
            ("example.org.".to_owned(), RecordType::SOA),
            ("mx.example.org.".to_owned(), RecordType::MX),
            ("odd.example.org.".to_owned(), RecordType::A),
            ("ptr.example.org.".to_owned(), RecordType::PTR),
            ("rec.example.org.".to_owned(), RecordType::A),
            ("rec.example.org.".to_owned(), RecordType::TXT),
        ]
    );
    let odd = &listing.rrsets[3];
    assert!(!odd.records()[0].is_canonical());
    // A name inside a value without the trailing dot is not guessed.
    assert!(!listing.rrsets[2].records()[0].is_canonical());
    // A type outside `record_types` is listed, canonical where it parses.
    assert!(listing.rrsets[4].records()[0].is_canonical());
    let mut skipped: Vec<(String, String, SkipReason)> = listing
        .skipped
        .iter()
        .map(|s| (s.name.to_string(), s.type_name.clone(), s.reason))
        .collect();
    skipped.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
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
    assert_eq!(warnings[0].field("skipped"), Some("4"));
    assert_eq!(warnings[0].field("provider"), Some("google_cloud"));
    let lists = mock.log().matching(Some("GET"), RRSETS);
    assert_eq!(lists.len(), 6, "every page of 11 rrsets");
    assert_eq!(lists[0].query, None, "no page size is sent");
}

/// A listing that cannot be read whole is an error, never a shorter result; an empty page with
/// a token is followed; a page without `rrsets` is empty.
#[tokio::test]
async fn google_cloud_listing_pages_oddly() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RRSETS).respond(200, r#"{"rrsets":[],"nextPageToken":"0"}"#));
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(listing.rrsets.len(), 2, "the apex NS and SOA");
    mock.faults().push(
        Fault::on("GET", RRSETS)
            .always()
            .respond(200, r#"{"nextPageToken":"same"}"#),
    );
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().clear();
    mock.faults()
        .push(Fault::on("GET", RRSETS).respond(200, r#"{"rrsets":[{"name":"#));
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().push(
        Fault::on("GET", RRSETS).respond(200, r#"{"kind":"dns#resourceRecordSetsListResponse"}"#),
    );
    assert!(client.list_rrsets(&zone()).await.unwrap().rrsets.is_empty());
    // A read of one name and type answered with another name, or with two rrsets.
    for body in [
        r#"{"rrsets":[{"name":"other.example.org.","type":"A","ttl":60,"rrdatas":["192.0.2.1"]}]}"#,
        r#"{"rrsets":[{"name":"rec.example.org.","type":"A","ttl":60,"rrdatas":["192.0.2.1"]},{"name":"rec.example.org.","type":"A","ttl":60,"rrdatas":["192.0.2.2"]}]}"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", RRSETS).respond(200, body));
        let e = client
            .get_rrset(&zone(), &dn(REC), RecordType::A)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
}

#[tokio::test]
async fn google_cloud_record_concurrent_change_is_conflict() {
    for status in [412u16, 400, 409, 404] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.set_precondition_status(status);
        control.set_addition_of_existing(AdditionOfExisting::Refuse(status));
        control.insert_rrset(ZONE, REC, "A", 60, &["192.0.2.1"]);
        let foreign_change = |data: &'static [&'static str]| {
            let hook = control.clone();
            Fault::on("POST", CHANGES).run(move || hook.insert_rrset(ZONE, REC, "A", 60, data))
        };

        // `Any`: refused once, read again, replaced.
        mock.faults().push(foreign_change(&["198.51.100.1"]));
        let wanted = rrset(REC, RecordType::A, None, &["192.0.2.9"]);
        let before = writes(&mock);
        assert_eq!(
            client
                .set_rrset(&zone(), &wanted, Expect::Any)
                .await
                .unwrap(),
            SetOutcome::Replaced,
            "{status}"
        );
        assert_eq!(writes(&mock), before + 2, "{status}");
        assert_eq!(stored(&mock, REC, "A"), ["192.0.2.9"], "{status}");
        assert_eq!(
            last_change(&mock)["deletions"][0]["rrdatas"],
            json!(["198.51.100.1"]),
            "{status}: the re-run is conditional on the new state"
        );

        // `Matches`: the re-run sees the change and fails the expectation.
        let current = rrset(REC, RecordType::A, None, &["192.0.2.9"]);
        mock.faults().push(foreign_change(&["198.51.100.2"]));
        let e = client
            .set_rrset(
                &zone(),
                &rrset(REC, RecordType::A, None, &["192.0.2.10"]),
                Expect::Matches(&current),
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{status}: {e:?}");
        assert_eq!(stored(&mock, REC, "A"), ["198.51.100.2"], "{status}");

        // Two changes in a row: `Conflict`, nothing of ours written.
        let hook = control.clone();
        let n = Arc::new(std::sync::atomic::AtomicU32::new(0));
        mock.faults()
            .push(Fault::on("POST", CHANGES).times(2).run(move || {
                let i = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                hook.insert_rrset(
                    ZONE,
                    REC,
                    "A",
                    60,
                    &[["198.51.100.3", "198.51.100.4"][i as usize]],
                );
            }));
        let before = writes(&mock);
        let e = client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Conflict, "{status}: {e:?}");
        assert_eq!(writes(&mock), before + 2, "{status}");
        assert_eq!(stored(&mock, REC, "A"), ["198.51.100.4"], "{status}");

        // `Absent`, and the rrset is created by someone else after the read.
        let other = "other.example.org";
        let hook = control.clone();
        mock.faults().push(Fault::on("POST", CHANGES).run(move || {
            hook.insert_rrset(ZONE, other, "A", 60, &["198.51.100.5"]);
        }));
        let e = client
            .set_rrset(
                &zone(),
                &rrset(other, RecordType::A, None, &["192.0.2.1"]),
                Expect::Absent,
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{status}: {e:?}");
        assert_eq!(stored(&mock, other, "A"), ["198.51.100.5"], "{status}");

        // A delete under `Matches` meets a change: the changed rrset stays.
        let seen = client
            .get_rrset(&zone(), &dn(other), RecordType::A)
            .await
            .unwrap()
            .unwrap();
        let hook = control.clone();
        mock.faults().push(Fault::on("POST", CHANGES).run(move || {
            hook.insert_rrset(ZONE, other, "A", 60, &["198.51.100.6"]);
        }));
        let e = client
            .delete_rrset(&zone(), &dn(other), RecordType::A, Expect::Matches(&seen))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{status}: {e:?}");
        assert_eq!(stored(&mock, other, "A"), ["198.51.100.6"], "{status}");

        // A delete whose rrset someone else deleted first is done.
        let hook = control.clone();
        mock.faults().push(Fault::on("POST", CHANGES).run(move || {
            hook.delete_rrset(ZONE, other, "A");
        }));
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(other), RecordType::A, Expect::Any)
                .await
                .unwrap(),
            DeleteOutcome::Deleted,
            "{status}"
        );
    }
}

/// Every record-level change is sent exactly once: a 502, a 429, a 413 and a 401 each end the
/// operation with nothing changed, and the repeat converges.
#[tokio::test]
async fn google_cloud_record_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let a = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    let b = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    for status in [502u16, 429, 413, 401] {
        for step in ["create", "replace", "delete"] {
            if step != "create" {
                client.set_rrset(&zone(), &a, Expect::Any).await.unwrap();
            }
            let fault = Fault::on("POST", CHANGES);
            mock.faults().push(if status == 429 {
                fault.rate_limited("1")
            } else {
                fault.status(status)
            });
            let before = writes(&mock);
            let state = stored(&mock, REC, "A");
            let e = match step {
                "create" => client
                    .set_rrset(&zone(), &a, Expect::Absent)
                    .await
                    .unwrap_err(),
                "replace" => client
                    .set_rrset(&zone(), &b, Expect::Any)
                    .await
                    .unwrap_err(),
                _ => client
                    .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
                    .await
                    .unwrap_err(),
            };
            let expected = match status {
                429 | 413 => ErrorKind::RateLimited,
                _ => ErrorKind::Transient,
            };
            assert_eq!(e.kind(), expected, "{status} {step}: {e:?}");
            assert_eq!(writes(&mock), before + 1, "{status} {step}");
            assert_eq!(stored(&mock, REC, "A"), state, "{status} {step}");
            let again = match step {
                "create" => client
                    .set_rrset(&zone(), &a, Expect::Absent)
                    .await
                    .map(|_| ()),
                "replace" => client.set_rrset(&zone(), &b, Expect::Any).await.map(|_| ()),
                _ => client
                    .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
                    .await
                    .map(|_| ()),
            };
            again.unwrap();
            client
                .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
                .await
                .unwrap();
            assert!(user_rrsets(&mock).is_empty(), "{status} {step}");
        }
    }
}

/// The zone is recreated under a new ID: the read and the listing look it up again, and a
/// change that meets the stale ID runs once more.
#[tokio::test]
async fn google_cloud_record_stale_zone_id() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let a = rrset(REC, RecordType::A, Some(60), &["192.0.2.1"]);
    client.set_rrset(&zone(), &a, Expect::Absent).await.unwrap();
    control.recreate_zone(ZONE);
    assert_eq!(
        client
            .get_rrset(&zone(), &dn(REC), RecordType::A)
            .await
            .unwrap(),
        Some(a.clone())
    );
    control.recreate_zone(ZONE);
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.rrsets.contains(&a));
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", CHANGES).run(move || {
        hook.recreate_zone(ZONE);
    }));
    let b = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &b, Expect::Matches(&a))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, REC, "A"), ["192.0.2.2"]);
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

/// The live client, built from the maintainer's settings and credentials.
fn live_client(ctx: &Context) -> AnyProvider {
    AnyProvider::from_json(
        ProviderId::GoogleCloud,
        &live_env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_SETTINGS"),
        &SecretString::from(live_env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_CREDENTIALS")),
        ctx,
    )
    .unwrap()
}

/// Adds and removes two values under a generated label in the zone the maintainer names, and
/// removes exactly the values it added afterwards, also when the body failed.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_google_cloud_add_and_remove() {
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(live_client(&ctx));
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

/// A record-level round trip of A (with a TTL), MX, CAA and TXT (with spaces and more than 255
/// characters) on a name the test generates: created under `Expect::Absent`, read back equal,
/// `Unchanged` when written again, listed, replaced under `Expect::Matches`; deleted afterwards,
/// also when the body failed, and only while they hold nothing but what the test wrote.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_google_cloud_record_round_trip() {
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(live_client(&ctx));
    let tag = random_u64();
    let records = zone.prepend(&format!("_zw-live-{tag:016x}-rr")).unwrap();
    let set = |rtype: RecordType, ttl: Option<u32>, data: Vec<RecordData>| {
        RrSet::new(
            records.clone(),
            rtype,
            ttl.map(|t| RrsetTtl::from_secs(t).unwrap()),
            data,
        )
        .unwrap()
    };
    let a_set = set(
        RecordType::A,
        Some(120),
        vec![
            rd(RecordType::A, "192.0.2.1"),
            rd(RecordType::A, "192.0.2.2"),
        ],
    );
    let a_next = set(RecordType::A, None, vec![rd(RecordType::A, "192.0.2.3")]);
    let sets = [
        a_set.clone(),
        set(
            RecordType::MX,
            None,
            vec![rd(RecordType::MX, &format!("10 mx.{}", zone.as_str()))],
        ),
        set(
            RecordType::CAA,
            None,
            vec![rd(RecordType::CAA, "0 issue \"letsencrypt.org\"")],
        ),
        set(
            RecordType::TXT,
            None,
            vec![
                Txt::new(format!("zw-live {tag:016x} with spaces"))
                    .unwrap()
                    .to_data()
                    .unwrap(),
                Txt::new("z".repeat(300)).unwrap().to_data().unwrap(),
            ],
        ),
    ];
    let outcome = tokio::spawn({
        let (client, zone, records, sets) =
            (client.clone(), zone.clone(), records.clone(), sets.clone());
        let (a_set, a_next) = (a_set.clone(), a_next.clone());
        async move {
            for set in &sets {
                assert_eq!(
                    client.set_rrset(&zone, set, Expect::Absent).await.unwrap(),
                    SetOutcome::Created,
                    "{}",
                    set.rtype()
                );
                let read = client
                    .get_rrset(&zone, &records, set.rtype())
                    .await
                    .unwrap()
                    .unwrap();
                eprintln!("record-level probe: {} read back as {read:?}", set.rtype());
                assert!(read.same_records(set), "{read:?}");
                assert_eq!(
                    client.set_rrset(&zone, set, Expect::Any).await.unwrap(),
                    SetOutcome::Unchanged
                );
            }
            let listing = client.list_rrsets(&zone).await.unwrap();
            assert!(listing.rrsets.contains(&a_set));
            assert_eq!(
                client
                    .set_rrset(&zone, &a_next, Expect::Matches(&a_set))
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
        }
    })
    .await;
    let mut cleanup = Vec::new();
    for set in &sets {
        let rtype = set.rtype();
        let mut ours = set.records().to_vec();
        if rtype == RecordType::A {
            ours.extend(a_next.records().iter().cloned());
        }
        match client.get_rrset(&zone, &records, rtype).await {
            Ok(Some(current)) if current.records().iter().all(|r| ours.contains(r)) => {
                if let Err(e) = client
                    .delete_rrset(&zone, &records, rtype, Expect::Matches(&current))
                    .await
                {
                    cleanup.push(format!("{e}"));
                }
            }
            Ok(Some(_)) => {
                cleanup.push(format!("{rtype} at the test's name holds foreign records"))
            }
            Ok(None) => {}
            Err(e) => cleanup.push(format!("{e}")),
        }
    }
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}

/// The assumptions the client depends on that no source states, through the public operations
/// (the change semantics themselves, a stale deletion, an addition of an existing rrset and a
/// mixed change, are probed directly by `live_google_cloud_change_semantics` in
/// `src/providers/google_cloud/live.rs`), each exercised under a name
/// prefix the maintainer gives (`ZONEWRIGHT_LIVE_GOOGLE_CLOUD_PREFIX`, a label below the zone):
///
/// 1. a missing rrset is an empty listing for a name and type, not a 404;
/// 2. the change's deletion of an rrset that changed since the read is refused (two clients on
///    separate contexts race; the outcomes are printed), and the client turns the refusal into a
///    repeat or `Conflict`, never into a lost value;
/// 3. a change is answered `pending` or `done`, and `changes.get` answers it;
/// 4. a TXT value written quoted reads back in a form `read_txt` decodes to the same value;
/// 5. the zones the client lists, from `visibility` (printed: a zone without it is taken as
///    public);
/// 6. a managed zone that does not exist is answered 404 by `managedZones.get` (a configured
///    managed zone of a generated name is reported not found, not as an error).
///
/// Everything it creates is under `<prefix>-<random>`, and is removed afterwards with the value
/// operations, also when the body failed. Step 6 writes nothing.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn google_cloud_live_assumptions() {
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_ZONE"));
    let prefix = live_env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_PREFIX");
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let other_ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(live_client(&ctx));
    let second = Arc::new(live_client(&other_ctx));
    let tag = random_u64();
    let name = zone.prepend(&format!("{prefix}-{tag:016x}")).unwrap();
    let values: Vec<Txt> = ["a", "b", "c", "d"]
        .iter()
        .map(|s| txt(&format!("zw-live-{tag:016x}-{s}")))
        .collect();
    let outcome = tokio::spawn({
        let (client, second, zone, name, values) = (
            client.clone(),
            second.clone(),
            zone.clone(),
            name.clone(),
            values.clone(),
        );
        async move {
            // 1: a fresh name reads as absent.
            assert_eq!(
                client
                    .get_rrset(&zone, &name, RecordType::TXT)
                    .await
                    .unwrap(),
                None
            );
            // 3, 4, 5: written values read back, in order, as the same values.
            for value in &values[..2] {
                client
                    .add_txt_value(&zone, &name, value, None)
                    .await
                    .unwrap();
            }
            let read = client
                .get_rrset(&zone, &name, RecordType::TXT)
                .await
                .unwrap()
                .unwrap();
            eprintln!("assumption probe: TXT read back as {read:?}");
            let mut expected: Vec<RecordData> =
                values[..2].iter().map(|v| v.to_data().unwrap()).collect();
            expected.sort();
            let mut records = read.records().to_vec();
            records.sort();
            assert_eq!(records, expected, "{read:?}");
            // 2: two clients on separate contexts change the same rrset at once; neither value
            // is lost, and a refusal surfaces only as `Conflict`.
            let (a, b) = tokio::join!(
                client.add_txt_value(&zone, &name, &values[2], None),
                second.add_txt_value(&zone, &name, &values[3], None),
            );
            eprintln!("assumption probe: concurrent adds {a:?} / {b:?}");
            for result in [&a, &b] {
                if let Err(e) = result {
                    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
                }
            }
            for value in &values {
                client
                    .add_txt_value(&zone, &name, value, None)
                    .await
                    .unwrap();
            }
            // 5: the zones the client lists.
            eprintln!(
                "assumption probe: zones {:?}",
                client.list_zones().await.unwrap()
            );
        }
    })
    .await;
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

    // 6: a configured managed zone that does not exist. Read only.
    let mut settings: Value =
        serde_json::from_str(&live_env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_SETTINGS")).unwrap();
    let missing = zone
        .prepend(&format!("{prefix}-{tag:016x}-missing"))
        .unwrap();
    settings["managed_zones"] = json!({ missing.as_str(): format!("zw-live-missing-{tag:016x}") });
    let probe = AnyProvider::from_json(
        ProviderId::GoogleCloud,
        &settings.to_string(),
        &SecretString::from(live_env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_CREDENTIALS")),
        &ctx,
    )
    .unwrap();
    let report = probe.check([&missing]).await.unwrap();
    eprintln!("assumption probe: missing managed zone {report:?}");
    assert!(!report.zones[0].found, "{report:?}");
}

// ---- Link to the DNS mock ----------------------------------------------------------------------

#[cfg(feature = "inspector")]
mod dns_link {
    use zonewright::{Expect, Provider, RecordType};
    use zonewright_mock::changes::ChangeSource;
    use zonewright_mock::dns::{DnsMock, Role};
    use zonewright_mock::link::{LinkOptions, link};

    use super::{NAME, REC, ZONE, add, rrset, setup, zone};
    use crate::common::link::{ask, is_absent, rd, txt, txt_round_trip, values};

    /// A value written through the client is served over DNS; the provider's other spellings of
    /// names and TXT data are served in one form.
    #[tokio::test]
    async fn google_cloud_txt_value_is_served_over_dns() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = txt_round_trip(&mock, &client, &dns).await;
        let control = mock.control();
        control.insert_rrset(
            ZONE,
            "alias.example.org",
            "CNAME",
            300,
            &["target.example.net"],
        );
        control.insert_rrset(ZONE, "plain.example.org", "TXT", 300, &["plain"]);
        control.insert_rrset(ZONE, "split.example.org", "TXT", 300, &["\"a b\" \"c\""]);
        link.settled().await;
        assert_eq!(link.skipped(), 0);
        assert_eq!(
            values(ask(dns.addr(), "alias.example.org", RecordType::CNAME).await),
            [rd(RecordType::CNAME, "target.example.net.")]
        );
        assert_eq!(
            values(ask(dns.addr(), "plain.example.org", RecordType::TXT).await),
            [txt("plain")]
        );
        assert_eq!(
            values(ask(dns.addr(), "split.example.org", RecordType::TXT).await),
            [rd(RecordType::TXT, "\"a b\" \"c\"")]
        );
        // The private zone of the same name is not published a second time.
        assert_eq!(mock.published().zones, ["example.org"]);
    }

    /// Record-level data written through the client are served; `reset` returns the mock to its
    /// seed.
    #[tokio::test]
    async fn google_cloud_records_are_served_and_reset() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = link(&mock, &dns, LinkOptions::new());
        let mx = rrset(REC, RecordType::MX, Some(300), &["10 mx.example.org."]);
        client.set_rrset(&zone(), &mx, Expect::Any).await.unwrap();
        add(&client, "before-reset").await.unwrap();
        link.settled().await;
        assert_eq!(
            values(ask(dns.addr(), REC, RecordType::MX).await),
            [rd(RecordType::MX, "10 mx.example.org.")]
        );
        mock.control().reset();
        link.settled().await;
        assert!(mock.log().is_empty());
        assert_eq!(mock.control().tokens_issued(), 0);
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
