//! Tests of the Yandex Cloud client (`yandex_cloud`) against its mock.
#![cfg(feature = "yandex_cloud")]
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

use base64::Engine as _;
use secrecy::SecretString;
use serde_json::{Value, json};
use zonewright::providers::yandex_cloud::{
    AuthorizedKey, YandexCloud, YandexCloudConfig, YandexCloudCredentials,
};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RemoveOutcome, RrSet, Ttl, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::echo::{DEFAULT_ISSUED_TOKEN, Echo, EchoServer, Echoed, Render};
use zonewright_mock::yandex_cloud::{
    Seed, SeedZone, StrictFailure, YandexCloudMock, ec_private_key_pem, other_test_key, test_key,
};

use common::echo::{CANARY_KEY, CANARY_USER, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The zone most tests write to (`ZONE`) and the owner name (`NAME`).
const ZONE: &str = "example.org";
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const ZONES: &str = "/dns/v1/zones";
const ZONE_GET: &str = "/dns/v1/zones/*";
const GET_SET: &str = "/dns/v1/zones/*:getRecordSet";
const UPDATE: &str = "/dns/v1/zones/*:updateRecordSets";
const TOKENS: &str = "/iam/v1/tokens";
const OPERATIONS: &str = "/operations/*";

fn zone() -> DomainName {
    dn(ZONE)
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings for `mock`, folder lookup, the shortest polling interval.
fn settings(mock: &YandexCloudMock) -> YandexCloudConfig {
    let mut config = YandexCloudConfig::new("b1gtestfolder000001".into());
    config.dns_url = mock.dns_url();
    config.iam_url = mock.iam_url();
    config.operation_url = mock.operation_url();
    config.operation_poll_ms = 250;
    config
}

/// Credentials from the authorized key file `key`.
fn credentials_from(key: Value) -> YandexCloudCredentials {
    serde_json::from_value(json!({ "authorized_key": key })).unwrap()
}

/// The standard seed's credentials with `private_pem`.
fn credentials(private_pem: &str) -> YandexCloudCredentials {
    credentials_from(Seed::standard().authorized_key(private_pem))
}

fn client_with(mock: &YandexCloudMock, ctx: &Context) -> YandexCloud {
    YandexCloud::new(settings(mock), credentials(&test_key().private_pem), ctx).unwrap()
}

async fn setup() -> (YandexCloudMock, YandexCloud) {
    setup_with(Seed::standard()).await
}

async fn setup_with(seed: Seed) -> (YandexCloudMock, YandexCloud) {
    let mock = YandexCloudMock::start(seed).await;
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

/// Number of write requests the mock received.
fn writes(mock: &YandexCloudMock) -> usize {
    mock.log().count(Some("POST"), UPDATE)
}

/// Number of `DnsZone.get` requests (not the custom methods below the zone).
fn zone_gets(mock: &YandexCloudMock) -> usize {
    mock.log()
        .matching(Some("GET"), ZONE_GET)
        .iter()
        .filter(|r| !r.path.contains(':'))
        .count()
}

/// The body of the last `updateRecordSets`.
fn last_update(mock: &YandexCloudMock) -> Value {
    mock.log()
        .matching(Some("POST"), UPDATE)
        .pop()
        .unwrap()
        .body_json()
        .unwrap()
}

fn data(mock: &YandexCloudMock) -> Vec<String> {
    mock.control().txt(ZONE, NAME)
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

assert_not_impl!(YandexCloud: std::fmt::Display, serde::Serialize);
assert_not_impl!(YandexCloudCredentials: std::fmt::Display, serde::Serialize);
assert_not_impl!(AuthorizedKey: std::fmt::Display, serde::Serialize);

/// The authorized key of the echo tests: canary identifiers and a generated private key.
fn canary_key() -> Value {
    json!({
        "id": CANARY_KEY,
        "service_account_id": CANARY_USER,
        "private_key": test_key().private_pem,
    })
}

fn echo_client(echo: &EchoServer, iam_url: &str) -> YandexCloud {
    let mut config = YandexCloudConfig::new("b1gtestfolder000001".into());
    config.dns_url = echo.url("/dns/v1");
    config.iam_url = iam_url.to_owned();
    config.operation_url = echo.url("/operations");
    config.operation_poll_ms = 250;
    YandexCloud::new(config, credentials_from(canary_key()), &context()).unwrap()
}

/// `check` and a write against an echo that quotes every request back, for every dialect: no
/// canary, no issued token and no JWT in any error, `ZoneCheck::detail` or `Debug`, and the
/// write's error shows the redaction. Passes per dialect: the API echoes (the issued token in
/// `Authorization`); the IAM service echoes (the signed JWT); and the reads answer like the API
/// so that the write (a create or a strict replacement) and the poll of its operation reach the
/// echo.
#[tokio::test]
async fn yandex_cloud_secret_echo() {
    let secrets = [CANARY_KEY, CANARY_USER, DEFAULT_ISSUED_TOKEN];
    for dialect in dialects() {
        for status in [400, 401] {
            let label = format!("{} {:?} {status} api", dialect.name, dialect.spelling);
            let echo = dialect.echo(status).start().await;
            let client = echo_client(&echo, &echo.token_url());
            echo_round(&label, &client, &secrets).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
            assert!(echo.token_requests() > 0, "{label}: no token was issued");

            let label = format!("{} {:?} {status} iam", dialect.name, dialect.spelling);
            let echo = dialect
                .echo(status)
                .token_path("/no-token-endpoint")
                .start()
                .await;
            let client = echo_client(&echo, &echo.url(TOKENS));
            echo_round(&label, &client, &secrets).await;
            let token_requests = echo.log().matching(Some("POST"), TOKENS);
            assert!(
                !token_requests.is_empty(),
                "{label}: the IAM service was not reached"
            );
            assert!(token_requests[0].body_str().contains("eyJ"), "{label}");
        }
        for status in [400, 403, 404, 409, 500] {
            for existing in [false, true] {
                // A poll answered 5xx is retried with back-off; the 4xx polls cover the path.
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
                    let echo = dialect
                        .echo(status)
                        .render_under(
                            "/dns/v1/zones",
                            reads_then(dialect.render.clone(), existing, poll),
                        )
                        .start()
                        .await;
                    let client = echo_client(&echo, &echo.token_url());
                    echo_round(&label, &client, &secrets).await;
                    assert_eq!(
                        echo.log().count(Some("POST"), UPDATE),
                        1,
                        "{label}: the write did not reach the echo"
                    );
                    if poll {
                        assert!(
                            echo.log().count(Some("GET"), OPERATIONS) > 0,
                            "{label}: the operation was not polled"
                        );
                    }
                }
            }
        }
    }

    // The key ID and the service account ID travel only inside the signed JWT (the `kid` of its
    // header, the `iss` of its claims), base64url-encoded. An IAM service that quotes the
    // decoded JWT back in its error message puts them in plain text: they are redacted too.
    for status in [400, 401] {
        let label = format!("{status} iam decoded jwt");
        let echo = Echo::new(status)
            .token_path("/no-token-endpoint")
            .render_under(TOKENS, decoded_jwt(status))
            .start()
            .await;
        let client = echo_client(&echo, &echo.url(TOKENS));
        let mut texts = Vec::new();
        match client.check(&[zone()]).await {
            Ok(report) => panic!("{label}: check passed without a token: {report:?}"),
            Err(e) => texts.push(format!("{e} | {e:?}")),
        }
        match client
            .add_txt_value(&zone(), &name(), &txt("v1"), None)
            .await
        {
            Ok(outcome) => panic!("{label}: the echo accepted a write: {outcome:?}"),
            Err(e) => texts.push(format!("{e} | {e:?}")),
        }
        assert!(
            echo.log().count(Some("POST"), TOKENS) >= 2,
            "{label}: the IAM service was not reached"
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

/// A renderer for the IAM token path that decodes the JWT of the request and answers `status`
/// with its header and claims, in plain text, as the error message.
fn decoded_jwt(status: u16) -> Render {
    Arc::new(move |e: &Echoed| {
        let body: Value = serde_json::from_str(&e.body).unwrap();
        let jwt = body["jwt"].as_str().unwrap();
        let parts: Vec<Value> = jwt
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
                "code": 3,
                "message": format!("cannot accept the JWT of key {kid} for account {iss}"),
            })),
        )
            .into_response()
    })
}

/// A renderer that answers the reads like the API (one public zone; no record set, or a TXT set
/// with a foreign value) and every other request with `errors`; with `poll`, the write is
/// accepted with an unfinished operation, whose poll then meets the echo.
fn reads_then(errors: Render, existing: bool, poll: bool) -> Render {
    Arc::new(move |e: &Echoed| {
        let ok = |body: Value| (StatusCode::OK, axum::Json(body)).into_response();
        if e.method == Method::POST {
            return if poll {
                ok(json!({"id": "dnsop000000000001", "done": false}))
            } else {
                errors(e)
            };
        }
        if e.path.ends_with("/zones") {
            return ok(json!({"dnsZones": [{
                "id": "dnszone000000000001",
                "zone": "example.org.",
                "publicVisibility": {}
            }]}));
        }
        if e.path.ends_with(":getRecordSet") {
            return if existing {
                ok(json!({
                    "name": "_acme-challenge.example.org.",
                    "type": "TXT",
                    "ttl": "60",
                    "data": ["foreign"]
                }))
            } else {
                (
                    StatusCode::NOT_FOUND,
                    axum::Json(json!({"code": 5, "message": "RecordSet not found"})),
                )
                    .into_response()
            };
        }
        ok(json!({"id": "dnszone000000000001", "zone": "example.org.", "publicVisibility": {}}))
    })
}

async fn echo_round(label: &str, client: &YandexCloud, secrets: &[&str]) {
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
    let write = match client
        .add_txt_value(&zone(), &name(), &txt("v1"), None)
        .await
    {
        Ok(outcome) => panic!("{label}: the echo accepted a write: {outcome:?}"),
        Err(e) => format!("{e} | {e:?}"),
    };
    assert!(
        write.contains(REDACTED),
        "{label}: the echo did not reach the error: {write}"
    );
    texts.push(write);
    for text in &texts {
        assert_clean(label, text, secrets);
    }
}

/// A `TRACE` capture over a success, a renewed token, repeated 401s, a 500 and a key the IAM
/// service refuses: the transport's events are there, and no canary, issued token or JWT is.
#[tokio::test(flavor = "current_thread")]
async fn yandex_cloud_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.key_id = CANARY_KEY.into();
    seed.service_account_id = CANARY_USER.into();
    let mock = YandexCloudMock::start(seed).await;
    let client =
        YandexCloud::new(settings(&mock), credentials_from(canary_key()), &context()).unwrap();
    let mut texts = Vec::new();

    add(&client, "v1").await.unwrap();
    mock.control().revoke_tokens();
    add(&client, "v2").await.unwrap();

    mock.faults()
        .push(Fault::on("GET", GET_SET).always().status(401));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("POST", UPDATE).status(500));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    let mut key = canary_key();
    key["private_key"] = json!(other_test_key().private_pem);
    let wrong = YandexCloud::new(settings(&mock), credentials_from(key), &context()).unwrap();
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
        assert_clean("yandex_cloud logs and errors", text, &secrets);
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request, token requests included.
#[tokio::test]
async fn yandex_cloud_name_outside_zone_sends_nothing() {
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
    assert_eq!(mock.control().tokens_issued(), 0);
}

/// `Created`, `Appended` for a second value, then `AlreadyPresent` without a write.
#[tokio::test]
async fn yandex_cloud_add_is_idempotent() {
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
    assert_eq!(data(&mock), ["AAA", "BBB"]);
    // The public zone was used, not the private one of the same name listed before it.
    let rrsets = mock.control().rrsets();
    assert_eq!(rrsets.len(), 1);
    assert_eq!(rrsets[0].zone_id, mock.control().zone_id(ZONE));
    assert_eq!(mock.control().tokens_issued(), 1, "the token is cached");
}

/// Removing an absent value next to a foreign one writes nothing; adding and removing our value
/// leaves the foreign value, the TTL and the description as they were. The strict write repeats
/// the set exactly as it was read. A single foreign value is never a reason to delete the set.
#[tokio::test]
async fn yandex_cloud_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZONE, NAME, "TXT", "600", &["foreign"]);
    control.set_description(ZONE, NAME, "TXT", Some("set by hand"));
    let original = control.rrset(ZONE, NAME, "TXT").unwrap();

    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    let during = control.rrset(ZONE, NAME, "TXT").unwrap();
    assert_eq!(during.ttl, "600");
    assert_eq!(during.description.as_deref(), Some("set by hand"));
    assert_eq!(during.data, ["foreign", "ours"]);
    let body = last_update(&mock);
    let read = json!({
        "name": "_acme-challenge.example.org.",
        "type": "TXT",
        "ttl": "600",
        "data": ["foreign"],
        "description": "set by hand"
    });
    assert_eq!(body["deletions"], json!([read]));
    assert_eq!(
        body["additions"],
        json!([{
            "name": "_acme-challenge.example.org.",
            "type": "TXT",
            "ttl": "600",
            "data": ["foreign", "ours"],
            "description": "set by hand"
        }])
    );
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.rrset(ZONE, NAME, "TXT").unwrap(), original);

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_rrset(ZONE, other, "TXT", "60", &["foreign"]);
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &txt("ours"))
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(control.txt(ZONE, other), ["foreign"]);
}

/// The last value is removed with a deletion of the set and no addition.
#[tokio::test]
async fn yandex_cloud_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().rrsets().is_empty());
    let body = last_update(&mock);
    assert_eq!(body["deletions"].as_array().unwrap().len(), 1);
    assert_eq!(body["additions"], json!([]));
}

#[tokio::test]
async fn yandex_cloud_remove_is_idempotent() {
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

/// Two clients sharing a `Context` add to one name at once, the first write delayed: both values
/// end up in the set, and neither write was refused.
#[tokio::test]
async fn yandex_cloud_concurrent_adds_are_serialized() {
    let mock = YandexCloudMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, &ctx);
    let b = client_with(&mock, &ctx);
    mock.faults()
        .push(Fault::on("POST", UPDATE).delay(Duration::from_millis(300)));
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
    assert_eq!(values, ["AAA", "BBB"]);
    assert_eq!(writes(&mock), 2);
}

/// A foreign change between the read and the write is not lost, however the provider reports
/// the failed condition: the strict write is refused, the client reads again and repeats the
/// operation once; a second refusal is a retryable `Conflict` with nothing written.
#[tokio::test]
async fn yandex_cloud_concurrent_change_is_conflict() {
    for mode in [StrictFailure::Http, StrictFailure::Operation] {
        let (mock, client) = setup().await;
        mock.control().set_strict_failure(mode);
        add(&client, "AAA").await.unwrap();

        // One foreign change: the repeat succeeds and keeps it.
        let hook = mock.control().clone();
        mock.faults().push(Fault::on("POST", UPDATE).run(move || {
            hook.append_txt(ZONE, NAME, "foreign1");
        }));
        assert_eq!(
            add(&client, "BBB").await.unwrap(),
            AddOutcome::Appended,
            "{mode:?}"
        );
        assert_eq!(data(&mock), ["AAA", "foreign1", "BBB"], "{mode:?}");

        // A foreign change before each of the two writes: `Conflict`, nothing of ours written.
        let hook = mock.control().clone();
        let n = Arc::new(std::sync::atomic::AtomicU32::new(0));
        mock.faults()
            .push(Fault::on("POST", UPDATE).times(2).run(move || {
                let i = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                hook.append_txt(ZONE, NAME, &format!("foreign-r{i}"));
            }));
        let before = writes(&mock);
        let e = add(&client, "CCC").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Conflict, "{mode:?} {e:?}");
        assert!(e.is_retryable());
        assert_eq!(writes(&mock), before + 2, "{mode:?}");
        assert_eq!(
            data(&mock),
            ["AAA", "foreign1", "BBB", "foreign-r0", "foreign-r1"],
            "{mode:?}"
        );

        // A removal meets a foreign change: the foreign value survives, ours goes.
        let hook = mock.control().clone();
        mock.faults().push(Fault::on("POST", UPDATE).run(move || {
            hook.append_txt(ZONE, NAME, "foreign2");
        }));
        assert_eq!(
            remove(&client, "AAA").await.unwrap(),
            RemoveOutcome::Removed,
            "{mode:?}"
        );
        assert_eq!(
            data(&mock),
            ["foreign1", "BBB", "foreign-r0", "foreign-r1", "foreign2"],
            "{mode:?}"
        );

        // A set created by someone else between the read and our create.
        let other = "_acme-challenge.www.example.org";
        let hook = mock.control().clone();
        mock.faults().push(Fault::on("POST", UPDATE).run(move || {
            hook.append_txt(ZONE, other, "foreign3");
        }));
        assert_eq!(
            client
                .add_txt_value(&zone(), &dn(other), &txt("DDD"), None)
                .await
                .unwrap(),
            AddOutcome::Appended,
            "{mode:?}"
        );
        assert_eq!(mock.control().txt(ZONE, other), ["foreign3", "DDD"]);

        // The last value is about to be deleted when someone adds another: it survives.
        let lone = "_acme-challenge.lone.example.org";
        client
            .add_txt_value(&zone(), &dn(lone), &txt("EEE"), None)
            .await
            .unwrap();
        let hook = mock.control().clone();
        mock.faults().push(Fault::on("POST", UPDATE).run(move || {
            hook.append_txt(ZONE, lone, "foreign4");
        }));
        assert_eq!(
            client
                .remove_txt_value(&zone(), &dn(lone), &txt("EEE"))
                .await
                .unwrap(),
            RemoveOutcome::Removed,
            "{mode:?}"
        );
        assert_eq!(mock.control().txt(ZONE, lone), ["foreign4"]);
    }
}

/// The zone is deleted and created again under a new identifier while the client has the old
/// one cached. A read whose `404` cannot tell a missing zone from a missing set confirms the
/// zone, finds it gone, looks it up again and repeats the read: a removal never reports
/// `NotPresent` for a value that is there. A write that meets the stale identifier is refused,
/// the new read finds the zone under its new identifier, and the operation runs once more.
#[tokio::test]
async fn yandex_cloud_stale_zone_id() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for value in ["v1", "v2"] {
        add(&client, value).await.unwrap();
    }
    let lookups = || mock.log().count(Some("GET"), ZONES);
    assert_eq!(lookups(), 1);

    control.recreate_zone(ZONE);
    assert_eq!(remove(&client, "v1").await.unwrap(), RemoveOutcome::Removed);
    assert_eq!(lookups(), 2);
    control.recreate_zone(ZONE);
    assert_eq!(add(&client, "v3").await.unwrap(), AddOutcome::Appended);
    assert_eq!(data(&mock), ["v2", "v3"]);

    // A missing set under a cached identifier: the zone is confirmed, not looked up again.
    let other = dn("_acme-challenge.www.example.org");
    let before = (lookups(), zone_gets(&mock));
    assert_eq!(
        client
            .add_txt_value(&zone(), &other, &txt("w1"), None)
            .await
            .unwrap(),
        AddOutcome::Created
    );
    assert_eq!((lookups(), zone_gets(&mock)), (before.0, before.1 + 1));

    // The zone is recreated between the read and the write.
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", UPDATE).run(move || {
        hook.recreate_zone(ZONE);
    }));
    assert_eq!(add(&client, "v4").await.unwrap(), AddOutcome::Appended);
    assert_eq!(data(&mock), ["v2", "v3", "v4"]);
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", UPDATE).run(move || {
        hook.recreate_zone(ZONE);
    }));
    assert_eq!(remove(&client, "v4").await.unwrap(), RemoveOutcome::Removed);
    assert_eq!(data(&mock), ["v2", "v3"]);
}

/// The record-level operations are not offered: `Unsupported`, and nothing is sent.
#[tokio::test]
async fn yandex_cloud_unsupported_operations_send_nothing() {
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

/// Every write is sent exactly once, whatever happens: a 502, a 429 and a 401 on the strict
/// call each end the operation, which a repeat starts again with a read.
#[tokio::test]
async fn yandex_cloud_writes_are_sent_once() {
    let (mock, client) = setup().await;
    // A create, an update and a delete, each answered 502, 429 and 401.
    let cases: [(&str, u16); 3] = [("502", 502), ("429", 429), ("401", 401)];
    for (label, status) in cases {
        for step in ["create", "update", "delete"] {
            if step != "create" {
                add(&client, "AAA").await.unwrap();
            }
            let fault = Fault::on("POST", UPDATE);
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
                429 => ErrorKind::RateLimited,
                _ => ErrorKind::Transient,
            };
            assert_eq!(e.kind(), expected, "{label} {step}: {e:?}");
            assert_eq!(writes(&mock), before + 1, "{label} {step}");
            assert_eq!(data(&mock), state, "{label} {step}");
            // The repeat converges.
            match step {
                "create" => assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created),
                "update" => {
                    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
                    remove(&client, "BBB").await.unwrap();
                }
                _ => {}
            }
            remove(&client, "AAA").await.unwrap();
            assert!(mock.control().rrsets().is_empty(), "{label} {step}");
        }
    }
}

// ---- Record sets and operations ----------------------------------------------------------------

/// The first value creates the set: the name relative to the zone, the configured TTL as a
/// string, the value unquoted; no deletion.
#[tokio::test]
async fn yandex_cloud_add_creates_rrset() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    let body = last_update(&mock);
    assert_eq!(body["deletions"], json!([]));
    assert_eq!(
        body["additions"],
        json!([{"name": "_acme-challenge", "type": "TXT", "ttl": "60", "data": ["AAA"]}])
    );
    let read = mock.log().matching(Some("GET"), GET_SET).pop().unwrap();
    assert_eq!(read.query.as_deref(), Some("name=_acme-challenge&type=TXT"));
    let set = mock.control().rrset(ZONE, NAME, "TXT").unwrap();
    assert_eq!(set.ttl, "60");

    // A TTL given by the caller is used for a new set only.
    let other = dn("_acme-challenge.www.example.org");
    let ttl = Ttl::from_secs(300).unwrap();
    client
        .add_txt_value(&zone(), &other, &txt("BBB"), Some(ttl))
        .await
        .unwrap();
    client
        .add_txt_value(
            &zone(),
            &other,
            &txt("CCC"),
            Some(Ttl::from_secs(900).unwrap()),
        )
        .await
        .unwrap();
    let set = mock
        .control()
        .rrset(ZONE, "_acme-challenge.www.example.org", "TXT")
        .unwrap();
    assert_eq!(set.ttl, "300");

    // A value that is not plain is refused before any request.
    let requests = mock.log().len();
    let e = add(&client, "two words").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(mock.log().len(), requests);

    // The zone apex is addressed as `@`.
    client
        .add_txt_value(&zone(), &zone(), &txt("apex"), None)
        .await
        .unwrap();
    assert_eq!(last_update(&mock)["additions"][0]["name"], "@");
    assert_eq!(mock.control().txt(ZONE, ZONE), ["apex"]);
}

/// The operation is polled until it is done; an operation that finishes with an error is
/// `Rejected` with the provider's message and nothing changed; a poll that keeps failing is
/// `Transient`.
#[tokio::test]
async fn yandex_cloud_operations_are_polled() {
    let (mock, client) = setup().await;
    mock.control().set_operation_polls(3);
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), OPERATIONS), 3);
    mock.control().set_operation_polls(0);
    add(&client, "BBB").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), OPERATIONS), 3, "done at once");

    mock.control().set_operation_polls(1);
    mock.control().fail_next_operation("quota exceeded");
    let e = add(&client, "CCC").await.unwrap_err();
    match &e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(*status, None);
            assert_eq!(detail.as_str(), "quota exceeded");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(data(&mock), ["AAA", "BBB"]);

    mock.faults()
        .push(Fault::on("GET", OPERATIONS).times(3).status(500));
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    // The write was accepted; its outcome is unknown to the client. A repeat converges.
    assert_eq!(
        add(&client, "CCC").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
}

/// An operation still running after the last of the 60 polls is `Transient`.
#[tokio::test]
async fn yandex_cloud_unfinished_operation_is_transient() {
    let (mock, client) = setup().await;
    mock.control().set_operation_polls(1000);
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), OPERATIONS), 60);
}

/// The TXT dialect: quoted character-strings are joined, unquoted text is read as it is, and
/// data the dialect cannot decode is a foreign value written back unchanged.
#[tokio::test]
async fn yandex_cloud_txt_dialect() {
    let (mock, client) = setup().await;
    let undecodable = "\"a\" b \"";
    mock.control().insert_rrset(
        ZONE,
        NAME,
        "TXT",
        "60",
        &["\"part1\" \"part2\"", undecodable],
    );
    assert_eq!(
        add(&client, "part1part2").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        remove(&client, "part1part2").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(data(&mock), [undecodable]);
    assert_eq!(add(&client, "plain").await.unwrap(), AddOutcome::Appended);
    assert_eq!(data(&mock), [undecodable, "plain"]);
}

/// The TTL a caller requests may be anything the API accepts, 0 to 2147483647, not only the
/// range of the `ttl` setting.
#[tokio::test]
async fn yandex_cloud_caller_ttl_covers_the_api_range() {
    let (mock, client) = setup().await;
    for (i, secs) in [0u32, 30, 604_801, 2_147_483_647].into_iter().enumerate() {
        let name = dn(&format!("_acme-challenge.t{i}.example.org"));
        let outcome = client
            .add_txt_value(
                &zone(),
                &name,
                &txt("AAA"),
                Some(Ttl::from_secs(secs).unwrap()),
            )
            .await
            .unwrap();
        assert_eq!(outcome, AddOutcome::Created, "{secs}");
        let set = mock
            .control()
            .rrset(ZONE, &format!("_acme-challenge.t{i}.example.org"), "TXT")
            .unwrap();
        assert_eq!(set.ttl, secs.to_string());
    }
    let caps = &ProviderId::YandexCloud.meta().capabilities;
    assert!(caps.ttl.accepts(0) && caps.ttl.accepts(2_147_483_647));
}

/// A foreign value that the client can decode but stores in another form (two quoted
/// character-strings) is written back exactly as read, never re-encoded, when a value is added
/// next to it or removed from beside it.
#[tokio::test]
async fn yandex_cloud_kept_values_are_written_as_read() {
    let (mock, client) = setup().await;
    let foreign = "\"for\" \"eign\"";
    mock.control()
        .insert_rrset(ZONE, NAME, "TXT", "60", &[foreign]);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    assert_eq!(data(&mock), [foreign, "ours"]);
    assert_eq!(
        last_update(&mock)["additions"][0]["data"],
        json!([foreign, "ours"])
    );
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(data(&mock), [foreign]);
    assert_eq!(last_update(&mock)["additions"][0]["data"], json!([foreign]));
}

/// After `updateRecordSets` was accepted (200), an answer whose operation cannot be read leaves
/// the outcome unknown: `Transient`, not `Protocol` (design section 3.7), and not repeated.
#[tokio::test]
async fn yandex_cloud_unreadable_operation_after_accepted_write_is_transient() {
    let (mock, client) = setup().await;
    for (label, body) in [
        ("not json", "not json".to_owned()),
        ("no operation", r#"{"unexpected":true}"#.to_owned()),
        (
            "unsafe id",
            json!({"id": "../op", "done": false}).to_string(),
        ),
    ] {
        let before = writes(&mock);
        mock.faults()
            .push(Fault::on("POST", UPDATE).respond(200, body));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient, "{label}: {e:?}");
        assert_eq!(writes(&mock), before + 1, "{label}: sent once");
    }
}

/// A record set holds at most 100 values: the 101st is refused before the write.
#[tokio::test]
async fn yandex_cloud_rrset_value_limit() {
    let (mock, client) = setup().await;
    let values: Vec<String> = (0..100).map(|i| format!("v{i}")).collect();
    let values: Vec<&str> = values.iter().map(String::as_str).collect();
    mock.control()
        .insert_rrset(ZONE, NAME, "TXT", "60", &values);
    let e = add(&client, "one-too-many").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(remove(&client, "v7").await.unwrap(), RemoveOutcome::Removed);
}

/// Record sets of another type at the same name are never touched.
#[tokio::test]
async fn yandex_cloud_other_types_at_the_name_are_untouched() {
    let (mock, client) = setup().await;
    mock.control()
        .insert_rrset(ZONE, NAME, "A", "300", &["192.0.2.1"]);
    let before = mock.control().rrset(ZONE, NAME, "A").unwrap();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(mock.control().rrset(ZONE, NAME, "A").unwrap(), before);
    assert!(mock.control().rrset(ZONE, NAME, "TXT").is_none());
}

/// A refusal of the strict write with the set unchanged is that refusal: `Rejected` with the
/// status and the provider's message. An answer outside the error mapping is `Protocol`.
#[tokio::test]
async fn yandex_cloud_refusals_are_rejected() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", UPDATE).respond(
        400,
        r#"{"code":3,"message":"data element is too long","details":[]}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(400));
            assert_eq!(detail.as_str(), "data element is too long");
        }
        other => panic!("{other:?}"),
    }
    assert!(mock.control().rrsets().is_empty());
    mock.faults()
        .push(Fault::on("GET", GET_SET).respond(418, r#"{"code":2,"message":"teapot"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert!(e.to_string().contains("status 418: teapot"), "{e}");
    // A record set answer of an unexpected shape is never written back.
    mock.control().insert_rrset(ZONE, NAME, "TXT", "60", &["x"]);
    mock.faults().push(Fault::on("GET", GET_SET).respond(
        200,
        r#"{"name":"_acme-challenge.example.org.","type":"TXT","ttl":"60"}"#,
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 1);
}

// ---- Zones -------------------------------------------------------------------------------------

/// The zone is found on a later page of the folder listing.
#[tokio::test]
async fn yandex_cloud_zone_lookup_reads_every_page() {
    let (mock, client) = setup().await;
    mock.control().set_page_size(1);
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);
    let first = mock.log().matching(Some("GET"), ZONES)[0].clone();
    let query = first.query.unwrap();
    assert!(query.contains("folderId=b1gtestfolder000001"), "{query}");
    assert!(query.contains("pageSize=1000"), "{query}");
    let second = mock.log().matching(Some("GET"), ZONES)[1].clone();
    assert!(second.query.unwrap().contains("pageToken=1"));
}

/// A listing that cannot be read whole is an error, never a shorter result: a page that does
/// not parse, and a page token that does not advance.
#[tokio::test]
async fn yandex_cloud_truncated_listing_is_protocol() {
    let (mock, client) = setup().await;
    mock.control().set_page_size(1);
    mock.faults().push(
        Fault::on("GET", ZONES)
            .skip(1)
            .respond(200, r#"{"dnsZones":[{"id":"#),
    );
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().push(
        Fault::on("GET", ZONES)
            .always()
            .respond(200, r#"{"dnsZones":[],"nextPageToken":"same"}"#),
    );
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().clear();
    // An empty folder is an empty answer in proto3 JSON, not a truncated one.
    mock.faults()
        .push(Fault::on("GET", ZONES).respond(200, "{}"));
    assert!(client.list_zones().await.unwrap().is_empty());
}

/// `list_zones` returns the public zones of the folder, all pages, once each, sorted; the
/// identifiers are cached.
#[tokio::test]
async fn yandex_cloud_list_zones_public_all_pages() {
    let mut seed = Seed::standard();
    seed.zones.push(SeedZone {
        zone: "private.example.".into(),
        public: false,
    });
    seed.zones.push(SeedZone {
        zone: "example.net.".into(),
        public: true,
    });
    let (mock, client) = setup_with(seed).await;
    mock.control().set_page_size(1);
    let zones: Vec<DomainName> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name)
        .collect();
    assert_eq!(zones, [dn("example.net"), zone()]);
    assert_eq!(mock.log().count(Some("GET"), ZONES), 4);
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        mock.log().count(Some("GET"), ZONES),
        4,
        "the zone was cached"
    );
}

#[tokio::test]
async fn yandex_cloud_zone_not_found() {
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

/// Only a public zone is used (design section 11.3): a zone held as a private zone only is not
/// found, with a detail; two public zones of one name are `Config`, and `check` says why.
#[tokio::test]
async fn yandex_cloud_zone_selection() {
    let mut seed = Seed::standard();
    seed.zones = vec![SeedZone {
        zone: "example.org.".into(),
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

    mock.control().insert_zone(ZONE, true);
    mock.control().insert_zone(ZONE, true);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    assert!(
        report.zones[0]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("zone_ids"),
        "{report:?}"
    );
    let e = add(&client, "A").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// Zones with a configured ID (design section 11.3) are used by that ID after it was verified
/// against the zone's name, without a folder; a configured ID of another zone is `Config`.
#[tokio::test]
async fn yandex_cloud_configured_zone_ids() {
    let mock = YandexCloudMock::start(Seed::standard()).await;
    let id = mock.control().zone_id(ZONE);
    let mut config = settings(&mock);
    config.folder_id = None;
    config.zone_ids = Some([(ZONE.to_owned(), id.clone())].into_iter().collect());
    let client = YandexCloud::new(
        config.clone(),
        credentials(&test_key().private_pem),
        &context(),
    )
    .unwrap();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.log().count(Some("GET"), ZONES), 0);
    assert_eq!(zone_gets(&mock), 1);
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
    // Another zone without an ID and without a folder is not found.
    let report = client.check(&[zone(), dn("example.net")]).await.unwrap();
    assert!(report.zones[0].found);
    assert!(!report.zones[1].found);

    // From stored configuration, `zone_ids` as an object or as its JSON text.
    for zone_ids in [json!({ ZONE: id }), json!(json!({ ZONE: id }).to_string())] {
        let settings = json!({
            "zone_ids": zone_ids,
            "dns_url": mock.dns_url(),
            "iam_url": mock.iam_url(),
            "operation_url": mock.operation_url(),
        });
        let creds =
            json!({"authorized_key": Seed::standard().authorized_key(&test_key().private_pem)});
        let any = AnyProvider::from_json(
            ProviderId::YandexCloud,
            &settings.to_string(),
            &SecretString::from(creds.to_string()),
            &context(),
        )
        .unwrap();
        assert!(any.check(&[zone()]).await.unwrap().zones[0].found);
    }

    // The ID of another zone.
    let other = mock.control().insert_zone("example.net", true);
    config.zone_ids = Some([(ZONE.to_owned(), other)].into_iter().collect());
    let client =
        YandexCloud::new(config, credentials(&test_key().private_pem), &context()).unwrap();
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
}

#[tokio::test]
async fn yandex_cloud_check_reports_zones() {
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
    assert_eq!(mock.log().count(Some("GET"), ZONES), 3);
}

// ---- Authentication ----------------------------------------------------------------------------

fn decode_part(part: &str) -> Value {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The JWT: `typ`, `alg` PS256 and `kid` in the header; `iss`, `aud` (the token URL), `iat` and
/// `exp` one hour later in the claims; the mock verified its signature. The API gets the IAM
/// token as a bearer token.
#[tokio::test]
async fn yandex_cloud_jwt_and_token_request_shape() {
    let (mock, client) = setup().await;
    client.check(&[zone()]).await.unwrap();
    let request = mock.log().matching(Some("POST"), TOKENS).pop().unwrap();
    let body = request.body_json().unwrap();
    assert_eq!(body.as_object().unwrap().len(), 1);
    let jwt = body["jwt"].as_str().unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(
        decode_part(parts[0]),
        json!({"typ": "JWT", "alg": "PS256", "kid": "ajetestkey0000000001"})
    );
    let claims = decode_part(parts[1]);
    assert_eq!(claims["iss"], "ajetestsa00000000001");
    assert_eq!(claims["aud"], mock.iam_url());
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
}

#[tokio::test]
async fn yandex_cloud_token_is_cached() {
    let (mock, client) = setup().await;
    for i in 0..5 {
        add(&client, &format!("V{i}")).await.unwrap();
    }
    assert_eq!(mock.control().tokens_issued(), 1);
}

/// A token whose stated expiry is already reached is renewed before the next request.
#[tokio::test]
async fn yandex_cloud_token_is_renewed_before_expiry() {
    let (mock, client) = setup().await;
    mock.control().set_token_ttl(0);
    add(&client, "A1").await.unwrap();
    add(&client, "A2").await.unwrap();
    let api_requests = mock.log().count(None, "/dns/**") + mock.log().count(None, "/operations/**");
    assert!(api_requests >= 4);
    assert_eq!(mock.control().tokens_issued(), api_requests);
}

/// A revoked token is answered 401; the client signs a new JWT, obtains a new token and repeats
/// the read.
#[tokio::test]
async fn yandex_cloud_rejected_token_is_renewed() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    mock.control().revoke_tokens();
    add(&client, "BBB").await.unwrap();
    assert_eq!(mock.control().tokens_issued(), 2);
    let jwts: Vec<String> = mock
        .log()
        .matching(Some("POST"), TOKENS)
        .iter()
        .map(|r| r.body_json().unwrap()["jwt"].as_str().unwrap().to_owned())
        .collect();
    assert_ne!(jwts[0], jwts[1], "every exchange signs anew");
}

/// A 401 for a freshly obtained token is `Auth`, and nothing is written.
#[tokio::test]
async fn yandex_cloud_repeated_401_is_auth() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", GET_SET).times(5).status(401));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// A key the IAM service does not accept (another key pair, another key ID, another service
/// account) is `Auth`, and the DNS API is never contacted. A 400 of the IAM service is `Auth`.
#[tokio::test]
async fn yandex_cloud_wrong_key_is_auth() {
    let mock = YandexCloudMock::start(Seed::standard()).await;
    let seed = Seed::standard();
    let wrong = [
        seed.authorized_key(&other_test_key().private_pem),
        {
            let mut k = seed.authorized_key(&test_key().private_pem);
            k["id"] = json!("ajeotherkey000000001");
            k
        },
        {
            let mut k = seed.authorized_key(&test_key().private_pem);
            k["service_account_id"] = json!("ajeothersa0000000001");
            k
        },
    ];
    for key in wrong {
        let client = YandexCloud::new(settings(&mock), credentials_from(key), &context()).unwrap();
        let e = client.check(&[zone()]).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    }
    assert_eq!(mock.log().count(None, "/dns/**"), 0);
    let client = client_with(&mock, &context());
    mock.faults()
        .push(Fault::on("POST", TOKENS).respond(400, r#"{"code":3,"message":"invalid JWT"}"#));
    let e = client.check(&[]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
}

// ---- Transport ---------------------------------------------------------------------------------

/// A short `Retry-After` on a read is waited out; a long one is `RateLimited` with the wait.
#[tokio::test]
async fn yandex_cloud_rate_limit() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", GET_SET).rate_limited("1"));
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), GET_SET), 2);
    mock.faults()
        .push(Fault::on("GET", GET_SET).rate_limited("120"));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
}

/// A 5xx on a read is retried; three in a row are `Transient`, which is retryable.
#[tokio::test]
async fn yandex_cloud_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", GET_SET).status(500));
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("GET", GET_SET).times(3).status(503));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("GET"), GET_SET), 5);
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn yandex_cloud_from_json_builds_the_client() {
    let mock = YandexCloudMock::start(Seed::standard()).await;
    let settings = json!({
        "folder_id": "b1gtestfolder000001",
        "dns_url": mock.dns_url(),
        "iam_url": mock.iam_url(),
        "operation_url": mock.operation_url(),
    });
    let key = Seed::standard().authorized_key(&test_key().private_pem);
    // The key file as an object and as its JSON text (a form field); unknown keys are ignored.
    for key in [key.clone(), json!(key.to_string())] {
        let creds = json!({"authorized_key": key, "other": 1});
        let client = AnyProvider::from_json(
            ProviderId::YandexCloud,
            &settings.to_string(),
            &SecretString::from(creds.to_string()),
            &context(),
        )
        .unwrap();
        assert_eq!(client.id(), ProviderId::YandexCloud);
        assert!(client.check(&[zone()]).await.unwrap().zones[0].found);
    }
}

/// Configuration errors are `Config`, name the key and never repeat a value; malformed key
/// material is a fixed text.
#[test]
fn yandex_cloud_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || {
        json!({
            "folder_id": "b1gtestfolder000001",
            "dns_url": "http://127.0.0.1:1/dns/v1",
            "iam_url": "http://127.0.0.1:1/iam/v1/tokens",
            "operation_url": "http://127.0.0.1:1/operations",
        })
    };
    let with = |key: &str, value: Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let key = |field: &str, value: Value| {
        let mut key = Seed::standard().authorized_key(&test_key().private_pem);
        key[field] = value;
        json!({"authorized_key": key}).to_string()
    };
    let good = key("id", json!("ajetestkey0000000001"));
    let truncated: String = test_key().private_pem.chars().take(400).collect();
    let cases = [
        (
            {
                let mut s = base();
                s.as_object_mut().unwrap().remove("folder_id");
                s
            },
            good.clone(),
            "folder_id",
        ),
        (with(canary, json!(canary)), good.clone(), "unknown keys"),
        (
            with("folder_id", json!(format!("{canary}/x"))),
            good.clone(),
            "folder_id",
        ),
        (
            with(
                "zone_ids",
                json!({ format!("{canary} not a name"): "dnszone1" }),
            ),
            good.clone(),
            "zone_ids",
        ),
        (
            with("zone_ids", json!({ "example.org": format!("{canary}/x") })),
            good.clone(),
            "zone_ids",
        ),
        (with("ttl", json!(30)), good.clone(), "ttl"),
        (
            with("operation_poll_ms", json!(10)),
            good.clone(),
            "operation_poll_ms",
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
                "iam_url",
                json!(format!("https://iam.example.org/?{canary}")),
            ),
            good.clone(),
            "iam_url",
        ),
        (
            with(
                "operation_url",
                json!(format!("ftp://{canary}.example.org")),
            ),
            good.clone(),
            "operation_url",
        ),
        (
            base(),
            json!({"authorized_key": canary}).to_string(),
            "authorized_key",
        ),
        (
            base(),
            json!({"secret": canary}).to_string(),
            "authorized_key",
        ),
        (base(), key("id", json!("")), "authorized_key.id"),
        (
            base(),
            key("service_account_id", json!("")),
            "authorized_key.service_account_id",
        ),
        (
            base(),
            key(
                "private_key",
                json!(format!(
                    "{canary}\n-----BEGIN PRIVATE KEY-----\n{canary}\n-----END PRIVATE KEY-----\n"
                )),
            ),
            "authorized_key.private_key",
        ),
        (
            base(),
            key("private_key", json!(ec_private_key_pem())),
            "authorized_key.private_key",
        ),
        (
            base(),
            key("private_key", json!(truncated)),
            "authorized_key.private_key",
        ),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::YandexCloud,
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
    // The line the provider's CLI writes before the PEM section is ignored.
    let pem = &test_key().private_pem;
    assert!(pem.contains("PLEASE DO NOT REMOVE THIS LINE!"));
    AnyProvider::from_json(
        ProviderId::YandexCloud,
        &base().to_string(),
        &SecretString::from(good),
        &ctx,
    )
    .unwrap();
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round; the metadata's defaults are those of the settings type.
#[test]
fn yandex_cloud_config_keys_match_metadata() {
    let meta = ProviderId::YandexCloud.meta();
    let settings = serde_json::to_value(YandexCloudConfig::default()).unwrap();
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
    assert_eq!(secret, ["authorized_key"]);
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
/// removes exactly the values it added afterwards, also when the body failed. A second client
/// on its own context then races the first on a fresh name, so that the strict call's refusal
/// of a stale write is observed.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_yandex_cloud_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_YANDEX_CLOUD_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_YANDEX_CLOUD_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_YANDEX_CLOUD_ZONE"));
    let build = |ctx: &Context| {
        AnyProvider::from_json(
            ProviderId::YandexCloud,
            &settings,
            &SecretString::from(credentials.clone()),
            ctx,
        )
        .unwrap()
    };
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(build(&ctx));
    let tag = random_u64();
    let name = zone.prepend(&format!("_zw-live-{tag:016x}")).unwrap();
    let values = [
        txt(&format!("zw-live-{tag:016x}-a")),
        txt(&format!("zw-live-{tag:016x}-b")),
    ];
    let probe = zone.prepend(&format!("_zw-live-{tag:016x}-probe")).unwrap();
    let probe_values = [
        txt(&format!("zw-live-{tag:016x}-p")),
        txt(&format!("zw-live-{tag:016x}-q")),
    ];

    let body = {
        let (client, zone, name, values) =
            (client.clone(), zone.clone(), name.clone(), values.clone());
        tokio::spawn(async move {
            let report = client.check(std::slice::from_ref(&zone)).await.unwrap();
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
    let mut outcome = body.await;

    if outcome.is_ok() {
        // Two clients on separate contexts add to a fresh name at once: both read "no set", and
        // the strict call refuses the second create. Neither value may be lost.
        let other_ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
        let second = build(&other_ctx);
        let (a, b) = tokio::join!(
            client.add_txt_value(&zone, &probe, &probe_values[0], None),
            second.add_txt_value(&zone, &probe, &probe_values[1], None),
        );
        eprintln!("strict-call probe: {a:?} / {b:?}");
        let probe_body = tokio::spawn({
            let (client, zone, probe, probe_values) = (
                client.clone(),
                zone.clone(),
                probe.clone(),
                probe_values.clone(),
            );
            async move {
                for result in [&a, &b] {
                    if let Err(e) = result {
                        assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
                    }
                }
                for value in &probe_values {
                    client
                        .add_txt_value(&zone, &probe, value, None)
                        .await
                        .unwrap();
                }
                for value in &probe_values {
                    assert_eq!(
                        client
                            .add_txt_value(&zone, &probe, value, None)
                            .await
                            .unwrap(),
                        AddOutcome::AlreadyPresent
                    );
                }
            }
        });
        outcome = probe_body.await;
    }

    // Cleanup: exactly the values this test added, with the value operations.
    let mut cleanup = Vec::new();
    for value in &values {
        if let Err(e) = client.remove_txt_value(&zone, &name, value).await {
            cleanup.push(format!("{e}"));
        }
    }
    for value in &probe_values {
        if let Err(e) = client.remove_txt_value(&zone, &probe, value).await {
            cleanup.push(format!("{e}"));
        }
    }
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}
