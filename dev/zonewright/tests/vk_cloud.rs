//! Tests of the VK Cloud client (`vk_cloud`) against its mock.
#![cfg(feature = "vk_cloud")]
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
use zonewright::providers::vk_cloud::{VkCloud, VkCloudConfig, VkCloudCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RemoveOutcome, RrSet, Ttl, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::echo::{DEFAULT_ISSUED_TOKEN, EchoServer, Echoed, Render};
use zonewright_mock::vk_cloud::{PROJECT, Seed, SeedZone, VkCloudMock};

use common::echo::{CANARY_KEY, CANARY_PASSWORD, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The password of the standard seed's user.
const PASSWORD: &str = "test-only-password";

/// The user of the standard seed.
const USER: &str = "dns@example.test";

/// The owner name most tests write to, and its name relative to the zone.
const NAME: &str = "_acme-challenge.example.org";
const REL: &str = "_acme-challenge";

/// The zone most tests use.
const ZONE: &str = "example.org";

/// Fault patterns of the mock's paths. `TXT` also matches the listing path (`*` matches an
/// empty segment), so it is only used with `DELETE`.
const ZONES: &str = "/public-dns/v2/dns/";
const TXTS: &str = "/public-dns/v2/dns/*/txt/";
const TXT: &str = "/public-dns/v2/dns/*/txt/*";
const TOKENS: &str = "/identity/v3/auth/tokens";

fn zone() -> DomainName {
    dn(ZONE)
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings for the standard seed, pointed at `mock`.
fn settings(mock: &VkCloudMock) -> VkCloudConfig {
    let mut config = VkCloudConfig::new(PROJECT.into(), USER.into());
    config.dns_url = mock.dns_url();
    config.identity_url = mock.identity_url();
    config
}

fn credentials(password: &str) -> VkCloudCredentials {
    VkCloudCredentials::new(SecretString::from(password.to_owned()))
}

fn client_with(mock: &VkCloudMock, password: &str, ctx: &Context) -> VkCloud {
    VkCloud::new(settings(mock), credentials(password), ctx).unwrap()
}

async fn setup() -> (VkCloudMock, VkCloud) {
    setup_with(Seed::standard()).await
}

async fn setup_with(seed: Seed) -> (VkCloudMock, VkCloud) {
    let mock = VkCloudMock::start(seed).await;
    let client = client_with(&mock, PASSWORD, &context());
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
fn writes(mock: &VkCloudMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), TXTS) + log.count(Some("DELETE"), TXT)
}

/// The values at [`NAME`] as the mock holds them.
fn values(mock: &VkCloudMock) -> Vec<String> {
    mock.control().txt_values(ZONE, REL)
}

/// The settings JSON of `from_json` for the standard seed.
fn settings_json(mock: &VkCloudMock) -> String {
    serde_json::json!({
        "project_id": PROJECT,
        "username": USER,
        "dns_url": mock.dns_url(),
        "identity_url": mock.identity_url(),
    })
    .to_string()
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

assert_not_impl!(VkCloud: std::fmt::Display, serde::Serialize);
assert_not_impl!(VkCloudCredentials: std::fmt::Display, serde::Serialize);

/// What an echo round does for its write.
#[derive(Clone, Copy, Debug)]
enum Write {
    Add,
    Remove,
}

/// `check` and a write against an echo that quotes every request back, for every dialect: no
/// canary and no issued token in any error, `ZoneCheck::detail` or `Debug`, and the write's
/// error shows the redaction. Three kinds of pass per dialect: the API echoes reads (the issued
/// token in `X-Auth-Token`), the identity service echoes (the password in the token request),
/// and the listings answer normally so that the write itself reaches the echo: a create (no
/// record of ours) and a delete (the listing holds our value).
#[tokio::test]
async fn vk_cloud_secret_echo() {
    let secrets = [CANARY_PASSWORD, DEFAULT_ISSUED_TOKEN];
    for dialect in dialects() {
        for status in [400, 401] {
            let label = format!("{} {:?} {status} api", dialect.name, dialect.spelling);
            let echo = dialect.echo(status).start().await;
            let client = echo_client(&echo, &echo.token_url());
            echo_round(&label, &client, Write::Add, &secrets).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
            assert!(echo.token_requests() > 0, "{label}: no token was issued");

            let label = format!("{} {:?} {status} identity", dialect.name, dialect.spelling);
            let echo = dialect
                .echo(status)
                .token_path("/no-token-endpoint")
                .start()
                .await;
            let client = echo_client(&echo, &echo.url("/identity/v3"));
            echo_round(&label, &client, Write::Add, &secrets).await;
            assert!(
                echo.log().count(Some("POST"), TOKENS) > 0,
                "{label}: the identity service was not reached"
            );
        }
        for status in [400, 403, 409, 500] {
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
                let echo = dialect
                    .echo(status)
                    .render_under(
                        "/public-dns/v2/dns",
                        listings_then(dialect.render.clone(), matches!(write, Write::Remove)),
                    )
                    .start()
                    .await;
                let client = echo_client(&echo, &echo.token_url());
                echo_round(&label, &client, write, &secrets).await;
                let (method, path) = match write {
                    Write::Add => ("POST", TXTS),
                    Write::Remove => ("DELETE", TXT),
                };
                assert_eq!(
                    echo.log().count(Some(method), path),
                    1,
                    "{label}: the write did not reach the echo"
                );
            }
        }
    }
}

/// A renderer that answers the zone and TXT listings like the API (one zone; a foreign value,
/// and `v1` when `with_ours`) and every other request with `errors`.
fn listings_then(errors: Render, with_ours: bool) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method != Method::GET {
            return errors(e);
        }
        let body = if e.path.ends_with("/dns/") {
            serde_json::json!([{
                "uuid": "00000000-0000-4000-8000-000000000001",
                "tenant": PROJECT,
                "zone": ZONE,
                "status": "active"
            }])
        } else {
            let record = |id: &str, content: &str| {
                serde_json::json!({
                    "uuid": id,
                    "name": REL,
                    "dns": "/v2/dns/00000000-0000-4000-8000-000000000001",
                    "content": content,
                    "ttl": 60
                })
            };
            let mut records = vec![record("00000000-0000-4000-8000-000000000010", "foreign")];
            if with_ours {
                records.push(record("00000000-0000-4000-8000-000000000011", "v1"));
            }
            serde_json::Value::Array(records)
        };
        (StatusCode::OK, axum::Json(body)).into_response()
    })
}

fn echo_client(echo: &EchoServer, identity_url: &str) -> VkCloud {
    let mut config = VkCloudConfig::new(PROJECT.into(), USER.into());
    config.dns_url = echo.url("/public-dns/v2/dns");
    config.identity_url = identity_url.to_owned();
    VkCloud::new(config, credentials(CANARY_PASSWORD), &context()).unwrap()
}

async fn echo_round(label: &str, client: &VkCloud, write: Write, secrets: &[&str]) {
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
        assert_clean(label, text, secrets);
    }
}

/// A `TRACE` capture over a success, a renewed token, repeated 401s, a 500 and a wrong
/// password: the transport's events are there, and no canary and no issued token is.
#[tokio::test(flavor = "current_thread")]
async fn vk_cloud_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.users[0].password = CANARY_PASSWORD.into();
    let mock = VkCloudMock::start(seed).await;
    let client = client_with(&mock, CANARY_PASSWORD, &context());
    let mut texts = Vec::new();

    add(&client, "v1").await.unwrap();
    mock.control().revoke_tokens();
    add(&client, "v2").await.unwrap();

    mock.faults()
        .push(Fault::on("GET", TXTS).always().status(401));
    let e = add(&client, "v3").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("POST", TXTS).status(500));
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
    let tokens = mock.control().issued_tokens();
    assert!(tokens.len() >= 2);
    let mut secrets = vec![CANARY_PASSWORD, CANARY_KEY];
    secrets.extend(tokens.iter().map(String::as_str));
    for text in &texts {
        assert_clean("vk_cloud logs and errors", text, &secrets);
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request, token requests included: another
/// zone, a name that merely ends with the zone's text, the zone's text inside another name, and
/// a sibling zone.
#[tokio::test]
async fn vk_cloud_name_outside_zone_sends_nothing() {
    let (mock, client) = setup().await;
    let value = txt("v1");
    for (zone, name) in [
        ("example.org", "example.net"),
        ("example.org", "badexample.org"),
        ("example.org", "example.org.evil.net"),
        ("example.org", "acme.test.evil"),
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
    assert!(mock.control().records().is_empty());
}

/// `Created`, `Appended` for a second value (the apex and the wildcard of one certificate share
/// a name), then `AlreadyPresent` without a write; one token for all of it.
#[tokio::test]
async fn vk_cloud_add_is_idempotent() {
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
    assert_eq!(mock.log().count(Some("POST"), TXTS), 2);
    assert_eq!(values(&mock), ["AAA", "BBB"]);
    assert_eq!(mock.control().records()[0].ttl, 60);
    assert_eq!(mock.control().tokens_issued(), 1, "the token is cached");
}

/// Removing an absent value next to foreign ones writes nothing; adding and removing our value
/// leaves the foreign records, their identifiers and TTLs as they were. A single foreign value
/// is never a reason to delete anything, and our value at another name is not ours here.
#[tokio::test]
async fn vk_cloud_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_txt(ZONE, REL, "foreign", 600);
    control.insert_txt(ZONE, REL, "\"quoted-foreign\"", 3600);
    // The same value under another name of the zone is someone else's.
    control.insert_txt(ZONE, "_acme-challenge.www", "AAA", 300);
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
    assert_eq!(mock.log().count(Some("DELETE"), TXT), 1);

    // A name holding a single foreign value: nothing is deleted.
    let other = dn("_acme-challenge.www.example.org");
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &other, &txt("ours"))
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(control.txt_values(ZONE, "_acme-challenge.www"), ["AAA"]);
}

/// Removing the last value deletes its record, by identifier, and reports the rrset gone.
#[tokio::test]
async fn vk_cloud_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let id = mock.control().records()[0].uuid.clone();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().records().is_empty());
    let deletes = mock.log().matching(Some("DELETE"), TXT);
    assert_eq!(deletes.len(), 1);
    assert!(
        deletes[0].path.ends_with(&format!("/txt/{id}")),
        "{}",
        deletes[0].path
    );
}

/// A repeated removal is `NotPresent` and sends no delete.
#[tokio::test]
async fn vk_cloud_remove_is_idempotent() {
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
    for _ in 0..2 {
        assert_eq!(
            remove(&client, "BBB").await.unwrap(),
            RemoveOutcome::NotPresent
        );
    }
    assert_eq!(mock.log().count(Some("DELETE"), TXT), 2);
    assert!(mock.control().records().is_empty());
}

/// If the provider holds several records with our value, removal removes all of them.
#[tokio::test]
async fn vk_cloud_remove_deletes_every_record_with_the_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_txt(ZONE, REL, "dup", 60);
    control.insert_txt(ZONE, REL, "\"dup\"", 60);
    control.insert_txt(ZONE, REL, "keep", 60);
    assert_eq!(
        remove(&client, "dup").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(values(&mock), ["keep"]);
    assert_eq!(mock.log().count(Some("DELETE"), TXT), 2);
}

/// Two clients sharing a `Context` add to one name at once, the first write delayed: both values
/// end up in the rrset, one created and one appended. Without the name lock both would read "no
/// record" and both would report `Created`.
#[tokio::test]
async fn vk_cloud_concurrent_adds_are_serialized() {
    let mock = VkCloudMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, PASSWORD, &ctx);
    let b = client_with(&mock, PASSWORD, &ctx);
    mock.faults()
        .push(Fault::on("POST", TXTS).delay(Duration::from_millis(300)));
    let (zone, name, aaa, bbb) = (zone(), name(), txt("AAA"), txt("BBB"));
    let (ra, rb) = tokio::join!(
        a.add_txt_value(&zone, &name, &aaa, None),
        b.add_txt_value(&zone, &name, &bbb, None),
    );
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [AddOutcome::Appended, AddOutcome::Created]);
    let mut values = values(&mock);
    values.sort();
    assert_eq!(values, ["AAA", "BBB"]);
}

/// The zone is deleted and created again under a new identifier while the client has the old
/// one cached. A read with the stale identifier is answered 404, the zone is looked up again
/// and the read repeated: a removal never reports `NotPresent` for a value that is there. A
/// write that meets the stale identifier fails cleanly with a retryable error and drops it; the
/// next operation succeeds.
#[tokio::test]
async fn vk_cloud_stale_zone_id() {
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
    assert_eq!(values(&mock), ["v2", "v3"]);

    // The zone is recreated between the read and the create.
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", TXTS).run(move || {
        hook.recreate_zone(ZONE);
    }));
    let e = add(&client, "v4").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(add(&client, "v4").await.unwrap(), AddOutcome::Appended);
    assert_eq!(values(&mock), ["v2", "v3", "v4"]);
}

/// The record-level operations are not offered: `Unsupported`, and nothing is sent.
#[tokio::test]
async fn vk_cloud_unsupported_operations_send_nothing() {
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
/// operation's error, and the repeat starts with a read; a rejected token on a create is
/// `Transient` and the repeat obtains a new one). A delete of one record by its identifier is
/// repeated by the transport after a 5xx, a rate limit and a rejected token (design section
/// 5.3).
#[tokio::test]
async fn vk_cloud_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let posts = || mock.log().count(Some("POST"), TXTS);
    let deletes = || mock.log().count(Some("DELETE"), TXT);
    for (i, (fault, kind)) in [
        (Fault::on("POST", TXTS).status(502), ErrorKind::Transient),
        (
            Fault::on("POST", TXTS).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("POST", TXTS).status(401), ErrorKind::Transient),
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
    assert_eq!(mock.control().tokens_issued(), 1);
    // A create that was not applied is applied by the operation's repeat, with a new token.
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(posts(), 4);
    assert_eq!(mock.control().tokens_issued(), 2);

    // A delete by identifier is idempotent: a 502, a rate limit and a 401 are repeated.
    mock.faults().push(Fault::on("DELETE", TXT).status(502));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(deletes(), 2);
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("DELETE", TXT).rate_limited("1"));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(deletes(), 4);
    add(&client, "AAA").await.unwrap();
    mock.faults().push(Fault::on("DELETE", TXT).status(401));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(deletes(), 6);
    assert_eq!(mock.control().tokens_issued(), 3);
    assert!(mock.control().records().is_empty());
}

/// A delete answered 404 is a success only when a new read, under a freshly looked-up zone,
/// finds no record with the value: removed meanwhile by someone else, it is gone; with the zone
/// recreated (and the record in it) the value is still published, and the answer is a
/// retryable `Conflict`.
#[tokio::test]
async fn vk_cloud_delete_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", TXT).run(move || {
        hook.delete_txt_at(ZONE, REL);
    }));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.records().is_empty());

    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", TXT).run(move || {
        hook.recreate_zone(ZONE);
    }));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(values(&mock), ["AAA"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.records().is_empty());
}

// ---- TXT records -------------------------------------------------------------------------------

/// A create sends the documented body: the name relative to the zone, the value unquoted and
/// the configured TTL; the token goes in `X-Auth-Token`. The apex is written as `@`.
#[tokio::test]
async fn vk_cloud_add_creates_record() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    let posts = mock.log().matching(Some("POST"), TXTS);
    assert_eq!(posts.len(), 1);
    assert_eq!(
        posts[0].body_json().unwrap(),
        serde_json::json!({"name": REL, "content": "AAA", "ttl": 60})
    );
    assert_eq!(
        posts[0].header("x-auth-token"),
        Some(mock.control().issued_tokens()[0].as_str())
    );
    assert!(posts[0].header("authorization").is_none());
    let zone_id = mock.control().zone_id(ZONE);
    assert_eq!(posts[0].path, format!("/public-dns/v2/dns/{zone_id}/txt/"));
    // The zone identifier was looked up once and cached.
    add(&client, "BBB").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONES), 1);

    // The apex.
    client
        .add_txt_value(&zone(), &zone(), &txt("apex"), None)
        .await
        .unwrap();
    assert_eq!(mock.control().txt_values(ZONE, "@"), ["apex"]);
    assert_eq!(
        client
            .add_txt_value(&zone(), &zone(), &txt("apex"), None)
            .await
            .unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        client
            .remove_txt_value(&zone(), &zone(), &txt("apex"))
            .await
            .unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(values(&mock), ["AAA", "BBB"]);
}

/// TTL policy (design section 3.6): the caller's TTL or the configured one for a new rrset; a
/// record added to an existing rrset takes the smallest TTL of the set; the TTLs of other
/// records are never changed; a TTL outside the range is refused before any request.
#[tokio::test]
async fn vk_cloud_ttl_policy() {
    let (mock, client) = setup().await;
    let control = mock.control();
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
    control.insert_txt(ZONE, REL, "low", 120);
    add(&client, "CCC").await.unwrap();
    assert_eq!(control.records()[3].ttl, 120);
    assert_eq!(control.records()[0].ttl, 300, "the TTLs of others are kept");

    // The configured TTL for a new rrset.
    let mut config = settings(&mock);
    config.ttl = 3600;
    let other = VkCloud::new(config, credentials(PASSWORD), &context()).unwrap();
    other
        .add_txt_value(
            &zone(),
            &dn("_acme-challenge.www.example.org"),
            &txt("x"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(control.records_at(ZONE, "_acme-challenge.www")[0].ttl, 3600);

    let before = mock.log().len();
    for secs in [30, 86_401] {
        let e = client
            .add_txt_value(
                &zone(),
                &name(),
                &txt("DDD"),
                Some(Ttl::from_secs(secs).unwrap()),
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{secs}: {e:?}");
    }
    assert_eq!(mock.log().len(), before);
}

/// The TXT listing holds every record of the zone: records with other names, a relative name
/// that only looks absolute, and our value under them are skipped; the case of a name does not
/// matter.
#[tokio::test]
async fn vk_cloud_exact_name_match_ignores_other_names() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_txt(ZONE, "x._acme-challenge", "AAA", 60);
    // Relative: `_acme-challenge.example.org.example.org.`.
    control.insert_txt(ZONE, NAME, "AAA", 60);
    control.insert_txt(ZONE, "_acme-challenge-x", "AAA", 60);
    control.insert_txt(ZONE, "_ACME-CHALLENGE", "foreign", 60);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    assert_eq!(values(&mock), ["AAA"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert!(values(&mock).is_empty());
    for other in ["x._acme-challenge", NAME, "_acme-challenge-x"] {
        assert_eq!(control.txt_values(ZONE, other), ["AAA"], "{other}");
    }
    assert_eq!(control.txt_values(ZONE, "_ACME-CHALLENGE"), ["foreign"]);
    // A name written absolute, with the trailing dot, is the same name.
    control.insert_txt(ZONE, "_acme-challenge.example.org.", "abs", 60);
    assert_eq!(
        add(&client, "abs").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
}

/// TXT dialect: values come back unquoted or quoted and are compared as data; ours is written
/// unquoted. Content the dialect cannot decode is a foreign value left alone. Values the
/// client's dialect cannot carry are refused before any request.
#[tokio::test]
async fn vk_cloud_txt_dialect() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_txt(ZONE, REL, "AAA", 60);
    control.insert_txt(ZONE, REL, "\"BBB\"", 60);
    control.insert_txt(ZONE, REL, "\"CC\" \"CC\"", 60);
    let undecodable = "\"a\" b \"";
    control.insert_txt(ZONE, REL, undecodable, 60);
    for value in ["AAA", "BBB", "CCCC"] {
        assert_eq!(
            add(&client, value).await.unwrap(),
            AddOutcome::AlreadyPresent,
            "{value}"
        );
    }
    assert_eq!(writes(&mock), 0);
    assert_eq!(
        remove(&client, "CCCC").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert!(values(&mock).contains(&undecodable.to_owned()));
    let before = mock.log().len();
    for bad in ["two words", "quo\"te", "back\\slash", "caf\u{e9}"] {
        let e = add(&client, bad).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad}: {e:?}");
    }
    assert_eq!(mock.log().len(), before);
}

/// A create refused because another writer created the same value between the read and the
/// create (the documented `409` covers duplicates) is a retryable `Conflict` after a new read;
/// the repeat reports the value present. A refusal with the value absent stays the refusal,
/// with the provider's message.
#[tokio::test]
async fn vk_cloud_duplicate_create_is_conflict() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", TXTS).run(move || {
        hook.insert_txt(ZONE, REL, "AAA", 60);
    }));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("POST"), TXTS), 1);
    assert_eq!(values(&mock), ["AAA"]);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(mock.log().count(Some("POST"), TXTS), 1);

    for status in [400, 409] {
        mock.faults().push(Fault::on("POST", TXTS).respond(
            status,
            r#"{"error":{"code":400,"message":"invalid content"}}"#,
        ));
        let e = add(&client, "BBB").await.unwrap_err();
        match &e {
            Error::Rejected {
                status: s, detail, ..
            } => {
                assert_eq!(*s, Some(status));
                assert_eq!(detail.as_str(), "invalid content");
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(values(&mock), ["AAA"]);
}

/// Whether an empty listing is `404` or `200 []` is not documented. Both work; a `404` under a
/// cached zone identifier costs one zone lookup (it might be a stale identifier), under a fresh
/// one it is an empty listing.
#[tokio::test]
async fn vk_cloud_empty_listing_either_way() {
    for empty_is_404 in [true, false] {
        let mut seed = Seed::standard();
        seed.empty_is_404 = empty_is_404;
        let (mock, client) = setup_with(seed).await;
        let lookups = || mock.log().count(Some("GET"), ZONES);
        assert_eq!(
            remove(&client, "AAA").await.unwrap(),
            RemoveOutcome::NotPresent
        );
        assert_eq!(lookups(), 1);
        assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
        // Cached identifier, empty zone: a 404 leads to one more lookup.
        assert_eq!(lookups(), 1 + usize::from(empty_is_404));
        assert_eq!(
            remove(&client, "AAA").await.unwrap(),
            RemoveOutcome::RrsetDeleted
        );
        assert_eq!(
            remove(&client, "AAA").await.unwrap(),
            RemoveOutcome::NotPresent
        );
        assert_eq!(lookups(), 1 + 2 * usize::from(empty_is_404));
        // A project without zones: an empty list either way.
        let mut seed = Seed::standard();
        seed.empty_is_404 = empty_is_404;
        seed.zones.clear();
        let (_mock, empty) = setup_with(seed).await;
        assert!(empty.list_zones().await.unwrap().is_empty());
        let e = add(&empty, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ZoneNotFound, "{e:?}");
    }
}

/// A listing that is not complete or not in the documented form is an error, never a shorter
/// list, and nothing is written after it: an object instead of the array, a record without its
/// identifier, a body cut short.
#[tokio::test]
async fn vk_cloud_truncated_listing_fails() {
    let (mock, client) = setup().await;
    mock.control().insert_txt(ZONE, REL, "foreign", 60);
    let bodies = [
        r#"{"records":[]}"#.to_owned(),
        format!(r#"[{{"name":"{REL}","content":"foreign","ttl":60}}]"#),
        format!(r#"[{{"uuid":"00000000-0000-4000-8000-0000000000aa","name":"{REL}","ttl":60}}]"#),
        "null".to_owned(),
    ];
    for body in &bodies {
        for write in [Write::Add, Write::Remove] {
            mock.faults()
                .push(Fault::on("GET", TXTS).respond(200, body.clone()));
            let e = match write {
                Write::Add => add(&client, "AAA").await.unwrap_err(),
                Write::Remove => remove(&client, "foreign").await.unwrap_err(),
            };
            assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
            assert_eq!(writes(&mock), 0, "{body}");
        }
    }
    let records = format!(
        r#"[{{"uuid":"00000000-0000-4000-8000-0000000000aa","name":"{REL}","content":"foreign","ttl":60}}]"#
    );
    mock.faults()
        .push(
            Fault::on("GET", TXTS)
                .times(3)
                .truncated_body(200, records.len() + 100, records),
        );
    let e = remove(&client, "foreign").await.unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::Transient | ErrorKind::Protocol),
        "{e:?}"
    );
    assert_eq!(writes(&mock), 0);
    // The same for the zone listing.
    mock.faults()
        .push(Fault::on("GET", ZONES).respond(200, r#"{"zones":[]}"#));
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// An identifier the API returns that cannot go into a URL path is `Protocol`, and nothing is
/// requested with it; so is our zone listed without an identifier.
#[tokio::test]
async fn vk_cloud_unsafe_identifiers_are_protocol() {
    let (mock, client) = setup().await;
    let record = format!(r#"[{{"uuid":"../../x","name":"{REL}","content":"AAA","ttl":60}}]"#);
    mock.faults()
        .push(Fault::on("GET", TXTS).respond(200, record));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(mock.log().count(Some("DELETE"), "/**"), 0);

    for zones in [
        r#"[{"uuid":"a/b","zone":"example.org"}]"#,
        r#"[{"zone":"example.org","status":"active"}]"#,
    ] {
        mock.faults()
            .push(Fault::on("GET", ZONES).respond(200, zones));
        let fresh = client_with(&mock, PASSWORD, &context());
        let e = add(&fresh, "A").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{zones}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);
}

// ---- Zones -------------------------------------------------------------------------------------

/// A zone the project does not have is `ZoneNotFound`, before any write; so is a zone whose name
/// merely contains the asked one, and a zone of another project.
#[tokio::test]
async fn vk_cloud_zone_not_found() {
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
    mock.control().insert_zone("badexample.org", PROJECT);
    mock.control().insert_zone("example.org.evil.net", PROJECT);
    let e = client
        .add_txt_value(&dn("xample.org"), &dn("x.xample.org"), &txt("A"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    mock.control().insert_zone("example.net", "another-project");
    let e = client
        .add_txt_value(&other, &dn("x.example.net"), &txt("A"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// The zone identifier is read whether the listing calls it `uuid` (lego) or `DnsUuid` (the
/// provider's OpenAPI).
#[tokio::test]
async fn vk_cloud_zone_identifier_under_either_name() {
    for key in ["uuid", "DnsUuid"] {
        let mut seed = Seed::standard();
        seed.zone_id_key = key;
        let (mock, client) = setup_with(seed).await;
        assert_eq!(
            add(&client, "AAA").await.unwrap(),
            AddOutcome::Created,
            "{key}"
        );
        assert_eq!(
            remove(&client, "AAA").await.unwrap(),
            RemoveOutcome::RrsetDeleted,
            "{key}"
        );
        let zones = client.list_zones().await.unwrap();
        assert_eq!(zones.len(), 1, "{key}");
        assert!(client.check(&[zone()]).await.unwrap().zones[0].found);
        assert!(mock.control().records().is_empty());
    }
}

/// `check` exchanges the credentials on every call, with or without zones, and looks every zone
/// up afresh.
#[tokio::test]
async fn vk_cloud_check_reports_zones() {
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
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);

    // Without zones the credentials are still verified: a token is obtained.
    let (mock2, client2) = setup().await;
    let report = client2.check(&[]).await.unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones.is_empty());
    assert_eq!(mock2.control().tokens_issued(), 1);
    // A cached token proves nothing about the credentials now: every `check` exchanges them.
    client2.check(&[]).await.unwrap();
    assert_eq!(mock2.control().tokens_issued(), 2);
    add(&client2, "AAA").await.unwrap();
    assert_eq!(
        mock2.control().tokens_issued(),
        2,
        "the new token is cached"
    );

    // A zone recreated since the last check is found under its new identifier. (A record in
    // the zone keeps its TXT listing non-empty, so that the add's read needs no lookup.)
    mock.control().insert_txt(ZONE, "other", "foreign", 60);
    mock.control().recreate_zone(ZONE);
    assert!(client.check(&[zone()]).await.unwrap().zones[0].found);
    assert_eq!(mock.log().count(Some("GET"), ZONES), 3);
    let lookups = mock.log().count(Some("GET"), ZONES);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        mock.log().count(Some("GET"), ZONES),
        lookups,
        "check cached it"
    );

    // A token scoped to a project the user does not have is refused.
    let mut config = settings(&mock);
    config.project_id = "foreign-project".into();
    let other = VkCloud::new(config, credentials(PASSWORD), &context()).unwrap();
    let e = other.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
}

/// Every zone of the project, sorted and unique, from one listing; the identifiers are cached.
#[tokio::test]
async fn vk_cloud_list_zones() {
    let mut seed = Seed::standard();
    for i in 0..5 {
        seed.zones.push(SeedZone {
            name: format!("zone{i}.example.net"),
            project_id: PROJECT.into(),
        });
    }
    seed.zones.push(SeedZone {
        name: "other.example".into(),
        project_id: "another-project".into(),
    });
    let (mock, client) = setup_with(seed).await;
    // A record keeps the zone's TXT listing non-empty, so that a read under the cached
    // identifier needs no lookup.
    mock.control().insert_txt(ZONE, "other", "foreign", 60);
    let zones: Vec<DomainName> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name)
        .collect();
    assert_eq!(zones.len(), 6, "{zones:?}");
    assert!(zones.contains(&zone()));
    assert!(!zones.contains(&dn("other.example")));
    assert!(zones.windows(2).all(|w| w[0] < w[1]), "sorted");
    assert_eq!(mock.log().count(Some("GET"), ZONES), 1);
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        mock.log().count(Some("GET"), ZONES),
        1,
        "the zone was cached"
    );

    let wrong = client_with(&mock, "wrong", &context());
    assert_eq!(
        wrong.list_zones().await.unwrap_err().kind(),
        ErrorKind::Auth
    );
}

// ---- Authentication ----------------------------------------------------------------------------

/// The Keystone request: the password method, the user in the configured domain (`users` by
/// default), the project scope by ID; the API gets the token in `X-Auth-Token`.
#[tokio::test]
async fn vk_cloud_keystone_request_shape() {
    let (mock, client) = setup().await;
    client.check(&[zone()]).await.unwrap();
    let token_request = mock.log().matching(Some("POST"), TOKENS).pop().unwrap();
    assert_eq!(
        token_request.body_json().unwrap(),
        serde_json::json!({"auth": {
            "identity": {"methods": ["password"], "password": {"user": {
                "name": USER,
                "domain": {"name": "users"},
                "password": PASSWORD
            }}},
            "scope": {"project": {"id": PROJECT}}
        }})
    );
    let api_request = mock.log().matching(Some("GET"), ZONES).pop().unwrap();
    assert_eq!(
        api_request.header("x-auth-token"),
        Some(mock.control().issued_tokens()[0].as_str())
    );
    assert!(api_request.header("authorization").is_none());

    let mut config = settings(&mock);
    config.user_domain = "other-domain".into();
    let other = VkCloud::new(config, credentials(PASSWORD), &context()).unwrap();
    let e = other.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    let token_request = mock.log().matching(Some("POST"), TOKENS).pop().unwrap();
    assert_eq!(
        token_request.body_json().unwrap()["auth"]["identity"]["password"]["user"]["domain"],
        serde_json::json!({"name": "other-domain"})
    );
}

/// Concurrent operations of one client share one token request.
#[tokio::test]
async fn vk_cloud_token_single_flight() {
    let (mock, client) = setup().await;
    let client = Arc::new(client);
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..10 {
        let client = client.clone();
        tasks.spawn(async move {
            let name = dn(&format!("d{i}.example.org"));
            client
                .add_txt_value(&zone(), &name, &txt("AAA"), None)
                .await
                .unwrap();
        });
    }
    while let Some(done) = tasks.join_next().await {
        done.unwrap();
    }
    assert_eq!(mock.control().tokens_issued(), 1);
}

/// A token whose stated expiry is already reached is renewed before the next request.
#[tokio::test]
async fn vk_cloud_token_is_renewed_before_expiry() {
    let (mock, client) = setup().await;
    mock.control().set_token_ttl(0);
    add(&client, "A1").await.unwrap();
    add(&client, "A2").await.unwrap();
    let api_requests = mock.log().count(None, "/public-dns/**");
    assert!(api_requests >= 4);
    assert_eq!(mock.control().tokens_issued(), api_requests);
}

/// A revoked token is answered 401; the client obtains a new one and repeats the read.
#[tokio::test]
async fn vk_cloud_rejected_token_is_renewed() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    mock.control().revoke_tokens();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(mock.control().tokens_issued(), 2);
}

/// A 401 for a freshly obtained token is `Auth`, and nothing is written.
#[tokio::test]
async fn vk_cloud_repeated_401_is_auth() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", ZONES).times(5).status(401));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// Wrong credentials are `Auth` for every operation, no DNS request is made without a token,
/// and the password appears in no error.
#[tokio::test]
async fn vk_cloud_wrong_password_is_auth() {
    let mock = VkCloudMock::start(Seed::standard()).await;
    let canary = "wrong-canary-6";
    let client = client_with(&mock, canary, &context());
    let results = [
        client.check(&[zone()]).await.map(drop),
        client.list_zones().await.map(drop),
        add(&client, "AAA").await.map(drop),
        remove(&client, "AAA").await.map(drop),
    ];
    for result in results {
        let e = result.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
        assert!(!format!("{e} {e:?} {client:?}").contains(canary));
    }
    assert_eq!(mock.log().count(None, "/public-dns/**"), 0);
}

// ---- Transport ---------------------------------------------------------------------------------

/// A short `Retry-After` on a read is waited out; a long one is `RateLimited` with the wait.
#[tokio::test]
async fn vk_cloud_rate_limit() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", ZONES).rate_limited("1"));
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);
    mock.faults()
        .push(Fault::on("GET", TXTS).rate_limited("120"));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
}

/// A 5xx on a read is retried; three in a row are `Transient`, which is retryable.
#[tokio::test]
async fn vk_cloud_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    mock.faults().push(Fault::on("GET", TXTS).status(500));
    add(&client, "BBB").await.unwrap();
    mock.faults()
        .push(Fault::on("GET", TXTS).times(3).status(503));
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("GET"), TXTS), 6);
}

/// 403 is `Forbidden` without a write; a documented refusal is `Rejected` with the status and
/// the provider's message; an undocumented status is `Protocol`; a redirect is not followed.
#[tokio::test]
async fn vk_cloud_status_mapping() {
    let (mock, client) = setup().await;
    let body = r#"{"error":{"code":403,"message":"no access"}}"#;
    mock.faults()
        .push(Fault::on("GET", TXTS).respond(403, body));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    assert!(e.to_string().contains("no access"), "{e}");
    mock.faults().push(
        Fault::on("GET", ZONES).respond(400, r#"{"error":{"code":400,"message":"bad filter"}}"#),
    );
    let fresh = client_with(&mock, PASSWORD, &context());
    let e = add(&fresh, "AAA").await.unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(400));
            assert_eq!(detail.as_str(), "bad filter");
        }
        other => panic!("{other:?}"),
    }
    mock.faults()
        .push(Fault::on("GET", TXTS).respond(418, r#"{"message":"teapot"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert!(e.to_string().contains("status 418: teapot"), "{e}");
    mock.faults()
        .push(Fault::on("GET", TXTS).redirect(302, "http://127.0.0.1:9/elsewhere"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    // A create answered 503 is not repeated.
    mock.faults().push(Fault::on("POST", TXTS).status(503));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("POST"), TXTS), 1);
    assert!(mock.control().records().is_empty());
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn vk_cloud_from_json_builds_the_client() {
    let mock = VkCloudMock::start(Seed::standard()).await;
    let ctx = context();
    let client = AnyProvider::from_json(
        ProviderId::VkCloud,
        &settings_json(&mock),
        &SecretString::from(format!("{{\"password\": \"{PASSWORD}\", \"other\": 1}}")),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::VkCloud);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    // An object with the required keys only is the defaults: the public API, refused by the
    // test context.
    let e = AnyProvider::from_json(
        ProviderId::VkCloud,
        &serde_json::json!({"project_id": PROJECT, "username": USER}).to_string(),
        &SecretString::from(format!("{{\"password\": \"{PASSWORD}\"}}")),
        &ctx,
    )
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
}

/// The smallest valid configuration builds a client without any request (the sample the
/// conformance tests use).
#[test]
fn vk_cloud_sample_configuration_builds() {
    let settings = r#"{"project_id":"b5b7ffd4ef0547e5b222f44555df0000","username":"dns@example.test","identity_url":"http://127.0.0.1:9/identity/v3","dns_url":"http://127.0.0.1:9/public-dns/v2/dns"}"#;
    let credentials = r#"{"password":"test-only-password"}"#;
    let client = AnyProvider::from_json(
        ProviderId::VkCloud,
        settings,
        &SecretString::from(credentials.to_owned()),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::VkCloud);
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn vk_cloud_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || {
        serde_json::json!({
            "project_id": PROJECT,
            "username": USER,
            "dns_url": "http://127.0.0.1:1/public-dns/v2/dns",
            "identity_url": "http://127.0.0.1:1/identity/v3",
        })
    };
    let with = |key: &str, value: serde_json::Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let without = |key: &str| {
        let mut settings = base();
        settings.as_object_mut().unwrap().remove(key);
        settings
    };
    let password = serde_json::json!({"password": "pw"}).to_string();
    let cases = [
        (without("project_id"), password.clone(), "project_id"),
        (without("username"), password.clone(), "username"),
        (
            with(canary, serde_json::json!(canary)),
            password.clone(),
            "unknown keys",
        ),
        (
            with("project_id", serde_json::json!(format!("{canary}/x"))),
            password.clone(),
            "project_id",
        ),
        (
            with("project_id", serde_json::json!("")),
            password.clone(),
            "project_id",
        ),
        (
            with("username", serde_json::json!("")),
            password.clone(),
            "username",
        ),
        (
            with("user_domain", serde_json::json!("")),
            password.clone(),
            "user_domain",
        ),
        (with("ttl", serde_json::json!(30)), password.clone(), "ttl"),
        (
            with("ttl", serde_json::json!(86_401)),
            password.clone(),
            "ttl",
        ),
        (
            with(
                "dns_url",
                serde_json::json!(format!("https://u:{canary}@api.example.org")),
            ),
            password.clone(),
            "dns_url",
        ),
        (
            with(
                "identity_url",
                serde_json::json!(format!("https://auth.example.org/?{canary}")),
            ),
            password.clone(),
            "identity_url",
        ),
        (
            base(),
            serde_json::json!({"password": 5, canary: canary}).to_string(),
            "password",
        ),
        (
            base(),
            serde_json::json!({"secret": canary}).to_string(),
            "password",
        ),
        (
            base(),
            serde_json::json!({"password": ""}).to_string(),
            "password",
        ),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::VkCloud,
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
    // The bounds of the TTL are accepted.
    for ttl in [60, 86_400] {
        AnyProvider::from_json(
            ProviderId::VkCloud,
            &with("ttl", serde_json::json!(ttl)).to_string(),
            &SecretString::from(password.clone()),
            &ctx,
        )
        .unwrap_or_else(|e| panic!("ttl {ttl}: {e:?}"));
    }
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round; the defaults of the metadata are those of the settings type.
#[test]
fn vk_cloud_config_keys_match_metadata() {
    let meta = ProviderId::VkCloud.meta();
    let defaults = serde_json::to_value(VkCloudConfig::new(String::new(), String::new())).unwrap();
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
    assert_eq!(secret, ["password"]);
    for field in meta.fields.iter().filter(|f| f.required) {
        assert!(["project_id", "username", "password"].contains(&field.key));
    }
    for field in meta.fields.iter().filter(|f| f.default.is_some()) {
        let value = &defaults[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
    }
}

/// The capabilities say what the client does: the value operations, `list_zones`, nothing at
/// record level, one record per value, a TTL per record.
#[test]
fn vk_cloud_capabilities_match_the_client() {
    use zonewright::{Operation, TtlSupport, ValueGuarantee};
    let caps = &ProviderId::VkCloud.meta().capabilities;
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
    assert!(!caps.atomic_rrset_write);
    assert!(matches!(
        caps.ttl,
        TtlSupport::PerRecord {
            min: 60,
            max: 86_400
        }
    ));
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
async fn live_vk_cloud_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_VK_CLOUD_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_VK_CLOUD_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_VK_CLOUD_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::VkCloud,
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
            assert!(report.zones[0].found, "{report:?}");
            let listed = client.list_zones().await.unwrap();
            assert!(listed.iter().any(|z| z.name == zone), "{listed:?}");
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
