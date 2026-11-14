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
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, SetOutcome, SkipReason,
    Ttl, Txt,
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
    // One server and one context for every case: each case reconfigures the server, and
    // every client reuses the context's pooled connection (see `EchoServer::reset`).
    let ctx = context();
    let echo = EchoServer::start(200).await;
    let secrets = [CANARY_PASSWORD, DEFAULT_ISSUED_TOKEN];
    for dialect in dialects() {
        for status in [400, 401] {
            let label = format!("{} {:?} {status} api", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status));
            let client = echo_client(&echo, &echo.token_url(), &ctx);
            echo_round(&label, &client, Write::Add, &secrets).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
            assert!(echo.token_requests() > 0, "{label}: no token was issued");

            let label = format!("{} {:?} {status} identity", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status).token_path("/no-token-endpoint"));
            let client = echo_client(&echo, &echo.url("/identity/v3"), &ctx);
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
                echo.reset(dialect.echo(status).render_under(
                    "/public-dns/v2/dns",
                    listings_then(dialect.render.clone(), matches!(write, Write::Remove)),
                ));
                let client = echo_client(&echo, &echo.token_url(), &ctx);
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

fn echo_client(echo: &EchoServer, identity_url: &str, ctx: &Context) -> VkCloud {
    let mut config = VkCloudConfig::new(PROJECT.into(), USER.into());
    config.dns_url = echo.url("/public-dns/v2/dns");
    config.identity_url = identity_url.to_owned();
    VkCloud::new(config, credentials(CANARY_PASSWORD), ctx).unwrap()
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

/// Every operation is offered; the types the API does not document are not: CAA, TLSA, PTR, SOA
/// and a type known only by its code are `UnsupportedRecordType` for every record-level
/// operation, and nothing is sent.
#[tokio::test]
async fn vk_cloud_unsupported_operations_send_nothing() {
    let (mock, client) = setup().await;
    for (rtype, text) in [
        (RecordType::CAA, "0 issue \"ca.example.net\""),
        (RecordType::TLSA, "3 1 1 0a1b"),
        (RecordType::PTR, "host.example.net."),
        (
            RecordType::SOA,
            "ns1.example.org. admin.example.org. 1 7200 3600 1209600 300",
        ),
        (RecordType::from_code(65_280), "\\# 0"),
    ] {
        let set = rr(NAME, rtype, None, &[text]);
        let errors = [
            client.get_rrset(&zone(), &name(), rtype).await.unwrap_err(),
            client
                .set_rrset(&zone(), &set, Expect::Any)
                .await
                .unwrap_err(),
            client
                .delete_rrset(&zone(), &name(), rtype, Expect::Any)
                .await
                .unwrap_err(),
        ];
        for e in errors {
            assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
        }
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
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
    for secs in [30, 59] {
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

/// Whether an empty listing is `404` or `200 []` is not documented. Both work; either one under
/// a cached zone identifier costs one zone lookup (it might be a stale identifier), under a
/// fresh one it is an empty listing.
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
        // Cached identifier, empty zone: one more lookup.
        assert_eq!(lookups(), 2, "empty_is_404 = {empty_is_404}");
        // Cached identifier, a record in the zone: no lookup.
        assert_eq!(
            remove(&client, "AAA").await.unwrap(),
            RemoveOutcome::RrsetDeleted
        );
        assert_eq!(lookups(), 2, "empty_is_404 = {empty_is_404}");
        assert_eq!(
            remove(&client, "AAA").await.unwrap(),
            RemoveOutcome::NotPresent
        );
        assert_eq!(lookups(), 3, "empty_is_404 = {empty_is_404}");
        // A project without zones: `200 []` is an empty list; a `404` cannot be told apart
        // from a wrong `dns_url` and is an error.
        let mut seed = Seed::standard();
        seed.empty_is_404 = empty_is_404;
        seed.zones.clear();
        let (_mock, empty) = setup_with(seed).await;
        if empty_is_404 {
            let e = empty.list_zones().await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
            let e = add(&empty, "AAA").await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
        } else {
            assert!(empty.list_zones().await.unwrap().is_empty());
            let e = add(&empty, "AAA").await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::ZoneNotFound, "{e:?}");
        }
    }
}

/// A `dns_url` whose path is wrong gets `404` for the zone listing. That is an error in every
/// operation, never "no zones": `check` does not report the zone as missing, `list_zones` does
/// not return an empty list, and nothing is written.
#[tokio::test]
async fn vk_cloud_zone_listing_404_is_an_error() {
    let (mock, client) = setup().await;
    for _ in 0..3 {
        mock.faults().push(Fault::on("GET", ZONES).status(404));
    }
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// The zone is recreated under a new identifier while the client has the old one cached, and
/// the provider answers the old identifier's TXT listing with `200 []` (what it does is not
/// documented). The empty listing is confirmed by a fresh lookup: the value in the recreated
/// zone is found and removed, never reported `NotPresent`.
#[tokio::test]
async fn vk_cloud_empty_listing_under_cached_id_is_confirmed() {
    let mut seed = Seed::standard();
    seed.unknown_zone_lists_empty = true;
    let (mock, client) = setup_with(seed).await;
    let control = mock.control();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    control.recreate_zone(ZONE);
    assert_eq!(values(&mock), ["AAA"], "the record moved with the zone");
    let lookups = mock.log().count(Some("GET"), ZONES);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(mock.log().count(Some("GET"), ZONES), lookups + 1);
    assert!(values(&mock).is_empty());
}

/// Two zones of the same name in the project, with different identifiers: the client does not
/// pick one. Operations are `Config` with nothing written, `check` reports the zone as not
/// usable with a reason, and `list_zones` lists the name once without caching an identifier.
#[tokio::test]
async fn vk_cloud_ambiguous_zone_name_is_refused() {
    let (mock, client) = setup().await;
    let control = mock.control();
    // An identifier cached before the second zone appears is dropped by `list_zones`.
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Created);
    let before = writes(&mock);
    control.insert_zone(ZONE, PROJECT);
    assert_eq!(client.list_zones().await.unwrap().len(), 1);
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    assert!(report.zones[0].detail.is_some());
    let zones = client.list_zones().await.unwrap();
    assert_eq!(zones.len(), 1);
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(
        e.kind(),
        ErrorKind::Config,
        "not cached by list_zones: {e:?}"
    );
    assert_eq!(writes(&mock), before);
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

/// The capabilities say what the client does: every operation, the seven documented types, none
/// read-only, one record per value, a TTL per record within the documented range.
#[test]
fn vk_cloud_capabilities_match_the_client() {
    use zonewright::{Operation, Preconditions, TtlSupport, ValueGuarantee};
    let caps = &ProviderId::VkCloud.meta().capabilities;
    for op in [
        Operation::Check,
        Operation::ListZones,
        Operation::AddTxtValue,
        Operation::RemoveTxtValue,
        Operation::ListRrsets,
        Operation::GetRrset,
        Operation::SetRrset,
        Operation::DeleteRrset,
    ] {
        assert!(caps.supports(op), "{op}");
    }
    for rtype in [
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::SRV,
        RecordType::TXT,
    ] {
        assert!(caps.can_read(rtype) && caps.can_write(rtype), "{rtype}");
    }
    for rtype in [RecordType::SOA, RecordType::CAA, RecordType::TLSA] {
        assert!(!caps.can_read(rtype), "{rtype}");
    }
    assert!(caps.read_only_types.is_empty());
    assert_eq!(caps.txt_values, ValueGuarantee::PerValue);
    assert_eq!(caps.preconditions, Preconditions::ReadThenWrite);
    assert!(caps.txt_plain_only);
    assert!(!caps.atomic_rrset_write);
    assert!(matches!(
        caps.ttl,
        TtlSupport::PerRecord {
            min: 60,
            max: 2_147_483_647
        }
    ));
}

// ---- Record level (design sections 3.4, 3.6 and 12.3) ------------------------------------------

/// Fault patterns of the record paths of every type. `*` matches an empty segment, so the
/// member pattern is only used with `DELETE`.
const COLLECTIONS: &str = "/public-dns/v2/dns/*/*/";
const MEMBERS: &str = "/public-dns/v2/dns/*/*/*";

/// A record value in canonical text.
fn rdata(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap()
}

/// An rrset at `owner`.
fn rr(owner: &str, rtype: RecordType, ttl: Option<u32>, texts: &[&str]) -> RrSet {
    RrSet::new(
        dn(owner),
        rtype,
        ttl.map(|t| Ttl::from_secs(t).unwrap()),
        texts.iter().map(|t| rdata(rtype, t)),
    )
    .unwrap()
}

fn ttl(secs: u32) -> Option<Ttl> {
    Some(Ttl::from_secs(secs).unwrap())
}

/// Number of record write requests of any type: creates and deletes.
fn record_writes(mock: &VkCloudMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), COLLECTIONS)
        + log.count(Some("DELETE"), MEMBERS)
        + log.count(Some("PUT"), MEMBERS)
}

/// The values of the records of type `kind` at the relative name `rel`, as the mock stores them
/// (the type's value fields joined by spaces), sorted.
fn stored(mock: &VkCloudMock, kind: &str, rel: &str) -> Vec<String> {
    let keys: &[&str] = match kind {
        "a" => &["ipv4"],
        "aaaa" => &["ipv6"],
        "mx" => &["priority", "content"],
        "srv" => &["priority", "weight", "port", "host"],
        _ => &["content"],
    };
    let mut values: Vec<String> = mock
        .control()
        .records_of(ZONE, kind, rel)
        .iter()
        .map(|r| {
            keys.iter()
                .map(|k| r.field(k).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    values.sort();
    values
}

/// Every supported type through set, get and list with canonical equality: the apex, an IDN
/// name, a wildcard, a delegation, an SRV name, multi-value sets and a TXT value of a full
/// character-string; then the fields the API stores, and a repeat that changes nothing.
#[tokio::test]
async fn vk_cloud_record_round_trips() {
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
        rr(
            "*.example.org",
            RecordType::AAAA,
            None,
            &["2001:db8::1", "2001:db8::2"],
        ),
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
        rr("example.org", RecordType::TXT, None, &[&long, "\"v=1\""]),
        rr(
            "_acme-challenge.example.org",
            RecordType::TXT,
            Some(2_147_483_647),
            &["\"abc-DEF_123\""],
        ),
    ];
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
        // A set without a TTL gets the configured default.
        let expected = set.clone().with_ttl(set.ttl().or(ttl(60)));
        let got = client
            .get_rrset(&zone(), set.name(), set.rtype())
            .await
            .unwrap();
        assert_eq!(got.as_ref(), Some(&expected), "{label}");
        assert!(got.unwrap().records().iter().all(RecordData::is_canonical));
        let before = record_writes(&mock);
        assert_eq!(
            client.set_rrset(&zone(), set, Expect::Any).await.unwrap(),
            SetOutcome::Unchanged,
            "{label}"
        );
        assert_eq!(record_writes(&mock), before, "{label}");
    }
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.skipped.is_empty(), "{:?}", listing.skipped);
    assert_eq!(listing.rrsets.len(), sets.len());
    for set in &sets {
        let expected = set.clone().with_ttl(set.ttl().or(ttl(60)));
        assert!(listing.rrsets.contains(&expected), "{expected:?}");
    }

    // The names and fields the API stores.
    assert_eq!(stored(&mock, "a", "@"), ["192.0.2.1", "192.0.2.2"]);
    assert_eq!(stored(&mock, "a", "xn--bcher-kva"), ["192.0.2.3"]);
    assert_eq!(stored(&mock, "aaaa", "*"), ["2001:db8::1", "2001:db8::2"]);
    assert_eq!(stored(&mock, "cname", "www"), ["target.example.net"]);
    assert_eq!(
        stored(&mock, "ns", "sub"),
        ["ns1.example.net", "ns2.example.net"]
    );
    assert_eq!(
        stored(&mock, "mx", "@"),
        ["10 mail.example.org", "20 backup.example.net"]
    );
    assert_eq!(
        stored(&mock, "srv", "_sip._tcp"),
        ["1 5 5060 sip.example.org", "2 0 5061 sip2.example.org"]
    );
    assert_eq!(
        stored(&mock, "txt", "@"),
        ["v=1".to_owned(), "x".repeat(255)]
    );
    let ttls: Vec<u64> = mock
        .control()
        .records_of(ZONE, "ns", "sub")
        .iter()
        .map(|r| r.ttl)
        .collect();
    assert_eq!(ttls, [3600, 3600]);

    // A host name stated with its trailing dot by another writer reads as the same value.
    mock.control().insert_record(
        ZONE,
        "mx",
        "other",
        serde_json::json!({"content": "Mail.Example.org.", "priority": 10}),
        600,
    );
    let other = rr(
        "other.example.org",
        RecordType::MX,
        None,
        &["10 mail.example.org."],
    );
    assert_eq!(
        client
            .get_rrset(&zone(), &dn("other.example.org"), RecordType::MX)
            .await
            .unwrap(),
        Some(other.clone().with_ttl(ttl(600)))
    );
    let before = record_writes(&mock);
    assert_eq!(
        client
            .set_rrset(&zone(), &other, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    assert_eq!(record_writes(&mock), before);
}

/// `Expect::Absent` on an existing set and `Expect::Matches` on a different or missing one are
/// `PreconditionFailed` and write nothing; an expectation that holds lets the write through.
#[tokio::test]
async fn vk_cloud_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record(
        ZONE,
        "a",
        "www",
        serde_json::json!({"ipv4": "192.0.2.1"}),
        600,
    );
    let original = control.all_records();
    let www = "www.example.org";
    let wanted = rr(www, RecordType::A, None, &["192.0.2.7"]);
    let other = rr(www, RecordType::A, None, &["192.0.2.2"]);
    let more = rr(www, RecordType::A, None, &["192.0.2.1", "192.0.2.2"]);
    let with_ttl = rr(www, RecordType::A, Some(300), &["192.0.2.1"]);
    for expect in [
        Expect::Absent,
        Expect::Matches(&other),
        Expect::Matches(&more),
        Expect::Matches(&with_ttl),
    ] {
        let e = client
            .set_rrset(&zone(), &wanted, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{expect:?}: {e:?}");
        assert!(!e.is_retryable());
    }
    for expect in [Expect::Matches(&other), Expect::Matches(&with_ttl)] {
        let e = client
            .delete_rrset(&zone(), &dn(www), RecordType::A, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{expect:?}: {e:?}");
    }
    let txt = rr(www, RecordType::TXT, None, &["\"v\""]);
    let e = client
        .set_rrset(&zone(), &txt, Expect::Matches(&txt))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &dn(www), RecordType::TXT, Expect::Matches(&txt))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(record_writes(&mock), 0);
    assert_eq!(control.all_records(), original);

    // The expectation holds, with the TTL and without one.
    let current = rr(www, RecordType::A, Some(600), &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&current))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, "a", "www"), ["192.0.2.7"]);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Matches(&wanted))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
}

/// `Any` replaces whatever is there, touching only the records that change; an equal set is
/// `Unchanged` without a write; a delete removes every record and a repeat is `NotPresent`.
#[tokio::test]
async fn vk_cloud_set_any_replaces_and_delete_converges() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record(
        ZONE,
        "a",
        "www",
        serde_json::json!({"ipv4": "192.0.2.1"}),
        600,
    );
    control.insert_record(
        ZONE,
        "a",
        "www",
        serde_json::json!({"ipv4": "192.0.2.2"}),
        600,
    );
    let kept = control.records_of(ZONE, "a", "www")[1].clone();
    let replaced = rr(www, RecordType::A, None, &["192.0.2.2", "192.0.2.3"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &replaced, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, "a", "www"), ["192.0.2.2", "192.0.2.3"]);
    let log = mock.log();
    assert_eq!(log.count(Some("POST"), COLLECTIONS), 1);
    assert_eq!(log.count(Some("DELETE"), MEMBERS), 1);
    // The record that stays is the same record, with its TTL; the new one joins with it.
    let records = control.records_of(ZONE, "a", "www");
    assert!(records.contains(&kept));
    assert!(records.iter().all(|r| r.ttl == 600));

    let before = record_writes(&mock);
    assert_eq!(
        client
            .set_rrset(&zone(), &replaced, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    assert_eq!(record_writes(&mock), before);

    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(control.records_of(ZONE, "a", "www").is_empty());
    let before = record_writes(&mock);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
    assert_eq!(record_writes(&mock), before);
    assert_eq!(
        client
            .get_rrset(&zone(), &dn(www), RecordType::A)
            .await
            .unwrap(),
        None
    );
}

/// Refusals before any request: SOA is not a type of this API, the apex NS set is not writable,
/// a TTL below 60 and an expectation about another name or type are `InvalidInput`, a name
/// outside the zone is `NameOutsideZone`. The bounds themselves are accepted.
#[tokio::test]
async fn vk_cloud_record_refusals_send_nothing() {
    let (mock, client) = setup().await;
    let soa = rr(
        "example.org",
        RecordType::SOA,
        None,
        &["ns1.example.org. admin.example.org. 1 7200 3600 1209600 300"],
    );
    let e = client
        .set_rrset(&zone(), &soa, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");

    let apex_ns = rr("example.org", RecordType::NS, None, &["ns1.example.net."]);
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

    for secs in [0, 59] {
        let set = rr("www.example.org", RecordType::A, Some(secs), &["192.0.2.1"]);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{secs}: {e:?}");
    }
    let a = rr("www.example.org", RecordType::A, None, &["192.0.2.1"]);
    let txt = rr("www.example.org", RecordType::TXT, None, &["\"v\""]);
    let e = client
        .set_rrset(&zone(), &a, Expect::Matches(&txt))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    let e = client
        .delete_rrset(
            &zone(),
            &dn("www.example.org"),
            RecordType::A,
            Expect::Absent,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");

    for (zone, owner) in [
        ("example.org", "example.net"),
        ("example.org", "badexample.org"),
        ("a.example.org", "b.example.org"),
    ] {
        let set = rr(owner, RecordType::A, None, &["192.0.2.1"]);
        let e = client
            .set_rrset(&dn(zone), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NameOutsideZone, "{e:?}");
        let e = client
            .delete_rrset(&dn(zone), &dn(owner), RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NameOutsideZone, "{e:?}");
        let e = client
            .get_rrset(&dn(zone), &dn(owner), RecordType::A)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NameOutsideZone, "{e:?}");
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
    assert_eq!(mock.control().tokens_issued(), 0);

    // The bounds are accepted and stored.
    for (owner, secs) in [("lo", 60), ("hi", 2_147_483_647)] {
        let set = rr(
            &format!("{owner}.example.org"),
            RecordType::A,
            Some(secs),
            &["192.0.2.1"],
        );
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
        assert_eq!(
            mock.control().records_of(ZONE, "a", owner)[0].ttl,
            u64::from(secs)
        );
    }
}

/// An SRV owner name is stated as service and protocol labels relative to the zone; a name that
/// does not start with them is refused after the read and nothing is written. Labels to the right
/// of them are sent as they are.
#[tokio::test]
async fn vk_cloud_srv_names_start_with_service_and_protocol() {
    let (mock, client) = setup().await;
    for owner in [
        "example.org",
        "sip.example.org",
        "_sip.example.org",
        "_sip.tcp.example.org",
    ] {
        let set = rr(owner, RecordType::SRV, None, &["1 1 5060 sip.example.org."]);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{owner}: {e:?}");
    }
    assert_eq!(record_writes(&mock), 0);
    let deep = rr(
        "_sip._udp.sub.example.org",
        RecordType::SRV,
        None,
        &["1 1 5060 sip.example.org."],
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &deep, Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    assert_eq!(
        stored(&mock, "srv", "_sip._udp.sub"),
        ["1 1 5060 sip.example.org"]
    );
}

/// Values whose encoding at this API no source establishes are refused after the read and
/// nothing is written; the same value already at the provider is kept as it is.
#[tokio::test]
async fn vk_cloud_values_without_an_encoding_are_refused() {
    let (mock, client) = setup().await;
    for set in [
        rr("www.example.org", RecordType::TXT, None, &["\"two words\""]),
        rr("www.example.org", RecordType::TXT, None, &["\"a\\\"b\""]),
        rr("www.example.org", RecordType::MX, None, &["0 ."]),
        rr("_s._tcp.example.org", RecordType::SRV, None, &["0 0 0 ."]),
        rr(
            "www.example.org",
            RecordType::CNAME,
            None,
            &["a\\.b.example.net."],
        ),
    ] {
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{set:?}: {e:?}");
    }
    assert_eq!(record_writes(&mock), 0);

    // An SPF value with spaces written by someone else: listed, kept, and a value joins it.
    mock.control()
        .insert_txt(ZONE, "www", "v=spf1 mx -all", 300);
    let read = client
        .get_rrset(&zone(), &dn("www.example.org"), RecordType::TXT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.records()[0].as_str(), "\"v=spf1 mx -all\"");
    let mut members = read.records().to_vec();
    members.push(rdata(RecordType::TXT, "\"plain\""));
    let both = RrSet::new(dn("www.example.org"), RecordType::TXT, None, members).unwrap();
    assert_eq!(
        client
            .set_rrset(&zone(), &both, Expect::Matches(&read))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, "txt", "www"), ["plain", "v=spf1 mx -all"]);
}

/// Per-record TTLs (design section 3.6): a set whose records disagree reads with the smallest; a
/// value added without a TTL gets it and the others keep theirs. The API cannot change the TTL
/// of a record that stays: such a request is `InvalidInput` and nothing is written, while a
/// replacement of every record carries the requested TTL.
#[tokio::test]
async fn vk_cloud_record_ttls() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record(
        ZONE,
        "a",
        "www",
        serde_json::json!({"ipv4": "192.0.2.1"}),
        600,
    );
    control.insert_record(
        ZONE,
        "a",
        "www",
        serde_json::json!({"ipv4": "192.0.2.2"}),
        300,
    );
    let read = client
        .get_rrset(&zone(), &dn(www), RecordType::A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.ttl(), ttl(300));

    let three = rr(
        www,
        RecordType::A,
        None,
        &["192.0.2.1", "192.0.2.2", "192.0.2.3"],
    );
    client
        .set_rrset(&zone(), &three, Expect::Any)
        .await
        .unwrap();
    let ttls = || {
        let mut t: Vec<(String, u64)> = control
            .records_of(ZONE, "a", "www")
            .into_iter()
            .map(|r| (r.field("ipv4").unwrap(), r.ttl))
            .collect();
        t.sort();
        t
    };
    let mixed = [
        ("192.0.2.1".to_owned(), 600),
        ("192.0.2.2".to_owned(), 300),
        ("192.0.2.3".to_owned(), 300),
    ];
    assert_eq!(ttls(), mixed);

    // A TTL for records that stay: refused, nothing written, nothing changed.
    mock.log().clear();
    for set in [
        three.clone().with_ttl(ttl(300)),
        rr(www, RecordType::A, Some(900), &["192.0.2.1", "192.0.2.9"]),
    ] {
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    }
    assert_eq!(record_writes(&mock), 0);
    assert_eq!(ttls(), mixed);

    // Every record replaced: the new ones carry the requested TTL.
    let fresh = rr(www, RecordType::A, Some(900), &["192.0.2.8", "192.0.2.9"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &fresh, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        ttls(),
        [("192.0.2.8".to_owned(), 900), ("192.0.2.9".to_owned(), 900)]
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &fresh, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
}

/// The listing reads every type, with the smallest TTL of each set; a name the model cannot hold
/// and two CNAME records at one name are in `skipped`, an unparseable value is non-canonical
/// data. The API lists by type, so a type outside the model cannot appear.
#[tokio::test]
async fn vk_cloud_listing_reports_skipped_sets() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let a = |rel: &str, ip: &str, ttl: u64| {
        control.insert_record(ZONE, "a", rel, serde_json::json!({"ipv4": ip}), ttl);
    };
    a("www", "192.0.2.1", 600);
    a("www", "192.0.2.2", 300);
    a("odd", "not an address", 300);
    a("bad name", "192.0.2.9", 300);
    control.insert_record(
        ZONE,
        "ns",
        "@",
        serde_json::json!({"content": "ns1.mcs.mail.ru"}),
        86400,
    );
    control.insert_record(
        ZONE,
        "ns",
        "@",
        serde_json::json!({"content": "ns2.mcs.mail.ru"}),
        86400,
    );
    for target in ["a.example.net", "b.example.net"] {
        control.insert_record(
            ZONE,
            "cname",
            "two",
            serde_json::json!({"content": target}),
            300,
        );
    }
    control.insert_record(
        ZONE,
        "mx",
        "@",
        serde_json::json!({"content": "mx.example.org"}),
        300,
    );
    control.insert_txt(ZONE, "WWW", "v", 120);
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
    assert_eq!(
        get("example.org", RecordType::NS),
        Some(rr(
            "example.org",
            RecordType::NS,
            Some(86400),
            &["ns1.mcs.mail.ru.", "ns2.mcs.mail.ru."]
        ))
    );
    let odd = get("odd.example.org", RecordType::A).unwrap();
    assert!(!odd.records()[0].is_canonical());
    assert_eq!(odd.records()[0].as_str(), "not an address");
    // An MX record without its priority: kept as non-canonical data.
    let mx = get("example.org", RecordType::MX).unwrap();
    assert!(!mx.records()[0].is_canonical());
    assert_eq!(
        get("www.example.org", RecordType::TXT),
        Some(rr(
            "www.example.org",
            RecordType::TXT,
            Some(120),
            &["\"v\""]
        ))
    );

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
                "example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::UnsupportedName
            ),
            (
                "two.example.org.".to_owned(),
                "CNAME".to_owned(),
                SkipReason::NotPlainRecords
            ),
        ]
    );
    assert_eq!(listing.rrsets.len(), 5);

    // One listing per type, and nothing else.
    let gets: Vec<String> = mock
        .log()
        .matching(Some("GET"), COLLECTIONS)
        .into_iter()
        .map(|r| r.path)
        .filter(|p| p != ZONES)
        .collect();
    let id = control.zone_id(ZONE);
    let expected: Vec<String> = ["a", "aaaa", "cname", "mx", "ns", "srv", "txt"]
        .iter()
        .map(|k| format!("/public-dns/v2/dns/{id}/{k}/"))
        .collect();
    assert_eq!(gets, expected);
}

/// A listing or a read that does not have the documented shape is an error, never a shorter
/// result, and nothing is written after a short read.
#[tokio::test]
async fn vk_cloud_truncated_rrset_listing_is_protocol() {
    let (mock, client) = setup().await;
    mock.control().insert_record(
        ZONE,
        "a",
        "www",
        serde_json::json!({"ipv4": "192.0.2.1"}),
        60,
    );
    let a = "/public-dns/v2/dns/*/a/";
    for body in [
        r#"{"records":[]}"#,
        r#"[{"uuid":"00000000-0000-4000-8000-0000000000aa","ipv4":"192.0.2.1"}]"#,
        r#"[{"name":"www","ipv4":"192.0.2.1"}]"#,
        r#"[{"uuid":"00000000-0000-4000-8000-0000000000aa","name":"www","ipv4":"192.0.2.1"}"#,
        "null",
    ] {
        mock.faults().push(Fault::on("GET", a).respond(200, body));
        let e = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
        mock.faults().push(Fault::on("GET", a).respond(200, body));
        let e = client
            .get_rrset(&zone(), &dn("www.example.org"), RecordType::A)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
        let set = rr("www.example.org", RecordType::A, None, &["192.0.2.2"]);
        mock.faults().push(Fault::on("GET", a).respond(200, body));
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
        mock.faults().push(Fault::on("GET", a).respond(200, body));
        let e = client
            .delete_rrset(&zone(), &dn("www.example.org"), RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    // One failed type fails the whole listing.
    mock.faults().push(
        Fault::on("GET", "/public-dns/v2/dns/*/srv/")
            .status(500)
            .always(),
    );
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    mock.faults().clear();
    assert_eq!(record_writes(&mock), 0);
}

/// Records at other names, other types at the same name and a name that only looks like ours are
/// untouched by every operation.
#[tokio::test]
async fn vk_cloud_record_operations_touch_only_their_rrset() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_txt(ZONE, "www", "foreign", 300);
    control.insert_record(
        ZONE,
        "aaaa",
        "www",
        serde_json::json!({"ipv6": "2001:db8::1"}),
        300,
    );
    control.insert_record(
        ZONE,
        "a",
        "x.www",
        serde_json::json!({"ipv4": "192.0.2.1"}),
        300,
    );
    control.insert_record(
        ZONE,
        "a",
        "www.example.org",
        serde_json::json!({"ipv4": "192.0.2.1"}),
        300,
    );
    control.insert_record(
        ZONE,
        "cname",
        "www2",
        serde_json::json!({"content": "t.example.net"}),
        300,
    );
    let others = control.all_records();

    let www = "www.example.org";
    let set = rr(www, RecordType::A, None, &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &set, Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    let set = rr(www, RecordType::A, None, &["192.0.2.5", "192.0.2.6"]);
    client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::CNAME, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
    assert_eq!(control.all_records(), others);
}

/// A replacement creates the missing records before it deletes the surplus ones. A failure part
/// way leaves a superset of the old values, never a subset, and a repeat sends only the rest.
#[tokio::test]
async fn vk_cloud_replacement_creates_before_it_deletes() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record(
        ZONE,
        "a",
        "www",
        serde_json::json!({"ipv4": "192.0.2.1"}),
        300,
    );
    control.insert_record(
        ZONE,
        "a",
        "www",
        serde_json::json!({"ipv4": "192.0.2.2"}),
        300,
    );
    let wanted = rr(www, RecordType::A, None, &["192.0.2.3", "192.0.2.4"]);

    // The second create fails: the old values are all there, with the first new one.
    mock.faults()
        .push(Fault::on("POST", COLLECTIONS).skip(1).status(502));
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(
        stored(&mock, "a", "www"),
        ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    );
    assert_eq!(mock.log().count(Some("DELETE"), MEMBERS), 0);

    // The first delete is refused: every wanted value is published, the old ones too.
    mock.faults().push(Fault::on("DELETE", MEMBERS).status(403));
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    assert_eq!(
        stored(&mock, "a", "www"),
        ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]
    );

    // The repeat converges, then nothing is left to do.
    mock.log().clear();
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, "a", "www"), ["192.0.2.3", "192.0.2.4"]);
    assert_eq!(mock.log().count(Some("POST"), COLLECTIONS), 0);
    assert_eq!(mock.log().count(Some("DELETE"), MEMBERS), 2);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );

    // The order of the requests of one replacement.
    mock.log().clear();
    let next = rr(www, RecordType::A, None, &["192.0.2.5"]);
    client.set_rrset(&zone(), &next, Expect::Any).await.unwrap();
    let methods: Vec<String> = mock
        .log()
        .entries()
        .into_iter()
        .filter(|r| r.method != "GET")
        .map(|r| r.method.to_string())
        .collect();
    assert_eq!(methods, ["POST", "DELETE", "DELETE"]);
}

/// A CNAME is replaced by a delete followed by a create (the API has no documented update of
/// the value with its TTL), never by a second record next to the first; no `PUT` is sent.
#[tokio::test]
async fn vk_cloud_cname_is_replaced_by_delete_then_create() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record(
        ZONE,
        "cname",
        "www",
        serde_json::json!({"content": "old.example.net"}),
        300,
    );
    let new = rr(
        "www.example.org",
        RecordType::CNAME,
        None,
        &["new.example.net."],
    );
    assert_eq!(
        client.set_rrset(&zone(), &new, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    let records = control.records_of(ZONE, "cname", "www");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].field("content").unwrap(), "new.example.net");
    // The record's TTL as read is kept.
    assert_eq!(records[0].ttl, 300);
    let methods: Vec<String> = mock
        .log()
        .entries()
        .into_iter()
        .filter(|r| r.method != "GET" && r.path != TOKENS)
        .map(|r| r.method.to_string())
        .collect();
    assert_eq!(methods, ["DELETE", "POST"]);
}

/// Two clients sharing a `Context` write one name at once, the first create delayed: the second
/// reads after the first wrote, so its `Expect::Absent` fails.
#[tokio::test]
async fn vk_cloud_concurrent_record_writes_are_serialized() {
    let mock = VkCloudMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, PASSWORD, &ctx);
    let b = client_with(&mock, PASSWORD, &ctx);
    mock.faults()
        .push(Fault::on("POST", COLLECTIONS).delay(Duration::from_millis(300)));
    let first = rr("www.example.org", RecordType::A, None, &["192.0.2.1"]);
    let second = rr("www.example.org", RecordType::A, None, &["192.0.2.2"]);
    let zone = zone();
    let (ra, rb) = tokio::join!(
        a.set_rrset(&zone, &first, Expect::Absent),
        b.set_rrset(&zone, &second, Expect::Absent),
    );
    let mut kinds = [ra.map_err(|e| e.kind()), rb.map_err(|e| e.kind())];
    kinds.sort_by_key(|r| format!("{r:?}"));
    assert_eq!(
        kinds,
        [Err(ErrorKind::PreconditionFailed), Ok(SetOutcome::Created)]
    );
    assert_eq!(mock.control().records_of(ZONE, "a", "www").len(), 1);
}

/// Creates are sent once whatever the answer (502, 429, 401); the delete of one record by its
/// identifier is repeated by the transport after a 502, a 429 and a 401.
#[tokio::test]
async fn vk_cloud_record_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let set = rr(www, RecordType::MX, None, &["10 mail.example.org."]);
    for (fault, kind) in [
        (
            Fault::on("POST", COLLECTIONS).status(502),
            ErrorKind::Transient,
        ),
        (
            Fault::on("POST", COLLECTIONS).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (
            Fault::on("POST", COLLECTIONS).status(401),
            ErrorKind::Transient,
        ),
    ] {
        mock.log().clear();
        mock.faults().push(fault);
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(mock.log().count(Some("POST"), COLLECTIONS), 1);
        assert!(control.all_records().is_empty());
    }
    assert_eq!(
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap(),
        SetOutcome::Created
    );
    for fault in [
        Fault::on("DELETE", MEMBERS).status(502),
        Fault::on("DELETE", MEMBERS).rate_limited("1"),
        Fault::on("DELETE", MEMBERS).status(401),
    ] {
        mock.log().clear();
        mock.faults().push(fault);
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(www), RecordType::MX, Expect::Any)
                .await
                .unwrap(),
            DeleteOutcome::Deleted
        );
        assert_eq!(mock.log().count(Some("DELETE"), MEMBERS), 2);
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
    }
    assert_eq!(mock.log().count(Some("PUT"), MEMBERS), 0);
}

/// The record-level requests as the OpenAPI describes them: one listing of the type, the create
/// with the relative name, the type's fields and the TTL, the delete by identifier on the type's
/// path.
#[tokio::test]
async fn vk_cloud_record_request_shapes() {
    let (mock, client) = setup().await;
    let id = mock.control().zone_id(ZONE);
    for (set, kind, body) in [
        (
            rr("example.org", RecordType::A, None, &["192.0.2.1"]),
            "a",
            serde_json::json!({"name": "@", "ipv4": "192.0.2.1", "ttl": 60}),
        ),
        (
            rr(
                "v6.example.org",
                RecordType::AAAA,
                Some(120),
                &["2001:db8::1"],
            ),
            "aaaa",
            serde_json::json!({"name": "v6", "ipv6": "2001:db8::1", "ttl": 120}),
        ),
        (
            rr(
                "www.example.org",
                RecordType::CNAME,
                None,
                &["t.example.net."],
            ),
            "cname",
            serde_json::json!({"name": "www", "content": "t.example.net", "ttl": 60}),
        ),
        (
            rr(
                "sub.example.org",
                RecordType::NS,
                None,
                &["ns1.example.net."],
            ),
            "ns",
            serde_json::json!({"name": "sub", "content": "ns1.example.net", "ttl": 60}),
        ),
        (
            rr(
                "example.org",
                RecordType::MX,
                None,
                &["10 mail.example.org."],
            ),
            "mx",
            serde_json::json!({
                "name": "@", "content": "mail.example.org", "priority": 10, "ttl": 60
            }),
        ),
        (
            rr(
                "_sip._udp.example.org",
                RecordType::SRV,
                None,
                &["1 2 3 sip.example.org."],
            ),
            "srv",
            serde_json::json!({
                "name": "_sip._udp", "priority": 1, "weight": 2, "port": 3,
                "host": "sip.example.org", "ttl": 60
            }),
        ),
        (
            rr("*.example.org", RecordType::TXT, None, &["\"v1\""]),
            "txt",
            serde_json::json!({"name": "*", "content": "v1", "ttl": 60}),
        ),
    ] {
        mock.log().clear();
        client
            .set_rrset(&zone(), &set, Expect::Absent)
            .await
            .unwrap();
        let entries = mock.log().entries();
        let gets: Vec<&str> = entries
            .iter()
            .filter(|r| r.method == "GET" && r.path != ZONES)
            .map(|r| r.path.as_str())
            .collect();
        let collection = format!("/public-dns/v2/dns/{id}/{kind}/");
        // One listing of the type; a second one when the first, under the cached zone
        // identifier, found nothing and the zone was looked up again.
        assert!(!gets.is_empty() && gets.len() <= 2, "{kind}: {gets:?}");
        assert!(gets.iter().all(|p| *p == collection), "{kind}: {gets:?}");
        let post = mock
            .log()
            .matching(Some("POST"), COLLECTIONS)
            .pop()
            .unwrap();
        assert_eq!(post.path, collection, "{kind}");
        assert_eq!(post.body_json().unwrap(), body, "{kind}");

        mock.log().clear();
        client
            .delete_rrset(&zone(), set.name(), set.rtype(), Expect::Any)
            .await
            .unwrap();
        let uuid = post_uuid(&mock, kind);
        assert!(uuid.is_none(), "{kind}: the record was not deleted");
        let delete = mock.log().matching(Some("DELETE"), MEMBERS).pop().unwrap();
        assert!(
            delete.path.starts_with(&collection),
            "{kind}: {}",
            delete.path
        );
    }
    assert_eq!(record_writes(&mock), 1);
}

/// The identifier of the one record of type `kind` the mock holds, if any.
fn post_uuid(mock: &VkCloudMock, kind: &str) -> Option<String> {
    mock.control()
        .all_records()
        .into_iter()
        .find(|r| r.kind == kind)
        .map(|r| r.uuid)
}

/// After the zone is recreated under a new identifier, the record-level operations look it up
/// again: a read under the cached identifier that finds nothing is confirmed by a fresh lookup,
/// and never reported as an absent rrset while the records are published.
#[tokio::test]
async fn vk_cloud_record_stale_zone_id() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let set = rr(www, RecordType::A, None, &["192.0.2.1"]);
    client
        .set_rrset(&zone(), &set, Expect::Absent)
        .await
        .unwrap();
    let expected = set.clone().with_ttl(ttl(60));

    control.recreate_zone(ZONE);
    assert_eq!(
        client
            .get_rrset(&zone(), &dn(www), RecordType::A)
            .await
            .unwrap(),
        Some(expected.clone())
    );
    control.recreate_zone(ZONE);
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(listing.rrsets, std::slice::from_ref(&expected));
    control.recreate_zone(ZONE);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Matches(&expected))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(control.all_records().is_empty());

    // An empty listing answered `200 []` under the cached identifier is confirmed the same way.
    let mut seed = Seed::standard();
    seed.empty_is_404 = false;
    seed.unknown_zone_lists_empty = true;
    let (mock, client) = setup_with(seed).await;
    client
        .set_rrset(&zone(), &set, Expect::Absent)
        .await
        .unwrap();
    mock.control().recreate_zone(ZONE);
    assert_eq!(
        client
            .set_rrset(&zone(), &set, Expect::Absent)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );
}

/// A delete answered 404 is a success only when a new read, under a freshly looked-up zone, no
/// longer finds the value; with the zone recreated (and the record in it) the answer is a
/// retryable `Conflict` and the repeat converges.
#[tokio::test]
async fn vk_cloud_record_delete_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    let set = rr(www, RecordType::A, None, &["192.0.2.1"]);
    client
        .set_rrset(&zone(), &set, Expect::Absent)
        .await
        .unwrap();

    let hook = control.clone();
    mock.faults()
        .push(Fault::on("DELETE", MEMBERS).run(move || {
            hook.recreate_zone(ZONE);
        }));
    let e = client
        .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );

    // Deleted by someone else between the read and the delete: done.
    client
        .set_rrset(&zone(), &set, Expect::Absent)
        .await
        .unwrap();
    let uuid = post_uuid(&mock, "a").unwrap();
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("DELETE", MEMBERS).run(move || hook.delete_record(&uuid)));
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(control.all_records().is_empty());
}

/// A create refused because another writer created the same record after the read is a
/// retryable `Conflict` (found by a new read), and the repeat reports it unchanged; any other
/// refusal is the error.
#[tokio::test]
async fn vk_cloud_refused_record_create_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let set = rr("www.example.org", RecordType::A, None, &["192.0.2.1"]);
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("POST", COLLECTIONS).run(move || {
            hook.insert_record(
                ZONE,
                "a",
                "www",
                serde_json::json!({"ipv4": "192.0.2.1"}),
                60,
            );
        }));
    let e = client
        .set_rrset(&zone(), &set, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert_eq!(
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap(),
        SetOutcome::Unchanged
    );

    mock.faults()
        .push(Fault::on("POST", COLLECTIONS).status(400));
    let other = rr("x.example.org", RecordType::A, None, &["192.0.2.2"]);
    let e = client
        .set_rrset(&zone(), &other, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(control.records_of(ZONE, "a", "x").len(), 0);
}

/// What the echo answers for each record-level request kind.
#[derive(Clone, Copy, Debug)]
enum RecordRequest {
    /// A create: no A record at the name.
    Create,
    /// A delete: TXT records at the name.
    Delete,
    /// A record listing of the zone listing: the type listings are the echo.
    List,
}

/// A renderer that answers the zone listing like the API and, unless `records_echo`, every
/// record listing with TXT-shaped records at [`REL`] (a foreign value and `v1`); every other
/// request gets `errors`.
fn record_listings_then(errors: Render, records_echo: bool) -> Render {
    let listings = listings_then(errors.clone(), true);
    Arc::new(move |e: &Echoed| {
        if e.method == Method::GET && (e.path.ends_with("/dns/") || !records_echo) {
            return listings(e);
        }
        errors(e)
    })
}

/// The record-level requests against an echo, for every dialect: the create, the delete and the
/// per-type listing. No canary and no issued token in any error or `Debug`, and the error shows
/// the redaction.
#[tokio::test]
async fn vk_cloud_secret_echo_record_level() {
    // One server and one context for every case: each case reconfigures the server, and
    // every client reuses the context's pooled connection (see `EchoServer::reset`).
    let ctx = context();
    let echo = EchoServer::start(200).await;
    let secrets = [CANARY_PASSWORD, DEFAULT_ISSUED_TOKEN];
    for dialect in dialects() {
        for (kind, statuses) in [
            // A 401 to a create is not repeated and carries no echo (the token is renewed by
            // the operation's repeat); the read and the token request cover the 401 body.
            (RecordRequest::Create, [400, 403, 409, 500].as_slice()),
            // A 5xx to a delete by identifier or a listing is repeated by the transport with
            // back-off: it adds time and no coverage.
            (RecordRequest::Delete, [400, 403, 409].as_slice()),
            (RecordRequest::List, [400, 401, 403].as_slice()),
        ] {
            for &status in statuses {
                let label = format!("{} {:?} {status} {kind:?}", dialect.name, dialect.spelling);
                echo.reset(dialect.echo(status).render_under(
                    "/public-dns/v2/dns",
                    record_listings_then(
                        dialect.render.clone(),
                        matches!(kind, RecordRequest::List),
                    ),
                ));
                let client = echo_client(&echo, &echo.token_url(), &ctx);
                let result = match kind {
                    RecordRequest::Create => {
                        let set = rr(NAME, RecordType::A, None, &["192.0.2.1"]);
                        client
                            .set_rrset(&zone(), &set, Expect::Any)
                            .await
                            .map(|o| format!("{o:?}"))
                    }
                    RecordRequest::Delete => client
                        .delete_rrset(&zone(), &name(), RecordType::TXT, Expect::Any)
                        .await
                        .map(|o| format!("{o:?}")),
                    RecordRequest::List => client
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
                assert_clean(&label, &text, &secrets);
                let (method, path) = match kind {
                    RecordRequest::Create => ("POST", COLLECTIONS),
                    RecordRequest::Delete => ("DELETE", MEMBERS),
                    RecordRequest::List => ("GET", "/public-dns/v2/dns/*/a/"),
                };
                assert!(
                    echo.log().count(Some(method), path) >= 1,
                    "{label}: the request did not reach the echo"
                );
            }
        }
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

/// Record-level round trip under a generated label in the zone the maintainer names: an A set
/// and a TXT set are created, read, listed, replaced and deleted; afterwards every rrset at the
/// generated names is deleted, also when the body failed. Nothing else is touched.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_vk_cloud_record_round_trip() {
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
    let name = zone.prepend(&format!("zw-live-{tag:016x}")).unwrap();
    let created = [
        (name.clone(), RecordType::A),
        (name.clone(), RecordType::TXT),
    ];

    let body = {
        let (client, zone, name) = (client.clone(), zone.clone(), name.clone());
        tokio::spawn(async move {
            let set = |rtype: RecordType, ttl: Option<u32>, texts: &[&str]| {
                RrSet::new(
                    name.clone(),
                    rtype,
                    ttl.map(|t| Ttl::from_secs(t).unwrap()),
                    texts.iter().map(|t| RecordData::parse(rtype, t).unwrap()),
                )
                .unwrap()
            };
            let a = set(RecordType::A, Some(300), &["192.0.2.1", "192.0.2.2"]);
            let txt = set(RecordType::TXT, Some(300), &["\"zw-live\""]);
            for wanted in [&a, &txt] {
                assert_eq!(
                    client
                        .set_rrset(&zone, wanted, Expect::Absent)
                        .await
                        .unwrap(),
                    SetOutcome::Created
                );
                assert_eq!(
                    client
                        .get_rrset(&zone, &name, wanted.rtype())
                        .await
                        .unwrap()
                        .as_ref(),
                    Some(wanted)
                );
                assert_eq!(
                    client.set_rrset(&zone, wanted, Expect::Any).await.unwrap(),
                    SetOutcome::Unchanged
                );
            }
            let listing = client.list_rrsets(&zone).await.unwrap();
            assert!(listing.rrsets.contains(&a), "{listing:?}");
            assert!(listing.rrsets.contains(&txt), "{listing:?}");
            let replaced = set(RecordType::A, None, &["192.0.2.2", "192.0.2.3"]);
            assert_eq!(
                client
                    .set_rrset(&zone, &replaced, Expect::Matches(&a))
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            for rtype in [RecordType::A, RecordType::TXT] {
                assert_eq!(
                    client
                        .delete_rrset(&zone, &name, rtype, Expect::Any)
                        .await
                        .unwrap(),
                    DeleteOutcome::Deleted
                );
                assert_eq!(client.get_rrset(&zone, &name, rtype).await.unwrap(), None);
            }
        })
    };
    let outcome = body.await;

    // Cleanup: every rrset at the generated name, which only this test writes.
    let mut cleanup = Vec::new();
    for (name, rtype) in &created {
        if let Err(e) = client.delete_rrset(&zone, name, *rtype, Expect::Any).await {
            cleanup.push(format!("{e}"));
        }
    }
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}
