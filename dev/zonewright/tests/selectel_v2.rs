//! Tests of the Selectel v2 client (`selectel_v2`) against its mock.
#![cfg(feature = "selectel_v2")]
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
use zonewright::providers::selectel_v2::{SelectelV2, SelectelV2Config, SelectelV2Credentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RemoveOutcome, RrSet, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::echo::{DEFAULT_ISSUED_TOKEN, EchoServer, Echoed, Render};
use zonewright_mock::selectel_v2::{Seed, SeedZone, SelectelV2Mock};

use common::echo::{CANARY_KEY, CANARY_PASSWORD, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The password of the standard seed's user.
const PASSWORD: &str = "test-only-password";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const ZONES: &str = "/domains/v2/zones";
const RRSETS: &str = "/domains/v2/zones/*/rrset";
const RRSET: &str = "/domains/v2/zones/*/rrset/*";
const TOKENS: &str = "/identity/v3/auth/tokens";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings for the standard seed, pointed at `mock`.
fn settings(mock: &SelectelV2Mock) -> SelectelV2Config {
    let mut config = SelectelV2Config::new("123456".into(), "zw-test-user".into());
    config.project_id = Some("project-a".into());
    config.base_url = mock.base_url();
    config.auth_url = mock.auth_url();
    config
}

fn credentials(password: &str) -> SelectelV2Credentials {
    SelectelV2Credentials::new(SecretString::from(password.to_owned()))
}

fn client_with(mock: &SelectelV2Mock, password: &str, ctx: &Context) -> SelectelV2 {
    SelectelV2::new(settings(mock), credentials(password), ctx).unwrap()
}

async fn setup() -> (SelectelV2Mock, SelectelV2) {
    setup_with(Seed::standard()).await
}

async fn setup_with(seed: Seed) -> (SelectelV2Mock, SelectelV2) {
    let mock = SelectelV2Mock::start(seed).await;
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
fn writes(mock: &SelectelV2Mock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), RRSETS)
        + log.count(Some("PATCH"), RRSET)
        + log.count(Some("DELETE"), RRSET)
}

/// The settings JSON of `from_json` for the standard seed.
fn settings_json(mock: &SelectelV2Mock) -> String {
    serde_json::json!({
        "account_id": "123456",
        "project_id": "project-a",
        "username": "zw-test-user",
        "base_url": mock.base_url(),
        "auth_url": mock.auth_url(),
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

assert_not_impl!(SelectelV2: std::fmt::Display, serde::Serialize);
assert_not_impl!(SelectelV2Credentials: std::fmt::Display, serde::Serialize);

/// `check` and a write against an echo that quotes every request back, for every dialect: no
/// canary and no issued token in any error, `ZoneCheck::detail` or `Debug`, and the write's
/// error shows the redaction. Two passes per dialect and status: the API echoes (the issued
/// token in `X-Auth-Token`), and the identity service echoes (the password in the token
/// request).
#[tokio::test]
async fn selectel_v2_secret_echo() {
    let secrets = [CANARY_PASSWORD, DEFAULT_ISSUED_TOKEN];
    for dialect in dialects() {
        for status in [400, 401] {
            let label = format!("{} {:?} {status} api", dialect.name, dialect.spelling);
            let echo = dialect.echo(status).start().await;
            let client = echo_client(&echo, &echo.token_url());
            echo_round(&label, &client, &secrets).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
            assert!(echo.token_requests() > 0, "{label}: no token was issued");

            let label = format!("{} {:?} {status} identity", dialect.name, dialect.spelling);
            let echo = dialect
                .echo(status)
                .token_path("/no-token-endpoint")
                .start()
                .await;
            let client = echo_client(&echo, &echo.url("/identity/v3"));
            echo_round(&label, &client, &secrets).await;
            assert!(
                echo.log().count(Some("POST"), TOKENS) > 0,
                "{label}: the identity service was not reached"
            );
        }
        // The listings answer normally, so the write itself reaches the echo: a create (no
        // rrset) and an update (an rrset with a foreign value).
        for status in [400, 403, 422, 500] {
            for existing in [false, true] {
                let label = format!(
                    "{} {:?} {status} write existing={existing}",
                    dialect.name, dialect.spelling
                );
                let echo = dialect
                    .echo(status)
                    .render_under(
                        "/domains/v2/zones",
                        listings_then(dialect.render.clone(), existing),
                    )
                    .start()
                    .await;
                let client = echo_client(&echo, &echo.token_url());
                echo_round(&label, &client, &secrets).await;
                let (method, path) = if existing {
                    ("PATCH", RRSET)
                } else {
                    ("POST", RRSETS)
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

/// A renderer that answers the zone and rrset listings like the API (one zone; no rrset, or a
/// TXT rrset with a foreign value) and every other request with `errors`.
fn listings_then(errors: Render, existing: bool) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method != Method::GET {
            return errors(e);
        }
        let result = if e.path.ends_with("/zones") {
            serde_json::json!([{
                "id": "00000000-0000-4000-8000-000000000001",
                "name": "example.org.",
                "project_id": "project-a"
            }])
        } else if existing {
            serde_json::json!([{
                "id": "00000000-0000-4000-8000-000000000002",
                "zone_id": "00000000-0000-4000-8000-000000000001",
                "name": "_acme-challenge.example.org.",
                "type": "TXT",
                "ttl": 60,
                "records": [{"content": "\"foreign\"", "disabled": false}]
            }])
        } else {
            serde_json::json!([])
        };
        let count = result.as_array().map_or(0, Vec::len);
        let body = serde_json::json!({"count": count, "next_offset": 0, "result": result});
        (StatusCode::OK, axum::Json(body)).into_response()
    })
}

fn echo_client(echo: &EchoServer, auth_url: &str) -> SelectelV2 {
    let mut config = SelectelV2Config::new("123456".into(), "zw-test-user".into());
    config.project_id = Some("project-a".into());
    config.base_url = echo.url("/domains/v2");
    config.auth_url = auth_url.to_owned();
    SelectelV2::new(config, credentials(CANARY_PASSWORD), &context()).unwrap()
}

async fn echo_round(label: &str, client: &SelectelV2, secrets: &[&str]) {
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

/// A `TRACE` capture over a success, a renewed token, repeated 401s, a 500 and a wrong
/// password: the transport's events are there, and no canary and no issued token is.
#[tokio::test(flavor = "current_thread")]
async fn selectel_v2_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.users[0].password = CANARY_PASSWORD.into();
    let mock = SelectelV2Mock::start(seed).await;
    let client = client_with(&mock, CANARY_PASSWORD, &context());
    let mut texts = Vec::new();

    client
        .add_txt_value(&zone(), &name(), &txt("v1"), None)
        .await
        .unwrap();
    mock.control().revoke_tokens();
    client
        .add_txt_value(&zone(), &name(), &txt("v2"), None)
        .await
        .unwrap();

    mock.faults()
        .push(Fault::on("GET", RRSETS).always().status(401));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("v3"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("PATCH", RRSET).status(500));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("v3"), None)
        .await
        .unwrap_err();
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
        assert_clean("selectel_v2 logs and errors", text, &secrets);
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request, token requests included: another
/// zone, a name that merely ends with the zone's text, the zone's text inside another name, and
/// a sibling zone.
#[tokio::test]
async fn selectel_v2_name_outside_zone_sends_nothing() {
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

/// `Created`, `Appended` for a second value (the apex and the wildcard of one certificate share
/// a name), then `AlreadyPresent` without a write.
#[tokio::test]
async fn selectel_v2_add_is_idempotent() {
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
/// leaves the foreign records, the TTL and the comment as they were. A single foreign value is
/// never a reason to delete the rrset.
#[tokio::test]
async fn selectel_v2_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(
        "example.org",
        NAME,
        "TXT",
        600,
        &["\"foreign\"", "\"foreign-disabled\""],
    );
    control.set_txt_disabled(NAME, "foreign-disabled", true);
    control.set_comment(NAME, "TXT", Some("set by hand"));
    control.set_managed_by(NAME, "TXT", Some("00000000-0000-4000-8000-0000000000aa"));
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
    assert_eq!(during.ttl, 600);
    assert_eq!(during.comment.as_deref(), Some("set by hand"));
    assert_eq!(
        during.managed_by.as_deref(),
        Some("00000000-0000-4000-8000-0000000000aa")
    );
    let patch = mock.log().matching(Some("PATCH"), RRSET).pop().unwrap();
    assert_eq!(patch.body_json().unwrap()["comment"], "set by hand");
    assert_eq!(
        patch.header("x-managed-by"),
        Some("00000000-0000-4000-8000-0000000000aa")
    );
    assert_eq!(
        control.txt_values(NAME),
        ["foreign", "foreign-disabled", "ours"]
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
    assert_eq!(after.comment, original.comment);
    assert_eq!(after.managed_by, original.managed_by);

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_rrset("example.org", other, "TXT", 60, &["\"foreign\""]);
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &ours)
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(control.txt_values(other), ["foreign"]);
}

#[tokio::test]
async fn selectel_v2_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap();
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &txt("AAA"))
            .await
            .unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().rrsets().is_empty());
    assert_eq!(mock.log().count(Some("DELETE"), RRSET), 1);
    assert_eq!(mock.log().count(Some("PATCH"), RRSET), 0);
}

#[tokio::test]
async fn selectel_v2_remove_is_idempotent() {
    let (mock, client) = setup().await;
    // No rrset at all.
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap();
    client
        .add_txt_value(&zone(), &name(), &txt("BBB"), None)
        .await
        .unwrap();
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
/// end up in the rrset. Without the name lock both would read "no rrset" and the second create
/// would be refused.
#[tokio::test]
async fn selectel_v2_concurrent_adds_are_serialized() {
    let mock = SelectelV2Mock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, PASSWORD, &ctx);
    let b = client_with(&mock, PASSWORD, &ctx);
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
    let mut values = mock.control().txt_values(NAME);
    values.sort();
    assert_eq!(values, ["AAA", "BBB"]);
}

/// The zone is deleted and created again under a new identifier while the client has the old
/// one cached. A read with the stale identifier is answered 404, the zone is looked up again and
/// the read repeated: a removal never reports `NotPresent` for a value that is there. A write
/// that meets the stale identifier fails cleanly with a retryable error and drops it; the next
/// operation succeeds.
#[tokio::test]
async fn selectel_v2_stale_zone_id() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for value in ["v1", "v2"] {
        client
            .add_txt_value(&zone(), &name(), &txt(value), None)
            .await
            .unwrap();
    }
    let lookups = || mock.log().count(Some("GET"), ZONES);
    assert_eq!(lookups(), 1);

    control.recreate_zone("example.org");
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &txt("v1"))
            .await
            .unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(lookups(), 2);
    control.recreate_zone("example.org");
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &txt("v3"), None)
            .await
            .unwrap(),
        AddOutcome::Appended
    );
    assert_eq!(control.txt_values(NAME), ["v2", "v3"]);

    // The zone is recreated between the read and the write.
    let hook = control.clone();
    mock.faults().push(Fault::on("PATCH", RRSET).run(move || {
        hook.recreate_zone("example.org");
    }));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("v4"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &txt("v4"), None)
            .await
            .unwrap(),
        AddOutcome::Appended
    );
    assert_eq!(control.txt_values(NAME), ["v2", "v3", "v4"]);
}

/// The record-level operations are not offered: `Unsupported`, and nothing is sent.
#[tokio::test]
async fn selectel_v2_unsupported_operations_send_nothing() {
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

/// Retry behavior: a create, an update and a delete of the rrset are each sent once whatever
/// happens (a 5xx is the operation's error, and the repeat starts with a read). A repeated
/// delete could remove a value another writer added after the read.
#[tokio::test]
async fn selectel_v2_writes_are_sent_once() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", RRSETS).status(500));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("POST"), RRSETS), 1);
    assert!(mock.control().rrsets().is_empty());
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &txt("AAA"), None)
            .await
            .unwrap(),
        AddOutcome::Created
    );

    mock.faults().push(Fault::on("PATCH", RRSET).status(503));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("BBB"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("PATCH"), RRSET), 1);
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);

    // The delete is answered 502 and not applied; meanwhile another writer adds a value. A
    // repeat of the delete would remove it.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("DELETE", RRSET)
            .run(move || {
                let mut records = hook.txt_values(NAME);
                records.push("foreign".into());
                let quoted: Vec<String> = records.iter().map(|v| format!("\"{v}\"")).collect();
                let quoted: Vec<&str> = quoted.iter().map(String::as_str).collect();
                hook.delete_rrset(NAME, "TXT");
                hook.insert_rrset("example.org", NAME, "TXT", 60, &quoted);
            })
            .status(502),
    );
    let e = client
        .remove_txt_value(&zone(), &name(), &txt("AAA"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("DELETE"), RRSET), 1);
    assert_eq!(mock.control().txt_values(NAME), ["AAA", "foreign"]);
    // The repeat reads the new state and removes only our value.
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &txt("AAA"))
            .await
            .unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(mock.control().txt_values(NAME), ["foreign"]);

    // A rejected token on a write is not repeated with a new one: the operation fails and its
    // repeat obtains the new token.
    mock.faults().push(Fault::on("PATCH", RRSET).status(401));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("CCC"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    mock.faults().push(Fault::on("POST", RRSETS).status(401));
    let other = dn("_acme-challenge.www.example.org");
    let e = client
        .add_txt_value(&zone(), &other, &txt("CCC"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    // A rate limit on a write is reported, not waited out and repeated.
    mock.faults()
        .push(Fault::on("PATCH", RRSET).rate_limited("1"));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("CCC"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(mock.log().count(Some("PATCH"), RRSET), 4);
    assert_eq!(mock.log().count(Some("POST"), RRSETS), 3);
    assert_eq!(mock.control().txt_values(NAME), ["foreign"]);
    assert_eq!(add(&client, "CCC").await.unwrap(), AddOutcome::Appended);
}

/// A delete answered 404 is a success only when a new read finds no rrset: removed meanwhile
/// by someone else, the rrset is gone; with the zone recreated (and the rrset in it) the value
/// is still published, and the answer is a retryable `Conflict`.
#[tokio::test]
async fn selectel_v2_delete_not_found_reads_again() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", RRSET).run(move || {
        hook.delete_rrset(NAME, "TXT");
    }));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.rrsets().is_empty());

    add(&client, "AAA").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("DELETE", RRSET).run(move || {
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
    assert!(control.rrsets().is_empty());
}

// ---- TXT records and rrsets --------------------------------------------------------------------

/// The first value creates the rrset: absolute name, the configured TTL, the value quoted.
#[tokio::test]
async fn selectel_v2_add_creates_rrset() {
    let (mock, client) = setup().await;
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &txt("AAA"), None)
            .await
            .unwrap(),
        AddOutcome::Created
    );
    let rrsets = mock.control().rrsets();
    assert_eq!(rrsets.len(), 1);
    assert_eq!(rrsets[0].name, "_acme-challenge.example.org.");
    assert_eq!(rrsets[0].rtype, "TXT");
    assert_eq!(rrsets[0].ttl, 60);
    assert_eq!(rrsets[0].records[0].content, "\"AAA\"");
    // A TTL given by the caller is used for a new rrset only.
    let other = dn("_acme-challenge.www.example.org");
    let ttl = zonewright::Ttl::from_secs(300).unwrap();
    client
        .add_txt_value(&zone(), &other, &txt("BBB"), Some(ttl))
        .await
        .unwrap();
    assert_eq!(
        mock.control()
            .rrset("_acme-challenge.www.example.org", "TXT")
            .unwrap()
            .ttl,
        300
    );
    client
        .add_txt_value(
            &zone(),
            &other,
            &txt("CCC"),
            Some(zonewright::Ttl::from_secs(900).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        mock.control()
            .rrset("_acme-challenge.www.example.org", "TXT")
            .unwrap()
            .ttl,
        300
    );
    // A TTL outside the provider's range is refused before any request.
    let requests = mock.log().len();
    let e = client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("DDD"),
            Some(zonewright::Ttl::from_secs(30).unwrap()),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(mock.log().len(), requests);
}

/// A second value is appended after the first, in order, with one PATCH carrying both.
#[tokio::test]
async fn selectel_v2_add_appends_second_value() {
    let (mock, client) = setup().await;
    client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap();
    client
        .add_txt_value(&zone(), &name(), &txt("BBB"), None)
        .await
        .unwrap();
    let rrsets = mock.control().rrsets();
    assert_eq!(rrsets.len(), 1);
    let contents: Vec<&str> = rrsets[0]
        .records
        .iter()
        .map(|r| r.content.as_str())
        .collect();
    assert_eq!(contents, ["\"AAA\"", "\"BBB\""]);
    let patch = mock.log().matching(Some("PATCH"), RRSET).pop().unwrap();
    let body = patch.body_json().unwrap();
    // The update form has no name and no type.
    assert_eq!(
        body,
        serde_json::json!({"ttl": 60, "records": [
            {"content": "\"AAA\"", "disabled": false},
            {"content": "\"BBB\"", "disabled": false}
        ]})
    );
}

/// A value present only in a disabled record is not published: adding it enables that record
/// instead of adding a duplicate, and a second add is `AlreadyPresent`.
#[tokio::test]
async fn selectel_v2_add_enables_disabled_same_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset("example.org", NAME, "TXT", 60, &["\"foreign\"", "\"AAA\""]);
    control.set_txt_disabled(NAME, "AAA", true);
    let outcome = client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap();
    assert_eq!(outcome, AddOutcome::Appended);
    assert_eq!(control.txt_values(NAME), ["foreign", "AAA"]);
    assert!(control.txt_disabled(NAME).is_empty());
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &txt("AAA"), None)
            .await
            .unwrap(),
        AddOutcome::AlreadyPresent
    );
    // A disabled copy of a value does not make its removal touch it.
    control.set_txt_disabled(NAME, "foreign", true);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &txt("foreign"))
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(control.txt_disabled(NAME), ["foreign"]);
}

/// The API's `name` filter matches substrings: a longer name that contains ours is listed too
/// and must be left alone.
#[tokio::test]
async fn selectel_v2_exact_name_match_ignores_noisy_filter() {
    let (mock, client) = setup().await;
    let noise = "www._acme-challenge.example.org";
    mock.control()
        .insert_rrset("example.org", noise, "TXT", 60, &["\"noise\""]);
    client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap();
    assert_eq!(mock.control().txt_values(noise), ["noise"]);
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);
    client
        .remove_txt_value(&zone(), &name(), &txt("AAA"))
        .await
        .unwrap();
    assert_eq!(mock.control().txt_values(noise), ["noise"]);
    // The listing filter is sent in the documented form: the name without the trailing dot.
    let read = mock.log().matching(Some("GET"), RRSETS).pop().unwrap();
    let query = read.query.unwrap();
    assert!(
        query.contains("name=_acme-challenge.example.org&"),
        "{query}"
    );
    assert!(query.contains("rrset_types=TXT"), "{query}");
}

/// The TXT dialect: quoted character-strings are joined, unquoted text is read as it is, and
/// content the dialect cannot decode is a foreign value written back unchanged.
#[tokio::test]
async fn selectel_v2_txt_dialect() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let undecodable = "\"a\" b \"";
    control.insert_rrset(
        "example.org",
        NAME,
        "TXT",
        60,
        &["\"part1\" \"part2\"", undecodable],
    );
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &txt("part1part2"), None)
            .await
            .unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &txt("part1part2"))
            .await
            .unwrap(),
        RemoveOutcome::Removed
    );
    let records = control.rrset(NAME, "TXT").unwrap().records;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].content, undecodable);

    let other = "_acme-challenge.www.example.org";
    control.insert_rrset("example.org", other, "TXT", 60, &["plain"]);
    assert_eq!(
        client
            .add_txt_value(&zone(), &dn(other), &txt("plain"), None)
            .await
            .unwrap(),
        AddOutcome::AlreadyPresent
    );
}

/// An rrset created by someone else between the read and the create is a retryable `Conflict`;
/// nothing is overwritten, and the repeat appends. What the API answers to such a create is not
/// documented (the mock's 409 is invented): whatever the refusal, the client reads again and
/// decides by what it finds. A refusal with no rrset there is the refusal.
#[tokio::test]
async fn selectel_v2_create_conflict_is_conflict() {
    for status in [None, Some(422), Some(400)] {
        create_conflict(status).await;
    }
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("POST", RRSETS).respond(422, r#"{"error":"validation error"}"#));
    let e = add(&client, "AAA").await.unwrap_err();
    assert!(
        matches!(
            e,
            Error::Rejected {
                status: Some(422),
                ..
            }
        ),
        "{e:?}"
    );
    assert!(mock.control().rrsets().is_empty());
}

/// A foreign create races ours; the mock answers with its own 409 (`None`) or with `status`.
async fn create_conflict(status: Option<u16>) {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    let fault = Fault::on("POST", RRSETS).run(move || {
        hook.insert_rrset("example.org", NAME, "TXT", 60, &["\"foreign\""]);
    });
    mock.faults().push(match status {
        None => fault,
        Some(status) => fault.respond(status, r#"{"error":"refused"}"#),
    });
    let e = client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.control().txt_values(NAME), ["foreign"]);
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &txt("AAA"), None)
            .await
            .unwrap(),
        AddOutcome::Appended
    );
    assert_eq!(mock.control().txt_values(NAME), ["foreign", "AAA"]);
}

/// An rrset holds at most 100 records: the 101st value is refused before the write.
#[tokio::test]
async fn selectel_v2_rrset_record_limit() {
    let (mock, client) = setup().await;
    let contents: Vec<String> = (0..100).map(|i| format!("\"v{i}\"")).collect();
    let contents: Vec<&str> = contents.iter().map(String::as_str).collect();
    mock.control()
        .insert_rrset("example.org", NAME, "TXT", 60, &contents);
    let e = client
        .add_txt_value(&zone(), &name(), &txt("one-too-many"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &name(), &txt("v7"))
            .await
            .unwrap(),
        RemoveOutcome::Removed
    );
}

// ---- Zones -------------------------------------------------------------------------------------

/// The zone is found on the second page of the filtered listing.
#[tokio::test]
async fn selectel_v2_zone_lookup_reads_every_page() {
    let mut seed = Seed::standard();
    seed.zones = (0..1500)
        .map(|i| SeedZone {
            name: format!("z{i}.example.org."),
            project_id: "project-a".into(),
        })
        .chain(std::iter::once(SeedZone {
            name: "example.org.".into(),
            project_id: "project-a".into(),
        }))
        .collect();
    let (mock, client) = setup_with(seed).await;
    client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);
}

#[tokio::test]
async fn selectel_v2_zone_not_found() {
    let (mock, client) = setup().await;
    let missing = dn("example.net");
    let e = client
        .add_txt_value(
            &missing,
            &dn("_acme-challenge.example.net"),
            &txt("A"),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let e = client
        .remove_txt_value(&missing, &dn("_acme-challenge.example.net"), &txt("A"))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// A disabled zone is reported by `check` with a detail and refuses writes.
#[tokio::test]
async fn selectel_v2_disabled_zone() {
    let (mock, client) = setup().await;
    mock.control().set_zone_disabled("example.org", true);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    assert!(
        report.zones[0]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("disabled")
    );
    let e = client
        .add_txt_value(&zone(), &name(), &txt("A"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Rejected { status: None, .. }), "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// The token is scoped to one project. A zone of another project is either not listed (not
/// found) or listed and refused with 403, which is `Forbidden` without a repeat; nothing is
/// written either way.
#[tokio::test]
async fn selectel_v2_foreign_project_zone() {
    for listed in [false, true] {
        let mut seed = Seed::standard();
        seed.zones.push(SeedZone {
            name: "example.net.".into(),
            project_id: "project-b".into(),
        });
        seed.list_foreign_zones = listed;
        let (mock, client) = setup_with(seed).await;
        let e = client
            .add_txt_value(
                &dn("example.net"),
                &dn("_acme-challenge.example.net"),
                &txt("A"),
                None,
            )
            .await
            .unwrap_err();
        if listed {
            assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
            assert_eq!(mock.log().count(Some("GET"), RRSETS), 1, "no repeat");
        } else {
            assert_eq!(e.kind(), ErrorKind::ZoneNotFound, "{e:?}");
        }
        assert_eq!(writes(&mock), 0);
        assert!(mock.control().rrsets().is_empty());
    }
}

#[tokio::test]
async fn selectel_v2_check_reports_zones() {
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
    // A cached token proves nothing about the credentials now: every `check` exchanges them.
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

/// `list_zones` reads every page of the unfiltered listing and returns the enabled zones of
/// the configured project only, even when the API lists others. The identifiers are cached.
#[tokio::test]
async fn selectel_v2_list_zones_own_project_all_pages() {
    let mut seed = Seed::standard();
    seed.zones.extend((0..1100).map(|i| SeedZone {
        name: format!("z{i}.example.org."),
        project_id: "project-a".into(),
    }));
    seed.zones.push(SeedZone {
        name: "example.net.".into(),
        project_id: "project-b".into(),
    });
    seed.list_foreign_zones = true;
    let (mock, client) = setup_with(seed).await;
    mock.control().set_zone_disabled("z7.example.org", true);
    let zones: Vec<DomainName> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name)
        .collect();
    assert_eq!(zones.len(), 1100);
    assert!(zones.contains(&zone()));
    assert!(!zones.contains(&dn("example.net")), "foreign project");
    assert!(!zones.contains(&dn("z7.example.org")), "disabled");
    assert!(zones.windows(2).all(|w| w[0] < w[1]), "sorted");
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);
    client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap();
    assert_eq!(
        mock.log().count(Some("GET"), ZONES),
        2,
        "the zone was cached"
    );
}

/// Names are sent in Unicode form (design section 11.3): the zone filter and the name of a new
/// rrset. The mock stores Unicode names, so an ASCII-compatible spelling would not be found.
#[tokio::test]
async fn selectel_v2_internationalized_names_are_sent_in_unicode() {
    let mut seed = Seed::standard();
    seed.zones = vec![SeedZone {
        name: "пример.рф.".into(),
        project_id: "project-a".into(),
    }];
    let (mock, client) = setup_with(seed).await;
    let zone = dn("пример.рф");
    let name = dn("_acme-challenge.пример.рф");
    assert!(zone.as_str().starts_with("xn--"));
    assert_eq!(
        client
            .add_txt_value(&zone, &name, &txt("AAA"), None)
            .await
            .unwrap(),
        AddOutcome::Created
    );
    assert_eq!(
        mock.control().rrsets()[0].name,
        "_acme-challenge.пример.рф."
    );
    assert_eq!(
        client
            .remove_txt_value(&zone, &name, &txt("AAA"))
            .await
            .unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(client.check(&[zone]).await.unwrap().zones[0].found);
}

/// Records of another type at the same name are never touched.
#[tokio::test]
async fn selectel_v2_other_types_at_the_name_are_untouched() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset("example.org", NAME, "A", 300, &["192.0.2.1"]);
    let before = control.rrset(NAME, "A").unwrap();
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
    let after = control.rrset(NAME, "A").unwrap();
    assert_eq!(after.id, before.id);
    assert_eq!(after.records, before.records);
    assert_eq!(after.ttl, before.ttl);
    assert!(control.rrset(NAME, "TXT").is_none());
}

/// A listing that stops short of the number of items it states is an error, never a shorter
/// result.
#[tokio::test]
async fn selectel_v2_truncated_listing_is_protocol() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", ZONES).respond(
        200,
        r#"{"count":3,"next_offset":0,"result":[{"id":"00000000-0000-4000-8000-000000000001","name":"example.org.","project_id":"project-a"}]}"#,
    ));
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
}

/// Of two zones with the same name, the one of the token's project is used.
#[tokio::test]
async fn selectel_v2_zone_of_the_own_project_is_preferred() {
    let mut seed = Seed::standard();
    seed.zones = vec![
        SeedZone {
            name: "example.org.".into(),
            project_id: "project-b".into(),
        },
        SeedZone {
            name: "example.org.".into(),
            project_id: "project-a".into(),
        },
    ];
    seed.list_foreign_zones = true;
    let (mock, client) = setup_with(seed).await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    let own = mock
        .control()
        .zones()
        .into_iter()
        .find(|z| z.project_id == "project-a")
        .unwrap();
    assert_eq!(mock.control().rrsets()[0].zone_id, own.id);
}

// ---- Authentication ----------------------------------------------------------------------------

/// The project given by name (design section 11.3): the token is scoped by the name within the
/// account's domain, the operations work, and `list_zones` tells the project's zones from
/// others by the project ID the identity service states for the token.
#[tokio::test]
async fn selectel_v2_project_name_scope() {
    let mut seed = Seed::standard();
    seed.zones.push(SeedZone {
        name: "example.net.".into(),
        project_id: "project-b".into(),
    });
    seed.list_foreign_zones = true;
    let mock = SelectelV2Mock::start(seed).await;
    let mut config = settings(&mock);
    config.project_id = None;
    config.project_name = Some("dns-project".into());
    config.user_domain_name = Some("123456".into());
    let client = SelectelV2::new(config.clone(), credentials(PASSWORD), &context()).unwrap();

    let zones: Vec<DomainName> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name)
        .collect();
    assert_eq!(zones, [zone()]);
    let token_request = mock.log().matching(Some("POST"), TOKENS).pop().unwrap();
    assert_eq!(
        token_request.body_json().unwrap()["auth"]["scope"],
        serde_json::json!({"project": {"name": "dns-project", "domain": {"name": "123456"}}})
    );
    assert!(client.check(&[zone()]).await.unwrap().zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );

    // From stored configuration too.
    let json = serde_json::json!({
        "account_id": "123456",
        "project_name": "dns-project",
        "username": "zw-test-user",
        "base_url": mock.base_url(),
        "auth_url": mock.auth_url(),
    });
    let any = AnyProvider::from_json(
        ProviderId::SelectelV2,
        &json.to_string(),
        &SecretString::from(format!("{{\"password\": \"{PASSWORD}\"}}")),
        &context(),
    )
    .unwrap();
    assert!(any.check(&[zone()]).await.unwrap().zones[0].found);

    // A project name the account does not have is refused by the identity service.
    config.project_name = Some("no-such-project".into());
    let wrong = SelectelV2::new(config, credentials(PASSWORD), &context()).unwrap();
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
}

/// The Keystone request: the password method, the user in the account's domain (or the
/// configured one), the project scope by ID; the API gets the token in `X-Auth-Token`.
#[tokio::test]
async fn selectel_v2_keystone_request_shape() {
    let (mock, client) = setup().await;
    client.check(&[zone()]).await.unwrap();
    let token_request = mock.log().matching(Some("POST"), TOKENS).pop().unwrap();
    assert_eq!(
        token_request.body_json().unwrap(),
        serde_json::json!({"auth": {
            "identity": {"methods": ["password"], "password": {"user": {
                "name": "zw-test-user",
                "domain": {"name": "123456"},
                "password": PASSWORD
            }}},
            "scope": {"project": {"id": "project-a"}}
        }})
    );
    let api_request = mock.log().matching(Some("GET"), ZONES).pop().unwrap();
    assert_eq!(
        api_request.header("x-auth-token"),
        Some(mock.control().issued_tokens()[0].as_str())
    );
    assert!(api_request.header("authorization").is_none());

    let mut config = settings(&mock);
    config.user_domain_name = Some("other-domain".into());
    let other = SelectelV2::new(config, credentials(PASSWORD), &context()).unwrap();
    let e = other.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    let token_request = mock.log().matching(Some("POST"), TOKENS).pop().unwrap();
    assert_eq!(
        token_request.body_json().unwrap()["auth"]["identity"]["password"]["user"]["domain"],
        serde_json::json!({"name": "other-domain"})
    );
}

#[tokio::test]
async fn selectel_v2_token_is_cached() {
    let (mock, client) = setup().await;
    for i in 0..5 {
        client
            .add_txt_value(&zone(), &name(), &txt(&format!("V{i}")), None)
            .await
            .unwrap();
    }
    assert_eq!(mock.control().tokens_issued(), 1);
}

/// A token whose stated expiry is already reached is renewed before the next request.
#[tokio::test]
async fn selectel_v2_token_is_renewed_before_expiry() {
    let (mock, client) = setup().await;
    mock.control().set_token_ttl(0);
    client
        .add_txt_value(&zone(), &name(), &txt("A1"), None)
        .await
        .unwrap();
    client
        .add_txt_value(&zone(), &name(), &txt("A2"), None)
        .await
        .unwrap();
    // Every API request needed a new token, and none more were issued.
    let api_requests = mock.log().count(None, "/domains/**");
    assert!(api_requests >= 4);
    assert_eq!(mock.control().tokens_issued(), api_requests);
}

/// Concurrent operations of one client share one token request.
#[tokio::test]
async fn selectel_v2_token_single_flight() {
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

/// A revoked token is answered 401; the client obtains a new one and repeats the read.
#[tokio::test]
async fn selectel_v2_rejected_token_is_renewed() {
    let (mock, client) = setup().await;
    client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap();
    mock.control().revoke_tokens();
    client
        .add_txt_value(&zone(), &name(), &txt("BBB"), None)
        .await
        .unwrap();
    assert_eq!(mock.control().tokens_issued(), 2);
}

/// A 401 for a freshly obtained token is `Auth`.
#[tokio::test]
async fn selectel_v2_repeated_401_is_auth() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RRSETS).times(5).status(401));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

#[tokio::test]
async fn selectel_v2_wrong_password_is_auth() {
    let mock = SelectelV2Mock::start(Seed::standard()).await;
    let client = client_with(&mock, "wrong-password", &context());
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    let e = client.list_zones().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    let e = client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(mock.log().count(None, "/domains/**"), 0);
}

// ---- Transport ---------------------------------------------------------------------------------

/// A short `Retry-After` on a read is waited out; a long one is `RateLimited` with the wait.
#[tokio::test]
async fn selectel_v2_rate_limit() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RRSETS).rate_limited("1"));
    client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap();
    assert_eq!(mock.log().count(Some("GET"), RRSETS), 2);
    mock.faults()
        .push(Fault::on("GET", RRSETS).rate_limited("120"));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("BBB"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
}

/// A 5xx on a read is retried; three in a row are `Transient`, which is retryable.
#[tokio::test]
async fn selectel_v2_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RRSETS).status(500));
    client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap();
    mock.faults()
        .push(Fault::on("GET", RRSETS).times(3).status(503));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("BBB"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(mock.log().count(Some("GET"), RRSETS), 5);
}

/// The API's documented refusals are `Rejected` with the status and the provider's message.
#[tokio::test]
async fn selectel_v2_refusals_are_rejected() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", RRSETS).respond(
        422,
        r#"{"error":"validation error","description":"ttl must be between 60 and 604800"}"#,
    ));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap_err();
    match e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(status, Some(422));
            assert_eq!(
                detail.as_str(),
                "validation error: ttl must be between 60 and 604800"
            );
        }
        other => panic!("{other:?}"),
    }
    mock.faults()
        .push(Fault::on("GET", RRSETS).respond(418, r#"{"error":"teapot"}"#));
    let e = client
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert!(e.to_string().contains("status 418: teapot"), "{e}");
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn selectel_v2_from_json_builds_the_client() {
    let mock = SelectelV2Mock::start(Seed::standard()).await;
    let ctx = context();
    let client = AnyProvider::from_json(
        ProviderId::SelectelV2,
        &settings_json(&mock),
        &SecretString::from(format!("{{\"password\": \"{PASSWORD}\", \"other\": 1}}")),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::SelectelV2);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert_eq!(
        client
            .add_txt_value(&zone(), &name(), &txt("AAA"), None)
            .await
            .unwrap(),
        AddOutcome::Created
    );
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn selectel_v2_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || {
        serde_json::json!({
            "account_id": "123456",
            "project_id": "project-a",
            "username": "zw-test-user",
            "base_url": "http://127.0.0.1:1/domains/v2",
            "auth_url": "http://127.0.0.1:1/identity/v3",
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
        (without("account_id"), password.clone(), "account_id"),
        (without("username"), password.clone(), "username"),
        (without("project_id"), password.clone(), "project_id"),
        (
            with(canary, serde_json::json!(canary)),
            password.clone(),
            "unknown keys",
        ),
        (
            with("account_id", serde_json::json!(format!("12{canary}"))),
            password.clone(),
            "account_id",
        ),
        (
            with("project_id", serde_json::json!(format!("{canary}/x"))),
            password.clone(),
            "project_id",
        ),
        (
            with("project_name", serde_json::json!(canary)),
            password.clone(),
            "project_name",
        ),
        (
            {
                let mut s = without("project_id");
                // A project name must not carry control characters.
                s["project_name"] = serde_json::json!(format!("{canary}\n"));
                s
            },
            password.clone(),
            "project_name",
        ),
        (with("ttl", serde_json::json!(30)), password.clone(), "ttl"),
        (
            with("user_domain_name", serde_json::json!("")),
            password.clone(),
            "user_domain_name",
        ),
        (
            with(
                "base_url",
                serde_json::json!(format!("https://u:{canary}@api.example.org")),
            ),
            password.clone(),
            "base_url",
        ),
        (
            with(
                "auth_url",
                serde_json::json!(format!("https://auth.example.org/?{canary}")),
            ),
            password.clone(),
            "auth_url",
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
            ProviderId::SelectelV2,
            &settings.to_string(),
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{key}: {e:?}");
        let text = format!("{e} | {e:?}");
        assert!(text.contains(key), "{key}: {text}");
        assert!(!text.contains(canary), "{key}: {text}");
    }
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round.
#[test]
fn selectel_v2_config_keys_match_metadata() {
    let meta = ProviderId::SelectelV2.meta();
    let mut config = SelectelV2Config::new("123456".into(), "user".into());
    config.project_id = Some("p".into());
    config.project_name = Some("n".into());
    config.user_domain_name = Some("d".into());
    let settings = serde_json::to_value(&config).unwrap();
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
    assert_eq!(secret, ["password"]);
    for field in meta.fields.iter().filter(|f| f.required) {
        assert!(["account_id", "username", "password"].contains(&field.key));
    }
    // The defaults of the metadata are those of the settings type.
    let defaults =
        serde_json::to_value(SelectelV2Config::new(String::new(), String::new())).unwrap();
    for field in meta.fields.iter().filter(|f| f.default.is_some()) {
        let value = &defaults[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
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
async fn live_selectel_v2_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_SELECTEL_V2_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_SELECTEL_V2_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_SELECTEL_V2_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::SelectelV2,
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

    // Probe: what the API answers to a create of an rrset that exists. Two clients on separate
    // contexts (so the name lock does not serialize them) add to a fresh name at once; both
    // read "no rrset", and the second create meets the first one's rrset. The client must
    // never report both as created with a value lost, and a refusal must be `Conflict`.
    let probe = zone.prepend(&format!("_zw-live-{tag:016x}-probe")).unwrap();
    let probe_values = [
        txt(&format!("zw-live-{tag:016x}-p")),
        txt(&format!("zw-live-{tag:016x}-q")),
    ];
    if outcome.is_ok() {
        let other_ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
        let settings = live_env("ZONEWRIGHT_LIVE_SELECTEL_V2_SETTINGS");
        let credentials = live_env("ZONEWRIGHT_LIVE_SELECTEL_V2_CREDENTIALS");
        let second = AnyProvider::from_json(
            ProviderId::SelectelV2,
            &settings,
            &SecretString::from(credentials),
            &other_ctx,
        )
        .unwrap();
        let (a, b) = tokio::join!(
            client.add_txt_value(&zone, &probe, &probe_values[0], None),
            second.add_txt_value(&zone, &probe, &probe_values[1], None),
        );
        eprintln!("duplicate-create probe: {a:?} / {b:?}");
        let probe_body = tokio::spawn({
            let (client, zone, probe, probe_values) = (
                client.clone(),
                zone.clone(),
                probe.clone(),
                probe_values.clone(),
            );
            async move {
                assert!(
                    !(matches!(a, Ok(AddOutcome::Created)) && matches!(b, Ok(AddOutcome::Created))),
                    "both creates reported success: the API accepted a duplicate create"
                );
                for result in [&a, &b] {
                    if let Err(e) = result {
                        assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
                    }
                }
                // Repeating the refused add converges; both values end up published.
                for value in &probe_values {
                    client
                        .add_txt_value(&zone, &probe, value, None)
                        .await
                        .unwrap();
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
