//! Tests of the nic.ru client (`nicru`) against its mock.
#![cfg(feature = "nicru")]
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

use secrecy::SecretString;
use zonewright::providers::nicru::{Nicru, NicruConfig, NicruCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RemoveOutcome, RrSet, Ttl, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::{IntoResponse as _, Response};
use zonewright_mock::echo::{self as echo_mock, DEFAULT_ISSUED_TOKEN, EchoServer, Echoed, Render};
use zonewright_mock::nicru::{NicruMock, Seed};

use common::echo::{
    CANARY_KEY, CANARY_PASSWORD, CANARY_TOKEN, CANARY_USER, Dialect, LogCapture, REDACTED,
    assert_clean, dialects,
};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The owner name most tests write to, and its name relative to the zone.
const NAME: &str = "_acme-challenge.example.org";
const REL: &str = "_acme-challenge";

/// Fault patterns of the mock's paths.
const TOKEN: &str = "/oauth/token";
const ZONES: &str = "/dns-master/zones";
const RECORDS: &str = "/dns-master/services/*/zones/*/records";
const RECORD: &str = "/dns-master/services/*/zones/*/records/*";
const COMMIT: &str = "/dns-master/services/*/zones/*/commit";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings for `seed`, pointed at `mock`, without request spacing.
fn settings(mock: &NicruMock, seed: &Seed) -> NicruConfig {
    let mut config = NicruConfig::new(seed.username.clone());
    config.base_url = mock.base_url();
    config.token_url = mock.token_url();
    config.min_request_interval_ms = 0;
    config
}

fn credentials(password: &str, client_id: &str, client_secret: &str) -> NicruCredentials {
    NicruCredentials::new(
        SecretString::from(password.to_owned()),
        SecretString::from(client_id.to_owned()),
        SecretString::from(client_secret.to_owned()),
    )
}

fn client_for(mock: &NicruMock, seed: &Seed, password: &str, ctx: &Context) -> Nicru {
    Nicru::new(
        settings(mock, seed),
        credentials(password, &seed.client_id, &seed.client_secret),
        ctx,
    )
    .unwrap()
}

fn client_with(mock: &NicruMock, ctx: &Context) -> Nicru {
    let seed = Seed::standard();
    client_for(mock, &seed, &seed.password, ctx)
}

async fn setup() -> (NicruMock, Nicru) {
    let mock = NicruMock::start(Seed::standard()).await;
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

fn puts(mock: &NicruMock) -> usize {
    mock.log().count(Some("PUT"), RECORDS)
}

fn deletes(mock: &NicruMock) -> usize {
    mock.log().count(Some("DELETE"), RECORD)
}

fn commits(mock: &NicruMock) -> usize {
    mock.log().count(Some("POST"), COMMIT)
}

/// Number of write requests the mock received: edits and commits.
fn writes(mock: &NicruMock) -> usize {
    puts(mock) + deletes(mock) + commits(mock)
}

/// A `fail` answer of the API with one error.
fn fail_body(code: &str, text: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<response><status>fail</status><errors>\
         <error code=\"{code}\">{text}</error></errors></response>"
    )
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

assert_not_impl!(Nicru: std::fmt::Display, serde::Serialize);
assert_not_impl!(NicruCredentials: std::fmt::Display, serde::Serialize);

/// Every secret of an echo round: the four canaries of the configuration (the user name first)
/// and the token the echo issues.
const ECHO_SECRETS: [&str; 5] = [
    CANARY_USER,
    CANARY_PASSWORD,
    CANARY_KEY,
    CANARY_TOKEN,
    DEFAULT_ISSUED_TOKEN,
];

/// An XML answer with status 200.
fn xml_ok(body: String) -> Response {
    (StatusCode::OK, [("content-type", "text/xml")], body).into_response()
}

/// A renderer for the DNS API: the zone and record listings as the API answers them (the zone
/// `example.org`, a foreign TXT value and, with `ours`, the value `v1`), the edits accepted
/// when `edits_ok`, and everything else with `errors`.
fn api_then(errors: Render, ours: bool, edits_ok: bool) -> Render {
    Arc::new(move |e: &Echoed| {
        let zone = "<zone admin=\"x\" enable=\"true\" has-changes=\"false\" has-primary=\"true\" \
                    id=\"1\" idn-name=\"example.org\" name=\"example.org\" service=\"zwservice\"";
        if e.method == Method::GET && e.path.ends_with("/zones") {
            return xml_ok(format!(
                "<response><status>success</status><data>{zone}/></data></response>"
            ));
        }
        if e.method == Method::GET {
            let mut rrs = String::from(
                "<rr id=\"1001\"><name>_acme-challenge</name><ttl>300</ttl><type>TXT</type>\
                 <txt><string>foreign</string></txt></rr>",
            );
            if ours {
                rrs.push_str(
                    "<rr id=\"1002\"><name>_acme-challenge</name><ttl>300</ttl><type>TXT</type>\
                     <txt><string>v1</string></txt></rr>",
                );
            }
            return xml_ok(format!(
                "<response><status>success</status><data>{zone}>{rrs}</zone></data></response>"
            ));
        }
        if edits_ok && (e.method == Method::PUT || e.method == Method::DELETE) {
            return xml_ok("<response><status>success</status></response>".to_owned());
        }
        errors(e)
    })
}

/// The API's own failure envelope, with the echoed request as the error text and status 200,
/// as the documentation shows it for the DNS API; the token endpoint gets the status asked for.
fn nicru_envelope() -> Render {
    Arc::new(|e: &Echoed| {
        let body = fail_body("4001", &echo_mock::xml_escape(&e.text));
        let status = if e.path.starts_with("/dns-master") {
            StatusCode::OK
        } else {
            e.status
        };
        (status, [("content-type", "text/xml")], body).into_response()
    })
}

fn echo_client(echo: &EchoServer, token_url: &str) -> Nicru {
    let mut config = NicruConfig::new(CANARY_USER.to_owned());
    config.base_url = echo.url("/dns-master");
    config.token_url = token_url.to_owned();
    config.min_request_interval_ms = 0;
    Nicru::new(
        config,
        credentials(CANARY_PASSWORD, CANARY_KEY, CANARY_TOKEN),
        &context(),
    )
    .unwrap()
}

/// What an echo round does for its write.
#[derive(Clone, Copy, Debug)]
enum Write {
    Add,
    Remove,
}

async fn echo_round(label: &str, client: &Nicru, write: Write) {
    // The user name is a setting, not a secret, and `Debug` shows the settings; it is still
    // kept out of every error.
    assert_clean(label, &format!("{client:?}"), &ECHO_SECRETS[1..]);
    let mut texts = Vec::new();
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
        assert_clean(label, text, &ECHO_SECRETS);
    }
}

/// `check` and a write against an echo that quotes every request back, for every dialect and
/// the API's own failure envelope: no canary and no issued token in any error,
/// `ZoneCheck::detail` or `Debug`, and the write's error shows the redaction. Every request
/// kind reaches the echo: the token request (its form body carries all four credentials), the
/// listings, the staging of a record and of a deletion, and the commit.
#[tokio::test]
async fn nicru_secret_echo() {
    let mut all = dialects();
    all.push(Dialect {
        name: "nicru_envelope",
        spelling: echo_mock::Spelling::Verbatim,
        render: nicru_envelope(),
    });
    for dialect in all {
        let tag = |what: &str, status: u16| {
            format!("{} {:?} {status} {what}", dialect.name, dialect.spelling)
        };

        // The token request is echoed: the token path is one the echo does not serve.
        for status in [400, 401] {
            let label = tag("token", status);
            let echo = dialect.echo(status).start().await;
            let client = echo_client(&echo, &echo.url(TOKEN));
            echo_round(&label, &client, Write::Add).await;
            assert!(
                echo.log().count(Some("POST"), TOKEN) >= 1,
                "{label}: the token request did not reach the echo"
            );
        }

        // The listings are echoed.
        for status in [400, 401, 403] {
            let label = tag("read", status);
            let echo = dialect.echo(status).start().await;
            let client = echo_client(&echo, &echo.token_url());
            echo_round(&label, &client, Write::Add).await;
            assert!(echo.token_requests() > 0, "{label}: no token was requested");
            assert!(
                echo.log().count(Some("GET"), ZONES) >= 1,
                "{label}: the API was not reached"
            );
        }

        // The edits are echoed.
        for status in [400, 403, 422, 500] {
            for write in [Write::Add, Write::Remove] {
                // A 5xx to a delete by identifier is repeated by the transport, with back-off:
                // it adds time and no coverage.
                if status == 500 && matches!(write, Write::Remove) {
                    continue;
                }
                let label = tag(&format!("edit {write:?}"), status);
                let ours = matches!(write, Write::Remove);
                let echo = dialect
                    .echo(status)
                    .render_under("/dns-master", api_then(dialect.render.clone(), ours, false))
                    .start()
                    .await;
                let client = echo_client(&echo, &echo.token_url());
                echo_round(&label, &client, write).await;
                let (method, path) = match write {
                    Write::Add => ("PUT", RECORDS),
                    Write::Remove => ("DELETE", RECORD),
                };
                assert!(
                    echo.log().count(Some(method), path) >= 1,
                    "{label}: the edit did not reach the echo"
                );
            }
        }

        // The commit is echoed.
        for status in [400, 403] {
            for write in [Write::Add, Write::Remove] {
                let label = tag(&format!("commit {write:?}"), status);
                let ours = matches!(write, Write::Remove);
                let echo = dialect
                    .echo(status)
                    .render_under("/dns-master", api_then(dialect.render.clone(), ours, true))
                    .start()
                    .await;
                let client = echo_client(&echo, &echo.token_url());
                echo_round(&label, &client, write).await;
                assert_eq!(
                    echo.log().count(Some("POST"), COMMIT),
                    3,
                    "{label}: the commit did not reach the echo three times"
                );
            }
        }
    }
}

/// A `TRACE` capture over a success, repeated 401s, a 500, an expired token and a wrong
/// password: the transport's events are there, and no canary and no issued token is.
#[tokio::test(flavor = "current_thread")]
async fn nicru_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.username = CANARY_USER.into();
    seed.password = CANARY_PASSWORD.into();
    seed.client_id = CANARY_KEY.into();
    seed.client_secret = CANARY_TOKEN.into();
    let mock = NicruMock::start(seed.clone()).await;
    let client = client_for(&mock, &seed, CANARY_PASSWORD, &context());
    let mut texts = Vec::new();

    add(&client, "v1").await.unwrap();

    mock.faults()
        .push(Fault::on("GET", ZONES).always().status(401));
    let e = add(&client, "v2").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("PUT", RECORDS).status(500));
    let e = add(&client, "v2").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    mock.control().expire_tokens();
    add(&client, "v2").await.unwrap();

    let wrong = client_for(&mock, &seed, "not-the-password", &context());
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    // The user name is a setting, not a secret, and `Debug` shows the settings.
    assert_clean(
        "nicru Debug",
        &format!("{wrong:?} | {client:?}"),
        &[CANARY_PASSWORD, CANARY_KEY, CANARY_TOKEN],
    );

    let entries = capture.entries();
    assert!(
        entries.iter().any(|e| e.target == "zonewright::http"),
        "the capture holds no transport event"
    );
    texts.push(capture.text());
    for text in &texts {
        assert_clean(
            "nicru logs and errors",
            text,
            &[CANARY_USER, CANARY_PASSWORD, CANARY_KEY, CANARY_TOKEN],
        );
        assert!(
            !text.contains("nic-test-token"),
            "an issued token leaks: {text}"
        );
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request, token requests included: another
/// zone, a name that merely ends with the zone's text, the zone's text inside another name, and
/// a sibling zone.
#[tokio::test]
async fn nicru_name_outside_zone_sends_nothing() {
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
        assert_eq!(e.kind(), ErrorKind::NameOutsideZone, "{e:?}");
        let e = client
            .remove_txt_value(&zone, &name, &value)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NameOutsideZone, "{e:?}");
    }
    assert!(mock.log().is_empty());
}

/// `Created`, `Appended` for a second value, then `AlreadyPresent` without a write. Each
/// change is published by a commit.
#[tokio::test]
async fn nicru_add_is_idempotent() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "v1").await.unwrap(), AddOutcome::Created);
    assert_eq!(add(&client, "v2").await.unwrap(), AddOutcome::Appended);
    let before = writes(&mock);
    assert_eq!(
        add(&client, "v2").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(commits(&mock), 2);
    assert_eq!(mock.control().published_txt(REL), ["v1", "v2"]);
    assert!(!mock.control().has_changes("example.org"));
}

/// Removing an absent value next to a foreign one writes nothing; adding and removing our value
/// leaves the foreign record, its TTL, another type at the name and our value at another name
/// as they were. A single foreign value is never a reason to delete anything.
#[tokio::test]
async fn nicru_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let foreign = control.insert_record("example.org", REL, "TXT", "foreign", Some("300"));
    control.insert_record("example.org", REL, "A", "192.0.2.1", Some("600"));
    control.insert_record("example.org", "other", "TXT", "v1", None);

    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);

    assert_eq!(add(&client, "v1").await.unwrap(), AddOutcome::Appended);
    assert_eq!(remove(&client, "v1").await.unwrap(), RemoveOutcome::Removed);

    let left = control.published(REL, "TXT");
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, foreign);
    assert_eq!(left[0].value(), "foreign");
    assert_eq!(left[0].ttl.as_deref(), Some("300"));
    assert_eq!(control.published(REL, "A").len(), 1);
    assert_eq!(control.published_txt("other"), ["v1"]);
    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::NotPresent
    );
}

/// Removing the last value deletes its record, by identifier, and reports the rrset gone.
#[tokio::test]
async fn nicru_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "v1").await.unwrap();
    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(deletes(&mock), 1);
    let path = &mock.log().matching(Some("DELETE"), RECORD)[0].path;
    assert!(
        path.starts_with("/dns-master/services/zwservice/zones/example.org/records/"),
        "{path}"
    );
    assert!(mock.control().published_txt(REL).is_empty());
    assert!(!mock.control().has_changes("example.org"));
}

#[tokio::test]
async fn nicru_remove_is_idempotent() {
    let (mock, client) = setup().await;
    add(&client, "v1").await.unwrap();
    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    let before = writes(&mock);
    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
}

/// If the zone holds several records with our value, removal removes all of them.
#[tokio::test]
async fn nicru_remove_deletes_every_record_with_the_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", REL, "TXT", "v1", Some("30"));
    control.insert_record("example.org", REL, "TXT", "v1", Some("30"));
    control.insert_record("example.org", REL, "TXT", "foreign", Some("30"));
    assert_eq!(remove(&client, "v1").await.unwrap(), RemoveOutcome::Removed);
    assert_eq!(deletes(&mock), 2);
    assert_eq!(control.published_txt(REL), ["foreign"]);
}

/// Two clients sharing a `Context` add to one name at once, the first edit delayed: both values
/// end up published, one created and one appended.
#[tokio::test]
async fn nicru_concurrent_adds_are_serialized() {
    let mock = Arc::new(NicruMock::start(Seed::standard()).await);
    let ctx = context();
    let first = Arc::new(client_with(&mock, &ctx));
    let second = client_with(&mock, &ctx);
    mock.faults()
        .push(Fault::on("PUT", RECORDS).delay(Duration::from_millis(300)));
    let task = {
        let first = first.clone();
        tokio::spawn(async move { add(&*first, "v1").await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let b = add(&second, "v2").await.unwrap();
    let a = task.await.unwrap().unwrap();
    let mut outcomes = [a, b];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [AddOutcome::Appended, AddOutcome::Created]);
    let mut values = mock.control().published_txt(REL);
    values.sort();
    assert_eq!(values, ["v1", "v2"]);
}

/// Two operations on different names of one zone, from two clients sharing a `Context`: the
/// second waits for the first one's commit instead of taking its staged edit for a foreign one
/// (the zone lock), and both values are published.
#[tokio::test]
async fn nicru_parallel_operations_in_one_zone_both_succeed() {
    let mock = Arc::new(NicruMock::start(Seed::standard()).await);
    let ctx = context();
    let first = Arc::new(client_with(&mock, &ctx));
    let second = client_with(&mock, &ctx);
    mock.faults()
        .push(Fault::on("POST", COMMIT).delay(Duration::from_millis(300)));
    let task = {
        let first = first.clone();
        tokio::spawn(async move {
            first
                .add_txt_value(&zone(), &dn("a.example.org"), &txt("AAA"), None)
                .await
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !mock.control().has_changes("example.org") {
        assert!(Instant::now() < deadline, "the first edit was not staged");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let b = second
        .add_txt_value(&zone(), &dn("b.example.org"), &txt("BBB"), None)
        .await
        .unwrap();
    assert_eq!(b, AddOutcome::Created);
    assert_eq!(task.await.unwrap().unwrap(), AddOutcome::Created);
    assert_eq!(mock.control().published_txt("a"), ["AAA"]);
    assert_eq!(mock.control().published_txt("b"), ["BBB"]);
    assert!(!mock.control().has_changes("example.org"));
    // One commit per operation: the second did not commit the first one's edit while the
    // first was still inside its read, edit and commit.
    assert_eq!(commits(&mock), 2);
    let log = mock.log().entries();
    let first_commit = log
        .iter()
        .position(|r| r.method == Method::POST && r.path.ends_with("/commit"))
        .unwrap();
    let staged_b = log
        .iter()
        .position(|r| r.method == Method::PUT && r.body_str().contains("<name>b</name>"))
        .unwrap();
    assert!(first_commit < staged_b, "b was staged before a's commit");
}

/// The client does not cache zones: it looks the zone up on every operation. A zone moved to
/// another service (new service, new zone identifier) between two operations is found there,
/// and a removal never reports `NotPresent` for a value that is there.
#[tokio::test]
async fn nicru_stale_zone_id() {
    let (mock, client) = setup().await;
    add(&client, "v1").await.unwrap();
    mock.control().move_zone("example.org", "newservice");
    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    let path = &mock.log().matching(Some("DELETE"), RECORD)[0].path;
    assert!(path.contains("/services/newservice/"), "{path}");
    assert!(mock.control().published_txt(REL).is_empty());
}

/// The record-level operations are not offered: `Unsupported`, and nothing is sent.
#[tokio::test]
async fn nicru_unsupported_operations_send_nothing() {
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

/// Retry behavior. Staging a record is sent once whatever happens: a 502, a 429, a 401 and error
/// 4097 are the operation's error, and the repeat starts with a read. Staging the deletion of a
/// record by its identifier is idempotent and repeated by the transport after a 5xx, a rate
/// limit or a rejected token (design section 5.3). Each commit request is sent once; the commit
/// is tried three times in all (design section 11.3).
#[tokio::test]
async fn nicru_writes_are_sent_once() {
    let (mock, client) = setup().await;
    for (i, (fault, kind)) in [
        (Fault::on("PUT", RECORDS).status(502), ErrorKind::Transient),
        (
            Fault::on("PUT", RECORDS).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("PUT", RECORDS).status(401), ErrorKind::Transient),
        (
            Fault::on("PUT", RECORDS)
                .respond(200, fail_body("4097", "Access token expired or not found")),
            ErrorKind::Transient,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        mock.faults().push(fault);
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(puts(&mock), i + 1, "{e:?}");
        assert_eq!(commits(&mock), 0, "{e:?}");
        assert!(mock.control().staged_txt(REL).is_empty());
    }
    // A staging that was not applied is applied by the operation's repeat.
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(puts(&mock), 5);

    // A deletion by identifier is idempotent: a 502, a rate limit and a 401 are repeated.
    for (i, fault) in [
        Fault::on("DELETE", RECORD).status(502),
        Fault::on("DELETE", RECORD).rate_limited("1"),
        Fault::on("DELETE", RECORD).status(401),
    ]
    .into_iter()
    .enumerate()
    {
        mock.faults().push(fault);
        assert_eq!(
            remove(&client, "AAA").await.unwrap(),
            RemoveOutcome::RrsetDeleted
        );
        assert_eq!(deletes(&mock), 2 * (i + 1));
        add(&client, "AAA").await.unwrap();
    }

    // A commit that keeps failing is sent three times, once per attempt, and the operation is
    // `Transient`; the staged change waits for the next operation.
    for status in [502, 429, 401] {
        let before = commits(&mock);
        let fault = if status == 429 {
            Fault::on("POST", COMMIT).always().rate_limited("1")
        } else {
            Fault::on("POST", COMMIT).always().status(status)
        };
        mock.faults().push(fault);
        let e = add(&client, "BBB").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient, "{status}: {e:?}");
        assert_eq!(commits(&mock), before + 3, "{status}");
        mock.faults().clear();
        assert_eq!(
            add(&client, "BBB").await.unwrap(),
            AddOutcome::AlreadyPresent,
            "{status}"
        );
        assert_eq!(commits(&mock), before + 4, "{status}");
        assert_eq!(mock.control().published_txt(REL), ["AAA", "BBB"]);
        remove(&client, "BBB").await.unwrap();
    }
}

/// A listing is complete or the operation fails, and nothing is written after it: a zone
/// listing without its data element, a record listing without its zone element, and a record
/// without an identifier are `Protocol` errors.
#[tokio::test]
async fn nicru_truncated_listing_fails() {
    let (mock, client) = setup().await;
    let empty = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<response><status>success</status></response>";
    let no_zone = "<response><status>success</status><data></data></response>";
    let no_id = "<response><status>success</status><data><zone name=\"example.org\" \
                 service=\"zwservice\"><rr><name>_acme-challenge</name><type>TXT</type><txt>\
                 <string>v1</string></txt></rr></zone></data></response>";
    for fault in [
        Fault::on("GET", ZONES).respond(200, empty),
        Fault::on("GET", RECORDS).respond(200, empty),
        Fault::on("GET", RECORDS).respond(200, no_zone),
        Fault::on("GET", RECORDS).respond(200, no_id),
        Fault::on("GET", RECORDS).respond(200, "not xml"),
    ] {
        mock.faults().push(fault);
        let e = remove(&client, "v1").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
        mock.faults()
            .push(Fault::on("GET", RECORDS).respond(200, no_id));
        let e = add(&client, "v1").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
        mock.faults().clear();
    }
    assert_eq!(writes(&mock), 0);
}

/// `check` exchanges the credentials for a new token on every call, even with a valid token
/// cached, so a changed password is reported at once.
#[tokio::test]
async fn nicru_check_exercises_the_credentials() {
    let (mock, client) = setup().await;
    let report = client.check(&[zone(), dn("example.net")]).await.unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones[0].found);
    assert!(report.zones[0].detail.is_none());
    assert!(!report.zones[1].found);
    assert_eq!(mock.control().tokens_issued(), 1);
    client.check(&[]).await.unwrap();
    assert_eq!(mock.control().tokens_issued(), 2);
    mock.control().set_password("changed");
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
}

// ---- Staged changes (design section 11.3) ------------------------------------------------------

/// Values are published by a commit; foreign values stay, and only our records are removed.
#[tokio::test]
async fn nicru_multi_value_commit_and_remove_only_own() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", REL, "TXT", "foreign", Some("300"));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Appended);
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        add(&client, "BBB").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(control.published_txt(REL), ["foreign", "AAA", "BBB"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.published_txt(REL), ["foreign"]);
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::NotPresent
    );
}

/// A zone with staged changes this process did not make is refused for an add and a removal,
/// before the record listing, and nothing is staged or committed. `check` reports the zone
/// found, with a detail.
#[tokio::test]
async fn nicru_refuses_foreign_uncommitted_changes() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.stage_record("example.org", "foreign-edit", "TXT", "pending", None);
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(!e.is_retryable());
    // Before the listing: with staged changes it may not show what is published, and "not
    // there" could be a false `NotPresent`.
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), RECORDS), 0);
    assert_eq!(writes(&mock), 0);
    assert!(control.published_txt("foreign-edit").is_empty());
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    let detail = report.zones[0].detail.as_ref().unwrap();
    assert!(detail.as_str().contains("did not make"), "{detail}");
}

/// A commit of our own edit that fails is tried again at once; one that fails three times
/// leaves the edit staged and the zone marked as ours, and the operation is retryable. The next
/// operation commits the edit instead of refusing the zone as one with foreign changes.
#[tokio::test]
async fn nicru_own_uncommitted_change_is_committed_not_refused() {
    let (mock, client) = setup().await;
    let control = mock.control();
    mock.faults().push(Fault::on("POST", COMMIT).status(503));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(control.published_txt(REL), ["AAA"]);
    assert_eq!(commits(&mock), 2);

    mock.faults()
        .push(Fault::on("POST", COMMIT).times(3).status(503));
    let e = add(&client, "BBB").await.unwrap_err();
    assert!(e.is_retryable(), "{e:?}");
    assert!(control.has_changes("example.org"));
    assert_eq!(control.published_txt(REL), ["AAA"]);
    let report = client.check(&[zone()]).await.unwrap();
    let detail = report.zones[0].detail.as_ref().unwrap();
    assert!(detail.as_str().contains("of this process"), "{detail}");
    assert_eq!(
        add(&client, "BBB").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(control.published_txt(REL), ["AAA", "BBB"]);
    assert!(!control.has_changes("example.org"));

    // The same for a removal.
    mock.faults()
        .push(Fault::on("POST", COMMIT).times(3).status(503));
    assert!(remove(&client, "AAA").await.unwrap_err().is_retryable());
    assert_eq!(control.published_txt(REL), ["AAA", "BBB"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(control.published_txt(REL), ["BBB"]);
}

/// An operation dropped between its edit and its commit leaves the zone marked: the next
/// operation in the same `Context` commits the edit (design section 3.2). A client of another
/// `Context`, as after a restart, does not know the edit and refuses the zone.
#[tokio::test]
async fn nicru_dropped_operation_is_finished_by_the_next() {
    let (mock, client) = setup().await;
    let control = mock.control();
    mock.faults().push(
        Fault::on("POST", COMMIT)
            .delay(Duration::from_secs(2))
            .status(503),
    );
    let dropped = tokio::time::timeout(Duration::from_millis(300), add(&client, "AAA")).await;
    assert!(dropped.is_err(), "the operation was not dropped");
    assert_eq!(control.staged_txt(REL), ["AAA"]);
    assert!(control.published_txt(REL).is_empty());
    assert!(control.has_changes("example.org"));

    let other = client_with(&mock, &context());
    let e = add(&other, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");

    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(control.published_txt(REL), ["AAA"]);
    assert!(!control.has_changes("example.org"));
}

/// A zone found without staged changes clears a stale mark: an edit that was refused, and so
/// staged nothing, must not make a later foreign edit look like ours.
#[tokio::test]
async fn nicru_stale_mark_does_not_cover_foreign_changes() {
    let (mock, client) = setup().await;
    let control = mock.control();
    mock.faults()
        .push(Fault::on("PUT", RECORDS).respond(200, fail_body("4004", "refused")));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(!control.has_changes("example.org"));
    // A clean zone clears the mark ...
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    // ... so a foreign edit staged afterwards is refused, not committed.
    control.stage_record("example.org", "foreign-edit", "TXT", "pending", None);
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(commits(&mock), 0);
    assert!(control.published_txt("foreign-edit").is_empty());
}

// ---- Tokens ------------------------------------------------------------------------------------

/// An expired token (error 4097 on a listing) is replaced and the listing repeated once; an
/// HTTP 401 takes the transport's path. A wrong password is `Auth` without the password in the
/// text, and an unknown zone is `ZoneNotFound`.
#[tokio::test]
async fn nicru_token_expired_reauth_and_bad_password() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "AAA").await.unwrap();
    assert_eq!(control.tokens_issued(), 1);
    control.expire_tokens();
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    assert_eq!(control.tokens_issued(), 2);
    mock.faults().push(Fault::on("GET", ZONES).status(401));
    assert_eq!(
        add(&client, "BBB").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(control.tokens_issued(), 3);

    // The token expires between the read and the staging: not repeated, retryable.
    let hook = control.clone();
    mock.faults()
        .push(Fault::on("PUT", RECORDS).run(move || hook.expire_tokens()));
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(add(&client, "CCC").await.unwrap(), AddOutcome::Appended);

    // A token that is refused as soon as it is issued is `Auth`.
    mock.faults().push(
        Fault::on("GET", ZONES)
            .times(2)
            .respond(200, fail_body("4097", "Access token expired or not found")),
    );
    let e = add(&client, "DDD").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");

    let seed = Seed::standard();
    let bad = client_for(&mock, &seed, "wrong-canary-2", &context());
    let e = add(&bad, "A").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(!format!("{e} {e:?} {bad:?}").contains("wrong-canary-2"));

    let e = client
        .add_txt_value(&dn("example.net"), &dn("x.example.net"), &txt("A"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ZoneNotFound, "{e:?}");
}

// ---- Zones -------------------------------------------------------------------------------------

/// Every zone of a DNS-master service of the contract, sorted, each once; zones of a Secondary
/// service are left out. Wrong credentials are an error.
#[tokio::test]
async fn nicru_list_zones() {
    let (mock, client) = setup().await;
    mock.control()
        .insert_zone("example.net", "otherservice", true);
    mock.control()
        .insert_zone("secondary.example", "secondaryservice", false);
    let zones: Vec<DomainName> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name)
        .collect();
    assert_eq!(zones, [dn("example.net"), dn("example.org")]);
    let seed = Seed::standard();
    let bad = client_for(&mock, &seed, "wrong", &context());
    assert_eq!(bad.list_zones().await.unwrap_err().kind(), ErrorKind::Auth);
}

/// A zone of a Secondary service cannot be written: `Rejected`, nothing staged, and `check`
/// reports it not found with a detail. A zone listed under two DNS-master services likewise.
#[tokio::test]
async fn nicru_secondary_and_ambiguous_zones_are_refused() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_zone("secondary.example", "secondaryservice", false);
    let e = client
        .add_txt_value(
            &dn("secondary.example"),
            &dn("_acme-challenge.secondary.example"),
            &txt("v1"),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    control.insert_zone("example.org", "otherservice", true);
    let e = add(&client, "v1").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(writes(&mock), 0);
    let report = client
        .check(&[dn("secondary.example"), zone()])
        .await
        .unwrap();
    for check in &report.zones {
        assert!(!check.found);
        assert!(check.detail.is_some());
    }
}

// ---- Requests ----------------------------------------------------------------------------------

/// The token request is the documented password grant, form-encoded, with the application's
/// credentials in the body and no `Authorization` header; the API calls carry the token as a
/// bearer token and XML.
#[tokio::test]
async fn nicru_requests_have_the_documented_shape() {
    let (mock, client) = setup().await;
    add(&client, "v1").await.unwrap();
    let token = &mock.log().matching(Some("POST"), TOKEN)[0];
    assert_eq!(
        token.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert!(token.header("authorization").is_none());
    let body = token.body_str();
    for pair in [
        "grant_type=password",
        "username=123%2FNIC-REG",
        "password=test-only-password",
        "client_id=0123456789abcdef0123456789abcdef",
        "client_secret=test-only-client-secret",
        "scope=.%2B%3A%2Fdns-master%2F.%2B",
    ] {
        assert!(body.split('&').any(|p| p == pair), "{pair} in {body}");
    }

    let put = &mock.log().matching(Some("PUT"), RECORDS)[0];
    assert_eq!(
        put.path,
        "/dns-master/services/zwservice/zones/example.org/records"
    );
    assert_eq!(put.header("content-type"), Some("text/xml"));
    assert_eq!(put.header("accept"), Some("text/xml"));
    assert_eq!(put.header("authorization"), Some("Bearer nic-test-token-1"));
    let body = put.body_str();
    assert!(body.starts_with("<?xml"), "{body}");
    for part in [
        "<request><rr-list><rr>",
        "<name>_acme-challenge</name>",
        "<ttl>30</ttl>",
        "<type>TXT</type>",
        "<txt><string>v1</string></txt>",
    ] {
        assert!(body.contains(part), "{part} in {body}");
    }
    let commit = &mock.log().matching(Some("POST"), COMMIT)[0];
    assert_eq!(
        commit.path,
        "/dns-master/services/zwservice/zones/example.org/commit"
    );
    assert!(commit.body.is_empty());
}

/// TTL: a new rrset gets the caller's TTL or the configured one; a value added to an existing
/// set gets the set's smallest TTL, or none when the set states none; a TTL outside the range
/// is refused before any request. The apex is written as `@`.
#[tokio::test]
async fn nicru_ttl_and_apex() {
    let (mock, client) = setup().await;
    let control = mock.control();
    client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("v1"),
            Some(Ttl::from_secs(120).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(control.published(REL, "TXT")[0].ttl.as_deref(), Some("120"));

    control.insert_record("example.org", "set", "TXT", "foreign", Some("300"));
    control.insert_record("example.org", "set", "TXT", "foreign2", Some("600"));
    client
        .add_txt_value(&zone(), &dn("set.example.org"), &txt("v1"), None)
        .await
        .unwrap();
    let ours = control
        .published("set", "TXT")
        .into_iter()
        .find(|r| r.value() == "v1")
        .unwrap();
    assert_eq!(ours.ttl.as_deref(), Some("300"));

    control.insert_record("example.org", "nottl", "TXT", "foreign", None);
    client
        .add_txt_value(&zone(), &dn("nottl.example.org"), &txt("v1"), None)
        .await
        .unwrap();
    let ours = control
        .published("nottl", "TXT")
        .into_iter()
        .find(|r| r.value() == "v1")
        .unwrap();
    assert_eq!(ours.ttl, None);

    client
        .add_txt_value(&zone(), &zone(), &txt("apex"), None)
        .await
        .unwrap();
    assert_eq!(control.published_txt("@"), ["apex"]);

    let before = mock.log().len();
    let e = client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("v9"),
            Some(Ttl::from_secs(10).unwrap()),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    let e = add(&client, "with space").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(mock.log().len(), before);
}

/// Requests are spaced by `min_request_interval_ms`.
#[tokio::test]
async fn nicru_requests_are_paced() {
    let mock = NicruMock::start(Seed::standard()).await;
    let seed = Seed::standard();
    let mut config = settings(&mock, &seed);
    config.min_request_interval_ms = 200;
    let client = Nicru::new(
        config,
        credentials(&seed.password, &seed.client_id, &seed.client_secret),
        &context(),
    )
    .unwrap();
    let start = Instant::now();
    // The token request and the zone listing.
    client.check(&[zone()]).await.unwrap();
    assert!(start.elapsed() >= Duration::from_millis(200));
}

// ---- Configuration -----------------------------------------------------------------------------

/// `from_json` builds the client from the documented keys; a missing required key, an unknown
/// key, an invalid value and malformed credentials are `Config` errors that quote no value.
#[test]
fn nicru_configuration() {
    let ctx = context();
    let build = |settings: &str, credentials: &str| {
        AnyProvider::from_json(
            ProviderId::Nicru,
            settings,
            &SecretString::from(credentials.to_owned()),
            &ctx,
        )
    };
    let creds = r#"{"password":"pw-canary-1","client_id":"id","client_secret":"secret-canary-2"}"#;
    let ok = r#"{"username":"123/NIC-REG","base_url":"http://127.0.0.1:9/dns-master","token_url":"http://127.0.0.1:9/oauth/token"}"#;
    let client = build(ok, creds).unwrap();
    let debug = format!("{client:?}");
    assert!(debug.contains("123/NIC-REG"), "{debug}");
    assert!(!debug.contains("canary"), "{debug}");

    let e = build(r#"{"base_url":"http://127.0.0.1:9"}"#, creds).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
    assert!(e.to_string().contains("username"), "{e}");
    for bad in [
        r#"{"username":"u","base_url":"http://127.0.0.1:9","token_url":"http://127.0.0.1:9","unknown":"x-canary"}"#,
        r#"{"username":"u","base_url":"http://127.0.0.1:9","token_url":"http://127.0.0.1:9","ttl":10}"#,
        r#"{"username":"u","base_url":"http://127.0.0.1:9","token_url":"http://127.0.0.1:9","min_request_interval_ms":70000}"#,
        r#"{"username":"u","base_url":"http://127.0.0.1:9","token_url":"http://127.0.0.1:9","scope":""}"#,
        r#"{"username":"","base_url":"http://127.0.0.1:9","token_url":"http://127.0.0.1:9"}"#,
        r#"{"username":"u","base_url":"http://user:x-canary@127.0.0.1:9","token_url":"http://127.0.0.1:9"}"#,
        r#"{"username":"u","base_url":"http://127.0.0.1:9"}"#,
    ] {
        let e = build(bad, creds).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{bad}");
        assert!(!e.to_string().contains("canary"), "{e}");
    }
    for bad in [
        r#"{"password":"pw-canary-1","client_id":"id"}"#,
        r#"{"password":"","client_id":"id","client_secret":"s"}"#,
        r#"{"password":"pw-canary-1","client_id":"","client_secret":"s"}"#,
        r#"["pw-canary-1"]"#,
    ] {
        let e = build(ok, bad).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{bad}");
        assert!(!e.to_string().contains("canary"), "{e}");
    }
}

/// The capabilities say what the client does: the value operations, `list_zones`, nothing at
/// record level, one record per value, the slow publication as the propagation timeout.
#[test]
fn nicru_capabilities_match_the_client() {
    use zonewright::{Operation, ValueGuarantee};
    let meta = ProviderId::Nicru.meta();
    let caps = &meta.capabilities;
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
    assert_eq!(
        meta.default_propagation_timeout,
        Some(Duration::from_secs(1200))
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

/// Adds and removes two values under a generated label in the zone the maintainer names, and
/// removes exactly the values it added afterwards, also when the body failed. The zone must
/// have no staged changes when the test starts.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_nicru_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_NICRU_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_NICRU_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_NICRU_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::Nicru,
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
            assert!(report.credentials_verified);
            assert!(report.zones[0].found, "{report:?}");
            assert!(report.zones[0].detail.is_none(), "{report:?}");
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
