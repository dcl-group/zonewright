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

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use zonewright::providers::nicru::{Nicru, NicruConfig, NicruCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl, SetOutcome,
    SkipReason, Txt,
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
const ROLLBACK: &str = "/dns-master/services/*/zones/*/rollback";

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

/// What the shared echo of one dialect does in the current round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Every request is echoed, the token request included when the client's token URL is one
    /// the echo does not serve as its token endpoint.
    All,
    /// The listings are answered; the edits are echoed.
    Edits,
    /// The listings and the edits are answered; the commit is echoed.
    Commit,
    /// The listings and the staging of a record are answered; the staging of a deletion and the
    /// rollback are echoed.
    Rollback,
}

/// The state of the shared echo of one dialect: the status of the echoed answers, the stage,
/// whether the listings hold our values, and whether an edit was answered (the zone then lists
/// staged changes).
#[derive(Clone, Copy, Debug)]
struct Scenario {
    status: StatusCode,
    stage: Stage,
    ours: bool,
    staged: bool,
}

type SharedScenario = Arc<Mutex<Scenario>>;

/// The renderer of the shared echo: the zone and record listings as the API answers them (the
/// zone `example.org`, a foreign TXT value and, with `ours`, the TXT value `v1` and the A record
/// `192.0.2.1` at `www`), edits, commit and rollback as the stage says, and everything else
/// echoed by `errors` with the scenario's status.
fn scenario_render(errors: Render, scenario: SharedScenario) -> Render {
    Arc::new(move |e: &Echoed| {
        let mut sc = scenario.lock().unwrap();
        let mut echoed = e.clone();
        echoed.status = sc.status;
        if !e.path.starts_with("/dns-master") || sc.stage == Stage::All {
            return errors(&echoed);
        }
        let zone = format!(
            "<zone admin=\"x\" enable=\"true\" has-changes=\"{}\" has-primary=\"true\" id=\"1\" \
             idn-name=\"example.org\" name=\"example.org\" service=\"zwservice\"",
            sc.staged
        );
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
            if sc.ours {
                rrs.push_str(
                    "<rr id=\"1002\"><name>_acme-challenge</name><ttl>300</ttl><type>TXT</type>\
                     <txt><string>v1</string></txt></rr>\
                     <rr id=\"1003\"><name>www</name><ttl>300</ttl><type>A</type>\
                     <a>192.0.2.1</a></rr>",
                );
            }
            return xml_ok(format!(
                "<response><status>success</status><data>{zone}>{rrs}</zone></data></response>"
            ));
        }
        let answered = match sc.stage {
            Stage::All | Stage::Edits => false,
            Stage::Commit => e.method == Method::PUT || e.method == Method::DELETE,
            Stage::Rollback => e.method == Method::PUT,
        };
        if answered {
            sc.staged = true;
            return xml_ok("<response><status>success</status></response>".to_owned());
        }
        errors(&echoed)
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

fn echo_client(echo: &EchoServer, token_url: &str, ctx: &Context) -> Nicru {
    let mut config = NicruConfig::new(CANARY_USER.to_owned());
    config.base_url = echo.url("/dns-master");
    config.token_url = token_url.to_owned();
    config.min_request_interval_ms = 0;
    Nicru::new(
        config,
        credentials(CANARY_PASSWORD, CANARY_KEY, CANARY_TOKEN),
        ctx,
    )
    .unwrap()
}

/// What an echo round does for its write.
#[derive(Clone, Copy, Debug)]
enum Write {
    Add,
    Remove,
    /// `set_rrset` of the A rrset at `www` to `192.0.2.2`.
    Set,
    /// `delete_rrset` of the A rrset at `www`.
    Delete,
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
    let www = dn("www.example.org");
    let result = match write {
        Write::Add => add(client, "v1").await.map(|o| format!("{o:?}")),
        Write::Remove => remove(client, "v1").await.map(|o| format!("{o:?}")),
        Write::Set => client
            .set_rrset(
                &zone(),
                &rr("www.example.org", RecordType::A, None, &["192.0.2.2"]),
                Expect::Any,
            )
            .await
            .map(|o| format!("{o:?}")),
        Write::Delete => client
            .delete_rrset(&zone(), &www, RecordType::A, Expect::Any)
            .await
            .map(|o| format!("{o:?}")),
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

/// All rounds of one dialect against one echo server, whose scenario each round sets, with
/// clients on one `Context`, so that they share its pooled connection (`tests/common/echo.rs`).
/// Every round starts with a zone the listings show without staged changes, so a mark a
/// failed round leaves in the context is cleared by the next round's read.
async fn echo_dialect(dialect: Dialect) {
    let ctx = context();
    let scenario = Arc::new(Mutex::new(Scenario {
        status: StatusCode::BAD_REQUEST,
        stage: Stage::All,
        ours: false,
        staged: false,
    }));
    let echo = dialect
        .echo(400)
        .render(scenario_render(dialect.render.clone(), scenario.clone()))
        .start()
        .await;
    let set = |status: u16, stage: Stage, ours: bool| {
        *scenario.lock().unwrap() = Scenario {
            status: StatusCode::from_u16(status).unwrap(),
            stage,
            ours,
            staged: false,
        };
    };
    let tag = |what: &str, status: u16| {
        format!("{} {:?} {status} {what}", dialect.name, dialect.spelling)
    };
    let count = |method: &str, path: &str| echo.log().count(Some(method), path);

    // The token request is echoed: the token path is one the echo does not serve.
    for status in [400, 401] {
        let label = tag("token", status);
        set(status, Stage::All, false);
        let before = count("POST", TOKEN);
        echo_round(
            &label,
            &echo_client(&echo, &echo.url(TOKEN), &ctx),
            Write::Add,
        )
        .await;
        assert!(
            count("POST", TOKEN) > before,
            "{label}: the token request did not reach the echo"
        );
    }

    // The listings are echoed.
    for status in [400, 401, 403] {
        let label = tag("read", status);
        set(status, Stage::All, false);
        let (tokens, zones) = (echo.token_requests(), count("GET", ZONES));
        echo_round(
            &label,
            &echo_client(&echo, &echo.token_url(), &ctx),
            Write::Add,
        )
        .await;
        assert!(
            echo.token_requests() > tokens,
            "{label}: no token was requested"
        );
        assert!(
            count("GET", ZONES) > zones,
            "{label}: the API was not reached"
        );
    }

    // The edits are echoed: the staging of a TXT record and of its deletion, and of a record
    // and a deletion at record level.
    for status in [400, 403, 422, 500] {
        for write in [Write::Add, Write::Remove, Write::Set, Write::Delete] {
            let label = tag(&format!("edit {write:?}"), status);
            let ours = matches!(write, Write::Remove | Write::Delete);
            set(status, Stage::Edits, ours);
            let (method, path) = match write {
                Write::Add | Write::Set => ("PUT", RECORDS),
                Write::Remove | Write::Delete => ("DELETE", RECORD),
            };
            let before = count(method, path);
            echo_round(&label, &echo_client(&echo, &echo.token_url(), &ctx), write).await;
            assert!(
                count(method, path) > before,
                "{label}: the edit did not reach the echo"
            );
        }
    }

    // The commit and the rollback carry no credential but the token, whose spellings the rounds
    // above cover: once per renderer.
    if dialect.spelling != echo_mock::Spelling::Verbatim {
        return;
    }
    for write in [Write::Add, Write::Set] {
        let label = tag(&format!("commit {write:?}"), 400);
        set(400, Stage::Commit, false);
        let before = count("POST", COMMIT);
        echo_round(&label, &echo_client(&echo, &echo.token_url(), &ctx), write).await;
        assert_eq!(
            count("POST", COMMIT),
            before + 3,
            "{label}: the commit did not reach the echo three times"
        );
    }
    let label = tag("rollback Set", 400);
    set(400, Stage::Rollback, true);
    let before = count("POST", ROLLBACK);
    echo_round(
        &label,
        &echo_client(&echo, &echo.token_url(), &ctx),
        Write::Set,
    )
    .await;
    assert_eq!(
        count("POST", ROLLBACK),
        before + 3,
        "{label}: the rollback did not reach the echo three times"
    );
}

/// `check` and a write against an echo that quotes every request back, for every dialect and
/// the API's own failure envelope: no canary and no issued token in any error,
/// `ZoneCheck::detail` or `Debug`, and the write's error shows the redaction. Every request
/// kind reaches the echo: the token request (its form body carries all four credentials), the
/// listings, the staging of a record and of a deletion (TXT value operations and record level),
/// the commit and the rollback. One echo server per dialect; the dialects run in parallel, since
/// the redaction checks dominate the time.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn nicru_secret_echo() {
    let mut all = dialects();
    all.push(Dialect {
        name: "nicru_envelope",
        spelling: echo_mock::Spelling::Verbatim,
        render: nicru_envelope(),
    });
    let tasks: Vec<_> = all
        .into_iter()
        .map(|dialect| tokio::spawn(echo_dialect(dialect)))
        .collect();
    for task in tasks {
        if let Err(e) = task.await {
            std::panic::resume_unwind(e.into_panic());
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
        let set = RrSet::new(
            name.clone(),
            RecordType::TXT,
            None,
            [value.to_data().unwrap()],
        )
        .unwrap();
        let e = client
            .set_rrset(&zone, &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NameOutsideZone, "{e:?}");
        let e = client
            .delete_rrset(&zone, &name, RecordType::TXT, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NameOutsideZone, "{e:?}");
        let e = client
            .get_rrset(&zone, &name, RecordType::TXT)
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

/// Every operation is offered; what the client cannot do is refused before any request, token
/// requests included: a type outside `record_types` (`UnsupportedRecordType`, for reads and
/// writes), SOA and other read-only writes, the apex NS set, a TTL outside the range, an
/// expectation about another rrset and `Expect::Absent` for a delete (`InvalidInput`).
#[tokio::test]
async fn nicru_unsupported_operations_send_nothing() {
    let (mock, client) = setup().await;
    let caa: RecordType = "CAA".parse().unwrap();
    let hinfo: RecordType = "HINFO".parse().unwrap();
    for rtype in [caa, hinfo, RecordType::TLSA, RecordType::SSHFP] {
        let e = client.get_rrset(&zone(), &name(), rtype).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
        let e = client
            .delete_rrset(&zone(), &name(), rtype, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{rtype}: {e:?}");
    }
    let caa_set = RrSet::new(
        name(),
        caa,
        None,
        [RecordData::parse(caa, "0 issue \"ca.example.net\"").unwrap()],
    )
    .unwrap();
    let soa = rr(
        "example.org",
        RecordType::SOA,
        None,
        &["ns1.example.net. admin.example.org. 1 7200 3600 1209600 300"],
    );
    for set in [&caa_set, &soa] {
        let e = client
            .set_rrset(&zone(), set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");
    }
    let e = client
        .delete_rrset(&zone(), &zone(), RecordType::SOA, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");

    let apex_ns = rr("example.org", RecordType::NS, None, &["ns1.example.net."]);
    let www = rr("www.example.org", RecordType::A, None, &["192.0.2.1"]);
    let other = rr("other.example.org", RecordType::A, None, &["192.0.2.1"]);
    for (set, expect) in [
        (&apex_ns, Expect::Any),
        (
            &rr("www.example.org", RecordType::A, Some(29), &["192.0.2.1"]),
            Expect::Any,
        ),
        (
            &rr(
                "www.example.org",
                RecordType::A,
                Some(86_401),
                &["192.0.2.1"],
            ),
            Expect::Any,
        ),
        (&www, Expect::Matches(&other)),
    ] {
        let e = client.set_rrset(&zone(), set, expect).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{set:?}: {e:?}");
    }
    for (name, rtype, expect) in [
        (zone(), RecordType::NS, Expect::Any),
        (dn("www.example.org"), RecordType::A, Expect::Absent),
        (
            dn("www.example.org"),
            RecordType::A,
            Expect::Matches(&other),
        ),
    ] {
        let e = client
            .delete_rrset(&zone(), &name, rtype, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{name} {rtype}: {e:?}");
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

    // Staging a deletion is sent once too: the API documents no answer for a record that is
    // already deleted, so a repeat could not be read.
    for (i, (fault, kind)) in [
        (
            Fault::on("DELETE", RECORD).status(502),
            ErrorKind::Transient,
        ),
        (
            Fault::on("DELETE", RECORD).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (
            Fault::on("DELETE", RECORD).status(401),
            ErrorKind::Transient,
        ),
        (
            Fault::on("DELETE", RECORD)
                .respond(200, fail_body("4097", "Access token expired or not found")),
            ErrorKind::Transient,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        mock.faults().push(fault);
        let e = remove(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(deletes(&mock), i + 1, "{e:?}");
        assert_eq!(mock.control().published_txt(REL), ["AAA"]);
    }
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(deletes(&mock), 5);
    add(&client, "AAA").await.unwrap();

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

/// A foreign edit staged between the zone lookup and the record listing of a TXT value
/// operation, on a zone that was clean when it was looked up, is seen in the listing's
/// `has-changes`: the add and the removal are `Rejected`, nothing is staged, committed or rolled
/// back, and the foreign edit stays staged.
#[tokio::test]
async fn nicru_txt_refuses_changes_staged_after_the_zone_lookup() {
    for adding in [true, false] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.insert_record("example.org", REL, "TXT", "AAA", None);
        let hook = control.clone();
        // A hook runs before the request reaches the mock, so the zone lookup answered clean
        // and only the record listing sees the staged edit.
        mock.faults().push(
            Fault::on("GET", RECORDS)
                .run(move || {
                    hook.stage_record("example.org", "late", "TXT", "pending", None);
                })
                .pass(),
        );
        let e = if adding {
            add(&client, "BBB").await.map(drop).unwrap_err()
        } else {
            remove(&client, "AAA").await.map(drop).unwrap_err()
        };
        assert_eq!(e.kind(), ErrorKind::Rejected, "{adding}: {e:?}");
        assert!(e.to_string().contains("did not make"), "{adding}: {e}");
        assert_eq!(mock.log().count(Some("GET"), RECORDS), 1, "{adding}");
        assert_eq!(writes(&mock) + rollbacks(&mock), 0, "{adding}");
        assert_eq!(control.staged_txt(REL), ["AAA"], "{adding}");
        assert_eq!(control.published_txt(REL), ["AAA"], "{adding}");
        assert_eq!(control.staged_txt("late"), ["pending"], "{adding}");
        assert!(control.published_txt("late").is_empty(), "{adding}");
        assert!(control.has_changes("example.org"), "{adding}");
    }
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

/// An operation dropped while its commit is in flight leaves the zone with an unconfirmed mark:
/// whether the commit was applied is unknown, so the staged changes cannot be shown to be this
/// process's. Every later operation refuses the zone, in this `Context` as in another one (as
/// after a restart), and nothing is committed; once the staged changes are committed by hand,
/// the next operation clears the mark and goes on, and a foreign edit staged after that is
/// refused, not taken for ours.
#[tokio::test]
async fn nicru_dropped_operation_leaves_the_zone_refused() {
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
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(e.to_string().contains("cannot show"), "{e}");
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let report = client.check(&[zone()]).await.unwrap();
    let detail = report.zones[0].detail.as_ref().unwrap();
    assert!(detail.as_str().contains("cannot show"), "{detail}");
    assert_eq!(commits(&mock), 1);
    assert!(control.published_txt(REL).is_empty());

    // Committed by hand: the zone is clean, the mark goes, the operation goes on.
    control.commit("example.org");
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    control.stage_record("example.org", "foreign-edit", "TXT", "pending", None);
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(commits(&mock), 1);
    assert!(control.published_txt("foreign-edit").is_empty());
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

/// A refused edit clears the mark at once, without looking at the zone: when someone else
/// stages an edit while the refused request is answered, neither the failed operation nor the
/// next one commits it; the next one refuses the zone. Covers a staging and a deletion, each
/// refused with a `fail` answer and with an HTTP refusal.
#[tokio::test]
async fn nicru_refused_edit_clears_the_mark() {
    for (method, path, fault_status) in [
        ("PUT", RECORDS, None),
        ("PUT", RECORDS, Some(429)),
        ("DELETE", RECORD, None),
        ("DELETE", RECORD, Some(403)),
    ] {
        let (mock, client) = setup().await;
        let control = mock.control();
        if method == "DELETE" {
            add(&client, "AAA").await.unwrap();
        }
        let before = commits(&mock);
        let hook = control.clone();
        // Another writer stages an edit while the refused request is in flight.
        let fault = Fault::on(method, path).run(move || {
            hook.stage_record("example.org", "foreign-edit", "TXT", "pending", None);
        });
        let fault = match fault_status {
            None => fault.respond(200, fail_body("4004", "refused")),
            Some(429) => fault.rate_limited("1"),
            Some(status) => fault.status(status),
        };
        mock.faults().push(fault);
        let result = if method == "PUT" {
            add(&client, "AAA").await.map(drop)
        } else {
            remove(&client, "AAA").await.map(drop)
        };
        let label = format!("{method} {fault_status:?}");
        assert!(result.is_err(), "{label}");
        assert_eq!(commits(&mock), before, "{label}");
        let e = add(&client, "BBB").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{label}: {e:?}");
        assert_eq!(commits(&mock), before, "{label}");
        assert!(control.published_txt("foreign-edit").is_empty(), "{label}");
    }
}

/// An edit whose outcome is unknown (a 502, or an answer the client cannot read) is settled
/// at once by listing the zone again: staged changes there are this edit and are committed;
/// a clean zone clears the mark, so a later foreign edit is refused.
#[tokio::test]
async fn nicru_unknown_edit_outcome_is_settled() {
    // Applied, answer lost: the staging is committed by the failed operation itself.
    let (mock, client) = setup().await;
    let control = mock.control();
    let hook = control.clone();
    mock.faults().push(
        Fault::on("PUT", RECORDS)
            .run(move || {
                hook.stage_record("example.org", REL, "TXT", "AAA", Some("30"));
            })
            .status(502),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(control.published_txt(REL), ["AAA"]);
    assert!(!control.has_changes("example.org"));
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );

    // The same for a deletion.
    let hook = control.clone();
    mock.faults().push(
        Fault::on("DELETE", RECORD)
            .run(move || hook.stage_txt_deletion(REL, "AAA"))
            .status(502),
    );
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(control.published_txt(REL).is_empty());
    assert!(!control.has_changes("example.org"));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );

    // Not applied: the clean zone clears the mark, and a foreign edit staged afterwards is
    // refused. An answer with status `success` and an HTTP error status is unreadable, and
    // takes the same path.
    for fault in [
        Fault::on("PUT", RECORDS).status(502),
        Fault::on("PUT", RECORDS).respond(400, "<response><status>success</status></response>"),
    ] {
        let (mock, client) = setup().await;
        let control = mock.control();
        mock.faults().push(fault);
        let e = add(&client, "AAA").await.unwrap_err();
        assert!(
            matches!(e.kind(), ErrorKind::Transient | ErrorKind::Protocol),
            "{e:?}"
        );
        control.stage_record("example.org", "foreign-edit", "TXT", "pending", None);
        let e = add(&client, "BBB").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
        assert_eq!(commits(&mock), 0);
        assert!(control.published_txt("foreign-edit").is_empty());
    }
}

/// A successful commit clears the mark: a foreign edit staged after a completed operation is
/// refused by the next one, with no clean read in between.
#[tokio::test]
async fn nicru_successful_commit_clears_the_mark() {
    let (mock, client) = setup().await;
    let control = mock.control();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    control.stage_record("example.org", "foreign-edit", "TXT", "pending", None);
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(commits(&mock), 1);
    assert!(control.published_txt("foreign-edit").is_empty());
}

/// A zone whose staged-change flag is missing or not `true` or `false` is an unexpected
/// answer, never "nothing staged".
#[tokio::test]
async fn nicru_has_changes_must_be_stated() {
    let (mock, client) = setup().await;
    for flag in ["", " has-changes=\"yes\""] {
        let body = format!(
            "<response><status>success</status><data><zone name=\"example.org\" \
             service=\"zwservice\" has-primary=\"true\"{flag}/></data></response>"
        );
        mock.faults()
            .push(Fault::on("GET", ZONES).respond(200, body.clone()));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{flag}: {e:?}");
        mock.faults()
            .push(Fault::on("GET", ZONES).respond(200, body));
        let e = client.check(&[zone()]).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{flag}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);
}

/// The commit attempts of one operation are spaced: three failing attempts take at least the
/// two pauses (200 ms and 400 ms).
#[tokio::test]
async fn nicru_commit_attempts_are_spaced() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("POST", COMMIT).times(3).status(503));
    let start = Instant::now();
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(
        start.elapsed() >= Duration::from_millis(600),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(commits(&mock), 3);
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
            Some(RrsetTtl::from_secs(120).unwrap()),
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
            Some(RrsetTtl::from_secs(10).unwrap()),
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

/// The capabilities say what the client does: every operation, the types whose element the
/// documentation shows, SOA read only, one record per value, one commit per replacement, the
/// slow publication as the propagation timeout.
#[test]
fn nicru_capabilities_match_the_client() {
    use zonewright::{Operation, Preconditions, TtlSupport, ValueGuarantee};
    let meta = ProviderId::Nicru.meta();
    let caps = &meta.capabilities;
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
        RecordType::DNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::PTR,
        RecordType::SRV,
        RecordType::TXT,
    ] {
        assert!(caps.can_write(rtype), "{rtype}");
    }
    assert!(caps.can_read(RecordType::SOA));
    assert!(!caps.can_write(RecordType::SOA));
    for rtype in ["CAA", "HINFO", "NAPTR", "RP", "TLSA"] {
        assert!(!caps.can_read(rtype.parse().unwrap()), "{rtype}");
    }
    assert_eq!(caps.preconditions, Preconditions::ReadThenWrite);
    assert!(!caps.atomic_rrset_write);
    assert_eq!(
        caps.ttl,
        TtlSupport::PerRecord {
            min: 30,
            max: 86_400
        }
    );
    assert_eq!(caps.txt_values, ValueGuarantee::PerValue);
    assert!(caps.txt_plain_only);
    assert_eq!(
        meta.default_propagation_timeout,
        Some(Duration::from_secs(1200))
    );
}

// ---- Record level ------------------------------------------------------------------------------

/// The TTL a new set gets when the caller gives none: the configured default.
const DEFAULT_TTL: u32 = 30;

/// A record value in canonical text.
fn rdata(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap()
}

/// An rrset at `owner`.
fn rr(owner: &str, rtype: RecordType, ttl: Option<u32>, texts: &[&str]) -> RrSet {
    RrSet::new(
        dn(owner),
        rtype,
        ttl.map(|t| RrsetTtl::from_secs(t).unwrap()),
        texts.iter().map(|t| rdata(rtype, t)),
    )
    .unwrap()
}

/// `set` with the configured default TTL when it has none.
fn with_default_ttl(set: &RrSet) -> RrSet {
    set.clone().with_ttl(
        set.ttl()
            .or(Some(RrsetTtl::from_secs(DEFAULT_TTL).unwrap())),
    )
}

/// The zone's listing shows every record at the name, so a CNAME next to other data, or other
/// data next to a CNAME, is refused after the read and before any edit or commit (RFC 1034
/// section 3.6.2). Data at other names does not count.
#[tokio::test]
async fn nicru_cname_next_to_other_data_is_refused() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", "www", "A", "192.0.2.1", None);
    control.insert_record("example.org", "alias", "CNAME", "target.example.net.", None);
    let before = control.published_all("example.org");

    let cname = rr(
        "www.example.org",
        RecordType::CNAME,
        None,
        &["target.example.net."],
    );
    let e = client
        .set_rrset(&zone(), &cname, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    let a = rr("alias.example.org", RecordType::A, None, &["192.0.2.2"]);
    let e = client
        .set_rrset(&zone(), &a, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(mock.log().count(Some("POST"), ROLLBACK), 0);
    assert_eq!(control.published_all("example.org"), before);
    assert!(!control.has_changes("example.org"));

    // At names without the other kind of data the same writes go through.
    let cname = rr(
        "new.example.org",
        RecordType::CNAME,
        None,
        &["target.example.net."],
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &cname, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    let a = rr("www2.example.org", RecordType::A, None, &["192.0.2.2"]);
    assert_eq!(
        client.set_rrset(&zone(), &a, Expect::Any).await.unwrap(),
        SetOutcome::Created
    );
}

fn rollbacks(mock: &NicruMock) -> usize {
    mock.log().count(Some("POST"), ROLLBACK)
}

/// The published records of `rel` (relative) and `rtype`, each as its fields joined by spaces,
/// sorted.
fn published(mock: &NicruMock, rel: &str, rtype: &str) -> Vec<String> {
    let mut out: Vec<String> = mock
        .control()
        .published(rel, rtype)
        .iter()
        .map(|r| r.strings.join(" "))
        .collect();
    out.sort();
    out
}

/// The zone's staged records equal its published ones (by identifier): nothing is pending.
fn settled(mock: &NicruMock) -> bool {
    let ids = |records: Vec<zonewright_mock::nicru::Record>| {
        let mut ids: Vec<u64> = records.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids
    };
    let control = mock.control();
    !control.has_changes("example.org")
        && ids(control.staged_all("example.org")) == ids(control.published_all("example.org"))
}

/// Every supported type through set, get and list with canonical equality: the apex (written
/// `@`), an IDN name, a wildcard, a delegation, multi-value sets, a TXT value longer than one
/// string; each set is published by exactly one commit; the requests carry the documented
/// elements.
#[tokio::test]
async fn nicru_record_round_trips() {
    let (mock, client) = setup().await;
    let long = Txt::new(format!("v=DKIM1; k=rsa; p={}", "A".repeat(560)))
        .unwrap()
        .to_data()
        .unwrap();
    let long_text = long.as_str().to_owned();
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
            Some(600),
            &["192.0.2.3"],
        ),
        rr("*.example.org", RecordType::AAAA, None, &["2001:db8::1"]),
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
        rr(
            "1.2.example.org",
            RecordType::PTR,
            None,
            &["host.example.net."],
        ),
        rr(
            "old.example.org",
            RecordType::DNAME,
            None,
            &["example.net."],
        ),
        rr(
            "example.org",
            RecordType::TXT,
            None,
            &[&long_text, "\"v=spf1 mx -all\""],
        ),
    ];
    for set in &sets {
        let label = format!("{} {}", set.name(), set.rtype());
        let commits_before = commits(&mock);
        assert_eq!(
            client
                .set_rrset(&zone(), set, Expect::Absent)
                .await
                .unwrap(),
            SetOutcome::Created,
            "{label}"
        );
        assert_eq!(commits(&mock), commits_before + 1, "{label}");
        assert!(settled(&mock), "{label}");
        let got = client
            .get_rrset(&zone(), set.name(), set.rtype())
            .await
            .unwrap();
        assert_eq!(got.as_ref(), Some(&with_default_ttl(set)), "{label}");
        assert!(got.unwrap().records().iter().all(RecordData::is_canonical));
        // A repeat changes nothing.
        let before = writes(&mock);
        assert_eq!(
            client.set_rrset(&zone(), set, Expect::Any).await.unwrap(),
            SetOutcome::Unchanged,
            "{label}"
        );
        assert_eq!(writes(&mock), before, "{label}");
    }
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.skipped.is_empty(), "{:?}", listing.skipped);
    assert_eq!(listing.rrsets.len(), sets.len());
    for set in &sets {
        assert!(listing.rrsets.contains(&with_default_ttl(set)), "{set:?}");
    }

    // What the API stores, and the requests that carried it.
    assert_eq!(published(&mock, "@", "A"), ["192.0.2.1", "192.0.2.2"]);
    assert_eq!(published(&mock, "xn--bcher-kva", "A"), ["192.0.2.3"]);
    assert_eq!(published(&mock, "*", "AAAA"), ["2001:db8::1"]);
    assert_eq!(published(&mock, "www", "CNAME"), ["target.example.net."]);
    assert_eq!(
        published(&mock, "@", "MX"),
        ["10 mail.example.org.", "20 backup.example.net."]
    );
    assert_eq!(
        published(&mock, "_sip._tcp", "SRV"),
        ["1 5 5060 sip.example.org.", "2 0 5061 sip2.example.org."]
    );
    assert_eq!(published(&mock, "1.2", "PTR"), ["host.example.net."]);
    assert_eq!(published(&mock, "old", "DNAME"), ["example.net."]);
    let control = mock.control();
    let dkim = control
        .published("@", "TXT")
        .into_iter()
        .find(|r| r.strings.len() > 1)
        .unwrap();
    assert_eq!(dkim.strings.len(), 3);
    assert!(dkim.strings.iter().all(|s| s.len() <= 255));
    assert_eq!(
        Txt::new(dkim.value()).unwrap().to_data().unwrap().as_str(),
        long_text
    );
    assert!(
        control
            .published("xn--bcher-kva", "A")
            .iter()
            .all(|r| r.ttl.as_deref() == Some("600"))
    );
    assert!(
        control
            .published("@", "MX")
            .iter()
            .all(|r| r.ttl.as_deref() == Some("30"))
    );
    let bodies: Vec<String> = mock
        .log()
        .matching(Some("PUT"), RECORDS)
        .iter()
        .map(|r| r.body_str().into_owned())
        .collect();
    for needle in [
        "<rr><name>@</name><ttl>30</ttl><type>A</type><a>192.0.2.1</a></rr>",
        "<name>xn--bcher-kva</name><ttl>600</ttl><type>A</type>",
        "<type>CNAME</type><cname><name>target.example.net.</name></cname>",
        "<type>NS</type><ns><name>ns1.example.net.</name></ns>",
        "<type>MX</type><mx><preference>10</preference><exchange><name>mail.example.org.</name>\
         </exchange></mx>",
        "<type>SRV</type><srv><priority>1</priority><weight>5</weight><port>5060</port><target>\
         <name>sip.example.org.</name></target></srv>",
        "<type>PTR</type><ptr><name>host.example.net.</name></ptr>",
        "<type>DNAME</type><dname><name>example.net.</name></dname>",
        "<type>TXT</type><txt><string>v=spf1 mx -all</string></txt>",
    ] {
        assert!(
            bodies.iter().any(|b| b.contains(needle)),
            "{needle}: {bodies:?}"
        );
    }

    // A TTL listed in BIND form reads in seconds.
    control.insert_record("example.org", "bind", "A", "192.0.2.9", Some("1h"));
    assert_eq!(
        client
            .get_rrset(&zone(), &dn("bind.example.org"), RecordType::A)
            .await
            .unwrap(),
        Some(rr(
            "bind.example.org",
            RecordType::A,
            Some(3600),
            &["192.0.2.9"]
        ))
    );
}

/// `Expect::Absent` on an existing set and `Expect::Matches` on a different or missing one are
/// `PreconditionFailed` and write nothing; an expectation that holds lets the write through.
#[tokio::test]
async fn nicru_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", "www", "A", "192.0.2.1", Some("600"));
    let wanted = rr(www, RecordType::A, None, &["192.0.2.7"]);
    let other = rr(www, RecordType::A, None, &["192.0.2.2"]);
    let more = rr(www, RecordType::A, None, &["192.0.2.1", "192.0.2.2"]);
    let ttl = rr(www, RecordType::A, Some(300), &["192.0.2.1"]);
    for expect in [
        Expect::Absent,
        Expect::Matches(&other),
        Expect::Matches(&more),
        Expect::Matches(&ttl),
    ] {
        let e = client
            .set_rrset(&zone(), &wanted, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{expect:?}: {e:?}");
        assert!(!e.is_retryable());
    }
    for expect in [Expect::Matches(&other), Expect::Matches(&ttl)] {
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
    assert_eq!(writes(&mock), 0);
    assert_eq!(rollbacks(&mock), 0);
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.1"]);

    // The expectation holds, with the TTL and without one.
    let current = rr(www, RecordType::A, Some(600), &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&current))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.7"]);
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
    assert!(settled(&mock));
}

/// `Any` replaces whatever is there, keeping the TTL of the existing set; a TTL change alone
/// stages each record again with the new TTL; a CNAME is replaced; a delete removes every
/// record and a repeat is `NotPresent`. Each change is one commit.
#[tokio::test]
async fn nicru_set_any_replaces_and_delete_converges() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", "www", "A", "192.0.2.1", Some("600"));
    control.insert_record("example.org", "www", "A", "192.0.2.2", Some("600"));

    let next = rr(www, RecordType::A, None, &["192.0.2.2", "192.0.2.3"]);
    assert_eq!(
        client.set_rrset(&zone(), &next, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.2", "192.0.2.3"]);
    assert!(
        control
            .published("www", "A")
            .iter()
            .all(|r| r.ttl.as_deref() == Some("600"))
    );
    assert_eq!((puts(&mock), deletes(&mock), commits(&mock)), (1, 1, 1));

    let retuned = next
        .clone()
        .with_ttl(Some(RrsetTtl::from_secs(120).unwrap()));
    assert_eq!(
        client
            .set_rrset(&zone(), &retuned, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.2", "192.0.2.3"]);
    assert!(
        control
            .published("www", "A")
            .iter()
            .all(|r| r.ttl.as_deref() == Some("120"))
    );
    assert_eq!((puts(&mock), deletes(&mock), commits(&mock)), (3, 3, 2));
    assert_eq!(
        client
            .get_rrset(&zone(), &dn(www), RecordType::A)
            .await
            .unwrap(),
        Some(retuned.clone())
    );

    control.insert_record(
        "example.org",
        "alias",
        "CNAME",
        "a.example.net.",
        Some("300"),
    );
    let cname = rr(
        "alias.example.org",
        RecordType::CNAME,
        None,
        &["b.example.net."],
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &cname, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(published(&mock, "alias", "CNAME"), ["b.example.net."]);
    assert_eq!(commits(&mock), 3);

    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(www), RecordType::A, Expect::Matches(&retuned))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(published(&mock, "www", "A").is_empty());
    assert_eq!(commits(&mock), 4);
    let before = writes(&mock);
    for expect in [Expect::Any, Expect::Matches(&retuned)] {
        let result = client
            .delete_rrset(&zone(), &dn(www), RecordType::A, expect)
            .await;
        match expect {
            Expect::Any => assert_eq!(result.unwrap(), DeleteOutcome::NotPresent),
            _ => assert_eq!(result.unwrap_err().kind(), ErrorKind::PreconditionFailed),
        }
    }
    assert_eq!(writes(&mock), before);
    assert!(settled(&mock));
}

/// Values the client has no established encoding for are refused after the read, before any
/// edit: TXT with a quote, a backslash or an outer space, a name with an escaped dot.
#[tokio::test]
async fn nicru_values_without_an_encoding_are_refused() {
    let (mock, client) = setup().await;
    for set in [
        rr("www.example.org", RecordType::TXT, None, &["\"a\\\"b\""]),
        rr("www.example.org", RecordType::TXT, None, &["\"a\\\\b\""]),
        rr("www.example.org", RecordType::TXT, None, &["\" lead\""]),
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
    assert_eq!(writes(&mock), 0);
    assert_eq!(rollbacks(&mock), 0);
}

/// Everything the API lists is reported: canonical sets, SOA and the apex NS set, data that
/// does not parse as non-canonical members (a host name without the trailing dot, an address
/// that is none, the types without a canonical form), and what cannot be an rrset in
/// `skipped` (a type whose element no source shows, an unknown type name, an invalid owner
/// name). A listed set with a non-canonical member can be written back with a member added.
#[tokio::test]
async fn nicru_listing_reports_skipped_sets() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record(
        "example.org",
        "@",
        "SOA",
        "ns3-l2.nic.ru. dns.nic.ru. 2011112002 1440 3600 2592000 600",
        None,
    );
    control.insert_record("example.org", "@", "NS", "ns3-l2.nic.ru.", None);
    control.insert_record("example.org", "@", "NS", "ns4-l2.nic.ru.", None);
    control.insert_record("example.org", "rel", "MX", "10 mail", Some("300"));
    control.insert_raw(
        "example.org",
        "odd",
        "A",
        "<a>not-an-address</a>",
        Some("300"),
    );
    control.insert_record("example.org", "hw", "HINFO", "PC-Intel RUEL", Some("300"));
    control.insert_raw(
        "example.org",
        "@",
        "CAA",
        "<caa><flags>0</flags><tag>issue</tag></caa>",
        None,
    );
    control.insert_raw("example.org", "x", "FOO", "<foo>1</foo>", None);
    control.insert_raw("example.org", "bad name", "A", "<a>192.0.2.1</a>", None);

    let listing = client.list_rrsets(&zone()).await.unwrap();
    let find = |owner: &str, rtype: &str| {
        let rtype: RecordType = rtype.parse().unwrap();
        listing
            .rrsets
            .iter()
            .find(|s| s.name() == &dn(owner) && s.rtype() == rtype)
            .unwrap_or_else(|| panic!("{owner} {rtype}: {:?}", listing.rrsets))
            .clone()
    };
    assert_eq!(
        find("example.org", "SOA").records(),
        [rdata(
            RecordType::SOA,
            "ns3-l2.nic.ru. dns.nic.ru. 2011112002 1440 3600 2592000 600"
        )]
    );
    assert_eq!(find("example.org", "NS").records().len(), 2);
    let mx = find("rel.example.org", "MX");
    assert!(!mx.records()[0].is_canonical());
    assert_eq!(mx.records()[0].as_str(), "10 mail");
    let odd = find("odd.example.org", "A");
    assert!(!odd.records()[0].is_canonical());
    let hw = find("hw.example.org", "HINFO");
    assert_eq!(hw.records()[0].as_str(), "PC-Intel RUEL");
    assert!(!hw.records()[0].is_canonical());
    assert_eq!(listing.rrsets.len(), 5, "{:?}", listing.rrsets);

    let mut skipped: Vec<(String, String, SkipReason)> = listing
        .skipped
        .iter()
        .map(|s| (s.name.to_string(), s.type_name.clone(), s.reason))
        .collect();
    skipped.sort_by(|a, b| a.1.cmp(&b.1));
    assert_eq!(
        skipped,
        [
            (
                "example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::UnsupportedName
            ),
            (
                "example.org.".to_owned(),
                "CAA".to_owned(),
                SkipReason::NotPlainRecords
            ),
            (
                "x.example.org.".to_owned(),
                "FOO".to_owned(),
                SkipReason::UnknownType
            ),
        ]
    );

    // The listed MX set, written back with a member added: the non-canonical record stays as it
    // is, the new one is staged, nothing is deleted.
    let wider = RrSet::new(
        mx.name().clone(),
        RecordType::MX,
        None,
        mx.records()
            .iter()
            .cloned()
            .chain([rdata(RecordType::MX, "20 backup.example.net.")]),
    )
    .unwrap();
    assert_eq!(
        client
            .set_rrset(&zone(), &wider, Expect::Matches(&mx))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!((puts(&mock), deletes(&mock)), (1, 0));
    assert_eq!(
        published(&mock, "rel", "MX"),
        ["10 mail", "20 backup.example.net."]
    );
    // The listed set with its non-canonical member is unchanged; a non-canonical member the
    // zone does not hold is refused before any edit.
    assert_eq!(
        client
            .set_rrset(&zone(), &odd.clone().with_ttl(None), Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    let foreign: RrSet = serde_json::from_value(serde_json::json!({
        "name": "odd.example.org.", "type": "A", "ttl": null,
        "records": [{"raw": "also-not-an-address"}]
    }))
    .unwrap();
    let e = client
        .set_rrset(&zone(), &foreign, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!((puts(&mock), deletes(&mock)), (1, 0));
}

/// A record listing is complete or the operation fails, and nothing is written after it: a
/// listing without its zone element, a record without an identifier, an unclear `has-changes`,
/// and a zone listing without its data element are `Protocol` errors.
#[tokio::test]
async fn nicru_truncated_rrset_listing_fails() {
    let (mock, client) = setup().await;
    let set = rr("www.example.org", RecordType::A, None, &["192.0.2.1"]);
    let no_zone = "<response><status>success</status><data></data></response>";
    let no_id = "<response><status>success</status><data><zone name=\"example.org\" \
                 service=\"zwservice\" has-changes=\"false\"><rr><name>www</name><type>A</type>\
                 <a>192.0.2.1</a></rr></zone></data></response>";
    let unclear = "<response><status>success</status><data><zone name=\"example.org\" \
                   service=\"zwservice\" has-changes=\"maybe\"></zone></data></response>";
    let empty = "<response><status>success</status></response>";
    for fault in [
        Fault::on("GET", RECORDS).always().respond(200, no_zone),
        Fault::on("GET", RECORDS).always().respond(200, no_id),
        Fault::on("GET", RECORDS).always().respond(200, unclear),
        Fault::on("GET", ZONES).always().respond(200, empty),
    ] {
        mock.faults().push(fault);
        let e = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
        let e = client
            .get_rrset(&zone(), &dn("www.example.org"), RecordType::A)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
        let e = client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
        mock.faults().clear();
    }
    assert_eq!(writes(&mock), 0);
}

/// A zone with staged changes is not read, since the record listing could show them as if
/// published, and not written: foreign staged changes, and a foreign edit staged between the
/// zone lookup and the record listing, are `Rejected` with nothing written.
#[tokio::test]
async fn nicru_staged_changes_block_record_operations() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", "www", "A", "192.0.2.1", None);
    let www = dn("www.example.org");
    let set = rr("www.example.org", RecordType::A, None, &["192.0.2.2"]);
    control.stage_record("example.org", "foreign-edit", "A", "192.0.2.9", None);
    for _ in 0..2 {
        assert_eq!(
            client.list_rrsets(&zone()).await.unwrap_err().kind(),
            ErrorKind::Rejected
        );
        assert_eq!(
            client
                .get_rrset(&zone(), &www, RecordType::A)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Rejected
        );
        assert_eq!(
            client
                .set_rrset(&zone(), &set, Expect::Any)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Rejected
        );
        assert_eq!(
            client
                .delete_rrset(&zone(), &www, RecordType::A, Expect::Any)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Rejected
        );
    }
    assert_eq!(writes(&mock) + rollbacks(&mock), 0);
    assert!(control.published("foreign-edit", "A").is_empty());
    // The zone lookup alone decides when the record listing does not state `has-changes`.
    let silent = "<response><status>success</status><data><zone name=\"example.org\" \
                  service=\"zwservice\"><rr id=\"1\"><name>www</name><type>A</type>\
                  <a>192.0.2.1</a></rr></zone></data></response>";
    mock.faults()
        .push(Fault::on("GET", RECORDS).always().respond(200, silent));
    assert_eq!(
        client.list_rrsets(&zone()).await.unwrap_err().kind(),
        ErrorKind::Rejected
    );
    assert_eq!(
        client
            .get_rrset(&zone(), &www, RecordType::A)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Rejected
    );
    mock.faults().clear();

    // Staged while the operation reads (between its zone lookup and its record listing), for a
    // write and for a listing, each on a zone that was clean when it was looked up.
    for listing in [false, true] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.insert_record("example.org", "www", "A", "192.0.2.1", None);
        let hook = control.clone();
        mock.faults().push(
            Fault::on("GET", RECORDS)
                .run(move || {
                    hook.stage_record("example.org", "late", "A", "192.0.2.8", None);
                })
                .pass(),
        );
        let e = if listing {
            client.list_rrsets(&zone()).await.unwrap_err()
        } else {
            client
                .set_rrset(&zone(), &set, Expect::Any)
                .await
                .unwrap_err()
        };
        assert_eq!(e.kind(), ErrorKind::Rejected, "{listing}: {e:?}");
        assert_eq!(writes(&mock) + rollbacks(&mock), 0);
        assert_eq!(published(&mock, "www", "A"), ["192.0.2.1"]);
    }
}

/// A replacement that fails part-way is never published: its staged edits are rolled back, the
/// published set stays the old one, and a repeat converges with one commit. Covered: an unknown
/// outcome of the second staging, a refused deletion after the stagings, a CNAME whose old
/// record's deletion is staged when the new record is refused, and an operation dropped
/// between two edits, which leaves the zone refused until it is rolled back by hand. An edit
/// refused before anything was staged rolls nothing back.
#[tokio::test]
async fn nicru_failed_replacement_is_never_published() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", "www", "A", "192.0.2.1", Some("300"));
    control.insert_record("example.org", "www", "A", "192.0.2.2", Some("300"));
    let wanted = rr(www, RecordType::A, None, &["192.0.2.3", "192.0.2.4"]);
    let refused = fail_body("4004", "refused");
    for (i, fault) in [
        Fault::on("PUT", RECORDS).skip(1).status(502),
        Fault::on("DELETE", RECORD).respond(200, refused.clone()),
    ]
    .into_iter()
    .enumerate()
    {
        mock.faults().push(fault);
        let e = client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap_err();
        assert!(
            matches!(e.kind(), ErrorKind::Transient | ErrorKind::Rejected),
            "{e:?}"
        );
        assert_eq!(rollbacks(&mock), i + 1);
        assert_eq!(commits(&mock), 0);
        assert_eq!(published(&mock, "www", "A"), ["192.0.2.1", "192.0.2.2"]);
        assert!(settled(&mock));
    }
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(commits(&mock), 1);
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.3", "192.0.2.4"]);

    // A CNAME: the old record's deletion is staged first, then the new record is refused.
    control.insert_record("example.org", "alias", "CNAME", "a.example.net.", None);
    mock.faults()
        .push(Fault::on("PUT", RECORDS).respond(200, refused.clone()));
    let cname = rr(
        "alias.example.org",
        RecordType::CNAME,
        None,
        &["b.example.net."],
    );
    let e = client
        .set_rrset(&zone(), &cname, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(rollbacks(&mock), 3);
    assert_eq!(published(&mock, "alias", "CNAME"), ["a.example.net."]);
    assert!(settled(&mock));

    // Refused before anything was staged: nothing to roll back, and the mark is cleared, so a
    // foreign edit staged afterwards is refused rather than taken for ours.
    mock.faults()
        .push(Fault::on("PUT", RECORDS).respond(200, refused));
    let e = client
        .set_rrset(
            &zone(),
            &rr("new.example.org", RecordType::A, None, &["192.0.2.5"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(rollbacks(&mock), 3);
    control.stage_record("example.org", "foreign-edit", "A", "192.0.2.9", None);
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!((commits(&mock), rollbacks(&mock)), (1, 3));

    // Dropped between the two stagings: the next operation rolls the first one back.
    let mock = Arc::new(NicruMock::start(Seed::standard()).await);
    let ctx = context();
    let first = Arc::new(client_with(&mock, &ctx));
    let control = mock.control().clone();
    control.insert_record("example.org", "www", "A", "192.0.2.1", None);
    mock.faults().push(
        Fault::on("PUT", RECORDS)
            .skip(1)
            .delay(Duration::from_secs(5))
            .pass(),
    );
    let task = {
        let first = first.clone();
        let wanted = wanted.clone();
        tokio::spawn(async move { first.set_rrset(&zone(), &wanted, Expect::Any).await })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while puts(&mock) < 2 {
        assert!(Instant::now() < deadline, "the second staging was not sent");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    task.abort();
    let _ = task.await;
    assert!(control.has_changes("example.org"));
    mock.faults().clear();
    // The outcome of the second staging is unknown and no listing settled it: the next
    // operation can tell the staged changes from someone else's no better than a stranger, so
    // it refuses the zone and neither commits nor rolls back.
    let second = client_with(&mock, &ctx);
    let e = second
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!((commits(&mock), rollbacks(&mock)), (0, 0));
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.1"]);
    // Rolled back by hand: the next operation goes on.
    control.rollback("example.org");
    second
        .add_txt_value(&zone(), &name(), &txt("AAA"), None)
        .await
        .unwrap();
    assert_eq!(rollbacks(&mock), 0);
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.1"]);
    assert_eq!(control.published_txt(REL), ["AAA"]);
    assert!(settled(&mock));
}

/// A commit that keeps failing leaves the complete change staged and marked for a commit: the
/// next operation publishes it. A rollback that keeps failing leaves the zone marked for a
/// rollback: the next operation, here a TXT value operation, rolls back first, and the
/// half-applied replacement is never published.
#[tokio::test]
async fn nicru_failed_commit_and_rollback_are_settled_by_the_next_operation() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = "www.example.org";
    control.insert_record("example.org", "www", "A", "192.0.2.1", Some("300"));
    let wanted = rr(www, RecordType::A, None, &["192.0.2.2"]);
    mock.faults()
        .push(Fault::on("POST", COMMIT).always().status(502));
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(commits(&mock), 3);
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.1"]);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.zones[0].found);
    assert!(report.zones[0].detail.is_some());
    mock.faults().clear();
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    assert_eq!((commits(&mock), rollbacks(&mock)), (4, 0));
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.2"]);
    assert!(settled(&mock));

    let next = rr(www, RecordType::A, None, &["192.0.2.3"]);
    mock.faults()
        .push(Fault::on("DELETE", RECORD).respond(200, fail_body("4004", "refused")));
    mock.faults()
        .push(Fault::on("POST", ROLLBACK).always().status(502));
    let e = client
        .set_rrset(&zone(), &next, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(rollbacks(&mock), 3);
    assert!(control.has_changes("example.org"));
    mock.faults().clear();
    // A read settles this process's own leftovers first, as a write does: here it rolls the
    // half-applied replacement back and then lists the published records.
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert_eq!(rollbacks(&mock), 4);
    assert!(settled(&mock));
    assert!(listing.rrsets.contains(&with_default_ttl(&rr(
        www,
        RecordType::A,
        Some(300),
        &["192.0.2.2"]
    ))));
    add(&client, "AAA").await.unwrap();
    assert_eq!((commits(&mock), rollbacks(&mock)), (5, 4));
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.2"]);
    assert_eq!(control.published_txt(REL), ["AAA"]);
    assert!(settled(&mock));
}

/// `get_rrset` and `list_rrsets` settle this process's own staged changes before they read:
/// a complete change whose commit failed is committed, a half-applied one rolled back. Staged
/// changes this process did not make are still refused.
#[tokio::test]
async fn nicru_reads_settle_own_leftovers() {
    let www = "www.example.org";
    let wanted = rr(www, RecordType::A, None, &["192.0.2.2"]);
    for read_with_get in [true, false] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.insert_record("example.org", "www", "A", "192.0.2.1", Some("300"));
        mock.faults()
            .push(Fault::on("POST", COMMIT).always().status(502));
        let e = client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
        assert_eq!(commits(&mock), 3);
        mock.faults().clear();
        let expected = rr(www, RecordType::A, Some(300), &["192.0.2.2"]);
        if read_with_get {
            assert_eq!(
                client
                    .get_rrset(&zone(), &dn(www), RecordType::A)
                    .await
                    .unwrap(),
                Some(expected)
            );
        } else {
            let listing = client.list_rrsets(&zone()).await.unwrap();
            assert!(listing.rrsets.contains(&expected), "{listing:?}");
        }
        assert_eq!((commits(&mock), rollbacks(&mock)), (4, 0));
        assert!(settled(&mock));

        // A foreign staged edit is refused by both reads and never committed.
        control.stage_record("example.org", "foreign-edit", "A", "192.0.2.9", None);
        assert_eq!(
            client
                .get_rrset(&zone(), &dn(www), RecordType::A)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Rejected
        );
        assert_eq!(
            client.list_rrsets(&zone()).await.unwrap_err().kind(),
            ErrorKind::Rejected
        );
        assert_eq!((commits(&mock), rollbacks(&mock)), (4, 0));
        assert!(published(&mock, "foreign-edit", "A").is_empty());
    }
}

/// When every commit attempt fails but one of them was applied (its answer lost), the zone is
/// listed once more and, being clean, loses its mark: a foreign edit staged before the next
/// operation is refused, not committed as ours.
#[tokio::test]
async fn nicru_lost_commit_answer_clears_the_mark() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let hook = control.clone();
    mock.faults().push(
        Fault::on("POST", COMMIT)
            .always()
            .run(move || hook.commit("example.org"))
            .status(502),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(commits(&mock), 3);
    assert_eq!(control.published_txt(REL), ["AAA"]);
    assert!(!control.has_changes("example.org"));
    mock.faults().clear();
    control.stage_record("example.org", "foreign-edit", "TXT", "pending", None);
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(commits(&mock), 3);
    assert!(control.published_txt("foreign-edit").is_empty());
}

/// The first edit of a record-level operation whose outcome is unknown (here applied, its
/// answer lost) is not taken for refused: the operation rolls the zone back, so the staged
/// edit is neither published nor left behind unmarked.
#[tokio::test]
async fn nicru_unknown_first_edit_is_rolled_back() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let hook = control.clone();
    mock.faults().push(
        Fault::on("PUT", RECORDS)
            .run(move || {
                hook.stage_record("example.org", "www", "A", "192.0.2.1", Some("30"));
            })
            .status(502),
    );
    let wanted = rr("www.example.org", RecordType::A, None, &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!((commits(&mock), rollbacks(&mock)), (0, 1));
    assert!(published(&mock, "www", "A").is_empty());
    assert!(settled(&mock));
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.1"]);
}

/// Critic 6, probe A: a staging answered 502 without being applied, and the listing that
/// should settle it fails as well, leave an unconfirmed rollback mark on a clean zone. A foreign
/// edit staged afterwards is never rolled back: reads and writes refuse the zone. Once the zone
/// is clean again the mark goes, and a later foreign edit is refused as foreign.
#[tokio::test]
async fn nicru_unconfirmed_rollback_mark_is_not_acted_on() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = dn("www.example.org");
    control.insert_record("example.org", "www", "A", "192.0.2.1", None);
    mock.fail_creates_unapplied(1, 3);
    let wanted = rr("www.example.org", RecordType::A, None, &["192.0.2.2"]);
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(!control.has_changes("example.org"));

    control.stage_record("example.org", "foreign-edit", "A", "192.0.2.9", None);
    let e = client
        .get_rrset(&zone(), &www, RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(e.to_string().contains("cannot show"), "{e}");
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let report = client.check(&[zone()]).await.unwrap();
    let detail = report.zones[0].detail.as_ref().unwrap();
    assert!(detail.as_str().contains("cannot show"), "{detail}");
    assert_eq!((commits(&mock), rollbacks(&mock)), (0, 0));
    assert_eq!(control.staged("foreign-edit", "A").len(), 1);
    assert_eq!(puts(&mock), 1);

    // The other writer commits: the zone is clean, a read clears the mark.
    control.commit("example.org");
    assert_eq!(
        client
            .get_rrset(&zone(), &www, RecordType::A)
            .await
            .unwrap()
            .unwrap()
            .records()
            .len(),
        1
    );
    control.stage_record("example.org", "foreign-two", "A", "192.0.2.10", None);
    let e = client
        .get_rrset(&zone(), &www, RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    let report = client.check(&[zone()]).await.unwrap();
    let detail = report.zones[0].detail.as_ref().unwrap();
    assert!(detail.as_str().contains("did not make"), "{detail}");
    assert_eq!((commits(&mock), rollbacks(&mock)), (0, 0));
}

/// Critic 6, probe B: every commit attempt is applied with its answer lost, and the listing
/// after the last attempt fails as well, so the zone is clean but keeps an unconfirmed commit
/// mark. Another writer then stages the deletion of a published TXT record: neither a read nor
/// a write commits it. Covered for a TXT value operation and for a record-level write.
#[tokio::test]
async fn nicru_unconfirmed_commit_mark_is_not_acted_on() {
    for record_level in [false, true] {
        let (mock, client) = setup().await;
        let control = mock.control();
        control.insert_record("example.org", "other", "TXT", "keep", None);
        mock.lose_commit_answers(3, 3);
        let e = if record_level {
            client
                .set_rrset(
                    &zone(),
                    &rr("www.example.org", RecordType::A, None, &["192.0.2.1"]),
                    Expect::Any,
                )
                .await
                .unwrap_err()
        } else {
            add(&client, "AAA").await.unwrap_err()
        };
        assert_eq!(e.kind(), ErrorKind::Transient, "{record_level}: {e:?}");
        assert_eq!(commits(&mock), 3, "{record_level}");
        assert!(!control.has_changes("example.org"), "{record_level}");

        control.stage_txt_deletion("other", "keep");
        let e = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{record_level}: {e:?}");
        let e = client
            .get_rrset(&zone(), &dn("other.example.org"), RecordType::TXT)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{record_level}: {e:?}");
        let e = add(&client, "BBB").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{record_level}: {e:?}");
        let e = client
            .delete_rrset(&zone(), &dn("www.example.org"), RecordType::A, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{record_level}: {e:?}");
        assert_eq!((commits(&mock), rollbacks(&mock)), (3, 0), "{record_level}");
        assert_eq!(control.published_txt("other"), ["keep"], "{record_level}");
        assert!(control.has_changes("example.org"), "{record_level}");
    }
}

/// A rollback applied with its answer lost, every attempt, leaves a clean zone: the listing
/// after the last attempt clears the mark, so a foreign edit staged afterwards is refused, not
/// rolled back. When that listing fails too, the mark stays unconfirmed and the foreign edit is
/// refused as well.
#[tokio::test]
async fn nicru_lost_rollback_answer_clears_the_mark() {
    for failing_listings in [0, 3] {
        let (mock, client) = setup().await;
        let control = mock.control();
        let www = dn("www.example.org");
        control.insert_record("example.org", "www", "A", "192.0.2.1", None);
        mock.faults()
            .push(Fault::on("DELETE", RECORD).respond(200, fail_body("4004", "refused")));
        mock.lose_rollback_answers(3, failing_listings);
        let wanted = rr("www.example.org", RecordType::A, None, &["192.0.2.2"]);
        let e = client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap_err();
        let label = format!("listings failing: {failing_listings}");
        assert_eq!(e.kind(), ErrorKind::Transient, "{label}: {e:?}");
        assert_eq!(rollbacks(&mock), 3, "{label}");
        assert!(settled(&mock), "{label}");
        assert_eq!(published(&mock, "www", "A"), ["192.0.2.1"], "{label}");

        control.stage_record("example.org", "foreign-edit", "A", "192.0.2.9", None);
        let e = client
            .get_rrset(&zone(), &www, RecordType::A)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{label}: {e:?}");
        let e = client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Rejected, "{label}: {e:?}");
        let expected = if failing_listings == 0 {
            "did not make"
        } else {
            "cannot show"
        };
        assert!(e.to_string().contains(expected), "{label}: {e}");
        assert_eq!((commits(&mock), rollbacks(&mock)), (0, 3), "{label}");
        assert_eq!(control.staged("foreign-edit", "A").len(), 1, "{label}");
    }
}

/// Settling a confirmed mark unconfirms it before the first attempt: when the commit (or
/// rollback) that settles it is applied with its answer lost and the listing after it fails, a
/// foreign edit staged afterwards is refused, not committed (or rolled back) as ours.
#[tokio::test]
async fn nicru_settling_a_confirmed_mark_unconfirms_it_first() {
    // A confirmed commit mark: every commit attempt fails, the listing after them succeeds.
    let (mock, client) = setup().await;
    let control = mock.control();
    mock.faults()
        .push(Fault::on("POST", COMMIT).times(3).status(502));
    assert!(add(&client, "AAA").await.unwrap_err().is_retryable());
    assert!(control.has_changes("example.org"));
    // The next operation settles it; its commits are applied with their answers lost.
    mock.lose_commit_answers(3, 3);
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(control.published_txt(REL), ["AAA"]);
    control.stage_record("example.org", "foreign-edit", "TXT", "pending", None);
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!(commits(&mock), 6);
    assert!(control.published_txt("foreign-edit").is_empty());

    // A confirmed rollback mark: a refused deletion, every rollback attempt fails, the listing
    // after them succeeds.
    let (mock, client) = setup().await;
    let control = mock.control();
    let www = dn("www.example.org");
    control.insert_record("example.org", "www", "A", "192.0.2.1", None);
    mock.faults()
        .push(Fault::on("DELETE", RECORD).respond(200, fail_body("4004", "refused")));
    mock.faults()
        .push(Fault::on("POST", ROLLBACK).times(3).status(502));
    let wanted = rr("www.example.org", RecordType::A, None, &["192.0.2.2"]);
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(control.has_changes("example.org"));
    // A read settles it; its rollbacks are applied with their answers lost.
    mock.lose_rollback_answers(3, 3);
    let e = client
        .get_rrset(&zone(), &www, RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(settled(&mock));
    control.stage_record("example.org", "foreign-edit", "A", "192.0.2.9", None);
    let e = client
        .get_rrset(&zone(), &www, RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert_eq!((commits(&mock), rollbacks(&mock)), (0, 6));
    assert_eq!(control.staged("foreign-edit", "A").len(), 1);
}

/// A TTL change of a CNAME stages the deletion of the old record before the record with the
/// new TTL, so that two CNAME records are never staged at the name; for other types the new
/// record goes first.
#[tokio::test]
async fn nicru_singleton_ttl_change_stages_the_delete_first() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record(
        "example.org",
        "alias",
        "CNAME",
        "a.example.net.",
        Some("300"),
    );
    control.insert_record("example.org", "www", "A", "192.0.2.1", Some("300"));
    let edits = |mock: &NicruMock| -> Vec<String> {
        mock.log()
            .entries()
            .iter()
            .filter(|r| r.matches(Some("PUT"), RECORDS) || r.matches(Some("DELETE"), RECORD))
            .map(|r| r.method.to_string())
            .collect()
    };
    let cname = rr(
        "alias.example.org",
        RecordType::CNAME,
        Some(120),
        &["a.example.net."],
    );
    assert_eq!(
        client
            .set_rrset(&zone(), &cname, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(edits(&mock), ["DELETE", "PUT"]);
    assert_eq!(published(&mock, "alias", "CNAME"), ["a.example.net."]);
    assert_eq!(
        control.published("alias", "CNAME")[0].ttl.as_deref(),
        Some("120")
    );
    mock.log().clear();
    let a = rr("www.example.org", RecordType::A, Some(120), &["192.0.2.1"]);
    assert_eq!(
        client.set_rrset(&zone(), &a, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(edits(&mock), ["PUT", "DELETE"]);
    assert_eq!(commits(&mock), 1);
}

/// A listed record whose TTL is present but does not parse makes the read fail
/// (`Error::Protocol`); it is never read as a record without a TTL.
#[tokio::test]
async fn nicru_unparsable_ttl_is_protocol() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", "www", "A", "192.0.2.1", Some("12x"));
    assert_eq!(
        client
            .get_rrset(&zone(), &dn("www.example.org"), RecordType::A)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Protocol
    );
    assert_eq!(
        client.list_rrsets(&zone()).await.unwrap_err().kind(),
        ErrorKind::Protocol
    );
    let e = client
        .set_rrset(
            &zone(),
            &rr("www.example.org", RecordType::A, None, &["192.0.2.2"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// Record operations change their own rrset only: other types at the same name and other names
/// keep their records, identifiers and TTLs.
#[tokio::test]
async fn nicru_record_operations_touch_only_their_rrset() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", "www", "TXT", "keep", Some("600"));
    control.insert_record("example.org", "www", "AAAA", "2001:db8::1", Some("600"));
    control.insert_record("example.org", "www2", "A", "192.0.2.1", Some("600"));
    control.insert_record("example.org", "sub.www", "A", "192.0.2.1", Some("600"));
    let others = |mock: &NicruMock| {
        let mut all: Vec<_> = mock
            .control()
            .published_all("example.org")
            .into_iter()
            .filter(|r| !(r.name == "www" && r.rtype == "A"))
            .collect();
        all.sort_by_key(|r| r.id);
        all
    };
    let before = others(&mock);
    let www = dn("www.example.org");
    client
        .set_rrset(
            &zone(),
            &rr("www.example.org", RecordType::A, None, &["192.0.2.1"]),
            Expect::Absent,
        )
        .await
        .unwrap();
    client
        .set_rrset(
            &zone(),
            &rr("www.example.org", RecordType::A, Some(60), &["192.0.2.2"]),
            Expect::Any,
        )
        .await
        .unwrap();
    client
        .delete_rrset(&zone(), &www, RecordType::A, Expect::Any)
        .await
        .unwrap();
    assert_eq!(others(&mock), before);
}

/// Two writes to one name from two clients sharing a `Context` are serialized: the second
/// starts after the first has committed, and each is one commit.
#[tokio::test]
async fn nicru_concurrent_record_writes_are_serialized() {
    let mock = Arc::new(NicruMock::start(Seed::standard()).await);
    let ctx = context();
    let first = Arc::new(client_with(&mock, &ctx));
    let second = client_with(&mock, &ctx);
    mock.faults().push(
        Fault::on("PUT", RECORDS)
            .delay(Duration::from_millis(300))
            .pass(),
    );
    let task = {
        let first = first.clone();
        tokio::spawn(async move {
            first
                .set_rrset(
                    &zone(),
                    &rr("www.example.org", RecordType::A, None, &["192.0.2.1"]),
                    Expect::Absent,
                )
                .await
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while puts(&mock) == 0 {
        assert!(Instant::now() < deadline, "the first staging was not sent");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let second_set = rr("www.example.org", RecordType::A, None, &["192.0.2.2"]);
    assert_eq!(
        second
            .set_rrset(&zone(), &second_set, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(task.await.unwrap().unwrap(), SetOutcome::Created);
    assert_eq!(published(&mock, "www", "A"), ["192.0.2.2"]);
    assert_eq!(commits(&mock), 2);
    let log = mock.log().entries();
    let first_commit = log
        .iter()
        .position(|r| r.method == Method::POST && r.path.ends_with("/commit"))
        .unwrap();
    let second_put = log
        .iter()
        .position(|r| r.method == Method::PUT && r.body_str().contains("192.0.2.2"))
        .unwrap();
    assert!(
        first_commit < second_put,
        "the second write was staged before the first commit"
    );
}

/// Record-level edits are sent once whatever happens: a 502, a 429 and a 401 on the staging of
/// a record or of a deletion are the operation's error with exactly one such request, and an
/// edit that was not applied is neither committed nor needs a rollback.
#[tokio::test]
async fn nicru_record_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_record("example.org", "www", "A", "192.0.2.1", None);
    let set = rr("new.example.org", RecordType::A, None, &["192.0.2.1"]);
    let www = dn("www.example.org");
    for (i, (method, path)) in [("PUT", RECORDS), ("DELETE", RECORD)]
        .into_iter()
        .enumerate()
    {
        for (j, (status, kind)) in [
            (502, ErrorKind::Transient),
            (429, ErrorKind::RateLimited),
            (401, ErrorKind::Transient),
        ]
        .into_iter()
        .enumerate()
        {
            let fault = if status == 429 {
                Fault::on(method, path).rate_limited("1")
            } else {
                Fault::on(method, path).status(status)
            };
            mock.faults().push(fault);
            let e = if i == 0 {
                client.set_rrset(&zone(), &set, Expect::Any).await
            } else {
                client
                    .delete_rrset(&zone(), &www, RecordType::A, Expect::Any)
                    .await
                    .map(|_| SetOutcome::Unchanged)
            }
            .unwrap_err();
            assert_eq!(e.kind(), kind, "{method} {status}: {e:?}");
            assert_eq!(
                mock.log().count(Some(method), path),
                j + 1,
                "{method} {status}"
            );
            assert_eq!(
                (commits(&mock), rollbacks(&mock)),
                (0, 0),
                "{method} {status}"
            );
            assert!(settled(&mock), "{method} {status}");
        }
    }
    assert_eq!(
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap(),
        SetOutcome::Created
    );
    assert_eq!(
        client
            .delete_rrset(&zone(), &www, RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert_eq!((puts(&mock), deletes(&mock), commits(&mock)), (4, 4, 2));
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
            let report = client.check([&zone]).await.unwrap();
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
    if !cleanup.is_empty() {
        eprintln!("cleanup failed: {cleanup:?}");
    }
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}

/// A record-level round trip on an A rrset and a TXT rrset under a generated label in the zone
/// the maintainer names: create, read, replace, list, delete. Afterwards it deletes exactly the
/// rrsets of that label it may have created, also when the body failed. The zone must have no
/// staged changes when the test starts.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_nicru_record_round_trip() {
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
    let name = zone.prepend(&format!("zw-live-{tag:016x}")).unwrap();

    let body = {
        let (client, zone, name) = (client.clone(), zone.clone(), name.clone());
        tokio::spawn(async move {
            let owner = name.as_str().to_owned();
            let a = rr(
                &owner,
                RecordType::A,
                Some(300),
                &["192.0.2.1", "192.0.2.2"],
            );
            assert_eq!(
                client.set_rrset(&zone, &a, Expect::Absent).await.unwrap(),
                SetOutcome::Created
            );
            assert_eq!(
                client.get_rrset(&zone, &name, RecordType::A).await.unwrap(),
                Some(a.clone())
            );
            let replaced = rr(
                &owner,
                RecordType::A,
                Some(300),
                &["192.0.2.2", "192.0.2.3"],
            );
            assert_eq!(
                client
                    .set_rrset(&zone, &replaced, Expect::Matches(&a))
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            let text = Txt::new(format!("zw-live {tag:016x} {}", "x".repeat(300)))
                .unwrap()
                .to_data()
                .unwrap();
            let txt_set = RrSet::new(name.clone(), RecordType::TXT, None, [text]).unwrap();
            assert_eq!(
                client
                    .set_rrset(&zone, &txt_set, Expect::Absent)
                    .await
                    .unwrap(),
                SetOutcome::Created
            );
            let listing = client.list_rrsets(&zone).await.unwrap();
            assert!(listing.rrsets.contains(&replaced), "{listing:?}");
            assert!(
                listing
                    .rrsets
                    .iter()
                    .any(|s| s.name() == &name && s.same_records(&txt_set)),
                "{listing:?}"
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

    // Cleanup: the rrsets of the generated name only.
    let mut cleanup = Vec::new();
    for rtype in [RecordType::A, RecordType::TXT] {
        if let Err(e) = client.delete_rrset(&zone, &name, rtype, Expect::Any).await {
            cleanup.push(format!("{e}"));
        }
    }
    if !cleanup.is_empty() {
        eprintln!("cleanup failed: {cleanup:?}");
    }
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}

/// The zone's default TTL (design section 3.6): a record without `<ttl>`. A set staged without
/// one, a switch from a number to it (the value staged again without `<ttl>`, the old record
/// deleted) and back, unchanged round trips in both states, expectations of each kind, the
/// `ttl` setting's spelling, and a TXT value added with it.
#[tokio::test]
async fn nicru_provider_default_ttl() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let default = Some(RrsetTtl::ProviderDefault);
    let www = "www.example.org";
    let set = |ttl: Option<RrsetTtl>| rr(www, RecordType::A, None, &["192.0.2.1"]).with_ttl(ttl);
    let ttls = || -> Vec<Option<String>> {
        control
            .published("www", "A")
            .into_iter()
            .map(|r| r.ttl)
            .collect()
    };
    let puts = |mock: &NicruMock| -> Vec<String> {
        mock.log()
            .matching(Some("PUT"), RECORDS)
            .iter()
            .map(|r| r.body_str().into_owned())
            .collect()
    };

    // Staged without `<ttl>`.
    assert_eq!(
        client
            .set_rrset(&zone(), &set(default), Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    let staged = puts(&mock);
    assert_eq!(staged.len(), 1);
    assert!(!staged[0].contains("<ttl>"), "{}", staged[0]);
    assert_eq!(ttls(), [None]);
    let read = client
        .get_rrset(&zone(), &dn(www), RecordType::A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, set(default));
    let before = writes(&mock);
    for wanted in [read.clone(), set(None)] {
        assert_eq!(
            client
                .set_rrset(&zone(), &wanted, Expect::Matches(&read))
                .await
                .unwrap(),
            SetOutcome::Unchanged
        );
    }
    let e = client
        .set_rrset(
            &zone(),
            &set(None),
            Expect::Matches(&set(Some(RrsetTtl::from_secs(30).unwrap()))),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed);
    assert_eq!(writes(&mock), before);

    // Default to explicit and back: the value staged again, the old record deleted.
    let explicit = set(Some(RrsetTtl::from_secs(600).unwrap()));
    mock.log().clear();
    assert_eq!(
        client
            .set_rrset(&zone(), &explicit, Expect::Matches(&set(default)))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert!(puts(&mock)[0].contains("<ttl>600</ttl>"));
    assert_eq!(ttls(), [Some("600".to_owned())]);
    let before = writes(&mock);
    assert_eq!(
        client
            .set_rrset(&zone(), &explicit, Expect::Matches(&explicit))
            .await
            .unwrap(),
        SetOutcome::Unchanged
    );
    assert_eq!(writes(&mock), before);
    mock.log().clear();
    assert_eq!(
        client
            .set_rrset(&zone(), &set(default), Expect::Matches(&explicit))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let staged = puts(&mock);
    assert_eq!(staged.len(), 1);
    assert!(!staged[0].contains("<ttl>"), "{}", staged[0]);
    assert_eq!(ttls(), [None]);

    // A TXT value added with the default is staged without `<ttl>`.
    mock.log().clear();
    client
        .add_txt_value(&zone(), &name(), &txt("v1"), default)
        .await
        .unwrap();
    assert!(!puts(&mock)[0].contains("<ttl>"));
    assert_eq!(control.published(REL, "TXT")[0].ttl, None);

    // The setting "provider_default": a new set without a TTL.
    let seed = Seed::standard();
    let mut config = settings(&mock, &seed);
    config.ttl = RrsetTtl::ProviderDefault;
    let configured = Nicru::new(
        config,
        credentials(&seed.password, &seed.client_id, &seed.client_secret),
        &context(),
    )
    .unwrap();
    configured
        .set_rrset(
            &zone(),
            &rr("new.example.org", RecordType::A, None, &["192.0.2.9"]),
            Expect::Absent,
        )
        .await
        .unwrap();
    assert_eq!(control.published("new", "A")[0].ttl, None);
}
