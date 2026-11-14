//! Tests of the reg.ru client (`regru`) against its mock.
#![cfg(feature = "regru")]
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
use serde_json::{Value, json};
use zonewright::providers::regru::{Regru, RegruConfig, RegruCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RemoveOutcome, RrSet, Ttl, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum;
use zonewright_mock::axum::http::StatusCode;
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::echo::{EchoServer, Echoed, Render};
use zonewright_mock::regru::{RegruMock, Seed, parse_form};

use common::echo::{CANARY_KEY, CANARY_PASSWORD, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The user name and the password of the standard seed.
const USER: &str = "zw-test-user";
const PASSWORD: &str = "test-only-password";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// The same name relative to the zone, as the API spells it.
const SUB: &str = "_acme-challenge";

/// Fault patterns of the mock's paths. Every call is a POST.
const NOP: &str = "/api/regru2/nop";
const ZONE_NOP: &str = "/api/regru2/zone/nop";
const READ: &str = "/api/regru2/zone/get_resource_records";
const ADD: &str = "/api/regru2/zone/add_txt";
const REMOVE: &str = "/api/regru2/zone/remove_record";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings pointed at `base_url`, without pacing.
fn settings(base_url: String) -> RegruConfig {
    let mut config = RegruConfig::new(USER.to_owned());
    config.base_url = base_url;
    config.min_request_interval_ms = 0;
    config
}

fn credentials(password: &str) -> RegruCredentials {
    RegruCredentials::new(SecretString::from(password.to_owned()))
}

fn client_with(mock: &RegruMock, password: &str, ctx: &Context) -> Regru {
    Regru::new(settings(mock.base_url()), credentials(password), ctx).unwrap()
}

async fn setup() -> (RegruMock, Regru) {
    let mock = RegruMock::start(Seed::standard()).await;
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
fn writes(mock: &RegruMock) -> usize {
    let log = mock.log();
    log.count(Some("POST"), ADD) + log.count(Some("POST"), REMOVE)
}

/// The settings JSON of `from_json` for `mock`.
fn settings_json(mock: &RegruMock) -> String {
    json!({ "username": USER, "base_url": mock.base_url() }).to_string()
}

/// The form fields of a logged request.
fn form_of(request: &zonewright_mock::LoggedRequest) -> Vec<(String, String)> {
    parse_form(&request.body)
}

/// The parsed `input_data` of a logged request.
fn input_of(request: &zonewright_mock::LoggedRequest) -> Value {
    let form = form_of(request);
    let data = form
        .iter()
        .find(|(k, _)| k == "input_data")
        .map(|(_, v)| v.as_str())
        .expect("input_data");
    serde_json::from_str(data).unwrap()
}

/// A success answer for one domain, as the API words it.
fn domain_ok(extra: Value) -> String {
    let mut entry = json!({"dname": "example.org", "result": "success", "service_id": "1"});
    for (key, value) in extra.as_object().unwrap() {
        entry[key] = value.clone();
    }
    json!({"result": "success", "answer": {"domains": [entry]}}).to_string()
}

/// An answer with an error of the whole call.
fn top_error(code: &str, text: &str) -> String {
    json!({"result": "error", "error_code": code, "error_text": text}).to_string()
}

/// An answer with an error in the domain's entry.
fn domain_error(code: &str, text: &str) -> String {
    json!({"result": "success", "answer": {"domains": [
        {"dname": "example.org", "result": "error", "error_code": code, "error_text": text}
    ]}})
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

assert_not_impl!(Regru: std::fmt::Display, serde::Serialize);
assert_not_impl!(RegruCredentials: std::fmt::Display, serde::Serialize);

/// What the echo's listing answers: no record, a record with a foreign value, or a record with
/// the value `AAA`.
#[derive(Clone, Copy)]
enum Existing {
    Nothing,
    Foreign,
    Ours,
}

/// How a JSON string is escaped in an echoed answer.
#[derive(Clone, Copy, Debug)]
enum Style {
    /// `serde_json`.
    Serde,
    /// PHP `json_encode` defaults: `/` as `\/`, non-ASCII as `\uXXXX`.
    Php,
    /// Go: `< > &` as `<`, `>`, `&`.
    Go,
    /// .NET: `" ' + & < >` and non-ASCII as uppercase `\uXXXX`.
    DotNet,
    /// Non-ASCII as lowercase `\uXXXX`, `/` as it is.
    Unicode,
    /// A JSON document in a JSON string: escaped twice.
    InJson,
}

/// The JSON string literal of `text` in `style`.
fn literal(text: &str, style: Style) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        let unit = match style {
            Style::Serde | Style::InJson => false,
            Style::Php | Style::Unicode => !c.is_ascii(),
            Style::Go => matches!(c, '<' | '>' | '&'),
            Style::DotNet => matches!(c, '"' | '\'' | '+' | '&' | '<' | '>') || !c.is_ascii(),
        };
        if unit {
            let mut units = [0u16; 2];
            for u in c.encode_utf16(&mut units) {
                if matches!(style, Style::DotNet) {
                    out.push_str(&format!("\\u{u:04X}"));
                } else {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            continue;
        }
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '/' if matches!(style, Style::Php) => out.push_str("\\/"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    if matches!(style, Style::InJson) {
        // The whole literal is the content of another string.
        let inner = out;
        return literal(&inner, Style::Serde);
    }
    out
}

/// At which level of the answer an error is put.
#[derive(Clone, Copy, Debug)]
enum Level {
    /// `{"result":"error", ...}`.
    Top,
    /// An entry of `answer.domains`.
    Domain,
}

/// A renderer that answers with the error envelope of the API (HTTP 200) with the echoed request
/// in `error_text`, escaped as `style` says.
fn envelope(level: Level, code: &'static str, style: Style) -> Render {
    Arc::new(move |e: &Echoed| {
        let text = literal(&e.text, style);
        let body = match level {
            Level::Top => format!(
                r#"{{"result":"error","error_code":"{code}","error_text":{text},"error_params":{{"command_name":{text}}}}}"#
            ),
            Level::Domain => format!(
                r#"{{"result":"success","answer":{{"domains":[{{"dname":"example.org","result":"error","error_code":"{code}","error_text":{text}}}]}}}}"#
            ),
        };
        (StatusCode::OK, [("content-type", "text/plain")], body).into_response()
    })
}

/// A renderer that answers `nop`, `zone/nop` and the listing like the API and every other request
/// with `errors`.
fn reads_then(errors: Render, existing: Existing) -> Render {
    Arc::new(move |e: &Echoed| {
        let body = if e.path.ends_with("/zone/get_resource_records") {
            let rrs = match existing {
                Existing::Nothing => json!([]),
                Existing::Foreign => {
                    json!([{"subname": SUB, "rectype": "TXT", "content": "foreign"}])
                }
                Existing::Ours => json!([{"subname": SUB, "rectype": "TXT", "content": "AAA"}]),
            };
            domain_ok(json!({ "rrs": rrs }))
        } else if e.path.ends_with("/zone/nop") {
            domain_ok(json!({}))
        } else if e.path.ends_with("/nop") {
            json!({"result": "success", "answer": {"login": "u", "user_id": "1"}}).to_string()
        } else {
            return errors(e);
        };
        (
            StatusCode::OK,
            axum::Json(serde_json::from_str::<Value>(&body).unwrap()),
        )
            .into_response()
    })
}

/// The canary credentials: the user name is a setting here but is sent in the same form, and the
/// password has a newline and non-ASCII letters.
fn echo_client(echo: &EchoServer) -> Regru {
    let mut config = RegruConfig::new(CANARY_KEY.to_owned());
    config.base_url = echo.url("/api/regru2");
    config.min_request_interval_ms = 0;
    Regru::new(config, credentials(CANARY_PASSWORD), &context()).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Write {
    Add,
    Remove,
}

/// `check` and a write against an echo that quotes every request back: no canary in any error,
/// `ZoneCheck::detail` or `Debug`, and the write's error shows the redaction.
async fn echo_round(label: &str, client: &Regru, write: Write) {
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
        Write::Add => add(client, "AAA").await.map(|o| format!("{o:?}")),
        Write::Remove => remove(client, "AAA").await.map(|o| format!("{o:?}")),
    };
    let text = match result {
        Ok(outcome) => panic!("{label}: the echo accepted a write: {outcome}"),
        Err(e) => format!("{e} | {e:?}"),
    };
    assert!(
        text.contains(REDACTED),
        "{label}: the echo did not reach the error: {text}"
    );
    texts.push(text);
    for text in &texts {
        assert_clean(label, text, &[CANARY_PASSWORD, CANARY_KEY]);
    }
}

/// Which escape styles an envelope is rendered in for a dialect: the one the dialect names, and
/// for the others the two that matter most (plain and PHP, where `/` is `\/` and non-ASCII is
/// `\uXXXX`).
fn styles(name: &str) -> Vec<Style> {
    match name {
        "json_ascii" | "json_ascii_with_notice" => vec![Style::Php],
        "json_go" => vec![Style::Go],
        "json_dotnet" => vec![Style::DotNet],
        "json_unicode" => vec![Style::Unicode],
        "json_in_json" => vec![Style::InJson],
        _ => vec![Style::Serde, Style::Php],
    }
}

/// `check` and the writes against an echo, for every dialect. Five kinds of request reach it: the
/// credentials call, the zone call, the listing, the add and the remove; and errors come in two
/// forms: an HTTP status with the dialect's body, and the API's own envelope, which answers
/// `200` with the error in the JSON body.
#[tokio::test]
async fn regru_secret_echo() {
    for dialect in dialects() {
        // Everything is the echo: the credentials call is the first request. A 5xx is left out
        // here, as reads are retried with real back-off sleeps; the write rounds cover it.
        for status in [400, 401] {
            let label = format!("{} {:?} {status} nop", dialect.name, dialect.spelling);
            let echo = dialect.echo(status).start().await;
            let client = echo_client(&echo);
            echo_round(&label, &client, Write::Add).await;
            assert!(echo.log().count(Some("POST"), NOP) > 0, "{label}");
            assert!(echo.log().count(Some("POST"), READ) > 0, "{label}");
        }
        // The credentials call is answered; the zone call is the echo.
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} zone/nop", dialect.name, dialect.spelling);
            let echo = dialect
                .echo(status)
                .render_under("/api/regru2/zone", dialect.render.clone())
                .render_under(
                    "/api/regru2/nop",
                    reads_then(dialect.render.clone(), Existing::Nothing),
                )
                .start()
                .await;
            let client = echo_client(&echo);
            // A refusal of the zone call is an error or, as the provider's reason for a zone it
            // will not manage, the detail of the zone's entry; either way it is clean.
            let text = match client.check(&[zone()]).await {
                Ok(report) => {
                    let detail = report.zones[0].detail.as_ref().expect("the reason");
                    assert!(detail.as_str().contains(REDACTED), "{label}: {detail}");
                    format!("{detail} | {client:?}")
                }
                Err(e) => format!("{e} | {e:?} | {client:?}"),
            };
            assert_clean(&label, &text, &[CANARY_PASSWORD, CANARY_KEY]);
            assert!(
                echo.log().count(Some("POST"), ZONE_NOP) > 0,
                "{label}: the zone call did not reach the echo"
            );
        }
        // The listing answers normally, so the write itself reaches the echo: an add (with and
        // without a foreign record at the name) and a remove.
        for (existing, write, statuses) in [
            (
                Existing::Nothing,
                Write::Add,
                [400, 401, 403, 422, 500].as_slice(),
            ),
            (
                Existing::Foreign,
                Write::Add,
                [400, 401, 403, 422, 500].as_slice(),
            ),
            (
                Existing::Ours,
                Write::Remove,
                [400, 401, 403, 422, 500].as_slice(),
            ),
        ] {
            for &status in statuses {
                let label = format!("{} {:?} {status} {write:?}", dialect.name, dialect.spelling);
                let echo = dialect
                    .echo(status)
                    .render(reads_then(dialect.render.clone(), existing))
                    .start()
                    .await;
                let client = echo_client(&echo);
                echo_round(&label, &client, write).await;
                let path = match write {
                    Write::Add => ADD,
                    Write::Remove => REMOVE,
                };
                assert!(
                    echo.log().count(Some("POST"), path) >= 1,
                    "{label}: the write did not reach the echo"
                );
            }
        }
        // The API's own error form: `200` with the error in the JSON body, in the dialect's
        // escape style, at both levels of the answer.
        for style in styles(dialect.name) {
            for (level, code) in [
                (Level::Top, "ECHO_ERROR"),
                (Level::Top, "PASSWORD_AUTH_FAILED"),
                (Level::Top, "ACCESS_DENIED_FROM_IP"),
            ] {
                let label = format!(
                    "{} {:?} {style:?} {level:?} {code}",
                    dialect.name, dialect.spelling
                );
                let echo = dialect
                    .echo(200)
                    .render(envelope(level, code, style))
                    .start()
                    .await;
                let client = echo_client(&echo);
                echo_round(&label, &client, Write::Add).await;
            }
            for (code, write, existing) in [
                ("ECHO_ERROR", Write::Add, Existing::Nothing),
                (
                    "TEXT_CONTAINS_INVALID_CHARACTERS",
                    Write::Add,
                    Existing::Foreign,
                ),
                ("DOMAIN_PROTECTION", Write::Add, Existing::Nothing),
                ("ECHO_ERROR", Write::Remove, Existing::Ours),
            ] {
                let label = format!(
                    "{} {:?} {style:?} domain {code} {write:?}",
                    dialect.name, dialect.spelling
                );
                let echo = dialect
                    .echo(200)
                    .render(reads_then(envelope(Level::Domain, code, style), existing))
                    .start()
                    .await;
                let client = echo_client(&echo);
                echo_round(&label, &client, write).await;
                let path = match write {
                    Write::Add => ADD,
                    Write::Remove => REMOVE,
                };
                assert!(
                    echo.log().count(Some("POST"), path) >= 1,
                    "{label}: the write did not reach the echo"
                );
            }
        }
        // A 200 answer in the dialect's own body, which is not the API's envelope at all.
        let label = format!("{} {:?} 200 body", dialect.name, dialect.spelling);
        let echo = dialect
            .echo(200)
            .render(reads_then(dialect.render.clone(), Existing::Nothing))
            .start()
            .await;
        let client = echo_client(&echo);
        echo_round(&label, &client, Write::Add).await;
    }
}

/// A `TRACE` capture over a success, a 401, a 500, an envelope error and a wrong password: the
/// transport's events are there, and no canary is.
#[tokio::test(flavor = "current_thread")]
async fn regru_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.username = CANARY_KEY.into();
    seed.password = CANARY_PASSWORD.into();
    let mock = RegruMock::start(seed).await;
    let mut config = settings(mock.base_url());
    config.username = CANARY_KEY.into();
    let client = Regru::new(config.clone(), credentials(CANARY_PASSWORD), &context()).unwrap();
    let mut texts = Vec::new();

    add(&client, "AAA").await.unwrap();
    remove(&client, "AAA").await.unwrap();

    mock.faults()
        .push(Fault::on("POST", READ).always().status(401));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("POST", ADD).status(500));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    mock.faults().push(Fault::on("POST", ADD).respond(
        200,
        top_error("ECHO_ERROR", &format!("{CANARY_PASSWORD} {CANARY_KEY}")),
    ));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    let mut wrong_config = settings(mock.base_url());
    wrong_config.username = CANARY_KEY.into();
    let wrong = Regru::new(wrong_config, credentials("other-pW9x"), &context()).unwrap();
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
            "regru logs and errors",
            text,
            &[CANARY_PASSWORD, CANARY_KEY, "other-pW9x"],
        );
    }
    // The credentials travel in the body: never in a URL.
    for request in mock.log().entries() {
        assert!(request.query.is_none(), "{request:?}");
        assert!(!request.path.contains("canary") && !request.path.contains("Canary"));
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely ends
/// with the zone's text, the zone's text inside another name, and a sibling zone.
#[tokio::test]
async fn regru_name_outside_zone_sends_nothing() {
    let (mock, client) = setup().await;
    let value = txt("AAA");
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
}

/// A value the capabilities do not accept and any TTL (the API cannot set one) are refused
/// before any request; a value the capabilities accept but the provider's text rules refuse is
/// `InvalidInput` and writes nothing.
#[tokio::test]
async fn regru_invalid_input_sends_nothing() {
    let (mock, client) = setup().await;
    for value in ["two words", "quo\"te", "back\\slash"] {
        let e = add(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
        let e = remove(&client, value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{value}: {e:?}");
    }
    for ttl in [30, 60, 3600] {
        let e = client
            .add_txt_value(
                &zone(),
                &name(),
                &txt("AAA"),
                Some(Ttl::from_secs(ttl).unwrap()),
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{ttl}: {e:?}");
    }
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());

    // The documentation allows only alphanumeric characters in the text; a plain value with a
    // hyphen is sent, and the API's refusal is the answer.
    let e = add(&client, "with-hyphen").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.control().records().is_empty());
    assert_eq!(mock.log().count(Some("POST"), ADD), 1);
}

/// `Created`, `Appended` for a second value (the apex and the wildcard of one certificate share
/// a name), then `AlreadyPresent` without a write.
#[tokio::test]
async fn regru_add_is_idempotent() {
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
    assert_eq!(mock.control().txt("example.org", SUB), ["AAA", "BBB"]);
}

/// Removing an absent value next to foreign ones writes nothing; adding and removing our value
/// leaves the foreign records as they were. A single foreign value is never a reason to delete
/// anything.
#[tokio::test]
async fn regru_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_record("example.org", SUB, "TXT", "foreign1");
    control.add_record("example.org", SUB, "TXT", "foreign2");
    let original = control.records();

    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        control.txt("example.org", SUB),
        ["foreign1", "foreign2", "ours"]
    );
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.records(), original);
    // Only our value was named by the request: with no content the API would remove every TXT
    // record at the name.
    let removes = mock.log().matching(Some("POST"), REMOVE);
    assert_eq!(removes.len(), 1);
    let input = input_of(&removes[0]);
    assert_eq!(input["content"], "ours");
    assert_eq!(input["record_type"], "TXT");

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.add_record("example.org", "_acme-challenge.www", "TXT", "foreign");
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &txt("ours"))
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(
        control.txt("example.org", "_acme-challenge.www"),
        ["foreign"]
    );
}

/// Records of other types at the same name and TXT records at other names are not touched and
/// are not mistaken for ours, even when they hold the same content.
#[tokio::test]
async fn regru_other_types_at_the_name_are_untouched() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_record("example.org", SUB, "A", "192.0.2.1");
    control.add_record("example.org", SUB, "CNAME", "AAA");
    control.add_record("example.org", "other", "TXT", "AAA");
    control.add_record("example.org", "_acme-challenge.www", "TXT", "AAA");
    control.add_record("example.org", "@", "TXT", "AAA");
    let original = control.records();
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(control.records(), original);
    // The removal named the type.
    let removes = mock.log().matching(Some("POST"), REMOVE);
    assert_eq!(input_of(&removes[0])["record_type"], "TXT");
    assert_eq!(input_of(&removes[0])["subdomain"], SUB);
}

#[tokio::test]
async fn regru_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().records().is_empty());
    assert_eq!(mock.log().count(Some("POST"), REMOVE), 1);
}

#[tokio::test]
async fn regru_remove_is_idempotent() {
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
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert!(mock.control().records().is_empty());
}

/// A duplicate of the value (made by a writer outside the process) is one value: the removal
/// names its content once, the API removes every record with it, and nothing else goes.
#[tokio::test]
async fn regru_remove_deletes_every_copy_of_the_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_record("example.org", SUB, "TXT", "AAA");
    control.add_record("example.org", SUB, "TXT", "foreign");
    control.add_record("example.org", SUB, "TXT", "AAA");
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt("example.org", SUB), ["foreign"]);
}

/// The value in two spellings, one record quoted and one plain (made by writers outside the
/// process): each record is removed by its own content, the confirming read after the first
/// removal does not mistake the other spelling for a failed removal, and the foreign record
/// stays.
#[tokio::test]
async fn regru_remove_handles_every_spelling_of_the_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_record("example.org", SUB, "TXT", "\"AAA\"");
    control.add_record("example.org", SUB, "TXT", "foreign");
    control.add_record("example.org", SUB, "TXT", "AAA");
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt("example.org", SUB), ["foreign"]);
    let contents: Vec<String> = mock
        .log()
        .matching(Some("POST"), REMOVE)
        .iter()
        .map(|request| input_of(request)["content"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(contents, ["\"AAA\"", "AAA"]);
}

/// Contents with characters the form encoding, the JSON of `input_data` or a careless parser
/// could cut (`&`, `=`, `;`, `+`, `%`, `#`) reach the API intact: the removal names exactly the
/// content the listing returned, so it can never turn into a removal without a content or with a
/// shorter one. Records whose content is a prefix of ours stay.
#[tokio::test]
async fn regru_remove_sends_the_content_intact() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let value = "a&b=c;d+e%26f#g";
    control.add_record("example.org", SUB, "TXT", value);
    control.add_record("example.org", SUB, "TXT", "a");
    control.add_record("example.org", SUB, "TXT", "a&b");
    assert_eq!(
        remove(&client, value).await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(control.txt("example.org", SUB), ["a", "a&b"]);
    let removes = mock.log().matching(Some("POST"), REMOVE);
    assert_eq!(removes.len(), 1);
    assert_eq!(input_of(&removes[0])["content"], value);
}

/// Two clients sharing a `Context` add to one name at once, the first write delayed: the second
/// waits for the lock and sees the first one's record. Without the name lock both would read "no
/// record" and both report `Created`.
#[tokio::test]
async fn regru_concurrent_adds_are_serialized() {
    let mock = RegruMock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, PASSWORD, &ctx);
    let b = client_with(&mock, PASSWORD, &ctx);
    mock.faults()
        .push(Fault::on("POST", ADD).delay(Duration::from_millis(300)));
    let (zone, name, aaa, bbb) = (zone(), name(), txt("AAA"), txt("BBB"));
    let (ra, rb) = tokio::join!(
        a.add_txt_value(&zone, &name, &aaa, None),
        b.add_txt_value(&zone, &name, &bbb, None),
    );
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [AddOutcome::Appended, AddOutcome::Created]);
    let mut values = mock.control().txt("example.org", SUB);
    values.sort();
    assert_eq!(values, ["AAA", "BBB"]);
}

/// A foreign value added between the read and the write is not lost: the add names only our
/// value.
#[tokio::test]
async fn regru_foreign_value_added_between_read_and_write_survives() {
    let (mock, client) = setup().await;
    let hook = mock.control().clone();
    mock.faults().push(Fault::on("POST", ADD).run(move || {
        hook.add_record("example.org", SUB, "TXT", "foreign");
    }));
    add(&client, "ours").await.unwrap();
    let mut values = mock.control().txt("example.org", SUB);
    values.sort();
    assert_eq!(values, ["foreign", "ours"]);
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(mock.control().txt("example.org", SUB), ["foreign"]);

    // The same for the removal: a foreign value added between the read and the remove call stays.
    add(&client, "ours").await.unwrap();
    let hook = mock.control().clone();
    mock.faults().push(Fault::on("POST", REMOVE).run(move || {
        hook.add_record("example.org", SUB, "TXT", "foreign2");
    }));
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    let mut values = mock.control().txt("example.org", SUB);
    values.sort();
    assert_eq!(values, ["foreign", "foreign2"]);
}

/// A removal the API answered `success` but did not apply is not reported as done: the client
/// reads the zone again and the value is still there.
#[tokio::test]
async fn regru_remove_unconfirmed_is_detected() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("POST", REMOVE).respond(200, domain_ok(json!({}))));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(mock.control().txt("example.org", SUB), ["AAA"]);
    // The repeat works.
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );

    // A record that cannot be removed by the content the API returned (here: the content comes
    // back quoted and the removal does not match it) is detected the same way.
    mock.control().add_record("example.org", SUB, "TXT", "BBB");
    mock.control().set_quoted(true);
    assert_eq!(
        add(&client, "BBB").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    let e = remove(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(mock.control().txt("example.org", SUB), ["BBB"]);
}

/// The record-level operations and the zone listing are not offered: `Unsupported`, and nothing is
/// sent.
#[tokio::test]
async fn regru_unsupported_operations_send_nothing() {
    let (mock, client) = setup().await;
    let set = RrSet::new(name(), RecordType::TXT, None, [txt("v").to_data().unwrap()]).unwrap();
    let errors = [
        client.list_zones().await.unwrap_err(),
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

/// Retry behavior: an add and a remove are sent once whatever happens (a 502, a 429, a 401 and
/// the API's own transient and rate-limit errors are the operation's error, and the repeat starts
/// with a read); a repeated add could add a second copy of the value.
#[tokio::test]
async fn regru_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let adds = || mock.log().count(Some("POST"), ADD);
    let removes = || mock.log().count(Some("POST"), REMOVE);

    mock.faults().push(Fault::on("POST", ADD).status(502));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(adds(), 1);
    assert!(mock.control().records().is_empty());

    mock.faults().push(Fault::on("POST", ADD).rate_limited("1"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(adds(), 2);

    mock.faults().push(Fault::on("POST", ADD).status(401));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(adds(), 3);

    // The API's own errors, in a 200 answer, are not repeated either.
    for (n, (body, kind)) in [
        (
            top_error("SERVICE_UNAVAILABLE", "later"),
            ErrorKind::Transient,
        ),
        (top_error("INTERNAL_ERROR", "oops"), ErrorKind::Transient),
        (
            top_error("IP_EXCEEDED_ALLOWED_CONNECTION_RATE", "slow down"),
            ErrorKind::RateLimited,
        ),
        (
            domain_error("ACCOUNT_EXCEEDED_ALLOWED_CONNECTION_RATE", "slow down"),
            ErrorKind::RateLimited,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        mock.faults()
            .push(Fault::on("POST", ADD).respond(200, body));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        assert_eq!(adds(), 4 + n);
    }
    assert!(mock.control().records().is_empty());

    // The add is answered 502 but was applied: the repeat finds the value instead of adding a
    // second copy.
    let hook = mock.control().clone();
    mock.faults().push(
        Fault::on("POST", ADD)
            .run(move || hook.add_record("example.org", SUB, "TXT", "AAA"))
            .status(502),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(adds(), 8);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(adds(), 8);
    assert_eq!(mock.control().txt("example.org", SUB), ["AAA"]);

    // The same for the remove.
    mock.faults().push(Fault::on("POST", REMOVE).status(502));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(removes(), 1);
    mock.faults()
        .push(Fault::on("POST", REMOVE).rate_limited("1"));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(removes(), 2);
    mock.faults().push(Fault::on("POST", REMOVE).status(401));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert_eq!(removes(), 3);
    mock.faults()
        .push(Fault::on("POST", REMOVE).respond(200, top_error("SERVICE_UNAVAILABLE", "later")));
    let e = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(removes(), 4);
    assert_eq!(mock.control().txt("example.org", SUB), ["AAA"]);

    // A refusal by the provider is not repeated either.
    mock.faults()
        .push(Fault::on("POST", ADD).respond(200, domain_error("TEXT_TOOLONG", "Text too long")));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(adds(), 9);
}

/// The reads are the requests that are repeated: a 502 is retried, three in a row are `Transient`
/// (which is retryable), a `429` with a short wait is waited out, a long one is the error.
#[tokio::test]
async fn regru_reads_are_retried() {
    let (mock, client) = setup().await;
    let reads = || mock.log().count(Some("POST"), READ);
    mock.faults().push(Fault::on("POST", READ).status(502));
    add(&client, "AAA").await.unwrap();
    assert_eq!(reads(), 2);

    mock.faults()
        .push(Fault::on("POST", READ).rate_limited("1"));
    add(&client, "BBB").await.unwrap();
    assert_eq!(reads(), 4);

    mock.faults()
        .push(Fault::on("POST", READ).rate_limited("120"));
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
    assert_eq!(reads(), 5);

    mock.faults()
        .push(Fault::on("POST", READ).times(3).status(503));
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(reads(), 8);
    // Nothing was written by the failed ones.
    assert_eq!(mock.control().txt("example.org", SUB), ["AAA", "BBB"]);
}

// ---- Requests and names ------------------------------------------------------------------------

/// The requests as the documentation and lego describe them: a POST of a form with the user name
/// and the password as fields of their own, `input_format=json`, the JSON `input_data` without the
/// credentials, no query string and no `Authorization` header; the add with no TTL.
#[tokio::test]
async fn regru_request_shapes() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    add(&client, "BBB").await.unwrap();
    remove(&client, "AAA").await.unwrap();
    client.check(&[zone()]).await.unwrap();

    for request in mock.log().entries() {
        assert_eq!(request.method.as_str(), "POST");
        assert_eq!(request.query, None, "{}", request.path);
        assert_eq!(
            request.header("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        assert!(request.header("authorization").is_none());
        let form = form_of(&request);
        let get = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
        assert_eq!(get("username"), Some(USER));
        assert_eq!(get("password"), Some(PASSWORD));
        if request.path == NOP {
            // `nop` takes no other parameter.
            assert_eq!(form.len(), 2, "{form:?}");
            continue;
        }
        assert_eq!(get("input_format"), Some("json"));
        assert_eq!(form.len(), 4, "{form:?}");
        let input = input_of(&request);
        assert!(input.get("username").is_none() && input.get("password").is_none());
        assert_eq!(input["domains"], json!([{"dname": "example.org"}]));
        assert_eq!(input["output_content_type"], "plain");
    }

    let first_add = &mock.log().matching(Some("POST"), ADD)[0];
    assert_eq!(
        input_of(first_add),
        json!({
            "domains": [{"dname": "example.org"}],
            "subdomain": SUB,
            "text": "AAA",
            "output_content_type": "plain"
        })
    );
    let the_remove = &mock.log().matching(Some("POST"), REMOVE)[0];
    assert_eq!(
        input_of(the_remove),
        json!({
            "domains": [{"dname": "example.org"}],
            "subdomain": SUB,
            "content": "AAA",
            "record_type": "TXT",
            "output_content_type": "plain"
        })
    );
    // `zone/clear` deletes every record of the zone: never called.
    assert_eq!(mock.log().count(None, "/api/regru2/zone/clear"), 0);
    // One read per operation, and one more after the remove, which confirms it.
    assert_eq!(mock.log().count(Some("POST"), READ), 4);
}

/// The zone itself is `@`; names below the zone are relative, several labels deep as well.
#[tokio::test]
async fn regru_apex_and_deep_names() {
    let (mock, client) = setup().await;
    let apex = zone();
    assert_eq!(
        client
            .add_txt_value(&zone(), &apex, &txt("AAA"), None)
            .await
            .unwrap(),
        AddOutcome::Created
    );
    assert_eq!(mock.control().txt("example.org", "@"), ["AAA"]);
    assert_eq!(
        input_of(&mock.log().matching(Some("POST"), ADD)[0])["subdomain"],
        "@"
    );
    assert_eq!(
        client
            .add_txt_value(&zone(), &apex, &txt("AAA"), None)
            .await
            .unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        client
            .remove_txt_value(&zone(), &apex, &txt("AAA"))
            .await
            .unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(
        input_of(&mock.log().matching(Some("POST"), REMOVE)[0])["subdomain"],
        "@"
    );

    let deep = dn("_acme-challenge.a.b.example.org");
    client
        .add_txt_value(&zone(), &deep, &txt("AAA"), None)
        .await
        .unwrap();
    assert_eq!(
        mock.control().txt("example.org", "_acme-challenge.a.b"),
        ["AAA"]
    );
    // A name that only looks like it (another depth) is a different name.
    assert_eq!(
        client
            .add_txt_value(
                &zone(),
                &dn("_acme-challenge.b.example.org"),
                &txt("AAA"),
                None
            )
            .await
            .unwrap(),
        AddOutcome::Created
    );
}

/// The name of a record is compared exactly, on the client's side: the listing is the whole zone,
/// and records at other names with the same content, at the same name in another type, and at a
/// look-alike name are not ours.
#[tokio::test]
async fn regru_exact_name_match() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_record("example.org", "x._acme-challenge", "TXT", "AAA");
    control.add_record("example.org", "_acme-challenge.x", "TXT", "AAA");
    control.add_record("example.org", "*", "TXT", "AAA");
    control.add_record("example.org", "@", "TXT", "AAA");
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(control.txt("example.org", SUB), ["AAA"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    for sub in ["x._acme-challenge", "_acme-challenge.x", "*", "@"] {
        assert_eq!(control.txt("example.org", sub), ["AAA"], "{sub}");
    }
    // A removal names its name too: the API is never asked to remove at a name that is not ours.
    for request in mock.log().matching(Some("POST"), REMOVE) {
        assert_eq!(input_of(&request)["subdomain"], SUB);
    }
}

/// Contents that come back quoted are read as the values they hold.
#[tokio::test]
async fn regru_quoted_content_is_read() {
    let (mock, client) = setup().await;
    mock.control().add_record("example.org", SUB, "TXT", "AAA");
    mock.control().set_quoted(true);
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    assert_eq!(writes(&mock), 1);
}

/// The request spacing of the setting: two requests are at least the interval apart.
#[tokio::test]
async fn regru_requests_are_paced() {
    let mock = RegruMock::start(Seed::standard()).await;
    let mut config = settings(mock.base_url());
    config.min_request_interval_ms = 300;
    let client = Regru::new(config, credentials(PASSWORD), &context()).unwrap();
    let start = Instant::now();
    client.check(&[]).await.unwrap();
    client.check(&[]).await.unwrap();
    assert!(
        start.elapsed() >= Duration::from_millis(300),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(mock.log().len(), 2);
}

// ---- check -------------------------------------------------------------------------------------

#[tokio::test]
async fn regru_check_exercises_the_credentials() {
    let (mock, client) = setup().await;
    let report = client
        .check(&[zone(), dn("missing.test"), dn("elsewhere.example")])
        .await
        .unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones[0].found && report.zones[0].detail.is_none());
    assert!(!report.zones[1].found && report.zones[1].detail.is_none());
    // A domain whose zone is served by other name servers cannot be managed: the provider's
    // reason is the detail.
    assert!(!report.zones[2].found);
    let detail = report.zones[2].detail.as_ref().unwrap();
    assert!(
        detail.as_str().contains("DOMAIN_IS_NOT_USE_REGRU_NSS"),
        "{detail}"
    );

    // With no zone the credentials are still tested, on every call.
    let report = client.check(&[]).await.unwrap();
    assert!(report.credentials_verified && report.zones.is_empty());
    assert_eq!(mock.log().count(Some("POST"), NOP), 2);
    assert_eq!(mock.log().count(Some("POST"), ZONE_NOP), 3);

    // The credentials call is refused: no zone is asked for.
    let zone_calls = mock.log().count(Some("POST"), ZONE_NOP);
    mock.faults().push(Fault::on("POST", NOP).status(401));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    mock.faults().push(Fault::on("POST", NOP).status(403));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    mock.faults()
        .push(Fault::on("POST", NOP).respond(200, top_error("ACCESS_DENIED_FROM_IP", "denied")));
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    assert_eq!(mock.log().count(Some("POST"), ZONE_NOP), zone_calls);

    // The API answers a wrong password with `200` and an error in the body.
    let wrong = client_with(&mock, "wrong-password", &context());
    for zones in [vec![], vec![zone()]] {
        let e = wrong.check(&zones).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
        assert!(!format!("{e} {e:?} {wrong:?}").contains("wrong-password"));
    }
    // A transient failure of a zone call is not "zone not found".
    mock.faults().push(
        Fault::on("POST", ZONE_NOP).respond(200, domain_error("SERVICE_UNAVAILABLE", "later")),
    );
    let e = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
}

// ---- Errors ------------------------------------------------------------------------------------

#[tokio::test]
async fn regru_zone_not_found() {
    let (_mock, client) = setup().await;
    let other = dn("example.net");
    let e = client
        .add_txt_value(
            &other,
            &dn("_acme-challenge.example.net"),
            &txt("AAA"),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let e = client
        .remove_txt_value(&other, &dn("_acme-challenge.example.net"), &txt("AAA"))
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    // A zone on other name servers cannot be changed: refused with the provider's reason.
    let elsewhere = dn("elsewhere.example");
    let e = client
        .add_txt_value(
            &elsewhere,
            &dn("_acme-challenge.elsewhere.example"),
            &txt("AAA"),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    assert!(
        format!("{e}").contains("DOMAIN_IS_NOT_USE_REGRU_NSS"),
        "{e}"
    );
}

/// The error codes of the documentation, at both levels of the answer, are the errors the
/// design names; an unlisted code is `Rejected` with the provider's words.
#[tokio::test]
async fn regru_envelope_errors_are_classified() {
    let (mock, client) = setup().await;
    let cases = [
        ("PASSWORD_AUTH_FAILED", ErrorKind::Auth),
        ("NO_USERNAME", ErrorKind::Auth),
        ("ACCESS_DENIED", ErrorKind::Forbidden),
        ("ACCESS_DENIED_FROM_IP", ErrorKind::Forbidden),
        ("ACCOUNT_BLOCKED", ErrorKind::Forbidden),
        ("DOMAIN_PROTECTION", ErrorKind::Forbidden),
        (
            "IP_EXCEEDED_ALLOWED_CONNECTION_RATE",
            ErrorKind::RateLimited,
        ),
        (
            "ACCOUNT_EXCEEDED_ALLOWED_CONNECTION_RATE",
            ErrorKind::RateLimited,
        ),
        ("SERVICE_UNAVAILABLE", ErrorKind::Transient),
        ("INTERNAL_ERROR", ErrorKind::Transient),
        ("TEXT_TOOLONG", ErrorKind::InvalidInput),
        ("TEXT_CONTAINS_INVALID_CHARACTERS", ErrorKind::InvalidInput),
        ("DOMAIN_NOT_FOUND", ErrorKind::ZoneNotFound),
        ("SERVICE_NOT_FOUND", ErrorKind::ZoneNotFound),
        ("DOMAIN_IS_NOT_USE_REGRU_NSS", ErrorKind::Rejected),
        ("SOMETHING_NEW", ErrorKind::Rejected),
    ];
    for (code, kind) in cases {
        // At the level of the domain, for a write...
        mock.faults()
            .push(Fault::on("POST", ADD).respond(200, domain_error(code, "words")));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), kind, "domain {code}: {e:?}");
        // ...and of the whole call, for a read (the first request of an operation). A domain
        // that is not found is not named at that level, so it is a refusal there.
        mock.faults()
            .push(Fault::on("POST", READ).respond(200, top_error(code, "words")));
        let e = add(&client, "AAA").await.unwrap_err();
        let expected = if kind == ErrorKind::ZoneNotFound {
            ErrorKind::Rejected
        } else {
            kind
        };
        assert_eq!(e.kind(), expected, "top {code}: {e:?}");
        if let Error::Rejected { status, detail, .. } = &e {
            assert_eq!(*status, Some(200));
            assert_eq!(detail.as_str(), format!("{code}: words"));
        }
    }
    assert!(mock.control().records().is_empty());
    assert_eq!(mock.log().count(Some("POST"), ADD), cases.len());
}

/// An answer that is not the documented envelope is `Protocol`, and above all an add or remove
/// is never reported as done on an answer that does not say so for the domain asked for.
#[tokio::test]
async fn regru_unreadable_answers_are_protocol() {
    let (mock, client) = setup().await;
    let bodies = [
        "not json".to_owned(),
        "<html>oops</html>".to_owned(),
        "PHP Notice: x\n{\"result\":\"success\"}".to_owned(),
        "{}".to_owned(),
        "[]".to_owned(),
        r#"{"result":"success"}"#.to_owned(),
        r#"{"result":"success","answer":{}}"#.to_owned(),
        r#"{"result":"success","answer":{"domains":[]}}"#.to_owned(),
        r#"{"result":"success","answer":{"domains":"x"}}"#.to_owned(),
        // An entry for another domain, two entries, an entry without result.
        r#"{"result":"success","answer":{"domains":[{"dname":"other.example","result":"success"}]}}"#.to_owned(),
        r#"{"result":"success","answer":{"domains":[{"dname":"example.org","result":"success"},{"dname":"example.org","result":"success"}]}}"#.to_owned(),
        r#"{"result":"success","answer":{"domains":[{"dname":"example.org"}]}}"#.to_owned(),
        r#"{"result":"success","answer":{"domains":[{"result":"success"}]}}"#.to_owned(),
        r#"{"result":"weird"}"#.to_owned(),
        r#"{"result":"error"}"#.to_owned(),
    ];
    for body in &bodies {
        for path in [ADD, REMOVE] {
            let (mock, client) = setup().await;
            mock.control().add_record("example.org", SUB, "TXT", "AAA");
            mock.faults()
                .push(Fault::on("POST", path).respond(200, body.clone()));
            let result = if path == ADD {
                add(&client, "BBB").await.map(|o| format!("{o:?}"))
            } else {
                remove(&client, "AAA").await.map(|o| format!("{o:?}"))
            };
            let e = result.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Protocol, "{path} {body}: {e:?}");
        }
        // The same for the reads: the zone call and the listing.
        for (path, check) in [(ZONE_NOP, true), (READ, false)] {
            mock.faults()
                .push(Fault::on("POST", path).respond(200, body.clone()));
            let e = if check {
                client.check(&[zone()]).await.unwrap_err()
            } else {
                add(&client, "CCC").await.unwrap_err()
            };
            assert_eq!(e.kind(), ErrorKind::Protocol, "{path} {body}: {e:?}");
        }
    }
    // The credentials call answers no domain, so a bare `success` is a valid answer to it; what
    // is not an envelope at all is not.
    for body in [
        "not json",
        "<html>oops</html>",
        "{}",
        "[]",
        r#"{"result":"weird"}"#,
        r#"{"result":"error"}"#,
    ] {
        mock.faults()
            .push(Fault::on("POST", NOP).respond(200, body));
        let e = client.check(&[zone()]).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "nop {body}: {e:?}");
    }
    assert!(mock.control().records().is_empty());
}

/// A refusal at the HTTP level is `Rejected` with the status and the provider's message; a status
/// the client cannot interpret is `Protocol`.
#[tokio::test]
async fn regru_refusals_are_rejected() {
    let (mock, client) = setup().await;
    mock.faults().push(
        Fault::on("POST", ADD).respond(400, top_error("PARAMETER_MISSING", "subdomain required")),
    );
    let e = add(&client, "AAA").await.unwrap_err();
    match &e {
        Error::Rejected { status, detail, .. } => {
            assert_eq!(*status, Some(400));
            assert_eq!(detail.as_str(), "PARAMETER_MISSING: subdomain required");
        }
        other => panic!("{other:?}"),
    }
    mock.faults()
        .push(Fault::on("POST", ADD).respond(404, "<html>no</html>"));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Rejected, "{e:?}");
    mock.faults().push(Fault::on("POST", ADD).respond(204, ""));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert!(mock.control().records().is_empty());
}

/// A listing that is not complete fails; it is never a shorter list. Writing is never started on
/// the strength of one.
#[tokio::test]
async fn regru_truncated_listing_is_protocol() {
    let (mock, client) = setup().await;
    mock.control().add_record("example.org", SUB, "TXT", "AAA");
    let bodies = [
        // No list at all.
        domain_ok(json!({})),
        domain_ok(json!({"rrs": null})),
        // A record without its name or its type.
        domain_ok(json!({"rrs": [{"rectype": "TXT", "content": "x"}]})),
        domain_ok(json!({"rrs": [{"subname": SUB, "content": "x"}]})),
        // Cut off in the middle.
        r#"{"result":"success","answer":{"domains":[{"dname":"example.org","result":"success","rrs":[{"subname":"#
            .to_owned(),
    ];
    for body in bodies {
        mock.faults()
            .push(Fault::on("POST", READ).respond(200, body.clone()));
        let e = add(&client, "BBB").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
        mock.faults()
            .push(Fault::on("POST", READ).respond(200, body.clone()));
        let e = remove(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    assert_eq!(writes(&mock), 0);
    assert_eq!(mock.control().txt("example.org", SUB), ["AAA"]);

    // A body cut off on the wire (the declared length is not delivered) is an error as well, and
    // so is one over the transport's size limit.
    mock.faults()
        .push(
            Fault::on("POST", READ)
                .times(3)
                .truncated_body(200, 1000, "{\"result\":\"succ"),
        );
    let e = add(&client, "BBB").await.unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::Transient | ErrorKind::Protocol),
        "{e:?}"
    );
    mock.faults()
        .push(Fault::on("POST", READ).oversized_body(200, 5 * 1024 * 1024));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// A 3xx answer is never followed, with or without a client certificate: the password in the
/// body must not go to the address it points to.
#[tokio::test]
async fn regru_redirect_is_refused_and_the_password_is_not_forwarded() {
    let (cert_pem, key_pem) = client_certificate();
    for with_certificate in [false, true] {
        for status in [301, 302, 307, 308] {
            let target = RegruMock::start(Seed::standard()).await;
            let mock = RegruMock::start(Seed::standard()).await;
            let creds = if with_certificate {
                RegruCredentials::with_client_certificate(
                    SecretString::from(PASSWORD.to_owned()),
                    SecretString::from(cert_pem.clone()),
                    SecretString::from(key_pem.clone()),
                )
            } else {
                credentials(PASSWORD)
            };
            let client = Regru::new(settings(mock.base_url()), creds, &context()).unwrap();
            mock.faults().push(
                Fault::on("POST", READ)
                    .always()
                    .redirect(status, &target.url("/api/regru2/zone/get_resource_records")),
            );
            let e = add(&client, "AAA").await.unwrap_err();
            match &e {
                Error::Rejected { status: got, .. } => assert_eq!(*got, Some(status)),
                other => panic!("{other:?}"),
            }
            assert!(!e.is_retryable());
            assert_eq!(mock.log().count(Some("POST"), READ), 1);
            assert_eq!(target.connections(), 0);
            assert!(target.log().is_empty());
        }
    }
}

// ---- Configuration -----------------------------------------------------------------------------

/// A client certificate and its key, generated for the test.
fn client_certificate() -> (String, String) {
    let certified = rcgen::generate_simple_self_signed(vec!["client.example".to_owned()]).unwrap();
    (certified.cert.pem(), certified.signing_key.serialize_pem())
}

#[tokio::test]
async fn regru_from_json_builds_the_client() {
    let mock = RegruMock::start(Seed::standard()).await;
    let ctx = context();
    let client = AnyProvider::from_json(
        ProviderId::Regru,
        &settings_json(&mock),
        &SecretString::from(format!("{{\"password\": \"{PASSWORD}\", \"other\": 1}}")),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Regru);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(report.credentials_verified && report.zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    let caps = client.capabilities();
    assert!(!caps.list_zones && caps.add_txt_value && caps.remove_txt_value);
}

/// The smallest configuration the shared test support uses to build a client without a request.
#[test]
fn regru_minimal_configuration_builds() {
    let client = AnyProvider::from_json(
        ProviderId::Regru,
        r#"{"username":"zw-test-user","base_url":"http://127.0.0.1:9/api/regru2"}"#,
        &SecretString::from(r#"{"password":"test-only-password"}"#.to_owned()),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Regru);
    // The defaults: the settings with only the required key use the provider's endpoint, which
    // the loopback-only context of the tests refuses.
    let e = AnyProvider::from_json(
        ProviderId::Regru,
        r#"{"username":"zw-test-user"}"#,
        &SecretString::from(r#"{"password":"test-only-password"}"#.to_owned()),
        &context(),
    )
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config);
}

/// A client certificate with its key builds; one without the other does not.
#[test]
fn regru_client_certificate_builds() {
    let (cert, key) = client_certificate();
    let ctx = context();
    let config = settings("http://127.0.0.1:9/api/regru2".to_owned());
    Regru::new(
        config.clone(),
        RegruCredentials::with_client_certificate(
            SecretString::from(PASSWORD.to_owned()),
            SecretString::from(cert.clone()),
            SecretString::from(key.clone()),
        ),
        &ctx,
    )
    .unwrap();
    let json = |value: serde_json::Value| SecretString::from(value.to_string());
    let settings = serde_json::to_string(&config).unwrap();
    AnyProvider::from_json(
        ProviderId::Regru,
        &settings,
        &json(json!({"password": PASSWORD, "tls_cert_pem": cert, "tls_key_pem": key})),
        &ctx,
    )
    .unwrap();
    for credentials in [
        json!({"password": PASSWORD, "tls_cert_pem": cert}),
        json!({"password": PASSWORD, "tls_key_pem": key}),
    ] {
        let e = AnyProvider::from_json(ProviderId::Regru, &settings, &json(credentials), &ctx)
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config);
        assert!(format!("{e}").contains("tls_cert_pem"), "{e}");
    }
}

/// Configuration errors are `Config`, name the key and never repeat a value. A malformed key is
/// one fixed text, whatever it contained.
#[test]
fn regru_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || json!({ "username": "u", "base_url": "http://127.0.0.1:1/api/regru2" });
    let with = |key: &str, value: Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let password = json!({"password": "pw"}).to_string();
    let (cert, key) = client_certificate();
    let cases = [
        (json!({"base_url": "http://127.0.0.1:1/x"}), password.clone(), "username"),
        (with("username", json!("")), password.clone(), "username"),
        (with("username", json!("a\nb")), password.clone(), "username"),
        (
            with("min_request_interval_ms", json!(60_001)),
            password.clone(),
            "min_request_interval_ms",
        ),
        (
            with(canary, json!(canary)),
            password.clone(),
            "unknown keys",
        ),
        (
            with("base_url", json!(format!("http://example.com/{canary}"))),
            password.clone(),
            "base_url",
        ),
        (
            with("base_url", json!(format!("https://u:{canary}@api.example.org"))),
            password.clone(),
            "base_url",
        ),
        (
            base(),
            json!({"password": 5, canary: canary}).to_string(),
            "password",
        ),
        (base(), json!({"secret": canary}).to_string(), "password"),
        (base(), json!({"password": ""}).to_string(), "password"),
        (
            base(),
            json!({"password": "pw", "tls_cert_pem": cert}).to_string(),
            "tls_cert_pem",
        ),
        (
            base(),
            json!({"password": "pw", "tls_cert_pem": cert, "tls_key_pem": format!("-----BEGIN PRIVATE KEY-----\n{canary}\n-----END PRIVATE KEY-----\n")}).to_string(),
            "client certificate key",
        ),
        (
            base(),
            json!({"password": "pw", "tls_cert_pem": canary, "tls_key_pem": key}).to_string(),
            "client certificate",
        ),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::Regru,
            &settings.to_string(),
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{key}: {e:?}");
        let text = format!("{e} | {e:?}");
        assert!(key == "unknown keys" || text.contains(key), "{key}: {text}");
        assert!(!text.contains(canary), "{key}: {text}");
    }
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round; the defaults of the metadata are those of the settings type.
#[test]
fn regru_config_keys_match_metadata() {
    let meta = ProviderId::Regru.meta();
    let settings = serde_json::to_value(RegruConfig::new("u".to_owned())).unwrap();
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
    assert_eq!(secret, ["password", "tls_cert_pem", "tls_key_pem"]);
    for field in meta.fields.iter().filter(|f| f.default.is_some()) {
        let value = &settings[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
    }
    let caps = &meta.capabilities;
    assert!(!caps.list_zones && caps.add_txt_value && caps.remove_txt_value);
    assert!(!caps.list_rrsets && !caps.get_rrset && !caps.set_rrset && !caps.delete_rrset);
    assert!(!caps.ttl.accepts(60));
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
async fn live_regru_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_REGRU_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_REGRU_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_REGRU_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::Regru,
            &settings,
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap(),
    );
    let tag = random_u64();
    let name = zone.prepend(&format!("_zw-live-{tag:016x}")).unwrap();
    // The API accepts only alphanumeric characters in the text of a TXT record.
    let values = [
        txt(&format!("zwlive{tag:016x}a")),
        txt(&format!("zwlive{tag:016x}b")),
    ];

    let body = {
        let (client, zone, name, values) =
            (client.clone(), zone.clone(), name.clone(), values.clone());
        tokio::spawn(async move {
            let report = client.check(std::slice::from_ref(&zone)).await.unwrap();
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
