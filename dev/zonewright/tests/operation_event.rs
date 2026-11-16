//! The operation event (design section 5.6): one `DEBUG` event with target
//! `zonewright::operation` per call of a `Provider` method, with the typed client and through
//! `AnyProvider` alike, carrying names and the outcome, and never a value or the provider's
//! error code.
//!
//! Exercised for two HTTP clients of different API shapes (Cloudflare, per record; Selectel v2,
//! per rrset) and for the RFC 2136 client. That every client routes every method through the
//! event is a source scan of `conformance.rs`.
#![cfg(any(feature = "cloudflare", feature = "selectel_v2", feature = "rfc2136"))]
// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use zonewright::{AnyProvider, DomainName, Error, Provider, Txt};

use common::dn;
use common::echo::{Captured, LogCapture};

/// The target of the operation event.
const TARGET: &str = "zonewright::operation";

/// The fields every operation event carries.
const ALWAYS: [&str; 5] = ["message", "provider", "operation", "outcome", "elapsed_ms"];

/// The documented fields of the event of `operation`, sorted: [`ALWAYS`], plus `zones` for
/// `check`, `zone` for `list_rrsets`, and `zone`, `name` and `rtype` for the operations on one
/// rrset. There is no `code`.
fn documented_fields(operation: &str) -> Vec<&'static str> {
    let mut fields = ALWAYS.to_vec();
    match operation {
        "check" => fields.push("zones"),
        "list_zones" => {}
        "list_rrsets" => fields.push("zone"),
        _ => fields.extend(["zone", "name", "rtype"]),
    }
    fields.sort_unstable();
    fields
}

/// The TXT value of every test: distinctive, so that a field that held it would show.
const VALUE: &str = "zwOperationEventValue7";

/// The owner name the tests write to.
const NAME: &str = "_acme-challenge.example.org";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn value() -> Txt {
    Txt::new(VALUE).unwrap()
}

/// The operation events captured so far, after checking their shape: level `DEBUG`, the fixed
/// message, exactly the documented fields for the operation (no `code` among them),
/// `elapsed_ms` a number, and the TXT value in no field.
fn operation_events(capture: &LogCapture) -> Vec<Captured> {
    let events: Vec<Captured> = capture
        .entries()
        .into_iter()
        .filter(|e| e.target == TARGET && !e.span)
        .collect();
    for event in &events {
        assert_eq!(event.level, tracing::Level::DEBUG, "{event}");
        assert_eq!(
            event.field("message"),
            Some("provider operation"),
            "{event}"
        );
        assert_eq!(event.field("code"), None, "{event}");
        let mut names = event.names();
        names.sort_unstable();
        let operation = event.field("operation").unwrap_or_default();
        assert_eq!(names, documented_fields(operation), "{event}");
        assert!(
            event
                .field("elapsed_ms")
                .is_some_and(|ms| ms.parse::<u64>().is_ok()),
            "{event}"
        );
        for (field, text) in &event.fields {
            assert!(
                !text.contains(VALUE),
                "field {field} holds the value: {event}"
            );
        }
    }
    events
}

/// Asserts that exactly one operation event was captured since `before` events, and returns it.
fn one_event(capture: &LogCapture, before: usize) -> Captured {
    let events = operation_events(capture);
    assert_eq!(
        events.len(),
        before + 1,
        "expected one more operation event:\n{}",
        capture.text()
    );
    events.last().cloned().unwrap()
}

/// Asserts the names of an `add_txt_value` at [`NAME`] in `example.org` by `provider`.
fn assert_add_names(event: &Captured, provider: &str) {
    assert_eq!(event.field("provider"), Some(provider), "{event}");
    assert_eq!(event.field("operation"), Some("add_txt_value"), "{event}");
    assert_eq!(event.field("zone"), Some("example.org."), "{event}");
    assert_eq!(
        event.field("name"),
        Some("_acme-challenge.example.org."),
        "{event}"
    );
    assert_eq!(event.field("rtype"), Some("TXT"), "{event}");
    assert_eq!(event.field("zones"), None, "{event}");
}

/// Runs an `add_txt_value` that succeeds, through the typed client and through `AnyProvider`,
/// and asserts one event for each with `outcome = ok`.
async fn assert_add_ok<P: Provider>(capture: &LogCapture, client: P, provider: &str)
where
    AnyProvider: From<P>,
{
    let before = operation_events(capture).len();
    client
        .add_txt_value(&zone(), &name(), &value(), None)
        .await
        .unwrap();
    let event = one_event(capture, before);
    assert_add_names(&event, provider);
    assert_eq!(event.field("outcome"), Some("ok"), "{event}");

    // Through `AnyProvider`: the client's event, and no second one.
    let any = AnyProvider::from(client);
    let before = operation_events(capture).len();
    any.add_txt_value(&zone(), &name(), &value(), None)
        .await
        .unwrap();
    let event = one_event(capture, before);
    assert_add_names(&event, provider);
    assert_eq!(event.field("outcome"), Some("ok"), "{event}");
}

/// Asserts that the last call was refused with the provider code `code` on the error, and that
/// exactly one event reports it with the error's kind as `outcome` and without the code, which
/// comes from the response and stays on the error.
fn assert_refusal(
    capture: &LogCapture,
    before: usize,
    err: &Error,
    provider: &str,
    code: Option<&str>,
) {
    assert_eq!(err.provider_code().map(|c| c.as_str()), code, "{err:?}");
    let event = one_event(capture, before);
    assert_add_names(&event, provider);
    assert_eq!(event.field("outcome"), Some(err.kind().as_str()), "{event}");
    if let Some(code) = code {
        for (field, text) in event.fields.iter().filter(|(f, _)| f != "elapsed_ms") {
            assert!(
                !text.contains(code),
                "field {field} holds the code: {event}"
            );
        }
    }
}

#[cfg(feature = "cloudflare")]
mod cloudflare {
    use secrecy::SecretString;
    use zonewright::providers::cloudflare::{Cloudflare, CloudflareConfig, CloudflareCredentials};
    use zonewright::{ErrorKind, Provider};
    use zonewright_mock::Fault;
    use zonewright_mock::cloudflare::{CloudflareMock, Seed};

    use super::common::context;
    use super::common::echo::LogCapture;
    use super::{assert_add_ok, assert_refusal, name, one_event, operation_events, value, zone};

    const RECORDS: &str = "/client/v4/zones/*/dns_records";

    fn client(mock: &CloudflareMock) -> Cloudflare {
        let mut config = CloudflareConfig::default();
        config.base_url = mock.base_url();
        let credentials = CloudflareCredentials::new(SecretString::from("cf-test-token"));
        Cloudflare::new(config, credentials, &context()).unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cloudflare_add_emits_one_operation_event() {
        let (capture, _guard) = LogCapture::install();
        let mock = CloudflareMock::start(Seed::standard()).await;
        assert_add_ok(&capture, client(&mock), "cloudflare").await;
    }

    /// A refusal with Cloudflare's error code: `outcome` is the kind; the code stays on the error.
    #[tokio::test(flavor = "current_thread")]
    async fn cloudflare_refusal_reports_the_kind_only() {
        let (capture, _guard) = LogCapture::install();
        let mock = CloudflareMock::start(Seed::standard()).await;
        let client = client(&mock);
        let body = r#"{"success":false,"errors":[{"code":81058,"message":"An identical record already exists."}],"messages":[],"result":null}"#;
        mock.faults()
            .push(Fault::on("POST", RECORDS).respond(400, body));
        let before = operation_events(&capture).len();
        let err = client
            .add_txt_value(&zone(), &name(), &value(), None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Rejected, "{err:?}");
        assert_refusal(&capture, before, &err, "cloudflare", Some("81058"));
    }

    /// `check` reports the number of zones and no zone name; `list_zones` neither.
    #[tokio::test(flavor = "current_thread")]
    async fn cloudflare_check_and_list_zones_report_no_zone() {
        let (capture, _guard) = LogCapture::install();
        let mock = CloudflareMock::start(Seed::standard()).await;
        let client = client(&mock);
        let before = operation_events(&capture).len();
        client.check(&[zone(), zone()]).await.unwrap();
        let event = one_event(&capture, before);
        assert_eq!(event.field("operation"), Some("check"), "{event}");
        assert_eq!(event.field("zones"), Some("2"), "{event}");
        assert_eq!(event.field("zone"), None, "{event}");
        assert_eq!(event.field("outcome"), Some("ok"), "{event}");
        let before = operation_events(&capture).len();
        client.list_zones().await.unwrap();
        let event = one_event(&capture, before);
        assert_eq!(event.field("operation"), Some("list_zones"), "{event}");
        for field in ["zones", "zone", "name", "rtype"] {
            assert_eq!(event.field(field), None, "{event}");
        }
    }
}

#[cfg(feature = "selectel_v2")]
mod selectel_v2 {
    use secrecy::SecretString;
    use zonewright::providers::selectel_v2::{SelectelV2, SelectelV2Config, SelectelV2Credentials};
    use zonewright::{ErrorKind, Provider};
    use zonewright_mock::Fault;
    use zonewright_mock::selectel_v2::{Seed, SelectelV2Mock};

    use super::common::context;
    use super::common::echo::LogCapture;
    use super::{assert_add_ok, assert_refusal, name, operation_events, value, zone};

    const RRSETS: &str = "/domains/v2/zones/*/rrset";

    fn client(mock: &SelectelV2Mock) -> SelectelV2 {
        let mut config = SelectelV2Config::new("123456".into(), "zw-test-user".into());
        config.project_id = Some("project-a".into());
        config.base_url = mock.base_url();
        config.auth_url = mock.auth_url();
        let credentials = SelectelV2Credentials::new(SecretString::from("test-only-password"));
        SelectelV2::new(config, credentials, &context()).unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn selectel_v2_add_emits_one_operation_event() {
        let (capture, _guard) = LogCapture::install();
        let mock = SelectelV2Mock::start(Seed::standard()).await;
        assert_add_ok(&capture, client(&mock), "selectel_v2").await;
    }

    /// A refusal without a provider code: `outcome` is the kind.
    #[tokio::test(flavor = "current_thread")]
    async fn selectel_v2_refusal_reports_kind() {
        let (capture, _guard) = LogCapture::install();
        let mock = SelectelV2Mock::start(Seed::standard()).await;
        let client = client(&mock);
        mock.faults()
            .push(Fault::on("POST", RRSETS).respond(422, r#"{"error":"validation error"}"#));
        let before = operation_events(&capture).len();
        let err = client
            .add_txt_value(&zone(), &name(), &value(), None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Rejected, "{err:?}");
        assert_refusal(&capture, before, &err, "selectel_v2", None);
    }
}

#[cfg(feature = "rfc2136")]
mod rfc2136 {
    use base64::Engine as _;
    use secrecy::SecretString;
    use zonewright::providers::rfc2136::{Rfc2136, Rfc2136Config, Rfc2136Credentials};
    use zonewright::{ErrorKind, Provider};
    use zonewright_mock::rfc2136::{FORMERR, Fault, Op, Rfc2136Mock, STANDARD_SECRET, Seed};

    use super::common::context;
    use super::common::echo::LogCapture;
    use super::{assert_add_ok, assert_refusal, name, one_event, operation_events, value, zone};

    fn client(mock: &Rfc2136Mock) -> Rfc2136 {
        let secret = base64::engine::general_purpose::STANDARD.encode(STANDARD_SECRET);
        Rfc2136::new(
            Rfc2136Config::new(mock.server(), "zw-test-key".to_owned()),
            Rfc2136Credentials::new(SecretString::from(secret)),
            &context(),
        )
        .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rfc2136_add_emits_one_operation_event() {
        let (capture, _guard) = LogCapture::install();
        let mock = Rfc2136Mock::start(Seed::standard()).await;
        assert_add_ok(&capture, client(&mock), "rfc2136").await;
    }

    /// A refusal by RCODE: `outcome` is the kind; the RCODE's mnemonic stays on the error.
    #[tokio::test(flavor = "current_thread")]
    async fn rfc2136_refusal_reports_the_kind_only() {
        let (capture, _guard) = LogCapture::install();
        let mock = Rfc2136Mock::start(Seed::standard()).await;
        let client = client(&mock);
        mock.control().push(Fault::on(Op::Update).rcode(FORMERR));
        let before = operation_events(&capture).len();
        let err = client
            .add_txt_value(&zone(), &name(), &value(), None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Rejected, "{err:?}");
        assert_refusal(&capture, before, &err, "rfc2136", Some("FORMERR"));
    }

    /// An operation the client does not support is reported as well, with `outcome` equal to
    /// `unsupported`.
    #[tokio::test(flavor = "current_thread")]
    async fn rfc2136_unsupported_operation_is_reported() {
        let (capture, _guard) = LogCapture::install();
        let mock = Rfc2136Mock::start(Seed::standard()).await;
        let client = client(&mock);
        let before = operation_events(&capture).len();
        let err = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported, "{err:?}");
        let event = one_event(&capture, before);
        assert_eq!(event.field("operation"), Some("list_rrsets"), "{event}");
        assert_eq!(event.field("zone"), Some("example.org."), "{event}");
        assert_eq!(event.field("outcome"), Some("unsupported"), "{event}");
    }
}
