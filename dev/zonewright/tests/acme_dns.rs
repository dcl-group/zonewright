//! Tests of the acme-dns client (`acme_dns`) against its mock.
#![cfg(feature = "acme_dns")]
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
use zonewright::providers::acme_dns::{AcmeDns, AcmeDnsConfig, AcmeDnsCredentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DomainName, Error, ErrorKind, Expect, Provider, ProviderId,
    RecordType, RrSet, Ttl, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::acme_dns::{Account, AcmeDnsMock, Seed};
use zonewright_mock::echo::EchoServer;

use common::echo::{CANARY_KEY, CANARY_TOKEN, LogCapture, REDACTED, assert_clean, dialects};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The acme-dns server's own domain: the provider's zone.
const ZONE: &str = "auth.example.org";

/// The path of the one request the API has.
const UPDATE: &str = "/update";

fn zone() -> DomainName {
    dn(ZONE)
}

/// The name of registration `i`: its `fulldomain`.
fn name(mock: &AcmeDnsMock, i: usize) -> DomainName {
    dn(&mock.control().fulldomain(i))
}

/// A value the server accepts: 43 characters of the base64url alphabet.
fn value(c: char) -> String {
    c.to_string().repeat(43)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

fn config(base_url: String) -> AcmeDnsConfig {
    AcmeDnsConfig::new(base_url)
}

fn credentials(registrations: String) -> AcmeDnsCredentials {
    AcmeDnsCredentials::new(SecretString::from(registrations))
}

fn client_in(mock: &AcmeDnsMock, ctx: &Context) -> AcmeDns {
    AcmeDns::new(
        config(mock.base_url()),
        credentials(mock.control().registrations_text()),
        ctx,
    )
    .unwrap()
}

async fn setup() -> (AcmeDnsMock, AcmeDns) {
    let mock = AcmeDnsMock::start(Seed::standard()).await;
    let client = client_in(&mock, &context());
    (mock, client)
}

/// Adds `value` at the name of registration `i`.
async fn add(
    mock: &AcmeDnsMock,
    client: &impl Provider,
    i: usize,
    value: &str,
) -> Result<AddOutcome, Error> {
    client
        .add_txt_value(&zone(), &name(mock, i), &txt(value), None)
        .await
}

/// Number of update requests the mock received.
fn updates(mock: &AcmeDnsMock) -> usize {
    mock.log().count(Some("POST"), UPDATE)
}

// ---- Secrets (design section 12.2) -------------------------------------------------------------

/// Neither the client type nor the credentials type can be printed with `Display` or serialized.
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

assert_not_impl!(AcmeDns: std::fmt::Display, serde::Serialize);
assert_not_impl!(AcmeDnsCredentials: std::fmt::Display, serde::Serialize);

/// Two registrations that carry `username` and `password`. A canary is put in one field at a
/// time, so that each field is shown to be covered by the scrubber on its own.
fn registrations_with(username: &str, password: &str) -> String {
    serde_json::json!([
        {
            "username": username, "password": password,
            "subdomain": "aaaa", "fulldomain": "aaaa.auth.example.org",
        },
        {
            "username": username, "password": password,
            "subdomain": "bbbb", "fulldomain": "bbbb.auth.example.org",
        },
    ])
    .to_string()
}

/// The credential pairs of the echo tests with the canary each one is about: the user name, then
/// the key.
fn canary_pairs() -> [(String, String, &'static str); 2] {
    [
        (
            CANARY_TOKEN.into(),
            "plain-key-0123456789".into(),
            CANARY_TOKEN,
        ),
        (
            "plain-user-0123456789".into(),
            CANARY_KEY.into(),
            CANARY_KEY,
        ),
    ]
}

fn echo_client(echo: &EchoServer, username: &str, password: &str) -> AcmeDns {
    AcmeDns::new(
        config(echo.base_url()),
        credentials(registrations_with(username, password)),
        &context(),
    )
    .unwrap()
}

/// `check` and an update for each registration against an echo that quotes every request back:
/// no canary in any error, `ZoneCheck::detail` or `Debug`, and the write's error shows the
/// redaction.
async fn echo_round(label: &str, client: &AcmeDns, canary: &str) {
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
    for (label, name) in [
        ("first registration", "aaaa.auth.example.org"),
        ("second registration", "bbbb.auth.example.org"),
    ] {
        let result = client
            .add_txt_value(&zone(), &dn(name), &txt(&value('E')), None)
            .await;
        let text = match result {
            Ok(outcome) => panic!("{label}: the echo accepted a write: {outcome:?}"),
            Err(e) => format!("{e} | {e:?}"),
        };
        assert!(
            text.contains(REDACTED),
            "{label}: the echo did not reach the error: {text}"
        );
        texts.push(text);
    }
    for text in &texts {
        assert_clean(label, text, &[canary]);
    }
}

/// `check` and the update, for every dialect and every refusal. The update of a value is the one
/// kind of request the client makes (`check` sends nothing); the API has no token exchange and no
/// read. A 429 is not in the list: its error carries no text of the answer (its handling is in
/// `acme_dns_writes_are_sent_once`).
#[tokio::test]
async fn acme_dns_secret_echo() {
    for dialect in dialects() {
        for status in [400, 401, 403, 404, 500] {
            let label = format!("{} {:?} {status}", dialect.name, dialect.spelling);
            for (username, password, canary) in canary_pairs() {
                let echo = dialect.echo(status).start().await;
                let client = echo_client(&echo, &username, &password);
                echo_round(&label, &client, canary).await;
                assert!(echo.api_requests() > 0, "{label}: the API was not reached");
                // The write itself reached the echo.
                let wrote = echo.log().entries().iter().any(|r| {
                    r.body_json()
                        .is_some_and(|b| b["txt"] == serde_json::json!(value('E')))
                });
                assert!(wrote, "{label}: no update with a value reached the echo");
            }
        }
    }
}

/// A `TRACE` capture over a success, a displacing send, repeated refusals and a 500: the
/// transport's events are there, and neither a credential nor a value is.
#[tokio::test(flavor = "current_thread")]
async fn acme_dns_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.any_credential_form = true;
    seed.accounts = vec![Account {
        username: CANARY_TOKEN.into(),
        password: CANARY_KEY.into(),
        subdomain: "aaaa".into(),
    }];
    let mock = AcmeDnsMock::start(seed).await;
    let client = client_in(&mock, &context());
    let name = dn(&mock.control().fulldomain(0));
    let mut texts = Vec::new();

    let values = ['A', 'B', 'C', 'D'].map(value);
    for v in &values[..3] {
        client
            .add_txt_value(&zone(), &name, &txt(v), None)
            .await
            .unwrap();
    }

    mock.faults().push(Fault::on("POST", UPDATE).status(401));
    let e = client
        .add_txt_value(&zone(), &name, &txt(&values[3]), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    mock.faults().push(Fault::on("POST", UPDATE).status(500));
    let e = client
        .add_txt_value(&zone(), &name, &txt(&values[3]), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    let wrong = AcmeDns::new(
        config(mock.base_url()),
        credentials(
            serde_json::json!([{
                "username": CANARY_KEY, "password": CANARY_TOKEN,
                "subdomain": "aaaa", "fulldomain": mock.control().fulldomain(0),
            }])
            .to_string(),
        ),
        &context(),
    )
    .unwrap();
    let e = wrong
        .add_txt_value(&zone(), &name, &txt(&values[3]), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?} | {wrong:?} | {client:?}"));

    let entries = capture.entries();
    assert!(
        entries.iter().any(|e| e.target == "zonewright::http"),
        "the capture holds no transport event"
    );
    assert!(
        entries
            .iter()
            .any(|e| e.level == tracing::Level::WARN && e.target.contains("acme_dns")),
        "the displacing send logged no warning"
    );
    texts.push(capture.text());
    for text in &texts {
        assert_clean(
            "acme_dns logs and errors",
            text,
            &[CANARY_TOKEN, CANARY_KEY],
        );
        for v in &values {
            assert!(
                !text.contains(v.as_str()),
                "a TXT value reached a log or an error"
            );
        }
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely ends
/// with the zone's text, and a sibling zone.
#[tokio::test]
async fn acme_dns_name_outside_zone_sends_nothing() {
    let (mock, client) = setup().await;
    let own = name(&mock, 0);
    let v = txt(&value('A'));
    let cases = [
        (zone(), dn("_acme-challenge.example.org")),
        (zone(), dn(&format!("evil{ZONE}"))),
        (zone(), dn("auth.example.org.example.net")),
        (dn("other.example.org"), own.clone()),
        (dn("example.com"), own.clone()),
    ];
    for (zone, name) in cases {
        let e = client
            .add_txt_value(&zone, &name, &v, None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NameOutsideZone, "{zone} {name}: {e:?}");
    }
    assert!(mock.log().is_empty());
    assert_eq!(mock.control().stored(), 0);
}

/// A name inside the zone that is not the `fulldomain` of a configured registration is
/// `InvalidInput`, not `Config`, and nothing is sent: the base name, the challenge name itself (the
/// application forgot to follow the CNAME), a name below a `fulldomain` and a registration the
/// client was not given.
#[tokio::test]
async fn acme_dns_unregistered_name_sends_nothing() {
    let mock = AcmeDnsMock::start(Seed::numbered(3)).await;
    // The client knows the first two registrations only.
    let registrations: Vec<serde_json::Value> =
        (0..2).map(|i| mock.control().register_json(i)).collect();
    let client = AcmeDns::new(
        config(mock.base_url()),
        credentials(serde_json::Value::Array(registrations).to_string()),
        &context(),
    )
    .unwrap();
    let v = txt(&value('A'));
    let own = mock.control().fulldomain(0);
    let names = [
        dn(ZONE),
        dn(&format!("_acme-challenge.{ZONE}")),
        dn(&format!("x.{own}")),
        dn(&mock.control().fulldomain(2)),
    ];
    for name in names {
        let e = client
            .add_txt_value(&zone(), &name, &v, None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{name}: {e:?}");
    }
    assert!(mock.log().is_empty());
    // The registered names work, in any letter case.
    let upper = dn(&own.to_uppercase());
    client
        .add_txt_value(&zone(), &upper, &v, None)
        .await
        .unwrap();
    assert_eq!(updates(&mock), 1);
}

/// A value the server would refuse, a requested TTL and a root or wildcard zone are refused
/// before any request.
#[tokio::test]
async fn acme_dns_invalid_input_sends_nothing() {
    let (mock, client) = setup().await;
    let own = name(&mock, 0);
    let invalid = [
        value('A')[..42].to_owned(),
        format!("{}A", value('A')),
        format!("{}+", &value('A')[..42]),
        format!("{}=", &value('A')[..42]),
        format!("{} ", &value('A')[..42]),
        format!("{}\u{e9}", &value('A')[..42]),
        "\u{e9}".repeat(43),
        String::new(),
        "x".to_owned(),
    ];
    for v in invalid {
        let Ok(v) = Txt::new(v.clone()) else {
            continue;
        };
        let e = client
            .add_txt_value(&zone(), &own, &v, None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{v:?}: {e:?}");
    }
    let e = client
        .add_txt_value(
            &zone(),
            &own,
            &txt(&value('A')),
            Some(Ttl::from_secs(60).unwrap()),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    for zone in [DomainName::root(), dn("*.auth.example.org")] {
        let e = client
            .add_txt_value(&zone, &own, &txt(&value('A')), None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{zone}: {e:?}");
    }
    assert!(mock.log().is_empty());
    // The alphabet's edges are accepted.
    let edges = format!("{}-_09zZ", &value('A')[..37]);
    assert_eq!(
        client
            .add_txt_value(&zone(), &own, &txt(&edges), None)
            .await
            .unwrap(),
        AddOutcome::Accepted
    );
}

/// Every add is `Accepted`, and a repeat of a value this process sent writes nothing: the server
/// would store it in the other slot and displace its neighbor.
#[tokio::test]
async fn acme_dns_add_is_idempotent() {
    let (mock, client) = setup().await;
    let control = mock.control().clone();
    let sub = control.subdomain(0);
    let (a, b) = (value('A'), value('B'));

    assert_eq!(
        add(&mock, &client, 0, &a).await.unwrap(),
        AddOutcome::Accepted
    );
    assert_eq!(updates(&mock), 1);
    assert_eq!(
        add(&mock, &client, 0, &b).await.unwrap(),
        AddOutcome::Accepted
    );
    assert_eq!(updates(&mock), 2);
    assert_eq!(control.values(&sub), [a.clone(), b.clone()]);

    // Repeats: no write, still `Accepted`, never `AlreadyPresent`.
    for v in [&a, &b, &a] {
        assert_eq!(
            add(&mock, &client, 0, v).await.unwrap(),
            AddOutcome::Accepted
        );
    }
    assert_eq!(updates(&mock), 2);
    assert_eq!(control.values(&sub), [a, b]);
}

/// The value lands in the registration whose `fulldomain` is the name, with that registration's
/// credentials and the request shape of the documentation.
#[tokio::test]
async fn acme_dns_add_writes_to_the_matching_registration() {
    let (mock, client) = setup().await;
    let control = mock.control().clone();
    add(&mock, &client, 1, &value('C')).await.unwrap();
    assert_eq!(control.values(&control.subdomain(1)), [value('C')]);
    assert!(control.values(&control.subdomain(0)).is_empty());

    let request = mock.log().last().unwrap();
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.path, UPDATE);
    assert_eq!(request.query, None);
    let register = control.register_json(1);
    assert_eq!(request.header("x-api-user"), register["username"].as_str());
    assert_eq!(request.header("x-api-key"), register["password"].as_str());
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(
        request.body_json().unwrap(),
        serde_json::json!({ "subdomain": control.subdomain(1), "txt": value('C') })
    );
    // The credentials went in headers only.
    assert!(
        !request
            .body_str()
            .contains(register["password"].as_str().unwrap())
    );
}

/// The server keeps two values: a third displaces the oldest, which the memory forgets, so a
/// repeat of it is sent; and the displacement is logged at `WARN`, without the value.
#[tokio::test(flavor = "current_thread")]
async fn acme_dns_third_value_displaces_the_oldest() {
    let (capture, _guard) = LogCapture::install();
    let (mock, client) = setup().await;
    let control = mock.control().clone();
    let sub = control.subdomain(0);
    let warnings = || {
        capture
            .entries()
            .iter()
            .filter(|e| e.level == tracing::Level::WARN && e.target.contains("acme_dns"))
            .count()
    };
    for c in ['A', 'B'] {
        add(&mock, &client, 0, &value(c)).await.unwrap();
    }
    assert_eq!(warnings(), 0, "nothing was displaced yet");
    add(&mock, &client, 0, &value('C')).await.unwrap();
    assert_eq!(control.values(&sub), [value('B'), value('C')]);
    assert_eq!(warnings(), 1);
    // `A` was displaced: the repeat sends it, and displaces `B`.
    assert_eq!(
        add(&mock, &client, 0, &value('A')).await.unwrap(),
        AddOutcome::Accepted
    );
    assert_eq!(updates(&mock), 4);
    assert_eq!(control.values(&sub), [value('A'), value('C')]);
    assert_eq!(warnings(), 2);
    assert!(!capture.text().contains(&value('B')));
}

/// The memory belongs to the context: a client built again from it (after a settings change)
/// does not repeat a value, and a client of another context, which has no memory, does.
#[tokio::test]
async fn acme_dns_memory_belongs_to_the_context() {
    let mock = AcmeDnsMock::start(Seed::standard()).await;
    let ctx = context();
    let first = client_in(&mock, &ctx);
    add(&mock, &first, 0, &value('A')).await.unwrap();
    assert_eq!(updates(&mock), 1);

    let rebuilt = client_in(&mock, &ctx);
    add(&mock, &rebuilt, 0, &value('A')).await.unwrap();
    assert_eq!(updates(&mock), 1, "the rebuilt client remembers");

    let foreign = client_in(&mock, &context());
    add(&mock, &foreign, 0, &value('A')).await.unwrap();
    assert_eq!(updates(&mock), 2, "another context has no memory");
}

/// A value the memory has forgotten is sent again after 15 minutes. The clock is the runtime's;
/// the test moves it while no request is in flight (a paused clock would let a request's timeout
/// run out while the runtime waits for the mock).
#[tokio::test(flavor = "current_thread")]
async fn acme_dns_memory_expires() {
    let (mock, client) = setup().await;
    add(&mock, &client, 0, &value('A')).await.unwrap();
    for (seconds, sent) in [(15 * 60 - 5, 1), (10, 2)] {
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(seconds)).await;
        tokio::time::resume();
        add(&mock, &client, 0, &value('A')).await.unwrap();
        assert_eq!(updates(&mock), sent, "after {seconds} s more");
    }
}

/// The memory holds at most 1,024 names: with 1,030 registrations the least recently used name
/// is forgotten and its value is sent again, while a recently used one is not.
#[tokio::test]
async fn acme_dns_memory_is_bounded() {
    let mock = AcmeDnsMock::start(Seed::numbered(1030)).await;
    let client = client_in(&mock, &context());
    for i in 0..1030 {
        add(&mock, &client, i, &value('A')).await.unwrap();
    }
    assert_eq!(updates(&mock), 1030);
    // Names 6 to 1029 are remembered; the first six were dropped as the least recently used.
    add(&mock, &client, 1029, &value('A')).await.unwrap();
    add(&mock, &client, 6, &value('A')).await.unwrap();
    assert_eq!(updates(&mock), 1030);
    add(&mock, &client, 0, &value('A')).await.unwrap();
    assert_eq!(updates(&mock), 1031);
}

/// Two adds of one value from two clients of one context, with the first write delayed, send it
/// once: the second waits for the name's lock and then finds the value confirmed. Two adds of
/// different values both end up stored.
#[tokio::test]
async fn acme_dns_concurrent_adds_are_serialized() {
    let mock = AcmeDnsMock::start(Seed::standard()).await;
    let ctx = context();
    let (one, two) = (client_in(&mock, &ctx), client_in(&mock, &ctx));
    let control = mock.control().clone();
    let sub = control.subdomain(0);

    mock.faults().push(
        Fault::on("POST", UPDATE)
            .delay(Duration::from_millis(300))
            .pass(),
    );
    let (va, vb, vc) = (value('A'), value('B'), value('C'));
    let (a, b) = tokio::join!(add(&mock, &one, 0, &va), add(&mock, &two, 0, &va));
    assert_eq!(a.unwrap(), AddOutcome::Accepted);
    assert_eq!(b.unwrap(), AddOutcome::Accepted);
    assert_eq!(updates(&mock), 1, "the value was sent twice");
    assert_eq!(control.values(&sub), [value('A')]);

    mock.faults().push(
        Fault::on("POST", UPDATE)
            .delay(Duration::from_millis(300))
            .pass(),
    );
    let (b, c) = tokio::join!(add(&mock, &one, 0, &vb), add(&mock, &two, 0, &vc));
    b.unwrap();
    c.unwrap();
    assert_eq!(updates(&mock), 3);
    // `A` is displaced by the second of the two, whichever it was.
    assert_eq!(control.values(&sub), [value('B'), value('C')]);
}

/// Only the operations the API has are offered; every other returns `Unsupported` before any
/// request, a removal included, however wrong its arguments are.
#[tokio::test]
async fn acme_dns_unsupported_operations_send_nothing() {
    let (mock, client) = setup().await;
    let own = name(&mock, 0);
    let v = txt(&value('A'));
    let set = RrSet::new(own.clone(), RecordType::TXT, None, [v.to_data().unwrap()]).unwrap();
    // A name outside the zone: the unsupported operation is reported first.
    let outside = dn("_acme-challenge.example.net");
    let errors = [
        client.list_zones().await.unwrap_err(),
        client.list_rrsets(&zone()).await.unwrap_err(),
        client
            .get_rrset(&zone(), &own, RecordType::TXT)
            .await
            .unwrap_err(),
        client
            .set_rrset(&zone(), &set, Expect::Any)
            .await
            .unwrap_err(),
        client
            .delete_rrset(&zone(), &own, RecordType::TXT, Expect::Any)
            .await
            .unwrap_err(),
        client
            .remove_txt_value(&zone(), &own, &v)
            .await
            .unwrap_err(),
        client
            .remove_txt_value(&zone(), &outside, &v)
            .await
            .unwrap_err(),
    ];
    for e in errors {
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e:?}");
    }
    // A removal that did not happen must not look like one that did, after an add either.
    add(&mock, &client, 0, &value('A')).await.unwrap();
    let before = updates(&mock);
    let e = client
        .remove_txt_value(&zone(), &own, &v)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e:?}");
    assert_eq!(updates(&mock), before);
    assert_eq!(mock.log().len(), before);
    let caps = client.capabilities();
    assert!(caps.add_txt_value && !caps.remove_txt_value && !caps.list_zones);
}

/// The update is a write and is sent once whatever happens: a 502, a 429, a 401, a refused
/// redirect and a dropped connection are the operation's error, with exactly one request each.
#[tokio::test]
async fn acme_dns_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let a = value('A');
    let mut expected = 0;
    let faults: [(Fault, ErrorKind); 5] = [
        (Fault::on("POST", UPDATE).status(502), ErrorKind::Transient),
        (
            Fault::on("POST", UPDATE).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("POST", UPDATE).status(401), ErrorKind::Auth),
        (
            Fault::on("POST", UPDATE).redirect(307, "http://127.0.0.1:9/update"),
            ErrorKind::Rejected,
        ),
        (
            Fault::on("POST", UPDATE).drop_connection(),
            ErrorKind::Transient,
        ),
    ];
    for (fault, kind) in faults {
        mock.faults().push(fault);
        let e = add(&mock, &client, 0, &a).await.unwrap_err();
        assert_eq!(e.kind(), kind, "{e:?}");
        expected += 1;
        assert_eq!(
            updates(&mock),
            expected,
            "{kind:?}: the update was repeated"
        );
        assert!(
            mock.control()
                .values(&mock.control().subdomain(0))
                .is_empty()
        );
    }
    // A write that reached the server but was answered 502: the repeat does not store the value
    // a second time next to a live neighbor.
    add(&mock, &client, 0, &value('B')).await.unwrap();
    expected += 1;
    let control = mock.control().clone();
    let (sub, d) = (control.subdomain(0), value('D'));
    mock.faults().push(
        Fault::on("POST", UPDATE)
            .run(move || control.write(&sub, &d))
            .status(502),
    );
    let e = add(&mock, &client, 0, &value('D')).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    expected += 1;
    assert_eq!(
        add(&mock, &client, 0, &value('D')).await.unwrap(),
        AddOutcome::Accepted
    );
    assert_eq!(updates(&mock), expected, "the unknown outcome was repeated");
    assert_eq!(
        mock.control().values(&mock.control().subdomain(0)),
        [value('B'), value('D')]
    );
}

/// The outcome of a send is unknown (a 5xx, a lost connection) and the name has a live neighbor:
/// the repeat sends nothing, because if the server stored the value a second send would displace
/// the neighbor.
#[tokio::test]
async fn acme_dns_unknown_outcome_with_a_live_neighbor_is_not_resent() {
    let (mock, client) = setup().await;
    let control = mock.control().clone();
    let sub = control.subdomain(0);
    add(&mock, &client, 0, &value('A')).await.unwrap();
    mock.faults().push(Fault::on("POST", UPDATE).status(500));
    let e = add(&mock, &client, 0, &value('B')).await.unwrap_err();
    assert!(e.is_retryable(), "{e:?}");
    assert_eq!(updates(&mock), 2);
    assert_eq!(
        add(&mock, &client, 0, &value('B')).await.unwrap(),
        AddOutcome::Accepted
    );
    assert_eq!(updates(&mock), 2, "the uncertain value was sent again");
    assert_eq!(
        control.values(&sub),
        [value('A')],
        "the neighbor was displaced"
    );
}

/// An unknown outcome with no neighbor: the repeat sends the value; after a 2xx the next repeat
/// is silent.
#[tokio::test]
async fn acme_dns_unknown_outcome_without_a_neighbor_is_resent() {
    let (mock, client) = setup().await;
    let control = mock.control().clone();
    let sub = control.subdomain(0);
    mock.faults()
        .push(Fault::on("POST", UPDATE).drop_connection());
    let e = add(&mock, &client, 0, &value('A')).await.unwrap_err();
    assert!(e.is_retryable(), "{e:?}");
    assert_eq!(updates(&mock), 1);
    assert_eq!(
        add(&mock, &client, 0, &value('A')).await.unwrap(),
        AddOutcome::Accepted
    );
    assert_eq!(updates(&mock), 2);
    assert_eq!(control.values(&sub), [value('A')]);
    add(&mock, &client, 0, &value('A')).await.unwrap();
    assert_eq!(updates(&mock), 2, "a confirmed value was sent again");
}

/// A definite refusal removes the value from the memory: the repeat sends it.
#[tokio::test]
async fn acme_dns_refused_update_is_forgotten() {
    let (mock, client) = setup().await;
    for status in [400, 401, 403, 429, 404] {
        mock.faults().push(Fault::on("POST", UPDATE).status(status));
        add(&mock, &client, 0, &value('A')).await.unwrap_err();
    }
    assert_eq!(updates(&mock), 5);
    assert_eq!(
        add(&mock, &client, 0, &value('A')).await.unwrap(),
        AddOutcome::Accepted
    );
    assert_eq!(updates(&mock), 6);
    assert_eq!(
        mock.control().values(&mock.control().subdomain(0)),
        [value('A')]
    );
}

/// A refused send that would have displaced the oldest value leaves that value remembered: the
/// server was not touched, so it is still in its slot.
#[tokio::test]
async fn acme_dns_refused_displacing_send_keeps_the_older_values() {
    let (mock, client) = setup().await;
    for c in ['A', 'B'] {
        add(&mock, &client, 0, &value(c)).await.unwrap();
    }
    mock.faults().push(Fault::on("POST", UPDATE).status(401));
    add(&mock, &client, 0, &value('C')).await.unwrap_err();
    assert_eq!(updates(&mock), 3);
    for c in ['A', 'B'] {
        add(&mock, &client, 0, &value(c)).await.unwrap();
    }
    assert_eq!(
        updates(&mock),
        3,
        "a value still in its slot was sent again"
    );
    assert_eq!(
        mock.control().values(&mock.control().subdomain(0)),
        [value('A'), value('B')]
    );
}

/// The server's refusals: wrong credentials are `Auth` (with no secret in the error), and the
/// other statuses map as the transport does.
#[tokio::test]
async fn acme_dns_refusals_are_classified() {
    let (mock, client) = setup().await;
    let cases = [
        (400, ErrorKind::Rejected),
        (401, ErrorKind::Auth),
        (403, ErrorKind::Forbidden),
        (404, ErrorKind::Rejected),
        (500, ErrorKind::Transient),
    ];
    for (status, kind) in cases {
        mock.faults()
            .push(Fault::on("POST", UPDATE).respond(status, r#"{"error": "injected"}"#));
        let e = add(&mock, &client, 0, &value('A')).await.unwrap_err();
        assert_eq!(e.kind(), kind, "{status}: {e:?}");
        if let Error::Rejected { status: s, .. } = e {
            assert_eq!(s, Some(status));
        }
    }
    assert_eq!(updates(&mock), cases.len());
}

#[tokio::test]
async fn acme_dns_bad_credentials_are_an_auth_error_without_the_secret() {
    let mock = AcmeDnsMock::start(Seed::standard()).await;
    let wrong = "wrong-password-value-xyz-wrong-password-";
    let mut register = mock.control().register_json(0);
    register["password"] = serde_json::json!(wrong);
    let client = AcmeDns::new(
        config(mock.base_url()),
        credentials(register.to_string()),
        &context(),
    )
    .unwrap();
    let own = dn(&mock.control().fulldomain(0));
    let e = client
        .add_txt_value(&zone(), &own, &txt(&value('A')), None)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(!format!("{e} {e:?} {client:?}").contains(wrong));
    // `check` cannot tell: it sends nothing and says so.
    let before = updates(&mock);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.credentials_verified);
    assert_eq!(updates(&mock), before);
    // The refused value is not remembered as sent: the repeat goes to the server again.
    let before = updates(&mock);
    client
        .add_txt_value(&zone(), &own, &txt(&value('A')), None)
        .await
        .unwrap_err();
    assert_eq!(updates(&mock), before + 1);
}

/// `check` sends nothing, on any call, with good or bad credentials and with faults queued: the
/// only request the server authenticates is the update, which writes. It reports the credentials
/// as not verified and says so in every zone's detail; a zone is found when a registration's
/// `fulldomain` is within it.
#[tokio::test]
async fn acme_dns_check_sends_nothing() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", UPDATE).status(500));
    let report = client
        .check(&[zone(), dn("other.example.org")])
        .await
        .unwrap();
    assert!(!report.credentials_verified);
    assert_eq!(report.zones.len(), 2);
    assert!(report.zones[0].found);
    assert!(!report.zones[1].found);
    for zone in &report.zones {
        let detail = zone.detail.as_ref().unwrap();
        assert!(detail.as_str().contains("not tested"), "{detail:?}");
    }
    let report = client.check(&[]).await.unwrap();
    assert!(!report.credentials_verified && report.zones.is_empty());

    let mut register = mock.control().register_json(0);
    register["password"] = serde_json::json!("x".repeat(40));
    let wrong = AcmeDns::new(
        config(mock.base_url()),
        credentials(register.to_string()),
        &context(),
    )
    .unwrap();
    let report = wrong.check(&[zone()]).await.unwrap();
    assert!(!report.credentials_verified);
    assert!(mock.log().is_empty());
    assert_eq!(mock.connections(), 0);
    assert_eq!(mock.control().stored(), 0);
}

/// Sends to one name are at least a second apart, whichever client of the context makes them:
/// the server stamps its writes with whole seconds and overwrites the row with the smallest
/// stamp, so two writes within one second would leave it free to overwrite the newer value.
/// Sends to different names are not delayed, and neither is a send after a refusal.
#[tokio::test]
async fn acme_dns_sends_to_one_name_are_paced() {
    let mock = AcmeDnsMock::start(Seed::standard()).await;
    let ctx = context();
    let (one, two) = (client_in(&mock, &ctx), client_in(&mock, &ctx));
    let control = mock.control().clone();
    let started = std::time::Instant::now();
    add(&mock, &one, 0, &value('A')).await.unwrap();
    add(&mock, &one, 1, &value('A')).await.unwrap();
    add(&mock, &two, 0, &value('B')).await.unwrap();
    add(&mock, &one, 0, &value('C')).await.unwrap();
    for i in 0..2 {
        let times = control.write_times(&control.subdomain(i));
        for pair in times.windows(2) {
            assert!(
                pair[1].duration_since(pair[0]) >= Duration::from_secs(1),
                "registration {i}: two writes {:?} apart",
                pair[1].duration_since(pair[0])
            );
        }
    }
    assert_eq!(control.write_times(&control.subdomain(0)).len(), 3);
    assert_eq!(
        control.values(&control.subdomain(0)),
        [value('B'), value('C')]
    );
    // Name 1 was written once, right after name 0: not delayed by it.
    let first = control.write_times(&control.subdomain(0))[0];
    let other = control.write_times(&control.subdomain(1))[0];
    assert!(other.duration_since(first) < Duration::from_secs(1));
    assert!(started.elapsed() >= Duration::from_secs(2));

    // A refused send wrote nothing and does not delay the next one.
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("POST", UPDATE).status(401));
    add(&mock, &client, 0, &value('A')).await.unwrap_err();
    let started = std::time::Instant::now();
    add(&mock, &client, 0, &value('A')).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn acme_dns_from_json_builds_the_client() {
    let mock = AcmeDnsMock::start(Seed::standard()).await;
    let ctx = context();
    let settings = serde_json::json!({ "server_url": mock.base_url() }).to_string();
    // One registration as an object, other keys in the credentials ignored, `allowfrom` ignored.
    let client = AnyProvider::from_json(
        ProviderId::AcmeDns,
        &settings,
        &SecretString::from(
            serde_json::json!({
                "registrations": mock.control().register_json(0).to_string(),
                "other": 1,
            })
            .to_string(),
        ),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::AcmeDns);
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.credentials_verified && report.zones[0].found);
    let own = name(&mock, 0);
    assert_eq!(
        client
            .add_txt_value(&zone(), &own, &txt(&value('A')), None)
            .await
            .unwrap(),
        AddOutcome::Accepted
    );
    // The same as an array.
    let client = AnyProvider::from_json(
        ProviderId::AcmeDns,
        &settings,
        &SecretString::from(
            serde_json::json!({ "registrations": mock.control().registrations_text() }).to_string(),
        ),
        &ctx,
    )
    .unwrap();
    assert!(client.check(&[zone()]).await.unwrap().zones[0].found);
}

/// The smallest configuration the shared test support uses to build a client without a request.
#[test]
fn acme_dns_minimal_configuration_builds() {
    let registrations = serde_json::json!({
        "username": "c36f50e8-4632-4000-8000-000000000001",
        "password": "htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KWtest",
        "subdomain": "8e5700ea-a4bf-4000-8000-000000000001",
        "fulldomain": "8e5700ea-a4bf-4000-8000-000000000001.auth.example.org",
    })
    .to_string();
    let client = AnyProvider::from_json(
        ProviderId::AcmeDns,
        r#"{"server_url":"http://127.0.0.1:9"}"#,
        &SecretString::from(serde_json::json!({ "registrations": registrations }).to_string()),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::AcmeDns);
    AnyProvider::from_json(
        ProviderId::AcmeDns,
        "{}",
        &SecretString::from("{}".to_owned()),
        &context(),
    )
    .unwrap_err();
}

/// A registration with every field valid, as the register call answers it.
fn registration() -> serde_json::Value {
    serde_json::json!({
        "username": "c36f50e8-4632-4000-8000-000000000001",
        "password": "htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KWtest",
        "subdomain": "8e5700ea-a4bf-4000-8000-000000000001",
        "fulldomain": "8e5700ea-a4bf-4000-8000-000000000001.auth.example.org",
        "allowfrom": [],
    })
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn acme_dns_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let settings = || serde_json::json!({ "server_url": "http://127.0.0.1:1" });
    let with = |key: &str, value: serde_json::Value| {
        let mut r = registration();
        r[key] = value;
        r
    };
    let creds = |r: serde_json::Value| serde_json::json!({ "registrations": r.to_string() });
    let mut duplicate = vec![registration(), registration()];
    duplicate[1]["username"] = serde_json::json!(canary);
    let mut unknown = settings();
    unknown[canary] = serde_json::json!(canary);
    let cases: Vec<(serde_json::Value, serde_json::Value, &str)> = vec![
        (unknown, creds(registration()), "unknown keys"),
        (serde_json::json!({}), creds(registration()), "server_url"),
        (
            serde_json::json!({ "server_url": format!("http://example.com/{canary}") }),
            creds(registration()),
            "server_url",
        ),
        (
            serde_json::json!({ "server_url": format!("https://u:{canary}@auth.example.org") }),
            creds(registration()),
            "server_url",
        ),
        (settings(), serde_json::json!({}), "registrations"),
        (
            settings(),
            serde_json::json!({ "registrations": 5, canary: canary }),
            "registrations",
        ),
        (
            settings(),
            serde_json::json!({ "token": canary }),
            "registrations",
        ),
        (settings(), creds(serde_json::json!([])), "registrations"),
        (settings(), creds(serde_json::json!({})), "registrations"),
        (
            settings(),
            creds(serde_json::json!(canary)),
            "registrations",
        ),
        (
            settings(),
            creds(with("password", serde_json::json!(""))),
            "registrations",
        ),
        (
            settings(),
            creds(with("username", serde_json::json!(""))),
            "registrations",
        ),
        (
            settings(),
            creds(with(
                "password",
                serde_json::json!(format!("{canary}\u{1}")),
            )),
            "registrations",
        ),
        (
            settings(),
            creds(with("subdomain", serde_json::json!(format!("{canary}.x")))),
            "registrations",
        ),
        (
            settings(),
            creds(with("subdomain", serde_json::json!("-leading"))),
            "registrations",
        ),
        (
            settings(),
            creds(with("subdomain", serde_json::json!("a".repeat(64)))),
            "registrations",
        ),
        (
            settings(),
            creds(with("fulldomain", serde_json::json!(format!("{canary} x")))),
            "registrations",
        ),
        (
            settings(),
            creds(with(
                "fulldomain",
                serde_json::json!("other.auth.example.org"),
            )),
            "registrations",
        ),
        (
            settings(),
            creds(with(
                "fulldomain",
                serde_json::json!("8e5700ea-a4bf-4000-8000-000000000001"),
            )),
            "registrations",
        ),
        (
            settings(),
            creds(with(
                "fulldomain",
                serde_json::json!("8e5700ea-a4bf-4000-8000-000000000001."),
            )),
            "registrations",
        ),
        (
            settings(),
            creds(serde_json::Value::Array(duplicate)),
            "registrations",
        ),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::AcmeDns,
            &settings.to_string(),
            &SecretString::from(credentials.to_string()),
            &ctx,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{key}: {e:?}");
        let text = format!("{e} | {e:?}");
        assert!(key == "unknown keys" || text.contains(key), "{key}: {text}");
        assert!(!text.contains(canary), "{key}: {text}");
        assert!(!text.contains("htB9mR9"), "{key}: {text}");
    }
}

/// The client's `Debug` shows the settings and the registrations' public names, never a
/// credential.
#[test]
fn acme_dns_debug_shows_no_credential() {
    let client = AcmeDns::new(
        config("http://127.0.0.1:1".into()),
        credentials(registration().to_string()),
        &context(),
    )
    .unwrap();
    let text = format!("{client:?}");
    assert!(text.contains("8e5700ea-a4bf-4000-8000-000000000001.auth.example.org."));
    assert!(!text.contains("c36f50e8"));
    assert!(!text.contains("htB9mR9"));
    let c = format!("{:?}", credentials(registration().to_string()));
    assert!(!c.contains("htB9mR9") && !c.contains("c36f50e8"), "{c}");
}

/// Every key of the metadata is a key of the settings or of the credentials, and the other way
/// round; the capabilities say what the client does.
#[test]
fn acme_dns_config_keys_match_metadata() {
    let meta = ProviderId::AcmeDns.meta();
    let settings =
        serde_json::to_value(AcmeDnsConfig::new("https://auth.example.org".into())).unwrap();
    let mut settings_keys: Vec<&str> = settings
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    settings_keys.sort_unstable();
    let meta_settings: Vec<&str> = meta
        .fields
        .iter()
        .filter(|f| !f.secret)
        .map(|f| f.key)
        .collect();
    assert_eq!(settings_keys, meta_settings);
    let secret: Vec<&str> = meta
        .fields
        .iter()
        .filter(|f| f.secret)
        .map(|f| f.key)
        .collect();
    assert_eq!(secret, ["registrations"]);
    assert!(meta.fields.iter().all(|f| f.required));
    let caps = &meta.capabilities;
    assert!(caps.add_txt_value);
    assert!(!caps.remove_txt_value && !caps.list_zones);
    assert!(!caps.list_rrsets && !caps.get_rrset && !caps.set_rrset && !caps.delete_rrset);
    assert_eq!(caps.txt_values, zonewright::ValueGuarantee::Rotating);
    assert_eq!(caps.ttl, zonewright::TtlSupport::NotSettable);
    assert!(!meta.verified);
    assert_eq!(
        meta.default_propagation_timeout,
        Some(Duration::from_secs(60))
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

/// Stores two random values in the first registration of the credentials and checks the answers.
///
/// acme-dns has no delete and no read, so this test cannot remove what it wrote or look at it:
/// the two values it stores replace both slots of the registration, which is the only cleanup the
/// API offers. Run it with a registration that is set aside for testing, never with one a
/// certificate depends on. `ZONEWRIGHT_LIVE_ACME_DNS_ZONE` is the acme-dns server's domain (the
/// registration's `fulldomain` is below it).
#[tokio::test]
#[ignore = "live API: run only by the maintainer, with a registration set aside for testing"]
async fn live_acme_dns_add() {
    let settings = live_env("ZONEWRIGHT_LIVE_ACME_DNS_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_ACME_DNS_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_ACME_DNS_ZONE"));
    // The name is the first registration's fulldomain.
    let registrations =
        serde_json::from_str::<serde_json::Value>(&credentials).unwrap()["registrations"]
            .as_str()
            .map(|text| serde_json::from_str::<serde_json::Value>(text).unwrap())
            .expect("the credentials hold the string key registrations");
    let first = registrations.as_array().map_or(&registrations, |a| &a[0]);
    let name = dn(first["fulldomain"].as_str().unwrap());

    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::AcmeDns,
            &settings,
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap(),
    );
    let tag = random_u64();
    // 43 characters of the base64url alphabet: 11 + 16 + 16.
    let values = [
        txt(&format!("zw-live-a0-{tag:016x}{tag:016x}")),
        txt(&format!("zw-live-b0-{tag:016x}{tag:016x}")),
    ];
    for v in &values {
        assert_eq!(v.as_bytes().len(), 43);
    }
    // `check` sends nothing: the credentials are tested by the first add.
    let report = client.check(std::slice::from_ref(&zone)).await.unwrap();
    assert!(!report.credentials_verified);
    assert!(report.zones[0].found, "{report:?}");
    for v in &values {
        assert_eq!(
            client.add_txt_value(&zone, &name, v, None).await.unwrap(),
            AddOutcome::Accepted
        );
    }
    // A repeat is not sent and is still `Accepted`; a removal is not offered.
    assert_eq!(
        client
            .add_txt_value(&zone, &name, &values[0], None)
            .await
            .unwrap(),
        AddOutcome::Accepted
    );
    let e = client
        .remove_txt_value(&zone, &name, &values[0])
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported);
}
