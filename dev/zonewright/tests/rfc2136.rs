//! Tests of the RFC 2136 client (`rfc2136`) against its mock.
#![cfg(feature = "rfc2136")]
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
use zonewright::providers::rfc2136::{Rfc2136, Rfc2136Config, Rfc2136Credentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, ContextOptions, DeleteOutcome, DomainName, Error, ErrorKind,
    Expect, Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl,
    SetOutcome, Ttl, Txt,
};
use zonewright_mock::rfc2136::{
    BADKEY, BADSIG, BADTIME, CLASS_ANY, CLASS_IN, CLASS_NONE, Call, FORMERR, Fault, KEY_NAME_512,
    MockKey, MockRecord, NOERROR, NOTAUTH, NXDOMAIN, Op, REFUSED, Rfc2136Mock, SERVFAIL,
    STANDARD_SECRET, STANDARD_SECRET_512, Seed, TYPE_A, TYPE_ANY, TYPE_CNAME, TYPE_TXT, txt_rdata,
};

use common::echo::{LogCapture, assert_clean};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";
/// The same, as the mock spells names.
const NAME_DOT: &str = "_acme-challenge.example.org.";
/// The standard key's name as a setting spells it.
const KEY: &str = "zw-test-key";
/// The TTL the client writes when none is given (the default of the `ttl` setting).
const DEFAULT_TTL: u32 = 60;

/// Every operation's slack for the back-off of three attempts (500 ms + 1000 ms, plus jitter).
const SLOW: Duration = Duration::from_secs(10);

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn hex(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect()
}

fn settings(mock: &Rfc2136Mock, key_name: &str) -> Rfc2136Config {
    Rfc2136Config::new(mock.server(), key_name.to_owned())
}

fn credentials(secret: &[u8]) -> Rfc2136Credentials {
    Rfc2136Credentials::new(SecretString::from(b64(secret)))
}

fn client_with(mock: &Rfc2136Mock, key_name: &str, secret: &[u8], ctx: &Context) -> Rfc2136 {
    Rfc2136::new(settings(mock, key_name), credentials(secret), ctx).unwrap()
}

async fn setup() -> (Rfc2136Mock, Rfc2136) {
    setup_with(Seed::standard()).await
}

async fn setup_with(seed: Seed) -> (Rfc2136Mock, Rfc2136) {
    let mock = Rfc2136Mock::start(seed).await;
    let client = client_with(&mock, KEY, STANDARD_SECRET, &context());
    (mock, client)
}

/// A context whose exchanges time out after `ms` milliseconds.
fn context_with_timeout(ms: u64) -> Context {
    let mut options = ContextOptions::default();
    options.loopback_only = true;
    options.request_timeout = Duration::from_millis(ms);
    Context::new(options).unwrap()
}

async fn add(client: &impl Provider, value: &str) -> Result<AddOutcome, Error> {
    tokio::time::timeout(
        SLOW,
        client.add_txt_value(&zone(), &name(), &txt(value), None),
    )
    .await
    .expect("the operation is bounded")
}

async fn remove(client: &impl Provider, value: &str) -> Result<RemoveOutcome, Error> {
    tokio::time::timeout(SLOW, client.remove_txt_value(&zone(), &name(), &txt(value)))
        .await
        .expect("the operation is bounded")
}

fn queries(mock: &Rfc2136Mock) -> usize {
    mock.control().count(Op::Query)
}

fn updates(mock: &Rfc2136Mock) -> usize {
    mock.control().count(Op::Update)
}

/// The records of the update section of every update received, flattened.
fn update_records(mock: &Rfc2136Mock) -> Vec<(u16, u16, u32, Vec<u8>)> {
    mock.control()
        .calls()
        .iter()
        .filter(|c| c.op == Op::Update)
        .flat_map(|c| c.updates.iter())
        .map(|u| (u.class, u.rtype, u.ttl, u.rdata.clone()))
        .collect()
}

/// The TTLs of the TXT records at `NAME`, by value.
fn ttls(mock: &Rfc2136Mock) -> Vec<(String, u32)> {
    let mut out: Vec<(String, u32)> = mock
        .control()
        .records(NAME_DOT)
        .into_iter()
        .filter(|r| r.rtype == TYPE_TXT)
        .map(|r| {
            let data = zonewright_mock::rfc2136::txt_data(&r.rdata).unwrap();
            (String::from_utf8(data).unwrap(), r.ttl)
        })
        .collect();
    out.sort();
    out
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

assert_not_impl!(Rfc2136: std::fmt::Display, serde::Serialize);
assert_not_impl!(Rfc2136Credentials: std::fmt::Display, serde::Serialize);

/// A synthetic TSIG secret, distinctive in base64 and in hex.
const CANARY_SECRET: &[u8; 32] = b"cAnary-TSIG-secret/+=@ \"'&<>\\~*!";
/// The key name the mock knows the canary secret under.
const CANARY_KEY: &str = "zw-canary-key";

fn canary_seed() -> Seed {
    let mut seed = Seed::standard();
    seed.keys.push(MockKey {
        name: format!("{CANARY_KEY}."),
        algorithm: "hmac-sha256.".to_owned(),
        secret: CANARY_SECRET.to_vec(),
    });
    seed
}

/// The secret in every spelling a configuration or a log could carry it: base64 (with and
/// without padding), lowercase and uppercase hex, and the raw text.
fn secret_spellings(secret: &[u8]) -> Vec<String> {
    let mut out = vec![
        b64(secret),
        b64(secret).trim_end_matches('=').to_owned(),
        hex(secret, false),
        hex(secret, true),
    ];
    if let Ok(text) = std::str::from_utf8(secret) {
        out.push(text.to_owned());
    }
    out
}

/// Every request MAC the mock saw, in base64 and hex.
fn mac_spellings(calls: &[Call]) -> Vec<String> {
    calls
        .iter()
        .filter(|c| !c.request_mac.is_empty())
        .flat_map(|c| {
            [
                b64(&c.request_mac),
                hex(&c.request_mac, false),
                hex(&c.request_mac, true),
            ]
        })
        .collect()
}

fn assert_no_spelling(what: &str, text: &str, spellings: &[String]) {
    for spelling in spellings {
        assert!(
            !text.contains(spelling.as_str()),
            "{what} leaks {spelling:?}: {text}"
        );
        // A fragment of a long spelling is a leak too.
        if spelling.len() >= 16 {
            for start in 0..=spelling.len() - 16 {
                if let Some(fragment) = spelling.get(start..start + 16) {
                    assert!(!text.contains(fragment), "{what} leaks a fragment: {text}");
                }
            }
        }
    }
}

/// The TSIG secret, in base64 and in hex, and the MAC of any message, never occur in an error,
/// a zone check's detail or the client's `Debug`, across the error paths of the mock (design
/// section 12.2: the RFC 2136 equivalent of the HTTP echo test).
#[tokio::test]
async fn rfc2136_secret_not_in_errors() {
    let mock = Rfc2136Mock::start(canary_seed()).await;
    let control = mock.control();
    control.add_txt(NAME_DOT, "present", 60);
    let ctx = context();
    let good = client_with(&mock, CANARY_KEY, CANARY_SECRET, &ctx);
    // The canary secret under a name the server knows with another secret: BADSIG.
    let badsig = client_with(&mock, KEY, CANARY_SECRET, &ctx);
    // The canary secret under a name the server does not know: BADKEY.
    let badkey = client_with(&mock, "zw-unknown-key", CANARY_SECRET, &ctx);
    let slow_ctx = context_with_timeout(200);
    let slow = client_with(&mock, CANARY_KEY, CANARY_SECRET, &slow_ctx);

    let mut texts: Vec<(String, String)> = Vec::new();
    let mut failures = Vec::new();
    let mut record = |label: &str, result: Result<String, Error>| match result {
        Ok(ok) => texts.push((label.to_owned(), ok)),
        Err(e) => {
            failures.push(label.to_owned());
            texts.push((label.to_owned(), format!("{e} {e:?}")));
        }
    };
    record(
        "badsig add",
        add(&badsig, "v1").await.map(|o| format!("{o:?}")),
    );
    record(
        "badkey remove",
        remove(&badkey, "present").await.map(|o| format!("{o:?}")),
    );
    record(
        "badkey check",
        badkey.check(&[zone()]).await.map(|r| format!("{r:?}")),
    );
    record(
        "badsig check without zones",
        badsig.check(&[]).await.map(|r| format!("{r:?}")),
    );
    control.clock_skew(1000);
    record(
        "badtime add",
        add(&good, "v1").await.map(|o| format!("{o:?}")),
    );
    control.clock_skew(0);
    for (label, fault) in [
        ("unsigned", Fault::any().unsigned()),
        ("corrupt mac", Fault::any().corrupt_mac()),
        ("other key", Fault::any().other_key()),
        ("time offset", Fault::any().time_offset(1000)),
        ("wrong id", Fault::any().wrong_id()),
        ("wrong question", Fault::any().wrong_question()),
        ("short length", Fault::any().short_length()),
        ("refused", Fault::on(Op::Update).rcode(REFUSED)),
        ("formerr", Fault::on(Op::Update).rcode(FORMERR)),
        ("notauth", Fault::on(Op::Update).rcode(NOTAUTH)),
        ("servfail", Fault::any().rcode(SERVFAIL).times(3)),
        ("closed", Fault::any().close().times(3)),
        ("truncated", Fault::any().truncate().times(3)),
    ] {
        control.push(fault);
        record(label, add(&good, "v2").await.map(|o| format!("{o:?}")));
        control.add_txt(NAME_DOT, "v2", 60);
        // Leave the state as it was for the next path.
        let _ = remove(&good, "v2").await;
    }
    control.push(Fault::any().delay(Duration::from_millis(600)).times(3));
    record("timeout", add(&slow, "v3").await.map(|o| format!("{o:?}")));
    record(
        "check of a foreign zone",
        good.check(&[dn("other.org"), zone()])
            .await
            .map(|r| format!("{r:?}")),
    );
    control.push(Fault::on(Op::Update).rcode(REFUSED));
    record(
        "check refused",
        good.check(&[zone()]).await.map(|r| format!("{r:?}")),
    );

    // The record-level request kinds: query, conditional update of a set, deletion of a set.
    let r = rrset("sec.example.org", RecordType::A, None, &["192.0.2.1"]);
    record(
        "badsig record set",
        set(&badsig, &r, Expect::Any)
            .await
            .map(|o| format!("{o:?}")),
    );
    record(
        "badkey record get",
        get(&badkey, "sec.example.org", RecordType::A)
            .await
            .map(|o| format!("{o:?}")),
    );
    let record_faults = || {
        [
            ("record refused", Fault::on(Op::Update).rcode(REFUSED)),
            ("record servfail", Fault::on(Op::Update).rcode(SERVFAIL)),
            (
                "record tsig error",
                Fault::on(Op::Update).rcode(NOTAUTH).tsig_error(BADSIG),
            ),
            ("record corrupt mac", Fault::on(Op::Update).corrupt_mac()),
            ("record closed", Fault::on(Op::Update).close()),
        ]
    };
    for (label, fault) in record_faults() {
        control.push(fault);
        record(
            label,
            set(&good, &r, Expect::Any).await.map(|o| format!("{o:?}")),
        );
        // A forged answer comes after the server applied the update.
        let _ = delete(&good, "sec.example.org", RecordType::A, Expect::Any).await;
    }
    set(&good, &r, Expect::Any).await.unwrap();
    for (label, fault) in record_faults() {
        control.push(fault);
        record(
            label,
            delete(&good, "sec.example.org", RecordType::A, Expect::Any)
                .await
                .map(|o| format!("{o:?}")),
        );
        set(&good, &r, Expect::Any).await.unwrap();
    }
    for value in ["192.0.2.8", "192.0.2.9"] {
        control.push(Fault::on(Op::Update).foreign_record(mock_record(
            "sec.example.org",
            RecordType::A,
            60,
            value,
        )));
    }
    let other = rrset("sec.example.org", RecordType::A, None, &["192.0.2.2"]);
    record(
        "record conflict",
        set(&good, &other, Expect::Any)
            .await
            .map(|o| format!("{o:?}")),
    );
    record(
        "record precondition",
        set(&good, &other, Expect::Absent)
            .await
            .map(|o| format!("{o:?}")),
    );
    control.refuse_queries(true);
    record(
        "record read refused",
        get(&good, "sec.example.org", RecordType::A)
            .await
            .map(|o| format!("{o:?}")),
    );
    control.refuse_queries(false);

    // Configuration errors with the canary in the secret.
    for secret in [format!("{}!", b64(CANARY_SECRET)), b64(&CANARY_SECRET[..8])] {
        let err = Rfc2136::new(
            settings(&mock, CANARY_KEY),
            Rfc2136Credentials::new(SecretString::from(secret)),
            &ctx,
        )
        .unwrap_err();
        record("config", Err(err));
    }

    let mut secrets = secret_spellings(CANARY_SECRET);
    secrets.extend(mac_spellings(&control.calls()));
    assert!(texts.len() >= 20);
    for client in [&good, &badsig, &badkey, &slow] {
        texts.push(("client debug".to_owned(), format!("{client:?}")));
    }
    for (label, text) in &texts {
        assert_no_spelling(label, text, &secrets);
    }
    // The paths were reached: TSIG errors, forged answers and server refusals all failed.
    assert_eq!(failures.len(), 36, "{texts:#?}");
    assert!(control.calls().iter().any(|c| c.tsig_error == BADSIG));
    assert!(control.calls().iter().any(|c| c.tsig_error == BADKEY));
    assert!(control.calls().iter().any(|c| c.tsig_error == BADTIME));
}

/// A `tracing` capture at every level through a success, a TSIG failure and SERVFAIL holds the
/// client's events with the operation, the RCODE and the duration, and no spelling of the
/// secret or of a MAC.
#[tokio::test(flavor = "current_thread")]
async fn rfc2136_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mock = Rfc2136Mock::start(canary_seed()).await;
    let ctx = context();
    let good = client_with(&mock, CANARY_KEY, CANARY_SECRET, &ctx);
    let badsig = client_with(&mock, KEY, CANARY_SECRET, &ctx);

    assert_eq!(add(&good, "v1").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        add(&badsig, "v2").await.unwrap_err().kind(),
        ErrorKind::Auth
    );
    mock.control().push(Fault::any().rcode(SERVFAIL).times(3));
    assert_eq!(
        add(&good, "v3").await.unwrap_err().kind(),
        ErrorKind::Transient
    );

    let entries = capture.entries();
    let events: Vec<_> = entries
        .iter()
        .filter(|e| e.target == "zonewright::rfc2136" && !e.span)
        .collect();
    assert!(events.len() >= 5, "{}", capture.text());
    for event in &events {
        let mut names = event.names();
        names.sort_unstable();
        let allowed = ["elapsed_ms", "message", "op", "rcode"];
        assert!(
            names.iter().all(|n| allowed.contains(n)),
            "unexpected field in {event}"
        );
        assert!(event.field("op").is_some() && event.field("elapsed_ms").is_some());
    }
    assert!(events.iter().any(|e| e.field("rcode") == Some("2")));
    assert!(events.iter().any(|e| e.field("rcode") == Some("0")));
    let text = capture.text();
    let mut secrets = secret_spellings(CANARY_SECRET);
    secrets.extend(mac_spellings(&mock.control().calls()));
    assert_no_spelling("the log", &text, &secrets);
    assert_clean("the log", &text, &[]);
    // No TXT value reaches the log either.
    for value in ["v1", "v2", "v3"] {
        assert!(!text.contains(value), "the log holds a TXT value: {text}");
    }
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name in another zone, a name that merely ends with the zone's text, and a name in a sibling
/// zone are refused before any request.
#[tokio::test]
async fn rfc2136_name_outside_zone_sends_nothing() {
    let (mock, client) = setup().await;
    let cases = [
        (zone(), dn("_acme-challenge.example.net")),
        (zone(), dn("_acme-challenge.badexample.org")),
        (dn("a.example.org"), dn("_acme-challenge.b.example.org")),
    ];
    for (zone, name) in cases {
        let err = client
            .add_txt_value(&zone, &name, &txt("v1"), None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NameOutsideZone, "{err:?}");
        let err = client
            .remove_txt_value(&zone, &name, &txt("v1"))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NameOutsideZone, "{err:?}");
    }
    assert!(mock.control().calls().is_empty());
}

#[tokio::test]
async fn rfc2136_add_is_idempotent() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "v1").await.unwrap(), AddOutcome::Created);
    assert_eq!(add(&client, "v2").await.unwrap(), AddOutcome::Appended);
    let before = updates(&mock);
    assert_eq!(
        add(&client, "v2").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        updates(&mock),
        before,
        "no write for a value already present"
    );
    assert_eq!(mock.control().txt(NAME_DOT), ["v1", "v2"]);
    // Every add was "add this RR" (class IN), never a deletion.
    for (class, rtype, _, _) in update_records(&mock) {
        assert_eq!((class, rtype), (1, TYPE_TXT));
    }
}

/// Removing an absent value next to a foreign one writes nothing; adding and removing our value
/// leaves the foreign value and its TTL as they were, also when the foreign value appears
/// between our read and our write.
#[tokio::test]
async fn rfc2136_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_txt(NAME_DOT, "foreign", 600);
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(updates(&mock), 0);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    // The added record joins with the existing RRset's TTL (design section 3.6).
    assert_eq!(
        ttls(&mock),
        [("foreign".to_owned(), 600), ("ours".to_owned(), 600)]
    );
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(ttls(&mock), [("foreign".to_owned(), 600)]);
    assert_eq!(
        control.rrset_deletes(),
        0,
        "an RRset is never deleted whole"
    );

    // A foreign value added by another writer right before our add reaches the server.
    control.push(Fault::on(Op::Update).foreign_txt(NAME_DOT, "late-foreign"));
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    assert_eq!(control.txt(NAME_DOT), ["foreign", "late-foreign", "ours"]);
    // And one added right before our removal survives it.
    control.push(Fault::on(Op::Update).foreign_txt(NAME_DOT, "later-foreign"));
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(
        control.txt(NAME_DOT),
        ["foreign", "late-foreign", "later-foreign"]
    );
    // Every deletion named exactly our RDATA with class NONE (RFC 2136 section 2.5.4).
    for (class, _, ttl, rdata) in update_records(&mock) {
        if class != 1 {
            assert_eq!((class, ttl), (254, 0));
            assert_eq!(rdata, txt_rdata(b"ours"));
        }
    }
    assert_eq!(control.rrset_deletes(), 0);
}

#[tokio::test]
async fn rfc2136_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "v1").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().txt(NAME_DOT).is_empty());
    // The RRset went away because its last RR was deleted, not by an RRset deletion.
    assert_eq!(mock.control().rrset_deletes(), 0);
}

#[tokio::test]
async fn rfc2136_remove_is_idempotent() {
    let (mock, client) = setup().await;
    add(&client, "v1").await.unwrap();
    add(&client, "v2").await.unwrap();
    assert_eq!(remove(&client, "v1").await.unwrap(), RemoveOutcome::Removed);
    let before = updates(&mock);
    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(updates(&mock), before, "no write for a value not present");
    assert_eq!(
        remove(&client, "v2").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(
        remove(&client, "v2").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert!(mock.control().txt(NAME_DOT).is_empty());
}

/// Two clients sharing a context: the second add waits for the first, whose write the mock
/// delays, and then sees its value.
#[tokio::test]
async fn rfc2136_concurrent_adds_are_serialized() {
    let mock = Rfc2136Mock::start(Seed::standard()).await;
    let ctx = context();
    let a = Arc::new(client_with(&mock, KEY, STANDARD_SECRET, &ctx));
    let b = Arc::new(client_with(&mock, KEY, STANDARD_SECRET, &ctx));
    mock.control()
        .push(Fault::on(Op::Update).delay(Duration::from_millis(300)));
    let (ra, rb) = tokio::join!(add(a.as_ref(), "va"), add(b.as_ref(), "vb"));
    let mut outcomes = [ra.unwrap(), rb.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [AddOutcome::Appended, AddOutcome::Created]);
    assert_eq!(mock.control().txt(NAME_DOT), ["va", "vb"]);
    // Serialized: read, write, read, write.
    let ops: Vec<Op> = mock.control().calls().iter().map(|c| c.op).collect();
    assert_eq!(ops, [Op::Query, Op::Update, Op::Query, Op::Update]);
}

/// Design sections 5.3 and 11.3: the messages of this client are idempotent at the server, so
/// they get at most 3 attempts after a connection failure, a lost answer or SERVFAIL, and
/// exactly one when the server refused them. Counted exactly.
#[tokio::test]
async fn rfc2136_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let control = mock.control();
    // A refusal is final: one update per operation.
    for (rcode, kind) in [
        (REFUSED, ErrorKind::Forbidden),
        (NOTAUTH, ErrorKind::ZoneNotFound),
        (FORMERR, ErrorKind::Rejected),
        (NXDOMAIN, ErrorKind::Rejected),
    ] {
        control.clear_calls();
        control.push(Fault::on(Op::Update).rcode(rcode));
        let err = add(&client, "v1").await.unwrap_err();
        assert_eq!(err.kind(), kind, "{rcode}: {err:?}");
        assert_eq!(updates(&mock), 1, "add, rcode {rcode}");

        control.add_txt(NAME_DOT, "v1", 60);
        control.clear_calls();
        control.push(Fault::on(Op::Update).rcode(rcode));
        let err = remove(&client, "v1").await.unwrap_err();
        assert_eq!(err.kind(), kind, "{rcode}: {err:?}");
        assert_eq!(updates(&mock), 1, "remove, rcode {rcode}");
        remove(&client, "v1").await.unwrap();
    }
    // A forged or garbled answer is not repeated either.
    control.clear_calls();
    control.push(Fault::on(Op::Update).corrupt_mac());
    assert_eq!(
        add(&client, "v1").await.unwrap_err().kind(),
        ErrorKind::Protocol
    );
    assert_eq!(updates(&mock), 1);
    remove(&client, "v1").await.unwrap();

    // SERVFAIL three times: three attempts, then `Transient`.
    control.clear_calls();
    control.push(Fault::on(Op::Update).rcode(SERVFAIL).times(3));
    let err = add(&client, "v1").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Transient, "{err:?}");
    assert_eq!(updates(&mock), 3);
    assert!(control.txt(NAME_DOT).is_empty());

    // An answer lost after the server applied the add: the repeat is ignored as a duplicate
    // (RFC 2136 section 2.5.1) and the outcome is still right.
    control.clear_calls();
    control.push(Fault::on(Op::Update).drop_reply());
    assert_eq!(add(&client, "v1").await.unwrap(), AddOutcome::Created);
    assert_eq!(updates(&mock), 2);
    assert_eq!(control.txt(NAME_DOT), ["v1"]);

    // The same for a deletion whose answer is lost.
    control.clear_calls();
    control.push(Fault::on(Op::Update).drop_reply());
    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(updates(&mock), 2);
    assert!(control.txt(NAME_DOT).is_empty());
    assert_eq!(control.rrset_deletes(), 0);
}

#[tokio::test]
async fn rfc2136_unsupported_operations_send_nothing() {
    let (mock, client) = setup().await;
    // The protocol has no listing of zones or records.
    let errors = [
        client.list_zones().await.map(drop).unwrap_err(),
        client.list_rrsets(&zone()).await.map(drop).unwrap_err(),
    ];
    for err in errors {
        match err {
            Error::Unsupported { provider, .. } => assert_eq!(provider, ProviderId::Rfc2136),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
    // Pseudo-types have no type code; SOA is read-only.
    let alias = RrSet::new(
        name(),
        RecordType::ALIAS,
        None,
        [RecordData::parse(RecordType::ALIAS, "target.example.org.").unwrap()],
    )
    .unwrap();
    let soa = RrSet::new(
        zone(),
        RecordType::SOA,
        None,
        [rd(RecordType::SOA, SOA_TEXT)],
    )
    .unwrap();
    let errors = [
        client
            .get_rrset(&zone(), &name(), RecordType::ALIAS)
            .await
            .map(drop)
            .unwrap_err(),
        client
            .set_rrset(&zone(), &alias, Expect::Any)
            .await
            .map(drop)
            .unwrap_err(),
        client
            .delete_rrset(&zone(), &name(), RecordType::ANAME, Expect::Any)
            .await
            .map(drop)
            .unwrap_err(),
        client
            .set_rrset(&zone(), &soa, Expect::Any)
            .await
            .map(drop)
            .unwrap_err(),
        client
            .delete_rrset(&zone(), &zone(), RecordType::SOA, Expect::Any)
            .await
            .map(drop)
            .unwrap_err(),
    ];
    for err in errors {
        assert_eq!(err.kind(), ErrorKind::UnsupportedRecordType, "{err:?}");
    }
    // Query and meta types are refused by every operation.
    for code in [41, 251, 252, 255] {
        let err = client
            .get_rrset(&zone(), &name(), RecordType::from_code(code))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "{code}: {err:?}");
    }
    assert!(mock.control().calls().is_empty());
}

// ---- TXT records -------------------------------------------------------------------------------

#[tokio::test]
async fn rfc2136_single_value_lifecycle() {
    let (mock, client) = setup().await;
    let control = mock.control();
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
    assert!(control.txt(NAME_DOT).is_empty());
    assert_eq!(control.rrset_deletes(), 0);
    // Every answer verified; the only non-NOERROR answer is the first read's NXDOMAIN.
    let calls = control.calls();
    assert!(calls.iter().all(|c| c.tsig_error == 0));
    assert!(
        calls
            .iter()
            .all(|c| c.rcode == Some(0) || (c.op == Op::Query && c.rcode == Some(NXDOMAIN)))
    );
}

#[tokio::test]
async fn rfc2136_other_types_at_the_name_are_untouched() {
    let (mock, client) = setup().await;
    let a = MockRecord {
        name: NAME_DOT.to_owned(),
        rtype: TYPE_A,
        ttl: 300,
        rdata: vec![192, 0, 2, 1],
    };
    mock.control().add_record(a.clone());
    assert_eq!(add(&client, "v1").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(mock.control().records(NAME_DOT), [a]);
}

/// Values travel as RDATA, so every value can be written: spaces, quotes, backslashes, non-ASCII
/// octets, more than 255 octets (several character-strings), and the empty value.
#[tokio::test]
async fn rfc2136_any_txt_value_round_trips() {
    let (mock, client) = setup().await;
    let long: Vec<u8> = (0..600u32).map(|i| b'a' + (i % 26) as u8).collect();
    let values = [
        Txt::new("v=spf1 mx -all").unwrap(),
        Txt::new("quote \" and \\ backslash").unwrap(),
        Txt::new("ключ".as_bytes()).unwrap(),
        Txt::new(vec![0u8, 1, 255]).unwrap(),
        Txt::new(long.clone()).unwrap(),
        Txt::new("").unwrap(),
    ];
    for value in &values {
        assert_eq!(
            client
                .add_txt_value(&zone(), &name(), value, None)
                .await
                .unwrap(),
            if value == &values[0] {
                AddOutcome::Created
            } else {
                AddOutcome::Appended
            }
        );
        assert_eq!(
            client
                .add_txt_value(&zone(), &name(), value, None)
                .await
                .unwrap(),
            AddOutcome::AlreadyPresent
        );
    }
    let stored = mock.control().records(NAME_DOT);
    assert_eq!(stored.len(), values.len());
    assert!(
        stored
            .iter()
            .any(|r| r.rdata.len() == 600 + 3 && r.rdata[0] == 255)
    );
    for value in &values {
        client
            .remove_txt_value(&zone(), &name(), value)
            .await
            .unwrap();
    }
    assert!(mock.control().records(NAME_DOT).is_empty());
    // The size of one message bounds a value, before any request.
    mock.control().clear_calls();
    let huge = Txt::new(vec![b'x'; 65_000]).unwrap();
    let err = client
        .add_txt_value(&zone(), &name(), &huge, None)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(mock.control().calls().is_empty());
}

/// A value stored with other character-string boundaries is the same value: it is found, and
/// it is removed with the RDATA exactly as the server returned it.
#[tokio::test]
async fn rfc2136_value_split_differently_is_matched() {
    let (mock, client) = setup().await;
    mock.control().add_record(MockRecord {
        name: NAME_DOT.to_owned(),
        rtype: TYPE_TXT,
        ttl: 60,
        rdata: b"\x02ab\x01c".to_vec(),
    });
    assert_eq!(
        add(&client, "abc").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        remove(&client, "abc").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().records(NAME_DOT).is_empty());
    assert_eq!(
        update_records(&mock),
        [(254, TYPE_TXT, 0, b"\x02ab\x01c".to_vec())]
    );
}

/// A record whose RDATA is not valid TXT data is a foreign value: never equal to ours, never
/// deleted.
#[tokio::test]
async fn rfc2136_malformed_record_is_left_alone() {
    let (mock, client) = setup().await;
    let odd = MockRecord {
        name: NAME_DOT.to_owned(),
        rtype: TYPE_TXT,
        ttl: 60,
        rdata: b"\x05ab".to_vec(),
    };
    mock.control().add_record(odd.clone());
    assert_eq!(
        remove(&client, "ab").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(add(&client, "ab").await.unwrap(), AddOutcome::Appended);
    assert_eq!(remove(&client, "ab").await.unwrap(), RemoveOutcome::Removed);
    assert_eq!(mock.control().records(NAME_DOT), [odd]);
}

/// Only TXT records of class IN owned by exactly the name count: a record a server adds for
/// another owner (the target of a CNAME) or of another class is not a value at the name.
#[tokio::test]
async fn rfc2136_answers_for_other_names_are_ignored() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.push(Fault::on(Op::Query).extra_answer(
        "target.example.org.",
        TYPE_TXT,
        1,
        &txt_rdata(b"ours"),
    ));
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Created);
    control.push(Fault::on(Op::Query).extra_answer(NAME_DOT, TYPE_TXT, 3, &txt_rdata(b"other")));
    assert_eq!(
        remove(&client, "other").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    control.push(Fault::on(Op::Query).extra_answer(NAME_DOT, 5, 1, b"\x01x\x00"));
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.txt(NAME_DOT).is_empty());
}

#[tokio::test]
async fn rfc2136_ttl_policy() {
    let (mock, client) = setup().await;
    // A new RRset: the configured TTL, or the caller's.
    add(&client, "v1").await.unwrap();
    assert_eq!(ttls(&mock), [("v1".to_owned(), DEFAULT_TTL)]);
    remove(&client, "v1").await.unwrap();
    client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("v2"),
            Some(RrsetTtl::from_secs(120).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(ttls(&mock), [("v2".to_owned(), 120)]);
    // An existing RRset keeps its TTL; the caller's TTL is for a new one only.
    client
        .add_txt_value(
            &zone(),
            &name(),
            &txt("v3"),
            Some(RrsetTtl::from_secs(3600).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        ttls(&mock),
        [("v2".to_owned(), 120), ("v3".to_owned(), 120)]
    );
    // Every TTL the protocol carries (RFC 2181 section 8) is accepted for a new RRset, beyond
    // the range of the `ttl` setting.
    for (owner, secs) in [("z0.example.org", 0), ("zmax.example.org", 2_147_483_647)] {
        client
            .add_txt_value(
                &zone(),
                &dn(owner),
                &txt("v4"),
                Some(RrsetTtl::from_secs(secs).unwrap()),
            )
            .await
            .unwrap();
        assert_eq!(mock.control().records(&format!("{owner}."))[0].ttl, secs);
    }
    // The configured TTL.
    let mut config = settings(&mock, KEY);
    config.ttl = RrsetTtl::from_secs(300).unwrap();
    let custom = Rfc2136::new(config, credentials(STANDARD_SECRET), &context()).unwrap();
    custom
        .add_txt_value(&zone(), &dn("x.example.org"), &txt("v5"), None)
        .await
        .unwrap();
    assert_eq!(mock.control().records("x.example.org.")[0].ttl, 300);
}

#[tokio::test]
async fn rfc2136_hmac_sha512_key() {
    let mock = Rfc2136Mock::start(Seed::standard()).await;
    let mut config = settings(&mock, KEY_NAME_512.trim_end_matches('.'));
    config.algorithm = "hmac-sha512".to_owned();
    let client = Rfc2136::new(config, credentials(STANDARD_SECRET_512), &context()).unwrap();
    assert_eq!(add(&client, "v1").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.control().txt(NAME_DOT), ["v1"]);
    assert_eq!(mock.control().calls()[0].request_mac.len(), 64);
}

/// A server ignores the add of a TXT record at a name that holds a CNAME and still answers
/// NOERROR (RFC 2136 section 3.4.2.2). The add carries the prerequisite "no CNAME RRset"
/// (section 2.4.3), so it is `Rejected` instead of a `Created` for nothing; with read access, on
/// the blind path, and when the CNAME appears between the read and the write. A removal finds no
/// TXT value and writes nothing.
#[tokio::test]
async fn rfc2136_add_next_to_a_cname_is_rejected() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let cname = MockRecord {
        name: NAME_DOT.to_owned(),
        rtype: TYPE_CNAME,
        ttl: 300,
        rdata: b"\x06target\x07example\x03org\x00".to_vec(),
    };
    control.add_record(cname.clone());
    let err = add(&client, "v1").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Rejected, "{err:?}");
    assert!(err.to_string().contains("CNAME"), "{err}");
    assert_eq!((queries(&mock), updates(&mock)), (1, 1));
    let calls = control.calls();
    let update = calls.iter().find(|c| c.op == Op::Update).unwrap();
    assert_eq!(update.prereqs.len(), 1);
    let prereq = &update.prereqs[0];
    assert_eq!(
        (prereq.name.as_str(), prereq.rtype, prereq.class, prereq.ttl),
        (NAME_DOT, TYPE_CNAME, 254, 0)
    );
    assert!(prereq.rdata.is_empty());
    assert_eq!(control.records(NAME_DOT), std::slice::from_ref(&cname));

    // Removal: no TXT value at the name, nothing written.
    control.clear_calls();
    assert_eq!(
        remove(&client, "v1").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(updates(&mock), 0);

    // The blind path.
    control.refuse_queries(true);
    assert_eq!(
        add(&client, "v1").await.unwrap_err().kind(),
        ErrorKind::Rejected
    );
    assert_eq!(control.records(NAME_DOT), std::slice::from_ref(&cname));
    control.refuse_queries(false);

    // A CNAME created by another writer between the read and the write: the server evaluates
    // the prerequisite with the update.
    let (mock, client) = setup().await;
    let control = mock.control();
    control.push(Fault::on(Op::Update).foreign_record(cname.clone()));
    assert_eq!(
        add(&client, "v0").await.unwrap_err().kind(),
        ErrorKind::Rejected
    );
    assert_eq!((queries(&mock), updates(&mock)), (1, 1));
    assert_eq!(control.records(NAME_DOT), [cname]);
}

// ---- Blind writes (design section 3.5) ---------------------------------------------------------

/// A server that lets the key update but refuses its queries: the change is sent without a read
/// and the outcome is `Accepted`, never a guessed `Created` or `Removed`.
#[tokio::test]
async fn rfc2136_works_when_queries_are_refused() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_txt(NAME_DOT, "foreign", 600);
    control.refuse_queries(true);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Accepted);
    assert_eq!(control.txt(NAME_DOT), ["AAA", "foreign"]);
    // Without a read the add carries the configured TTL (design section 3.6).
    assert_eq!(update_records(&mock)[0].2, DEFAULT_TTL);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Accepted
    );
    assert_eq!(control.txt(NAME_DOT), ["foreign"]);
    // A blind removal of a value that is not there deletes nothing else.
    assert_eq!(
        remove(&client, "absent").await.unwrap(),
        RemoveOutcome::Accepted
    );
    assert_eq!(control.txt(NAME_DOT), ["foreign"]);
    assert_eq!(control.rrset_deletes(), 0);
}

// ---- Answers that are not trusted --------------------------------------------------------------

/// An answer that is not correctly signed with the key, or does not match the request, is
/// `Protocol` and is not repeated.
#[tokio::test]
async fn rfc2136_forged_or_mismatched_answers_are_refused() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for (label, fault) in [
        ("unsigned", Fault::on(Op::Query).unsigned()),
        ("corrupt mac", Fault::on(Op::Query).corrupt_mac()),
        ("other key", Fault::on(Op::Query).other_key()),
        ("time outside fudge", Fault::on(Op::Query).time_offset(1000)),
        ("wrong id", Fault::on(Op::Query).wrong_id()),
        ("wrong question", Fault::on(Op::Query).wrong_question()),
        ("missing question", Fault::on(Op::Query).omit_question()),
        ("qr clear", Fault::on(Op::Query).clear_qr()),
        ("tc set", Fault::on(Op::Query).set_tc()),
        ("short length prefix", Fault::on(Op::Query).short_length()),
    ] {
        control.clear_calls();
        control.push(fault);
        let err = add(&client, "v1").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol, "{label}: {err:?}");
        assert_eq!(
            control.calls().len(),
            1,
            "{label}: not repeated, nothing written"
        );
    }
    // The same for the answer to an update: the value may be written, but no success is
    // reported on an unverified answer.
    for (value, fault) in [
        ("v2", Fault::on(Op::Update).unsigned()),
        ("v3", Fault::on(Op::Update).corrupt_mac()),
        ("v4", Fault::on(Op::Update).wrong_question()),
    ] {
        control.push(fault);
        assert_eq!(
            add(&client, value).await.unwrap_err().kind(),
            ErrorKind::Protocol
        );
    }
    // An update answer may leave the zone section empty (RFC 2136 section 3.8).
    control.push(Fault::on(Op::Update).omit_question());
    assert_eq!(add(&client, "v5").await.unwrap(), AddOutcome::Appended);
}

/// An unsigned answer with any RCODE is refused: a forged NXDOMAIN cannot turn a removal into
/// `NotPresent`, a forged REFUSED cannot start the blind path, a forged NOTAUTH or REFUSED to an
/// update cannot pass for a server's refusal (RFC 8945 section 5.4).
#[tokio::test]
async fn rfc2136_unsigned_error_answers_are_refused() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_txt(NAME_DOT, "AAA", 60);
    control.push(Fault::on(Op::Query).rcode(NXDOMAIN).unsigned());
    let err = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Protocol, "{err:?}");
    assert_eq!(control.txt(NAME_DOT), ["AAA"]);
    assert_eq!(updates(&mock), 0);
    for rcode in [REFUSED, NOTAUTH] {
        control.push(Fault::on(Op::Query).rcode(rcode).unsigned());
        let err = add(&client, "BBB").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol, "{rcode}: {err:?}");
    }
    assert_eq!(
        updates(&mock),
        0,
        "a forged REFUSED does not lead to a blind write"
    );
    control.push(Fault::on(Op::Update).rcode(NOTAUTH).unsigned());
    let err = client.check(&[zone()]).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Protocol, "{err:?}");
    assert_eq!(control.txt(NAME_DOT), ["AAA"]);
}

/// An answer without AA does not come from an authority for the zone: an empty one must not
/// make a removal `NotPresent`.
#[tokio::test]
async fn rfc2136_non_authoritative_answer_is_zone_not_found() {
    let (mock, client) = setup().await;
    mock.control().add_txt(NAME_DOT, "AAA", 60);
    mock.control().push(Fault::on(Op::Query).clear_aa());
    let err = remove(&client, "AAA").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ZoneNotFound, "{err:?}");
    assert_eq!(updates(&mock), 0);
    assert_eq!(mock.control().txt(NAME_DOT), ["AAA"]);
}

// ---- Server errors -----------------------------------------------------------------------------

#[tokio::test]
async fn rfc2136_tsig_errors_are_auth_errors() {
    let mock = Rfc2136Mock::start(Seed::standard()).await;
    let ctx = context();
    // Wrong secret: BADSIG.
    let wrong = client_with(&mock, KEY, b"wrong-secret-wrong-secret-wrong!", &ctx);
    let err = add(&wrong, "AAA").await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth { detail, .. } if detail.as_str().contains("BADSIG")),
        "{err:?}"
    );
    // Unknown key name: BADKEY.
    let nobody = client_with(&mock, "nobody", STANDARD_SECRET, &ctx);
    let err = nobody.check(&[zone()]).await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth { detail, .. } if detail.as_str().contains("BADKEY")),
        "{err:?}"
    );
    // The key's algorithm differs from the server's: BADKEY as well.
    let mut config = settings(&mock, KEY);
    config.algorithm = "hmac-sha512".to_owned();
    let other_alg = Rfc2136::new(config, credentials(STANDARD_SECRET), &ctx).unwrap();
    assert_eq!(
        remove(&other_alg, "AAA").await.unwrap_err().kind(),
        ErrorKind::Auth
    );
    // The server's clock is beyond the fudge: BADTIME, with the clock hint.
    mock.control().clock_skew(1000);
    let client = client_with(&mock, KEY, STANDARD_SECRET, &ctx);
    let err = add(&client, "AAA").await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth { detail, .. } if detail.as_str().contains("BADTIME")
            && detail.as_str().contains("clock")),
        "{err:?}"
    );
    assert!(mock.control().txt(NAME_DOT).is_empty(), "nothing written");
    // TSIG errors are final: one request each.
    assert!(mock.control().calls().iter().all(|c| c.tsig_error != 0));
    assert_eq!(mock.control().calls().len(), 4);
}

#[tokio::test]
async fn rfc2136_servfail_is_retried_and_refused_update_is_forbidden() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.push(Fault::on(Op::Update).rcode(SERVFAIL));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(control.txt(NAME_DOT), ["AAA"]);
    assert_eq!(updates(&mock), 2, "one repeat after SERVFAIL");
    control.push(Fault::on(Op::Query).rcode(SERVFAIL).times(2));
    assert_eq!(
        add(&client, "AAA").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    control.push(Fault::on(Op::Update).rcode(REFUSED));
    let err = add(&client, "BBB").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Forbidden, "{err:?}");
    assert_eq!(control.txt(NAME_DOT), ["AAA"]);
    control.push(Fault::on(Op::Update).rcode(FORMERR));
    let err = remove(&client, "AAA").await.unwrap_err();
    assert!(
        matches!(&err, Error::Rejected { status: None, detail, .. }
            if detail.as_str().contains("FORMERR")),
        "{err:?}"
    );
    // A query answered other than NOERROR, NXDOMAIN, REFUSED, NOTAUTH or SERVFAIL.
    control.push(Fault::on(Op::Query).rcode(FORMERR));
    assert_eq!(
        add(&client, "BBB").await.unwrap_err().kind(),
        ErrorKind::Rejected
    );
}

#[tokio::test]
async fn rfc2136_foreign_zone() {
    let (mock, client) = setup().await;
    let other = dn("other.org");
    // The query for a name outside every zone is refused, the update NOTAUTH.
    let err = client
        .add_txt_value(&other, &dn("_acme-challenge.other.org"), &txt("AAA"), None)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ZoneNotFound, "{err:?}");
    // NOTAUTH on the query itself.
    mock.control().push(Fault::on(Op::Query).rcode(NOTAUTH));
    assert_eq!(
        add(&client, "AAA").await.unwrap_err().kind(),
        ErrorKind::ZoneNotFound
    );
    // NOTZONE on the update: the server sees the name outside the zone.
    mock.control().push(Fault::on(Op::Update).rcode(10));
    assert_eq!(
        add(&client, "AAA").await.unwrap_err().kind(),
        ErrorKind::NameOutsideZone
    );
    assert!(mock.control().txt(NAME_DOT).is_empty());
}

// ---- Connections -------------------------------------------------------------------------------

#[tokio::test]
async fn rfc2136_connection_failures_are_retried_and_bounded() {
    let (mock, client) = setup().await;
    let control = mock.control();
    // A connection closed without an answer, or an answer cut short: repeated, then success.
    control.push(Fault::on(Op::Query).close());
    control.push(Fault::on(Op::Query).truncate());
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(queries(&mock), 3);
    // Three in a row: `Transient`, after exactly three attempts.
    control.clear_calls();
    control.push(Fault::on(Op::Update).truncate().times(3));
    assert_eq!(
        add(&client, "BBB").await.unwrap_err().kind(),
        ErrorKind::Transient
    );
    assert_eq!(updates(&mock), 3);
    // A server that does not listen.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let config = Rfc2136Config::new(closed.to_string(), KEY.to_owned());
    let nowhere = Rfc2136::new(config, credentials(STANDARD_SECRET), &context()).unwrap();
    let err = add(&nowhere, "AAA").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Transient, "{err:?}");
}

#[tokio::test]
async fn rfc2136_slow_server_times_out() {
    let mock = Rfc2136Mock::start(Seed::standard()).await;
    let client = client_with(&mock, KEY, STANDARD_SECRET, &context_with_timeout(200));
    mock.control().push(
        Fault::on(Op::Query)
            .delay(Duration::from_millis(800))
            .times(3),
    );
    let started = std::time::Instant::now();
    let err = add(&client, "AAA").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Transient, "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    // The mock logs a request when its delay ends; wait for the last one.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert_eq!(queries(&mock), 3);
    // One slow answer is repeated and then succeeds.
    mock.control()
        .push(Fault::on(Op::Query).delay(Duration::from_millis(800)));
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

// ---- check -------------------------------------------------------------------------------------

#[tokio::test]
async fn rfc2136_check_reports_zones() {
    let (mock, client) = setup().await;
    let report = client.check(&[zone(), dn("other.org")]).await.unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones[0].found && report.zones[0].detail.is_none());
    assert!(!report.zones[1].found);
    assert!(
        report.zones[1]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("NOTAUTH")
    );
    // A zone the key may not update.
    mock.control().push(Fault::on(Op::Update).rcode(REFUSED));
    let report = client.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    assert!(
        report.zones[0]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("REFUSED")
    );
    // The check changes nothing: an update whose only content is a prerequisite.
    let calls = mock.control().calls();
    assert!(calls.iter().all(|c| c.updates.is_empty()));
    assert!(
        calls
            .iter()
            .all(|c| c.prereqs.len() == 1 && c.prereqs[0].class == 255)
    );
    assert!(mock.control().records("example.org.").is_empty());
}

/// SERVFAIL to the query of `check(&[])` is repeated and then `Transient`, never a report.
#[tokio::test]
async fn rfc2136_check_without_zones_servfail_is_transient() {
    let (mock, client) = setup().await;
    mock.control()
        .push(Fault::on(Op::Query).rcode(SERVFAIL).times(3));
    let err = tokio::time::timeout(SLOW, client.check(&[]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Transient, "{err:?}");
    assert_eq!(queries(&mock), 3);
}

/// A signed answer that reports a TSIG error under an RCODE other than NOTAUTH contradicts RFC
/// 8945 sections 5.2.1 to 5.2.3, where every TSIG error a server reports carries RCODE 9
/// (NOTAUTH): it is `Protocol`, neither a success nor an `Auth` error, and it is not repeated.
#[tokio::test]
async fn rfc2136_tsig_error_without_notauth_is_protocol() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.push(Fault::on(Op::Update).rcode(NOERROR).tsig_error(BADSIG));
    let err = add(&client, "v1").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Protocol, "{err:?}");
    assert_eq!(updates(&mock), 1);
    control.push(Fault::on(Op::Query).rcode(NOERROR).tsig_error(BADTIME));
    assert_eq!(
        client.check(&[]).await.unwrap_err().kind(),
        ErrorKind::Protocol
    );
}

/// A NOTAUTH answer that reports a TSIG error other than an unsigned BADKEY or BADSIG is honored
/// only when its MAC verifies against the request MAC (RFC 8945 sections 5.2.3, 5.3.2 and 5.4).
/// With a corrupted MAC it is `Protocol`, not `Auth`, and it is not repeated.
#[tokio::test]
async fn rfc2136_tsig_error_with_a_bad_mac_is_protocol() {
    /// TSIG error BADTRUNC (RFC 8945 section 3).
    const BADTRUNC: u16 = 22;
    let (mock, client) = setup().await;
    let control = mock.control();
    control.push(
        Fault::on(Op::Update)
            .rcode(NOTAUTH)
            .tsig_error(BADTIME)
            .corrupt_mac(),
    );
    let err = add(&client, "v1").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Protocol, "{err:?}");
    assert_eq!(updates(&mock), 1);
    control.push(
        Fault::on(Op::Update)
            .rcode(NOTAUTH)
            .tsig_error(BADTRUNC)
            .corrupt_mac(),
    );
    let err = add(&client, "v1").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Protocol, "{err:?}");
    assert_eq!(updates(&mock), 2);
    let before = queries(&mock);
    control.push(
        Fault::on(Op::Query)
            .rcode(NOTAUTH)
            .tsig_error(BADTIME)
            .corrupt_mac(),
    );
    let err = client.check(&[]).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Protocol, "{err:?}");
    assert_eq!(queries(&mock), before + 1);
    assert!(mock.control().txt(NAME_DOT).is_empty(), "nothing written");
}

/// Without zones, `check` still exercises the key: a signed query whose answer is verified.
#[tokio::test]
async fn rfc2136_check_exercises_the_credentials() {
    let (mock, client) = setup().await;
    let report = client.check(&[]).await.unwrap();
    assert!(report.credentials_verified);
    assert!(report.zones.is_empty());
    assert_eq!(queries(&mock), 1);
    let wrong = client_with(&mock, KEY, b"wrong-secret-wrong-secret-wrong!", &context());
    assert_eq!(wrong.check(&[]).await.unwrap_err().kind(), ErrorKind::Auth);
    assert_eq!(
        wrong.check(&[zone()]).await.unwrap_err().kind(),
        ErrorKind::Auth
    );
    mock.control().push(Fault::on(Op::Query).unsigned());
    assert_eq!(
        client.check(&[]).await.unwrap_err().kind(),
        ErrorKind::Protocol
    );
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn rfc2136_config_validation() {
    let mock = Rfc2136Mock::start(Seed::standard()).await;
    let ctx = context();
    let good = b64(STANDARD_SECRET);
    let cases: Vec<(serde_json::Value, String, &str)> = vec![
        (serde_json::json!({}), "not base64!".to_owned(), "base64"),
        (serde_json::json!({}), b64(b"short"), "at least 16"),
        (
            serde_json::json!({ "algorithm": "hmac-md5" }),
            good.clone(),
            "algorithm",
        ),
        (serde_json::json!({ "server": "" }), good.clone(), "server"),
        (
            serde_json::json!({ "server": "127.0.0.1:0" }),
            good.clone(),
            "server",
        ),
        (
            serde_json::json!({ "key_name": "bad key" }),
            good.clone(),
            "key_name",
        ),
        (serde_json::json!({ "ttl": 0 }), good.clone(), "ttl"),
        (serde_json::json!({ "ttl": 86401 }), good.clone(), "ttl"),
        // The context refuses anything but loopback addresses.
        (
            serde_json::json!({ "server": "ns1.example.org" }),
            good.clone(),
            "loopback",
        ),
        (
            serde_json::json!({ "server": "localhost:53" }),
            good.clone(),
            "loopback",
        ),
        (
            serde_json::json!({ "server": "192.0.2.1" }),
            good.clone(),
            "loopback",
        ),
    ];
    for (extra, secret, needle) in cases {
        let mut settings = serde_json::json!({ "server": mock.server(), "key_name": KEY });
        for (k, v) in extra.as_object().unwrap() {
            settings[k] = v.clone();
        }
        let credentials = serde_json::json!({ "secret": secret }).to_string();
        let err = AnyProvider::from_json(
            ProviderId::Rfc2136,
            &settings.to_string(),
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config, "{needle}: {err:?}");
        assert!(err.to_string().contains(needle), "{needle}: {err}");
        assert!(!err.to_string().contains(&secret));
    }
    // Missing keys, unknown keys, malformed credentials.
    for (settings, credentials, needle) in [
        (
            r#"{"key_name":"k"}"#,
            format!(r#"{{"secret":"{good}"}}"#),
            "server",
        ),
        (
            &format!(r#"{{"server":"{}"}}"#, mock.server()) as &str,
            format!(r#"{{"secret":"{good}"}}"#),
            "key_name",
        ),
        (
            &format!(
                r#"{{"server":"{}","key_name":"k","extra":1}}"#,
                mock.server()
            ),
            format!(r#"{{"secret":"{good}"}}"#),
            "unknown keys",
        ),
        (
            &format!(r#"{{"server":"{}","key_name":"k"}}"#, mock.server()),
            r#"{"password":"x"}"#.to_owned(),
            "secret",
        ),
    ] {
        let err = AnyProvider::from_json(
            ProviderId::Rfc2136,
            settings,
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
        assert!(err.to_string().contains(needle), "{needle}: {err}");
    }
    // `null` for the optional keys means the default; IPv6 loopback is a loopback address.
    let settings = format!(
        r#"{{"server":"{}","key_name":"{KEY}","algorithm":null,"ttl":null}}"#,
        mock.server()
    );
    let client = AnyProvider::from_json(
        ProviderId::Rfc2136,
        &settings,
        &SecretString::from(format!(r#"{{"secret":"{good}"}}"#)),
        &ctx,
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Rfc2136);
    assert_eq!(add(&client, "v1").await.unwrap(), AddOutcome::Created);
    let v6 = Rfc2136Config::new("[::1]:53".to_owned(), KEY.to_owned());
    assert!(Rfc2136::new(v6, credentials(STANDARD_SECRET), &ctx).is_ok());
    // Without `loopback_only` a host name is accepted (and resolved only when used).
    let open = Context::new(ContextOptions::default()).unwrap();
    let host = Rfc2136Config::new("ns1.example.org:5353".to_owned(), KEY.to_owned());
    let client = Rfc2136::new(host, credentials(STANDARD_SECRET), &open).unwrap();
    let debug = format!("{client:?}");
    assert!(debug.contains("ns1.example.org:5353") && debug.contains(KEY));
    assert!(!ProviderId::Rfc2136.meta().verified);
}

// ---- Record level (design sections 3.4, 11.3 and 12.3) -----------------------------------------

/// An SOA value for the apex.
const SOA_TEXT: &str = "ns1.example.org. admin.example.org. 2026111401 7200 3600 1209600 300";

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

fn wire(rtype: RecordType, text: &str) -> Vec<u8> {
    rd(rtype, text).to_wire(rtype).unwrap()
}

/// A record as the mock holds it.
fn mock_record(name: &str, rtype: RecordType, ttl: u32, text: &str) -> MockRecord {
    MockRecord {
        name: format!("{}.", name.trim_end_matches('.')),
        rtype: rtype.code().unwrap(),
        ttl,
        rdata: wire(rtype, text),
    }
}

async fn get(
    client: &impl Provider,
    name: &str,
    rtype: RecordType,
) -> Result<Option<RrSet>, Error> {
    tokio::time::timeout(SLOW, client.get_rrset(&zone(), &dn(name), rtype))
        .await
        .expect("the operation is bounded")
}

async fn set(client: &impl Provider, set: &RrSet, expect: Expect<'_>) -> Result<SetOutcome, Error> {
    tokio::time::timeout(SLOW, client.set_rrset(&zone(), set, expect))
        .await
        .expect("the operation is bounded")
}

async fn delete(
    client: &impl Provider,
    name: &str,
    rtype: RecordType,
    expect: Expect<'_>,
) -> Result<DeleteOutcome, Error> {
    tokio::time::timeout(SLOW, client.delete_rrset(&zone(), &dn(name), rtype, expect))
        .await
        .expect("the operation is bounded")
}

/// The RDATA the mock holds for `name` and `rtype`, sorted, with the TTLs.
fn stored(mock: &Rfc2136Mock, name: &str, rtype: RecordType) -> Vec<(Vec<u8>, u32)> {
    let mut out: Vec<(Vec<u8>, u32)> = mock
        .control()
        .records_of(
            &format!("{}.", name.trim_end_matches('.')),
            rtype.code().unwrap(),
        )
        .into_iter()
        .map(|r| (r.rdata, r.ttl))
        .collect();
    out.sort();
    out
}

/// The update calls received so far.
fn update_calls(mock: &Rfc2136Mock) -> Vec<Call> {
    mock.control()
        .calls()
        .into_iter()
        .filter(|c| c.op == Op::Update)
        .collect()
}

/// Every type the record model has a canonical form for, plus a type without one, through set,
/// get and an identical set: at the apex where the type allows it, at a wildcard name, at an IDN
/// name, below the apex as a delegation (NS), with a long TXT value and with multi-value sets.
/// What the server stores is the wire form of the requested values, and a value read back is
/// canonical and equal to the requested one, also where the server compressed names inside the
/// RDATA (MX, NS, CNAME, PTR at names that share a suffix with the question).
#[tokio::test]
async fn rfc2136_record_round_trips() {
    let (mock, client) = setup().await;
    let long = format!("\"{}\"", "x".repeat(600));
    let idn = dn("пример.example.org");
    let idn = idn.as_str().to_owned();
    let cases: Vec<(String, RecordType, Option<u32>, Vec<String>)> = [
        (
            "rt.example.org",
            RecordType::A,
            Some(300),
            vec!["192.0.2.1", "192.0.2.2", "192.0.2.3"],
        ),
        (
            "rt.example.org",
            RecordType::AAAA,
            None,
            vec!["2001:db8::1"],
        ),
        ("example.org", RecordType::A, None, vec!["192.0.2.80"]),
        (
            "example.org",
            RecordType::MX,
            Some(3600),
            vec!["10 mail.example.org.", "20 mx.example.net."],
        ),
        (
            "example.org",
            RecordType::TXT,
            None,
            vec!["\"v=spf1 mx -all\"", "\"quote \\\" and \\\\\""],
        ),
        (
            "example.org",
            RecordType::CAA,
            None,
            vec!["0 issue \"ca.example.net\""],
        ),
        (
            "example.org",
            RecordType::HTTPS,
            None,
            vec!["1 . alpn=\"h2\""],
        ),
        (
            "_sip._tcp.example.org",
            RecordType::SRV,
            None,
            vec!["0 5 5060 sip.example.org.", "0 0 0 ."],
        ),
        (
            "alias.example.org",
            RecordType::CNAME,
            None,
            vec!["target.alias.example.org."],
        ),
        (
            "ptr.example.org",
            RecordType::PTR,
            None,
            vec!["host.ptr.example.org."],
        ),
        (
            "_443._tcp.example.org",
            RecordType::TLSA,
            None,
            vec!["3 1 1 0a1b2c3d4e5f"],
        ),
        (
            "ssh.example.org",
            RecordType::SSHFP,
            None,
            vec!["4 2 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"],
        ),
        (
            "svc.example.org",
            RecordType::SVCB,
            None,
            vec!["1 . alpn=\"h2,h3\" port=8443"],
        ),
        (
            "dname.example.org",
            RecordType::DNAME,
            None,
            vec!["other.example.net."],
        ),
        (
            "child.example.org",
            RecordType::NS,
            None,
            vec!["ns1.child.example.org.", "ns2.example.net."],
        ),
        ("*.example.org", RecordType::A, None, vec!["192.0.2.10"]),
        (
            "unknown.example.org",
            RecordType::from_code(65_280),
            None,
            vec!["\\# 3 010203"],
        ),
    ]
    .into_iter()
    .map(|(n, t, ttl, v)| {
        (
            n.to_owned(),
            t,
            ttl,
            v.into_iter().map(str::to_owned).collect(),
        )
    })
    .chain([(
        idn.clone(),
        RecordType::TXT,
        None,
        vec![long.clone(), "\"second\"".to_owned()],
    )])
    .collect();
    for (name, rtype, ttl, texts) in &cases {
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        let wanted = rrset(name, *rtype, *ttl, &texts);
        assert_eq!(
            set(&client, &wanted, Expect::Absent).await.unwrap(),
            SetOutcome::Created,
            "{name} {rtype}"
        );
        let read = get(&client, name, *rtype).await.unwrap().unwrap();
        let ttl = ttl.unwrap_or(DEFAULT_TTL);
        assert_eq!(
            read,
            wanted
                .clone()
                .with_ttl(Some(RrsetTtl::from_secs(ttl).unwrap())),
            "{name}"
        );
        assert!(read.records().iter().all(RecordData::is_canonical));
        let mut expected: Vec<(Vec<u8>, u32)> =
            texts.iter().map(|t| (wire(*rtype, t), ttl)).collect();
        expected.sort();
        assert_eq!(stored(&mock, name, *rtype), expected, "{name} {rtype}");
        // The same set again writes nothing.
        mock.control().clear_calls();
        assert_eq!(
            set(&client, &wanted, Expect::Any).await.unwrap(),
            SetOutcome::Unchanged,
            "{name} {rtype}"
        );
        assert_eq!(updates(&mock), 0);
        // A replacement keeps the RDATA of the records that stay exactly as the server holds
        // it: the prerequisite naming them matches.
        let mut more = texts.clone();
        let extra = match *rtype {
            t if t == RecordType::A => Some("192.0.2.99"),
            t if t == RecordType::MX => Some("30 mail.example.org."),
            t if t == RecordType::NS => Some("ns3.child.example.org."),
            t if t == RecordType::TXT => Some("\"third\""),
            _ => None,
        };
        if let Some(extra) = extra {
            more.push(extra);
            let bigger = rrset(name, *rtype, None, &more);
            assert_eq!(
                set(&client, &bigger, Expect::Matches(&read)).await.unwrap(),
                SetOutcome::Replaced,
                "{name} {rtype}"
            );
            let again = get(&client, name, *rtype).await.unwrap().unwrap();
            assert!(again.same_records(&bigger));
            assert_eq!(again.ttl(), Some(RrsetTtl::from_secs(ttl).unwrap()));
        }
    }
    // Everything at once is still there: no operation touched another name or type.
    for (name, rtype, _, texts) in &cases {
        let read = get(&client, name, *rtype).await.unwrap().unwrap();
        for text in texts {
            assert!(read.contains(&rd(*rtype, text)), "{name} {rtype}");
        }
    }
    assert_eq!(mock.control().name_deletes(), 0);
}

/// `Expect::Absent` on an existing set, `Expect::Matches` on a changed, a missing or a
/// differently timed set: `PreconditionFailed`, and no update is sent.
#[tokio::test]
async fn rfc2136_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_record(mock_record(
        "e.example.org",
        RecordType::A,
        300,
        "192.0.2.1",
    ));
    let current = rrset("e.example.org", RecordType::A, Some(300), &["192.0.2.1"]);
    let wanted = rrset("e.example.org", RecordType::A, None, &["192.0.2.2"]);
    let changed = rrset("e.example.org", RecordType::A, None, &["192.0.2.3"]);
    let other_ttl = rrset("e.example.org", RecordType::A, Some(600), &["192.0.2.1"]);
    let missing = rrset("f.example.org", RecordType::A, None, &["192.0.2.1"]);
    let cases = [
        set(&client, &wanted, Expect::Absent).await,
        set(&client, &wanted, Expect::Matches(&changed)).await,
        set(&client, &wanted, Expect::Matches(&other_ttl)).await,
        set(&client, &missing, Expect::Matches(&missing)).await,
    ];
    for result in cases {
        assert_eq!(result.unwrap_err().kind(), ErrorKind::PreconditionFailed);
    }
    let deletes = [
        delete(
            &client,
            "e.example.org",
            RecordType::A,
            Expect::Matches(&changed),
        )
        .await,
        delete(
            &client,
            "e.example.org",
            RecordType::A,
            Expect::Matches(&other_ttl),
        )
        .await,
        delete(
            &client,
            "f.example.org",
            RecordType::A,
            Expect::Matches(&missing),
        )
        .await,
    ];
    for result in deletes {
        assert_eq!(result.unwrap_err().kind(), ErrorKind::PreconditionFailed);
    }
    assert_eq!(updates(&mock), 0);
    assert_eq!(
        stored(&mock, "e.example.org", RecordType::A),
        [(vec![192, 0, 2, 1], 300)]
    );
    // The matching expectation passes, without a TTL and with the right one.
    let without_ttl = current.clone().with_ttl(None);
    assert_eq!(
        set(&client, &wanted, Expect::Matches(&without_ttl))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let now = rrset("e.example.org", RecordType::A, Some(300), &["192.0.2.2"]);
    assert_eq!(
        delete(
            &client,
            "e.example.org",
            RecordType::A,
            Expect::Matches(&now)
        )
        .await
        .unwrap(),
        DeleteOutcome::Deleted
    );
}

/// The messages: `Absent` travels as "RRset does not exist" plus the CNAME guard, `Matches` and
/// every write to an existing set as "RRset exists (value dependent)" with the RRs as the server
/// holds them, then "delete an RRset" and the adds, in one update; `Any` creates and replaces;
/// a delete names the set as read and deletes the RRset; "delete all RRsets from a name" is
/// never sent.
#[tokio::test]
async fn rfc2136_record_messages() {
    let (mock, client) = setup().await;
    let a = RecordType::A;
    let n = "m.example.org";
    let first = rrset(n, a, None, &["192.0.2.1", "192.0.2.2"]);
    assert_eq!(
        set(&client, &first, Expect::Any).await.unwrap(),
        SetOutcome::Created
    );
    let calls = update_calls(&mock);
    assert_eq!(calls.len(), 1);
    let prereqs: Vec<(u16, u16, u32, usize)> = calls[0]
        .prereqs
        .iter()
        .map(|p| (p.class, p.rtype, p.ttl, p.rdata.len()))
        .collect();
    assert_eq!(
        prereqs,
        [(CLASS_NONE, 1, 0, 0), (CLASS_NONE, TYPE_CNAME, 0, 0)]
    );
    assert!(
        calls[0]
            .updates
            .iter()
            .all(|u| u.class == CLASS_IN && u.ttl == DEFAULT_TTL)
    );
    assert_eq!(calls[0].updates.len(), 2);

    mock.control().clear_calls();
    let second = rrset(n, a, Some(120), &["192.0.2.2", "192.0.2.3"]);
    assert_eq!(
        set(&client, &second, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    let calls = update_calls(&mock);
    assert_eq!(calls.len(), 1);
    let mut prereq_rdata: Vec<Vec<u8>> = calls[0].prereqs.iter().map(|p| p.rdata.clone()).collect();
    prereq_rdata.sort();
    assert_eq!(prereq_rdata, [vec![192, 0, 2, 1], vec![192, 0, 2, 2]]);
    assert!(
        calls[0]
            .prereqs
            .iter()
            .all(|p| p.class == CLASS_IN && p.ttl == 0 && p.rtype == 1)
    );
    let updates_sent: Vec<(u16, u32, Vec<u8>)> = calls[0]
        .updates
        .iter()
        .map(|u| (u.class, u.ttl, u.rdata.clone()))
        .collect();
    assert_eq!(
        updates_sent,
        [
            (CLASS_ANY, 0, vec![]),
            (CLASS_IN, 120, vec![192, 0, 2, 2]),
            (CLASS_IN, 120, vec![192, 0, 2, 3]),
        ]
    );
    assert_eq!(
        stored(&mock, n, a),
        [(vec![192, 0, 2, 2], 120), (vec![192, 0, 2, 3], 120)]
    );

    // A set without a TTL keeps the TTL of the existing set.
    let third = rrset(n, a, None, &["192.0.2.4"]);
    assert_eq!(
        set(&client, &third, Expect::Matches(&second))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, n, a), [(vec![192, 0, 2, 4], 120)]);

    mock.control().clear_calls();
    assert_eq!(
        delete(&client, n, a, Expect::Any).await.unwrap(),
        DeleteOutcome::Deleted
    );
    let calls = update_calls(&mock);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].prereqs.len(), 1);
    assert_eq!(
        (calls[0].prereqs[0].class, calls[0].prereqs[0].rdata.clone()),
        (CLASS_IN, vec![192, 0, 2, 4])
    );
    let deletion: Vec<(u16, u16)> = calls[0]
        .updates
        .iter()
        .map(|u| (u.class, u.rtype))
        .collect();
    assert_eq!(deletion, [(CLASS_ANY, 1)]);
    assert!(stored(&mock, n, a).is_empty());
    // A missing set: `NotPresent`, nothing written; `Absent` has no meaning for a delete.
    mock.control().clear_calls();
    assert_eq!(
        delete(&client, n, a, Expect::Any).await.unwrap(),
        DeleteOutcome::NotPresent
    );
    assert_eq!(updates(&mock), 0);
    assert_eq!(
        delete(&client, n, a, Expect::Absent)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(queries(&mock), 1);
    assert_eq!(mock.control().name_deletes(), 0);
}

/// A change by another writer between the read and the update fails the update's prerequisite
/// and is not overwritten: the layer reads again and decides on the new state (`Expect::Any`
/// goes ahead, `Matches` and `Absent` fail); a second change in between is `Conflict`.
#[tokio::test]
async fn rfc2136_record_concurrent_change_is_conflict() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let a = RecordType::A;
    let n = "c.example.org";
    let mine = rrset(n, a, None, &["192.0.2.1"]);
    // Created by someone else after the read: YXRRSET, read again, `Absent` fails.
    control.push(Fault::on(Op::Update).foreign_record(mock_record(n, a, 600, "192.0.2.9")));
    assert_eq!(
        set(&client, &mine, Expect::Absent)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );
    assert_eq!((queries(&mock), updates(&mock)), (2, 1));
    assert_eq!(stored(&mock, n, a), [(vec![192, 0, 2, 9], 600)]);
    let foreign = rrset(n, a, Some(600), &["192.0.2.9"]);
    // Changed after the read: NXRRSET, read again, `Matches` fails and nothing is lost.
    control.clear_calls();
    control.push(Fault::on(Op::Update).foreign_record(mock_record(n, a, 600, "192.0.2.8")));
    assert_eq!(
        set(&client, &mine, Expect::Matches(&foreign))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PreconditionFailed
    );
    assert_eq!((queries(&mock), updates(&mock)), (2, 1));
    assert_eq!(stored(&mock, n, a).len(), 2);
    // `Any`: the second attempt writes on the new state.
    control.clear_calls();
    control.push(Fault::on(Op::Update).foreign_record(mock_record(n, a, 600, "192.0.2.7")));
    assert_eq!(
        set(&client, &mine, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!((queries(&mock), updates(&mock)), (2, 2));
    assert_eq!(stored(&mock, n, a), [(vec![192, 0, 2, 1], 600)]);
    // Two changes, one before each update: `Conflict`, and the other writer's state stands.
    control.clear_calls();
    control.push(Fault::on(Op::Update).foreign_record(mock_record(n, a, 600, "192.0.2.6")));
    control.push(Fault::on(Op::Update).foreign_record(mock_record(n, a, 600, "192.0.2.4")));
    assert_eq!(
        set(&client, &rrset(n, a, None, &["192.0.2.5"]), Expect::Any)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Conflict
    );
    assert_eq!((queries(&mock), updates(&mock)), (2, 2));
    assert_eq!(
        stored(&mock, n, a),
        [
            (vec![192, 0, 2, 1], 600),
            (vec![192, 0, 2, 4], 600),
            (vec![192, 0, 2, 6], 600)
        ]
    );
    // A delete whose set changed in between: read again, then delete the new set.
    control.clear_calls();
    control.push(Fault::on(Op::Update).foreign_delete(&format!("{n}."), 1));
    assert_eq!(
        delete(&client, n, a, Expect::Any).await.unwrap(),
        DeleteOutcome::NotPresent
    );
    assert_eq!((queries(&mock), updates(&mock)), (2, 1));
    assert_eq!(mock.control().name_deletes(), 0);
}

/// Record-level updates are conditional and sent exactly once whatever the failure (design
/// section 5.3): SERVFAIL, a connection closed before or after the server applied the update, a
/// refusal, a TSIG error, a forged answer. Counted exactly. A repeat of the call converges.
#[tokio::test]
async fn rfc2136_record_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let a = RecordType::A;
    let n = "w.example.org";
    let wanted = rrset(n, a, None, &["192.0.2.1"]);
    let faults: [(Fault, ErrorKind); 7] = [
        (Fault::on(Op::Update).rcode(SERVFAIL), ErrorKind::Transient),
        (Fault::on(Op::Update).close(), ErrorKind::Transient),
        (Fault::on(Op::Update).truncate(), ErrorKind::Transient),
        (Fault::on(Op::Update).rcode(REFUSED), ErrorKind::Forbidden),
        (
            Fault::on(Op::Update).rcode(NOTAUTH),
            ErrorKind::ZoneNotFound,
        ),
        (
            Fault::on(Op::Update).rcode(NOTAUTH).tsig_error(BADSIG),
            ErrorKind::Auth,
        ),
        (Fault::on(Op::Update).corrupt_mac(), ErrorKind::Protocol),
    ];
    for (fault, kind) in faults.clone() {
        control.clear_calls();
        control.push(fault);
        let err = set(&client, &wanted, Expect::Any).await.unwrap_err();
        assert_eq!(err.kind(), kind, "set: {err:?}");
        assert_eq!(updates(&mock), 1, "set: {kind:?}");
        // A truncated or forged answer comes after the server applied the update.
        delete(&client, n, a, Expect::Any).await.unwrap();
    }
    set(&client, &wanted, Expect::Any).await.unwrap();
    for (fault, kind) in faults {
        control.clear_calls();
        control.push(fault);
        let err = delete(&client, n, a, Expect::Any).await.unwrap_err();
        assert_eq!(err.kind(), kind, "delete: {err:?}");
        assert_eq!(updates(&mock), 1, "delete: {kind:?}");
        // Keep the set for the next case.
        set(&client, &wanted, Expect::Any).await.unwrap();
    }
    // An answer lost after the server applied the update: `Transient`, and the repeat sees the
    // new state.
    control.clear_calls();
    control.push(Fault::on(Op::Update).drop_reply());
    let other = rrset(n, a, None, &["192.0.2.2"]);
    assert_eq!(
        set(&client, &other, Expect::Any).await.unwrap_err().kind(),
        ErrorKind::Transient
    );
    assert_eq!(updates(&mock), 1);
    assert_eq!(
        set(&client, &other, Expect::Any).await.unwrap(),
        SetOutcome::Unchanged
    );
    control.clear_calls();
    control.push(Fault::on(Op::Update).drop_reply());
    assert_eq!(
        delete(&client, n, a, Expect::Any).await.unwrap_err().kind(),
        ErrorKind::Transient
    );
    assert_eq!(updates(&mock), 1);
    assert_eq!(
        delete(&client, n, a, Expect::Any).await.unwrap(),
        DeleteOutcome::NotPresent
    );
    // Reads are repeated as every query is.
    control.clear_calls();
    control.push(Fault::on(Op::Query).rcode(SERVFAIL).times(2));
    assert_eq!(get(&client, n, a).await.unwrap(), None);
    assert_eq!(queries(&mock), 3);
}

/// Other names, and other types at the same name, are untouched by every record operation.
#[tokio::test]
async fn rfc2136_record_operations_leave_other_sets_alone() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let n = "o.example.org";
    let others = [
        mock_record(n, RecordType::TXT, 600, "\"keep\""),
        mock_record(n, RecordType::AAAA, 600, "2001:db8::5"),
        mock_record("x.o.example.org", RecordType::A, 600, "192.0.2.50"),
        mock_record("example.org", RecordType::A, 600, "192.0.2.51"),
        mock_record("p.example.org", RecordType::A, 600, "192.0.2.52"),
    ];
    for record in &others {
        control.add_record(record.clone());
    }
    let a = RecordType::A;
    set(&client, &rrset(n, a, None, &["192.0.2.1"]), Expect::Absent)
        .await
        .unwrap();
    set(
        &client,
        &rrset(n, a, Some(90), &["192.0.2.2", "192.0.2.3"]),
        Expect::Any,
    )
    .await
    .unwrap();
    delete(&client, n, a, Expect::Any).await.unwrap();
    let mut left = control.all_records();
    left.sort_by(|x, y| (&x.name, x.rtype, &x.rdata).cmp(&(&y.name, y.rtype, &y.rdata)));
    let mut expected = others.to_vec();
    expected.sort_by(|x, y| (&x.name, x.rtype, &x.rdata).cmp(&(&y.name, y.rtype, &y.rdata)));
    assert_eq!(left, expected);
    assert_eq!(control.name_deletes(), 0);
}

/// SOA is read-only and the apex NS set is not writable: refused before any request. Both can
/// be read.
#[tokio::test]
async fn rfc2136_record_soa_and_apex_ns_are_not_writable() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_record(mock_record("example.org", RecordType::SOA, 3600, SOA_TEXT));
    control.add_record(mock_record(
        "example.org",
        RecordType::NS,
        3600,
        "ns1.example.org.",
    ));
    control.add_record(mock_record(
        "example.org",
        RecordType::NS,
        3600,
        "ns2.example.net.",
    ));
    let ns = rrset("example.org", RecordType::NS, None, &["ns3.example.org."]);
    let errors = [
        set(&client, &ns, Expect::Any).await.unwrap_err(),
        delete(&client, "example.org", RecordType::NS, Expect::Any)
            .await
            .unwrap_err(),
    ];
    for err in errors {
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err:?}");
    }
    let soa = rrset("example.org", RecordType::SOA, None, &[SOA_TEXT]);
    assert_eq!(
        set(&client, &soa, Expect::Any).await.unwrap_err().kind(),
        ErrorKind::UnsupportedRecordType
    );
    assert!(control.calls().is_empty());
    let read = get(&client, "example.org", RecordType::SOA)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, soa.with_ttl(Some(RrsetTtl::from_secs(3600).unwrap())));
    let read = get(&client, "example.org", RecordType::NS)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.records().len(), 2);
    assert_eq!(updates(&mock), 0);
}

/// The TTL range of the capabilities is the protocol's, 0 to 2^31 - 1 (RFC 2181 section 8): the
/// bounds and a delegation's 172800 are accepted; the configured TTL for a new set.
#[tokio::test]
async fn rfc2136_record_ttl_bounds() {
    let (mock, client) = setup().await;
    assert!(Ttl::from_secs(2_147_483_648).is_err());
    for ttl in [0, 1, 86_400, 86_401, 172_800, 2_147_483_647] {
        let wanted = rrset("t.example.org", RecordType::A, Some(ttl), &["192.0.2.1"]);
        set(&client, &wanted, Expect::Any).await.unwrap();
        assert_eq!(
            stored(&mock, "t.example.org", RecordType::A),
            [(vec![192, 0, 2, 1], ttl)]
        );
    }
    let mut config = settings(&mock, KEY);
    config.ttl = RrsetTtl::from_secs(300).unwrap();
    let custom = Rfc2136::new(config, credentials(STANDARD_SECRET), &context()).unwrap();
    let wanted = rrset("u.example.org", RecordType::A, None, &["192.0.2.1"]);
    set(&custom, &wanted, Expect::Absent).await.unwrap();
    assert_eq!(
        stored(&mock, "u.example.org", RecordType::A),
        [(vec![192, 0, 2, 1], 300)]
    );
}

/// RFC 2136 section 3.4.2.2: a server silently ignores a non-CNAME record added at a CNAME and a
/// CNAME added next to other data. The client refuses the first when its read saw the CNAME,
/// guards both with prerequisites, and never reports such an update as done.
#[tokio::test]
async fn rfc2136_record_cname_rules() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let c = "cn.example.org";
    control.add_record(mock_record(
        c,
        RecordType::CNAME,
        300,
        "target.example.org.",
    ));
    // Another type at a CNAME: refused after the read, no update.
    let a = rrset(c, RecordType::A, None, &["192.0.2.1"]);
    for expect in [Expect::Any, Expect::Absent] {
        let err = set(&client, &a, expect).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Rejected, "{err:?}");
    }
    assert_eq!(updates(&mock), 0);
    // A CNAME created between the read and the update: the guard fails (YXRRSET), the second
    // read sees it, and the client refuses.
    let d = "cd.example.org";
    control.push(Fault::on(Op::Update).foreign_record(mock_record(
        d,
        RecordType::CNAME,
        300,
        "t.example.org.",
    )));
    let err = set(
        &client,
        &rrset(d, RecordType::A, None, &["192.0.2.1"]),
        Expect::Any,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Rejected, "{err:?}");
    assert!(stored(&mock, d, RecordType::A).is_empty());
    // A CNAME next to other data: "name is not in use" fails (YXDOMAIN), nothing changes.
    let e = "ce.example.org";
    control.add_record(mock_record(e, RecordType::TXT, 300, "\"data\""));
    control.clear_calls();
    let cname = rrset(e, RecordType::CNAME, None, &["target.example.org."]);
    let err = set(&client, &cname, Expect::Any).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Rejected, "{err:?}");
    assert_eq!(updates(&mock), 1);
    let prereqs: Vec<(u16, u16)> = update_calls(&mock)[0]
        .prereqs
        .iter()
        .map(|p| (p.class, p.rtype))
        .collect();
    assert_eq!(prereqs, [(CLASS_NONE, TYPE_CNAME), (CLASS_NONE, TYPE_ANY)]);
    assert!(stored(&mock, e, RecordType::CNAME).is_empty());
    // A CNAME replaced by another: one update, and it is in place.
    let replaced = rrset(c, RecordType::CNAME, None, &["other.example.org."]);
    assert_eq!(
        set(&client, &replaced, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        get(&client, c, RecordType::CNAME)
            .await
            .unwrap()
            .unwrap()
            .records(),
        replaced.records()
    );
    // At a CNAME name a read of another type finds nothing, and its delete is `NotPresent`.
    assert_eq!(get(&client, c, RecordType::A).await.unwrap(), None);
    assert_eq!(
        delete(&client, c, RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
}

/// An update must fit one DNS message over TCP (65535 octets). A requested set that cannot fit
/// is refused before any request; a replacement that would not fit with the RRs read in its
/// prerequisite is refused after the read, before any update.
#[tokio::test]
async fn rfc2136_record_message_size() {
    let (mock, client) = setup().await;
    let value = |i: usize| format!("\"{i:04}{}\"", "v".repeat(250));
    let texts: Vec<String> = (0..300).map(value).collect();
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let huge = rrset("s.example.org", RecordType::TXT, None, &refs);
    let err = set(&client, &huge, Expect::Any).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err:?}");
    assert!(mock.control().calls().is_empty());
    // 120 RRs of about 260 octets each fit once (about 37000 octets) but not twice.
    let first: Vec<&str> = refs[..120].to_vec();
    let second: Vec<&str> = refs[120..240].to_vec();
    let a = rrset("s.example.org", RecordType::TXT, None, &first);
    let b = rrset("s.example.org", RecordType::TXT, None, &second);
    assert_eq!(
        set(&client, &a, Expect::Absent).await.unwrap(),
        SetOutcome::Created
    );
    mock.control().clear_calls();
    let err = set(&client, &b, Expect::Any).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err:?}");
    assert_eq!((queries(&mock), updates(&mock)), (1, 0));
    // The large set can still be deleted.
    assert_eq!(
        delete(&client, "s.example.org", RecordType::TXT, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
}

/// RDATA the record model cannot read is carried as non-canonical data in the generic form and
/// written back unchanged; a non-canonical value the server does not hold cannot be written.
#[tokio::test]
async fn rfc2136_record_non_canonical_data() {
    let (mock, client) = setup().await;
    let n = "nc.example.org";
    // Five octets are not an A record.
    mock.control().add_record(MockRecord {
        name: format!("{n}."),
        rtype: TYPE_A,
        ttl: 300,
        rdata: vec![192, 0, 2, 1, 7],
    });
    let read = get(&client, n, RecordType::A).await.unwrap().unwrap();
    assert_eq!(read.records().len(), 1);
    let raw = read.records()[0].clone();
    assert!(!raw.is_canonical());
    assert_eq!(raw.as_str(), "\\# 5 c000020107");
    // Kept as it is next to a new value: the prerequisite and the add carry the RDATA as read.
    let both = RrSet::new(
        dn(n),
        RecordType::A,
        None,
        [raw.clone(), rd(RecordType::A, "192.0.2.2")],
    )
    .unwrap();
    assert_eq!(
        set(&client, &both, Expect::Matches(&read)).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        stored(&mock, n, RecordType::A),
        [(vec![192, 0, 2, 1, 7], 300), (vec![192, 0, 2, 2], 300)]
    );
    // Introduced elsewhere: refused after the read, nothing written.
    mock.control().clear_calls();
    let elsewhere = RrSet::new(dn("nd.example.org"), RecordType::A, None, [raw]).unwrap();
    assert_eq!(
        set(&client, &elsewhere, Expect::Any)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(updates(&mock), 0);
}

/// A key that may update but not query: the record-level operations cannot observe the prior
/// state, and the record model has no outcome for a write it did not see; they are refused
/// with `Forbidden`, and nothing is written.
#[tokio::test]
async fn rfc2136_record_operations_need_read_access() {
    let (mock, client) = setup().await;
    mock.control().refuse_queries(true);
    let wanted = rrset("r.example.org", RecordType::A, None, &["192.0.2.1"]);
    let errors = [
        get(&client, "r.example.org", RecordType::A)
            .await
            .map(drop)
            .unwrap_err(),
        set(&client, &wanted, Expect::Absent)
            .await
            .map(drop)
            .unwrap_err(),
        delete(&client, "r.example.org", RecordType::A, Expect::Any)
            .await
            .map(drop)
            .unwrap_err(),
    ];
    for err in errors {
        assert_eq!(err.kind(), ErrorKind::Forbidden, "{err:?}");
    }
    assert_eq!(updates(&mock), 0);
}

/// A delegation: the NS set at the cut is read from the referral the server answers with, and
/// can be replaced and deleted; a name below the cut cannot be read (`Rejected`); a non-AA
/// answer without a referral is `ZoneNotFound`.
#[tokio::test]
async fn rfc2136_record_delegations() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.add_record(mock_record(
        "sub.example.org",
        RecordType::NS,
        3600,
        "ns1.sub.example.org.",
    ));
    let read = get(&client, "sub.example.org", RecordType::NS)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        read,
        rrset(
            "sub.example.org",
            RecordType::NS,
            Some(3600),
            &["ns1.sub.example.org."]
        )
    );
    let wanted = rrset(
        "sub.example.org",
        RecordType::NS,
        None,
        &["ns1.sub.example.org.", "ns2.example.net."],
    );
    assert_eq!(
        set(&client, &wanted, Expect::Matches(&read)).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(stored(&mock, "sub.example.org", RecordType::NS).len(), 2);
    let err = get(&client, "www.sub.example.org", RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Rejected, "{err:?}");
    let err = get(&client, "sub.example.org", RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Rejected, "{err:?}");
    control.clear_calls();
    let err = set(
        &client,
        &rrset("www.sub.example.org", RecordType::A, None, &["192.0.2.1"]),
        Expect::Any,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Rejected, "{err:?}");
    assert_eq!(updates(&mock), 0);
    assert_eq!(
        delete(&client, "sub.example.org", RecordType::NS, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(stored(&mock, "sub.example.org", RecordType::NS).is_empty());
    control.push(Fault::on(Op::Query).clear_aa());
    let err = get(&client, "q.example.org", RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ZoneNotFound, "{err:?}");
}

/// Two record operations on one name from two clients sharing a context are serialized: the
/// second reads after the first has written.
#[tokio::test]
async fn rfc2136_record_concurrent_sets_are_serialized() {
    let mock = Rfc2136Mock::start(Seed::standard()).await;
    let ctx = context();
    let one = client_with(&mock, KEY, STANDARD_SECRET, &ctx);
    let two = client_with(&mock, KEY, STANDARD_SECRET, &ctx);
    mock.control()
        .push(Fault::on(Op::Update).delay(Duration::from_millis(300)));
    let first = rrset("z.example.org", RecordType::A, None, &["192.0.2.1"]);
    let second = rrset("z.example.org", RecordType::A, None, &["192.0.2.2"]);
    let (a, b) = tokio::join!(set(&one, &first, Expect::Absent), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        set(&two, &second, Expect::Matches(&first)).await
    });
    assert_eq!(a.unwrap(), SetOutcome::Created);
    assert_eq!(b.unwrap(), SetOutcome::Replaced);
    let ops: Vec<Op> = mock.control().calls().iter().map(|c| c.op).collect();
    assert_eq!(ops, [Op::Query, Op::Update, Op::Query, Op::Update]);
    assert_eq!(
        stored(&mock, "z.example.org", RecordType::A),
        [(vec![192, 0, 2, 2], DEFAULT_TTL)]
    );
}

/// Names outside the zone are refused before any request by every record operation.
#[tokio::test]
async fn rfc2136_record_name_outside_zone_sends_nothing() {
    let (mock, client) = setup().await;
    for name in ["a.example.net", "a.badexample.org"] {
        let wanted = rrset(name, RecordType::A, None, &["192.0.2.1"]);
        let errors = [
            client
                .get_rrset(&zone(), &dn(name), RecordType::A)
                .await
                .map(drop)
                .unwrap_err(),
            client
                .set_rrset(&zone(), &wanted, Expect::Any)
                .await
                .map(drop)
                .unwrap_err(),
            client
                .delete_rrset(&zone(), &dn(name), RecordType::A, Expect::Any)
                .await
                .map(drop)
                .unwrap_err(),
        ];
        for err in errors {
            assert_eq!(err.kind(), ErrorKind::NameOutsideZone, "{err:?}");
        }
    }
    // Also a set too large for any message: the zone check comes first.
    let texts: Vec<String> = (0..300)
        .map(|i| format!("\"{i:04}{}\"", "v".repeat(250)))
        .collect();
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let huge = rrset("a.example.net", RecordType::TXT, None, &refs);
    assert_eq!(
        client
            .set_rrset(&zone(), &huge, Expect::Any)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NameOutsideZone
    );
    assert!(mock.control().calls().is_empty());
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
async fn live_rfc2136_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_RFC2136_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_RFC2136_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_RFC2136_ZONE"));
    let ctx = Context::new(ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::Rfc2136,
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
            let [a, b] = &values;
            // With read access the outcomes are exact; a server that refuses queries answers
            // `Accepted` throughout (design section 3.5).
            let first = client.add_txt_value(&zone, &name, a, None).await.unwrap();
            assert!(
                matches!(first, AddOutcome::Created | AddOutcome::Accepted),
                "{first:?}"
            );
            let blind = first == AddOutcome::Accepted;
            let second = client.add_txt_value(&zone, &name, b, None).await.unwrap();
            assert_eq!(
                second,
                if blind {
                    AddOutcome::Accepted
                } else {
                    AddOutcome::Appended
                }
            );
            let again = client.add_txt_value(&zone, &name, b, None).await.unwrap();
            assert_eq!(
                again,
                if blind {
                    AddOutcome::Accepted
                } else {
                    AddOutcome::AlreadyPresent
                }
            );
            let removed = client.remove_txt_value(&zone, &name, a).await.unwrap();
            assert_eq!(
                removed,
                if blind {
                    RemoveOutcome::Accepted
                } else {
                    RemoveOutcome::Removed
                }
            );
            let last = client.remove_txt_value(&zone, &name, b).await.unwrap();
            assert_eq!(
                last,
                if blind {
                    RemoveOutcome::Accepted
                } else {
                    RemoveOutcome::RrsetDeleted
                }
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

/// A record-level round trip under a generated label: create with `Absent`, read, replace with
/// `Matches`, an identical set (`Unchanged`), delete with `Matches`. Cleanup removes exactly the
/// values the test wrote, with the value operations, also when the body failed. Needs a key
/// that may query the zone.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_rfc2136_record_round_trip() {
    let settings = live_env("ZONEWRIGHT_LIVE_RFC2136_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_RFC2136_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_RFC2136_ZONE"));
    let ctx = Context::new(ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::Rfc2136,
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
        txt(&format!("zw-live-{tag:016x}-c")),
    ];

    let body = {
        let (client, zone, name, values) =
            (client.clone(), zone.clone(), name.clone(), values.clone());
        tokio::spawn(async move {
            let data = |v: &Txt| v.to_data().unwrap();
            let first = RrSet::new(
                name.clone(),
                RecordType::TXT,
                Some(RrsetTtl::from_secs(120).unwrap()),
                [data(&values[0]), data(&values[1])],
            )
            .unwrap();
            assert_eq!(
                client
                    .set_rrset(&zone, &first, Expect::Absent)
                    .await
                    .unwrap(),
                SetOutcome::Created
            );
            let read = client
                .get_rrset(&zone, &name, RecordType::TXT)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(read, first);
            let second = RrSet::new(
                name.clone(),
                RecordType::TXT,
                None,
                [data(&values[1]), data(&values[2])],
            )
            .unwrap();
            assert_eq!(
                client
                    .set_rrset(&zone, &second, Expect::Matches(&read))
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            assert_eq!(
                client.set_rrset(&zone, &second, Expect::Any).await.unwrap(),
                SetOutcome::Unchanged
            );
            let read = client
                .get_rrset(&zone, &name, RecordType::TXT)
                .await
                .unwrap()
                .unwrap();
            assert!(read.same_records(&second));
            assert_eq!(read.ttl(), Some(RrsetTtl::from_secs(120).unwrap()));
            assert_eq!(
                client
                    .delete_rrset(&zone, &name, RecordType::TXT, Expect::Matches(&read))
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
            assert_eq!(
                client
                    .get_rrset(&zone, &name, RecordType::TXT)
                    .await
                    .unwrap(),
                None
            );
        })
    };
    let outcome = body.await;

    // Cleanup: exactly the values this test wrote, with the value operations.
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

/// Only answer records owned by exactly the name, of exactly the type and class IN, are part of
/// the set read: a record of another name, another type or another class in the answer is not.
#[tokio::test]
async fn rfc2136_record_answers_for_other_names_are_ignored() {
    let (mock, client) = setup().await;
    let control = mock.control();
    let n = "own.example.org";
    control.add_record(mock_record(n, RecordType::A, 300, "192.0.2.1"));
    for (owner, rtype, class) in [
        ("other.example.org.", TYPE_A, CLASS_IN),
        ("x.own.example.org.", TYPE_A, CLASS_IN),
        ("own.example.org.", TYPE_TXT, CLASS_IN),
        ("own.example.org.", TYPE_A, 3),
    ] {
        let rdata: &[u8] = if rtype == TYPE_A {
            &[192, 0, 2, 9]
        } else {
            b"\x01x"
        };
        control.push(Fault::on(Op::Query).extra_answer(owner, rtype, class, rdata));
        let read = get(&client, n, RecordType::A).await.unwrap().unwrap();
        assert_eq!(
            read,
            rrset(n, RecordType::A, Some(300), &["192.0.2.1"]),
            "{owner}"
        );
    }
    // A write after such a read names only the set's own RRs in its prerequisite.
    control.push(Fault::on(Op::Query).extra_answer(
        "other.example.org.",
        TYPE_A,
        CLASS_IN,
        &[192, 0, 2, 9],
    ));
    control.clear_calls();
    let wanted = rrset(n, RecordType::A, None, &["192.0.2.2"]);
    assert_eq!(
        set(&client, &wanted, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    let calls = update_calls(&mock);
    assert_eq!(calls[0].prereqs.len(), 1);
    assert_eq!(calls[0].prereqs[0].rdata, [192, 0, 2, 1]);
}

// ---- Served over DNS ---------------------------------------------------------------------------

/// The mock's published state, linked to the DNS mock, is what the mock answers itself. The
/// mock answers only signed queries, so its own answers are read through the client.
#[cfg(feature = "inspector")]
mod served_over_dns {
    use std::net::{Ipv4Addr, SocketAddr};

    use zonewright::{Expect, Provider, RecordType, RrSet};
    use zonewright_mock::changes::ChangeSource as _;
    use zonewright_mock::dns::{DnsMock, Role};
    use zonewright_mock::link::{LinkOptions, link};
    use zonewright_mock::rfc2136::{Op, Rfc2136Mock, Seed};

    use super::common::dn;
    use super::common::link::{NAME, ZONE, ask, is_absent, rd, txt, txt_round_trip, values};
    use super::{KEY, NAME_DOT, setup};
    use zonewright_mock::rfc2136::STANDARD_SECRET;

    /// A TXT value goes to DNS and away again. An MX, a CNAME, a CAA and a TXT of two strings
    /// written through `set_rrset` are answered by the linked DNS mock exactly as the mock answers
    /// them itself.
    #[tokio::test]
    async fn rfc2136_txt_value_is_served_over_dns() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = txt_round_trip(&mock, &client, &dns).await;

        let records = [
            (ZONE, RecordType::MX, "10 mail.example.net."),
            (
                "alias.example.org",
                RecordType::CNAME,
                "target.example.net.",
            ),
            (ZONE, RecordType::CAA, "0 issue \"ca.example.net\""),
            (NAME, RecordType::TXT, "\"first\" \"second\""),
        ];
        for (name, rtype, text) in records {
            let rrset = RrSet::new(dn(name), rtype, None, [rd(rtype, text)]).unwrap();
            client
                .set_rrset(&dn(ZONE), &rrset, Expect::Any)
                .await
                .unwrap();
        }
        link.settled().await;
        for (name, rtype, text) in records {
            let linked = values(ask(dns.addr(), name, rtype).await);
            assert_eq!(linked, [rd(rtype, text)], "{name} {rtype}");
            let own = client.get_rrset(&dn(ZONE), &dn(name), rtype).await.unwrap();
            assert_eq!(own.unwrap().records(), linked.as_slice(), "{name} {rtype}");
        }
        assert_eq!(link.skipped(), 0);
    }

    /// A reset returns the mock to its seed: the record written through the client is gone from
    /// the mock, from its own answers and from the linked DNS mock, no request is recorded, and
    /// the client works again.
    #[tokio::test]
    async fn rfc2136_reset_returns_to_the_seed() {
        let (mock, client) = setup().await;
        let dns = DnsMock::start(Role::Authoritative).await;
        let link = link(&mock, &dns, LinkOptions::new());
        let mut stream = mock.changes().subscribe();
        super::add(&client, "before-reset").await.unwrap();
        link.settled().await;
        assert_eq!(
            values(ask(dns.addr(), NAME, RecordType::TXT).await),
            [txt("before-reset")]
        );
        assert!(stream.try_next().is_some());

        mock.control().reset();
        let removal = stream.try_next().unwrap();
        assert_eq!((removal.name.as_str(), removal.rrset), (NAME, None));
        assert!(mock.control().all_records().is_empty());
        assert!(mock.control().calls().is_empty());
        link.settled().await;
        let answer = ask(dns.addr(), NAME, RecordType::TXT).await;
        assert!(is_absent(&answer), "{answer:?}");

        super::add(&client, "after-reset").await.unwrap();
        assert_eq!(mock.control().txt(NAME_DOT), ["after-reset"]);
        assert!(mock.control().count(Op::Update) > 0);
    }

    /// `start_on` binds to the address given; on a wildcard address the server answers on
    /// loopback.
    #[tokio::test]
    async fn rfc2136_mock_starts_on_a_given_address() {
        let mock = Rfc2136Mock::start_on(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            Seed::standard(),
        )
        .await;
        assert!(mock.addr().ip().is_unspecified());
        let port = mock.addr().port();
        let mut config = super::settings(&mock, KEY);
        config.server = format!("127.0.0.1:{port}");
        let client = super::Rfc2136::new(
            config,
            super::credentials(STANDARD_SECRET),
            &super::context(),
        )
        .unwrap();
        super::add(&client, "on-loopback").await.unwrap();
        assert_eq!(mock.control().txt(NAME_DOT), ["on-loopback"]);
        let own = client
            .get_rrset(&dn(ZONE), &dn(NAME), RecordType::TXT)
            .await
            .unwrap();
        assert_eq!(own.unwrap().records(), [txt("on-loopback")]);
    }
}
