//! Tests of the Route 53 client (`route53`) against its mock.
#![cfg(feature = "route53")]
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
use zonewright::providers::route53::{Route53, Route53Config, Route53Credentials};
use zonewright::{
    AddOutcome, AnyProvider, Context, DeleteOutcome, DomainName, Error, ErrorKind, Expect,
    Operation, Provider, ProviderId, RecordData, RecordType, RemoveOutcome, RrSet, RrsetTtl,
    SetOutcome, SkipReason, Ttl, Txt,
};
use zonewright_mock::Fault;
use zonewright_mock::axum::http::{Method, StatusCode};
use zonewright_mock::axum::response::IntoResponse as _;
use zonewright_mock::echo::{EchoServer, Echoed, Render};
use zonewright_mock::route53::{
    Route53Mock, Seed, SeedZone, XMLNS, error_body, invalid_change_batch_body,
};

use common::echo::{
    CANARY_KEY, CANARY_PASSWORD, CANARY_TOKEN, LogCapture, REDACTED, assert_clean, dialects,
};
use common::{context, dn};

// ---- Fixtures ----------------------------------------------------------------------------------

/// The access key and the secret of the standard seed.
const ACCESS_KEY: &str = "AKIAZWTEST0000000001";
const SECRET: &str = "test-only-secret/key+0000000000000000000";

/// The public zone `example.org.` of the standard seed.
const ZID: &str = "ZEXAMPLE0000000001";

/// The owner name most tests write to.
const NAME: &str = "_acme-challenge.example.org";

/// Fault patterns of the mock's paths.
const ZONES: &str = "/2013-04-01/hostedzonesbyname";
const ZONE: &str = "/2013-04-01/hostedzone/*";
const RRSETS: &str = "/2013-04-01/hostedzone/*/rrset";
const CHANGE: &str = "/2013-04-01/hostedzone/*/rrset/";
const STATUS: &str = "/2013-04-01/change/*";

fn zone() -> DomainName {
    dn("example.org")
}

fn name() -> DomainName {
    dn(NAME)
}

fn txt(value: &str) -> Txt {
    Txt::new(value).unwrap()
}

/// Settings pointed at `base_url`, polling at the floor of 250 ms.
fn settings_for(base_url: &str) -> Route53Config {
    let mut config = Route53Config::new(ACCESS_KEY.into());
    config.base_url = base_url.to_owned();
    config.change_poll_ms = 250;
    config
}

fn credentials(secret: &str, token: Option<&str>) -> Route53Credentials {
    let secret = SecretString::from(secret.to_owned());
    match token {
        None => Route53Credentials::new(secret),
        Some(token) => {
            Route53Credentials::with_session_token(secret, SecretString::from(token.to_owned()))
        }
    }
}

fn client_with(mock: &Route53Mock, secret: &str, token: Option<&str>, ctx: &Context) -> Route53 {
    Route53::new(
        settings_for(&mock.base_url()),
        credentials(secret, token),
        ctx,
    )
    .unwrap()
}

async fn setup() -> (Route53Mock, Route53) {
    setup_with(Seed::standard()).await
}

async fn setup_with(seed: Seed) -> (Route53Mock, Route53) {
    let secret = seed.secret_access_key.clone();
    let token = seed.session_token.clone();
    let mock = Route53Mock::start(seed).await;
    let client = client_with(&mock, &secret, token.as_deref(), &context());
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

/// Number of change batches the mock received, refused ones included.
fn writes(mock: &Route53Mock) -> usize {
    mock.log().count(Some("POST"), CHANGE)
}

/// Canonical data of `rtype`.
fn rd(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap()
}

/// An rrset of canonical data.
fn rrset(name: &str, rtype: RecordType, ttl: Option<u32>, texts: &[&str]) -> RrSet {
    RrSet::new(
        dn(name),
        rtype,
        ttl.map(|t| RrsetTtl::from_secs(t).unwrap()),
        texts.iter().map(|t| rd(rtype, t)),
    )
    .unwrap()
}

/// The record types without a canonical text of their own.
fn ds() -> RecordType {
    RecordType::from_code(43)
}
fn naptr() -> RecordType {
    RecordType::from_code(35)
}
fn spf() -> RecordType {
    RecordType::from_code(99)
}

/// A hook that adds a foreign value to the TXT rrset at [`NAME`] (or creates it) in zone
/// [`ZID`], as another writer would between the client's read and its write.
fn add_foreign(mock: &Route53Mock, value: &'static str) -> impl Fn() + Send + Sync + 'static {
    let control = mock.control().clone();
    move || {
        let current = control.rrset(NAME, "TXT");
        let ttl = current.as_ref().map_or(60, |r| r.ttl);
        let mut values: Vec<String> = current.map(|r| r.values).unwrap_or_default();
        values.push(format!("\"{value}\""));
        let values: Vec<&str> = values.iter().map(String::as_str).collect();
        control.insert_rrset(ZID, NAME, "TXT", ttl, &values);
    }
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

assert_not_impl!(Route53: std::fmt::Display, serde::Serialize);
assert_not_impl!(Route53Credentials: std::fmt::Display, serde::Serialize);

/// `check` and a write against an echo that quotes every request back, for every dialect: no
/// canary in any error, `ZoneCheck::detail` or `Debug`, and the write's error shows the
/// redaction. The secret access key is never sent; the session token travels in a header and
/// is echoed. One pass where every request is echoed, and passes where the listings answer
/// like the API so that the change batch itself (a create, and a delete plus create) reaches
/// the echo.
#[tokio::test]
async fn route53_secret_echo() {
    // One server and one context for every case: each case reconfigures the server, and
    // every client reuses the context's pooled connection (see `EchoServer::reset`).
    let ctx = context();
    let echo = EchoServer::start(200).await;
    let secrets = [CANARY_PASSWORD, CANARY_TOKEN];
    for dialect in dialects() {
        for status in [400, 401, 403] {
            let label = format!("{} {:?} {status} api", dialect.name, dialect.spelling);
            echo.reset(dialect.echo(status));
            let client = echo_client(&echo, &ctx);
            echo_round(&label, &client, &secrets).await;
            assert!(echo.api_requests() > 0, "{label}: the API was not reached");
        }
        for status in [400, 403, 500] {
            for existing in [false, true] {
                let label = format!(
                    "{} {:?} {status} write existing={existing}",
                    dialect.name, dialect.spelling
                );
                echo.reset(dialect.echo(status).render_under(
                    "/2013-04-01/",
                    listings_then(dialect.render.clone(), existing),
                ));
                let client = echo_client(&echo, &ctx);
                echo_round(&label, &client, &secrets).await;
                assert_eq!(
                    echo.log().count(Some("POST"), CHANGE),
                    1,
                    "{label}: the change batch did not reach the echo"
                );
            }
        }
    }
}

/// The record-level requests against the same echoes: a listing, an rrset written whole (a
/// create, or a delete plus create over the existing set) and a delete. No canary in any error,
/// and each change batch reached the echo.
#[tokio::test]
async fn route53_secret_echo_record_level() {
    // One server and one context for every case: each case reconfigures the server, and
    // every client reuses the context's pooled connection (see `EchoServer::reset`).
    let ctx = context();
    let echo = EchoServer::start(200).await;
    let secrets = [CANARY_PASSWORD, CANARY_TOKEN];
    for dialect in dialects() {
        for status in [400, 403, 500] {
            for existing in [false, true] {
                let label = format!(
                    "{} {:?} {status} record existing={existing}",
                    dialect.name, dialect.spelling
                );
                echo.reset(dialect.echo(status).render_under(
                    "/2013-04-01/",
                    listings_then(dialect.render.clone(), existing),
                ));
                let client = echo_client(&echo, &ctx);
                let mut texts = vec![format!("{client:?}")];
                match client.list_rrsets(&zone()).await {
                    Ok(listing) => texts.push(format!("{listing:?}")),
                    Err(e) => texts.push(format!("{e} | {e:?}")),
                }
                let set = rrset(NAME, RecordType::TXT, None, &["\"v1\""]);
                let e = client
                    .set_rrset(&zone(), &set, Expect::Any)
                    .await
                    .unwrap_err();
                let text = format!("{e} | {e:?}");
                assert!(text.contains(REDACTED), "{label}: {text}");
                texts.push(text);
                let mut batches = 1;
                if existing {
                    let e = client
                        .delete_rrset(&zone(), &name(), RecordType::TXT, Expect::Any)
                        .await
                        .unwrap_err();
                    let text = format!("{e} | {e:?}");
                    assert!(text.contains(REDACTED), "{label}: {text}");
                    texts.push(text);
                    batches = 2;
                }
                assert_eq!(
                    echo.log().count(Some("POST"), CHANGE),
                    batches,
                    "{label}: the change batches did not reach the echo"
                );
                for text in &texts {
                    assert_clean(&label, text, &secrets);
                }
            }
        }
    }
}

/// A renderer that answers the zone and rrset listings like the API (one public zone; no
/// rrset, or a TXT rrset with a foreign value) and every other request with `errors`.
fn listings_then(errors: Render, existing: bool) -> Render {
    Arc::new(move |e: &Echoed| {
        if e.method != Method::GET {
            return errors(e);
        }
        let body = if e.path.ends_with("/hostedzonesbyname") {
            format!(
                "<ListHostedZonesByNameResponse xmlns=\"{XMLNS}\"><HostedZones><HostedZone>\
                 <Id>/hostedzone/{ZID}</Id><Name>example.org.</Name><CallerReference>x\
                 </CallerReference><Config><PrivateZone>false</PrivateZone></Config>\
                 </HostedZone></HostedZones><IsTruncated>false</IsTruncated><MaxItems>100\
                 </MaxItems></ListHostedZonesByNameResponse>"
            )
        } else {
            let set = if existing {
                "<ResourceRecordSet><Name>_acme-challenge.example.org.</Name><Type>TXT</Type>\
                 <TTL>60</TTL><ResourceRecords><ResourceRecord><Value>\"foreign\"</Value>\
                 </ResourceRecord></ResourceRecords></ResourceRecordSet>"
            } else {
                ""
            };
            format!(
                "<ListResourceRecordSetsResponse xmlns=\"{XMLNS}\"><ResourceRecordSets>{set}\
                 </ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems>\
                 </ListResourceRecordSetsResponse>"
            )
        };
        (StatusCode::OK, body).into_response()
    })
}

fn echo_client(echo: &EchoServer, ctx: &Context) -> Route53 {
    Route53::new(
        settings_for(&echo.base_url()),
        credentials(CANARY_PASSWORD, Some(CANARY_TOKEN)),
        ctx,
    )
    .unwrap()
}

async fn echo_round(label: &str, client: &Route53, secrets: &[&str]) {
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

/// A `TRACE` capture over a success, repeated 401s, a 500 and a wrong secret (whose answer
/// repeats the canonical request with the session token): the transport's events are there,
/// and no canary is.
#[tokio::test(flavor = "current_thread")]
async fn route53_no_secret_in_logs() {
    let (capture, _guard) = LogCapture::install();
    let mut seed = Seed::standard();
    seed.secret_access_key = CANARY_PASSWORD.into();
    seed.session_token = Some(CANARY_TOKEN.into());
    let mock = Route53Mock::start(seed).await;
    let client = client_with(&mock, CANARY_PASSWORD, Some(CANARY_TOKEN), &context());
    let mut texts = Vec::new();

    add(&client, "v1").await.unwrap();

    mock.faults()
        .push(Fault::on("GET", RRSETS).always().status(401));
    let e = add(&client, "v2").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?}"));
    mock.faults().clear();

    mock.faults().push(Fault::on("POST", CHANGE).status(500));
    let e = add(&client, "v2").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    texts.push(format!("{e} | {e:?}"));

    let wrong = client_with(&mock, CANARY_KEY, Some(CANARY_TOKEN), &context());
    let e = wrong.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    texts.push(format!("{e} | {e:?} | {wrong:?} | {client:?}"));

    let entries = capture.entries();
    assert!(
        entries.iter().any(|e| e.target == "zonewright::http"),
        "the capture holds no transport event"
    );
    texts.push(capture.text());
    let secrets = [CANARY_PASSWORD, CANARY_KEY, CANARY_TOKEN];
    for text in &texts {
        assert_clean("route53 logs and errors", text, &secrets);
    }
}

/// A signature refused with the canonical request in its message: the error names the code and
/// the first sentence only, never the canonical request, the string to sign or the token. A
/// provider that quotes the secret and the token in any error is scrubbed.
#[tokio::test]
async fn route53_auth_error_does_not_leak_canonical_string_or_token() {
    let mut seed = Seed::standard();
    seed.session_token = Some("sts-token-canary-0001".into());
    let mock = Route53Mock::start(seed).await;
    let bad = client_with(
        &mock,
        "wrong-canary-1",
        Some("sts-token-canary-0001"),
        &context(),
    );
    let e = add(&bad, "A").await.unwrap_err();
    let text = format!("{e} | {e:?} | {bad:?}");
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(text.contains("SignatureDoesNotMatch"), "{text}");
    for canary in [
        "sts-token-canary",
        "wrong-canary-1",
        "Canonical String",
        "String-to-Sign",
        "x-amz-security-token",
    ] {
        assert!(!text.contains(canary), "{canary} leaked: {text}");
    }

    let client = client_with(&mock, SECRET, Some("sts-token-canary-0001"), &context());
    for (status, code) in [
        (403, "AccessDenied"),
        (400, "InvalidInput"),
        (500, "InternalFailure"),
        (403, "InvalidClientTokenId"),
        (401, "NotAuthorized"),
    ] {
        mock.faults().push(Fault::on("GET", ZONES).times(3).respond(
            status,
            error_body(
                code,
                &format!("token sts-token-canary-0001 secret {SECRET}"),
            ),
        ));
        let e = client.check(&[zone()]).await.unwrap_err();
        let text = format!("{e} | {e:?} | {client:?}");
        assert!(
            !text.contains("sts-token-canary") && !text.contains("test-only-secret"),
            "{code}: {text}"
        );
        assert!(text.contains(code), "{code}: {text}");
        mock.faults().clear();
    }
    assert!(client.check(&[zone()]).await.unwrap().zones[0].found);
}

// ---- Invariants (design section 12.3) ----------------------------------------------------------

/// A name outside the zone is refused before any request: another zone, a name that merely
/// ends with the zone's text, the zone's text inside another name, and a sibling zone.
#[tokio::test]
async fn route53_name_outside_zone_sends_nothing() {
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
}

/// `Created`, `Appended` for a second value, then `AlreadyPresent` without a write.
#[tokio::test]
async fn route53_add_is_idempotent() {
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
/// leaves the foreign values (one of them in a spelling the client does not decode) and the TTL
/// exactly as they were. A single foreign value is never a reason to delete the rrset.
#[tokio::test]
async fn route53_never_removes_foreign_value() {
    let (mock, client) = setup().await;
    let control = mock.control();
    // `\101` is an octal escape ("A") in the API's TXT syntax.
    control.insert_rrset(ZID, NAME, "TXT", 600, &["\"foreign\"", "\"ours\\101\""]);
    let original = control.rrset(NAME, "TXT").unwrap();

    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), 0);
    assert_eq!(add(&client, "ours").await.unwrap(), AddOutcome::Appended);
    let during = control.rrset(NAME, "TXT").unwrap();
    assert_eq!(during.ttl, 600);
    assert_eq!(during.values, ["\"foreign\"", "\"ours\\101\"", "\"ours\""]);
    // A value that only decodes wrongly as ours ("oursA" read with decimal escapes would be
    // "ourse") is never taken for ours.
    assert_eq!(add(&client, "ourse").await.unwrap(), AddOutcome::Appended);
    assert_eq!(
        remove(&client, "ourse").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(
        remove(&client, "ours").await.unwrap(),
        RemoveOutcome::Removed
    );
    let after = control.rrset(NAME, "TXT").unwrap();
    assert_eq!(after, original);

    // A single foreign value: nothing is deleted.
    let other = "_acme-challenge.www.example.org";
    control.insert_rrset(ZID, other, "TXT", 60, &["\"foreign\""]);
    let before = writes(&mock);
    assert_eq!(
        client
            .remove_txt_value(&zone(), &dn(other), &txt("ours"))
            .await
            .unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(writes(&mock), before);
    assert_eq!(control.txt_values(other), ["foreign"]);
}

/// The last value is removed by a batch that deletes the rrset exactly as read (TTL and value)
/// and creates nothing.
#[tokio::test]
async fn route53_remove_last_value_deletes_rrset() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().rrset(NAME, "TXT").is_none());
    let last = mock.control().batches().pop().unwrap();
    assert!(
        last.contains("<Action>DELETE</Action>")
            && !last.contains("CREATE")
            && last.contains("<TTL>60</TTL>")
            && last.contains("&quot;AAA&quot;"),
        "{last}"
    );
}

#[tokio::test]
async fn route53_remove_is_idempotent() {
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
    assert!(mock.control().rrset(NAME, "TXT").is_none());
}

/// Two clients sharing a `Context` add to one name at once, the first write delayed: both values
/// end up in the rrset, without a refused batch.
#[tokio::test]
async fn route53_concurrent_adds_are_serialized() {
    let mock = Route53Mock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, SECRET, None, &ctx);
    let b = client_with(&mock, SECRET, None, &ctx);
    mock.faults()
        .push(Fault::on("POST", CHANGE).delay(Duration::from_millis(300)));
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
    assert_eq!(writes(&mock), 2, "no batch was refused");
}

/// A foreign change between the read and the write is never lost: the batch's `DELETE` of the
/// old set no longer matches, Route 53 refuses the whole batch, and the client reads again and
/// repeats once. A second refusal is `Conflict`. A refusal while the rrset is unchanged is the
/// provider's refusal and is not repeated.
#[tokio::test]
async fn route53_concurrent_change_is_conflict() {
    // Append: a foreign value arrives before the first batch; the repeat keeps it.
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("POST", CHANGE).run(add_foreign(&mock, "foreign")));
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    assert_eq!(mock.control().txt_values(NAME), ["AAA", "foreign", "BBB"]);
    assert_eq!(writes(&mock), 3);

    // Remove: likewise.
    mock.faults()
        .push(Fault::on("POST", CHANGE).run(add_foreign(&mock, "second")));
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(
        mock.control().txt_values(NAME),
        ["foreign", "BBB", "second"]
    );

    // Create: someone creates the rrset after our read; our CREATE is refused.
    let other = "_acme-challenge.www.example.org";
    let control = mock.control().clone();
    mock.faults().push(Fault::on("POST", CHANGE).run(move || {
        control.insert_rrset(ZID, other, "TXT", 300, &["\"theirs\""]);
    }));
    assert_eq!(
        client
            .add_txt_value(&zone(), &dn(other), &txt("ours"), None)
            .await
            .unwrap(),
        AddOutcome::Appended
    );
    assert_eq!(mock.control().txt_values(other), ["theirs", "ours"]);
    assert_eq!(mock.control().rrset(other, "TXT").unwrap().ttl, 300);

    // Two refusals in a row: `Conflict`, retryable, and the foreign values are there.
    let before = writes(&mock);
    mock.faults().push(
        Fault::on("POST", CHANGE)
            .times(2)
            .run(add_foreign(&mock, "again")),
    );
    let e = add(&client, "CCC").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(writes(&mock), before + 2);
    assert_eq!(
        mock.control().txt_values(NAME),
        ["foreign", "BBB", "second", "again", "again"]
    );

    // A refusal for another reason: the rrset is unchanged, so it is the error, sent once.
    let before = writes(&mock);
    mock.faults().push(Fault::on("POST", CHANGE).respond(
        400,
        invalid_change_batch_body(&["Invalid Resource Record: something else"]),
    ));
    let e = add(&client, "CCC").await.unwrap_err();
    assert!(
        matches!(
            e,
            Error::Rejected {
                status: Some(400),
                ..
            }
        ),
        "{e:?}"
    );
    assert!(e.to_string().contains("something else"), "{e}");
    assert_eq!(writes(&mock), before + 1);
}

/// The zone is deleted and created again under a new ID while the client has the old one
/// cached. A read with the stale ID is answered 404, the zone is looked up again and the read
/// repeated: a removal never reports `NotPresent` for a value that is there. A batch that meets
/// the stale ID writes nothing; the client looks the zone up again and repeats once.
#[tokio::test]
async fn route53_stale_zone_id() {
    let (mock, client) = setup().await;
    let control = mock.control();
    add(&client, "v1").await.unwrap();
    add(&client, "v2").await.unwrap();
    let lookups = || mock.log().count(Some("GET"), ZONES);
    assert_eq!(lookups(), 1);

    control.recreate_zone("example.org");
    assert_eq!(remove(&client, "v1").await.unwrap(), RemoveOutcome::Removed);
    assert_eq!(lookups(), 2);
    control.recreate_zone("example.org");
    assert_eq!(add(&client, "v3").await.unwrap(), AddOutcome::Appended);
    assert_eq!(control.txt_values(NAME), ["v2", "v3"]);

    // The zone is recreated between the read and the write.
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", CHANGE).run(move || {
        hook.recreate_zone("example.org");
    }));
    assert_eq!(add(&client, "v4").await.unwrap(), AddOutcome::Appended);
    assert_eq!(control.txt_values(NAME), ["v2", "v3", "v4"]);

    // ... and between the read and the last delete: the rrset is still there under the new
    // zone, so the removal is repeated rather than reported done.
    remove(&client, "v2").await.unwrap();
    remove(&client, "v3").await.unwrap();
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", CHANGE).run(move || {
        hook.recreate_zone("example.org");
    }));
    assert_eq!(
        remove(&client, "v4").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(control.rrset(NAME, "TXT").is_none());
}

/// A change batch is sent once whatever happens: a 5xx, a rate limit (429 or Route 53's 400
/// `Throttling` and `PriorRequestNotComplete`) and a 401 are the operation's error, and the
/// repeat starts with a read.
#[tokio::test]
async fn route53_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let cases: [(Fault, ErrorKind); 5] = [
        (Fault::on("POST", CHANGE).status(502), ErrorKind::Transient),
        (Fault::on("POST", CHANGE).rate_limited("1"), ErrorKind::RateLimited),
        (Fault::on("POST", CHANGE).status(401), ErrorKind::Auth),
        (
            Fault::on("POST", CHANGE).respond(400, error_body("Throttling", "Rate exceeded")),
            ErrorKind::RateLimited,
        ),
        (
            Fault::on("POST", CHANGE).respond(
                400,
                error_body(
                    "PriorRequestNotComplete",
                    "The request was rejected because Route 53 was still processing a prior request.",
                ),
            ),
            ErrorKind::RateLimited,
        ),
    ];
    // Create, append and delete batches alike.
    for (fault, kind) in cases {
        for existing in [0usize, 1, 2] {
            mock.control().delete_rrset(NAME, "TXT");
            let values: Vec<&str> = ["\"AAA\"", "\"BBB\""][..existing].to_vec();
            if !values.is_empty() {
                mock.control().insert_rrset(ZID, NAME, "TXT", 60, &values);
            }
            mock.faults().push(fault.clone());
            let before = writes(&mock);
            let e = if existing == 1 {
                remove(&client, "AAA").await.unwrap_err()
            } else {
                add(&client, "CCC").await.unwrap_err()
            };
            assert_eq!(e.kind(), kind, "{existing}: {e:?}");
            assert_eq!(writes(&mock), before + 1, "{existing}: {kind:?}");
        }
    }
    mock.control().delete_rrset(NAME, "TXT");
    assert_eq!(add(&client, "CCC").await.unwrap(), AddOutcome::Created);
}

/// Every operation is offered; a record type outside the record-level list is
/// `UnsupportedRecordType`, a query type `InvalidInput`, and nothing is sent.
#[tokio::test]
async fn route53_unsupported_operations_send_nothing() {
    let (mock, client) = setup().await;
    let caps = ProviderId::Route53.meta().capabilities;
    for op in [
        Operation::Check,
        Operation::ListZones,
        Operation::ListRrsets,
        Operation::GetRrset,
        Operation::SetRrset,
        Operation::DeleteRrset,
        Operation::AddTxtValue,
        Operation::RemoveTxtValue,
    ] {
        assert!(caps.supports(op), "{op}");
    }
    for rtype in ["DNAME", "ALIAS", "LOC", "TYPE65534"] {
        let rtype: RecordType = rtype.parse().unwrap();
        let set = RrSet::new(
            name(),
            rtype,
            None,
            [RecordData::parse(rtype, "\\# 1 00")
                .unwrap_or_else(|_| RecordData::parse(rtype, "target.example.net.").unwrap())],
        )
        .unwrap();
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
    let any: RecordType = "ANY".parse().unwrap();
    let e = client.get_rrset(&zone(), &name(), any).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
}

/// A zone listing that says it is truncated without naming the next page, or that lacks its
/// list, is an error, never a shorter result.
#[tokio::test]
async fn route53_truncated_listing_is_protocol() {
    let (mock, client) = setup().await;
    let zone_xml = format!(
        "<HostedZone><Id>/hostedzone/{ZID}</Id><Name>example.org.</Name>\
         <Config><PrivateZone>false</PrivateZone></Config></HostedZone>"
    );
    for body in [
        format!(
            "<ListHostedZonesByNameResponse xmlns=\"{XMLNS}\"><HostedZones>{zone_xml}\
             </HostedZones><IsTruncated>true</IsTruncated></ListHostedZonesByNameResponse>"
        ),
        format!(
            "<ListHostedZonesByNameResponse xmlns=\"{XMLNS}\"><IsTruncated>false</IsTruncated>\
             </ListHostedZonesByNameResponse>"
        ),
        format!(
            "<ListHostedZonesByNameResponse xmlns=\"{XMLNS}\"><HostedZones>{zone_xml}\
             </HostedZones></ListHostedZonesByNameResponse>"
        ),
    ] {
        mock.faults()
            .push(Fault::on("GET", ZONES).respond(200, body.clone()));
        let e = client.list_zones().await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    // An rrset listing without its list is not "no rrset": nothing is written after it.
    mock.faults().push(Fault::on("GET", RRSETS).respond(
        200,
        format!("<ListResourceRecordSetsResponse xmlns=\"{XMLNS}\"/>"),
    ));
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

// ---- TXT records and rrsets --------------------------------------------------------------------

/// Two values in one rrset, then removed one by one; the second batch deletes the old set
/// before it creates the merged one, and the existing TTL is kept.
#[tokio::test]
async fn route53_merge_two_values_and_delete_last_with_exact_ttl() {
    let (mock, client) = setup().await;
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(add(&client, "BBB").await.unwrap(), AddOutcome::Appended);
    let rrset = mock.control().rrset(NAME, "TXT").unwrap();
    assert_eq!(rrset.values, ["\"AAA\"", "\"BBB\""]);
    assert_eq!(rrset.ttl, 60);
    assert!(
        mock.log().count(Some("GET"), STATUS) >= 2,
        "the change was polled"
    );
    let batch = &mock.control().batches()[1];
    let delete = batch.find("<Action>DELETE</Action>").unwrap();
    let create = batch.find("<Action>CREATE</Action>").unwrap();
    assert!(delete < create, "{batch}");

    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(mock.control().txt_values(NAME), ["BBB"]);
    assert_eq!(
        remove(&client, "BBB").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().rrset(NAME, "TXT").is_none());
}

/// The first value creates the rrset with the configured TTL, or the caller's; an existing
/// rrset keeps its TTL; the caller's TTL may be anything the API accepts, beyond the range of
/// the `ttl` setting.
#[tokio::test]
async fn route53_add_creates_rrset_with_the_ttl() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    let rrset = mock.control().rrset(NAME, "TXT").unwrap();
    assert_eq!((rrset.ttl, rrset.zone_id.as_str()), (60, ZID));
    let other = dn("_acme-challenge.www.example.org");
    let ttl = |s| Some(zonewright::RrsetTtl::from_secs(s).unwrap());
    client
        .add_txt_value(&zone(), &other, &txt("BBB"), ttl(300))
        .await
        .unwrap();
    client
        .add_txt_value(&zone(), &other, &txt("CCC"), ttl(900))
        .await
        .unwrap();
    assert_eq!(
        mock.control()
            .rrset("_acme-challenge.www.example.org", "TXT")
            .unwrap()
            .ttl,
        300
    );
    let deep = dn("_acme-challenge.deep.example.org");
    client
        .add_txt_value(&zone(), &deep, &txt("DDD"), ttl(172_800))
        .await
        .unwrap();
    assert_eq!(
        mock.control()
            .rrset("_acme-challenge.deep.example.org", "TXT")
            .unwrap()
            .ttl,
        172_800
    );
}

/// The listing starts at the requested name and returns the next rrset in sort order when
/// there is none: that neighbor is not ours and is left alone.
#[tokio::test]
async fn route53_listing_next_rrset_is_not_ours() {
    // The next rrset in sort order is a TXT rrset of another name ...
    let (mock, client) = setup().await;
    let neighbor = "_acme-challenge.xyz.example.org";
    mock.control()
        .insert_rrset(ZID, neighbor, "TXT", 300, &["\"AAA\""]);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(mock.control().txt_values(neighbor), ["AAA"]);
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert_eq!(mock.control().txt_values(neighbor), ["AAA"]);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::NotPresent
    );
    assert_eq!(mock.control().txt_values(neighbor), ["AAA"]);

    // ... or an rrset of another type at the same name.
    mock.control()
        .insert_rrset(ZID, NAME, "TYPE65534", 300, &["\\# 0"]);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
    assert_eq!(
        remove(&client, "AAA").await.unwrap(),
        RemoveOutcome::RrsetDeleted
    );
    assert!(mock.control().rrset(NAME, "TYPE65534").is_some());
}

/// Records of another type at the same name are never touched.
#[tokio::test]
async fn route53_other_types_at_the_name_are_untouched() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZID, NAME, "A", 300, &["192.0.2.1"]);
    control.insert_rrset(ZID, NAME, "SPF", 300, &["\"v=spf1 -all\""]);
    let a = control.rrset(NAME, "A").unwrap();
    let spf = control.rrset(NAME, "SPF").unwrap();
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
    assert_eq!(control.rrset(NAME, "A").unwrap(), a);
    assert_eq!(control.rrset(NAME, "SPF").unwrap(), spf);
    assert!(control.rrset(NAME, "TXT").is_none());
}

/// The TXT dialect: quoted character-strings are joined, and a value the client does not
/// decode is a foreign value written back unchanged.
#[tokio::test]
async fn route53_txt_dialect() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(
        ZID,
        NAME,
        "TXT",
        60,
        &["\"part1\" \"part2\"", "\"ex\\344mple\""],
    );
    assert_eq!(
        add(&client, "part1part2").await.unwrap(),
        AddOutcome::AlreadyPresent
    );
    assert_eq!(
        remove(&client, "part1part2").await.unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(
        control.rrset(NAME, "TXT").unwrap().values,
        ["\"ex\\344mple\""]
    );
    // The value is written quoted.
    add(&client, "AAA").await.unwrap();
    assert_eq!(
        control.rrset(NAME, "TXT").unwrap().values,
        ["\"ex\\344mple\"", "\"AAA\""]
    );

    // A foreign value that decodes but is not in canonical form (two character-strings, extra
    // spaces) is written back exactly as read, never re-encoded, across adds and removes.
    let other = "_acme-challenge.www.example.org";
    control.insert_rrset(ZID, other, "TXT", 60, &["\"a\"   \"b\""]);
    let other_name = dn(other);
    client
        .add_txt_value(&zone(), &other_name, &txt("ours"), None)
        .await
        .unwrap();
    assert_eq!(
        control.rrset(other, "TXT").unwrap().values,
        ["\"a\"   \"b\"", "\"ours\""]
    );
    client
        .remove_txt_value(&zone(), &other_name, &txt("ours"))
        .await
        .unwrap();
    assert_eq!(
        control.rrset(other, "TXT").unwrap().values,
        ["\"a\"   \"b\""]
    );
    // It is the value "ab".
    assert_eq!(
        client
            .add_txt_value(&zone(), &other_name, &txt("ab"), None)
            .await
            .unwrap(),
        AddOutcome::AlreadyPresent
    );
}

/// An rrset with a routing policy is not plain records: a value operation that meets one is
/// refused and writes nothing (design section 3.4).
#[tokio::test]
async fn route53_routing_policy_set_is_refused() {
    let (mock, client) = setup().await;
    mock.control()
        .insert_rrset(ZID, NAME, "TXT", 60, &["\"weighted\""]);
    mock.control().set_set_identifier(NAME, "TXT", "primary");
    let e = add(&client, "AAA").await.unwrap_err();
    assert!(matches!(e, Error::Rejected { status: None, .. }), "{e:?}");
    let e = remove(&client, "weighted").await.unwrap_err();
    assert!(matches!(e, Error::Rejected { status: None, .. }), "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// An rrset holds at most 400 records: the 401st value is refused before the write.
#[tokio::test]
async fn route53_rrset_record_limit() {
    let (mock, client) = setup().await;
    let values: Vec<String> = (0..400).map(|i| format!("\"v{i}\"")).collect();
    let values: Vec<&str> = values.iter().map(String::as_str).collect();
    mock.control().insert_rrset(ZID, NAME, "TXT", 60, &values);
    let e = add(&client, "one-too-many").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(remove(&client, "v7").await.unwrap(), RemoveOutcome::Removed);
}

/// The change is polled until `INSYNC`; a poll that fails is `Transient` (the write was accepted,
/// its outcome is unknown); a change that stays `PENDING` keeps the add waiting through look
/// after look, with the batch sent once. That the looks are bounded, and that the add then ends
/// with `Transient`, is the unit test `a_change_that_stays_pending_is_transient_after_the_last_look`
/// in `src/providers/route53/api.rs` with a lowered bound: the production bound of 60 looks at
/// the 250 ms floor takes 15 seconds.
#[tokio::test]
async fn route53_change_is_polled_until_insync() {
    let (mock, client) = setup().await;
    mock.control().set_pending_polls(2);
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), STATUS), 3);

    mock.control().set_pending_polls(0);
    mock.faults().push(Fault::on("GET", STATUS).respond(
        404,
        error_body(
            "NoSuchChange",
            "A change with the specified change ID does not exist.",
        ),
    ));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    // The batch was applied; the repeat finds the value.
    assert_eq!(
        add(&client, "BBB").await.unwrap(),
        AddOutcome::AlreadyPresent
    );

    mock.faults()
        .push(Fault::on("GET", STATUS).always().respond(
            200,
            format!(
                "<GetChangeResponse xmlns=\"{XMLNS}\"><ChangeInfo><Id>C1</Id>\
                 <Status>PENDING</Status></ChangeInfo></GetChangeResponse>"
            ),
        ));
    let before = mock.log().count(Some("GET"), STATUS);
    let writes_before = writes(&mock);
    let polled = async {
        while mock.log().count(Some("GET"), STATUS) < before + 3 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::select! {
        outcome = add(&client, "CCC") => {
            panic!("the add ended while its change was pending: {outcome:?}")
        }
        () = polled => {}
    }
    assert_eq!(writes(&mock), writes_before + 1);
}

/// The request: signed with SigV4 (host, x-amz-date and the session token signed), the change
/// batch in the documented document, names absolute.
#[tokio::test]
async fn route53_request_shape() {
    let mut seed = Seed::standard();
    seed.session_token = Some("sts-token-for-test".into());
    let (mock, client) = setup_with(seed).await;
    add(&client, "AAA").await.unwrap();
    let post = mock.log().matching(Some("POST"), CHANGE).pop().unwrap();
    let auth = post.header("authorization").unwrap();
    assert!(
        auth.starts_with(&format!("AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/")),
        "{auth}"
    );
    assert!(auth.contains("/us-east-1/route53/aws4_request"), "{auth}");
    assert!(
        auth.contains("SignedHeaders=host;x-amz-date;x-amz-security-token,"),
        "{auth}"
    );
    assert_eq!(
        post.header("x-amz-security-token"),
        Some("sts-token-for-test")
    );
    assert_eq!(post.header("x-amz-date").unwrap().len(), 16);
    let body = post.body_str();
    let doc = roxmltree_free_check(&body);
    assert!(doc, "{body}");
    assert!(
        body.contains(&format!(
            "<ChangeResourceRecordSetsRequest xmlns=\"{XMLNS}\">"
        )),
        "{body}"
    );
    assert!(
        body.contains(
            "<Change><Action>CREATE</Action><ResourceRecordSet>\
             <Name>_acme-challenge.example.org.</Name><Type>TXT</Type><TTL>60</TTL>\
             <ResourceRecords><ResourceRecord><Value>&quot;AAA&quot;</Value></ResourceRecord>\
             </ResourceRecords></ResourceRecordSet></Change>"
        ),
        "{body}"
    );
    let read = mock.log().matching(Some("GET"), RRSETS).pop().unwrap();
    assert_eq!(
        read.query.as_deref(),
        Some(format!("maxitems=1&name={NAME}.&type=TXT").as_str())
    );
    let lookup = mock.log().matching(Some("GET"), ZONES).pop().unwrap();
    assert_eq!(
        lookup.query.as_deref(),
        Some("dnsname=example.org&maxitems=100")
    );
}

/// The body is a complete XML document with the declaration.
fn roxmltree_free_check(body: &str) -> bool {
    body.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
        && body.ends_with("</ChangeResourceRecordSetsRequest>")
}

// ---- Zones -------------------------------------------------------------------------------------

/// The private zone of the same name is skipped; a missing zone is `ZoneNotFound`; two public
/// zones with the name are `Config` unless `hosted_zone_id` selects one; `hosted_zone_id` of
/// another name does not affect the lookup of this one.
#[tokio::test]
async fn route53_zones_public_exact_ambiguous_and_override() {
    let (mock, client) = setup().await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.control().rrset(NAME, "TXT").unwrap().zone_id, ZID);
    let e = client
        .add_txt_value(
            &dn("missing.test"),
            &dn("_acme-challenge.missing.test"),
            &txt("A"),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, Error::ZoneNotFound { .. }), "{e:?}");
    let report = client
        .check(&[zone(), dn("example.net"), dn("missing.test")])
        .await
        .unwrap();
    let found: Vec<bool> = report.zones.iter().map(|z| z.found).collect();
    assert_eq!(found, [true, true, false]);

    let mut seed = Seed::standard();
    seed.zones
        .push(SeedZone::new("ZEXAMPLE0000000002", "example.org.", false));
    let (mock2, client2) = setup_with(seed).await;
    let e = add(&client2, "A").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
    assert!(e.to_string().contains("hosted_zone_id"), "{e}");
    let report = client2.check(&[zone()]).await.unwrap();
    assert!(!report.zones[0].found);
    assert!(
        report.zones[0]
            .detail
            .as_ref()
            .unwrap()
            .as_str()
            .contains("hosted_zone_id")
    );

    let mut config = settings_for(&mock2.base_url());
    config.hosted_zone_id = Some("/hostedzone/ZEXAMPLE0000000002".into());
    let chosen = Route53::new(config.clone(), credentials(SECRET, None), &context()).unwrap();
    add(&chosen, "A").await.unwrap();
    assert_eq!(
        mock2.control().rrset(NAME, "TXT").unwrap().zone_id,
        "ZEXAMPLE0000000002"
    );
    chosen
        .add_txt_value(
            &dn("example.net"),
            &dn("_acme-challenge.example.net"),
            &txt("B"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        mock2
            .control()
            .rrset("_acme-challenge.example.net", "TXT")
            .unwrap()
            .zone_id,
        "ZOTHER000000000001"
    );

    // A configured ID of a private zone, or of no zone, is a configuration error.
    for id in ["ZPRIVATE0000000001", "ZNOSUCHZONE0000001"] {
        config.hosted_zone_id = Some(id.into());
        let wrong = Route53::new(config.clone(), credentials(SECRET, None), &context()).unwrap();
        let e = add(&wrong, "A").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config, "{id}: {e:?}");
        assert!(!wrong.check(&[zone()]).await.unwrap().zones[0].found);
    }
}

/// The zone is found on a later page of the listing.
#[tokio::test]
async fn route53_zone_lookup_reads_every_page() {
    let mut seed = Seed::standard();
    // Zones that sort before "example.org." with the labels reversed ("org.example.").
    seed.zones = (0..150)
        .map(|i| SeedZone::new(&format!("ZA{i:016}"), "example.org.", true))
        .chain(std::iter::once(SeedZone::new(ZID, "example.org.", false)))
        .collect();
    let (mock, client) = setup_with(seed).await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);
    assert_eq!(mock.control().rrset(NAME, "TXT").unwrap().zone_id, ZID);
}

/// `list_zones` reads every page and returns the public zones; with `hosted_zone_id`, that zone
/// only.
#[tokio::test]
async fn route53_list_zones_public_only() {
    let mut seed = Seed::standard();
    for i in 0..120 {
        seed.zones.push(SeedZone::new(
            &format!("ZMANY{i:011}"),
            &format!("z{i:03}.example.test."),
            false,
        ));
    }
    seed.zones
        .push(SeedZone::new("ZPRIVATEONLY000001", "private.test.", true));
    let (mock, client) = setup_with(seed).await;
    let zones: Vec<DomainName> = client
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name)
        .collect();
    assert_eq!(zones.len(), 122);
    assert!(zones.contains(&zone()) && zones.contains(&dn("example.net")));
    assert!(!zones.contains(&dn("private.test")));
    assert!(zones.windows(2).all(|w| w[0] < w[1]), "sorted");
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);
    // The IDs were cached.
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONES), 2);

    let mut config = settings_for(&mock.base_url());
    config.hosted_zone_id = Some("ZOTHER000000000001".into());
    let one = Route53::new(config, credentials(SECRET, None), &context()).unwrap();
    let zones: Vec<DomainName> = one
        .list_zones()
        .await
        .unwrap()
        .into_iter()
        .map(|z| z.name)
        .collect();
    assert_eq!(zones, [dn("example.net")]);
}

/// `check` makes a signed request on every call and looks zones up afresh every time.
#[tokio::test]
async fn route53_check_exercises_the_credentials() {
    let (mock, client) = setup().await;
    for calls in 1..=2 {
        let report = client.check(&[]).await.unwrap();
        assert!(report.credentials_verified);
        assert!(report.zones.is_empty());
        assert_eq!(mock.log().count(Some("GET"), ZONES), calls);
    }
    let last = mock.log().last().unwrap();
    assert!(last.header("authorization").is_some());
    assert_eq!(last.query.as_deref(), Some("maxitems=1"));
    for calls in 3..=4 {
        let report = client.check(&[zone()]).await.unwrap();
        assert!(report.credentials_verified);
        assert!(report.zones[0].found);
        assert_eq!(mock.log().count(Some("GET"), ZONES), calls);
    }
    // A wrong secret fails the check, with or without zones.
    let wrong = client_with(&mock, "wrong-secret", None, &context());
    assert_eq!(wrong.check(&[]).await.unwrap_err().kind(), ErrorKind::Auth);
    assert_eq!(
        wrong.check(&[zone()]).await.unwrap_err().kind(),
        ErrorKind::Auth
    );
}

/// A TLS server on a loopback port whose certificate no trust store knows: every handshake
/// fails on the client's side, so no request is ever answered. Returns its port.
fn untrusted_tls_server() -> u16 {
    use std::io::{Read as _, Write as _};
    let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let chain = vec![key.cert.der().clone()];
    let private = rustls_pki_types::PrivateKeyDer::Pkcs8(key.signing_key.serialize_der().into());
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .unwrap(),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let config = config.clone();
            std::thread::spawn(move || {
                let mut conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                let mut buf = [0u8; 1024];
                // The handshake fails when the client refuses the certificate; were it ever
                // to succeed, the server answers nothing usable.
                if tls.read(&mut buf).is_ok() {
                    let _ = tls.write_all(b"HTTP/1.1 500 Internal Server Error\r\n\r\n");
                }
            });
        }
    });
    port
}

/// `check` never reports verified credentials without an answer from the provider: a refused
/// TLS certificate (an `Error::Config` of the transport) fails the whole check, with or
/// without zones, instead of turning into "zone not found".
#[tokio::test]
async fn route53_check_without_an_answer_is_an_error() {
    let port = untrusted_tls_server();
    let config = settings_for(&format!("https://127.0.0.1:{port}"));
    let client = Route53::new(config, credentials(SECRET, None), &context()).unwrap();
    for zones in [vec![zone()], Vec::new()] {
        match client.check(&zones).await {
            Err(e) => assert_eq!(e.kind(), ErrorKind::Config, "{e:?}"),
            Ok(report) => panic!("{zones:?}: no request was answered: {report:?}"),
        }
    }
    let e = add(&client, "AAA").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Config, "{e:?}");
}

/// After a batch was accepted (2xx), an answer that does not name the change in the expected
/// form leaves the outcome unknown: `Transient`, not `Protocol` (design section 3.7).
#[tokio::test]
async fn route53_unreadable_answer_to_an_accepted_change_is_transient() {
    let (mock, client) = setup().await;
    for body in [
        "this is not XML".to_owned(),
        format!("<ChangeResourceRecordSetsResponse xmlns=\"{XMLNS}\"/>"),
        format!(
            "<ChangeResourceRecordSetsResponse xmlns=\"{XMLNS}\"><ChangeInfo>\
             <Id>/change/../admin</Id><Status>PENDING</Status></ChangeInfo>\
             </ChangeResourceRecordSetsResponse>"
        ),
    ] {
        let before = writes(&mock);
        mock.faults()
            .push(Fault::on("POST", CHANGE).respond(200, body.clone()));
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient, "{body}: {e:?}");
        assert_eq!(writes(&mock), before + 1, "{body}");
    }
}

/// A `GetChange` answer whose status is neither `PENDING` nor `INSYNC`, or that carries no
/// status, ends the add with `Transient` at that look: the batch was accepted and its outcome is
/// unknown (design section 3.7). Polling stops there, and the batch was applied.
#[tokio::test]
async fn route53_unexpected_change_status_is_transient() {
    let (mock, client) = setup().await;
    let bodies = [
        format!(
            "<GetChangeResponse xmlns=\"{XMLNS}\"><ChangeInfo><Id>C1</Id>\
             <Status>DONE</Status></ChangeInfo></GetChangeResponse>"
        ),
        format!(
            "<GetChangeResponse xmlns=\"{XMLNS}\"><ChangeInfo><Id>C1</Id>\
             <Status>insync</Status></ChangeInfo></GetChangeResponse>"
        ),
        format!(
            "<GetChangeResponse xmlns=\"{XMLNS}\"><ChangeInfo><Id>C1</Id>\
             </ChangeInfo></GetChangeResponse>"
        ),
        "<ErrorResponse/>".to_owned(),
    ];
    for (i, body) in bodies.into_iter().enumerate() {
        let value = format!("status-{i}");
        let writes_before = writes(&mock);
        let looks_before = mock.log().count(Some("GET"), STATUS);
        mock.faults()
            .push(Fault::on("GET", STATUS).respond(200, body.clone()));
        let e = add(&client, &value).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient, "{body}: {e:?}");
        assert!(e.is_retryable(), "{body}");
        assert_eq!(writes(&mock), writes_before + 1, "{body}");
        assert_eq!(
            mock.log().count(Some("GET"), STATUS),
            looks_before + 1,
            "{body}"
        );
        assert_eq!(
            add(&client, &value).await.unwrap(),
            AddOutcome::AlreadyPresent,
            "{body}"
        );
    }
}

// ---- Authentication ----------------------------------------------------------------------------

/// A wrong secret, an unknown access key and missing credentials keys.
#[tokio::test]
async fn route53_auth_refused_and_secret_not_leaked() {
    let mock = Route53Mock::start(Seed::standard()).await;
    let bad = client_with(&mock, "wrong-canary-1", None, &context());
    let e = add(&bad, "A").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    assert!(!format!("{e} {e:?} {bad:?}").contains("wrong-canary-1"));
    assert_eq!(bad.check(&[]).await.unwrap_err().kind(), ErrorKind::Auth);
    assert_eq!(bad.list_zones().await.unwrap_err().kind(), ErrorKind::Auth);

    let mut config = settings_for(&mock.base_url());
    config.access_key_id = "AKIAUNKNOWN".into();
    let other = Route53::new(config, credentials(SECRET, None), &context()).unwrap();
    assert_eq!(
        other.check(&[zone()]).await.unwrap_err().kind(),
        ErrorKind::Auth
    );
    assert_eq!(writes(&mock), 0);
}

/// Temporary credentials: the session token is sent and signed; without it the provider
/// refuses the request.
#[tokio::test]
async fn route53_session_token_required_and_signed() {
    let mut seed = Seed::standard();
    seed.session_token = Some("sts-token-canary".into());
    let (mock, client) = setup_with(seed).await;
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);
    let no_token = client_with(&mock, SECRET, None, &context());
    let e = no_token.check(&[zone()]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
    // An empty session token counts as none.
    let empty = client_with(&mock, SECRET, Some(""), &context());
    assert_eq!(empty.check(&[]).await.unwrap_err().kind(), ErrorKind::Auth);
    assert!(!format!("{client:?}").contains("sts-token-canary"));
}

/// A signature refused for its date is `Auth` with a hint about the clock.
#[tokio::test]
async fn route53_clock_skew_is_auth_with_a_hint() {
    let (mock, client) = setup().await;
    for (code, message) in [
        (
            "SignatureDoesNotMatch",
            "Signature expired: 20260101T000000Z is now earlier than 20260101T000500Z.",
        ),
        ("RequestExpired", "Request has expired."),
    ] {
        mock.faults()
            .push(Fault::on("GET", ZONES).respond(403, error_body(code, message)));
        let e = client.check(&[]).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Auth, "{e:?}");
        assert!(e.to_string().contains("clock"), "{e}");
    }
}

// ---- Transport ---------------------------------------------------------------------------------

/// Errors by code: a rate limit (400 `Throttling`, `PriorRequestNotComplete`) is `RateLimited`;
/// a 5xx on a batch is `Transient`; `AccessDenied` is `Forbidden`; another 400 is `Rejected`
/// with the provider's message; nothing of it was written.
#[tokio::test]
async fn route53_errors_mapped() {
    let (mock, client) = setup().await;
    // A throttled read is retried like a 429; throttled on every attempt, it is `RateLimited`.
    mock.faults().push(
        Fault::on("GET", ZONES)
            .times(3)
            .respond(400, error_body("Throttling", "Rate exceeded")),
    );
    let e = add(&client, "A").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), ZONES), 3);
    mock.faults()
        .push(Fault::on("GET", RRSETS).times(3).respond(
            400,
            error_body("PriorRequestNotComplete", "still processing"),
        ));
    let e = add(&client, "A").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited, "{e:?}");
    assert!(e.is_retryable());
    mock.faults()
        .push(Fault::on("POST", CHANGE).respond(500, error_body("InternalFailure", "try again")));
    assert_eq!(
        add(&client, "A").await.unwrap_err().kind(),
        ErrorKind::Transient
    );
    mock.faults()
        .push(Fault::on("POST", CHANGE).respond(403, error_body("AccessDenied", "not allowed")));
    let e = add(&client, "A").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e:?}");
    assert!(e.to_string().contains("AccessDenied: not allowed"), "{e}");
    mock.faults()
        .push(Fault::on("GET", RRSETS).respond(400, error_body("InvalidInput", "bad name")));
    let e = add(&client, "A").await.unwrap_err();
    assert!(
        matches!(
            e,
            Error::Rejected {
                status: Some(400),
                ..
            }
        ),
        "{e:?}"
    );
    assert!(e.to_string().contains("InvalidInput: bad name"), "{e}");
    assert!(mock.control().rrset(NAME, "TXT").is_none());
    add(&client, "A").await.unwrap();
    assert_eq!(mock.control().txt_values(NAME), ["A"]);
}

/// Route 53 answers a refused request rate with HTTP 400 and `Throttling` or
/// `PriorRequestNotComplete`. The transport treats it like a 429: a read is retried with
/// back-off and the operation then succeeds.
#[tokio::test]
async fn route53_throttled_read_is_retried() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RRSETS).respond(400, error_body("Throttling", "Rate exceeded")));
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), RRSETS), 2);
    mock.faults().push(Fault::on("GET", RRSETS).respond(
        400,
        error_body("PriorRequestNotComplete", "still processing"),
    ));
    add(&client, "BBB").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), RRSETS), 4);
    assert_eq!(mock.control().txt_values(NAME), ["AAA", "BBB"]);
}

/// A throttled change batch is not repeated: it is sent once and the result is
/// `RateLimited`, and nothing is written.
#[tokio::test]
async fn route53_throttled_write_is_sent_once() {
    let (mock, client) = setup().await;
    for code in ["Throttling", "PriorRequestNotComplete"] {
        mock.faults()
            .push(Fault::on("POST", CHANGE).respond(400, error_body(code, "slow down")));
        let before = writes(&mock);
        let e = add(&client, "AAA").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::RateLimited, "{code}: {e:?}");
        assert_eq!(writes(&mock), before + 1, "{code}");
        assert!(mock.control().rrset(NAME, "TXT").is_none(), "{code}");
    }
}

/// Every attempt is signed when it is sent: a read repeated after two 5xx answers (back-off of
/// at least 1.5 s in all) carries a later `x-amz-date` than its first attempt, and the mock
/// accepts its signature.
#[tokio::test]
async fn route53_each_attempt_is_signed_anew() {
    let (mock, client) = setup().await;
    mock.faults()
        .push(Fault::on("GET", RRSETS).times(2).status(503));
    add(&client, "AAA").await.unwrap();
    let reads = mock.log().matching(Some("GET"), RRSETS);
    assert_eq!(reads.len(), 3);
    let first = reads[0].header("x-amz-date").unwrap().to_owned();
    let last = reads[2].header("x-amz-date").unwrap().to_owned();
    assert!(last > first, "{first} {last}");
    assert_ne!(
        reads[0].header("authorization"),
        reads[2].header("authorization")
    );
    assert_eq!(mock.control().txt_values(NAME), ["AAA"]);
}

/// A 5xx on a read is retried; three in a row are `Transient`.
#[tokio::test]
async fn route53_server_errors_are_retried_then_transient() {
    let (mock, client) = setup().await;
    mock.faults().push(Fault::on("GET", RRSETS).status(500));
    add(&client, "AAA").await.unwrap();
    mock.faults()
        .push(Fault::on("GET", RRSETS).times(3).status(503));
    let e = add(&client, "BBB").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
    assert_eq!(mock.log().count(Some("GET"), RRSETS), 5);
}

/// `GetHostedZone` is used for the configured zone only, and its private flag is honored.
#[tokio::test]
async fn route53_hosted_zone_request() {
    let (mock, _) = setup().await;
    let mut config = settings_for(&mock.base_url());
    config.hosted_zone_id = Some(ZID.into());
    let client = Route53::new(config, credentials(SECRET, None), &context()).unwrap();
    add(&client, "AAA").await.unwrap();
    assert_eq!(mock.log().count(Some("GET"), ZONE), 1);
    assert_eq!(mock.log().count(Some("GET"), ZONES), 0);
}

// ---- Configuration -----------------------------------------------------------------------------

#[tokio::test]
async fn route53_from_json_builds_the_client() {
    let mock = Route53Mock::start(Seed::standard()).await;
    let settings = serde_json::json!({
        "access_key_id": ACCESS_KEY,
        "base_url": mock.base_url(),
        "change_poll_ms": 250,
    });
    let client = AnyProvider::from_json(
        ProviderId::Route53,
        &settings.to_string(),
        &SecretString::from(format!(
            "{{\"secret_access_key\": \"{SECRET}\", \"other\": 1}}"
        )),
        &context(),
    )
    .unwrap();
    assert_eq!(client.id(), ProviderId::Route53);
    assert!(client.check(&[zone()]).await.unwrap().zones[0].found);
    assert_eq!(add(&client, "AAA").await.unwrap(), AddOutcome::Created);
}

/// Configuration errors are `Config`, name the key and never repeat a value.
#[test]
fn route53_config_errors_name_no_value() {
    let ctx = context();
    let canary = "cfg-canary-91d2";
    let base = || {
        serde_json::json!({
            "access_key_id": ACCESS_KEY,
            "base_url": "http://127.0.0.1:1",
        })
    };
    let with = |key: &str, value: serde_json::Value| {
        let mut settings = base();
        settings[key] = value;
        settings
    };
    let secret = serde_json::json!({"secret_access_key": "s"}).to_string();
    let cases = [
        (
            {
                let mut s = base();
                s.as_object_mut().unwrap().remove("access_key_id");
                s
            },
            secret.clone(),
            "access_key_id",
        ),
        (
            with(canary, serde_json::json!(canary)),
            secret.clone(),
            "unknown keys",
        ),
        (
            with("access_key_id", serde_json::json!(format!("{canary}/x"))),
            secret.clone(),
            "access_key_id",
        ),
        (
            with("access_key_id", serde_json::json!("")),
            secret.clone(),
            "access_key_id",
        ),
        (
            with("hosted_zone_id", serde_json::json!(format!("../{canary}"))),
            secret.clone(),
            "hosted_zone_id",
        ),
        (with("ttl", serde_json::json!(0)), secret.clone(), "ttl"),
        (
            with("ttl", serde_json::json!(86_401)),
            secret.clone(),
            "ttl",
        ),
        (
            with("change_poll_ms", serde_json::json!(100)),
            secret.clone(),
            "change_poll_ms",
        ),
        (
            with(
                "base_url",
                serde_json::json!(format!("https://u:{canary}@route53.example")),
            ),
            secret.clone(),
            "base_url",
        ),
        (
            with(
                "base_url",
                serde_json::json!("http://127.0.0.1:1/2013-04-01"),
            ),
            secret.clone(),
            "base_url",
        ),
        (
            with("base_url", serde_json::json!("http://example.com")),
            secret.clone(),
            "base_url",
        ),
        (
            base(),
            serde_json::json!({"password": canary}).to_string(),
            "secret_access_key",
        ),
        (
            base(),
            serde_json::json!({"secret_access_key": ""}).to_string(),
            "secret_access_key",
        ),
        (
            base(),
            serde_json::json!({"secret_access_key": "s", "session_token": format!("{canary}\n")})
                .to_string(),
            "session_token",
        ),
    ];
    for (settings, credentials, key) in cases {
        let e = AnyProvider::from_json(
            ProviderId::Route53,
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
/// round; the defaults agree.
#[test]
fn route53_config_keys_match_metadata() {
    let meta = ProviderId::Route53.meta();
    let mut config = Route53Config::new("AKIA".into());
    config.hosted_zone_id = Some("Z1".into());
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
    assert_eq!(secret, ["secret_access_key", "session_token"]);
    for field in meta.fields.iter().filter(|f| f.required) {
        assert!(["access_key_id", "secret_access_key"].contains(&field.key));
    }
    let defaults = serde_json::to_value(Route53Config::new(String::new())).unwrap();
    for field in meta.fields.iter().filter(|f| f.default.is_some()) {
        let value = &defaults[field.key];
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        assert_eq!(Some(text.as_str()), field.default, "{}", field.key);
    }
}

// ---- Record level ------------------------------------------------------------------------------

/// An owner name of most record-level tests.
const REC: &str = "rec.example.org";

/// DS wire data: key tag 12345, algorithm 13, digest type 2, a 32-octet digest.
fn ds_wire() -> Vec<u8> {
    let mut wire = vec![0x30, 0x39, 13, 2];
    wire.extend([0xab; 32]);
    wire
}

/// NAPTR wire data: order 100, preference 10, "u", "E2U+sip", a regexp with `\` and `"`, and
/// the root as replacement.
fn naptr_wire() -> Vec<u8> {
    let mut wire = vec![0, 100, 0, 10];
    for string in [&b"u"[..], b"E2U+sip", b"!^(\\+1)$!sip:\"x\"@example.com!"] {
        wire.push(u8::try_from(string.len()).unwrap());
        wire.extend_from_slice(string);
    }
    wire.push(0);
    wire
}

fn wire_text(rtype: RecordType, wire: &[u8]) -> String {
    RecordData::from_wire(rtype, wire)
        .unwrap()
        .as_str()
        .to_owned()
}

/// Every writable type goes through set, get and list with canonical equality, is written in
/// the documented `Value` form, is `Unchanged` on a repeat without a write, and is deleted
/// under an exact expectation; with the apex, a wildcard, an internationalized name, a long
/// TXT value, a TXT value with octets outside printable ASCII and multi-value sets.
#[tokio::test]
async fn route53_record_round_trips() {
    let (mock, client) = setup().await;
    let long = "k".repeat(300);
    let long_txt = Txt::new(long.as_bytes()).unwrap().to_data().unwrap();
    let odd_txt = Txt::new("caf\u{e9} \"q\"".as_bytes())
        .unwrap()
        .to_data()
        .unwrap();
    let spf_txt = {
        let mut wire = vec![11];
        wire.extend_from_slice(b"v=spf1 -all");
        wire_text(spf(), &wire)
    };
    let ds_txt = wire_text(ds(), &ds_wire());
    let naptr_txt = wire_text(naptr(), &naptr_wire());
    let tlsa = format!("3 1 1 {}", "0a".repeat(32));
    let sshfp = format!("4 2 {}", "ab".repeat(32));
    #[allow(clippy::type_complexity)] // Reason: a table of test cases.
    let cases: Vec<(&str, RecordType, Vec<String>, Vec<String>)> = vec![
        (
            "example.org",
            RecordType::A,
            vec!["192.0.2.1".into(), "192.0.2.2".into()],
            vec!["192.0.2.1".into(), "192.0.2.2".into()],
        ),
        (
            REC,
            RecordType::AAAA,
            vec!["2001:db8::1".into()],
            vec!["2001:db8:0:0:0:0:0:1".into()],
        ),
        (
            "example.org",
            RecordType::CAA,
            vec![
                "0 issue \"ca.example.net\"".into(),
                "128 iodef \"mailto:ops@example.org\"".into(),
            ],
            vec![
                "0 issue \"ca.example.net\"".into(),
                "128 iodef \"mailto:ops@example.org\"".into(),
            ],
        ),
        (
            "cname.example.org",
            RecordType::CNAME,
            vec!["target.example.net.".into()],
            vec!["target.example.net.".into()],
        ),
        (
            "sub.example.org",
            ds(),
            vec![ds_txt.clone()],
            vec![format!("12345 13 2 {}", "ab".repeat(32))],
        ),
        (
            REC,
            RecordType::HTTPS,
            vec!["1 . alpn=\"h2,h3\" port=8443".into()],
            vec!["1 . alpn=\"h2,h3\" port=8443".into()],
        ),
        (
            "example.org",
            RecordType::MX,
            vec!["10 mail.example.org.".into(), "20 mx2.example.net.".into()],
            vec!["10 mail.example.org.".into(), "20 mx2.example.net.".into()],
        ),
        (
            REC,
            naptr(),
            vec![naptr_txt.clone()],
            vec!["100 10 \"u\" \"E2U+sip\" \"!^(\\\\+1)$!sip:\\\"x\\\"@example.com!\" .".into()],
        ),
        (
            "sub.example.org",
            RecordType::NS,
            vec!["ns1.example.net.".into(), "ns2.example.net.".into()],
            vec!["ns1.example.net.".into(), "ns2.example.net.".into()],
        ),
        (
            "ptr.example.org",
            RecordType::PTR,
            vec!["host.example.net.".into()],
            vec!["host.example.net.".into()],
        ),
        (
            REC,
            spf(),
            vec![spf_txt.clone()],
            vec!["\"v=spf1 -all\"".into()],
        ),
        (
            "_sip._tcp.example.org",
            RecordType::SRV,
            vec!["10 20 5060 sip.example.org.".into(), "0 0 0 .".into()],
            vec!["10 20 5060 sip.example.org.".into(), "0 0 0 .".into()],
        ),
        (
            REC,
            RecordType::SSHFP,
            vec![
                "1 1 7491973e5f8b39d5327cd4e08bc81b05f7710b49".into(),
                sshfp.clone(),
            ],
            vec![
                "1 1 7491973e5f8b39d5327cd4e08bc81b05f7710b49".into(),
                sshfp.clone(),
            ],
        ),
        (
            "_svc.example.org",
            RecordType::SVCB,
            vec!["0 svc.example.net.".into()],
            vec!["0 svc.example.net.".into()],
        ),
        (
            "_443._tcp.example.org",
            RecordType::TLSA,
            vec![tlsa.clone()],
            vec![tlsa.clone()],
        ),
        (
            "*.example.org",
            RecordType::TXT,
            vec![
                "\"v=spf1 mx -all\"".into(),
                long_txt.as_str().to_owned(),
                odd_txt.as_str().to_owned(),
            ],
            vec![
                "\"v=spf1 mx -all\"".into(),
                format!("\"{}\" \"{}\"", "k".repeat(255), "k".repeat(45)),
                "\"caf\\303\\251 \\\"q\\\"\"".into(),
            ],
        ),
        (
            "xn--bcher-kva.example.org",
            RecordType::TXT,
            vec!["\"idn\"".into()],
            vec!["\"idn\"".into()],
        ),
    ];
    for (name, rtype, texts, api) in &cases {
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        let wanted = rrset(name, *rtype, Some(300), &texts);
        assert_eq!(
            client
                .set_rrset(&zone(), &wanted, Expect::Absent)
                .await
                .unwrap(),
            SetOutcome::Created,
            "{rtype}"
        );
        let stored = mock.control().rrset(name, &rtype.to_string()).unwrap();
        assert_eq!(stored.ttl, 300, "{rtype}");
        let mut values = stored.values.clone();
        values.sort_unstable();
        let mut expected = api.clone();
        expected.sort_unstable();
        assert_eq!(values, expected, "{rtype}: written in the documented form");
        let read = client
            .get_rrset(&zone(), &dn(name), *rtype)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, wanted, "{rtype}");
        assert!(read.records().iter().all(RecordData::is_canonical));
        let before = writes(&mock);
        assert_eq!(
            client
                .set_rrset(&zone(), &wanted, Expect::Matches(&read))
                .await
                .unwrap(),
            SetOutcome::Unchanged,
            "{rtype}"
        );
        assert_eq!(writes(&mock), before, "{rtype}: an unchanged set wrote");
    }
    let listing = client.list_rrsets(&zone()).await.unwrap();
    assert!(listing.skipped.is_empty(), "{:?}", listing.skipped);
    for (name, rtype, texts, _) in &cases {
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        let wanted = rrset(name, *rtype, Some(300), &texts);
        assert!(
            listing.rrsets.contains(&wanted),
            "{rtype} {name} not listed"
        );
    }
    // The SOA and the apex NS set of the zone are listed too.
    for rtype in [RecordType::SOA, RecordType::NS] {
        assert!(
            listing
                .rrsets
                .iter()
                .any(|set| set.name() == &zone() && set.rtype() == rtype),
            "{rtype}"
        );
    }
    for (name, rtype, texts, _) in cases.iter().rev() {
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        let wanted = rrset(name, *rtype, Some(300), &texts);
        assert_eq!(
            client
                .delete_rrset(&zone(), &dn(name), *rtype, Expect::Matches(&wanted))
                .await
                .unwrap(),
            DeleteOutcome::Deleted,
            "{rtype}"
        );
        assert!(mock.control().rrset(name, &rtype.to_string()).is_none());
    }
    let left: Vec<String> = mock
        .control()
        .rrsets()
        .iter()
        .filter(|r| r.zone_id == ZID)
        .map(|r| r.rtype.clone())
        .collect();
    assert_eq!(left, ["SOA", "NS"]);
}

/// Values the API returns in another valid spelling read as canonical data equal to the
/// canonical form; writing the same set back is `Unchanged` and leaves the provider's text.
#[tokio::test]
async fn route53_reads_provider_spellings() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for (rtype, provider, canonical) in [
        (
            "AAAA",
            "2001:0db8:85a3:0:0:8a2e:0370:7334",
            "2001:db8:85a3::8a2e:370:7334".to_owned(),
        ),
        (
            "MX",
            "10 MAIL.Example.org",
            "10 mail.example.org.".to_owned(),
        ),
        (
            "CNAME",
            "target.example.net",
            "target.example.net.".to_owned(),
        ),
        ("TXT", "\"a\" \"b\"", "\"ab\"".to_owned()),
        ("TXT", "\"caf\\351\"", "\"caf\\233\"".to_owned()),
        (
            "SSHFP",
            "1 1 09F6A01D2175742B257C6B98B7C72C44C4040683",
            "1 1 09f6a01d2175742b257c6b98b7c72c44c4040683".to_owned(),
        ),
        (
            "DS",
            "12345 13 2 ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
            wire_text(ds(), &ds_wire()),
        ),
    ] {
        let name = format!("{}.example.org", rtype.to_lowercase());
        control.insert_rrset(ZID, &name, rtype, 600, &[provider]);
        let rtype: RecordType = rtype.parse().unwrap();
        let read = client
            .get_rrset(&zone(), &dn(&name), rtype)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            read,
            rrset(&name, rtype, Some(600), &[&canonical]),
            "{rtype}"
        );
        let before = writes(&mock);
        assert_eq!(
            client
                .set_rrset(
                    &zone(),
                    &rrset(&name, rtype, None, &[&canonical]),
                    Expect::Any
                )
                .await
                .unwrap(),
            SetOutcome::Unchanged
        );
        assert_eq!(writes(&mock), before);
        assert_eq!(
            control.rrset(&name, &rtype.to_string()).unwrap().values,
            [provider]
        );
        control.delete_rrset(&name, &rtype.to_string());
    }
}

#[tokio::test]
async fn route53_failed_expectation_is_precondition_failed() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZID, REC, "A", 600, &["192.0.2.1"]);
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.9"]);
    let wrong = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    let wrong_ttl = rrset(REC, RecordType::A, Some(300), &["192.0.2.1"]);
    for expect in [
        Expect::Absent,
        Expect::Matches(&wrong),
        Expect::Matches(&wrong_ttl),
    ] {
        let e = client
            .set_rrset(&zone(), &wanted, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{expect:?}: {e:?}");
        assert!(!e.is_retryable());
    }
    for expect in [Expect::Matches(&wrong), Expect::Matches(&wrong_ttl)] {
        let e = client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, expect)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{expect:?}: {e:?}");
    }
    let missing = rrset(REC, RecordType::MX, None, &["10 mail.example.org."]);
    let e = client
        .set_rrset(&zone(), &missing, Expect::Matches(&missing))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::MX, Expect::Matches(&missing))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(writes(&mock), 0);
    assert_eq!(control.rrset(REC, "A").unwrap().values, ["192.0.2.1"]);

    // The expectation holds, with the TTL and without one: one batch, `DELETE` of the expected
    // set as read and `CREATE` of the new one.
    let current = rrset(REC, RecordType::A, Some(600), &["192.0.2.1"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Matches(&current))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let batch = mock.control().batches().pop().unwrap();
    assert!(
        batch.contains(
            "<Change><Action>DELETE</Action><ResourceRecordSet><Name>rec.example.org.</Name>\
             <Type>A</Type><TTL>600</TTL><ResourceRecords><ResourceRecord><Value>192.0.2.1\
             </Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change>\
             <Change><Action>CREATE</Action><ResourceRecordSet><Name>rec.example.org.</Name>\
             <Type>A</Type><TTL>600</TTL><ResourceRecords><ResourceRecord><Value>192.0.2.9\
             </Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change>"
        ),
        "{batch}"
    );
    // `Absent` is a bare `CREATE`.
    assert_eq!(
        client
            .set_rrset(&zone(), &missing, Expect::Absent)
            .await
            .unwrap(),
        SetOutcome::Created
    );
    let batch = mock.control().batches().pop().unwrap();
    assert!(!batch.contains("DELETE"), "{batch}");
    assert_eq!(writes(&mock), 2);
}

/// `Expect::Any` replaces the records with `DELETE` as read plus `CREATE` (never `UPSERT`);
/// the TTL is kept unless one is requested; a value the client cannot decode is written back
/// exactly as read when the caller keeps it, and cannot be introduced otherwise.
#[tokio::test]
async fn route53_set_any_replaces_and_keeps_ttl() {
    let (mock, client) = setup().await;
    let control = mock.control();
    // A value in a spelling of its own stays as read when the caller keeps its value.
    control.insert_rrset(ZID, REC, "TXT", 900, &["\"a\"   \"b\"", "\"old\""]);
    let wanted = rrset(REC, RecordType::TXT, None, &["\"ab\"", "\"new\""]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let stored = control.rrset(REC, "TXT").unwrap();
    assert_eq!(stored.ttl, 900);
    assert_eq!(stored.values, ["\"a\"   \"b\"", "\"new\""]);
    let batch = control.batches().pop().unwrap();
    assert!(!batch.contains("UPSERT"), "{batch}");
    let delete = batch.find("<Action>DELETE</Action>").unwrap();
    let create = batch.find("<Action>CREATE</Action>").unwrap();
    assert!(delete < create, "{batch}");
    assert!(
        batch.contains(
            "<TTL>900</TTL><ResourceRecords><ResourceRecord><Value>&quot;a&quot;   \
             &quot;b&quot;</Value></ResourceRecord><ResourceRecord><Value>&quot;old&quot;\
             </Value>"
        ),
        "{batch}"
    );

    // A value the client cannot decode (a name with an octal escape) is non-canonical data,
    // written back exactly as read when the caller keeps it.
    let sub = "sub.example.org";
    control.insert_rrset(
        ZID,
        sub,
        "NS",
        900,
        &["ns1.example.net.", "odd\\052ns.example.net."],
    );
    let read = client
        .get_rrset(&zone(), &dn(sub), RecordType::NS)
        .await
        .unwrap()
        .unwrap();
    let odd = read
        .records()
        .iter()
        .find(|r| !r.is_canonical())
        .unwrap()
        .clone();
    assert_eq!(odd.as_str(), "odd\\052ns.example.net.");
    let keep = RrSet::new(
        dn(sub),
        RecordType::NS,
        None,
        [odd.clone(), rd(RecordType::NS, "ns2.example.net.")],
    )
    .unwrap();
    assert_eq!(
        client.set_rrset(&zone(), &keep, Expect::Any).await.unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(
        control.rrset(sub, "NS").unwrap().values,
        ["odd\\052ns.example.net.", "ns2.example.net."]
    );

    // A requested TTL replaces the TTL.
    let wanted = rrset(REC, RecordType::TXT, Some(120), &["\"only\""]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let stored = control.rrset(REC, "TXT").unwrap();
    assert_eq!(
        (stored.ttl, stored.values),
        (120, vec!["\"only\"".to_owned()])
    );

    // A new set gets the configured TTL.
    let wanted = rrset("new.example.org", RecordType::A, None, &["192.0.2.5"]);
    client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap();
    assert_eq!(control.rrset("new.example.org", "A").unwrap().ttl, 60);

    // Non-canonical data that the rrset does not hold, and values the client cannot encode,
    // are refused after the read and before any write.
    let before = writes(&mock);
    let foreign = RrSet::new(dn("other.example.org"), RecordType::NS, None, [odd]).unwrap();
    let e = client
        .set_rrset(&zone(), &foreign, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    for (rtype, text) in [
        (RecordType::TXT, "\"back\\\\slash\""),
        (RecordType::CAA, "0 issue \"a\\\"b\""),
        (RecordType::SVCB, "1 . key65000=\"x\""),
        (RecordType::HTTPS, "40000 example.net."),
    ] {
        let e = client
            .set_rrset(&zone(), &rrset(REC, rtype, None, &[text]), Expect::Any)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{rtype}: {e:?}");
    }
    assert_eq!(writes(&mock), before);
}

/// Delete with each expectation; a missing set is `NotPresent`; `Absent` has no meaning.
#[tokio::test]
async fn route53_delete_rrset_expectations() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZID, REC, "MX", 600, &["10 mail.example.org."]);
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::MX, Expect::Absent)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty());
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::MX, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(control.rrset(REC, "MX").is_none());
    let batch = control.batches().pop().unwrap();
    assert!(
        batch.contains(
            "<Action>DELETE</Action><ResourceRecordSet><Name>rec.example.org.</Name>\
             <Type>MX</Type><TTL>600</TTL>"
        ),
        "{batch}"
    );
    let before = writes(&mock);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::MX, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
    control.insert_rrset(ZID, REC, "MX", 600, &["10 mail.example.org."]);
    let exact = rrset(REC, RecordType::MX, None, &["10 mail.example.org."]);
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::MX, Expect::Matches(&exact))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert_eq!(writes(&mock), before + 1);
}

/// SOA, the apex NS set and a query type are refused before any request.
#[tokio::test]
async fn route53_protected_sets_send_nothing() {
    let (mock, client) = setup().await;
    let soa = rrset(
        "example.org",
        RecordType::SOA,
        None,
        &["ns.example.net. admin.example.org. 1 7200 900 1209600 86400"],
    );
    let e = client
        .set_rrset(&zone(), &soa, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &zone(), RecordType::SOA, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedRecordType, "{e:?}");
    let ns = rrset("example.org", RecordType::NS, None, &["ns.example.net."]);
    let e = client
        .set_rrset(&zone(), &ns, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    let e = client
        .delete_rrset(&zone(), &zone(), RecordType::NS, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    // The expected set must be about the operation's name and type.
    let a = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    let other = rrset("other.example.org", RecordType::A, None, &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &a, Expect::Matches(&other))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    // Names outside the zone.
    let outside = rrset("example.net", RecordType::A, None, &["192.0.2.1"]);
    let e = client
        .set_rrset(&zone(), &outside, Expect::Any)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::NameOutsideZone { .. }), "{e:?}");
    let e = client
        .delete_rrset(&zone(), &dn("badexample.org"), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::NameOutsideZone { .. }), "{e:?}");
    assert!(mock.log().is_empty(), "{:?}", mock.log().entries());
    // SOA can be read.
    let read = client
        .get_rrset(&zone(), &zone(), RecordType::SOA)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.ttl(), Some(RrsetTtl::from_secs(900).unwrap()));
}

/// The API's TTL range, 0 to 2147483647, is the capabilities' range: every TTL the model holds
/// is accepted, the bounds and a delegation's 172800 included.
#[tokio::test]
async fn route53_record_ttl_bounds() {
    let (mock, client) = setup().await;
    assert!(Ttl::from_secs(2_147_483_648).is_err());
    for ttl in [0, 1, 86_400, 86_401, 172_800, 2_147_483_647] {
        let set = rrset(REC, RecordType::A, Some(ttl), &["192.0.2.1"]);
        client.set_rrset(&zone(), &set, Expect::Any).await.unwrap();
        assert_eq!(mock.control().rrset(REC, "A").unwrap().ttl, u64::from(ttl));
    }
}

/// An rrset holds at most 400 records: a larger request is refused before any request.
#[tokio::test]
async fn route53_record_level_record_limit() {
    let (mock, client) = setup().await;
    let texts: Vec<String> = (0..401).map(|i| format!("\"v{i}\"")).collect();
    let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::TXT, None, &texts),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e:?}");
    assert!(mock.log().is_empty());
    client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::TXT, None, &texts[..400]),
            Expect::Any,
        )
        .await
        .unwrap();
    assert_eq!(mock.control().rrset(REC, "TXT").unwrap().values.len(), 400);
}

/// The listing reports what the model cannot hold, one entry per name and type, and never
/// drops it: routing-policy sets, an alias, a set bound to a health check, a type name the crate
/// does not know and an owner name that is not a valid domain name. Text the client cannot make
/// canonical is listed as non-canonical data. Record-level operations at a name and type that
/// holds a policy set or an alias are refused before any write, and so are the TXT value
/// operations.
#[tokio::test]
async fn route53_listing_reports_skipped_sets() {
    let (capture, _guard) = LogCapture::install();
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZID, REC, "A", 600, &["192.0.2.1"]);
    for (id, weight) in [("one", 10), ("two", 20)] {
        control.insert_policy_set(
            ZID,
            "weighted.example.org",
            "A",
            Some(id),
            &format!("<Weight>{weight}</Weight>"),
            60,
            &["192.0.2.10"],
        );
    }
    control.insert_policy_set(
        ZID,
        "geo.example.org",
        "TXT",
        Some("eu"),
        "<GeoLocation><ContinentCode>EU</ContinentCode></GeoLocation>",
        60,
        &["\"geo\""],
    );
    control.insert_alias(
        ZID,
        "alias.example.org",
        "A",
        "d111111abcdef8.cloudfront.net.",
    );
    control.insert_policy_set(
        ZID,
        "health.example.org",
        "A",
        None,
        "<HealthCheckId>abcdef11-2222-3333-4444-555555fedcba</HealthCheckId>",
        60,
        &["192.0.2.20"],
    );
    control.insert_rrset(ZID, "odd.example.org", "A", 600, &["not-an-address"]);
    control.insert_rrset(ZID, "w.example.org", "WIZARD", 600, &["magic"]);
    control.insert_rrset(ZID, "a b.example.org", "A", 600, &["192.0.2.30"]);

    let listing = client.list_rrsets(&zone()).await.unwrap();
    let mut skipped: Vec<(String, String, SkipReason)> = listing
        .skipped
        .iter()
        .map(|s| (s.name.as_str().to_owned(), s.type_name.clone(), s.reason))
        .collect();
    skipped.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(
        skipped,
        [
            (
                "alias.example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::NotPlainRecords
            ),
            (
                "example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::UnsupportedName
            ),
            (
                "geo.example.org.".to_owned(),
                "TXT".to_owned(),
                SkipReason::NotPlainRecords
            ),
            (
                "health.example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::NotPlainRecords
            ),
            (
                "w.example.org.".to_owned(),
                "WIZARD".to_owned(),
                SkipReason::UnknownType
            ),
            (
                "weighted.example.org.".to_owned(),
                "A".to_owned(),
                SkipReason::NotPlainRecords
            ),
        ]
    );
    let odd = listing
        .rrsets
        .iter()
        .find(|set| set.name() == &dn("odd.example.org"))
        .unwrap();
    assert!(!odd.records()[0].is_canonical());
    assert_eq!(odd.records()[0].as_str(), "not-an-address");
    assert!(
        listing
            .rrsets
            .contains(&rrset(REC, RecordType::A, Some(600), &["192.0.2.1"]))
    );
    let warned = capture
        .entries()
        .iter()
        .any(|e| e.target == "zonewright::rrsets");
    assert!(warned, "no warning about skipped sets");

    // Nothing at those names and types is read as an rrset or changed.
    let before = writes(&mock);
    for (name, rtype) in [
        ("weighted.example.org", RecordType::A),
        ("alias.example.org", RecordType::A),
        ("health.example.org", RecordType::A),
        ("geo.example.org", RecordType::TXT),
    ] {
        let e = client
            .get_rrset(&zone(), &dn(name), rtype)
            .await
            .unwrap_err();
        assert!(matches!(e, Error::Rejected { status: None, .. }), "{e:?}");
        let e = client
            .set_rrset(
                &zone(),
                &rrset(
                    name,
                    rtype,
                    None,
                    &[if rtype == RecordType::A {
                        "192.0.2.99"
                    } else {
                        "\"x\""
                    }],
                ),
                Expect::Any,
            )
            .await
            .unwrap_err();
        assert!(matches!(e, Error::Rejected { status: None, .. }), "{e:?}");
        let e = client
            .delete_rrset(&zone(), &dn(name), rtype, Expect::Any)
            .await
            .unwrap_err();
        assert!(matches!(e, Error::Rejected { status: None, .. }), "{e:?}");
    }
    let e = client
        .add_txt_value(&zone(), &dn("geo.example.org"), &txt("v"), None)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Rejected { status: None, .. }), "{e:?}");
    // A health check on a simple set is refused by the TXT value operations too.
    control.insert_policy_set(
        ZID,
        NAME,
        "TXT",
        None,
        "<HealthCheckId>abcdef11-2222-3333-4444-555555fedcba</HealthCheckId>",
        60,
        &["\"checked\""],
    );
    let e = remove(&client, "checked").await.unwrap_err();
    assert!(matches!(e, Error::Rejected { status: None, .. }), "{e:?}");
    assert_eq!(writes(&mock), before);
}

/// A listing longer than one page is read to the end, also when routing-policy sets of one
/// name and type straddle a page boundary (`NextRecordIdentifier`).
#[tokio::test]
async fn route53_listing_reads_every_page() {
    let (mock, client) = setup().await;
    let control = mock.control();
    for i in 0..297 {
        control.insert_rrset(
            ZID,
            &format!("h{i:03}.example.org"),
            "A",
            60,
            &["192.0.2.1"],
        );
    }
    for id in ["a", "b", "c", "d"] {
        control.insert_policy_set(
            ZID,
            "weighted.example.org",
            "A",
            Some(id),
            "<Weight>1</Weight>",
            60,
            &["192.0.2.2"],
        );
    }
    for i in 0..5 {
        control.insert_rrset(ZID, &format!("z{i}.example.org"), "A", 60, &["192.0.2.3"]);
    }
    let listing = client.list_rrsets(&zone()).await.unwrap();
    // SOA, NS, 297 + 5 plain sets; one skipped entry for the four policy sets.
    assert_eq!(listing.rrsets.len(), 304);
    assert_eq!(listing.skipped.len(), 1, "{:?}", listing.skipped);
    let reads = mock.log().matching(Some("GET"), RRSETS);
    assert_eq!(reads.len(), 2);
    assert!(
        reads[1].query.as_deref().unwrap().contains("identifier="),
        "{:?}",
        reads[1].query
    );
}

/// An rrset listing that says it is truncated without naming the next page, that lacks its
/// list or its truncation flag, or that does not advance, is an error, never a shorter result.
#[tokio::test]
async fn route53_truncated_rrset_listing_is_protocol() {
    let (mock, client) = setup().await;
    let set = "<ResourceRecordSet><Name>example.org.</Name><Type>A</Type><TTL>60</TTL>\
               <ResourceRecords><ResourceRecord><Value>192.0.2.1</Value></ResourceRecord>\
               </ResourceRecords></ResourceRecordSet>";
    for body in [
        format!(
            "<ListResourceRecordSetsResponse xmlns=\"{XMLNS}\"><ResourceRecordSets>{set}\
             </ResourceRecordSets><IsTruncated>true</IsTruncated></ListResourceRecordSetsResponse>"
        ),
        format!(
            "<ListResourceRecordSetsResponse xmlns=\"{XMLNS}\"><IsTruncated>false</IsTruncated>\
             </ListResourceRecordSetsResponse>"
        ),
        format!(
            "<ListResourceRecordSetsResponse xmlns=\"{XMLNS}\"><ResourceRecordSets>{set}\
             </ResourceRecordSets></ListResourceRecordSetsResponse>"
        ),
    ] {
        mock.faults()
            .push(Fault::on("GET", RRSETS).respond(200, body.clone()));
        let e = client.list_rrsets(&zone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "{body}: {e:?}");
    }
    let stuck = format!(
        "<ListResourceRecordSetsResponse xmlns=\"{XMLNS}\"><ResourceRecordSets>{set}\
         </ResourceRecordSets><IsTruncated>true</IsTruncated><NextRecordName>a.example.org.\
         </NextRecordName><NextRecordType>A</NextRecordType></ListResourceRecordSetsResponse>"
    );
    mock.faults()
        .push(Fault::on("GET", RRSETS).always().respond(200, stuck));
    let e = client.list_rrsets(&zone()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    mock.faults().clear();
    // A read of one rrset without its list writes nothing.
    mock.faults().push(Fault::on("GET", RRSETS).respond(
        200,
        format!("<ListResourceRecordSetsResponse xmlns=\"{XMLNS}\"/>"),
    ));
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.1"]),
            Expect::Any,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e:?}");
    assert_eq!(writes(&mock), 0);
}

/// Records at other names and of other types at the same name are untouched by every
/// operation, also when the listing's next rrset in sort order is one of them.
#[tokio::test]
async fn route53_record_operations_leave_other_sets_alone() {
    let (mock, client) = setup().await;
    let control = mock.control();
    control.insert_rrset(ZID, REC, "AAAA", 300, &["2001:db8::5"]);
    control.insert_rrset(ZID, REC, "TXT", 300, &["\"keep\""]);
    control.insert_rrset(ZID, "x.rec.example.org", "A", 300, &["192.0.2.8"]);
    control.insert_rrset(ZID, "rec2.example.org", "A", 300, &["192.0.2.9"]);
    let before: Vec<_> = control.rrsets();
    // The next rrset after (rec, A) is (rec, AAAA): not ours.
    assert_eq!(
        client
            .get_rrset(&zone(), &dn(REC), RecordType::A)
            .await
            .unwrap(),
        None
    );
    let a = rrset(REC, RecordType::A, None, &["192.0.2.1", "192.0.2.2"]);
    client.set_rrset(&zone(), &a, Expect::Absent).await.unwrap();
    let a2 = rrset(REC, RecordType::A, None, &["192.0.2.3"]);
    client.set_rrset(&zone(), &a2, Expect::Any).await.unwrap();
    client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap();
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::NotPresent
    );
    assert_eq!(control.rrsets(), before);
}

/// Two writers on one name from clients sharing a `Context` are serialized: the second reads
/// what the first wrote, and no batch is refused.
#[tokio::test]
async fn route53_concurrent_sets_are_serialized() {
    let mock = Route53Mock::start(Seed::standard()).await;
    let ctx = context();
    let a = client_with(&mock, SECRET, None, &ctx);
    let b = client_with(&mock, SECRET, None, &ctx);
    mock.faults()
        .push(Fault::on("POST", CHANGE).delay(Duration::from_millis(300)));
    let first = rrset(REC, RecordType::A, None, &["192.0.2.1"]);
    let second = rrset(REC, RecordType::A, None, &["192.0.2.2"]);
    let (zone, rec) = (zone(), dn(REC));
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
    assert_eq!(writes(&mock), 1);
    mock.faults()
        .push(Fault::on("POST", CHANGE).delay(Duration::from_millis(300)));
    let (rd_, rs) = tokio::join!(
        a.delete_rrset(&zone, &rec, RecordType::A, Expect::Any),
        b.set_rrset(&zone, &second, Expect::Any),
    );
    rd_.unwrap();
    rs.unwrap();
    // Every batch was accepted: none was built from a stale read.
    assert_eq!(writes(&mock), mock.control().batches().len());
}

/// A change by another writer between the read and the write makes Route 53 refuse the batch;
/// the operation runs once more from the read and evaluates the expectation against the new
/// state; a second refusal is `Conflict`. A hosted zone recreated in between is looked up again.
#[tokio::test]
async fn route53_record_conflict_runs_again() {
    let (mock, client) = setup().await;
    let control = mock.control().clone();
    control.insert_rrset(ZID, REC, "A", 600, &["192.0.2.1"]);
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", CHANGE).run(move || {
        hook.insert_rrset(ZID, REC, "A", 600, &["192.0.2.1", "198.51.100.1"]);
    }));
    let wanted = rrset(REC, RecordType::A, None, &["192.0.2.9"]);
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    assert_eq!(writes(&mock), 2);
    assert_eq!(control.rrset(REC, "A").unwrap().values, ["192.0.2.9"]);

    // Under `Matches`, the second run sees the change and fails the expectation.
    let current = rrset(REC, RecordType::A, None, &["192.0.2.9"]);
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", CHANGE).run(move || {
        hook.insert_rrset(ZID, REC, "A", 600, &["203.0.113.1"]);
    }));
    let e = client
        .set_rrset(
            &zone(),
            &rrset(REC, RecordType::A, None, &["192.0.2.10"]),
            Expect::Matches(&current),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(control.rrset(REC, "A").unwrap().values, ["203.0.113.1"]);

    // A set created after an `Absent` read: the bare CREATE is refused, the re-run fails.
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", CHANGE).run(move || {
        hook.insert_rrset(ZID, "late.example.org", "A", 600, &["203.0.113.2"]);
    }));
    let e = client
        .set_rrset(
            &zone(),
            &rrset("late.example.org", RecordType::A, None, &["192.0.2.1"]),
            Expect::Absent,
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PreconditionFailed, "{e:?}");
    assert_eq!(
        control.rrset("late.example.org", "A").unwrap().values,
        ["203.0.113.2"]
    );

    // Two refusals in a row: `Conflict`, retryable, the foreign change kept.
    let before = writes(&mock);
    let hook = control.clone();
    let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    mock.faults()
        .push(Fault::on("POST", CHANGE).times(2).run(move || {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            hook.insert_rrset(
                ZID,
                REC,
                "A",
                600,
                &[["198.51.100.7", "198.51.100.8"][n as usize % 2]],
            );
        }));
    let e = client
        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict, "{e:?}");
    assert!(e.is_retryable());
    assert_eq!(writes(&mock), before + 2);
    assert_eq!(control.rrset(REC, "A").unwrap().values, ["198.51.100.8"]);

    // A refusal for another reason, the set unchanged: the refusal, sent once.
    let before = writes(&mock);
    mock.faults().push(Fault::on("POST", CHANGE).respond(
        400,
        invalid_change_batch_body(&["Invalid Resource Record: something else"]),
    ));
    let e = client
        .set_rrset(&zone(), &wanted, Expect::Any)
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            Error::Rejected {
                status: Some(400),
                ..
            }
        ),
        "{e:?}"
    );
    assert_eq!(writes(&mock), before + 1);

    // The zone recreated between the read and the write, then between the read and a delete.
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", CHANGE).run(move || {
        hook.recreate_zone("example.org");
    }));
    assert_eq!(
        client
            .set_rrset(&zone(), &wanted, Expect::Any)
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    let hook = control.clone();
    mock.faults().push(Fault::on("POST", CHANGE).run(move || {
        hook.recreate_zone("example.org");
    }));
    assert_eq!(
        client
            .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(control.rrset(REC, "A").is_none());
}

/// A record-level change batch is sent once whatever happens: a 5xx, a rate limit (429 or
/// Route 53's 400 `Throttling`) and a 401 are the operation's error.
#[tokio::test]
async fn route53_record_writes_are_sent_once() {
    let (mock, client) = setup().await;
    let cases: [(Fault, ErrorKind); 4] = [
        (Fault::on("POST", CHANGE).status(502), ErrorKind::Transient),
        (
            Fault::on("POST", CHANGE).rate_limited("1"),
            ErrorKind::RateLimited,
        ),
        (Fault::on("POST", CHANGE).status(401), ErrorKind::Auth),
        (
            Fault::on("POST", CHANGE).respond(400, error_body("Throttling", "Rate exceeded")),
            ErrorKind::RateLimited,
        ),
    ];
    for (fault, kind) in cases {
        for existing in [false, true] {
            mock.control().delete_rrset(REC, "A");
            if existing {
                mock.control()
                    .insert_rrset(ZID, REC, "A", 60, &["192.0.2.1"]);
            }
            for op in ["set", "delete"] {
                if op == "delete" && !existing {
                    continue;
                }
                mock.faults().push(fault.clone());
                let before = writes(&mock);
                let e = if op == "set" {
                    client
                        .set_rrset(
                            &zone(),
                            &rrset(REC, RecordType::A, None, &["192.0.2.2"]),
                            Expect::Any,
                        )
                        .await
                        .unwrap_err()
                } else {
                    client
                        .delete_rrset(&zone(), &dn(REC), RecordType::A, Expect::Any)
                        .await
                        .unwrap_err()
                };
                assert_eq!(e.kind(), kind, "{op} {existing}: {e:?}");
                assert_eq!(writes(&mock), before + 1, "{op} {existing}: {kind:?}");
            }
        }
    }
    // A throttled read is retried.
    mock.faults().push(
        Fault::on("GET", RRSETS)
            .times(2)
            .respond(400, error_body("Throttling", "Rate exceeded")),
    );
    assert!(
        client
            .get_rrset(&zone(), &dn(REC), RecordType::A)
            .await
            .unwrap()
            .is_some()
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
/// removes exactly the values it added afterwards, also when the body failed.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_route53_add_and_remove() {
    let settings = live_env("ZONEWRIGHT_LIVE_ROUTE53_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_ROUTE53_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_ROUTE53_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::Route53,
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
            assert!(report.zones[0].found, "{report:?}");
            assert!(client.check(&[]).await.unwrap().credentials_verified);
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

/// Writes, reads, lists and deletes an A rrset under a generated label in the zone the
/// maintainer names, and removes exactly what it created afterwards, also when the body failed.
#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_route53_record_round_trip() {
    let settings = live_env("ZONEWRIGHT_LIVE_ROUTE53_SETTINGS");
    let credentials = live_env("ZONEWRIGHT_LIVE_ROUTE53_CREDENTIALS");
    let zone = dn(&live_env("ZONEWRIGHT_LIVE_ROUTE53_ZONE"));
    let ctx = Context::new(zonewright::ContextOptions::default()).unwrap();
    let client = Arc::new(
        AnyProvider::from_json(
            ProviderId::Route53,
            &settings,
            &SecretString::from(credentials),
            &ctx,
        )
        .unwrap(),
    );
    let tag = random_u64();
    let name = zone.prepend(&format!("zw-live-{tag:016x}")).unwrap();
    let first = RrSet::new(
        name.clone(),
        RecordType::A,
        Some(RrsetTtl::from_secs(60).unwrap()),
        [
            rd(RecordType::A, "192.0.2.1"),
            rd(RecordType::A, "192.0.2.2"),
        ],
    )
    .unwrap();
    let second = RrSet::new(
        name.clone(),
        RecordType::A,
        None,
        [rd(RecordType::A, "192.0.2.3")],
    )
    .unwrap();

    let body = {
        let (client, zone, name, first, second) = (
            client.clone(),
            zone.clone(),
            name.clone(),
            first.clone(),
            second.clone(),
        );
        tokio::spawn(async move {
            assert_eq!(
                client
                    .set_rrset(&zone, &first, Expect::Absent)
                    .await
                    .unwrap(),
                SetOutcome::Created
            );
            let read = client
                .get_rrset(&zone, &name, RecordType::A)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(read, first);
            assert_eq!(
                client
                    .set_rrset(&zone, &second, Expect::Matches(&first))
                    .await
                    .unwrap(),
                SetOutcome::Replaced
            );
            let listing = client.list_rrsets(&zone).await.unwrap();
            assert!(
                listing
                    .rrsets
                    .iter()
                    .any(|set| set.name() == &name && set.same_records(&second))
            );
            assert_eq!(
                client
                    .delete_rrset(&zone, &name, RecordType::A, Expect::Matches(&second))
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted
            );
        })
    };
    let outcome = body.await;

    // Cleanup: the rrset at the generated name, whichever of the two sets it holds.
    let mut cleanup = Vec::new();
    for set in [&first, &second] {
        if let Err(e) = client
            .delete_rrset(&zone, &name, RecordType::A, Expect::Matches(set))
            .await
            && e.kind() != ErrorKind::PreconditionFailed
        {
            cleanup.push(format!("{e}"));
        }
    }
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}
