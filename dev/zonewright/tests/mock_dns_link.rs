//! Tests of the link between a provider mock and the mock DNS server: what a client writes
//! through a provider API is answered over DNS, as an ACME server would ask for it.
//!
//! To cover another provider mock, start it, build its client, and call [`txt_round_trip`] with
//! both and a [`DnsMock`] (see `selectel_v2_txt_value_is_served_and_removed`).
#![cfg(all(feature = "selectel_v2", feature = "cloudflare", feature = "inspector"))]
// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;
use zonewright::inspector::{Condition, Expectation, Question, WaitOptions};
use zonewright::providers::cloudflare::{Cloudflare, CloudflareConfig, CloudflareCredentials};
use zonewright::providers::selectel_v2::{SelectelV2, SelectelV2Config, SelectelV2Credentials};
use zonewright::{Expect, Provider, RecordType, RrSet, Txt};
use zonewright_mock::changes::{Change, ChangeSource, Origin};
use zonewright_mock::cloudflare::CloudflareMock;
use zonewright_mock::dns::{DnsMock, Role, TYPE_TXT};
use zonewright_mock::link::{LinkOptions, link};
use zonewright_mock::selectel_v2::SelectelV2Mock;
use zonewright_mock::{cloudflare, selectel_v2};

use common::link::{NAME, ZONE, ask, inspector, is_absent, rd, txt, txt_round_trip, values};
use common::{context, dn};

// ---- Helpers -------------------------------------------------------------------------------

fn selectel_client(mock: &SelectelV2Mock) -> SelectelV2 {
    let mut config = SelectelV2Config::new("123456".into(), "zw-test-user".into());
    config.project_id = Some("project-a".into());
    config.base_url = mock.base_url();
    config.auth_url = mock.auth_url();
    let credentials =
        SelectelV2Credentials::new(SecretString::from("test-only-password".to_owned()));
    SelectelV2::new(config, credentials, &context()).unwrap()
}

fn cloudflare_client(mock: &CloudflareMock) -> Cloudflare {
    let mut config = CloudflareConfig::default();
    config.base_url = mock.base_url();
    let credentials = CloudflareCredentials::new(SecretString::from("cf-test-token".to_owned()));
    Cloudflare::new(config, credentials, &context()).unwrap()
}

/// Every change waiting in `stream`, as (name, type, values, origin).
fn drain(
    stream: &mut zonewright_mock::changes::ChangeStream,
) -> Vec<(String, String, Option<Vec<String>>, Origin)> {
    let mut out = Vec::new();
    while let Some(Change {
        name,
        rtype,
        rrset,
        origin,
        ..
    }) = stream.try_next()
    {
        out.push((name, rtype, rrset.map(|r| r.values), origin));
    }
    out
}

fn strings(values: &[&str]) -> Option<Vec<String>> {
    Some(values.iter().map(|v| (*v).to_owned()).collect())
}

// ---- Selectel v2 ---------------------------------------------------------------------------

#[tokio::test]
async fn selectel_v2_txt_value_is_served_and_removed() {
    let mock = SelectelV2Mock::start(selectel_v2::Seed::standard()).await;
    // Seeded before the link: served as soon as the link is made.
    mock.control()
        .insert_rrset(ZONE, "www.example.org", "A", 300, &["192.0.2.10"]);
    let dns = DnsMock::start(Role::Authoritative).await;
    let client = selectel_client(&mock);
    let _link = txt_round_trip(&mock, &client, &dns).await;
    let answer = ask(dns.addr(), "www.example.org", RecordType::A).await;
    assert_eq!(values(answer), [rd(RecordType::A, "192.0.2.10")]);
}

#[tokio::test]
async fn a_held_link_keeps_the_value_from_dns_until_release() {
    let mock = SelectelV2Mock::start(selectel_v2::Seed::standard()).await;
    let dns = DnsMock::start(Role::Authoritative).await;
    let client = selectel_client(&mock);
    let link = link(&mock, &dns, LinkOptions::new().held(true));
    client
        .add_txt_value(&dn(ZONE), &dn(NAME), &Txt::new("held").unwrap(), None)
        .await
        .unwrap();
    // Settled while held: the change has reached the link, and DNS does not answer it yet.
    link.settled().await;
    let answer = ask(dns.addr(), NAME, RecordType::TXT).await;
    assert!(is_absent(&answer), "{answer:?}");
    link.release();
    link.settled().await;
    assert_eq!(
        values(ask(dns.addr(), NAME, RecordType::TXT).await),
        [txt("held")]
    );
}

#[tokio::test]
async fn a_wait_succeeds_after_a_delayed_change_and_not_at_once() {
    let mock = SelectelV2Mock::start(selectel_v2::Seed::standard()).await;
    let dns = DnsMock::start(Role::Authoritative).await;
    let client = selectel_client(&mock);
    // Held, so that the first round of the wait certainly runs before the value can be seen,
    // and delayed, so that the value appears some time after the release.
    let link = link(
        &mock,
        &dns,
        LinkOptions::new()
            .held(true)
            .delay(Duration::from_millis(200)),
    );
    client
        .add_txt_value(&dn(ZONE), &dn(NAME), &Txt::new("later").unwrap(), None)
        .await
        .unwrap();
    link.settled().await;

    let inspector = Arc::new(inspector(dns.addr()));
    let mut options = WaitOptions::new(Duration::from_secs(30));
    options.interval = WaitOptions::MIN_INTERVAL;
    options.jitter_percent = 0;
    let expectation = Expectation::new(
        Question::new(dn(NAME), RecordType::TXT),
        Condition::Present(vec![txt("later")]),
    );
    let wait = tokio::spawn({
        let inspector = inspector.clone();
        async move { inspector.wait(&dn(ZONE), &[expectation], &options).await }
    });
    // The first round has asked (and been answered from the held state) before the release.
    tokio::time::timeout(Duration::from_secs(10), async {
        while dns.count(NAME, TYPE_TXT) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    link.release();
    let report = wait.await.unwrap().unwrap();
    assert!(report.rounds >= 2, "{report:?}");
    assert!(report.servers[0].satisfied);
    assert!(report.servers[0].first_satisfied_after.unwrap() > Duration::ZERO);
}

#[tokio::test]
async fn subscribers_see_api_and_control_changes_in_order_and_a_reset() {
    let mock = SelectelV2Mock::start(selectel_v2::Seed::standard()).await;
    let client = selectel_client(&mock);
    let mut stream = mock.changes().subscribe();
    mock.control()
        .insert_rrset(ZONE, "www.example.org", "A", 300, &["192.0.2.10"]);
    for value in ["v1", "v2"] {
        client
            .add_txt_value(&dn(ZONE), &dn(NAME), &Txt::new(value).unwrap(), None)
            .await
            .unwrap();
    }
    client
        .remove_txt_value(&dn(ZONE), &dn(NAME), &Txt::new("v1").unwrap())
        .await
        .unwrap();
    // A change of an unpublished record is not reported.
    mock.control().set_comment(NAME, "TXT", Some("note"));
    assert_eq!(
        drain(&mut stream),
        [
            (
                "www.example.org".into(),
                "A".into(),
                strings(&["192.0.2.10"]),
                Origin::Control
            ),
            (NAME.into(), "TXT".into(), strings(&["\"v1\""]), Origin::Api),
            (
                NAME.into(),
                "TXT".into(),
                strings(&["\"v1\"", "\"v2\""]),
                Origin::Api
            ),
            (NAME.into(), "TXT".into(), strings(&["\"v2\""]), Origin::Api),
        ]
    );

    // A disabled record is not published.
    mock.control().set_txt_disabled(NAME, "v2", true);
    assert_eq!(
        drain(&mut stream),
        [(NAME.into(), "TXT".into(), None, Origin::Control)]
    );

    assert!(mock.control().tokens_issued() > 0);
    mock.control().reset();
    assert_eq!(
        drain(&mut stream),
        [("www.example.org".into(), "A".into(), None, Origin::Control)]
    );
    assert!(mock.log().is_empty());
    assert_eq!(mock.control().tokens_issued(), 0);
    assert!(mock.control().rrsets().is_empty());
    // The client works against the reset mock: it obtains a new token.
    client
        .add_txt_value(&dn(ZONE), &dn(NAME), &Txt::new("v3").unwrap(), None)
        .await
        .unwrap();
    assert_eq!(mock.control().tokens_issued(), 1);
}

// ---- Cloudflare ----------------------------------------------------------------------------

#[tokio::test]
async fn cloudflare_txt_value_is_served_and_removed() {
    let mock = CloudflareMock::start(cloudflare::Seed::standard()).await;
    let dns = DnsMock::start(Role::Authoritative).await;
    let client = cloudflare_client(&mock);
    let _link = txt_round_trip(&mock, &client, &dns).await;
}

#[tokio::test]
async fn cloudflare_records_of_one_name_are_one_rrset() {
    let mock = CloudflareMock::start(cloudflare::Seed::standard()).await;
    let dns = DnsMock::start(Role::Authoritative).await;
    let client = cloudflare_client(&mock);
    let link = link(&mock, &dns, LinkOptions::new());
    let mut stream = mock.changes().subscribe();
    for value in ["one", "two"] {
        client
            .add_txt_value(&dn(ZONE), &dn(NAME), &Txt::new(value).unwrap(), None)
            .await
            .unwrap();
    }
    assert_eq!(mock.control().records_of(NAME, "TXT").len(), 2);
    let changes = drain(&mut stream);
    assert_eq!(changes.last().unwrap().2, strings(&["\"one\"", "\"two\""]));
    link.settled().await;
    let mut seen = values(ask(dns.addr(), NAME, RecordType::TXT).await);
    seen.sort();
    let mut want = vec![txt("one"), txt("two")];
    want.sort();
    assert_eq!(seen, want);

    // A reset reports the removal and empties the DNS side through the link.
    mock.control().reset();
    assert_eq!(
        drain(&mut stream),
        [(NAME.into(), "TXT".into(), None, Origin::Control)]
    );
    link.settled().await;
    let answer = ask(dns.addr(), NAME, RecordType::TXT).await;
    assert!(is_absent(&answer), "{answer:?}");
}

// ---- Record types --------------------------------------------------------------------------

/// Writes a CNAME and a CAA rrset through `client` and sees both answered in their wire form.
async fn cname_and_caa(mock: &impl ChangeSource, client: &impl Provider) {
    let dns = DnsMock::start(Role::Authoritative).await;
    let link = link(mock, &dns, LinkOptions::new());
    let cname = rd(RecordType::CNAME, "target.example.net.");
    let caa = rd(RecordType::CAA, "0 issue \"ca.example.net\"");
    for (name, rtype, data) in [
        ("alias.example.org", RecordType::CNAME, &cname),
        (ZONE, RecordType::CAA, &caa),
    ] {
        let rrset = RrSet::new(dn(name), rtype, None, [data.clone()]).unwrap();
        client
            .set_rrset(&dn(ZONE), &rrset, Expect::Any)
            .await
            .unwrap();
    }
    link.settled().await;
    assert_eq!(
        values(ask(dns.addr(), "alias.example.org", RecordType::CNAME).await),
        [cname]
    );
    assert_eq!(values(ask(dns.addr(), ZONE, RecordType::CAA).await), [caa]);
    assert_eq!(link.skipped(), 0);
}

#[tokio::test]
async fn selectel_v2_cname_and_caa_are_served() {
    let mock = SelectelV2Mock::start(selectel_v2::Seed::standard()).await;
    cname_and_caa(&mock, &selectel_client(&mock)).await;
}

#[tokio::test]
async fn cloudflare_cname_and_caa_are_served() {
    let mock = CloudflareMock::start(cloudflare::Seed::standard()).await;
    cname_and_caa(&mock, &cloudflare_client(&mock)).await;
}

// ---- Binding ---------------------------------------------------------------------------------

#[tokio::test]
async fn mocks_started_on_a_wildcard_address_answer_on_loopback() {
    let any = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let mock = SelectelV2Mock::start_on(any, selectel_v2::Seed::standard()).await;
    let dns = DnsMock::start_on(any, Role::Authoritative).await;
    assert!(mock.addr().ip().is_unspecified());
    assert!(dns.addr().ip().is_unspecified());
    // The wildcard address is no destination: the URL and the query use the loopback address.
    let http = SocketAddr::from((Ipv4Addr::LOCALHOST, mock.addr().port()));
    let mut config = SelectelV2Config::new("123456".into(), "zw-test-user".into());
    config.project_id = Some("project-a".into());
    config.base_url = format!("http://{http}{}", selectel_v2::API_PATH);
    config.auth_url = format!("http://{http}{}", selectel_v2::IDENTITY_PATH);
    let credentials =
        SelectelV2Credentials::new(SecretString::from("test-only-password".to_owned()));
    let client = SelectelV2::new(config, credentials, &context()).unwrap();

    let link = link(&mock, &dns, LinkOptions::new());
    client
        .add_txt_value(&dn(ZONE), &dn(NAME), &Txt::new("anywhere").unwrap(), None)
        .await
        .unwrap();
    link.settled().await;
    let server = SocketAddr::from((Ipv4Addr::LOCALHOST, dns.addr().port()));
    assert_eq!(
        values(ask(server, NAME, RecordType::TXT).await),
        [txt("anywhere")]
    );
}
