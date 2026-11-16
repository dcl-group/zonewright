//! Helpers for tests of the link between a provider mock and the mock DNS server
//! (`zonewright_mock::link`): they ask the DNS mock through the crate's inspector.

use std::net::SocketAddr;
use std::time::Duration;

use zonewright::inspector::{
    Answer, Inspector, InspectorConfig, NameServer, NsDiscovery, Question,
};
use zonewright::{Provider, RecordData, RecordType, Txt};
use zonewright_mock::changes::ChangeSource;
use zonewright_mock::dns::DnsMock;
use zonewright_mock::link::{Link, LinkOptions, link};

use super::dn;

/// The zone of the standard seed of the provider mocks.
pub const ZONE: &str = "example.org";
/// The name a DNS-01 challenge for [`ZONE`] is answered at.
pub const NAME: &str = "_acme-challenge.example.org";

/// An inspector that asks `dns` only.
pub fn inspector(dns: SocketAddr) -> Inspector {
    let mut config = InspectorConfig::default();
    config.resolvers = Vec::new();
    config.discovery = NsDiscovery::Static(vec![NameServer::new(None, dns)]);
    config.query_timeout = Duration::from_secs(2);
    Inspector::new(config).unwrap()
}

pub fn rd(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap()
}

pub fn txt(value: &str) -> RecordData {
    rd(RecordType::TXT, &format!("\"{value}\""))
}

/// What `server` answers, with the AA flag required, for `rtype` at `name`.
pub async fn ask(server: SocketAddr, name: &str, rtype: RecordType) -> Answer {
    inspector(server)
        .query_server(server, &Question::new(dn(name), rtype))
        .await
}

/// The values of an authoritative answer; panics on any other answer.
pub fn values(answer: Answer) -> Vec<RecordData> {
    match answer {
        Answer::Records { records, .. } => records,
        other => panic!("expected records, got {other:?}"),
    }
}

pub fn is_absent(answer: &Answer) -> bool {
    matches!(answer, Answer::NxDomain | Answer::NoData)
}

/// Adds a TXT value at [`NAME`] through `client`, sees it answered by `dns` with the AA flag
/// through a link from `mock`, removes it and sees it gone. Leaves the link in place.
pub async fn txt_round_trip(
    mock: &impl ChangeSource,
    client: &impl Provider,
    dns: &DnsMock,
) -> Link {
    let link = link(mock, dns, LinkOptions::new());
    let value = format!("token-{}", dns.addr().port());
    let zone = dn(ZONE);
    let name = dn(NAME);
    client
        .add_txt_value(&zone, &name, &Txt::new(value.as_str()).unwrap(), None)
        .await
        .unwrap();
    link.settled().await;
    assert_eq!(
        values(ask(dns.addr(), NAME, RecordType::TXT).await),
        [txt(&value)]
    );
    client
        .remove_txt_value(&zone, &name, &Txt::new(value.as_str()).unwrap())
        .await
        .unwrap();
    link.settled().await;
    let answer = ask(dns.addr(), NAME, RecordType::TXT).await;
    assert!(is_absent(&answer), "{answer:?}");
    assert_eq!(link.skipped(), 0);
    link
}
