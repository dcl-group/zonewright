//! Tests of the propagation inspector against the mock DNS server.
#![cfg(feature = "inspector")]
// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zonewright::dns01::{CnameError, CnameLookup, follow_cname};
use zonewright::inspector::{
    AddressRefusal, Answer, Condition, Expectation, Inspector, InspectorConfig, InspectorError,
    IpFamilies, NameServer, NotAsked, NsDiscovery, Question, Report, WaitOptions,
};
use zonewright::{DomainName, RecordData, RecordType, TargetName};
use zonewright_mock::dns::{
    Action, Change, Data, DnsMock, Fault, NOTIMP, NXDOMAIN, Proto, REFUSED, Role, SERVFAIL, TYPE_A,
    TYPE_AAAA, TYPE_CAA, TYPE_CNAME, TYPE_HTTPS, TYPE_MX, TYPE_NS, TYPE_PTR, TYPE_SOA, TYPE_SRV,
    TYPE_SVCB, TYPE_TLSA, TYPE_TXT,
};

const ZONE: &str = "example.test";
const CHALLENGE: &str = "_acme-challenge.example.test";

fn name(text: &str) -> DomainName {
    DomainName::parse(text).unwrap()
}

fn question(owner: &str, rtype: RecordType) -> Question {
    Question::new(name(owner), rtype)
}

fn parse(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap()
}

fn txt(value: &str) -> RecordData {
    parse(RecordType::TXT, &format!("\"{value}\""))
}

fn records(answer: &Answer) -> &[RecordData] {
    match answer {
        Answer::Records { records, .. } => records,
        other => panic!("expected records, got {other:?}"),
    }
}

async fn authoritative() -> DnsMock {
    let mock = DnsMock::start(Role::Authoritative).await;
    mock.serve_zone(ZONE);
    mock
}

fn static_config(servers: &[SocketAddr], query_timeout: Duration) -> InspectorConfig {
    let mut config = InspectorConfig::default();
    config.resolvers = Vec::new();
    config.discovery = NsDiscovery::Static(
        servers
            .iter()
            .map(|addr| NameServer::new(None, *addr))
            .collect(),
    );
    config.query_timeout = query_timeout;
    config
}

fn static_inspector(servers: &[SocketAddr]) -> Inspector {
    Inspector::new(static_config(servers, Duration::from_millis(500))).unwrap()
}

fn resolver_config(resolvers: &[SocketAddr]) -> InspectorConfig {
    let mut config = InspectorConfig::default();
    config.resolvers = resolvers.to_vec();
    config.query_timeout = Duration::from_millis(500);
    config
}

fn resolver_inspector(resolvers: &[SocketAddr]) -> Inspector {
    Inspector::new(resolver_config(resolvers)).unwrap()
}

/// A UDP port with nothing behind it that answers: bound, never read.
async fn silent_socket() -> tokio::net::UdpSocket {
    tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// Values

#[tokio::test]
async fn values_seen_in_dns_equal_the_parsed_canonical_values() {
    let mock = authoritative().await;
    let long: Vec<u8> = (0..600)
        .map(|i| b'a' + u8::try_from(i % 26).unwrap())
        .collect();
    let long_text = String::from_utf8(long.clone()).unwrap();
    let tlsa_hash = [0xabu8; 32];
    let mut tlsa = vec![3, 1, 1];
    tlsa.extend_from_slice(&tlsa_hash);
    let mut caa = vec![0, 5];
    caa.extend_from_slice(b"issue");
    caa.extend_from_slice(b"ca.example.net");
    let mut caa_critical = vec![128, 5];
    caa_critical.extend_from_slice(b"issue");
    caa_critical.extend_from_slice(b";");
    // HTTPS: priority 1, target ".", alpn=h2,h3, port=8443.
    let https = vec![
        0, 1, 0, 0, 1, 0, 6, 2, b'h', b'2', 2, b'h', b'3', 0, 3, 0, 2, 0x20, 0xfb,
    ];
    // SVCB in alias mode: priority 0, target svc.example.net (uncompressed, as RFC 9460 says).
    let mut svcb = vec![0, 0];
    svcb.extend_from_slice(b"\x03svc\x07example\x03net\x00");
    let sshfp = vec![4, 2, 0x12, 0x34, 0xab];

    // (owner label, type code, served data, the text a provider would return)
    let cases: Vec<(&str, u16, Data, String)> = vec![
        (
            "txt-multi",
            TYPE_TXT,
            Data::txt(&[b"v=spf1 ", b"include:example.net ", b"-all"]),
            "\"v=spf1 include:example.net -all\"".to_owned(),
        ),
        (
            "txt-split-text",
            TYPE_TXT,
            Data::txt(&[b"ab", b"cd"]),
            "\"a\" \"bcd\"".to_owned(),
        ),
        (
            "txt-long",
            TYPE_TXT,
            Data::txt(&[&long[..255], &long[255..510], &long[510..]]),
            format!("\"{long_text}\""),
        ),
        (
            "txt-bytes",
            TYPE_TXT,
            Data::txt(&[b"\x00\xff\"\\ x"]),
            "\"\\000\\255\\\"\\\\ x\"".to_owned(),
        ),
        (
            "mx",
            TYPE_MX,
            Data::Mx(10, "Mail.Example.Test".to_owned()),
            "10 mail.example.test".to_owned(),
        ),
        (
            "null-mx",
            TYPE_MX,
            Data::Mx(0, ".".to_owned()),
            "0 .".to_owned(),
        ),
        (
            "srv",
            TYPE_SRV,
            Data::Srv(10, 5, 443, "srv.example.test".to_owned()),
            "10 5 443 srv.example.test.".to_owned(),
        ),
        (
            "caa",
            TYPE_CAA,
            Data::Raw(caa),
            "0 issue \"ca.example.net\"".to_owned(),
        ),
        (
            "caa-critical",
            TYPE_CAA,
            Data::Raw(caa_critical),
            "128 issue \";\"".to_owned(),
        ),
        (
            "tlsa",
            TYPE_TLSA,
            Data::Raw(tlsa),
            format!("3 1 1 {}", "AB".repeat(32)),
        ),
        (
            "https",
            TYPE_HTTPS,
            Data::Raw(https),
            "1 . port=8443 alpn=h2,h3".to_owned(),
        ),
        (
            "svcb",
            TYPE_SVCB,
            Data::Raw(svcb),
            "0 svc.example.net".to_owned(),
        ),
        ("a", TYPE_A, Data::a([192, 0, 2, 1]), "192.0.2.1".to_owned()),
        (
            "aaaa",
            TYPE_AAAA,
            Data::aaaa("2001:db8::1".parse().unwrap()),
            "2001:0DB8:0:0::1".to_owned(),
        ),
        (
            "cname",
            TYPE_CNAME,
            Data::name("Target.Example.Test"),
            "target.example.test.".to_owned(),
        ),
        (
            "ns",
            TYPE_NS,
            Data::name("ns1.example.test"),
            "ns1.example.test".to_owned(),
        ),
        (
            "ptr",
            TYPE_PTR,
            Data::name("host.example.test"),
            "host.example.test.".to_owned(),
        ),
        (
            "soa",
            TYPE_SOA,
            Data::Soa {
                mname: "ns1.example.test".to_owned(),
                rname: "hostmaster.example.test".to_owned(),
                serial: 2026111401,
                refresh: 3600,
                retry: 600,
                expire: 1_209_600,
                minimum: 300,
            },
            "ns1.example.test. hostmaster.example.test. 2026111401 3600 600 1209600 300".to_owned(),
        ),
        ("sshfp", 44, Data::Raw(sshfp), "4 2 1234AB".to_owned()),
        (
            "unknown",
            65280,
            Data::Raw(vec![1, 2, 3]),
            "\\# 3 010203".to_owned(),
        ),
    ];
    // NS below the apex would be a delegation; the NS case lives at the apex.
    let owner_of = |label: &str, code: u16| {
        if code == TYPE_NS {
            ZONE.to_owned()
        } else {
            format!("{label}.{ZONE}")
        }
    };
    for (label, code, served, _) in &cases {
        mock.add(&owner_of(label, *code), *code, 300, served.clone());
    }
    let inspector = static_inspector(&[mock.addr()]);
    for (label, code, _, text) in &cases {
        let rtype = RecordType::from_code(*code);
        let owner = owner_of(label, *code);
        let answer = inspector
            .query_server(mock.addr(), &question(&owner, rtype))
            .await;
        let expected = RecordData::parse(rtype, text)
            .unwrap_or_else(|err| panic!("{label}: the provider text does not parse: {err}"));
        assert_eq!(records(&answer), &[expected], "{label}");
    }
}

#[tokio::test]
async fn rrsets_are_deduplicated_sorted_and_carry_the_smallest_ttl() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 300, Data::txt(&[b"b"]));
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"a"]));
    mock.add(CHALLENGE, TYPE_TXT, 120, Data::txt(&[b"b"]));
    let inspector = static_inspector(&[mock.addr()]);
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    let Answer::Records { ttl, records } = answer else {
        panic!("expected records");
    };
    assert_eq!(ttl.as_secs(), 60);
    assert_eq!(records, vec![txt("a"), txt("b")]);
}

// ---------------------------------------------------------------------------------------------
// Transport

#[tokio::test]
async fn a_truncated_answer_is_repeated_over_tcp() {
    let mock = authoritative().await;
    let chunk = vec![b'x'; 255];
    for i in 0..4u8 {
        let mut first = chunk.clone();
        first[0] = b'0' + i;
        mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[&first, &chunk]));
    }
    let inspector = static_inspector(&[mock.addr()]);
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    assert_eq!(records(&answer).len(), 4);
    let log = mock.log();
    assert_eq!(
        log.iter().map(|q| q.proto).collect::<Vec<_>>(),
        vec![Proto::Udp, Proto::Tcp]
    );
    assert_eq!(log[0].edns_payload, Some(1232));

    // The TC bit alone, on a small answer, also moves the question to TCP.
    mock.clear_log();
    mock.add(
        &format!("small.{ZONE}"),
        TYPE_A,
        60,
        Data::a([192, 0, 2, 1]),
    );
    mock.push(Fault::new(Action::Truncate));
    let answer = inspector
        .query_server(
            mock.addr(),
            &question(&format!("small.{ZONE}"), RecordType::A),
        )
        .await;
    assert_eq!(records(&answer), &[parse(RecordType::A, "192.0.2.1")]);
    assert_eq!(mock.log().len(), 2);
}

#[tokio::test]
async fn large_answers_over_tcp_are_accepted_up_to_the_tcp_limit() {
    let mock = authoritative().await;
    let chunk = vec![b'y'; 255];
    for i in 0..40u8 {
        let mut first = chunk.clone();
        first[0] = i;
        mock.add(
            CHALLENGE,
            TYPE_TXT,
            60,
            Data::txt(&[&first, &chunk, &chunk]),
        );
    }
    let inspector = static_inspector(&[mock.addr()]);
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    assert_eq!(records(&answer).len(), 40);
}

#[tokio::test]
async fn formerr_to_an_edns_query_is_repeated_once_without_edns() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    mock.push(Fault::new(Action::FormErrOnEdns));
    let inspector = static_inspector(&[mock.addr()]);
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    assert_eq!(records(&answer), &[txt("v")]);
    let edns: Vec<bool> = mock.log().iter().map(|q| q.edns).collect();
    assert_eq!(edns, vec![true, false]);

    // A server that answers FORMERR also without EDNS is not asked a third time.
    mock.clear_log();
    mock.push(Fault::new(Action::Rcode(1)).always());
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    assert_eq!(answer, Answer::Failed("response code 1".to_owned()));
    assert_eq!(mock.log().len(), 2);
}

#[tokio::test]
async fn spoofed_datagrams_are_ignored() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    let mut config = static_config(&[mock.addr()], Duration::from_millis(300));
    config.query_timeout = Duration::from_millis(300);
    let inspector = Inspector::new(config).unwrap();
    let q = question(CHALLENGE, RecordType::TXT);

    for spoof in [
        Action::WrongId { then_answer: true },
        Action::WrongQuestion { then_answer: true },
        Action::OtherSource { then_answer: true },
    ] {
        mock.push(Fault::new(spoof.clone()).proto(Proto::Udp));
        let answer = inspector.query_server(mock.addr(), &q).await;
        assert_eq!(records(&answer), &[txt("v")], "{spoof:?} then the answer");
    }
    for spoof in [
        Action::WrongId { then_answer: false },
        Action::WrongQuestion { then_answer: false },
        Action::OtherSource { then_answer: false },
    ] {
        mock.push(Fault::new(spoof.clone()).proto(Proto::Udp));
        let started = Instant::now();
        let answer = inspector.query_server(mock.addr(), &q).await;
        assert_eq!(answer, Answer::Timeout, "{spoof:?} alone");
        assert!(started.elapsed() < Duration::from_millis(1500));
    }
}

#[tokio::test]
async fn an_off_topic_tcp_answer_fails_the_question() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    mock.push(Fault::new(Action::Truncate).proto(Proto::Udp));
    mock.push(Fault::new(Action::WrongQuestion { then_answer: false }).proto(Proto::Tcp));
    let inspector = static_inspector(&[mock.addr()]);
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    assert!(matches!(answer, Answer::Failed(detail) if detail.contains("TCP")));
}

#[tokio::test]
async fn malformed_and_oversized_answers_fail_the_question() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    let inspector = static_inspector(&[mock.addr()]);
    let q = question(CHALLENGE, RecordType::TXT);
    mock.push(Fault::new(Action::Malformed));
    assert!(matches!(
        inspector.query_server(mock.addr(), &q).await,
        Answer::Failed(detail) if detail.contains("decoded")
    ));
    mock.push(Fault::new(Action::Oversized));
    assert!(matches!(
        inspector.query_server(mock.addr(), &q).await,
        Answer::Failed(detail) if detail.contains("4096")
    ));
    // A record of the asked type whose RDATA is malformed for that type.
    mock.push(Fault::new(Action::Extra(vec![
        zonewright_mock::dns::Record::new(CHALLENGE, TYPE_TXT, 60, Data::Raw(vec![5, b'a'])),
    ])));
    assert!(matches!(
        inspector.query_server(mock.addr(), &q).await,
        Answer::Failed(_)
    ));
}

#[tokio::test]
async fn every_question_uses_a_new_socket_and_the_right_recursion_flag() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    let inspector = static_inspector(&[mock.addr()]);
    let q = question(CHALLENGE, RecordType::TXT);
    for _ in 0..5 {
        inspector.query_server(mock.addr(), &q).await;
    }
    let log = mock.log();
    let mut ports: Vec<u16> = log.iter().map(|q| q.source.port()).collect();
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), 5, "a new source port per question");
    assert!(log.iter().all(|q| !q.recursion_desired));

    let resolver = DnsMock::start(Role::Recursive).await;
    resolver.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    let inspector = resolver_inspector(&[resolver.addr()]);
    inspector.query_recursive(&q).await;
    assert!(resolver.log().iter().all(|q| q.recursion_desired));
}

// ---------------------------------------------------------------------------------------------
// Classification over the wire

#[tokio::test]
async fn answers_are_classified_per_the_design() {
    let mock = authoritative().await;
    mock.add(&format!("www.{ZONE}"), TYPE_A, 60, Data::a([192, 0, 2, 1]));
    mock.add(
        &format!("alias.{ZONE}"),
        TYPE_CNAME,
        60,
        Data::name("elsewhere.example.net"),
    );
    mock.add(
        &format!("sub.{ZONE}"),
        TYPE_NS,
        60,
        Data::name("ns.sub.example.test"),
    );
    mock.add(
        &format!("ns.sub.{ZONE}"),
        TYPE_A,
        60,
        Data::a([192, 0, 2, 53]),
    );
    let inspector = static_inspector(&[mock.addr()]);
    let ask = |owner: String, rtype: RecordType| {
        let inspector = &inspector;
        let addr = mock.addr();
        async move { inspector.query_server(addr, &question(&owner, rtype)).await }
    };
    assert_eq!(
        ask(format!("www.{ZONE}"), RecordType::TXT).await,
        Answer::NoData
    );
    assert_eq!(
        ask(format!("nope.{ZONE}"), RecordType::A).await,
        Answer::NxDomain
    );
    assert_eq!(
        ask(format!("alias.{ZONE}"), RecordType::TXT).await,
        Answer::Cname(TargetName::parse("elsewhere.example.net.").unwrap())
    );
    // A name below a delegation gets a referral.
    assert_eq!(
        ask(format!("x.sub.{ZONE}"), RecordType::A).await,
        Answer::NotAuthoritative
    );
    // A name outside the served zone is refused.
    assert_eq!(
        ask("other.example".to_owned(), RecordType::A).await,
        Answer::Refused
    );
    mock.push(Fault::new(Action::Rcode(SERVFAIL)));
    assert_eq!(
        ask(format!("www.{ZONE}"), RecordType::A).await,
        Answer::ServFail
    );
    mock.push(Fault::new(Action::Rcode(REFUSED)));
    assert_eq!(
        ask(format!("www.{ZONE}"), RecordType::A).await,
        Answer::Refused
    );
    mock.push(Fault::new(Action::Rcode(NOTIMP)));
    assert_eq!(
        ask(format!("www.{ZONE}"), RecordType::A).await,
        Answer::Failed("response code 4".to_owned())
    );
    mock.push(Fault::new(Action::NotAuthoritative));
    assert_eq!(
        ask(format!("www.{ZONE}"), RecordType::A).await,
        Answer::NotAuthoritative
    );
    // Types that cannot be asked are refused without a query.
    mock.clear_log();
    assert!(matches!(
        ask(ZONE.to_owned(), RecordType::ALIAS).await,
        Answer::Failed(_)
    ));
    assert!(matches!(
        ask(ZONE.to_owned(), RecordType::from_code(255)).await,
        Answer::Failed(_)
    ));
    assert!(mock.log().is_empty());
}

#[tokio::test]
async fn a_silent_server_times_out_and_a_closed_port_fails() {
    let silent = silent_socket().await;
    let silent_addr = silent.local_addr().unwrap();
    let closed_addr = {
        let socket = silent_socket().await;
        socket.local_addr().unwrap()
    };
    let inspector =
        Inspector::new(static_config(&[silent_addr], Duration::from_millis(300))).unwrap();
    let q = question(CHALLENGE, RecordType::TXT);
    let started = Instant::now();
    assert_eq!(
        inspector.query_server(silent_addr, &q).await,
        Answer::Timeout
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
    // A closed port answers with ICMP; the question fails (or times out where ICMP is
    // filtered), and never succeeds.
    let answer = inspector.query_server(closed_addr, &q).await;
    assert!(
        matches!(answer, Answer::Failed(_) | Answer::Timeout),
        "{answer:?}"
    );
}

#[tokio::test]
async fn resolver_answers_follow_cname_chains_within_bounds() {
    let resolver = DnsMock::start(Role::Recursive).await;
    let start = "start.example.test";
    let make_chain = |links: usize, prefix: &str| {
        for i in 0..links {
            let owner = if i == 0 {
                format!("{prefix}.example.test")
            } else {
                format!("{prefix}{i}.example.test")
            };
            resolver.add(
                &owner,
                TYPE_CNAME,
                60,
                Data::name(&format!("{prefix}{}.example.test", i + 1)),
            );
        }
        resolver.add(
            &format!("{prefix}{links}.example.test"),
            TYPE_A,
            60,
            Data::a([192, 0, 2, 9]),
        );
    };
    make_chain(8, "start");
    make_chain(9, "long");
    resolver.add(
        "loop.example.test",
        TYPE_CNAME,
        60,
        Data::name("back.example.test"),
    );
    resolver.add(
        "back.example.test",
        TYPE_CNAME,
        60,
        Data::name("loop.example.test"),
    );
    let inspector = resolver_inspector(&[resolver.addr()]);
    let one = |owner: &str| {
        let q = question(owner, RecordType::A);
        let inspector = &inspector;
        async move { inspector.query_recursive(&q).await.remove(0).1 }
    };
    assert_eq!(
        records(&one(start).await),
        &[parse(RecordType::A, "192.0.2.9")]
    );
    assert!(matches!(one("long.example.test").await, Answer::Failed(d) if d.contains("longer")));
    assert!(matches!(one("loop.example.test").await, Answer::Failed(d) if d.contains("loops")));
}

#[tokio::test]
async fn query_recursive_asks_every_resolver_and_keeps_their_order() {
    let r1 = DnsMock::start(Role::Recursive).await;
    let r2 = DnsMock::start(Role::Recursive).await;
    r1.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    r2.set_delay(Some(Duration::from_millis(100)));
    let inspector = resolver_inspector(&[r2.addr(), r1.addr()]);
    let answers = inspector
        .query_recursive(&question(CHALLENGE, RecordType::TXT))
        .await;
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0], (r2.addr(), Answer::NxDomain));
    assert_eq!(answers[1].0, r1.addr());
    assert_eq!(records(&answers[1].1), &[txt("v")]);
}

// ---------------------------------------------------------------------------------------------
// Discovery

async fn delegation_resolver(addresses: &[[u8; 4]]) -> DnsMock {
    let resolver = DnsMock::start(Role::Recursive).await;
    resolver.add(ZONE, TYPE_NS, 300, Data::name("ns1.example.net"));
    resolver.add(ZONE, TYPE_NS, 300, Data::name("ns2.example.net"));
    // NS records of another owner in the same data are never taken.
    resolver.add("example.net", TYPE_NS, 300, Data::name("ns.other.example"));
    for (i, ip) in addresses.iter().enumerate() {
        let host = if i % 2 == 0 {
            "ns1.example.net"
        } else {
            "ns2.example.net"
        };
        resolver.add(host, TYPE_A, 300, Data::a(*ip));
    }
    resolver
}

#[tokio::test]
async fn discovery_through_resolvers_returns_every_address_on_port_53() {
    let resolver = delegation_resolver(&[[192, 0, 2, 1], [198, 51, 100, 2], [192, 0, 2, 3]]).await;
    let inspector = resolver_inspector(&[resolver.addr()]);
    let servers = inspector.name_servers(&name(ZONE)).await.unwrap();
    let found: Vec<(String, String)> = servers
        .iter()
        .map(|s| {
            (
                s.name.as_ref().unwrap().as_str().to_owned(),
                s.query_addr().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        found,
        vec![
            ("ns1.example.net.".to_owned(), "192.0.2.1:53".to_owned()),
            ("ns1.example.net.".to_owned(), "192.0.2.3:53".to_owned()),
            ("ns2.example.net.".to_owned(), "198.51.100.2:53".to_owned()),
        ]
    );
    // Cached: no further queries.
    let before = resolver.log().len();
    inspector.name_servers(&name(ZONE)).await.unwrap();
    assert_eq!(resolver.log().len(), before);
}

/// Each server as (NS name, address, reason it is not asked).
fn rows(servers: &[NameServer]) -> Vec<(String, Option<String>, Option<NotAsked>)> {
    servers
        .iter()
        .map(|s| {
            (
                s.name.as_ref().unwrap().as_str().to_owned(),
                s.addr.map(|a| a.to_string()),
                s.not_asked,
            )
        })
        .collect()
}

fn row(
    ns: &str,
    addr: Option<&str>,
    reason: Option<NotAsked>,
) -> (String, Option<String>, Option<NotAsked>) {
    (ns.to_owned(), addr.map(str::to_owned), reason)
}

#[tokio::test]
async fn private_and_loopback_name_servers_are_reported_not_asked_by_default() {
    // ns1: 127.0.0.1 and 192.0.2.5; ns2: 10.0.0.7.
    let resolver = delegation_resolver(&[[127, 0, 0, 1], [10, 0, 0, 7], [192, 0, 2, 5]]).await;
    let inspector = resolver_inspector(&[resolver.addr()]);
    let refused = |reason| Some(NotAsked::AddressRefused(reason));
    // Every refused address is a row with its reason; nothing is left out.
    let servers = inspector.name_servers(&name(ZONE)).await.unwrap();
    assert_eq!(
        rows(&servers),
        vec![
            row(
                "ns1.example.net.",
                Some("127.0.0.1:53"),
                refused(AddressRefusal::Loopback)
            ),
            row("ns1.example.net.", Some("192.0.2.5:53"), None),
            row(
                "ns2.example.net.",
                Some("10.0.0.7:53"),
                refused(AddressRefusal::Private)
            ),
        ]
    );

    // The option admits private addresses; loopback stays refused.
    let mut config = resolver_config(&[resolver.addr()]);
    config.allow_private_addresses = true;
    let inspector = Inspector::new(config).unwrap();
    let servers = inspector.name_servers(&name(ZONE)).await.unwrap();
    let addrs: Vec<String> = servers
        .iter()
        .filter_map(NameServer::query_addr)
        .map(|a| a.to_string())
        .collect();
    assert_eq!(
        addrs,
        vec!["192.0.2.5:53".to_owned(), "10.0.0.7:53".to_owned()]
    );
    assert_eq!(servers.len(), 3);
}

#[tokio::test]
async fn a_wait_over_servers_that_cannot_be_asked_runs_to_its_timeout_and_says_why() {
    // ns1 at loopback (refused), ns2 without an IPv4 address (NODATA), dangling without any
    // record (NXDOMAIN). No query goes to a name server: none can be asked.
    let resolver = DnsMock::start(Role::Recursive).await;
    for ns in ["ns1.example.net", "ns2.example.net", "dangling.example.net"] {
        resolver.add(ZONE, TYPE_NS, 300, Data::name(ns));
    }
    resolver.add("ns1.example.net", TYPE_A, 300, Data::a([127, 0, 0, 1]));
    resolver.add(
        "ns2.example.net",
        TYPE_AAAA,
        300,
        Data::aaaa("2001:db8::53".parse().unwrap()),
    );
    let inspector = resolver_inspector(&[resolver.addr()]);
    let mut options = WaitOptions::new(Duration::from_millis(1500));
    options.interval = WaitOptions::MIN_INTERVAL;
    options.jitter_percent = 0;
    let started = Instant::now();
    let result = inspector
        .wait(
            &name(ZONE),
            &[Expectation::new(
                question(CHALLENGE, RecordType::TXT),
                Condition::Exact(Vec::new()),
            )],
            &options,
        )
        .await;
    let elapsed = started.elapsed();
    let Err(InspectorError::Timeout { report }) = result else {
        panic!("expected a timeout, got {result:?}");
    };
    assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
    assert_eq!(report.rounds, 2);
    let servers: Vec<NameServer> = report.servers.iter().map(|s| s.server.clone()).collect();
    let loopback = NotAsked::AddressRefused(AddressRefusal::Loopback);
    assert_eq!(
        rows(&servers),
        vec![
            row("dangling.example.net.", None, Some(NotAsked::NoAddress)),
            row("ns1.example.net.", Some("127.0.0.1:53"), Some(loopback)),
            row("ns2.example.net.", None, Some(NotAsked::NoAddress)),
        ]
    );
    for server in &report.servers {
        assert!(!server.satisfied);
        assert_eq!(server.first_satisfied_after, None);
        assert_eq!(
            server.answers,
            vec![Answer::NotAsked(server.server.not_asked.unwrap())]
        );
    }
    // The resolver saw discovery only, once (cached for the second round).
    assert_eq!(resolver.count(ZONE, TYPE_NS), 1);
    assert_eq!(resolver.count(CHALLENGE, TYPE_TXT), 0);
}

/// A resolver for a zone whose name servers all cannot be asked: ns1 at loopback (refused by
/// the address policy), ns2 with an IPv6 address only (no address in the default IPv4 family).
async fn unaskable_delegation() -> DnsMock {
    let resolver = DnsMock::start(Role::Recursive).await;
    for ns in ["ns1.example.net", "ns2.example.net"] {
        resolver.add(ZONE, TYPE_NS, 300, Data::name(ns));
    }
    resolver.add("ns1.example.net", TYPE_A, 300, Data::a([127, 0, 0, 1]));
    resolver.add(
        "ns2.example.net",
        TYPE_AAAA,
        300,
        Data::aaaa("2001:db8::53".parse().unwrap()),
    );
    resolver
}

#[tokio::test]
async fn ignoring_unaskable_servers_never_satisfies_a_zone_none_of_whose_servers_can_be_asked() {
    let resolver = unaskable_delegation().await;
    let inspector = resolver_inspector(&[resolver.addr()]);
    let mut options = WaitOptions::new(Duration::from_millis(1500));
    options.interval = WaitOptions::MIN_INTERVAL;
    options.jitter_percent = 0;
    options.ignore_unaskable_name_servers = true;
    // Exact-empty would hold for an answer of NODATA; no server is asked at all.
    let started = Instant::now();
    let result = inspector
        .wait(
            &name(ZONE),
            &[Expectation::new(
                question(CHALLENGE, RecordType::TXT),
                Condition::Exact(Vec::new()),
            )],
            &options,
        )
        .await;
    let elapsed = started.elapsed();
    let Err(InspectorError::Timeout { report }) = result else {
        panic!("expected a timeout, got {result:?}");
    };
    assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
    assert_eq!(report.rounds, 2);
    assert_eq!(report.unaskable_ignored, 2);
    let servers: Vec<NameServer> = report.servers.iter().map(|s| s.server.clone()).collect();
    let loopback = NotAsked::AddressRefused(AddressRefusal::Loopback);
    assert_eq!(
        rows(&servers),
        vec![
            row("ns1.example.net.", Some("127.0.0.1:53"), Some(loopback)),
            row("ns2.example.net.", None, Some(NotAsked::NoAddress)),
        ]
    );
    for server in &report.servers {
        assert!(!server.satisfied);
        assert_eq!(
            server.answers,
            vec![Answer::NotAsked(server.server.not_asked.unwrap())]
        );
    }
    assert_eq!(resolver.count(CHALLENGE, TYPE_TXT), 0);
}

#[tokio::test]
async fn by_default_unaskable_servers_are_waited_for_and_nothing_is_counted_ignored() {
    let resolver = unaskable_delegation().await;
    let inspector = resolver_inspector(&[resolver.addr()]);
    let mut options = WaitOptions::new(Duration::ZERO);
    assert!(!options.ignore_unaskable_name_servers);
    options.interval = WaitOptions::MIN_INTERVAL;
    let result = inspector
        .wait(
            &name(ZONE),
            &[Expectation::new(
                question(CHALLENGE, RecordType::TXT),
                Condition::Exact(Vec::new()),
            )],
            &options,
        )
        .await;
    let Err(InspectorError::Timeout { report }) = result else {
        panic!("expected a timeout, got {result:?}");
    };
    assert_eq!(report.rounds, 1);
    assert_eq!(report.unaskable_ignored, 0);
    assert_eq!(report.servers.len(), 2);
}

#[tokio::test]
async fn ignoring_unaskable_servers_does_not_change_a_static_list() {
    // Every entry of a static list is asked: a server that does not answer still blocks.
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    let silent = silent_socket().await;
    let inspector = Inspector::new(static_config(
        &[mock.addr(), silent.local_addr().unwrap()],
        Duration::from_millis(300),
    ))
    .unwrap();
    let mut options = WaitOptions::new(Duration::ZERO);
    options.ignore_unaskable_name_servers = true;
    let result = inspector
        .wait(
            &name(ZONE),
            &[Expectation::new(
                question(CHALLENGE, RecordType::TXT),
                Condition::Present(vec![txt("v")]),
            )],
            &options,
        )
        .await;
    let Err(InspectorError::Timeout { report }) = result else {
        panic!("expected a timeout, got {result:?}");
    };
    assert_eq!(report.unaskable_ignored, 0);
    let rows: Vec<(bool, Answer)> = report
        .servers
        .iter()
        .map(|s| (s.satisfied, s.answers[0].clone()))
        .collect();
    assert!(rows[0].0, "{rows:?}");
    assert_eq!(rows[1], (false, Answer::Timeout));

    // With the silent server gone the same options are satisfied, nothing left out.
    let inspector = static_inspector(&[mock.addr()]);
    let report = inspector
        .wait(
            &name(ZONE),
            &[Expectation::new(
                question(CHALLENGE, RecordType::TXT),
                Condition::Present(vec![txt("v")]),
            )],
            &options,
        )
        .await
        .unwrap();
    assert_eq!(report.unaskable_ignored, 0);
}

#[tokio::test]
async fn discovery_moves_on_to_the_next_resolver_and_is_bounded_in_time() {
    let silent = silent_socket().await;
    // One address per NS name.
    let good = delegation_resolver(&[[192, 0, 2, 1], [198, 51, 100, 2]]).await;
    let inspector = resolver_inspector(&[silent.local_addr().unwrap(), good.addr()]);
    let servers = inspector.name_servers(&name(ZONE)).await.unwrap();
    assert_eq!(servers.len(), 2);

    // Three distinct silent resolvers: a resolver may be listed only once.
    let silent2 = silent_socket().await;
    let silent3 = silent_socket().await;
    let mut config = resolver_config(&[
        silent.local_addr().unwrap(),
        silent2.local_addr().unwrap(),
        silent3.local_addr().unwrap(),
    ]);
    config.query_timeout = Duration::from_millis(300);
    config.discovery_timeout = Duration::from_millis(500);
    let inspector = Inspector::new(config).unwrap();
    let started = Instant::now();
    let err = inspector.name_servers(&name(ZONE)).await.unwrap_err();
    let elapsed = started.elapsed();
    assert!(
        matches!(&err, InspectorError::NoNameServers { detail, .. } if detail.contains("timeout")),
        "{err:?}"
    );
    assert!(elapsed >= Duration::from_millis(500), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
}

#[tokio::test]
async fn too_many_ns_names_is_an_error() {
    let resolver = DnsMock::start(Role::Recursive).await;
    for i in 0..17 {
        resolver.add(
            ZONE,
            TYPE_NS,
            300,
            Data::name(&format!("ns{i}.example.net")),
        );
    }
    let inspector = resolver_inspector(&[resolver.addr()]);
    let err = inspector.name_servers(&name(ZONE)).await.unwrap_err();
    assert!(matches!(
        err,
        InspectorError::TooManyNameServers { count: 17, .. }
    ));
    assert_eq!(resolver.count("ns0.example.net", TYPE_A), 0);
}

#[test]
fn the_inspector_and_its_futures_can_move_between_threads() {
    fn send_sync<T: Send + Sync>(_: &T) {}
    fn send<T: Send>(_: T) {}
    let inspector = static_inspector(&["127.0.0.1:53".parse().unwrap()]);
    send_sync(&inspector);
    let zone = name(ZONE);
    let q = question(CHALLENGE, RecordType::TXT);
    let expectations = [Expectation::new(q.clone(), Condition::Exact(Vec::new()))];
    let options = WaitOptions::new(Duration::ZERO);
    // Built, never polled: no query is sent.
    send(inspector.wait(&zone, &expectations, &options));
    send(inspector.observe(&zone, std::slice::from_ref(&q)));
    send(inspector.name_servers(&zone));
    send(inspector.query_server("127.0.0.1:53".parse().unwrap(), &q));
    send(inspector.query_recursive(&q));
    send(inspector.cname(&zone));
}

#[test]
fn invalid_configurations_are_refused() {
    let server = NameServer::new(None, "127.0.0.1:53".parse().unwrap());
    let refused = |config: InspectorConfig| {
        matches!(Inspector::new(config), Err(InspectorError::Config { .. }))
    };
    let mut c = InspectorConfig::default();
    c.query_timeout = Duration::ZERO;
    assert!(refused(c));
    let mut c = InspectorConfig::default();
    c.discovery_timeout = Duration::ZERO;
    assert!(refused(c));
    let mut c = InspectorConfig::default();
    c.max_servers = 0;
    assert!(refused(c));
    let mut c = InspectorConfig::default();
    c.resolvers.clear();
    assert!(refused(c));
    let mut c = InspectorConfig::default();
    c.resolvers = vec!["127.0.0.1:53".parse().unwrap(); 17];
    assert!(refused(c));
    let mut c = InspectorConfig::default();
    c.resolvers = vec![
        "127.0.0.1:53".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
    ];
    assert!(refused(c));
    let mut c = InspectorConfig::default();
    c.discovery = NsDiscovery::Static(Vec::new());
    assert!(refused(c));
    let mut c = InspectorConfig::default();
    c.max_servers = 1;
    c.discovery = NsDiscovery::Static(vec![server.clone(), server.clone()]);
    assert!(refused(c));
    // A static list names servers to ask.
    let mut unasked = server.clone();
    unasked.not_asked = Some(NotAsked::NoAddress);
    let mut c = InspectorConfig::default();
    c.discovery = NsDiscovery::Static(vec![server.clone(), unasked]);
    assert!(refused(c));
    let mut no_address = server.clone();
    no_address.addr = None;
    let mut c = InspectorConfig::default();
    c.discovery = NsDiscovery::Static(vec![no_address]);
    assert!(refused(c));
    let mut c = InspectorConfig::default();
    c.resolvers.clear();
    c.discovery = NsDiscovery::Static(vec![server]);
    assert!(Inspector::new(c).is_ok());
    assert!(Inspector::new(InspectorConfig::default()).is_ok());
}

// ---------------------------------------------------------------------------------------------
// Waiting

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    AllAgree,
    OneLagging,
    OneUnreachable,
    OneLame,
}

/// What the servers hold when they are in step, what a lagging server holds at first, and the
/// condition to wait for.
struct Case {
    in_step: Vec<&'static [u8]>,
    lagging: Vec<&'static [u8]>,
    condition: Condition,
}

fn set_txt(mock: &DnsMock, values: &[&[u8]]) {
    mock.set(
        CHALLENGE,
        TYPE_TXT,
        60,
        values.iter().map(|v| Data::txt(&[v])).collect(),
    );
}

async fn run(case: &Case, scenario: Scenario) -> (Result<Report, InspectorError>, Vec<SocketAddr>) {
    let mocks = [
        authoritative().await,
        authoritative().await,
        authoritative().await,
    ];
    for mock in &mocks {
        set_txt(mock, &case.in_step);
    }
    let silent = silent_socket().await;
    let mut servers: Vec<SocketAddr> = mocks.iter().map(DnsMock::addr).collect();
    match scenario {
        Scenario::AllAgree => {}
        Scenario::OneLagging => set_txt(&mocks[2], &case.lagging),
        Scenario::OneUnreachable => servers[2] = silent.local_addr().unwrap(),
        Scenario::OneLame => mocks[2].push(Fault::new(Action::NotAuthoritative).always()),
    }
    let inspector = Inspector::new(static_config(&servers, Duration::from_millis(250))).unwrap();
    let expectations = [Expectation::new(
        question(CHALLENGE, RecordType::TXT),
        case.condition.clone(),
    )];
    // The shortest interval without jitter: the second round starts 1 s after the first, and
    // no third round fits.
    let mut options = WaitOptions::new(Duration::from_millis(1500));
    options.interval = WaitOptions::MIN_INTERVAL;
    options.jitter_percent = 0;
    let zone = name(ZONE);
    let wait = inspector.wait(&zone, &expectations, &options);
    let catch_up = async {
        if scenario == Scenario::OneLagging {
            tokio::time::sleep(Duration::from_millis(200)).await;
            set_txt(&mocks[2], &case.in_step);
        }
    };
    let (result, ()) = tokio::join!(wait, catch_up);
    (result, servers)
}

async fn check(case: Case) {
    let (result, servers) = run(&case, Scenario::AllAgree).await;
    let report = result.unwrap();
    assert!(report.servers.iter().all(|s| s.satisfied));
    assert_eq!(report.rounds, 1);
    let addrs: Vec<SocketAddr> = report
        .servers
        .iter()
        .map(|s| s.server.query_addr().unwrap())
        .collect();
    assert_eq!(addrs, servers);
    assert!(
        report
            .servers
            .iter()
            .all(|s| s.first_satisfied_after.is_some() && s.answers.len() == 1)
    );

    let (result, _) = run(&case, Scenario::OneLagging).await;
    let report = result.unwrap();
    assert!(report.rounds > 1);
    let first = report.servers[0].first_satisfied_after.unwrap();
    let lagging = report.servers[2].first_satisfied_after.unwrap();
    assert!(lagging >= Duration::from_millis(200), "{lagging:?}");
    assert!(first < lagging);

    for (scenario, expected) in [
        (Scenario::OneUnreachable, Answer::Timeout),
        (Scenario::OneLame, Answer::NotAuthoritative),
    ] {
        let (result, _) = run(&case, scenario).await;
        let Err(InspectorError::Timeout { report }) = result else {
            panic!("{scenario:?}: expected a timeout, got {result:?}");
        };
        assert!(report.servers[0].satisfied && report.servers[1].satisfied);
        assert!(!report.servers[2].satisfied);
        assert_eq!(report.servers[2].answers, vec![expected], "{scenario:?}");
        assert_eq!(report.servers[2].first_satisfied_after, None);
        assert_eq!(report.rounds, 2, "{scenario:?}");
        assert!(report.elapsed >= Duration::from_secs(1));
    }
}

#[tokio::test]
async fn present_with_agreeing_lagging_unreachable_and_lame_servers() {
    check(Case {
        in_step: vec![b"token", b"someone-else"],
        lagging: vec![b"someone-else"],
        condition: Condition::Present(vec![txt("token")]),
    })
    .await;
}

#[tokio::test]
async fn exact_with_agreeing_lagging_unreachable_and_lame_servers() {
    check(Case {
        in_step: vec![b"a", b"b"],
        lagging: vec![b"a", b"b", b"stale"],
        condition: Condition::Exact(vec![txt("b"), txt("a")]),
    })
    .await;
}

#[tokio::test]
async fn exact_empty_with_agreeing_lagging_unreachable_and_lame_servers() {
    check(Case {
        in_step: Vec::new(),
        lagging: vec![b"stale"],
        condition: Condition::Exact(Vec::new()),
    })
    .await;
}

#[tokio::test]
async fn absent_with_agreeing_lagging_unreachable_and_lame_servers() {
    check(Case {
        in_step: vec![b"other"],
        lagging: vec![b"token", b"other"],
        condition: Condition::Absent(vec![txt("token")]),
    })
    .await;
}

#[tokio::test]
async fn the_total_wait_is_bounded_by_timeout_plus_one_query() {
    let silent = silent_socket().await;
    let inspector = Inspector::new(static_config(
        &[silent.local_addr().unwrap()],
        Duration::from_millis(200),
    ))
    .unwrap();
    let expectations = [Expectation::new(
        question(CHALLENGE, RecordType::TXT),
        Condition::Present(vec![txt("v")]),
    )];
    // Rounds of 200 ms (the query timeout) 1 s apart: the second starts at about 1.2 s, ends
    // at about 1.4 s, and then less than one pause is left.
    let mut options = WaitOptions::new(Duration::from_millis(1500));
    options.interval = WaitOptions::MIN_INTERVAL;
    options.jitter_percent = 0;
    let started = Instant::now();
    let err = inspector
        .wait(&name(ZONE), &expectations, &options)
        .await
        .unwrap_err();
    let elapsed = started.elapsed();
    let InspectorError::Timeout { report } = err else {
        panic!("expected a timeout");
    };
    assert!(elapsed >= Duration::from_millis(1400), "{elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(1500 + 200 + 400),
        "{elapsed:?}"
    );
    assert_eq!(report.rounds, 2);
    assert_eq!(report.servers[0].answers, vec![Answer::Timeout]);
}

#[tokio::test]
async fn a_round_asks_all_servers_and_questions_concurrently() {
    let mocks = [
        authoritative().await,
        authoritative().await,
        authoritative().await,
        authoritative().await,
    ];
    for mock in &mocks {
        mock.set_delay(Some(Duration::from_millis(300)));
        mock.add(&format!("a.{ZONE}"), TYPE_A, 60, Data::a([192, 0, 2, 1]));
    }
    let servers: Vec<SocketAddr> = mocks.iter().map(DnsMock::addr).collect();
    let inspector = Inspector::new(static_config(&servers, Duration::from_secs(2))).unwrap();
    let questions = [
        question(&format!("a.{ZONE}"), RecordType::A),
        question(&format!("a.{ZONE}"), RecordType::AAAA),
        question(&format!("b.{ZONE}"), RecordType::TXT),
    ];
    let started = Instant::now();
    let observed = inspector.observe(&name(ZONE), &questions).await.unwrap();
    let elapsed = started.elapsed();
    // Sequentially this would take 12 x 300 ms.
    assert!(elapsed < Duration::from_millis(1200), "{elapsed:?}");
    assert_eq!(observed.len(), 4);
    for (server, answers) in &observed {
        assert!(servers.contains(&server.addr.unwrap()));
        assert_eq!(answers.len(), 3);
        assert_eq!(records(&answers[0]), &[parse(RecordType::A, "192.0.2.1")]);
        assert_eq!(answers[1], Answer::NoData);
        assert_eq!(answers[2], Answer::NxDomain);
    }
    for mock in &mocks {
        assert_eq!(mock.log().len(), 3);
    }
}

#[tokio::test]
async fn dropping_a_wait_stops_its_queries() {
    let mock = authoritative().await;
    let inspector =
        Inspector::new(static_config(&[mock.addr()], Duration::from_millis(200))).unwrap();
    let expectations = [Expectation::new(
        question(CHALLENGE, RecordType::TXT),
        Condition::Present(vec![txt("never")]),
    )];
    let mut options = WaitOptions::new(Duration::from_secs(60));
    options.interval = WaitOptions::MIN_INTERVAL;
    options.jitter_percent = 0;
    let zone = name(ZONE);
    let wait = inspector.wait(&zone, &expectations, &options);
    // Rounds at 0 and 1 s; dropped at 1.2 s, before the third.
    assert!(
        tokio::time::timeout(Duration::from_millis(1200), wait)
            .await
            .is_err()
    );
    // A UDP query sent just before the drop may reach the mock's log only after the drop, the
    // more so on a loaded machine, so the count is taken once the log has been quiet for
    // 100 ms; then the test waits longer than an interval, in which a wait that kept running
    // would have asked again.
    let asked = settled_log_len(&mock).await;
    assert!(asked >= 2);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        mock.log().len(),
        asked,
        "nothing keeps asking after the drop"
    );
}

/// The length of `mock`'s query log once it has not grown for 100 ms; panics when it is still
/// growing after 10 s (queries that never stop).
async fn settled_log_len(mock: &DnsMock) -> usize {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last = mock.log().len();
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = mock.log().len();
        if now == last {
            return now;
        }
        assert!(
            Instant::now() < deadline,
            "nothing keeps asking after the drop"
        );
        last = now;
    }
}

// ---------------------------------------------------------------------------------------------
// CNAME lookup by quorum

#[tokio::test]
async fn cname_lookup_by_quorum_over_resolvers() {
    let r1 = DnsMock::start(Role::Recursive).await;
    let r2 = DnsMock::start(Role::Recursive).await;
    let r3 = DnsMock::start(Role::Recursive).await;
    for r in [&r1, &r2, &r3] {
        r.add(
            CHALLENGE,
            TYPE_CNAME,
            60,
            Data::name("challenges.example.net"),
        );
        r.add(
            "challenges.example.net",
            TYPE_CNAME,
            60,
            Data::name("final.example.org"),
        );
    }
    let inspector = resolver_inspector(&[r1.addr(), r2.addr(), r3.addr()]);
    let chain = follow_cname(&inspector, &name(CHALLENGE), 8).await.unwrap();
    assert_eq!(chain.effective(), &name("final.example.org"));
    assert_eq!(chain.links.len(), 2);
    assert!(r3.log().is_empty(), "two agreeing resolvers are enough");

    // One resolver with another answer: an error at once, not a majority.
    r2.set(
        CHALLENGE,
        TYPE_CNAME,
        60,
        vec![Data::name("attacker.example")],
    );
    let err = follow_cname(&inspector, &name(CHALLENGE), 8)
        .await
        .unwrap_err();
    assert!(matches!(err, CnameError::Lookup { .. }));
    assert!(err.is_retryable());

    // A silent resolver is skipped.
    r2.set_silent(true);
    let target = inspector.cname(&name(CHALLENGE)).await.unwrap();
    assert_eq!(target, Some(name("challenges.example.net")));
}

#[tokio::test]
async fn cname_chain_cap_and_loops_over_the_inspector() {
    let r1 = DnsMock::start(Role::Recursive).await;
    let r2 = DnsMock::start(Role::Recursive).await;
    for r in [&r1, &r2] {
        for i in 0..9 {
            r.add(
                &format!("c{i}.example.test"),
                TYPE_CNAME,
                60,
                Data::name(&format!("c{}.example.test", i + 1)),
            );
        }
        r.add(
            "x.example.test",
            TYPE_CNAME,
            60,
            Data::name("y.example.test"),
        );
        r.add(
            "y.example.test",
            TYPE_CNAME,
            60,
            Data::name("x.example.test"),
        );
    }
    let inspector = resolver_inspector(&[r1.addr(), r2.addr()]);
    let err = follow_cname(&inspector, &name("c0.example.test"), 8)
        .await
        .unwrap_err();
    assert!(matches!(err, CnameError::TooLong { max: 8, .. }));
    let chain = follow_cname(&inspector, &name("c1.example.test"), 8)
        .await
        .unwrap();
    assert_eq!(chain.links.len(), 8);
    let err = follow_cname(&inspector, &name("x.example.test"), 8)
        .await
        .unwrap_err();
    assert!(matches!(err, CnameError::Loop { .. }));
}

// ---------------------------------------------------------------------------------------------
// Tracing

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The capture behind the process-wide subscriber, installed once. A scoped subscriber is not
/// used: while other test threads register call sites concurrently, its interest can be cached
/// as "never" for a call site, and the event is then lost to it.
fn capture() -> &'static Capture {
    static CAPTURE: std::sync::OnceLock<Capture> = std::sync::OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
        capture
    })
}

#[tokio::test]
async fn events_carry_the_server_type_kind_and_duration_but_no_values_or_names() {
    let capture = capture();
    let mock = authoritative().await;
    // Only what is written from here on; an earlier test may have used the same port.
    let offset = capture.0.lock().unwrap().len();
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"secret-token-value"]));
    let inspector = static_inspector(&[mock.addr()]);
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    assert_eq!(records(&answer), &[txt("secret-token-value")]);

    let text = String::from_utf8_lossy(&capture.0.lock().unwrap()[offset..]).into_owned();
    let server = format!("server={}", mock.addr());
    let ours: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("zonewright::inspector") && line.contains(&server))
        .collect();
    assert_eq!(ours.len(), 1, "{text}");
    let line = ours[0];
    assert!(line.contains("DEBUG"), "{line}");
    assert!(line.contains("rtype=TXT"), "{line}");
    assert!(line.contains("answer=\"records\""), "{line}");
    assert!(line.contains("duration_ms="), "{line}");
    assert!(!line.contains("secret-token-value"), "{line}");
    assert!(!line.contains("_acme-challenge"), "{line}");
    assert!(
        !text.contains("secret-token-value"),
        "no value anywhere: {text}"
    );
}

// ---------------------------------------------------------------------------------------------
// Answer acceptance over the wire

#[tokio::test]
async fn answers_with_another_qr_opcode_type_or_class_are_ignored() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    let inspector =
        Inspector::new(static_config(&[mock.addr()], Duration::from_millis(300))).unwrap();
    let q = question(CHALLENGE, RecordType::TXT);
    let changes = [
        Change::NotResponse,
        Change::Opcode(2),
        Change::QuestionType(TYPE_A),
        Change::QuestionClass(3),
    ];
    for change in &changes {
        mock.push(
            Fault::new(Action::Altered {
                change: change.clone(),
                then_answer: true,
            })
            .proto(Proto::Udp),
        );
        let answer = inspector.query_server(mock.addr(), &q).await;
        assert_eq!(records(&answer), &[txt("v")], "{change:?} then the answer");
    }
    for change in &changes {
        mock.push(
            Fault::new(Action::Altered {
                change: change.clone(),
                then_answer: false,
            })
            .proto(Proto::Udp),
        );
        let answer = inspector.query_server(mock.addr(), &q).await;
        assert_eq!(answer, Answer::Timeout, "{change:?} alone");
    }
}

#[tokio::test]
async fn the_question_name_is_matched_case_insensitively() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    let inspector = static_inspector(&[mock.addr()]);
    let q = question(CHALLENGE, RecordType::TXT);
    for proto in [Proto::Udp, Proto::Tcp] {
        if proto == Proto::Tcp {
            mock.push(Fault::new(Action::Truncate).proto(Proto::Udp));
        }
        mock.push(
            Fault::new(Action::Altered {
                change: Change::UpperCaseQuestion,
                then_answer: false,
            })
            .proto(proto),
        );
        let answer = inspector.query_server(mock.addr(), &q).await;
        assert_eq!(records(&answer), &[txt("v")], "{proto:?}");
    }
}

#[tokio::test]
async fn a_truncated_tcp_answer_fails_the_question() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    mock.push(Fault::new(Action::Truncate).proto(Proto::Udp));
    mock.push(
        Fault::new(Action::Altered {
            change: Change::Truncated,
            then_answer: false,
        })
        .proto(Proto::Tcp),
    );
    let inspector = static_inspector(&[mock.addr()]);
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    assert!(
        matches!(&answer, Answer::Failed(detail) if detail.contains("truncated")),
        "{answer:?}"
    );
}

#[tokio::test]
async fn a_truncated_udp_answer_that_does_not_decode_goes_to_tcp() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    // QR, AA and TC; one question announced, the message cut inside its name.
    let mut cut = vec![0, 0, 0x86, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    cut.extend_from_slice(b"\x0e_acme-chal");
    mock.push(Fault::new(Action::Raw(cut)).proto(Proto::Udp));
    let inspector = static_inspector(&[mock.addr()]);
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    assert_eq!(records(&answer), &[txt("v")]);
    let protos: Vec<Proto> = mock.log().iter().map(|q| q.proto).collect();
    assert_eq!(protos, vec![Proto::Udp, Proto::Tcp]);

    // Without the TC flag the same cut message fails the question.
    let mut cut = vec![0, 0, 0x84, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    cut.extend_from_slice(b"\x0e_acme-chal");
    mock.push(Fault::new(Action::Raw(cut)).proto(Proto::Udp));
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    assert!(matches!(answer, Answer::Failed(_)), "{answer:?}");
}

#[tokio::test]
async fn a_truncated_udp_answer_without_a_question_section_goes_to_tcp() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    // QR, AA and TC, NOERROR, every count zero: decodable, but without the question.
    let header = vec![0, 0, 0x86, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    mock.push(Fault::new(Action::Raw(header)).proto(Proto::Udp));
    let inspector =
        Inspector::new(static_config(&[mock.addr()], Duration::from_millis(300))).unwrap();
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    assert_eq!(records(&answer), &[txt("v")]);
    let protos: Vec<Proto> = mock.log().iter().map(|q| q.proto).collect();
    assert_eq!(protos, vec![Proto::Udp, Proto::Tcp]);
}

#[tokio::test]
async fn a_stalled_tcp_retry_is_bounded_by_the_query_timeout() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"v"]));
    mock.push(Fault::new(Action::Truncate).proto(Proto::Udp));
    mock.push(Fault::new(Action::Stall).proto(Proto::Tcp));
    let inspector =
        Inspector::new(static_config(&[mock.addr()], Duration::from_millis(300))).unwrap();
    let started = Instant::now();
    let answer = inspector
        .query_server(mock.addr(), &question(CHALLENGE, RecordType::TXT))
        .await;
    let elapsed = started.elapsed();
    assert_eq!(answer, Answer::Timeout);
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
    let protos: Vec<Proto> = mock.log().iter().map(|q| q.proto).collect();
    assert_eq!(protos, vec![Proto::Udp, Proto::Tcp]);
}

#[tokio::test]
async fn nxdomain_with_records_of_the_asked_type_is_not_absence() {
    let mock = authoritative().await;
    mock.add(CHALLENGE, TYPE_TXT, 60, Data::txt(&[b"token"]));
    mock.push(Fault::new(Action::AnswerWithRcode(NXDOMAIN)).always());
    let inspector = static_inspector(&[mock.addr()]);
    let q = question(CHALLENGE, RecordType::TXT);
    let answer = inspector.query_server(mock.addr(), &q).await;
    assert!(
        matches!(&answer, Answer::Failed(detail) if detail.contains("NXDOMAIN")),
        "{answer:?}"
    );
    for condition in [
        Condition::Absent(vec![txt("token")]),
        Condition::Exact(Vec::new()),
    ] {
        let result = inspector
            .wait(
                &name(ZONE),
                &[Expectation::new(q.clone(), condition.clone())],
                &WaitOptions::new(Duration::ZERO),
            )
            .await;
        assert!(
            matches!(result, Err(InspectorError::Timeout { .. })),
            "{condition:?}: {result:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Discovery never shortens the list

#[tokio::test]
async fn an_ns_name_whose_address_no_resolver_answers_fails_the_discovery_uncached() {
    let r1 = delegation_resolver(&[[192, 0, 2, 1], [198, 51, 100, 2]]).await;
    let r2 = delegation_resolver(&[[192, 0, 2, 1], [198, 51, 100, 2]]).await;
    for resolver in [&r1, &r2] {
        resolver.push(
            Fault::new(Action::Rcode(SERVFAIL))
                .name("ns2.example.net")
                .rtype(TYPE_A),
        );
    }
    let inspector = resolver_inspector(&[r1.addr(), r2.addr()]);
    let err = inspector.name_servers(&name(ZONE)).await.unwrap_err();
    assert!(
        matches!(&err, InspectorError::NoNameServers { detail, .. }
            if detail.contains("ns2.example.net.") && detail.contains("no resolver answered")),
        "{err:?}"
    );
    assert_eq!(r1.count("ns2.example.net", TYPE_A), 1);
    assert_eq!(r2.count("ns2.example.net", TYPE_A), 1);
    // A wait over the same discovery fails too: it never reports success without a server.
    for resolver in [&r1, &r2] {
        resolver.push(
            Fault::new(Action::Rcode(SERVFAIL))
                .name("ns2.example.net")
                .rtype(TYPE_A),
        );
    }
    let result = inspector
        .wait(
            &name(ZONE),
            &[Expectation::new(
                question(CHALLENGE, RecordType::TXT),
                Condition::Exact(Vec::new()),
            )],
            &WaitOptions::new(Duration::ZERO),
        )
        .await;
    assert!(
        matches!(result, Err(InspectorError::NoNameServers { .. })),
        "{result:?}"
    );
    // Nothing was cached: the next call asks again and gets every server.
    let servers = inspector.name_servers(&name(ZONE)).await.unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(r1.count(ZONE, TYPE_NS), 3);
}

#[tokio::test]
async fn an_ns_name_without_an_address_in_the_families_is_a_row_not_asked() {
    let resolver = DnsMock::start(Role::Recursive).await;
    resolver.add(ZONE, TYPE_NS, 300, Data::name("ns1.example.net"));
    resolver.add(ZONE, TYPE_NS, 300, Data::name("v6only.example.net"));
    resolver.add("ns1.example.net", TYPE_A, 300, Data::a([192, 0, 2, 1]));
    resolver.add(
        "v6only.example.net",
        TYPE_AAAA,
        300,
        Data::aaaa("2001:db8::53".parse().unwrap()),
    );
    let inspector = resolver_inspector(&[resolver.addr()]);
    let servers = inspector.name_servers(&name(ZONE)).await.unwrap();
    assert_eq!(
        rows(&servers),
        vec![
            row("ns1.example.net.", Some("192.0.2.1:53"), None),
            row("v6only.example.net.", None, Some(NotAsked::NoAddress)),
        ]
    );
    // With both families every NS name has an address.
    let mut config = resolver_config(&[resolver.addr()]);
    config.ip_families = IpFamilies::Both;
    let inspector = Inspector::new(config).unwrap();
    let servers = inspector.name_servers(&name(ZONE)).await.unwrap();
    let addrs: Vec<String> = servers
        .iter()
        .map(|s| s.query_addr().unwrap().to_string())
        .collect();
    assert_eq!(
        addrs,
        vec!["192.0.2.1:53".to_owned(), "[2001:db8::53]:53".to_owned()]
    );
}

#[tokio::test]
async fn an_interval_below_the_floor_is_invalid_input() {
    let mock = authoritative().await;
    let inspector = static_inspector(&[mock.addr()]);
    let mut options = WaitOptions::new(Duration::from_secs(5));
    options.interval = Duration::from_millis(50);
    let result = inspector
        .wait(
            &name(ZONE),
            &[Expectation::new(
                question(CHALLENGE, RecordType::TXT),
                Condition::Exact(Vec::new()),
            )],
            &options,
        )
        .await;
    assert!(
        matches!(result, Err(InspectorError::InvalidInput { .. })),
        "{result:?}"
    );
    assert!(mock.log().is_empty());
}

#[tokio::test]
async fn duplicate_resolvers_are_a_configuration_error() {
    let resolver = DnsMock::start(Role::Recursive).await;
    let result = Inspector::new(resolver_config(&[resolver.addr(), resolver.addr()]));
    assert!(
        matches!(result, Err(InspectorError::Config { .. })),
        "{result:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Static servers that answer without the AA flag

/// A server for the zone that never sets AA: data at `www` (A), a SOA at the apex, and a
/// delegation of `sub`.
async fn unflagged_server() -> DnsMock {
    let mock = authoritative().await;
    mock.add(&format!("www.{ZONE}"), TYPE_A, 60, Data::a([192, 0, 2, 1]));
    mock.add(
        ZONE,
        TYPE_SOA,
        60,
        Data::Soa {
            mname: format!("ns.{ZONE}"),
            rname: format!("hostmaster.{ZONE}"),
            serial: 1,
            refresh: 3600,
            retry: 600,
            expire: 86400,
            minimum: 60,
        },
    );
    mock.add(
        &format!("sub.{ZONE}"),
        TYPE_NS,
        60,
        Data::name("ns.sub.example.test"),
    );
    mock.push(Fault::new(Action::NotAuthoritative).always());
    mock
}

fn unflagged_expectations() -> [Expectation; 3] {
    [
        Expectation::new(
            question(&format!("www.{ZONE}"), RecordType::A),
            Condition::Exact(vec![parse(RecordType::A, "192.0.2.1")]),
        ),
        Expectation::new(
            question(&format!("www.{ZONE}"), RecordType::TXT),
            Condition::Exact(Vec::new()),
        ),
        Expectation::new(
            question(&format!("nope.{ZONE}"), RecordType::A),
            Condition::Absent(vec![parse(RecordType::A, "192.0.2.1")]),
        ),
    ]
}

fn quick() -> WaitOptions {
    let mut options = WaitOptions::new(Duration::ZERO);
    options.jitter_percent = 0;
    options
}

#[tokio::test]
async fn by_default_a_static_server_without_aa_satisfies_nothing() {
    assert!(!InspectorConfig::default().accept_static_without_aa);
    let mock = unflagged_server().await;
    let inspector = static_inspector(&[mock.addr()]);
    let err = inspector
        .wait(&name(ZONE), &unflagged_expectations(), &quick())
        .await
        .unwrap_err();
    let InspectorError::Timeout { report } = err else {
        panic!("expected a timeout");
    };
    assert_eq!(report.servers[0].answers, vec![Answer::NotAuthoritative; 3]);
}

#[tokio::test]
async fn with_the_option_a_static_server_without_aa_is_read_by_its_content() {
    let mock = unflagged_server().await;
    let mut config = static_config(&[mock.addr()], Duration::from_millis(500));
    config.accept_static_without_aa = true;
    let inspector = Inspector::new(config).unwrap();
    let report = inspector
        .wait(&name(ZONE), &unflagged_expectations(), &quick())
        .await
        .unwrap();
    assert_eq!(report.rounds, 1);
    let answers = &report.servers[0].answers;
    assert_eq!(records(&answers[0]), &[parse(RecordType::A, "192.0.2.1")]);
    assert_eq!(answers[1], Answer::NoData);
    assert_eq!(answers[2], Answer::NxDomain);

    // A referral without AA is not absence, also with the option.
    let referral = [Expectation::new(
        question(&format!("x.sub.{ZONE}"), RecordType::A),
        Condition::Exact(Vec::new()),
    )];
    let err = inspector
        .wait(&name(ZONE), &referral, &quick())
        .await
        .unwrap_err();
    let InspectorError::Timeout { report } = err else {
        panic!("expected a timeout");
    };
    assert_eq!(report.servers[0].answers, vec![Answer::NotAuthoritative]);
    let observed = inspector
        .observe(
            &name(ZONE),
            &[question(&format!("x.sub.{ZONE}"), RecordType::A)],
        )
        .await
        .unwrap();
    assert_eq!(observed[0].1, vec![Answer::NotAuthoritative]);

    // query_server always requires AA, also for an address of the static list.
    assert_eq!(
        inspector
            .query_server(
                mock.addr(),
                &question(&format!("www.{ZONE}"), RecordType::A)
            )
            .await,
        Answer::NotAuthoritative
    );
}

// ---------------------------------------------------------------------------------------------
// The configurable question limits

#[test]
fn question_limits_are_settings_with_ceilings() {
    let defaults = InspectorConfig::default();
    assert_eq!(defaults.max_questions, 32);
    assert_eq!(defaults.max_questions_per_round, 1024);
    assert_eq!(InspectorConfig::QUESTIONS_CEILING, 256);
    assert_eq!(InspectorConfig::QUESTIONS_PER_ROUND_CEILING, 8192);
    assert_eq!(InspectorConfig::QUESTIONS_IN_FLIGHT, 128);
    let server = NameServer::new(None, "127.0.0.1:53".parse().unwrap());
    let with = |questions: usize, per_round: usize| {
        let mut c = InspectorConfig::default();
        c.discovery = NsDiscovery::Static(vec![server.clone()]);
        c.max_questions = questions;
        c.max_questions_per_round = per_round;
        Inspector::new(c)
    };
    for (questions, per_round) in [(0, 1024), (257, 8192), (32, 8193), (100, 99), (32, 0)] {
        let result = with(questions, per_round);
        assert!(
            matches!(&result, Err(InspectorError::Config { .. })),
            "{questions} {per_round} {result:?}"
        );
    }
    let Err(InspectorError::Config { detail }) = with(257, 8192) else {
        panic!("expected a configuration error");
    };
    assert!(detail.contains("256"), "{detail}");
    for (questions, per_round) in [(1, 1), (100, 1024), (256, 8192), (32, 32)] {
        assert!(
            with(questions, per_round).is_ok(),
            "{questions} {per_round}"
        );
    }
}

#[tokio::test]
async fn a_hundred_names_of_one_zone_in_one_call() {
    let mock = authoritative().await;
    let names: Vec<String> = (0..101).map(|i| format!("h{i}.{ZONE}")).collect();
    for name in &names {
        mock.add(name, TYPE_A, 60, Data::a([192, 0, 2, 7]));
    }
    let mut config = static_config(&[mock.addr()], Duration::from_secs(2));
    config.max_questions = 100;
    let inspector = Inspector::new(config).unwrap();
    let expectations: Vec<Expectation> = names
        .iter()
        .map(|name| {
            Expectation::new(
                question(name, RecordType::A),
                Condition::Present(vec![parse(RecordType::A, "192.0.2.7")]),
            )
        })
        .collect();

    // 101: refused, nothing sent, the limit named.
    let err = inspector
        .wait(&name(ZONE), &expectations, &quick())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, InspectorError::InvalidInput { detail } if detail.contains("100")),
        "{err:?}"
    );
    let questions: Vec<Question> = expectations.iter().map(|e| e.question.clone()).collect();
    assert!(matches!(
        inspector.observe(&name(ZONE), &questions).await,
        Err(InspectorError::InvalidInput { .. })
    ));
    assert!(mock.log().is_empty());

    // 100: accepted, every name asked once.
    let report = inspector
        .wait(&name(ZONE), &expectations[..100], &quick())
        .await
        .unwrap();
    assert!(report.servers[0].satisfied);
    assert_eq!(report.servers[0].answers.len(), 100);
    assert_eq!(mock.log().len(), 100);
    for name in &names[..100] {
        assert_eq!(mock.count(name, TYPE_A), 1, "{name}");
    }

    // The default limit is unchanged: 33 refused.
    let default = static_inspector(&[mock.addr()]);
    mock.clear_log();
    assert!(matches!(
        default.observe(&name(ZONE), &questions[..33]).await,
        Err(InspectorError::InvalidInput { .. })
    ));
    assert!(default.observe(&name(ZONE), &questions[..32]).await.is_ok());
    assert_eq!(mock.log().len(), 32);
}

#[tokio::test]
async fn the_round_limit_is_enforced_before_anything_is_sent() {
    let mocks = [authoritative().await, authoritative().await];
    let servers: Vec<SocketAddr> = mocks.iter().map(DnsMock::addr).collect();
    let mut config = static_config(&servers, Duration::from_secs(2));
    config.max_questions = 100;
    config.max_questions_per_round = 150;
    let inspector = Inspector::new(config).unwrap();
    let questions: Vec<Question> = (0..76)
        .map(|i| question(&format!("h{i}.{ZONE}"), RecordType::A))
        .collect();
    let err = inspector
        .observe(&name(ZONE), &questions)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, InspectorError::InvalidInput { detail }
            if detail.contains("152") && detail.contains("150")),
        "{err:?}"
    );
    assert!(mocks.iter().all(|mock| mock.log().is_empty()));
    let observed = inspector
        .observe(&name(ZONE), &questions[..75])
        .await
        .unwrap();
    assert_eq!(observed.len(), 2);
    assert!(mocks.iter().all(|mock| mock.log().len() == 75));
}
