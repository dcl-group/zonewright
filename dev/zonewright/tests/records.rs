// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The record model: record types, TTLs, record data, typed records and rrsets.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use zonewright::name::{DomainName, NameError, TargetName};
use zonewright::record::{
    Caa, Mx, RecordData, RecordError, RecordType, RrSet, RrsetTtl, Srv, SvcParam, Svcb, Tlsa, Ttl,
    Txt,
};

fn dn(s: &str) -> DomainName {
    DomainName::parse(s).unwrap()
}

fn tn(s: &str) -> TargetName {
    TargetName::parse(s).unwrap()
}

fn parse(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap_or_else(|err| panic!("{rtype} {text:?}: {err}"))
}

fn canonical(rtype: RecordType, text: &str) -> String {
    parse(rtype, text).as_str().to_owned()
}

fn is_syntax<T>(result: Result<T, RecordError>) -> bool {
    matches!(result, Err(RecordError::Syntax { .. }))
}

// ---- RecordType -----------------------------------------------------------------------------

/// The IANA "Resource Record (RR) TYPEs" registry, last updated 2026-11-09; 255 is printed `ANY`.
#[rustfmt::skip]
const IANA: &[(u16, &str)] = &[
    (1, "A"), (2, "NS"), (3, "MD"), (4, "MF"), (5, "CNAME"), (6, "SOA"), (7, "MB"), (8, "MG"),
    (9, "MR"), (10, "NULL"), (11, "WKS"), (12, "PTR"), (13, "HINFO"), (14, "MINFO"), (15, "MX"),
    (16, "TXT"), (17, "RP"), (18, "AFSDB"), (19, "X25"), (20, "ISDN"), (21, "RT"), (22, "NSAP"),
    (23, "NSAP-PTR"), (24, "SIG"), (25, "KEY"), (26, "PX"), (27, "GPOS"), (28, "AAAA"),
    (29, "LOC"), (30, "NXT"), (31, "EID"), (32, "NIMLOC"), (33, "SRV"), (34, "ATMA"),
    (35, "NAPTR"), (36, "KX"), (37, "CERT"), (38, "A6"), (39, "DNAME"), (40, "SINK"), (41, "OPT"),
    (42, "APL"), (43, "DS"), (44, "SSHFP"), (45, "IPSECKEY"), (46, "RRSIG"), (47, "NSEC"),
    (48, "DNSKEY"), (49, "DHCID"), (50, "NSEC3"), (51, "NSEC3PARAM"), (52, "TLSA"), (53, "SMIMEA"),
    (54, "DELEGPARAM"), (55, "HIP"), (56, "NINFO"), (57, "RKEY"), (58, "TALINK"), (59, "CDS"),
    (60, "CDNSKEY"), (61, "OPENPGPKEY"), (62, "CSYNC"), (63, "ZONEMD"), (64, "SVCB"),
    (65, "HTTPS"), (66, "DSYNC"), (67, "HHIT"), (68, "BRID"), (69, "UNECE"), (70, "ISO"),
    (99, "SPF"), (100, "UINFO"), (101, "UID"), (102, "GID"), (103, "UNSPEC"), (104, "NID"),
    (105, "L32"), (106, "L64"), (107, "LP"), (108, "EUI48"), (109, "EUI64"), (128, "NXNAME"),
    (249, "TKEY"), (250, "TSIG"), (251, "IXFR"), (252, "AXFR"), (253, "MAILB"), (254, "MAILA"),
    (255, "ANY"), (256, "URI"), (257, "CAA"), (258, "AVC"), (259, "DOA"), (260, "AMTRELAY"),
    (261, "RESINFO"), (262, "WALLET"), (263, "CLA"), (264, "IPN"), (32768, "TA"), (32769, "DLV"),
    (61440, "DELEG"),
];

#[test]
fn full_mnemonic_table() {
    for &(code, name) in IANA {
        let rtype = RecordType::from_code(code);
        assert_eq!(rtype.to_string(), name);
        assert_eq!(name.parse::<RecordType>().unwrap(), rtype);
        assert_eq!(
            name.to_ascii_lowercase().parse::<RecordType>().unwrap(),
            rtype
        );
        assert_eq!(format!("type{code}").parse::<RecordType>().unwrap(), rtype);
    }
    for code in 0..=u16::MAX {
        let rtype = RecordType::from_code(code);
        let text = rtype.to_string();
        if !IANA.iter().any(|&(c, _)| c == code) {
            assert_eq!(text, format!("TYPE{code}"));
        }
        assert_eq!(text.parse::<RecordType>().unwrap(), rtype, "{code}");
        assert_eq!(rtype.code(), Some(code));
    }
}

#[test]
fn record_type_parsing() {
    assert_eq!("mx".parse::<RecordType>().unwrap(), RecordType::MX);
    assert_eq!("Https".parse::<RecordType>().unwrap(), RecordType::HTTPS);
    assert_eq!("TYPE1".parse::<RecordType>().unwrap(), RecordType::A);
    assert_eq!("TYPE0001".parse::<RecordType>().unwrap(), RecordType::A);
    assert_eq!(
        "*".parse::<RecordType>().unwrap(),
        RecordType::from_code(255)
    );
    assert_eq!(
        "nsap-ptr".parse::<RecordType>().unwrap(),
        RecordType::from_code(23)
    );
    assert_eq!("alias".parse::<RecordType>().unwrap(), RecordType::ALIAS);
    assert_eq!("ANAME".parse::<RecordType>().unwrap(), RecordType::ANAME);
    for bad in [
        "",
        "MXX",
        "TYPE",
        "TYPE-1",
        "TYPE65536",
        "TYPE1x",
        " A",
        "A ",
        "TXT2",
        "URL",
    ] {
        assert_eq!(
            bad.parse::<RecordType>(),
            Err(RecordError::UnknownType),
            "{bad:?}"
        );
    }
}

#[test]
fn record_type_constants_and_pseudo_types() {
    let expected = [
        (RecordType::A, 1),
        (RecordType::AAAA, 28),
        (RecordType::NS, 2),
        (RecordType::CNAME, 5),
        (RecordType::SOA, 6),
        (RecordType::PTR, 12),
        (RecordType::MX, 15),
        (RecordType::TXT, 16),
        (RecordType::SRV, 33),
        (RecordType::DNAME, 39),
        (RecordType::CAA, 257),
        (RecordType::TLSA, 52),
        (RecordType::SSHFP, 44),
        (RecordType::SVCB, 64),
        (RecordType::HTTPS, 65),
    ];
    for (rtype, code) in expected {
        assert_eq!(rtype.code(), Some(code));
    }
    assert_eq!(RecordType::ALIAS.code(), None);
    assert_eq!(RecordType::ANAME.code(), None);
    assert_eq!(RecordType::ALIAS.to_string(), "ALIAS");
    assert_ne!(RecordType::ALIAS, RecordType::ANAME);
    assert_eq!(format!("{:?}", RecordType::MX), "RecordType(MX)");
}

#[test]
fn record_type_serde() {
    for rtype in [
        RecordType::A,
        RecordType::ALIAS,
        RecordType::from_code(65280),
    ] {
        let json = serde_json::to_string(&rtype).unwrap();
        assert_eq!(serde_json::from_str::<RecordType>(&json).unwrap(), rtype);
    }
    assert_eq!(
        serde_json::to_string(&RecordType::from_code(65280)).unwrap(),
        "\"TYPE65280\""
    );
    assert_eq!(
        serde_json::from_str::<RecordType>("\"txt\"").unwrap(),
        RecordType::TXT
    );
    assert!(serde_json::from_str::<RecordType>("\"NOPE\"").is_err());
}

// ---- Ttl ------------------------------------------------------------------------------------

#[test]
fn ttl_bounds_and_conversions() {
    assert_eq!(Ttl::from_secs(0).unwrap().as_secs(), 0);
    assert_eq!(Ttl::MAX.as_secs(), 2_147_483_647);
    assert_eq!(Ttl::from_secs(2_147_483_647).unwrap(), Ttl::MAX);
    assert_eq!(
        Ttl::from_secs(2_147_483_648),
        Err(RecordError::OutOfRange { field: "ttl" })
    );
    assert_eq!(
        Duration::from(Ttl::from_secs(300).unwrap()),
        Duration::from_secs(300)
    );
    assert_eq!(
        Ttl::try_from(Duration::from_secs(60)).unwrap().as_secs(),
        60
    );
    assert!(Ttl::try_from(Duration::from_millis(1500)).is_err());
    assert!(Ttl::try_from(Duration::from_secs(1 << 31)).is_err());
    assert!(Ttl::try_from(Duration::from_secs(u64::MAX)).is_err());
}

#[test]
fn ttl_serde() {
    let ttl = Ttl::from_secs(300).unwrap();
    assert_eq!(serde_json::to_string(&ttl).unwrap(), "300");
    assert_eq!(serde_json::from_str::<Ttl>("300").unwrap(), ttl);
    assert!(serde_json::from_str::<Ttl>("2147483648").is_err());
    assert!(serde_json::from_str::<Ttl>("-1").is_err());
    assert!(serde_json::from_str::<Ttl>("\"300\"").is_err());
}

#[test]
fn rrset_ttl_serde() {
    let explicit = RrsetTtl::from_secs(300).unwrap();
    assert_eq!(serde_json::to_string(&explicit).unwrap(), "300");
    assert_eq!(
        serde_json::to_string(&RrsetTtl::ProviderDefault).unwrap(),
        "\"provider_default\""
    );
    assert_eq!(serde_json::from_str::<RrsetTtl>("300").unwrap(), explicit);
    assert_eq!(
        serde_json::from_str::<RrsetTtl>("\"provider_default\"").unwrap(),
        RrsetTtl::ProviderDefault
    );
    assert_eq!(
        serde_json::from_str::<RrsetTtl>("2147483647").unwrap(),
        RrsetTtl::Explicit(Ttl::MAX)
    );
    let canary = "canary-7f3a";
    for bad in [
        "2147483648".to_owned(),
        "-1".to_owned(),
        "1.5".to_owned(),
        "\"300\"".to_owned(),
        "\"PROVIDER_DEFAULT\"".to_owned(),
        "null".to_owned(),
        "{}".to_owned(),
        format!("\"{canary}\""),
    ] {
        let e = serde_json::from_str::<RrsetTtl>(&bad).unwrap_err();
        assert!(!e.to_string().contains(canary), "{bad}: {e}");
    }
    assert_eq!(RrsetTtl::from(Ttl::MAX).explicit(), Some(Ttl::MAX));
    assert_eq!(RrsetTtl::ProviderDefault.explicit(), None);
}

// ---- Canonical text per type ----------------------------------------------------------------

#[test]
fn a_records() {
    assert_eq!(canonical(RecordType::A, "192.0.2.1"), "192.0.2.1");
    assert_eq!(canonical(RecordType::A, " \t192.0.2.1  "), "192.0.2.1");
    assert_eq!(canonical(RecordType::A, "0.0.0.0"), "0.0.0.0");
    for bad in [
        "192.0.2.01",
        "192.0.2",
        "192.0.2.1.5",
        "256.0.0.1",
        "192.0.2.1 192.0.2.2",
        "\"192.0.2.1\"",
        "",
        "x",
    ] {
        assert!(is_syntax(RecordData::parse(RecordType::A, bad)), "{bad:?}");
    }
}

#[test]
fn aaaa_records_follow_rfc5952() {
    let cases = [
        ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("2001:0db8::0001", "2001:db8::1"),
        ("2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"),
        ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),
        ("2001:db8::", "2001:db8::"),
        ("::", "::"),
        ("::FFFF:192.0.2.1", "::ffff:192.0.2.1"),
        ("0:0:0:0:0:ffff:c000:0201", "::ffff:192.0.2.1"),
    ];
    for (input, expected) in cases {
        assert_eq!(canonical(RecordType::AAAA, input), expected, "{input}");
    }
    for bad in ["2001:db8::1::1", "192.0.2.1", "2001:db8::g", "fe80::1%eth0"] {
        assert!(is_syntax(RecordData::parse(RecordType::AAAA, bad)), "{bad}");
    }
}

#[test]
fn name_records() {
    for rtype in [
        RecordType::NS,
        RecordType::CNAME,
        RecordType::PTR,
        RecordType::DNAME,
        RecordType::ALIAS,
        RecordType::ANAME,
    ] {
        assert_eq!(canonical(rtype, "Host.Example.org"), "host.example.org.");
        assert_eq!(canonical(rtype, "host.example.org."), "host.example.org.");
        assert!(matches!(
            RecordData::parse(rtype, "@"),
            Err(RecordError::Name(NameError::BadCharacter))
        ));
    }
    assert_eq!(
        canonical(RecordType::CNAME, "a\\.b.example.org."),
        "a\\.b.example.org."
    );
    assert_eq!(
        canonical(RecordType::CNAME, "\\097.example.org"),
        "a.example.org."
    );
    assert_eq!(
        canonical(RecordType::CNAME, "bücher.example.org"),
        "xn--bcher-kva.example.org."
    );
    assert!(matches!(
        RecordData::parse(RecordType::CNAME, "a\\1.example.org"),
        Err(RecordError::Name(NameError::BadEscape))
    ));
    assert!(is_syntax(RecordData::parse(
        RecordType::CNAME,
        "a.example.org b.example.org"
    )));
}

#[test]
fn relative_names() {
    let origin = dn("example.org");
    let rel = |rtype, text| RecordData::parse_relative(rtype, text, &origin).unwrap();
    assert_eq!(rel(RecordType::CNAME, "@").as_str(), "example.org.");
    assert_eq!(rel(RecordType::CNAME, "www").as_str(), "www.example.org.");
    assert_eq!(
        rel(RecordType::CNAME, "www.example.net.").as_str(),
        "www.example.net."
    );
    assert_eq!(
        rel(RecordType::MX, "10 mail").as_str(),
        "10 mail.example.org."
    );
    assert_eq!(rel(RecordType::MX, "10 @").as_str(), "10 example.org.");
    assert_eq!(
        rel(RecordType::SRV, "0 5 443 host").as_str(),
        "0 5 443 host.example.org."
    );
    assert_eq!(
        rel(RecordType::SVCB, "1 svc alpn=h2").as_str(),
        "1 svc.example.org. alpn=\"h2\""
    );
    assert_eq!(
        rel(RecordType::SVCB, "1 . alpn=h2").as_str(),
        "1 . alpn=\"h2\""
    );
    assert_eq!(
        rel(RecordType::SOA, "ns1 admin 1 2 3 4 5").as_str(),
        "ns1.example.org. admin.example.org. 1 2 3 4 5"
    );
    // Relative and absolute spellings of the same name are the same data.
    assert_eq!(
        rel(RecordType::CNAME, "www"),
        parse(RecordType::CNAME, "www.example.org")
    );
}

#[test]
fn mx_records() {
    assert_eq!(
        canonical(RecordType::MX, "10 mail.example.org"),
        "10 mail.example.org."
    );
    assert_eq!(
        canonical(RecordType::MX, "010\tMAIL.example.org."),
        "10 mail.example.org."
    );
    assert_eq!(canonical(RecordType::MX, "0 ."), "0 .");
    assert_eq!(
        RecordData::parse(RecordType::MX, "65536 mail.example.org"),
        Err(RecordError::OutOfRange {
            field: "preference"
        })
    );
    for bad in [
        "10",
        "-1 mail.example.org",
        "mail.example.org 10",
        "10 a.example.org b.example.org",
    ] {
        assert!(is_syntax(RecordData::parse(RecordType::MX, bad)), "{bad}");
    }
}

#[test]
fn srv_records() {
    assert_eq!(
        canonical(RecordType::SRV, "0 5 443 Host.example.org"),
        "0 5 443 host.example.org."
    );
    assert_eq!(canonical(RecordType::SRV, "0 0 0 ."), "0 0 0 .");
    assert_eq!(
        RecordData::parse(RecordType::SRV, "0 5 70000 host.example.org"),
        Err(RecordError::OutOfRange { field: "port" })
    );
    assert!(is_syntax(RecordData::parse(
        RecordType::SRV,
        "0 5 host.example.org"
    )));
}

#[test]
fn txt_quoting_and_escapes() {
    let cases = [
        ("\"v=spf1 mx -all\"", "\"v=spf1 mx -all\""),
        ("v=spf1", "\"v=spf1\""),
        ("\"a\" \"b\"", "\"ab\""),
        ("\"a\"\"b\"", "\"ab\""),
        ("  \"a\"\t\"b\"  ", "\"ab\""),
        ("\"\"", "\"\""),
        ("\"say \\\"hi\\\"\"", "\"say \\\"hi\\\"\""),
        ("\"back\\\\slash\"", "\"back\\\\slash\""),
        ("\"\\065\\066C\"", "\"ABC\""),
        ("\"\\x\\;\\(\"", "\"x;(\""),
        ("\"semi;colon (paren)\"", "\"semi;colon (paren)\""),
        ("\"tab\there\"", "\"tab\\009here\""),
        ("\"\\000\\255\"", "\"\\000\\255\""),
        ("\"é\"", "\"\\195\\169\""),
        ("caf\\195\\169", "\"caf\\195\\169\""),
        ("a\\ b", "\"a b\""),
        ("\\# 4 03616263", "\"abc\""),
        ("\\# 8 0361626303646566", "\"abcdef\""),
    ];
    for (input, expected) in cases {
        assert_eq!(canonical(RecordType::TXT, input), expected, "{input}");
    }
}

#[test]
fn txt_rejections() {
    for bad in [
        "v=spf1 mx -all",
        "\"abc",
        "\"a\"b",
        "ab\"c\"",
        "\"a\" ; comment",
        "( \"a\" )",
        "\"a\nb\"",
        "\"a\"\n\"b\"",
        "\"a\\1b\"",
        "\"a\\256\"",
        "\"trailing\\",
        "",
        "   ",
        "\"bell\u{7}\"",
        "key=\"v\"",
    ] {
        assert!(
            is_syntax(RecordData::parse(RecordType::TXT, bad)),
            "{bad:?}"
        );
    }
}

#[test]
fn txt_chunking_and_joining() {
    let long = "a".repeat(300);
    let data = parse(RecordType::TXT, &format!("\"{long}\""));
    assert_eq!(
        data.as_str(),
        format!("\"{}\" \"{}\"", "a".repeat(255), "a".repeat(45))
    );
    // Boundaries in the input are not part of the value.
    let split = parse(
        RecordType::TXT,
        &format!("\"{}\" \"{}\"", "a".repeat(100), "a".repeat(200)),
    );
    assert_eq!(split, data);
    // Exactly 255 octets is one chunk; 510 is two.
    assert_eq!(
        parse(RecordType::TXT, &format!("\"{}\"", "b".repeat(255)))
            .as_str()
            .matches('"')
            .count(),
        2
    );
    assert_eq!(
        parse(RecordType::TXT, &format!("\"{}\"", "b".repeat(510)))
            .as_str()
            .matches('"')
            .count(),
        4
    );
    // A chunk boundary may fall inside a multi-byte character.
    let text = format!("{}é", "x".repeat(254));
    let txt = Txt::new(text.clone()).unwrap();
    let data = txt.to_data().unwrap();
    assert_eq!(
        data.as_str(),
        format!("\"{}\\195\" \"\\169\"", "x".repeat(254))
    );
    assert_eq!(Txt::from_data(&data).unwrap().as_str(), Some(text.as_str()));
}

#[test]
fn txt_size_limits() {
    assert!(Txt::new(vec![b'a'; 65_279]).is_ok());
    assert_eq!(Txt::new(vec![b'a'; 65_280]), Err(RecordError::TooLong));
    let max = format!("\"{}\"", "a".repeat(65_279));
    assert!(RecordData::parse(RecordType::TXT, &max).is_ok());
    let over = format!("\"{}\"", "a".repeat(65_280));
    assert_eq!(
        RecordData::parse(RecordType::TXT, &over),
        Err(RecordError::TooLong)
    );
    let wire = Txt::new(vec![b'a'; 65_279])
        .unwrap()
        .to_data()
        .unwrap()
        .to_wire(RecordType::TXT)
        .unwrap();
    assert_eq!(wire.len(), 65_535);
}

#[test]
fn txt_typed() {
    let acme = Txt::new("gfj9Xq_Zp-h7Mw8yKxZp3Qd4Rr2Ss1Tt0Uu9Vv8Ww7X").unwrap();
    assert!(acme.is_plain());
    assert_eq!(
        acme.to_data().unwrap().as_str(),
        "\"gfj9Xq_Zp-h7Mw8yKxZp3Qd4Rr2Ss1Tt0Uu9Vv8Ww7X\""
    );
    assert!(!Txt::new("v=spf1 mx -all").unwrap().is_plain());
    assert!(!Txt::new("").unwrap().is_plain());
    assert!(!Txt::new("a\"b").unwrap().is_plain());
    assert!(!Txt::new("a\\b").unwrap().is_plain());
    assert!(!Txt::new(vec![b'a'; 256]).unwrap().is_plain());
    assert!(Txt::new(vec![b'a'; 255]).unwrap().is_plain());
    let spf = Txt::new("v=spf1 mx -all").unwrap();
    assert_eq!(
        spf.to_data().unwrap(),
        parse(RecordType::TXT, "\"v=spf1 mx -all\"")
    );
    assert_eq!(Txt::from_data(&spf.to_data().unwrap()).unwrap(), spf);
    let binary = Txt::new(vec![0xff, 0x00]).unwrap();
    assert_eq!(binary.as_str(), None);
    assert_eq!(binary.as_bytes(), &[0xff, 0x00]);
    assert_eq!(binary.to_data().unwrap().as_str(), "\"\\255\\000\"");
    assert_eq!(Txt::new("").unwrap().to_data().unwrap().as_str(), "\"\"");
}

#[test]
fn caa_records() {
    assert_eq!(
        canonical(RecordType::CAA, "0 issue \"ca.example.net\""),
        "0 issue \"ca.example.net\""
    );
    assert_eq!(
        canonical(RecordType::CAA, "0 ISSUE ca.example.net"),
        "0 issue \"ca.example.net\""
    );
    assert_eq!(
        canonical(RecordType::CAA, "128 iodef \"mailto:security@example.org\""),
        "128 iodef \"mailto:security@example.org\""
    );
    assert_eq!(canonical(RecordType::CAA, "0 issue \";\""), "0 issue \";\"");
    assert_eq!(canonical(RecordType::CAA, "0 issue \"\""), "0 issue \"\"");
    assert_eq!(
        canonical(RecordType::CAA, "0 issue \"ca.example.net; Account=AbC\""),
        "0 issue \"ca.example.net; Account=AbC\""
    );
    assert_eq!(
        RecordData::parse(RecordType::CAA, "256 issue \"x\""),
        Err(RecordError::OutOfRange { field: "flags" })
    );
    for bad in [
        "0 is-sue \"x\"",
        "0 \"issue\" \"x\"",
        "0 issue",
        "0 issue a b",
        "0 \"\" \"x\"",
    ] {
        assert!(is_syntax(RecordData::parse(RecordType::CAA, bad)), "{bad}");
    }
    let long_tag = format!("0 {} \"x\"", "a".repeat(256));
    assert_eq!(
        RecordData::parse(RecordType::CAA, &long_tag),
        Err(RecordError::TooLong)
    );
}

#[test]
fn caa_typed() {
    let caa = Caa {
        flags: Caa::CRITICAL,
        tag: "issuewild".to_owned(),
        value: b"ca.example.net".to_vec(),
    };
    assert!(caa.is_critical());
    let data = caa.to_data().unwrap();
    assert_eq!(data.as_str(), "128 issuewild \"ca.example.net\"");
    assert_eq!(Caa::from_data(&data).unwrap(), caa);
    let upper = Caa {
        flags: 0,
        tag: "Issue".to_owned(),
        value: Vec::new(),
    };
    assert!(!upper.is_critical());
    assert!(matches!(upper.to_data(), Err(RecordError::Syntax { .. })));
    let empty = Caa {
        flags: 0,
        tag: String::new(),
        value: Vec::new(),
    };
    assert!(matches!(empty.to_data(), Err(RecordError::Syntax { .. })));
    let quote = Caa {
        flags: 0,
        tag: "issue".to_owned(),
        value: b"a\"b\\c".to_vec(),
    };
    assert_eq!(quote.to_data().unwrap().as_str(), "0 issue \"a\\\"b\\\\c\"");
}

#[test]
fn tlsa_and_sshfp_records() {
    assert_eq!(
        canonical(RecordType::TLSA, "3 1 1 0A1B 2C3D"),
        "3 1 1 0a1b2c3d"
    );
    assert_eq!(
        canonical(RecordType::TLSA, "03 01 01 0a1b2c3d"),
        "3 1 1 0a1b2c3d"
    );
    for bad in ["3 1 1", "3 1 1 0a1", "3 1 1 0g", "3 1 1 \"0a\""] {
        assert!(is_syntax(RecordData::parse(RecordType::TLSA, bad)), "{bad}");
    }
    assert_eq!(
        RecordData::parse(RecordType::TLSA, "300 1 1 0a"),
        Err(RecordError::OutOfRange { field: "usage" })
    );
    assert_eq!(canonical(RecordType::SSHFP, "4 2 0A1B 2C"), "4 2 0a1b2c");
    assert!(is_syntax(RecordData::parse(RecordType::SSHFP, "4 2")));
}

#[test]
fn tlsa_typed() {
    let tlsa = Tlsa {
        usage: 3,
        selector: 1,
        matching_type: 1,
        data: vec![0x0a, 0x1b],
    };
    let data = tlsa.to_data().unwrap();
    assert_eq!(data.as_str(), "3 1 1 0a1b");
    assert_eq!(Tlsa::from_data(&data).unwrap(), tlsa);
    let empty = Tlsa {
        data: Vec::new(),
        ..tlsa
    };
    assert!(matches!(empty.to_data(), Err(RecordError::Syntax { .. })));
}

#[test]
fn mx_and_srv_typed() {
    let mx = Mx {
        preference: 10,
        exchange: tn("Mail.Example.org"),
    };
    let data = mx.to_data().unwrap();
    assert_eq!(data.as_str(), "10 mail.example.org.");
    assert_eq!(Mx::from_data(&data).unwrap(), mx);
    let null = Mx {
        preference: 0,
        exchange: TargetName::root(),
    };
    assert_eq!(null.to_data().unwrap().as_str(), "0 .");

    let srv = Srv {
        priority: 0,
        weight: 5,
        port: 443,
        target: tn("host.example.org"),
    };
    let data = srv.to_data().unwrap();
    assert_eq!(data.as_str(), "0 5 443 host.example.org.");
    assert_eq!(Srv::from_data(&data).unwrap(), srv);
    assert!(matches!(
        Srv::from_data(&parse(RecordType::A, "192.0.2.1")),
        Err(RecordError::Syntax { .. })
    ));
}

#[test]
fn soa_records() {
    assert_eq!(
        canonical(
            RecordType::SOA,
            "NS1.example.org. admin.example.org. 2026111401 2h 1h 2w 5m"
        ),
        "ns1.example.org. admin.example.org. 2026111401 7200 3600 1209600 300"
    );
    assert_eq!(
        canonical(
            RecordType::SOA,
            "ns1.example.org first\\.last.example.org 1 1h30m 1D 1W 30S"
        ),
        "ns1.example.org. first\\.last.example.org. 1 5400 86400 604800 30"
    );
    assert!(is_syntax(RecordData::parse(
        RecordType::SOA,
        "ns1.example.org. admin.example.org. 1h 1 1 1 1"
    )));
    assert!(is_syntax(RecordData::parse(
        RecordType::SOA,
        "ns1.example.org. admin.example.org. 1 1x 1 1 1"
    )));
    assert!(is_syntax(RecordData::parse(
        RecordType::SOA,
        "ns1.example.org. admin.example.org. 1 h 1 1 1"
    )));
    assert!(is_syntax(RecordData::parse(
        RecordType::SOA,
        "ns1.example.org. admin.example.org. 1 2 3 4"
    )));
    assert_eq!(
        RecordData::parse(RecordType::SOA, "a. b. 1 1000000w 1 1 1"),
        Err(RecordError::OutOfRange { field: "refresh" })
    );
}

#[test]
fn svcb_records() {
    let svcb = RecordType::SVCB;
    let cases = [
        (
            "1 . alpn=\"h2,h3\" port=8443",
            "1 . alpn=\"h2,h3\" port=8443",
        ),
        ("1 . port=8443 alpn=h2,h3", "1 . alpn=\"h2,h3\" port=8443"),
        ("0 Svc.Example.org", "0 svc.example.org."),
        ("1 . key3=443", "1 . port=443"),
        ("1 . KEY3=443", "1 . port=443"),
        ("1 . key0003=443", "1 . port=443"),
        (
            "1 . no-default-alpn alpn=h2",
            "1 . alpn=\"h2\" no-default-alpn",
        ),
        (
            "1 . alpn=h2 no-default-alpn=",
            "1 . alpn=\"h2\" no-default-alpn",
        ),
        (
            "16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1",
            "16 foo.example.org. mandatory=alpn,ipv4hint alpn=\"h2,h3-19\" ipv4hint=192.0.2.1",
        ),
        (
            "1 . ipv6hint=2001:DB8::1,2001:db8:0:0:0:0:0:2 ipv4hint=192.0.2.1,192.0.2.2",
            "1 . ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1,2001:db8::2",
        ),
        ("1 . ech=AAEC", "1 . ech=AAEC"),
        ("1 . ech=\"AAEC\"", "1 . ech=AAEC"),
        ("1 . key65000=\"abc\"", "1 . key65000=\"abc\""),
        ("1 . key65000=abc", "1 . key65000=\"abc\""),
        ("1 . key65000", "1 . key65000=\"\""),
        ("1 . key65000=\"a b\\\"c\"", "1 . key65000=\"a b\\\"c\""),
        ("1 . key7=\\000", "1 . key7=\"\\000\""),
        // RFC 9460 appendix A.1: identifiers "f\oo,bar" and "h2".
        (
            r#"16 foo.example.org. alpn="f\\\\oo\\,bar,h2""#,
            r#"16 foo.example.org. alpn="f\\\\oo\\,bar,h2""#,
        ),
        (
            r#"16 foo.example.org. alpn=f\\\092oo\092,bar,h2"#,
            r#"16 foo.example.org. alpn="f\\\\oo\\,bar,h2""#,
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(canonical(svcb, input), expected, "{input}");
        assert_eq!(canonical(RecordType::HTTPS, input), expected, "{input}");
    }
    let parsed = Svcb::from_data(&parse(
        svcb,
        r#"16 foo.example.org. alpn="f\\\\oo\\,bar,h2""#,
    ))
    .unwrap();
    assert_eq!(
        parsed.params,
        [SvcParam::Alpn(vec![b"f\\oo,bar".to_vec(), b"h2".to_vec()])]
    );

    for bad in [
        "1 . alpn=h2 key1=h3",
        "1 . port=1 port=2",
        "1 . key65535=x",
        "1 . unknown=1",
        "1 . no-default-alpn=x",
        "1 . port=",
        "1 . port=x",
        "1 . alpn=",
        "1 . alpn=h2,,h3",
        "1 . mandatory=mandatory",
        "1 . mandatory=port,port",
        "1 . ipv4hint=192.0.2.300",
        "1 . ipv6hint=192.0.2.1",
        "1 . ech=***",
        "1 . ech=",
        "1 . \"alpn=h2\"",
        "1",
    ] {
        assert!(
            matches!(
                RecordData::parse(svcb, bad),
                Err(RecordError::Syntax { .. }) | Err(RecordError::OutOfRange { .. })
            ),
            "{bad}"
        );
    }
    assert_eq!(
        RecordData::parse(svcb, "1 . port=70000"),
        Err(RecordError::OutOfRange { field: "port" })
    );
}

/// RFC 9460 section 2.4.3: a ServiceMode record must be self-consistent. `mandatory` lists only
/// keys present in the record (section 8), and `no-default-alpn` needs `alpn` (section 7.1.1).
/// AliasMode (priority 0) keeps its parameters as given (section 2.4.2). Text, typed
/// construction and wire form refuse the same values.
#[test]
fn svcb_self_consistency() {
    let accepted = [
        (
            "0 svc.example.org. no-default-alpn",
            "0 svc.example.org. no-default-alpn",
        ),
        (
            "0 svc.example.org. mandatory=port",
            "0 svc.example.org. mandatory=port",
        ),
        (
            "1 . mandatory=port,key65000 port=443 key65000=x",
            "1 . mandatory=port,key65000 port=443 key65000=\"x\"",
        ),
        (
            "1 . mandatory=alpn alpn=h2 no-default-alpn",
            "1 . mandatory=alpn alpn=\"h2\" no-default-alpn",
        ),
    ];
    for (input, expected) in accepted {
        assert_eq!(canonical(RecordType::SVCB, input), expected, "{input}");
        assert_eq!(canonical(RecordType::HTTPS, input), expected, "{input}");
    }

    for bad in [
        "1 . no-default-alpn",
        "1 . no-default-alpn port=443",
        "1 . mandatory=port",
        "1 . mandatory=alpn,port port=443",
        "1 . mandatory=key65000 alpn=h2",
        "1 . mandatory=no-default-alpn alpn=h2",
        "2 svc.example.org. mandatory=ipv4hint ipv6hint=2001:db8::1",
    ] {
        assert!(is_syntax(RecordData::parse(RecordType::SVCB, bad)), "{bad}");
        assert!(
            is_syntax(RecordData::parse(RecordType::HTTPS, bad)),
            "{bad}"
        );
    }

    // Typed construction.
    let lone = Svcb {
        priority: 1,
        target: TargetName::root(),
        params: vec![SvcParam::NoDefaultAlpn],
    };
    assert!(is_syntax(lone.to_data()));
    let absent = Svcb {
        params: vec![
            SvcParam::Mandatory(vec![3]),
            SvcParam::Alpn(vec![b"h2".to_vec()]),
        ],
        ..lone.clone()
    };
    assert!(is_syntax(absent.to_data()));
    let alias = Svcb {
        priority: 0,
        target: tn("svc.example.org"),
        ..lone.clone()
    };
    assert_eq!(
        alias.to_data().unwrap().as_str(),
        "0 svc.example.org. no-default-alpn"
    );

    // Wire form, the path the inspector reads answers through: priority, root target, then
    // key/length/value.
    let no_default_alpn = b"\x00\x01\x00\x00\x02\x00\x00";
    let mandatory_port = b"\x00\x01\x00\x00\x00\x00\x02\x00\x03";
    for wire in [&no_default_alpn[..], &mandatory_port[..]] {
        assert!(is_syntax(RecordData::from_wire(RecordType::SVCB, wire)));
        assert!(is_syntax(RecordData::from_wire(RecordType::HTTPS, wire)));
    }
    let alias_wire = b"\x00\x00\x00\x00\x02\x00\x00";
    assert_eq!(
        RecordData::from_wire(RecordType::HTTPS, alias_wire)
            .unwrap()
            .as_str(),
        "0 . no-default-alpn"
    );

    // A stored set that holds such a value as canonical text no longer deserializes; as a raw
    // member it still does.
    assert!(
        serde_json::from_str::<RrSet>(
            r#"{"name":"example.org.","type":"HTTPS","records":["1 . no-default-alpn"]}"#
        )
        .is_err()
    );
    let raw: RrSet = serde_json::from_str(
        r#"{"name":"example.org.","type":"HTTPS","records":[{"raw":"1 . no-default-alpn"}]}"#,
    )
    .unwrap();
    assert!(!raw.records()[0].is_canonical());
}

#[test]
fn svcb_typed() {
    let svcb = Svcb {
        priority: 1,
        target: TargetName::root(),
        params: vec![
            SvcParam::Port(8443),
            SvcParam::Ipv6Hint(vec!["2001:db8::1".parse::<Ipv6Addr>().unwrap()]),
            SvcParam::Alpn(vec![b"h2".to_vec(), b"h3".to_vec()]),
            SvcParam::Mandatory(vec![3, 1]),
            SvcParam::Ipv4Hint(vec![Ipv4Addr::new(192, 0, 2, 1)]),
            SvcParam::Other {
                key: 65000,
                value: b"x".to_vec(),
            },
            SvcParam::NoDefaultAlpn,
            SvcParam::Ech(vec![0, 1, 2]),
        ],
    };
    let data = svcb.to_data().unwrap();
    assert_eq!(
        data.as_str(),
        "1 . mandatory=alpn,port alpn=\"h2,h3\" no-default-alpn port=8443 ipv4hint=192.0.2.1 \
         ech=AAEC ipv6hint=2001:db8::1 key65000=\"x\""
    );
    assert_eq!(data, parse(RecordType::HTTPS, data.as_str()));
    let back = Svcb::from_data(&data).unwrap();
    assert_eq!(back.params[0], SvcParam::Mandatory(vec![1, 3]));
    assert_eq!(back.params.len(), 8);
    assert_eq!(back.to_data().unwrap(), data);

    // A defined key given as `Other` is written by name.
    let other = Svcb {
        priority: 1,
        target: tn("svc.example.org"),
        params: vec![SvcParam::Other {
            key: 3,
            value: vec![0x01, 0xbb],
        }],
    };
    assert_eq!(
        other.to_data().unwrap().as_str(),
        "1 svc.example.org. port=443"
    );
    let bad_other = Svcb {
        params: vec![SvcParam::Other {
            key: 3,
            value: vec![1],
        }],
        ..other.clone()
    };
    assert!(bad_other.to_data().is_err());

    let duplicate = Svcb {
        params: vec![SvcParam::Port(1), SvcParam::Port(2)],
        ..other.clone()
    };
    assert!(matches!(
        duplicate.to_data(),
        Err(RecordError::Syntax { .. })
    ));
    let duplicate_other = Svcb {
        params: vec![
            SvcParam::Port(1),
            SvcParam::Other {
                key: 3,
                value: vec![0, 2],
            },
        ],
        ..other.clone()
    };
    assert!(duplicate_other.to_data().is_err());
    let alpn_with_comma = Svcb {
        params: vec![SvcParam::Alpn(vec![b"a,b".to_vec(), b"c\\d".to_vec()])],
        ..other.clone()
    };
    let data = alpn_with_comma.to_data().unwrap();
    assert_eq!(data.as_str(), r#"1 svc.example.org. alpn="a\\,b,c\\\\d""#);
    assert_eq!(Svcb::from_data(&data).unwrap(), alpn_with_comma);
    let empty_alpn = Svcb {
        params: vec![SvcParam::Alpn(vec![])],
        ..other.clone()
    };
    assert!(empty_alpn.to_data().is_err());
    let long_alpn = Svcb {
        params: vec![SvcParam::Alpn(vec![vec![b'a'; 256]])],
        ..other
    };
    assert_eq!(long_alpn.to_data(), Err(RecordError::TooLong));
}

#[test]
fn generic_form() {
    let private = RecordType::from_code(65280);
    assert_eq!(canonical(private, "\\# 4 0A000001"), "\\# 4 0a000001");
    assert_eq!(canonical(private, "\\# 4 0a 00 00 01"), "\\# 4 0a000001");
    assert_eq!(canonical(private, "\\# 0"), "\\# 0");
    assert_eq!(canonical(private, "  \\#   0  "), "\\# 0");
    assert_eq!(canonical(RecordType::from_code(41), "\\# 0"), "\\# 0");
    assert!(is_syntax(RecordData::parse(private, "\\# 3 0a000001")));
    assert!(is_syntax(RecordData::parse(private, "\\# 4")));
    assert!(is_syntax(RecordData::parse(private, "\\#")));
    assert!(is_syntax(RecordData::parse(private, "10.0.0.1")));
    assert!(is_syntax(RecordData::parse(private, "\"\\#\" 0")));
    assert_eq!(
        RecordData::parse(private, "\\# 65536 00"),
        Err(RecordError::OutOfRange { field: "length" })
    );

    // A type with its own form converts the generic form.
    assert_eq!(
        parse(RecordType::A, "\\# 4 c0000201"),
        parse(RecordType::A, "192.0.2.1")
    );
    assert_eq!(
        parse(RecordType::MX, "\\# 8 000a046d61696c00"),
        parse(RecordType::MX, "10 mail.")
    );
    assert!(is_syntax(RecordData::parse(RecordType::A, "\\# 3 c00002")));
    assert!(is_syntax(RecordData::parse(RecordType::ALIAS, "\\# 1 00")));
    // TYPE1 is A.
    assert_eq!(
        parse("TYPE1".parse().unwrap(), "192.0.2.1"),
        parse(RecordType::A, "192.0.2.1")
    );
}

#[test]
fn general_text_rules() {
    for bad in [
        "10 mail.example.org ; comment",
        "( 10 mail.example.org )",
        "10\nmail.example.org",
        "10 mail.example.org\r",
    ] {
        assert!(is_syntax(RecordData::parse(RecordType::MX, bad)), "{bad:?}");
    }
    assert!(is_syntax(RecordData::parse(
        RecordType::MX,
        "\"10\" mail.example.org"
    )));
}

#[test]
fn errors_do_not_quote_input() {
    let inputs = [
        (RecordType::A, "s3cr3t-value"),
        (RecordType::MX, "s3cr3t-value mail."),
        (RecordType::TXT, "\"s3cr3t-value"),
        (RecordType::CAA, "0 s3cr3t-value! \"x\""),
        (RecordType::SVCB, "1 . s3cr3t-value=1"),
    ];
    for (rtype, text) in inputs {
        let err = RecordData::parse(rtype, text).unwrap_err();
        assert!(!err.to_string().contains("s3cr3t"), "{err}");
        assert!(!format!("{err:?}").contains("s3cr3t"), "{err:?}");
    }
}

// ---- Wire conversion ------------------------------------------------------------------------

#[test]
fn wire_round_trips() {
    let cases: &[(RecordType, &str, &[u8])] = &[
        (RecordType::A, "192.0.2.1", &[192, 0, 2, 1]),
        (
            RecordType::AAAA,
            "2001:db8::1",
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
        (RecordType::CNAME, "a.example.", b"\x01a\x07example\x00"),
        (RecordType::NS, "a\\.b.example.", b"\x03a.b\x07example\x00"),
        (RecordType::MX, "10 mail.example.", b"\x00\x0a\x04mail\x07example\x00"),
        (RecordType::MX, "0 .", b"\x00\x00\x00"),
        (RecordType::SRV, "0 5 443 h.example.", b"\x00\x00\x00\x05\x01\xbb\x01h\x07example\x00"),
        (RecordType::TXT, "\"abc\"", b"\x03abc"),
        (RecordType::TXT, "\"\"", b"\x00"),
        (RecordType::CAA, "0 issue \"ca.example.net\"", b"\x00\x05issueca.example.net"),
        (RecordType::TLSA, "3 1 1 0a1b", b"\x03\x01\x01\x0a\x1b"),
        (RecordType::SSHFP, "4 2 0a1b", b"\x04\x02\x0a\x1b"),
        (
            RecordType::SVCB,
            "1 foo.example.org. port=53",
            b"\x00\x01\x03foo\x07example\x03org\x00\x00\x03\x00\x02\x00\x35",
        ),
        (
            RecordType::HTTPS,
            "1 . alpn=\"h2,h3\" no-default-alpn",
            b"\x00\x01\x00\x00\x01\x00\x06\x02h2\x02h3\x00\x02\x00\x00",
        ),
        (
            RecordType::SOA,
            "a. b. 1 2 3 4 5",
            b"\x01a\x00\x01b\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05",
        ),
        (RecordType::from_code(65280), "\\# 3 010203", &[1, 2, 3]),
        (RecordType::from_code(65280), "\\# 0", &[]),
    ];
    for &(rtype, text, wire) in cases {
        let data = parse(rtype, text);
        assert_eq!(data.as_str(), text, "{rtype}");
        assert_eq!(data.to_wire(rtype).unwrap(), wire, "{rtype} {text}");
        assert_eq!(
            RecordData::from_wire(rtype, wire).unwrap(),
            data,
            "{rtype} {text}"
        );
    }
}

#[test]
fn wire_txt_strings_are_joined_and_rechunked() {
    let wire = b"\x02ab\x00\x01c";
    assert_eq!(
        RecordData::from_wire(RecordType::TXT, wire)
            .unwrap()
            .as_str(),
        "\"abc\""
    );
    let data = parse(RecordType::TXT, &format!("\"{}\"", "a".repeat(300)));
    let wire = data.to_wire(RecordType::TXT).unwrap();
    assert_eq!(wire.len(), 302);
    assert_eq!(wire[0], 255);
    assert_eq!(wire[256], 45);
    assert!(RecordData::from_wire(RecordType::TXT, b"").is_err());
    assert!(RecordData::from_wire(RecordType::TXT, b"\x05ab").is_err());
}

#[test]
fn wire_rejections() {
    // Compression pointer inside MX.
    assert!(is_syntax(RecordData::from_wire(
        RecordType::MX,
        b"\x00\x0a\x04mail\xc0\x0c"
    )));
    assert!(is_syntax(RecordData::from_wire(
        RecordType::A,
        &[192, 0, 2]
    )));
    assert!(is_syntax(RecordData::from_wire(
        RecordType::A,
        &[192, 0, 2, 1, 0]
    )));
    assert!(is_syntax(RecordData::from_wire(RecordType::AAAA, &[0; 4])));
    assert!(is_syntax(RecordData::from_wire(
        RecordType::CAA,
        b"\x00\x00"
    )));
    assert!(is_syntax(RecordData::from_wire(
        RecordType::CAA,
        b"\x00\x02a-x"
    )));
    assert!(is_syntax(RecordData::from_wire(
        RecordType::TLSA,
        b"\x03\x01\x01"
    )));
    assert!(is_syntax(RecordData::from_wire(
        RecordType::SSHFP,
        b"\x04\x02"
    )));
    // SVCB keys out of order, and a bad port length.
    assert!(is_syntax(RecordData::from_wire(
        RecordType::SVCB,
        b"\x00\x01\x00\x00\x03\x00\x02\x00\x35\x00\x01\x00\x03\x02h2"
    )));
    assert!(is_syntax(RecordData::from_wire(
        RecordType::SVCB,
        b"\x00\x01\x00\x00\x03\x00\x01\x00"
    )));
    assert!(is_syntax(RecordData::from_wire(
        RecordType::SVCB,
        b"\x00\x01\x00\xff\xff\x00\x00"
    )));
    // Pseudo-types have no wire form.
    assert!(is_syntax(RecordData::from_wire(RecordType::ALIAS, b"\x00")));
    let alias = parse(RecordType::ALIAS, "target.example.org");
    assert!(is_syntax(alias.to_wire(RecordType::ALIAS)));
    // Data of another type.
    assert!(is_syntax(
        parse(RecordType::A, "192.0.2.1").to_wire(RecordType::MX)
    ));
    assert_eq!(
        RecordData::from_wire(RecordType::from_code(65280), &vec![0; 65_536]),
        Err(RecordError::TooLong)
    );
}

#[test]
fn wire_case_and_unusual_names() {
    let upper = RecordData::from_wire(RecordType::CNAME, b"\x04HOST\x07Example\x00").unwrap();
    assert_eq!(upper, parse(RecordType::CNAME, "host.example."));
    let odd = RecordData::from_wire(RecordType::CNAME, b"\x03a b\x02@;\x00").unwrap();
    assert_eq!(odd.as_str(), "a\\032b.\\064\\059.");
    assert_eq!(parse(RecordType::CNAME, odd.as_str()), odd);
    assert_eq!(
        odd.to_wire(RecordType::CNAME).unwrap(),
        b"\x03a b\x02@;\x00"
    );
}

#[test]
fn wire_svcb_other_key_with_defined_number_is_decoded() {
    let data = RecordData::from_wire(
        RecordType::HTTPS,
        b"\x00\x01\x00\x00\x05\x00\x03\x00\x01\x02",
    )
    .unwrap();
    assert_eq!(data.as_str(), "1 . ech=AAEC");
}

// ---- Normalization properties ---------------------------------------------------------------

#[test]
fn canonical_text_is_idempotent() {
    let samples: &[(RecordType, &str)] = &[
        (RecordType::A, " 192.0.2.1 "),
        (RecordType::AAAA, "2001:0DB8:0000::0001"),
        (RecordType::CNAME, "Host.Example.org"),
        (RecordType::CNAME, "a\\.b\\032c\\255.example."),
        (RecordType::MX, "0010 mail.example.org"),
        (RecordType::SRV, "0 0 0 ."),
        (RecordType::TXT, "\"a\" \"b\\\"c\\\\\" \"\\200\""),
        (RecordType::TXT, "plain"),
        (RecordType::CAA, "0 ISSUE ca.example.net"),
        (RecordType::TLSA, "3 1 1 AB CD"),
        (RecordType::SSHFP, "1 1 ABCD"),
        (
            RecordType::SVCB,
            "1 . port=1 alpn=h2,h3 mandatory=port key9=\"\\000\"",
        ),
        (
            RecordType::SOA,
            "ns1.example.org. admin.example.org. 1 1h 1h 1w 1h",
        ),
        (RecordType::from_code(65280), "\\# 2 ABCD"),
    ];
    for &(rtype, input) in samples {
        let once = parse(rtype, input);
        let twice = parse(rtype, once.as_str());
        assert_eq!(once, twice, "{rtype} {input}");
        // The wire form agrees with the text form.
        let wire = once.to_wire(rtype).unwrap();
        assert_eq!(
            RecordData::from_wire(rtype, &wire).unwrap(),
            once,
            "{rtype} {input}"
        );
        // Canonical text has no leading, trailing or doubled spaces.
        let text = once.as_str();
        assert_eq!(text.trim(), text);
        assert!(!text.contains("  ") || rtype == RecordType::TXT, "{text}");
    }
}

#[test]
fn presentation_variants_compare_equal() {
    let groups: &[(RecordType, &[&str])] = &[
        (
            RecordType::A,
            &[
                "192.0.2.1",
                " 192.0.2.1",
                "\\# 4 C0000201",
                "\\# 4 c0 00 02 01",
            ],
        ),
        (
            RecordType::AAAA,
            &["2001:db8::1", "2001:DB8:0:0:0:0:0:1", "2001:0db8::0:1"],
        ),
        (
            RecordType::CNAME,
            &[
                "host.example.org.",
                "HOST.example.org",
                "\\104ost.example.org",
            ],
        ),
        (
            RecordType::MX,
            &[
                "10 mail.example.org.",
                "010 Mail.Example.Org",
                "10\tmail.example.org",
            ],
        ),
        (
            RecordType::TXT,
            &[
                "\"hello world\"",
                "\"hello\" \" world\"",
                "\"hello\"\" world\"",
                "hello\\032world",
                "\"hello\\ world\"",
            ],
        ),
        (
            RecordType::CAA,
            &[
                "0 issue \"ca.example.net\"",
                "0 Issue ca.example.net",
                "00 ISSUE \"ca.example.net\"",
            ],
        ),
        (
            RecordType::TLSA,
            &["3 1 1 0a1b", "3 1 1 0A1B", "3 1 1 0a 1b"],
        ),
        (
            RecordType::HTTPS,
            &[
                "1 . alpn=h2 port=443",
                "1 . port=443 alpn=\"h2\"",
                "1 . key3=443 key1=h2",
            ],
        ),
        (
            RecordType::SOA,
            &["a. b. 1 3600 60 604800 300", "A b 1 1h 1m 1w 5m"],
        ),
    ];
    for &(rtype, variants) in groups {
        let first = parse(rtype, variants[0]);
        for variant in variants.iter().skip(1) {
            assert_eq!(parse(rtype, variant), first, "{rtype} {variant:?}");
        }
    }
}

// ---- RecordData and RrSet -------------------------------------------------------------------

fn set_json(json: &str) -> RrSet {
    serde_json::from_str(json).unwrap()
}

#[test]
fn record_data_display_debug_serde() {
    let data = parse(RecordType::MX, "10 mail.example.org");
    assert!(data.is_canonical());
    assert_eq!(data.to_string(), "10 mail.example.org.");
    assert_eq!(format!("{data:?}"), "RecordData(\"10 mail.example.org.\")");
    assert_eq!(
        serde_json::to_string(&data).unwrap(),
        "\"10 mail.example.org.\""
    );
}

#[test]
fn rrset_new_sorts_and_dedups() {
    let set = RrSet::new(
        dn("example.org"),
        RecordType::A,
        Some(RrsetTtl::from_secs(300).unwrap()),
        [
            parse(RecordType::A, "192.0.2.2"),
            parse(RecordType::A, "192.0.2.1"),
            parse(RecordType::A, "192.0.2.2"),
        ],
    )
    .unwrap();
    assert_eq!(
        set.records(),
        [
            parse(RecordType::A, "192.0.2.1"),
            parse(RecordType::A, "192.0.2.2")
        ]
    );
    assert_eq!(set.name(), &dn("example.org"));
    assert_eq!(set.rtype(), RecordType::A);
    assert_eq!(set.ttl(), Some(RrsetTtl::from_secs(300).unwrap()));
    assert!(set.contains(&parse(RecordType::A, "192.0.2.1")));
    assert!(!set.contains(&parse(RecordType::A, "192.0.2.3")));

    let reordered = RrSet::new(
        dn("example.org"),
        RecordType::A,
        None,
        [
            parse(RecordType::A, "192.0.2.1"),
            parse(RecordType::A, "192.0.2.2"),
        ],
    )
    .unwrap();
    assert_ne!(set, reordered);
    assert!(set.same_records(&reordered));
    assert_eq!(reordered.clone().with_ttl(set.ttl()), set);
    let other_name = RrSet::new(
        dn("www.example.org"),
        RecordType::A,
        None,
        set.records().to_vec(),
    )
    .unwrap();
    assert!(!other_name.same_records(&reordered));
}

#[test]
fn rrset_new_validation() {
    assert_eq!(
        RrSet::new(
            dn("example.org"),
            RecordType::A,
            None,
            Vec::<RecordData>::new()
        ),
        Err(RecordError::EmptySet)
    );
    // A member of another type.
    assert!(matches!(
        RrSet::new(
            dn("example.org"),
            RecordType::A,
            None,
            [parse(RecordType::MX, "10 mail.example.org")]
        ),
        Err(RecordError::Syntax { .. })
    ));
    // Canonical for TXT only: a TXT string is not valid CAA text with the same spelling.
    assert!(matches!(
        RrSet::new(
            dn("example.org"),
            RecordType::CAA,
            None,
            [parse(RecordType::TXT, "plain")]
        ),
        Err(RecordError::Syntax { .. })
    ));
    // Parses for the type but is not its canonical text: generic form for A.
    assert!(matches!(
        RrSet::new(
            dn("example.org"),
            RecordType::A,
            None,
            [parse(RecordType::from_code(65280), "\\# 4 c0000201")]
        ),
        Err(RecordError::Syntax { .. })
    ));
    let cname = |t| parse(RecordType::CNAME, t);
    assert_eq!(
        RrSet::new(
            dn("www.example.org"),
            RecordType::CNAME,
            None,
            [cname("a.example.org"), cname("b.example.org")]
        ),
        Err(RecordError::NotSingleton)
    );
    assert!(
        RrSet::new(
            dn("www.example.org"),
            RecordType::CNAME,
            None,
            [cname("a.example.org"), cname("a.example.org")]
        )
        .is_ok()
    );
    let alias = parse(RecordType::ALIAS, "a.example.org");
    let alias2 = parse(RecordType::ALIAS, "b.example.org");
    assert_eq!(
        RrSet::new(dn("example.org"), RecordType::ALIAS, None, [alias, alias2]),
        Err(RecordError::NotSingleton)
    );
    // The same text is valid for SVCB and HTTPS.
    let svcb = parse(RecordType::SVCB, "1 . alpn=h2");
    assert!(RrSet::new(dn("example.org"), RecordType::HTTPS, None, [svcb]).is_ok());
}

#[test]
fn rrset_serde_round_trip() {
    let set = RrSet::new(
        dn("example.org"),
        RecordType::TXT,
        Some(RrsetTtl::from_secs(60).unwrap()),
        [
            parse(RecordType::TXT, "\"b\""),
            parse(RecordType::TXT, "\"a\""),
        ],
    )
    .unwrap();
    let json = serde_json::to_string(&set).unwrap();
    assert_eq!(
        json,
        r#"{"name":"example.org.","type":"TXT","ttl":60,"records":["\"a\"","\"b\""]}"#
    );
    assert_eq!(set_json(&json), set);

    let no_ttl = set.clone().with_ttl(None);
    let json = serde_json::to_string(&no_ttl).unwrap();
    assert!(json.contains("\"ttl\":null"));
    assert_eq!(set_json(&json), no_ttl);
    assert_eq!(
        set_json(r#"{"name":"example.org","type":"txt","records":["\"a\"","b"]}"#),
        no_ttl
    );

    // The provider's default is spelled as in the settings, and differs from no TTL stated.
    let default = set.clone().with_ttl(Some(RrsetTtl::ProviderDefault));
    let json = serde_json::to_string(&default).unwrap();
    assert_eq!(
        json,
        r#"{"name":"example.org.","type":"TXT","ttl":"provider_default","records":["\"a\"","\"b\""]}"#
    );
    assert_eq!(set_json(&json), default);
    assert_ne!(default, no_ttl);
    assert_ne!(default, set);
    assert!(default.same_records(&no_ttl));
}

#[test]
fn rrset_serde_raw_members() {
    // Text that does not parse for the type is kept as non-canonical data.
    let set = set_json(
        r#"{"name":"example.org.","type":"MX","ttl":300,"records":[{"raw":"  odd provider text "},"10 mail.example.org."]}"#,
    );
    assert_eq!(set.records().len(), 2);
    let raw = set.records().iter().find(|r| !r.is_canonical()).unwrap();
    assert_eq!(raw.as_str(), "odd provider text");
    assert_eq!(format!("{raw:?}"), "RecordData(raw \"odd provider text\")");
    assert_eq!(raw.to_wire(RecordType::MX), Err(RecordError::NotCanonical));
    assert_eq!(Mx::from_data(raw), Err(RecordError::NotCanonical));
    assert_eq!(Txt::from_data(raw), Err(RecordError::NotCanonical));
    assert_eq!(Svcb::from_data(raw), Err(RecordError::NotCanonical));
    let json = serde_json::to_string(&set).unwrap();
    assert!(json.contains(r#"{"raw":"odd provider text"}"#), "{json}");
    assert_eq!(set_json(&json), set);

    // Raw text that parses for the type stays raw: it is never parsed on deserialization.
    let kept = set_json(
        r#"{"name":"example.org.","type":"MX","ttl":null,"records":[{"raw":"10 MAIL.example.org"}]}"#,
    );
    assert!(!kept.records()[0].is_canonical());
    assert_eq!(kept.records()[0].as_str(), "10 MAIL.example.org");
    assert_ne!(
        kept.records()[0],
        parse(RecordType::MX, "10 mail.example.org.")
    );
    assert_eq!(set_json(&serde_json::to_string(&kept).unwrap()), kept);

    // The same for a dotless CNAME target, the shape a client keeps non-canonical on purpose.
    let cname = set_json(
        r#"{"name":"www.example.org.","type":"CNAME","ttl":300,"records":[{"raw":"mail.example.org"}]}"#,
    );
    assert!(!cname.records()[0].is_canonical());
    assert_eq!(cname.records()[0].as_str(), "mail.example.org");
    assert_ne!(
        cname.records()[0],
        parse(RecordType::CNAME, "mail.example.org.")
    );
    let json = serde_json::to_string(&cname).unwrap();
    assert!(json.contains(r#"{"raw":"mail.example.org"}"#), "{json}");
    assert_eq!(set_json(&json), cname);

    // A raw value and the canonical value with the same text are distinct.
    let mixed = set_json(
        r#"{"name":"example.org.","type":"A","records":[{"raw":"192.0.2.1 x"},"192.0.2.1"]}"#,
    );
    assert_eq!(mixed.records().len(), 2);
}

#[test]
fn rrset_serde_rejections() {
    for json in [
        r#"{"name":"example.org.","type":"A","records":[]}"#,
        r#"{"name":"example.org.","type":"A","records":["not an address"]}"#,
        r#"{"name":"example.org.","type":"A","records":["192.0.2.1"],"extra":1}"#,
        r#"{"name":"bad name","type":"A","records":["192.0.2.1"]}"#,
        r#"{"name":"example.org.","type":"NOPE","records":["192.0.2.1"]}"#,
        r#"{"name":"example.org.","type":"A","ttl":4294967295,"records":["192.0.2.1"]}"#,
        r#"{"name":"example.org.","type":"A","ttl":"default","records":["192.0.2.1"]}"#,
        r#"{"name":"example.org.","type":"A","ttl":"300","records":["192.0.2.1"]}"#,
        r#"{"name":"example.org.","type":"A","ttl":{},"records":["192.0.2.1"]}"#,
        r#"{"name":"example.org.","type":"A","records":[{"raw":"x","other":1}]}"#,
        r#"{"name":"example.org.","type":"CNAME","records":["a.example.org","b.example.org"]}"#,
        r#"{"type":"A","records":["192.0.2.1"]}"#,
    ] {
        assert!(serde_json::from_str::<RrSet>(json).is_err(), "{json}");
    }
}
