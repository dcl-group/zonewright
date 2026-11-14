// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Domain names: `DomainName` and `TargetName`.

use zonewright::name::{DomainName, NameError, TargetName};

fn dn(s: &str) -> DomainName {
    DomainName::parse(s).unwrap()
}

fn tn(s: &str) -> TargetName {
    TargetName::parse(s).unwrap()
}

// ---- DomainName: parsing --------------------------------------------------------------------

#[test]
fn parse_lowercases_and_adds_trailing_dot() {
    assert_eq!(dn("www.Example.ORG").as_str(), "www.example.org.");
    assert_eq!(dn("www.example.org.").as_str(), "www.example.org.");
    assert_eq!(dn("www.example.org"), dn("www.example.org."));
}

#[test]
fn root_and_empty() {
    assert!(dn(".").is_root());
    assert_eq!(DomainName::root().as_str(), ".");
    assert_eq!(DomainName::root().without_dot(), "");
    assert_eq!(DomainName::root().label_count(), 0);
    assert_eq!(DomainName::parse(""), Err(NameError::Empty));
    assert_eq!(DomainName::parse(".."), Err(NameError::BadLabelLength));
}

#[test]
fn whitespace_is_not_trimmed() {
    for input in [
        " example.org",
        "example.org ",
        "exa mple.org",
        "example.org\t",
        "\nexample.org",
    ] {
        assert_eq!(
            DomainName::parse(input),
            Err(NameError::BadCharacter),
            "{input:?}"
        );
    }
}

#[test]
fn underscore_labels_are_valid_anywhere() {
    for input in [
        "_acme-challenge.example.org",
        "_dmarc.example.org",
        "_25._tcp.mail.example.org",
        "a_b.example.org",
        "_.example.org",
        "b_.example.org",
    ] {
        assert!(DomainName::parse(input).is_ok(), "{input}");
    }
}

#[test]
fn wildcard_only_as_whole_leftmost_label() {
    let wildcard = dn("*.example.org");
    assert!(wildcard.is_wildcard());
    assert_eq!(wildcard.as_str(), "*.example.org.");
    assert!(!dn("www.example.org").is_wildcard());
    for input in [
        "a.*.example.org",
        "*a.example.org",
        "a*.example.org",
        "**.example.org",
        "example.*",
    ] {
        assert_eq!(
            DomainName::parse(input),
            Err(NameError::BadWildcard),
            "{input}"
        );
    }
}

#[test]
fn hyphen_rules() {
    assert!(DomainName::parse("a-b.example.org").is_ok());
    assert!(DomainName::parse("ab--cd.example.org").is_ok());
    assert_eq!(
        DomainName::parse("-a.example.org"),
        Err(NameError::BadHyphen)
    );
    assert_eq!(
        DomainName::parse("a-.example.org"),
        Err(NameError::BadHyphen)
    );
}

#[test]
fn other_characters_are_refused() {
    for input in [
        "a/b.example.org",
        "a@b.example.org",
        "a\\b.example.org",
        "a\"b.org",
        "a,b.org",
    ] {
        assert_eq!(
            DomainName::parse(input),
            Err(NameError::BadCharacter),
            "{input}"
        );
    }
}

#[test]
fn length_limits() {
    let label63 = "a".repeat(63);
    assert!(DomainName::parse(&format!("{label63}.example.org")).is_ok());
    let label64 = "a".repeat(64);
    assert_eq!(
        DomainName::parse(&format!("{label64}.example.org")),
        Err(NameError::BadLabelLength)
    );
    assert_eq!(
        DomainName::parse("a..example.org"),
        Err(NameError::BadLabelLength)
    );
    assert_eq!(
        DomainName::parse(".example.org"),
        Err(NameError::BadLabelLength)
    );

    // 4 labels of 63 octets and 3 dots: 255 octets. Trim to exactly 253 and 254.
    let name253 = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(name253.len(), 253);
    assert!(DomainName::parse(&name253).is_ok());
    assert!(DomainName::parse(&format!("{name253}.")).is_ok());
    let name254 = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    assert_eq!(DomainName::parse(&name254), Err(NameError::TooLong));
}

#[test]
fn idna_u_labels_become_a_labels() {
    assert_eq!(
        dn("Bücher.example.org").as_str(),
        "xn--bcher-kva.example.org."
    );
    assert_eq!(
        dn("XN--BCHER-KVA.example.org").as_str(),
        "xn--bcher-kva.example.org."
    );
    assert_eq!(dn("bücher.example.org"), dn("xn--bcher-kva.example.org"));
    // An ideographic full stop separates labels.
    assert_eq!(dn("例え。jp").as_str(), "xn--r8jz45g.jp.");
}

#[test]
fn bad_punycode_is_refused() {
    for input in [
        "xn--zz.example.org",
        "xn--a.example.org",
        "xn---.example.org",
        "xn--abc.example.org",
    ] {
        assert_eq!(DomainName::parse(input), Err(NameError::Idna), "{input}");
    }
}

#[test]
fn to_unicode_decodes_a_labels() {
    assert_eq!(
        dn("xn--bcher-kva.example.org").to_unicode(),
        "bücher.example.org."
    );
    assert_eq!(dn("www.example.org").to_unicode(), "www.example.org.");
    assert_eq!(DomainName::root().to_unicode(), ".");
}

// ---- DomainName: relations ------------------------------------------------------------------

#[test]
fn from_relative() {
    let origin = dn("example.org");
    assert_eq!(DomainName::from_relative("", &origin).unwrap(), origin);
    assert_eq!(DomainName::from_relative("@", &origin).unwrap(), origin);
    assert_eq!(
        DomainName::from_relative("www", &origin).unwrap(),
        dn("www.example.org")
    );
    assert_eq!(
        DomainName::from_relative("a.b", &origin).unwrap(),
        dn("a.b.example.org")
    );
    assert_eq!(
        DomainName::from_relative("www.example.net.", &origin).unwrap(),
        dn("www.example.net")
    );
    assert_eq!(
        DomainName::from_relative("org", &DomainName::root()).unwrap(),
        dn("org")
    );
    assert_eq!(
        DomainName::from_relative("a b", &origin),
        Err(NameError::BadCharacter)
    );
}

#[test]
fn labels_and_counts() {
    let name = dn("a.b.example.org");
    assert_eq!(
        name.labels().collect::<Vec<_>>(),
        ["a", "b", "example", "org"]
    );
    assert_eq!(name.label_count(), 4);
    assert_eq!(name.without_dot(), "a.b.example.org");
}

#[test]
fn is_within_compares_labels() {
    let zone = dn("example.org");
    assert!(dn("example.org").is_within(&zone));
    assert!(dn("www.example.org").is_within(&zone));
    assert!(dn("a.b.example.org").is_within(&zone));
    assert!(!dn("badexample.org").is_within(&zone));
    assert!(!dn("example.org.evil.example").is_within(&zone));
    assert!(!dn("org").is_within(&zone));
    assert!(!dn("example.net").is_within(&zone));
    assert!(dn("example.org").is_within(&DomainName::root()));
    assert!(DomainName::root().is_within(&DomainName::root()));
    assert!(!DomainName::root().is_within(&zone));
}

#[test]
fn relative_to() {
    let zone = dn("example.org");
    assert_eq!(dn("example.org").relative_to(&zone), Some(""));
    assert_eq!(dn("www.example.org").relative_to(&zone), Some("www"));
    assert_eq!(dn("a.b.example.org").relative_to(&zone), Some("a.b"));
    assert_eq!(dn("badexample.org").relative_to(&zone), None);
    assert_eq!(
        dn("www.example.org").relative_to(&DomainName::root()),
        Some("www.example.org")
    );
}

#[test]
fn parent() {
    assert_eq!(dn("www.example.org").parent(), Some(dn("example.org")));
    assert_eq!(dn("org").parent(), Some(DomainName::root()));
    assert_eq!(DomainName::root().parent(), None);
}

#[test]
fn prepend() {
    let zone = dn("example.org");
    assert_eq!(zone.prepend("www").unwrap(), dn("www.example.org"));
    assert_eq!(
        zone.prepend("_acme-challenge").unwrap(),
        dn("_acme-challenge.example.org")
    );
    assert_eq!(zone.prepend("*").unwrap(), dn("*.example.org"));
    assert_eq!(zone.prepend("WWW").unwrap(), dn("www.example.org"));
    assert_eq!(DomainName::root().prepend("org").unwrap(), dn("org"));
    assert_eq!(zone.prepend("a.b"), Err(NameError::BadCharacter));
    assert_eq!(zone.prepend(""), Err(NameError::BadLabelLength));
    assert_eq!(zone.prepend("-a"), Err(NameError::BadHyphen));
    assert_eq!(
        dn("*.example.org").prepend("a"),
        Err(NameError::BadWildcard)
    );
}

#[test]
fn display_debug_from_str_and_ordering() {
    let name: DomainName = "WWW.example.org".parse().unwrap();
    assert_eq!(name.to_string(), "www.example.org.");
    assert_eq!(format!("{name:?}"), "DomainName(\"www.example.org.\")");
    let mut names = vec![dn("b.example.org"), dn("a.example.org"), dn("example.org")];
    names.sort();
    assert_eq!(
        names,
        [dn("a.example.org"), dn("b.example.org"), dn("example.org")]
    );
}

#[test]
fn domain_name_serde() {
    let name = dn("www.example.org");
    let json = serde_json::to_string(&name).unwrap();
    assert_eq!(json, "\"www.example.org.\"");
    assert_eq!(serde_json::from_str::<DomainName>(&json).unwrap(), name);
    assert_eq!(
        serde_json::from_str::<DomainName>("\"WWW.Example.org\"").unwrap(),
        name
    );
    assert!(serde_json::from_str::<DomainName>("\"a b\"").is_err());
    assert!(serde_json::from_str::<DomainName>("42").is_err());
}

// ---- TargetName -----------------------------------------------------------------------------

#[test]
fn target_basic_forms() {
    assert_eq!(tn("Mail.Example.org").as_str(), "mail.example.org.");
    assert_eq!(tn("mail.example.org."), tn("mail.example.org"));
    assert!(tn(".").is_root());
    assert_eq!(TargetName::root().as_str(), ".");
    assert_eq!(TargetName::parse(""), Err(NameError::Empty));
    assert_eq!(TargetName::parse("@"), Err(NameError::BadCharacter));
    assert_eq!(TargetName::parse("a..b"), Err(NameError::BadLabelLength));
    assert_eq!(TargetName::parse(".a"), Err(NameError::BadLabelLength));
    assert_eq!(TargetName::parse("a b"), Err(NameError::BadCharacter));
    assert_eq!(TargetName::parse("a\tb"), Err(NameError::BadCharacter));
}

#[test]
fn target_accepts_unusual_labels() {
    assert_eq!(
        tn("0/25.2.0.192.in-addr.arpa").as_str(),
        "0/25.2.0.192.in-addr.arpa."
    );
    assert_eq!(tn("-a.example.org").as_str(), "-a.example.org.");
    assert_eq!(tn("*.example.org").as_str(), "*.example.org.");
    assert_eq!(tn("a*b.example.org").as_str(), "a*b.example.org.");
    assert_eq!(tn("a$b.example.org").as_str(), "a\\036b.example.org.");
}

#[test]
fn target_escapes() {
    // An escaped dot is part of the label.
    let mailbox = tn("first\\.last.example.org.");
    assert_eq!(mailbox.as_str(), "first\\.last.example.org.");
    assert!(mailbox.to_domain_name().is_none());
    assert_eq!(tn("\\065BC.example.org").as_str(), "abc.example.org.");
    assert_eq!(tn("a\\\\b.example.org").as_str(), "a\\\\b.example.org.");
    assert_eq!(tn("\\000.example.org").as_str(), "\\000.example.org.");
    assert_eq!(tn("a\\ b.example.org").as_str(), "a\\032b.example.org.");
    assert_eq!(tn("\\@.example.org").as_str(), "\\064.example.org.");
    assert_eq!(
        tn("\\(x\\).example.org").as_str(),
        "\\040x\\041.example.org."
    );
    assert_eq!(tn("\\;.example.org").as_str(), "\\059.example.org.");
    assert_eq!(tn("\\\".example.org").as_str(), "\\034.example.org.");
    assert_eq!(tn("\\255.example.org").as_str(), "\\255.example.org.");
    assert_eq!(tn("\\x.example.org").as_str(), "x.example.org.");
    // `\046` is a dot octet inside the label, the same as `\.`.
    assert_eq!(tn("a\\046b.example.org"), tn("a\\.b.example.org"));
    for bad in [
        "\\1.example.org",
        "\\12.example.org",
        "a\\12x.example.org",
        "\\256.example.org",
        "example.org\\",
    ] {
        assert_eq!(TargetName::parse(bad), Err(NameError::BadEscape), "{bad}");
    }
}

#[test]
fn target_idna() {
    assert_eq!(
        tn("Bücher.example.org").as_str(),
        "xn--bcher-kva.example.org."
    );
    // ASCII labels are not validated as Punycode inside RDATA.
    assert_eq!(tn("xn--zz.example.org").as_str(), "xn--zz.example.org.");
}

#[test]
fn target_lengths() {
    let label63 = "a".repeat(63);
    assert!(TargetName::parse(&format!("{label63}.example.org")).is_ok());
    let label64 = "a".repeat(64);
    assert_eq!(
        TargetName::parse(&format!("{label64}.org")),
        Err(NameError::BadLabelLength)
    );
    // Wire length: 4 * (1 + 63) = 256 > 255.
    let long = [label63.as_str(); 4].join(".");
    assert_eq!(TargetName::parse(&long), Err(NameError::TooLong));
    // 3 * 64 + (1 + 61) + 1 = 255.
    let max = format!("{}.{}.{}.{}", label63, label63, label63, "a".repeat(61));
    assert!(TargetName::parse(&max).is_ok());
}

#[test]
fn target_from_relative() {
    let origin = dn("example.org");
    assert_eq!(
        TargetName::from_relative("@", &origin).unwrap(),
        tn("example.org.")
    );
    assert_eq!(
        TargetName::from_relative("www", &origin).unwrap(),
        tn("www.example.org.")
    );
    assert_eq!(
        TargetName::from_relative("www.", &origin).unwrap(),
        tn("www.")
    );
    assert_eq!(
        TargetName::from_relative("a\\.b", &origin).unwrap(),
        tn("a\\.b.example.org.")
    );
    assert_eq!(
        TargetName::from_relative(".", &origin).unwrap(),
        TargetName::root()
    );
}

#[test]
fn target_from_wire() {
    let wire = b"\x04Mail\x07example\x03org\x00";
    let name = TargetName::from_wire(wire).unwrap();
    assert_eq!(name.as_str(), "mail.example.org.");
    assert_eq!(name, tn("mail.example.org"));

    let dotted = b"\x0afirst.last\x07example\x03org\x00";
    assert_eq!(
        TargetName::from_wire(dotted).unwrap(),
        tn("first\\.last.example.org.")
    );

    let odd = b"\x03a\x00\xff\x00";
    assert_eq!(TargetName::from_wire(odd).unwrap().as_str(), "a\\000\\255.");

    assert_eq!(TargetName::from_wire(b"\x00").unwrap(), TargetName::root());
    assert_eq!(TargetName::from_wire(b""), Err(NameError::Empty));
    // Compression pointer.
    assert!(TargetName::from_wire(b"\x03www\xc0\x0c").is_err());
    // Truncated.
    assert!(TargetName::from_wire(b"\x05ab").is_err());
    assert!(TargetName::from_wire(b"\x03www").is_err());
    // Bytes after the root label.
    assert!(TargetName::from_wire(b"\x01a\x00\x00").is_err());
}

#[test]
fn target_and_domain_name_conversions() {
    let name = dn("_acme-challenge.example.org");
    let target = TargetName::from(&name);
    assert_eq!(target.as_str(), name.as_str());
    assert_eq!(target, tn("_acme-challenge.example.org"));
    assert_eq!(target.to_domain_name(), Some(name.clone()));
    assert_eq!(TargetName::from(name.clone()), target);
    assert_eq!(TargetName::from(DomainName::root()), TargetName::root());
    assert_eq!(TargetName::from(dn("*.example.org")), tn("*.example.org"));
    assert!(tn("a/b.example.org").to_domain_name().is_none());
    assert!(tn("-a.example.org").to_domain_name().is_none());
}

#[test]
fn target_display_debug_serde() {
    let name: TargetName = "a\\.b.Example.org".parse().unwrap();
    assert_eq!(name.to_string(), "a\\.b.example.org.");
    assert_eq!(format!("{name:?}"), "TargetName(\"a\\\\.b.example.org.\")");
    let json = serde_json::to_string(&name).unwrap();
    assert_eq!(serde_json::from_str::<TargetName>(&json).unwrap(), name);
    assert!(serde_json::from_str::<TargetName>("\"\\\\1\"").is_err());
}

#[test]
fn target_canonical_text_is_idempotent() {
    for input in [
        "Mail.Example.org",
        "first\\.last.example.org",
        "a\\ b.example.org",
        "\\000\\255.example",
        "a/b.example",
        "bücher.example.org",
        ".",
    ] {
        let once = tn(input);
        let twice = tn(once.as_str());
        assert_eq!(once, twice, "{input}");
    }
}

#[test]
fn errors_do_not_quote_input() {
    let err = DomainName::parse("secret value.example.org").unwrap_err();
    assert!(!err.to_string().contains("secret"));
    let err = TargetName::parse("secret\\1.example.org").unwrap_err();
    assert!(!err.to_string().contains("secret"));
}
