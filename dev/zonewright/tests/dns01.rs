// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! DNS-01 helpers: challenge name, CNAME chains, zone selection.

mod common;

use std::collections::HashMap;

use zonewright::dns01::{
    CHALLENGE_LABEL, CNAME_CHAIN_MAX, CnameChain, CnameError, CnameLookup, LookupError,
    challenge_name, follow_cname, select_zone,
};
use zonewright::{DomainName, NameError};

use common::dn;

// ---- Challenge name ----------------------------------------------------------------------------

#[test]
fn challenge_name_prepends_the_label() {
    assert_eq!(CHALLENGE_LABEL, "_acme-challenge");
    assert_eq!(
        challenge_name(&dn("example.org")).unwrap(),
        dn("_acme-challenge.example.org")
    );
    assert_eq!(
        challenge_name(&dn("www.example.org")).unwrap(),
        dn("_acme-challenge.www.example.org")
    );
}

#[test]
fn challenge_name_drops_a_wildcard_label() {
    assert_eq!(
        challenge_name(&dn("*.example.org")).unwrap(),
        dn("_acme-challenge.example.org")
    );
    assert_eq!(
        challenge_name(&dn("*.example.org")).unwrap(),
        challenge_name(&dn("example.org")).unwrap()
    );
}

#[test]
fn challenge_name_fails_only_when_too_long() {
    // 4 labels of 63 octets and dots: 255 octets, over the limit once the label is added.
    let label = "a".repeat(63);
    let long = format!("{label}.{label}.{label}.{}", "b".repeat(50));
    let name = dn(&long);
    assert_eq!(challenge_name(&name), Err(NameError::TooLong));
    let fits = format!("{label}.{label}.{label}.{}", "b".repeat(30));
    assert!(challenge_name(&dn(&fits)).is_ok());
}

// ---- CNAME chains ------------------------------------------------------------------------------

/// A lookup table: name -> target, or name -> failure.
#[derive(Default)]
struct Table {
    cnames: HashMap<DomainName, DomainName>,
    failures: HashMap<DomainName, String>,
}

impl Table {
    fn link(mut self, from: &str, to: &str) -> Table {
        self.cnames.insert(dn(from), dn(to));
        self
    }

    fn fail(mut self, at: &str, detail: &str) -> Table {
        self.failures.insert(dn(at), detail.to_owned());
        self
    }
}

impl CnameLookup for Table {
    async fn cname(&self, name: &DomainName) -> Result<Option<DomainName>, LookupError> {
        if let Some(detail) = self.failures.get(name) {
            return Err(LookupError::new(detail.clone()));
        }
        Ok(self.cnames.get(name).cloned())
    }
}

#[tokio::test]
async fn no_cname_gives_an_empty_chain() {
    let start = dn("_acme-challenge.example.org");
    let chain = follow_cname(&Table::default(), &start, CNAME_CHAIN_MAX)
        .await
        .unwrap();
    assert_eq!(chain.start, start);
    assert!(chain.links.is_empty());
    assert_eq!(chain.effective(), &start);
}

#[tokio::test]
async fn chain_is_followed_in_order() {
    let table = Table::default()
        .link("_acme-challenge.example.org", "a.example.net")
        .link("a.example.net", "b.example.com");
    let chain: CnameChain = follow_cname(&table, &dn("_acme-challenge.example.org"), 8)
        .await
        .unwrap();
    assert_eq!(chain.links, [dn("a.example.net"), dn("b.example.com")]);
    assert_eq!(chain.effective(), &dn("b.example.com"));
}

#[tokio::test]
async fn cname_to_itself_is_a_loop() {
    let table = Table::default().link("a.example.org", "a.example.org");
    let err = follow_cname(&table, &dn("a.example.org"), 8)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        CnameError::Loop {
            name: dn("a.example.org")
        }
    );
    assert!(!err.is_retryable());
}

#[tokio::test]
async fn longer_loop_is_detected() {
    let table = Table::default()
        .link("a.example.org", "b.example.org")
        .link("b.example.org", "c.example.org")
        .link("c.example.org", "b.example.org");
    let err = follow_cname(&table, &dn("a.example.org"), 8)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        CnameError::Loop {
            name: dn("b.example.org")
        }
    );
}

fn chain_of(links: usize) -> Table {
    let mut table = Table::default();
    for i in 0..links {
        table = table.link(
            &format!("n{i}.example.org"),
            &format!("n{}.example.org", i + 1),
        );
    }
    table
}

#[tokio::test]
async fn exactly_max_links_is_accepted_and_one_more_is_too_long() {
    let start = dn("n0.example.org");
    let chain = follow_cname(&chain_of(3), &start, 3).await.unwrap();
    assert_eq!(chain.links.len(), 3);
    assert_eq!(chain.effective(), &dn("n3.example.org"));

    let err = follow_cname(&chain_of(4), &start, 3).await.unwrap_err();
    assert_eq!(err, CnameError::TooLong { start, max: 3 });
    assert!(!err.is_retryable());

    let chain = follow_cname(
        &chain_of(CNAME_CHAIN_MAX),
        &dn("n0.example.org"),
        CNAME_CHAIN_MAX,
    )
    .await
    .unwrap();
    assert_eq!(chain.links.len(), CNAME_CHAIN_MAX);
}

#[tokio::test]
async fn zero_links_allowed_accepts_only_a_non_cname() {
    let start = dn("n0.example.org");
    assert!(follow_cname(&chain_of(0), &start, 0).await.is_ok());
    assert!(matches!(
        follow_cname(&chain_of(1), &start, 0).await,
        Err(CnameError::TooLong { max: 0, .. })
    ));
}

#[tokio::test]
async fn lookup_failure_is_retryable_and_bounded() {
    let detail = format!("timeout\nfrom resolver {}", "x".repeat(1000));
    let table = Table::default()
        .link("a.example.org", "b.example.org")
        .fail("b.example.org", &detail);
    let err = follow_cname(&table, &dn("a.example.org"), 8)
        .await
        .unwrap_err();
    assert!(err.is_retryable());
    let CnameError::Lookup { name, detail } = &err else {
        panic!("expected Lookup, got {err:?}");
    };
    assert_eq!(name, &dn("b.example.org"));
    assert!(detail.len() <= 512);
    assert!(detail.starts_with("timeout from resolver"));
    assert!(!detail.contains('\n'));
    assert!(!err.to_string().contains('\n'));
}

#[test]
fn lookup_error_is_bounded() {
    let err = LookupError::new("a\u{0}b".repeat(400));
    assert!(err.to_string().len() <= 512);
    assert!(!err.to_string().contains('\u{0}'));
    assert_eq!(err.detail(), err.to_string());
}

// ---- Zone selection ----------------------------------------------------------------------------

#[test]
fn the_deepest_containing_zone_wins() {
    let zones = [
        (dn("example.org"), 1),
        (dn("sub.example.org"), 2),
        (dn("example.net"), 3),
    ];
    assert_eq!(
        select_zone(&dn("_acme-challenge.www.sub.example.org"), &zones).map(|z| z.1),
        Some(2)
    );
    assert_eq!(
        select_zone(&dn("_acme-challenge.example.org"), &zones).map(|z| z.1),
        Some(1)
    );
    assert_eq!(
        select_zone(&dn("sub.example.org"), &zones).map(|z| z.1),
        Some(2)
    );
    assert_eq!(select_zone(&dn("example.com"), &zones), None);
}

#[test]
fn matching_is_by_labels() {
    let zones = [(dn("example.org"), ())];
    assert!(select_zone(&dn("badexample.org"), &zones).is_none());
    assert!(select_zone(&dn("a.badexample.org"), &zones).is_none());
    assert!(select_zone(&dn("org"), &zones).is_none());
}

#[test]
fn the_first_of_equal_zones_wins() {
    let zones = [
        (dn("example.org"), "first"),
        (dn("example.org"), "second"),
        (dn("org"), "parent"),
    ];
    assert_eq!(
        select_zone(&dn("a.example.org"), &zones).map(|z| z.1),
        Some("first")
    );
    let empty: [(DomainName, ()); 0] = [];
    assert!(select_zone(&dn("a.example.org"), &empty).is_none());
}
