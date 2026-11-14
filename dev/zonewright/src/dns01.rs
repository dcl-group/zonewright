//! DNS-01 helpers (design section 7): the challenge name, CNAME chains and zone selection.
//!
//! Pure functions and one trait; no network code. The inspector implements [`CnameLookup`] when
//! its feature is enabled; an application can implement it over any resolver.
//!
//! Deliberately not here: CAA tree climbing and any judgement on whether a CA may issue, rules
//! about where a challenge may be delegated (such as "the CNAME target must not be a zone apex"),
//! and computing the TXT value from a key authorization. Those decide what a zone should contain
//! or belong to ACME.

use std::collections::HashSet;
use std::future::Future;

use crate::name::{DomainName, NameError};
use crate::redact::Detail;

/// The label that the DNS-01 challenge name starts with (RFC 8555 section 8.4).
pub const CHALLENGE_LABEL: &str = "_acme-challenge";

/// Default limit for [`follow_cname`].
pub const CNAME_CHAIN_MAX: usize = 8;

/// The name at which the DNS-01 TXT record for `identifier` is expected (RFC 8555 section 8.4).
///
/// A leading wildcard label is dropped: the challenge for `*.example.org` is at
/// `_acme-challenge.example.org`. Fails only when the result would be too long.
pub fn challenge_name(identifier: &DomainName) -> Result<DomainName, NameError> {
    let base = if identifier.is_wildcard() {
        identifier.parent().unwrap_or_else(DomainName::root)
    } else {
        identifier.clone()
    };
    base.prepend(CHALLENGE_LABEL)
}

/// Something that can say whether a name is a CNAME.
pub trait CnameLookup {
    /// `Ok(Some(target))`: the name is a CNAME to `target`. `Ok(None)`: it is not (no such
    /// record or no such name). `Err`: no trustworthy answer was obtained.
    fn cname(
        &self,
        name: &DomainName,
    ) -> impl Future<Output = Result<Option<DomainName>, LookupError>> + Send;
}

/// A lookup that gave no trustworthy answer. Its text is bounded to 512 bytes without control
/// characters.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct LookupError {
    detail: String,
}

impl LookupError {
    /// An error with this description. The text is cut to 512 bytes and control characters are
    /// replaced by spaces.
    pub fn new(detail: impl Into<String>) -> LookupError {
        LookupError {
            detail: bounded(&detail.into()),
        }
    }

    /// The description.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

fn bounded(text: &str) -> String {
    Detail::new(text).as_str().to_owned()
}

/// A CNAME chain from a start name.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CnameChain {
    /// The name the chain starts at.
    pub start: DomainName,
    /// The targets in order; empty when `start` is not a CNAME.
    pub links: Vec<DomainName>,
}

impl CnameChain {
    /// The last target, or `start` when there are no links: the name whose TXT rrset must hold
    /// the challenge value.
    #[must_use]
    pub fn effective(&self) -> &DomainName {
        self.links.last().unwrap_or(&self.start)
    }
}

/// Why a CNAME chain could not be followed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CnameError {
    /// A target repeats a name already seen in the chain, the start included.
    #[error("CNAME loop at {name}")]
    Loop {
        /// The repeated name.
        name: DomainName,
    },
    /// The chain has more links than allowed.
    #[error("CNAME chain from {start} is longer than {max} links")]
    TooLong {
        /// The start of the chain.
        start: DomainName,
        /// The limit.
        max: usize,
    },
    /// A lookup gave no trustworthy answer.
    #[error("lookup of {name} failed: {detail}")]
    Lookup {
        /// The name that was looked up.
        name: DomainName,
        /// The lookup's description, at most 512 bytes, no control characters.
        detail: String,
    },
}

impl CnameError {
    /// True for `Lookup` only: the other cases are properties of the zone data.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, CnameError::Lookup { .. })
    }
}

/// Follows CNAME records from `start`: asks `lookup` for `start`, then for each target in turn.
///
/// A target equal to any name already seen, including `start`, is [`CnameError::Loop`]. A chain
/// of exactly `max_links` links is accepted; one more is [`CnameError::TooLong`]. A lookup error
/// stops with [`CnameError::Lookup`].
pub async fn follow_cname<L: CnameLookup>(
    lookup: &L,
    start: &DomainName,
    max_links: usize,
) -> Result<CnameChain, CnameError> {
    let mut seen: HashSet<DomainName> = HashSet::new();
    seen.insert(start.clone());
    let mut links: Vec<DomainName> = Vec::new();
    let mut current = start.clone();
    loop {
        let answer = lookup
            .cname(&current)
            .await
            .map_err(|err| CnameError::Lookup {
                name: current.clone(),
                detail: bounded(err.detail()),
            })?;
        let Some(target) = answer else {
            return Ok(CnameChain {
                start: start.clone(),
                links,
            });
        };
        if !seen.insert(target.clone()) {
            return Err(CnameError::Loop { name: target });
        }
        if links.len() >= max_links {
            return Err(CnameError::TooLong {
                start: start.clone(),
                max: max_links,
            });
        }
        links.push(target.clone());
        current = target;
    }
}

/// Of the given zones, the one with the most labels that contains `name`, compared label by
/// label. If two entries have the same zone, the first wins. The payload `T` is whatever the
/// application attaches to a zone (an account, a provider ID).
pub fn select_zone<'a, T>(
    name: &DomainName,
    zones: &'a [(DomainName, T)],
) -> Option<&'a (DomainName, T)> {
    let mut best: Option<&'a (DomainName, T)> = None;
    for entry in zones {
        if !name.is_within(&entry.0) {
            continue;
        }
        if best.is_none_or(|current| entry.0.label_count() > current.0.label_count()) {
            best = Some(entry);
        }
    }
    best
}
