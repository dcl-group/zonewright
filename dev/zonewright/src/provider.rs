//! The provider trait, write preconditions, outcomes and reports (design section 2.6).

use std::future::Future;

use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};
use crate::redact::Detail;

/// The operations of one provider client.
///
/// [`Provider::check`] is the only method without a default body. Every other method has a
/// default that returns [`Error::Unsupported`] for its operation, so a client implements exactly
/// what its [`Capabilities`] announce. Implementations write `async fn`; the declared futures are
/// `Send` by contract. There is no `dyn Provider`: the set of providers is dispatched through
/// [`AnyProvider`](crate::AnyProvider).
///
/// The trait is not sealed: an application can implement it for a test double. Everything an
/// implementation has to return can be built outside the crate through the `new` constructors of
/// the report types and the constructor functions of [`Error`].
///
/// Every operation that takes a zone and a name checks, before any network request and in this
/// order: that the operation and the record type are supported; that the zone is neither the
/// root nor a wildcard and the type not a meta type; that the name is within the zone; and that
/// the request fits the provider (design section 3.1).
pub trait Provider: Send + Sync {
    /// The provider this client talks to.
    fn id(&self) -> ProviderId;

    /// What this client can do. The provider's static capabilities.
    fn capabilities(&self) -> &'static Capabilities {
        &self.id().meta().capabilities
    }

    /// Verifies the credentials and reports, for each zone, whether it is visible and usable.
    fn check(
        &self,
        zones: &[DomainName],
    ) -> impl Future<Output = Result<CheckReport, Error>> + Send;

    /// Zones in which these credentials can change records.
    fn list_zones(&self) -> impl Future<Output = Result<Vec<ZoneInfo>, Error>> + Send {
        let provider = self.id();
        async move { Err(Error::unsupported(provider, Operation::ListZones)) }
    }

    /// Every rrset of the zone, of every type the provider reports.
    fn list_rrsets(
        &self,
        zone: &DomainName,
    ) -> impl Future<Output = Result<ZoneListing, Error>> + Send {
        let _ = zone;
        let provider = self.id();
        async move { Err(Error::unsupported(provider, Operation::ListRrsets)) }
    }

    /// The rrset of `name` and `rtype`, or `None`. The same data `list_rrsets` would return for
    /// that name and type.
    fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> impl Future<Output = Result<Option<RrSet>, Error>> + Send {
        let _ = (zone, name, rtype);
        let provider = self.id();
        async move { Err(Error::unsupported(provider, Operation::GetRrset)) }
    }

    /// Makes the rrset at `rrset.name()` / `rrset.rtype()` equal to `rrset`, if `expect` holds
    /// for the rrset as it is at the provider.
    ///
    /// `rrset.ttl()` is what the write asks for the TTL (design section 3.6): `None` keeps the
    /// TTL of an existing rrset and gives a new one the client's `ttl` setting;
    /// `Some(RrsetTtl::Explicit(n))` sets `n`; `Some(RrsetTtl::ProviderDefault)` gives the rrset
    /// the provider's default TTL, and is `Error::InvalidInput` before any request where
    /// [`Capabilities::provider_default_ttl`] does not allow it. A CNAME at a name that holds other data, or another type at a
    /// name that holds a CNAME (RFC 1034 section 3.6.2), is `Error::InvalidInput` where the
    /// client's read shows it; elsewhere the provider's own answer is returned (design section
    /// 3.4).
    fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> impl Future<Output = Result<SetOutcome, Error>> + Send {
        let _ = (zone, rrset, expect);
        let provider = self.id();
        async move { Err(Error::unsupported(provider, Operation::SetRrset)) }
    }

    /// Removes all published values of `name` and `rtype`, if `expect` holds. `Expect::Absent`
    /// is `Error::InvalidInput`.
    fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        expect: Expect<'_>,
    ) -> impl Future<Output = Result<DeleteOutcome, Error>> + Send {
        let _ = (zone, name, rtype, expect);
        let provider = self.id();
        async move { Err(Error::unsupported(provider, Operation::DeleteRrset)) }
    }

    /// Adds one value to the TXT rrset at `name` without touching its other values.
    /// `ttl` is used only if the rrset has to be created: a number, the provider's default
    /// (`Error::InvalidInput` before any request where [`Capabilities::provider_default_ttl`]
    /// does not allow it), or with `None` the client's `ttl` setting. An existing rrset keeps
    /// its TTL.
    fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<RrsetTtl>,
    ) -> impl Future<Output = Result<AddOutcome, Error>> + Send {
        let _ = (zone, name, value, ttl);
        let provider = self.id();
        async move { Err(Error::unsupported(provider, Operation::AddTxtValue)) }
    }

    /// Removes that one value from the TXT rrset at `name` and nothing else.
    fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> impl Future<Output = Result<RemoveOutcome, Error>> + Send {
        let _ = (zone, name, value);
        let provider = self.id();
        async move { Err(Error::unsupported(provider, Operation::RemoveTxtValue)) }
    }
}

/// Precondition of a write, evaluated against the rrset as it is at the provider.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Expect<'a> {
    /// No precondition: create or replace.
    Any,
    /// The rrset must not exist: create only.
    Absent,
    /// The rrset must have exactly these records and, if the given set states a TTL, that
    /// TTL: `Some(RrsetTtl::Explicit(n))` holds for an rrset that reads with `n`,
    /// `Some(RrsetTtl::ProviderDefault)` for one that has the provider's default, and `None`
    /// for any TTL. The given set must have the name and type the operation is about; anything
    /// else is `Error::InvalidInput` before any request.
    Matches(&'a RrSet),
}

/// The result of a successful `set_rrset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetOutcome {
    /// The rrset did not exist and now does.
    Created,
    /// The rrset existed and was changed.
    Replaced,
    /// The rrset was already as requested; nothing was written.
    Unchanged,
}

/// The result of a successful `delete_rrset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteOutcome {
    /// The rrset existed and was removed.
    Deleted,
    /// The rrset did not exist; nothing was written.
    NotPresent,
}

/// The result of a successful `add_txt_value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddOutcome {
    /// The rrset did not exist and now holds the value.
    Created,
    /// The rrset existed with other values and now also holds the value.
    Appended,
    /// The value was already there; nothing was written.
    AlreadyPresent,
    /// The value was sent and not refused; the state before and after could not be observed.
    Accepted,
}

/// The result of a successful `remove_txt_value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoveOutcome {
    /// The value was removed; other values remain.
    Removed,
    /// The value was the only one; the rrset no longer exists.
    RrsetDeleted,
    /// The value was not there; nothing was written.
    NotPresent,
    /// The removal was sent and not refused; the state before and after could not be observed.
    Accepted,
}

/// The result of [`Provider::check`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CheckReport {
    /// The credentials were exercised against the provider and accepted. False when no request
    /// tested them: the provider offers no request that tests credentials without naming a zone
    /// and `zones` was empty, or the provider offers no request that tests credentials without
    /// writing (acme-dns, whose only authenticated request stores a value, so its `check` sends
    /// nothing and always reports false).
    pub credentials_verified: bool,
    /// One entry per requested zone, in the order given.
    pub zones: Vec<ZoneCheck>,
}

impl CheckReport {
    /// A report from its fields.
    #[must_use]
    pub fn new(credentials_verified: bool, zones: Vec<ZoneCheck>) -> CheckReport {
        CheckReport {
            credentials_verified,
            zones,
        }
    }
}

/// The state of one zone in a [`CheckReport`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ZoneCheck {
    /// The zone.
    pub zone: DomainName,
    /// The zone exists at the provider, is visible to these credentials and accepts changes.
    pub found: bool,
    /// Why the zone is not usable, or a warning about a usable one.
    pub detail: Option<Detail>,
}

impl ZoneCheck {
    /// A zone entry from its fields.
    #[must_use]
    pub fn new(zone: DomainName, found: bool, detail: Option<Detail>) -> ZoneCheck {
        ZoneCheck {
            zone,
            found,
            detail,
        }
    }
}

/// A zone returned by [`Provider::list_zones`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ZoneInfo {
    /// The zone name.
    pub name: DomainName,
}

impl ZoneInfo {
    /// A zone entry from its name.
    #[must_use]
    pub fn new(name: DomainName) -> ZoneInfo {
        ZoneInfo { name }
    }
}

/// The result of [`Provider::list_rrsets`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ZoneListing {
    /// Sorted by name, then type.
    pub rrsets: Vec<RrSet>,
    /// What the provider reported for the zone but the model cannot hold. Never silently empty:
    /// every such rrset has an entry.
    pub skipped: Vec<SkippedRrset>,
}

impl ZoneListing {
    /// A listing from its parts. The rrsets are sorted by name, then type.
    #[must_use]
    pub fn new(mut rrsets: Vec<RrSet>, skipped: Vec<SkippedRrset>) -> ZoneListing {
        rrsets.sort_by(|a, b| a.name().cmp(b.name()).then(a.rtype().cmp(&b.rtype())));
        ZoneListing { rrsets, skipped }
    }
}

/// Most characters of a provider's type name a [`SkippedRrset`] keeps.
const TYPE_NAME_MAX_CHARS: usize = 32;

/// An rrset a provider reported that the record model cannot hold.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkippedRrset {
    /// The owner name.
    pub name: DomainName,
    /// The type as the provider spells it, at most 32 characters, control characters removed.
    pub type_name: String,
    /// Why it was skipped.
    pub reason: SkipReason,
}

impl SkippedRrset {
    /// An entry from its fields. `type_name` is cut to 32 characters after control characters
    /// are removed.
    #[must_use]
    pub fn new(name: DomainName, type_name: &str, reason: SkipReason) -> SkippedRrset {
        let type_name = type_name
            .chars()
            .filter(|c| !c.is_control())
            .take(TYPE_NAME_MAX_CHARS)
            .collect();
        SkippedRrset {
            name,
            type_name,
            reason,
        }
    }
}

/// Why an rrset was skipped in a listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// The type name is neither a registered mnemonic, nor `TYPE<code>`, nor a pseudo-type.
    UnknownType,
    /// Not a plain rrset: an alias to a provider resource, a routing-policy set and the like.
    NotPlainRecords,
    /// The owner name is not a valid `DomainName` (design section 2.1).
    UnsupportedName,
}

#[cfg(test)]
mod tests {
    use super::{SkipReason, SkippedRrset, ZoneListing};
    use crate::name::DomainName;
    use crate::record::{RecordData, RecordType, RrSet};

    #[test]
    fn skipped_type_name_is_bounded() {
        let name = DomainName::parse("x.example.org").unwrap();
        let s = SkippedRrset::new(
            name,
            &format!("A\nB{}", "Z".repeat(100)),
            SkipReason::UnknownType,
        );
        assert_eq!(s.type_name.chars().count(), 32);
        assert!(s.type_name.starts_with("AB"));
    }

    #[test]
    fn listing_is_sorted() {
        let set = |n: &str, t: RecordType, v: &str| {
            RrSet::new(
                DomainName::parse(n).unwrap(),
                t,
                None,
                [RecordData::parse(t, v).unwrap()],
            )
            .unwrap()
        };
        let listing = ZoneListing::new(
            vec![
                set("b.example.org", RecordType::A, "192.0.2.1"),
                set("a.example.org", RecordType::TXT, "x"),
                set("a.example.org", RecordType::A, "192.0.2.2"),
            ],
            Vec::new(),
        );
        let order: Vec<_> = listing
            .rrsets
            .iter()
            .map(|s| (s.name().as_str().to_owned(), s.rtype()))
            .collect();
        assert_eq!(
            order,
            [
                ("a.example.org.".to_owned(), RecordType::A),
                ("a.example.org.".to_owned(), RecordType::TXT),
                ("b.example.org.".to_owned(), RecordType::A),
            ]
        );
    }
}
