//! Provider metadata and capabilities (design section 2.5).
//!
//! Metadata is static data, present for every provider in every build, so an application can
//! show a configuration form or decide what to offer for a provider whose client is not compiled
//! in. Capabilities describe this version of the crate: an operation whose client code is not
//! written yet is reported as unsupported.

use std::time::Duration;

use crate::error::Operation;
use crate::id::ProviderId;
use crate::record::{RecordType, RrsetTtl};

/// Static description of a provider.
#[derive(Debug)]
#[non_exhaustive]
pub struct ProviderMeta {
    /// The provider.
    pub id: ProviderId,
    /// Human-readable name, as in `PROVIDERS.md`.
    pub name: &'static str,
    /// True only for providers listed under "Verified against the live API" in `PROVIDERS.md`.
    pub verified: bool,
    /// How long the application should be prepared to wait for a change to reach all name
    /// servers, when the provider is known to need more or less than usual. `None`: no
    /// provider-specific value; the application uses its own default.
    pub default_propagation_timeout: Option<Duration>,
    /// Every key of the settings object and of the credentials object.
    pub fields: &'static [ConfigField],
    /// What the provider's client in this version of the crate can do.
    pub capabilities: Capabilities,
}

impl ProviderMeta {
    /// The field with this key, if any.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&'static ConfigField> {
        self.fields.iter().find(|field| field.key == key)
    }
}

/// One key of a provider's settings or credentials object.
#[derive(Debug)]
#[non_exhaustive]
pub struct ConfigField {
    /// Key in the JSON object: the credentials object when `secret`, else the settings object.
    pub key: &'static str,
    /// The value belongs in the credentials object, which the application stores encrypted.
    pub secret: bool,
    /// The key must be present.
    pub required: bool,
    /// What kind of value the key takes.
    pub kind: FieldKind,
    /// Default as text, for display. `None` for required fields and for fields with no default.
    pub default: Option<&'static str>,
    /// English label.
    pub label: &'static str,
    /// English help text, one sentence.
    pub help: &'static str,
    /// Rarely changed (endpoint overrides, polling intervals).
    pub advanced: bool,
}

/// The kind of value a [`ConfigField`] takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldKind {
    /// A short string.
    Text,
    /// Long or multi-line text (a PEM block, a JSON document).
    Multiline,
    /// A URL.
    Url,
    /// An integer within the bounds, inclusive.
    Integer {
        /// Smallest accepted value.
        min: i64,
        /// Largest accepted value.
        max: i64,
    },
    /// A TTL ([`RrsetTtl`](crate::RrsetTtl)): a number of seconds within the bounds, inclusive,
    /// and, when `provider_default` is true, also the string `"provider_default"`. Every key
    /// named `ttl` has this kind.
    Ttl {
        /// Smallest accepted number of seconds.
        min: u32,
        /// Largest accepted number of seconds.
        max: u32,
        /// The value `"provider_default"` is accepted: new rrsets get the provider's default
        /// TTL. Equal to [`ProviderDefaultTtl::can_request`] of the provider's capabilities.
        provider_default: bool,
    },
}

/// What a provider's client can do in this version of the crate.
///
/// Capabilities are per provider, not per client instance, and are the same whether or not the
/// provider's feature is enabled. An operation whose flag is false returns
/// [`Error::Unsupported`](crate::Error::Unsupported) before any network request.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Capabilities {
    /// [`Provider::list_zones`](crate::Provider::list_zones) is offered.
    pub list_zones: bool,
    /// [`Provider::list_rrsets`](crate::Provider::list_rrsets) is offered.
    pub list_rrsets: bool,
    /// [`Provider::get_rrset`](crate::Provider::get_rrset) is offered.
    pub get_rrset: bool,
    /// [`Provider::set_rrset`](crate::Provider::set_rrset) is offered.
    pub set_rrset: bool,
    /// [`Provider::delete_rrset`](crate::Provider::delete_rrset) is offered.
    pub delete_rrset: bool,
    /// [`Provider::add_txt_value`](crate::Provider::add_txt_value) is offered.
    pub add_txt_value: bool,
    /// [`Provider::remove_txt_value`](crate::Provider::remove_txt_value) is offered.
    pub remove_txt_value: bool,
    /// Types the record-level operations accept.
    pub record_types: TypeSet,
    /// Types within `record_types` that can be read but not written.
    pub read_only_types: &'static [RecordType],
    /// The TXT value operations accept only [`Txt::is_plain`](crate::Txt::is_plain) values.
    pub txt_plain_only: bool,
    /// What the TXT value operations guarantee against writers outside this process.
    pub txt_values: ValueGuarantee,
    /// How a write's precondition is checked.
    pub preconditions: Preconditions,
    /// Replacing an rrset is one request at the provider. False where the API works with
    /// individual records (or individual values) and a replacement is several requests, and
    /// where the API cannot replace a set at all. For a provider without record-level operations
    /// in this crate, the flag says what a set replacement is at the provider's API.
    pub atomic_rrset_write: bool,
    /// How TTLs can be set.
    pub ttl: TtlSupport,
    /// Whether an rrset can have the provider's default TTL instead of an explicit one
    /// ([`RrsetTtl::ProviderDefault`](crate::RrsetTtl::ProviderDefault)), and whether a write can
    /// ask for it (design section 3.6, `docs/design/03-semantics.md` in the repository).
    pub provider_default_ttl: ProviderDefaultTtl,
    /// Writes complete through a provider-side operation that the client polls.
    pub asynchronous: bool,
}

impl Capabilities {
    /// The operation is offered. [`Operation::Check`] is always offered:
    /// [`Provider::check`](crate::Provider::check) has no default body, so every client implements
    /// it.
    #[must_use]
    pub fn supports(&self, operation: Operation) -> bool {
        match operation {
            Operation::Check => true,
            Operation::ListZones => self.list_zones,
            Operation::ListRrsets => self.list_rrsets,
            Operation::GetRrset => self.get_rrset,
            Operation::SetRrset => self.set_rrset,
            Operation::DeleteRrset => self.delete_rrset,
            Operation::AddTxtValue => self.add_txt_value,
            Operation::RemoveTxtValue => self.remove_txt_value,
        }
    }

    /// The record-level read operations accept this type: it is in `record_types` and is not a
    /// query or meta type.
    #[must_use]
    pub fn can_read(&self, rtype: RecordType) -> bool {
        if rtype.is_meta() {
            return false;
        }
        match self.record_types {
            TypeSet::Listed(types) => types.contains(&rtype),
            TypeSet::AnyWithCode => rtype.code().is_some(),
        }
    }

    /// The record-level write operations accept this type: it can be read and is not in
    /// `read_only_types`.
    #[must_use]
    pub fn can_write(&self, rtype: RecordType) -> bool {
        self.can_read(rtype) && !self.read_only_types.contains(&rtype)
    }

    /// A write can ask for this TTL: a number within [`Capabilities::ttl`], or the provider's
    /// default where [`ProviderDefaultTtl::can_request`] holds. A write that asks for another
    /// TTL is [`Error::InvalidInput`](crate::Error::InvalidInput) before any request. At a
    /// [`ProviderDefaultTtl::ForNewRecords`] provider, a write that would turn an explicit TTL
    /// into the default is refused after its read all the same.
    #[must_use]
    pub fn accepts_ttl(&self, ttl: RrsetTtl) -> bool {
        match ttl {
            RrsetTtl::Explicit(ttl) => self.ttl.accepts(ttl.as_secs()),
            RrsetTtl::ProviderDefault => self.provider_default_ttl.can_request(),
        }
    }
}

/// A set of record types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TypeSet {
    /// Exactly these types. An empty list: no record-level support.
    Listed(&'static [RecordType]),
    /// Every type that has a type code and a wire form (a protocol-level client such as RFC
    /// 2136).
    AnyWithCode,
}

/// How a write's precondition ([`Expect`](crate::Expect)) is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Preconditions {
    /// The provider checks the precondition in the same request that writes.
    Atomic,
    /// The client reads, compares and then writes; a change by another writer between the read
    /// and the write is not detected.
    ReadThenWrite,
}

/// How TTLs can be set at a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TtlSupport {
    /// One TTL per rrset, within the given bounds (seconds).
    PerRrset {
        /// Smallest accepted TTL.
        min: u32,
        /// Largest accepted TTL.
        max: u32,
    },
    /// The API stores a TTL on every record. The crate writes the same TTL to all records of an
    /// rrset and reports the smallest one it reads; a requested TTL counts as already set only
    /// when every record has it.
    PerRecord {
        /// Smallest accepted TTL.
        min: u32,
        /// Largest accepted TTL.
        max: u32,
    },
    /// The provider chooses the TTL; a requested number is refused, and the provider's default
    /// is the only TTL a write can ask for.
    NotSettable,
}

impl TtlSupport {
    /// A requested TTL of `secs` seconds is accepted.
    #[must_use]
    pub fn accepts(&self, secs: u32) -> bool {
        match *self {
            TtlSupport::PerRrset { min, max } | TtlSupport::PerRecord { min, max } => {
                (min..=max).contains(&secs)
            }
            TtlSupport::NotSettable => false,
        }
    }
}

/// Whether an rrset can have no explicit TTL at a provider, the provider's default applying instead
/// (an "automatic" TTL, a zone default that applies while none is stored, or a TTL the provider
/// always chooses itself), and what a write can do about it (design section 3.6,
/// `docs/design/03-semantics.md` in the repository).
///
/// Where the provider's default exists, an rrset that has it reads as
/// [`RrsetTtl::ProviderDefault`](crate::RrsetTtl::ProviderDefault), and a write that states no
/// TTL keeps it. A write that asks for the provider's default where this does not allow it is
/// [`Error::InvalidInput`](crate::Error::InvalidInput), and a `ttl` setting that asks for it is
/// [`Error::Config`](crate::Error::Config).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderDefaultTtl {
    /// Every rrset has an explicit TTL. No read reports the provider's default, and every
    /// request for it is refused before any network request. A write that states no TTL keeps
    /// the TTL as read and gives a new rrset the client's `ttl` setting; where a read cannot
    /// state the TTL, the write sends the provider's value back where the client has it, and
    /// the `ttl` setting otherwise.
    Absent,
    /// An rrset can have the provider's default, and a write can ask for it where it creates
    /// records: a new rrset, or a value added to an rrset that has the default. The provider's
    /// API does not establish how an explicit TTL of an existing record is turned into the
    /// default, so a write that would have to do that is refused after its read and before any
    /// write.
    ForNewRecords,
    /// An rrset can have the provider's default, and every write can ask for it, also to turn
    /// an explicit TTL into it. Also the value of every provider whose TTL is
    /// [`TtlSupport::NotSettable`]: the provider's default is the only TTL there is.
    Requestable,
}

impl ProviderDefaultTtl {
    /// An rrset can have the provider's default TTL, and a read reports it.
    #[must_use]
    pub const fn exists(self) -> bool {
        !matches!(self, ProviderDefaultTtl::Absent)
    }

    /// A write, and the `ttl` setting, can ask for the provider's default for the records it
    /// creates.
    #[must_use]
    pub const fn can_request(self) -> bool {
        !matches!(self, ProviderDefaultTtl::Absent)
    }

    /// A write can turn an explicit TTL of an existing rrset or record into the provider's
    /// default.
    #[must_use]
    pub const fn can_replace_explicit(self) -> bool {
        matches!(self, ProviderDefaultTtl::Requestable)
    }
}

/// How far "a TXT value operation never overwrites or deletes a foreign value" holds when
/// someone outside this process writes to the same rrset at the same time
/// (design section 3.5, `docs/design/03-semantics.md` in the repository).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueGuarantee {
    /// Requests name only our value. Foreign values cannot be lost.
    PerValue,
    /// The whole set is written under a condition the provider checks. A concurrent change
    /// makes the write fail instead of being overwritten.
    Conditional,
    /// The whole set is written after a read, unconditionally. A value added by another writer
    /// between the read and the write is lost. The guarantee that a TXT value operation never
    /// overwrites or deletes a foreign value holds only inside one process.
    ReadThenWrite,
    /// The provider keeps a fixed number of most recent values and drops the oldest (acme-dns).
    Rotating,
    /// The provider has no TXT value operations in this crate.
    NotOffered,
}

#[cfg(test)]
mod tests {
    use super::{
        Capabilities, Preconditions, ProviderDefaultTtl, TtlSupport, TypeSet, ValueGuarantee,
    };
    use crate::error::Operation;
    use crate::record::{RecordType, RrsetTtl};

    const CAPS: Capabilities = Capabilities {
        list_zones: true,
        list_rrsets: true,
        get_rrset: true,
        set_rrset: false,
        delete_rrset: false,
        add_txt_value: true,
        remove_txt_value: false,
        record_types: TypeSet::Listed(&[RecordType::A, RecordType::TXT, RecordType::SOA]),
        read_only_types: &[RecordType::SOA],
        txt_plain_only: true,
        txt_values: ValueGuarantee::PerValue,
        preconditions: Preconditions::ReadThenWrite,
        atomic_rrset_write: false,
        ttl: TtlSupport::PerRrset { min: 60, max: 3600 },
        provider_default_ttl: ProviderDefaultTtl::Absent,
        asynchronous: false,
    };

    #[test]
    fn supports_follows_the_flags() {
        assert!(CAPS.supports(Operation::Check));
        assert!(CAPS.supports(Operation::ListZones));
        assert!(!CAPS.supports(Operation::SetRrset));
        assert!(CAPS.supports(Operation::AddTxtValue));
        assert!(!CAPS.supports(Operation::RemoveTxtValue));
    }

    #[test]
    fn type_checks() {
        assert!(CAPS.can_read(RecordType::A));
        assert!(CAPS.can_write(RecordType::A));
        assert!(CAPS.can_read(RecordType::SOA));
        assert!(!CAPS.can_write(RecordType::SOA));
        assert!(!CAPS.can_read(RecordType::MX));
        let any = Capabilities {
            record_types: TypeSet::AnyWithCode,
            ..CAPS
        };
        assert!(any.can_write(RecordType::from_code(65_280)));
        assert!(!any.can_read(RecordType::ALIAS));
        assert!(!any.can_read(RecordType::from_code(255)));
        assert!(!any.can_read(RecordType::from_code(41)));
        assert!(!any.can_read(RecordType::from_code(252)));
    }

    #[test]
    fn ttl_bounds() {
        assert!(CAPS.ttl.accepts(60));
        assert!(CAPS.ttl.accepts(3600));
        assert!(!CAPS.ttl.accepts(59));
        assert!(!TtlSupport::NotSettable.accepts(60));
        let explicit = |secs| RrsetTtl::from_secs(secs).unwrap();
        assert!(CAPS.accepts_ttl(explicit(60)));
        assert!(!CAPS.accepts_ttl(explicit(59)));
        assert!(!CAPS.accepts_ttl(RrsetTtl::ProviderDefault));
        let with_default = Capabilities {
            provider_default_ttl: ProviderDefaultTtl::ForNewRecords,
            ..CAPS
        };
        assert!(with_default.accepts_ttl(RrsetTtl::ProviderDefault));
        assert!(!with_default.accepts_ttl(explicit(3601)));
    }

    #[test]
    fn provider_default_levels() {
        let absent = ProviderDefaultTtl::Absent;
        let new = ProviderDefaultTtl::ForNewRecords;
        let all = ProviderDefaultTtl::Requestable;
        assert!(!absent.exists() && !absent.can_request() && !absent.can_replace_explicit());
        assert!(new.exists() && new.can_request() && !new.can_replace_explicit());
        assert!(all.exists() && all.can_request() && all.can_replace_explicit());
    }
}
