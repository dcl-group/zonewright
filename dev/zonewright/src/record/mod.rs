//! The record model: record types, TTLs, record data in canonical text form and rrsets.
//!
//! Record values are carried as zone-file text (RFC 1035 section 5) in one canonical spelling
//! per type, so a value read from a provider and a value seen on the wire compare equal exactly
//! when they are the same record. Typed views exist for TXT, MX, SRV, CAA, TLSA and SVCB/HTTPS.

mod caa;
mod data;
mod mx;
mod rrset;
mod rtype;
mod srv;
mod svcb;
mod text;
mod tlsa;
mod ttl;
mod txt;
mod wire;

pub use caa::Caa;
pub use data::RecordData;
pub use mx::Mx;
pub use rrset::RrSet;
pub use rtype::RecordType;
pub use srv::Srv;
pub use svcb::{SvcParam, Svcb};
pub use tlsa::Tlsa;
pub use ttl::Ttl;
pub use txt::Txt;

use crate::name::NameError;

/// An error in a record type, a TTL, record data or an rrset.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecordError {
    /// The string is not a known record type mnemonic, pseudo-type or `TYPE<code>`.
    #[error("unknown record type")]
    UnknownType,
    /// Text or wire data is not valid for the record type. `detail` names the position and kind
    /// of the problem and never quotes the input.
    #[error("invalid record data: {detail}")]
    Syntax {
        /// What is wrong and where.
        detail: String,
    },
    /// A numeric field is outside its range.
    #[error("the value of {field} is out of range")]
    OutOfRange {
        /// The field.
        field: &'static str,
    },
    /// The RDATA would exceed 65535 octets, or a character-string 255 octets.
    #[error("the record data is too long")]
    TooLong,
    /// A domain name inside RDATA is invalid.
    #[error("invalid domain name in record data: {0}")]
    Name(NameError),
    /// `RrSet::new` was given no records.
    #[error("an rrset needs at least one record")]
    EmptySet,
    /// More than one record for CNAME, SOA, DNAME, ALIAS or ANAME.
    #[error("this record type allows only one record per rrset")]
    NotSingleton,
    /// An operation that needs canonical data got raw provider text.
    #[error("the record data is not in canonical form")]
    NotCanonical,
}
