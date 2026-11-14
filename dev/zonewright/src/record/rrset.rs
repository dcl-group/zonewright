//! Rrsets: all records of one owner name and type.

use super::{RecordData, RecordError, RecordType, Ttl};
use crate::name::DomainName;

/// All records of one owner name and type.
///
/// Members are kept sorted by their text without duplicates, so two sets with the same members
/// are equal. `==` compares name, type, members and TTL; [`RrSet::same_records`] ignores the TTL.
///
/// Serialized as `{ "name", "type", "ttl", "records": [...] }`. A canonical record is a string,
/// parsed with [`RecordData::parse`] for the set's type; a non-canonical one is
/// `{ "raw": text }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RrSet {
    name: DomainName,
    rtype: RecordType,
    ttl: Option<Ttl>,
    records: Vec<RecordData>,
}

impl RrSet {
    /// `records` must not be empty. Duplicates are removed and the records are kept sorted by
    /// their text, so two sets with the same members are equal. Every canonical member is
    /// parsed again for `rtype` and must give the same text. CNAME, SOA, DNAME, ALIAS and ANAME
    /// sets hold exactly one record.
    pub fn new(
        name: DomainName,
        rtype: RecordType,
        ttl: Option<Ttl>,
        records: impl IntoIterator<Item = RecordData>,
    ) -> Result<RrSet, RecordError> {
        let mut records: Vec<RecordData> = records.into_iter().collect();
        if records.is_empty() {
            return Err(RecordError::EmptySet);
        }
        for (index, record) in records.iter().enumerate() {
            if !record.is_canonical() {
                continue;
            }
            let reparsed =
                RecordData::parse(rtype, record.as_str()).map_err(|_| RecordError::Syntax {
                    detail: format!("record {} is not valid data for the type", index + 1),
                })?;
            if reparsed.as_str() != record.as_str() {
                return Err(RecordError::Syntax {
                    detail: format!("record {} is not canonical data for the type", index + 1),
                });
            }
        }
        records.sort();
        records.dedup();
        if singleton(rtype) && records.len() > 1 {
            return Err(RecordError::NotSingleton);
        }
        Ok(RrSet {
            name,
            rtype,
            ttl,
            records,
        })
    }

    /// The owner name.
    pub fn name(&self) -> &DomainName {
        &self.name
    }

    /// The record type.
    pub fn rtype(&self) -> RecordType {
        self.rtype
    }

    /// In a set read from a provider, `None` means the provider does not report a TTL. In a set
    /// passed to a write, `None` means "keep the TTL of the existing rrset; for a new rrset use
    /// the client's configured default".
    pub fn ttl(&self) -> Option<Ttl> {
        self.ttl
    }

    /// The members, sorted by text, without duplicates.
    pub fn records(&self) -> &[RecordData] {
        &self.records
    }

    /// The set has a member with exactly this text and canonical flag.
    pub fn contains(&self, record: &RecordData) -> bool {
        self.records.binary_search(record).is_ok()
    }

    /// Same name, type and members; TTL ignored.
    pub fn same_records(&self, other: &RrSet) -> bool {
        self.name == other.name && self.rtype == other.rtype && self.records == other.records
    }

    /// The same set with another TTL.
    pub fn with_ttl(self, ttl: Option<Ttl>) -> RrSet {
        RrSet { ttl, ..self }
    }
}

/// The types whose rrset holds exactly one record: CNAME, SOA, DNAME, ALIAS and ANAME.
pub(crate) fn singleton(rtype: RecordType) -> bool {
    matches!(
        rtype,
        RecordType::CNAME
            | RecordType::SOA
            | RecordType::DNAME
            | RecordType::ALIAS
            | RecordType::ANAME
    )
}

/// Serialized shape of an rrset.
#[derive(serde::Serialize)]
struct RrSetOut<'a> {
    name: &'a DomainName,
    #[serde(rename = "type")]
    rtype: RecordType,
    ttl: Option<Ttl>,
    records: &'a [RecordData],
}

/// Deserialized shape of an rrset.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RrSetIn {
    name: DomainName,
    #[serde(rename = "type")]
    rtype: RecordType,
    #[serde(default)]
    ttl: Option<Ttl>,
    records: Vec<RecordIn>,
}

/// A member as stored: canonical text, or `{ "raw": text }`.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum RecordIn {
    Text(String),
    Raw(RawRecord),
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecord {
    raw: String,
}

impl serde::Serialize for RrSet {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RrSetOut {
            name: &self.name,
            rtype: self.rtype,
            ttl: self.ttl,
            records: &self.records,
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for RrSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let input = RrSetIn::deserialize(deserializer)?;
        let mut records = Vec::with_capacity(input.records.len());
        for record in input.records {
            let data = match record {
                RecordIn::Text(text) => {
                    RecordData::parse(input.rtype, &text).map_err(D::Error::custom)?
                }
                // Text that parses for the set's type is stored as canonical, so equality never
                // depends on how a value arrived.
                RecordIn::Raw(raw) => RecordData::parse(input.rtype, &raw.raw)
                    .unwrap_or_else(|_| RecordData::non_canonical(&raw.raw)),
            };
            records.push(data);
        }
        RrSet::new(input.name, input.rtype, input.ttl, records).map_err(D::Error::custom)
    }
}
