//! Record types and the IANA mnemonic table.

use std::fmt;
use std::str::FromStr;

use super::RecordError;

/// A DNS record type: any 16-bit type code, plus the provider pseudo-types that have no code.
///
/// `Display` prints the IANA registry mnemonic for a registered code and `TYPE<code>`
/// (RFC 3597) for any other. `FromStr` is case-insensitive and accepts the registry mnemonics,
/// the pseudo-type names `ALIAS` and `ANAME`, and `TYPE<code>`; `TYPE1` and `A` are the same
/// value. Any other string is [`RecordError::UnknownType`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordType(Repr);

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Repr {
    Code(u16),
    Alias,
    Aname,
}

impl RecordType {
    /// IPv4 address (RFC 1035).
    pub const A: RecordType = RecordType::from_code(1);
    /// IPv6 address (RFC 3596).
    pub const AAAA: RecordType = RecordType::from_code(28);
    /// Name server (RFC 1035).
    pub const NS: RecordType = RecordType::from_code(2);
    /// Canonical name (RFC 1035).
    pub const CNAME: RecordType = RecordType::from_code(5);
    /// Start of authority (RFC 1035).
    pub const SOA: RecordType = RecordType::from_code(6);
    /// Domain name pointer (RFC 1035).
    pub const PTR: RecordType = RecordType::from_code(12);
    /// Mail exchange (RFC 1035).
    pub const MX: RecordType = RecordType::from_code(15);
    /// Text (RFC 1035).
    pub const TXT: RecordType = RecordType::from_code(16);
    /// Service location (RFC 2782).
    pub const SRV: RecordType = RecordType::from_code(33);
    /// Delegation name (RFC 6672).
    pub const DNAME: RecordType = RecordType::from_code(39);
    /// Certification authority authorization (RFC 8659).
    pub const CAA: RecordType = RecordType::from_code(257);
    /// TLS certificate association (RFC 6698).
    pub const TLSA: RecordType = RecordType::from_code(52);
    /// SSH key fingerprint (RFC 4255).
    pub const SSHFP: RecordType = RecordType::from_code(44);
    /// Service binding (RFC 9460).
    pub const SVCB: RecordType = RecordType::from_code(64);
    /// HTTPS service binding (RFC 9460).
    pub const HTTPS: RecordType = RecordType::from_code(65);
    /// Provider pseudo-type: address records synthesized from a target name. No type code.
    pub const ALIAS: RecordType = RecordType(Repr::Alias);
    /// Provider pseudo-type: address records synthesized from a target name. No type code.
    pub const ANAME: RecordType = RecordType(Repr::Aname);

    /// The type with this code.
    pub const fn from_code(code: u16) -> RecordType {
        RecordType(Repr::Code(code))
    }

    /// The type code; `None` for pseudo-types.
    pub const fn code(self) -> Option<u16> {
        match self.0 {
            Repr::Code(code) => Some(code),
            Repr::Alias | Repr::Aname => None,
        }
    }

    /// True for ALIAS and ANAME.
    pub(crate) const fn is_pseudo(self) -> bool {
        matches!(self.0, Repr::Alias | Repr::Aname)
    }

    /// True for types that cannot be the type of an rrset at a provider: the reserved code 0,
    /// OPT (41), and the range 128 ..= 255 that RFC 6895 section 3.1 reserves for query and meta
    /// types (TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY and future ones). Every operation
    /// rejects them with `Error::InvalidInput` (design section 2.2).
    pub(crate) const fn is_meta(self) -> bool {
        match self.0 {
            Repr::Code(code) => code == 0 || code == 41 || (code >= 128 && code <= 255),
            Repr::Alias | Repr::Aname => false,
        }
    }
}

/// Mnemonics of the IANA "Resource Record (RR) TYPEs" registry, sorted by code.
///
/// Registry state of 2026-11-09 (the registry's "last updated" date), taken from
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv>. One departure: the
/// registry's mnemonic for 255 is `*`; it is printed as `ANY`, the spelling of zone files and
/// tools, and `*` is accepted on input.
#[rustfmt::skip]
const MNEMONICS: &[(u16, &str)] = &[
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

fn mnemonic(code: u16) -> Option<&'static str> {
    MNEMONICS
        .binary_search_by_key(&code, |&(c, _)| c)
        .ok()
        .and_then(|index| MNEMONICS.get(index))
        .map(|&(_, name)| name)
}

impl FromStr for RecordType {
    type Err = RecordError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("ALIAS") {
            return Ok(RecordType::ALIAS);
        }
        if s.eq_ignore_ascii_case("ANAME") {
            return Ok(RecordType::ANAME);
        }
        if s == "*" {
            return Ok(RecordType::from_code(255));
        }
        if let Some(&(code, _)) = MNEMONICS
            .iter()
            .find(|(_, name)| name.eq_ignore_ascii_case(s))
        {
            return Ok(RecordType::from_code(code));
        }
        let prefix = s.get(..4).ok_or(RecordError::UnknownType)?;
        let digits = s.get(4..).ok_or(RecordError::UnknownType)?;
        if !prefix.eq_ignore_ascii_case("TYPE")
            || digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(RecordError::UnknownType);
        }
        let code: u16 = digits.parse().map_err(|_| RecordError::UnknownType)?;
        Ok(RecordType::from_code(code))
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Repr::Alias => f.write_str("ALIAS"),
            Repr::Aname => f.write_str("ANAME"),
            Repr::Code(code) => match mnemonic(code) {
                Some(name) => f.write_str(name),
                None => write!(f, "TYPE{code}"),
            },
        }
    }
}

impl fmt::Debug for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordType({self})")
    }
}

impl serde::Serialize for RecordType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for RecordType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::MNEMONICS;

    #[test]
    fn table_is_sorted_and_unique() {
        for pair in MNEMONICS.windows(2) {
            assert!(pair[0].0 < pair[1].0);
        }
        for (i, a) in MNEMONICS.iter().enumerate() {
            for b in &MNEMONICS[i + 1..] {
                assert!(!a.1.eq_ignore_ascii_case(b.1));
            }
        }
    }
}
