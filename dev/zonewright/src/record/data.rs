//! `RecordData` and the per-type dispatch between text, wire and canonical form
//! (design sections 2.2 and 4).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::text::{self, Token, syntax};
use super::wire::{MAX_RDATA, Reader};
use super::{Caa, Mx, RecordError, RecordType, Srv, Svcb, Tlsa, Txt};
use crate::name::{DomainName, TargetName};

/// The RDATA of one record in normalized zone-file text form (design section 4).
///
/// Two values are equal exactly when their text (and canonical flag) is equal. `RecordData` does
/// not know its type; the [`RrSet`](super::RrSet) holding it does.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordData {
    text: String,
    canonical: bool,
}

impl RecordData {
    /// Strict parse of presentation-format RDATA. Domain names without a trailing dot are taken
    /// as absolute. Fails for text that is not valid for `rtype`.
    pub fn parse(rtype: RecordType, text: &str) -> Result<RecordData, RecordError> {
        Rdata::parse_text(rtype, text, None)?.into_data()
    }

    /// Zone-file semantics: a domain name without a trailing dot is relative to `origin`,
    /// and "@" is `origin`.
    pub fn parse_relative(
        rtype: RecordType,
        text: &str,
        origin: &DomainName,
    ) -> Result<RecordData, RecordError> {
        Rdata::parse_text(rtype, text, Some(origin))?.into_data()
    }

    /// From uncompressed wire-format RDATA. Pseudo-types have no wire form.
    pub fn from_wire(rtype: RecordType, rdata: &[u8]) -> Result<RecordData, RecordError> {
        if rtype.is_pseudo() {
            return Err(syntax("pseudo-types have no wire form"));
        }
        if rdata.len() > MAX_RDATA {
            return Err(RecordError::TooLong);
        }
        Rdata::decode_wire(Kind::of(rtype), rdata)?.into_data()
    }

    /// Wire-format RDATA without name compression. Fails for non-canonical data and
    /// pseudo-types.
    pub fn to_wire(&self, rtype: RecordType) -> Result<Vec<u8>, RecordError> {
        if !self.canonical {
            return Err(RecordError::NotCanonical);
        }
        if rtype.is_pseudo() {
            return Err(syntax("pseudo-types have no wire form"));
        }
        Rdata::parse_text(rtype, &self.text, None)?
            .normalize()?
            .encode_wire()
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// False for a value a provider returned that the crate could not parse (design section
    /// 4.9).
    pub fn is_canonical(&self) -> bool {
        self.canonical
    }

    /// Provider text that could not be parsed, kept trimmed of surrounding whitespace.
    pub(crate) fn non_canonical(text: &str) -> RecordData {
        RecordData {
            text: text.trim().to_owned(),
            canonical: false,
        }
    }

    /// Parses this value's text as `rtype` for a typed view; `NotCanonical` for raw text.
    pub(crate) fn rdata(&self, rtype: RecordType) -> Result<Rdata, RecordError> {
        if !self.canonical {
            return Err(RecordError::NotCanonical);
        }
        Rdata::parse_text(rtype, &self.text, None)
    }
}

impl fmt::Display for RecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for RecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.canonical {
            write!(f, "RecordData({:?})", self.text)
        } else {
            write!(f, "RecordData(raw {:?})", self.text)
        }
    }
}

impl serde::Serialize for RecordData {
    /// Canonical data as a string; non-canonical data as `{ "raw": text }`.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        if self.canonical {
            serializer.serialize_str(&self.text)
        } else {
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry("raw", &self.text)?;
            map.end()
        }
    }
}

/// Which canonical form a type has (design section 4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    A,
    Aaaa,
    Name,
    Mx,
    Srv,
    Txt,
    Caa,
    Tlsa,
    Sshfp,
    Svcb,
    Soa,
    Generic,
}

impl Kind {
    pub(crate) fn of(rtype: RecordType) -> Kind {
        if rtype.is_pseudo() {
            return Kind::Name;
        }
        match rtype {
            RecordType::A => Kind::A,
            RecordType::AAAA => Kind::Aaaa,
            RecordType::NS | RecordType::CNAME | RecordType::PTR | RecordType::DNAME => Kind::Name,
            RecordType::MX => Kind::Mx,
            RecordType::SRV => Kind::Srv,
            RecordType::TXT => Kind::Txt,
            RecordType::CAA => Kind::Caa,
            RecordType::TLSA => Kind::Tlsa,
            RecordType::SSHFP => Kind::Sshfp,
            RecordType::SVCB | RecordType::HTTPS => Kind::Svcb,
            RecordType::SOA => Kind::Soa,
            _ => Kind::Generic,
        }
    }
}

/// SSHFP RDATA (RFC 4255).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sshfp {
    algorithm: u8,
    fp_type: u8,
    fingerprint: Vec<u8>,
}

/// SOA RDATA (RFC 1035 section 3.3.13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Soa {
    mname: TargetName,
    rname: TargetName,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

/// Parsed RDATA of one record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Rdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Name(TargetName),
    Mx(Mx),
    Srv(Srv),
    Txt(Txt),
    Caa(Caa),
    Tlsa(Tlsa),
    Sshfp(Sshfp),
    Svcb(Svcb),
    Soa(Soa),
    Generic(Vec<u8>),
}

/// Requires exactly `count` fields.
pub(crate) fn expect_fields(tokens: &[Token<'_>], count: usize) -> Result<(), RecordError> {
    if tokens.len() == count {
        Ok(())
    } else {
        Err(syntax(format!(
            "expected {count} fields, found {}",
            tokens.len()
        )))
    }
}

/// Requires at least `count` fields.
pub(crate) fn expect_min_fields(tokens: &[Token<'_>], count: usize) -> Result<(), RecordError> {
    if tokens.len() >= count {
        Ok(())
    } else {
        Err(syntax(format!(
            "expected at least {count} fields, found {}",
            tokens.len()
        )))
    }
}

/// The field at `index`, which the caller has checked exists.
pub(crate) fn field<'t, 'a>(
    tokens: &'t [Token<'a>],
    index: usize,
) -> Result<&'t Token<'a>, RecordError> {
    tokens
        .get(index)
        .ok_or_else(|| syntax(format!("field {} is missing", index + 1)))
}

/// A domain-name field. With `origin`, zone-file semantics; without, absolute and `@` refused.
pub(crate) fn parse_name(
    token: &Token<'_>,
    origin: Option<&DomainName>,
) -> Result<TargetName, RecordError> {
    let text = token.plain("a domain name")?;
    let name = match origin {
        Some(origin) => TargetName::from_relative(text, origin),
        None => TargetName::parse(text),
    };
    name.map_err(RecordError::Name)
}

impl Rdata {
    /// Parses presentation text for `rtype`, including the RFC 3597 generic form.
    pub(crate) fn parse_text(
        rtype: RecordType,
        input: &str,
        origin: Option<&DomainName>,
    ) -> Result<Rdata, RecordError> {
        let kind = Kind::of(rtype);
        let tokens = text::tokenize(input)?;
        if tokens.is_empty() {
            return Err(syntax("no data"));
        }
        if tokens
            .first()
            .is_some_and(|token| token.is_plain() && token.text == "\\#")
        {
            if rtype.is_pseudo() {
                return Err(syntax("pseudo-types have no generic form"));
            }
            let data = parse_generic(&tokens)?;
            return Rdata::decode_wire(kind, &data);
        }
        let tokens = tokens.as_slice();
        let rdata = match kind {
            Kind::A => {
                expect_fields(tokens, 1)?;
                let token = field(tokens, 0)?;
                let address = text::parse_ipv4(token.plain("an IPv4 address")?)
                    .ok_or_else(|| syntax("field 1: not an IPv4 address in dotted decimal"))?;
                Rdata::A(address)
            }
            Kind::Aaaa => {
                expect_fields(tokens, 1)?;
                let token = field(tokens, 0)?;
                let address = text::parse_ipv6(token.plain("an IPv6 address")?)
                    .ok_or_else(|| syntax("field 1: not an IPv6 address"))?;
                Rdata::Aaaa(address)
            }
            Kind::Name => {
                expect_fields(tokens, 1)?;
                Rdata::Name(parse_name(field(tokens, 0)?, origin)?)
            }
            Kind::Mx => Rdata::Mx(Mx::parse_tokens(tokens, origin)?),
            Kind::Srv => Rdata::Srv(Srv::parse_tokens(tokens, origin)?),
            Kind::Txt => Rdata::Txt(Txt::parse_tokens(tokens)?),
            Kind::Caa => Rdata::Caa(Caa::parse_tokens(tokens)?),
            Kind::Tlsa => Rdata::Tlsa(Tlsa::parse_tokens(tokens)?),
            Kind::Sshfp => {
                expect_min_fields(tokens, 3)?;
                let fingerprint =
                    text::decode_hex(tokens.get(2..).unwrap_or_default(), "fingerprint")?;
                Rdata::Sshfp(Sshfp {
                    algorithm: text::parse_u8(field(tokens, 0)?, "algorithm")?,
                    fp_type: text::parse_u8(field(tokens, 1)?, "fingerprint type")?,
                    fingerprint,
                })
            }
            Kind::Svcb => Rdata::Svcb(Svcb::parse_tokens(tokens, origin)?),
            Kind::Soa => {
                expect_fields(tokens, 7)?;
                Rdata::Soa(Soa {
                    mname: parse_name(field(tokens, 0)?, origin)?,
                    rname: parse_name(field(tokens, 1)?, origin)?,
                    serial: text::parse_u32(field(tokens, 2)?, "serial")?,
                    refresh: text::parse_seconds(field(tokens, 3)?, "refresh")?,
                    retry: text::parse_seconds(field(tokens, 4)?, "retry")?,
                    expire: text::parse_seconds(field(tokens, 5)?, "expire")?,
                    minimum: text::parse_seconds(field(tokens, 6)?, "minimum")?,
                })
            }
            Kind::Generic => {
                return Err(syntax(
                    "a type without its own canonical form needs the generic form \\# <length> <hex>",
                ));
            }
        };
        rdata.normalize()
    }

    /// Decodes uncompressed wire-format RDATA.
    pub(crate) fn decode_wire(kind: Kind, data: &[u8]) -> Result<Rdata, RecordError> {
        let mut reader = Reader::new(data);
        let rdata = match kind {
            Kind::A => {
                let octets: [u8; 4] = reader
                    .bytes(4)?
                    .try_into()
                    .map_err(|_| syntax("an A record has 4 octets"))?;
                Rdata::A(Ipv4Addr::from(octets))
            }
            Kind::Aaaa => {
                let octets: [u8; 16] = reader
                    .bytes(16)?
                    .try_into()
                    .map_err(|_| syntax("an AAAA record has 16 octets"))?;
                Rdata::Aaaa(Ipv6Addr::from(octets))
            }
            Kind::Name => Rdata::Name(reader.name()?),
            Kind::Mx => Rdata::Mx(Mx::decode(&mut reader)?),
            Kind::Srv => Rdata::Srv(Srv::decode(&mut reader)?),
            Kind::Txt => Rdata::Txt(Txt::decode(&mut reader)?),
            Kind::Caa => Rdata::Caa(Caa::decode(&mut reader)?),
            Kind::Tlsa => Rdata::Tlsa(Tlsa::decode(&mut reader)?),
            Kind::Sshfp => {
                let algorithm = reader.u8()?;
                let fp_type = reader.u8()?;
                let fingerprint = reader.rest().to_vec();
                if fingerprint.is_empty() {
                    return Err(syntax(
                        "an SSHFP record needs at least one fingerprint octet",
                    ));
                }
                Rdata::Sshfp(Sshfp {
                    algorithm,
                    fp_type,
                    fingerprint,
                })
            }
            Kind::Svcb => Rdata::Svcb(Svcb::decode(&mut reader)?),
            Kind::Soa => Rdata::Soa(Soa {
                mname: reader.name()?,
                rname: reader.name()?,
                serial: reader.u32()?,
                refresh: reader.u32()?,
                retry: reader.u32()?,
                expire: reader.u32()?,
                minimum: reader.u32()?,
            }),
            Kind::Generic => Rdata::Generic(reader.rest().to_vec()),
        };
        reader.finish()?;
        rdata.normalize()
    }

    /// Brings typed values into canonical shape (SVCB parameter order and named keys) and
    /// checks field values that text and wire parsing cannot produce.
    pub(crate) fn normalize(self) -> Result<Rdata, RecordError> {
        Ok(match self {
            Rdata::Svcb(svcb) => Rdata::Svcb(svcb.normalized()?),
            other => other,
        })
    }

    /// Encodes wire-format RDATA. Fails for field values without a valid encoding and for data
    /// over 65535 octets.
    pub(crate) fn encode_wire(&self) -> Result<Vec<u8>, RecordError> {
        let mut out = Vec::new();
        match self {
            Rdata::A(address) => out.extend_from_slice(&address.octets()),
            Rdata::Aaaa(address) => out.extend_from_slice(&address.octets()),
            Rdata::Name(name) => out.extend_from_slice(name.wire()),
            Rdata::Mx(mx) => mx.encode(&mut out),
            Rdata::Srv(srv) => srv.encode(&mut out),
            Rdata::Txt(txt) => txt.encode(&mut out)?,
            Rdata::Caa(caa) => caa.encode(&mut out)?,
            Rdata::Tlsa(tlsa) => tlsa.encode(&mut out)?,
            Rdata::Sshfp(sshfp) => {
                if sshfp.fingerprint.is_empty() {
                    return Err(syntax(
                        "an SSHFP record needs at least one fingerprint octet",
                    ));
                }
                out.push(sshfp.algorithm);
                out.push(sshfp.fp_type);
                out.extend_from_slice(&sshfp.fingerprint);
            }
            Rdata::Svcb(svcb) => svcb.encode(&mut out)?,
            Rdata::Soa(soa) => {
                out.extend_from_slice(soa.mname.wire());
                out.extend_from_slice(soa.rname.wire());
                for value in [soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
            Rdata::Generic(data) => out.extend_from_slice(data),
        }
        if out.len() > MAX_RDATA {
            return Err(RecordError::TooLong);
        }
        Ok(out)
    }

    /// Writes the canonical text. Call only on normalized, encodable values.
    fn write_text(&self) -> String {
        let mut out = String::new();
        match self {
            Rdata::A(address) => out.push_str(&address.to_string()),
            Rdata::Aaaa(address) => out.push_str(&address.to_string()),
            Rdata::Name(name) => out.push_str(name.as_str()),
            Rdata::Mx(mx) => mx.write_text(&mut out),
            Rdata::Srv(srv) => srv.write_text(&mut out),
            Rdata::Txt(txt) => txt.write_text(&mut out),
            Rdata::Caa(caa) => caa.write_text(&mut out),
            Rdata::Tlsa(tlsa) => tlsa.write_text(&mut out),
            Rdata::Sshfp(sshfp) => {
                out.push_str(&format!("{} {} ", sshfp.algorithm, sshfp.fp_type));
                text::hex_into(&mut out, &sshfp.fingerprint);
            }
            Rdata::Svcb(svcb) => svcb.write_text(&mut out),
            Rdata::Soa(soa) => out.push_str(&format!(
                "{} {} {} {} {} {} {}",
                soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
            )),
            Rdata::Generic(data) => {
                out.push_str(&format!("\\# {}", data.len()));
                if !data.is_empty() {
                    out.push(' ');
                    text::hex_into(&mut out, data);
                }
            }
        }
        out
    }

    /// Normalizes, validates and produces canonical `RecordData`.
    pub(crate) fn into_data(self) -> Result<RecordData, RecordError> {
        let rdata = self.normalize()?;
        rdata.encode_wire()?;
        Ok(RecordData {
            text: rdata.write_text(),
            canonical: true,
        })
    }
}

/// Parses the RFC 3597 generic form `\# <length> <hex>`; the first field has been checked.
fn parse_generic(tokens: &[Token<'_>]) -> Result<Vec<u8>, RecordError> {
    expect_min_fields(tokens, 2)?;
    let length = text::parse_decimal(field(tokens, 1)?, "length", MAX_RDATA as u64)?;
    let data = text::decode_hex(tokens.get(2..).unwrap_or_default(), "generic data")?;
    if data.len() as u64 != length {
        return Err(syntax(
            "the length of the generic form does not match its data",
        ));
    }
    Ok(data)
}
