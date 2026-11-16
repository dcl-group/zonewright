//! SVCB and HTTPS data (RFC 9460, design section 4.6).

use std::net::{Ipv4Addr, Ipv6Addr};

use super::data::{Rdata, expect_min_fields, field, parse_name};
use super::text::{self, Token, syntax};
use super::wire::{self, Reader};
use super::{RecordData, RecordError, RecordType};
use crate::name::{DomainName, TargetName};

/// Key numbers of the parameters RFC 9460 defines.
const MANDATORY: u16 = 0;
const ALPN: u16 = 1;
const NO_DEFAULT_ALPN: u16 = 2;
const PORT: u16 = 3;
const IPV4HINT: u16 = 4;
const ECH: u16 = 5;
const IPV6HINT: u16 = 6;
/// Reserved as the "invalid key" (RFC 9460 section 14.3.2).
const INVALID_KEY: u16 = 65_535;

/// RDATA shared by SVCB and HTTPS (RFC 9460).
///
/// The canonical text writes the parameters in ascending order of their numeric key;
/// [`Svcb::to_data`] fails for duplicate keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Svcb {
    /// 0 is alias mode; any other value is service mode.
    pub priority: u16,
    /// The target; `.` means the owner name in service mode.
    pub target: TargetName,
    /// Service parameters.
    pub params: Vec<SvcParam>,
}

/// One service parameter of SVCB or HTTPS data (RFC 9460 section 7).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SvcParam {
    /// `mandatory` (key 0): keys a client must understand.
    Mandatory(Vec<u16>),
    /// `alpn` (key 1): ALPN protocol identifiers, each 1 to 255 octets.
    Alpn(Vec<Vec<u8>>),
    /// `no-default-alpn` (key 2).
    NoDefaultAlpn,
    /// `port` (key 3).
    Port(u16),
    /// `ipv4hint` (key 4).
    Ipv4Hint(Vec<Ipv4Addr>),
    /// `ech` (key 5): an ECHConfigList.
    Ech(Vec<u8>),
    /// `ipv6hint` (key 6).
    Ipv6Hint(Vec<Ipv6Addr>),
    /// Any other key, with its value in wire form.
    Other {
        /// The key number.
        key: u16,
        /// The value in wire form.
        value: Vec<u8>,
    },
}

impl SvcParam {
    fn key(&self) -> u16 {
        match self {
            SvcParam::Mandatory(_) => MANDATORY,
            SvcParam::Alpn(_) => ALPN,
            SvcParam::NoDefaultAlpn => NO_DEFAULT_ALPN,
            SvcParam::Port(_) => PORT,
            SvcParam::Ipv4Hint(_) => IPV4HINT,
            SvcParam::Ech(_) => ECH,
            SvcParam::Ipv6Hint(_) => IPV6HINT,
            SvcParam::Other { key, .. } => *key,
        }
    }

    /// Checks the value and brings it into canonical shape: a defined key given as `Other` is
    /// decoded into its own variant, and the `mandatory` list is sorted.
    fn normalized(self) -> Result<SvcParam, RecordError> {
        let param = match self {
            SvcParam::Other { key, value } if key <= IPV6HINT => decode_value(key, &value)?,
            other => other,
        };
        match &param {
            SvcParam::Mandatory(keys) => {
                if keys.is_empty() {
                    return Err(syntax("the mandatory parameter lists no keys"));
                }
                let mut sorted = keys.clone();
                sorted.sort_unstable();
                if sorted.windows(2).any(|pair| pair.first() == pair.get(1)) {
                    return Err(syntax("the mandatory parameter lists a key twice"));
                }
                if sorted.contains(&MANDATORY) || sorted.contains(&INVALID_KEY) {
                    return Err(syntax(
                        "the mandatory parameter lists a key it may not list",
                    ));
                }
                return Ok(SvcParam::Mandatory(sorted));
            }
            SvcParam::Alpn(ids) => {
                if ids.is_empty() {
                    return Err(syntax("the alpn parameter lists no protocols"));
                }
                if ids.iter().any(Vec::is_empty) {
                    return Err(syntax("an alpn protocol identifier is empty"));
                }
                if ids.iter().any(|id| id.len() > 255) {
                    return Err(RecordError::TooLong);
                }
            }
            SvcParam::Ipv4Hint(addresses) if addresses.is_empty() => {
                return Err(syntax("the ipv4hint parameter lists no addresses"));
            }
            SvcParam::Ipv6Hint(addresses) if addresses.is_empty() => {
                return Err(syntax("the ipv6hint parameter lists no addresses"));
            }
            SvcParam::Ech(config) if config.is_empty() => {
                return Err(syntax("the ech parameter is empty"));
            }
            SvcParam::Other { key, .. } if *key == INVALID_KEY => {
                return Err(syntax("the parameter key 65535 is reserved as invalid"));
            }
            _ => {}
        }
        Ok(param)
    }

    /// The value in wire form.
    fn encode_value(&self) -> Result<Vec<u8>, RecordError> {
        let mut out = Vec::new();
        match self {
            SvcParam::Mandatory(keys) => {
                for key in keys {
                    out.extend_from_slice(&key.to_be_bytes());
                }
            }
            SvcParam::Alpn(ids) => {
                for id in ids {
                    wire::push_character_string(&mut out, id)?;
                }
            }
            SvcParam::NoDefaultAlpn => {}
            SvcParam::Port(port) => out.extend_from_slice(&port.to_be_bytes()),
            SvcParam::Ipv4Hint(addresses) => {
                for address in addresses {
                    out.extend_from_slice(&address.octets());
                }
            }
            SvcParam::Ech(config) => out.extend_from_slice(config),
            SvcParam::Ipv6Hint(addresses) => {
                for address in addresses {
                    out.extend_from_slice(&address.octets());
                }
            }
            SvcParam::Other { value, .. } => out.extend_from_slice(value),
        }
        Ok(out)
    }

    /// Writes `key=value` in canonical presentation form.
    fn write_text(&self, out: &mut String) {
        match self {
            SvcParam::Mandatory(keys) => {
                out.push_str("mandatory=");
                let names: Vec<String> = keys.iter().map(|&key| key_name(key)).collect();
                out.push_str(&names.join(","));
            }
            SvcParam::Alpn(ids) => {
                // Two levels of escaping (RFC 9460 appendix A.1): commas and backslashes inside
                // an identifier are escaped within the value list, and the list is then written
                // as one character-string.
                let mut list = Vec::new();
                for (index, id) in ids.iter().enumerate() {
                    if index > 0 {
                        list.push(b',');
                    }
                    for &b in id {
                        if b == b',' || b == b'\\' {
                            list.push(b'\\');
                        }
                        list.push(b);
                    }
                }
                out.push_str("alpn=");
                text::quote_into(out, &list);
            }
            SvcParam::NoDefaultAlpn => out.push_str("no-default-alpn"),
            SvcParam::Port(port) => out.push_str(&format!("port={port}")),
            SvcParam::Ipv4Hint(addresses) => {
                let list: Vec<String> = addresses.iter().map(ToString::to_string).collect();
                out.push_str("ipv4hint=");
                out.push_str(&list.join(","));
            }
            SvcParam::Ech(config) => {
                out.push_str("ech=");
                out.push_str(&text::base64_encode(config));
            }
            SvcParam::Ipv6Hint(addresses) => {
                let list: Vec<String> = addresses.iter().map(ToString::to_string).collect();
                out.push_str("ipv6hint=");
                out.push_str(&list.join(","));
            }
            SvcParam::Other { key, value } => {
                out.push_str(&format!("key{key}="));
                text::quote_into(out, value);
            }
        }
    }
}

/// The presentation name of a key.
fn key_name(key: u16) -> String {
    match key {
        MANDATORY => "mandatory".to_owned(),
        ALPN => "alpn".to_owned(),
        NO_DEFAULT_ALPN => "no-default-alpn".to_owned(),
        PORT => "port".to_owned(),
        IPV4HINT => "ipv4hint".to_owned(),
        ECH => "ech".to_owned(),
        IPV6HINT => "ipv6hint".to_owned(),
        other => format!("key{other}"),
    }
}

/// Parses a key name or `key<number>`, case-insensitively.
fn parse_key(name: &str) -> Result<u16, RecordError> {
    let lower = name.to_ascii_lowercase();
    let key = match lower.as_str() {
        "mandatory" => MANDATORY,
        "alpn" => ALPN,
        "no-default-alpn" => NO_DEFAULT_ALPN,
        "port" => PORT,
        "ipv4hint" => IPV4HINT,
        "ech" => ECH,
        "ipv6hint" => IPV6HINT,
        _ => {
            let digits = lower
                .strip_prefix("key")
                .ok_or_else(|| syntax("unknown service parameter key"))?;
            let value = text::decimal_str(digits, "service parameter key", u64::from(u16::MAX))
                .map_err(|err| match err {
                    RecordError::Syntax { .. } => syntax("unknown service parameter key"),
                    other => other,
                })?;
            u16::try_from(value).map_err(|_| RecordError::OutOfRange {
                field: "service parameter key",
            })?
        }
    };
    if key == INVALID_KEY {
        return Err(syntax("the parameter key 65535 is reserved as invalid"));
    }
    Ok(key)
}

/// Decodes a value from wire form.
fn decode_value(key: u16, value: &[u8]) -> Result<SvcParam, RecordError> {
    let mut reader = Reader::new(value);
    let param = match key {
        MANDATORY => {
            let mut keys = Vec::new();
            while !reader.is_empty() {
                keys.push(reader.u16()?);
            }
            SvcParam::Mandatory(keys)
        }
        ALPN => {
            let mut ids = Vec::new();
            while !reader.is_empty() {
                ids.push(reader.character_string()?.to_vec());
            }
            SvcParam::Alpn(ids)
        }
        NO_DEFAULT_ALPN => SvcParam::NoDefaultAlpn,
        PORT => SvcParam::Port(reader.u16()?),
        IPV4HINT => {
            let mut addresses = Vec::new();
            while !reader.is_empty() {
                addresses.push(Ipv4Addr::from(reader.u32()?));
            }
            SvcParam::Ipv4Hint(addresses)
        }
        ECH => SvcParam::Ech(reader.rest().to_vec()),
        IPV6HINT => {
            let mut addresses = Vec::new();
            while !reader.is_empty() {
                let octets: [u8; 16] = reader
                    .bytes(16)?
                    .try_into()
                    .map_err(|_| syntax("an ipv6hint address has 16 octets"))?;
                addresses.push(Ipv6Addr::from(octets));
            }
            SvcParam::Ipv6Hint(addresses)
        }
        _ => SvcParam::Other {
            key,
            value: reader.rest().to_vec(),
        },
    };
    reader.finish()?;
    Ok(param)
}

/// Checks the requirements the parameters RFC 9460 defines place on each other in a ServiceMode
/// record (self-consistency, section 2.4.3):
///
/// - section 8: "For self-consistency (Section 2.4.3), listed keys MUST also appear in the
///   SvcParams" — every key `mandatory` lists is the key of a parameter of the record;
/// - section 7.1.1: "When "no-default-alpn" is specified in an RR, "alpn" must also be specified
///   in order for the RR to be "self-consistent"".
fn check_self_consistent(params: &[SvcParam]) -> Result<(), RecordError> {
    let present = |key: u16| params.iter().any(|param| param.key() == key);
    for param in params {
        match param {
            SvcParam::Mandatory(keys) => {
                if !keys.iter().all(|&key| present(key)) {
                    return Err(syntax(
                        "the mandatory parameter lists a key that is not present",
                    ));
                }
            }
            SvcParam::NoDefaultAlpn if !present(ALPN) => {
                return Err(syntax("no-default-alpn needs an alpn parameter"));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Splits an alpn value list (RFC 9460 appendix A.1) after the character-string escapes have
/// been resolved: `\` escapes the next octet, `,` separates.
fn split_alpn(value: &[u8]) -> Result<Vec<Vec<u8>>, RecordError> {
    let mut ids = Vec::new();
    let mut current = Vec::new();
    let mut octets = value.iter();
    while let Some(&b) = octets.next() {
        match b {
            b'\\' => {
                let &next = octets
                    .next()
                    .ok_or_else(|| syntax("the alpn value ends in a backslash"))?;
                current.push(next);
            }
            b',' => ids.push(std::mem::take(&mut current)),
            _ => current.push(b),
        }
    }
    ids.push(current);
    Ok(ids)
}

/// Splits a plain comma-separated value list.
fn split_list(value: &[u8], what: &str) -> Result<Vec<String>, RecordError> {
    let text = std::str::from_utf8(value).map_err(|_| syntax(format!("{what} is not ASCII")))?;
    if text.is_empty() {
        return Err(syntax(format!("{what} is empty")));
    }
    Ok(text.split(',').map(str::to_owned).collect())
}

/// Parses a value from presentation form (after the character-string escapes).
fn presentation_value(key: u16, value: &[u8]) -> Result<SvcParam, RecordError> {
    Ok(match key {
        MANDATORY => {
            let keys = split_list(value, "the mandatory value")?
                .iter()
                .map(|name| parse_key(name))
                .collect::<Result<Vec<_>, _>>()?;
            SvcParam::Mandatory(keys)
        }
        ALPN => SvcParam::Alpn(split_alpn(value)?),
        NO_DEFAULT_ALPN => {
            if !value.is_empty() {
                return Err(syntax("no-default-alpn takes no value"));
            }
            SvcParam::NoDefaultAlpn
        }
        PORT => {
            let text = std::str::from_utf8(value).map_err(|_| syntax("the port is not ASCII"))?;
            let port = text::decimal_str(text, "port", u64::from(u16::MAX))?;
            SvcParam::Port(
                u16::try_from(port).map_err(|_| RecordError::OutOfRange { field: "port" })?,
            )
        }
        IPV4HINT => SvcParam::Ipv4Hint(
            split_list(value, "the ipv4hint value")?
                .iter()
                .map(|a| {
                    text::parse_ipv4(a).ok_or_else(|| syntax("ipv4hint lists an invalid address"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        ECH => {
            let text =
                std::str::from_utf8(value).map_err(|_| syntax("the ech value is not ASCII"))?;
            SvcParam::Ech(text::base64_decode(text, "the ech value")?)
        }
        IPV6HINT => SvcParam::Ipv6Hint(
            split_list(value, "the ipv6hint value")?
                .iter()
                .map(|a| {
                    text::parse_ipv6(a).ok_or_else(|| syntax("ipv6hint lists an invalid address"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        _ => SvcParam::Other {
            key,
            value: value.to_vec(),
        },
    })
}

/// Parses one `key`, `key=value` or `key="value"` field.
fn parse_param(token: &Token<'_>) -> Result<SvcParam, RecordError> {
    let (key, value) = match token.key {
        Some(key) => (key, text::unescape(token.text, token.index)?),
        None if token.quoted => {
            return Err(syntax(format!(
                "field {}: a service parameter starts with its key",
                token.index
            )));
        }
        None => match token.text.split_once('=') {
            Some((key, value)) => (key, text::unescape(value, token.index)?),
            None => (token.text, Vec::new()),
        },
    };
    presentation_value(parse_key(key)?, &value)
}

impl Svcb {
    /// The canonical `RecordData`, valid for both [`RecordType::SVCB`] and
    /// [`RecordType::HTTPS`]. Fails for duplicate parameter keys and values without a valid
    /// encoding, and, in service mode (priority not 0), for parameters that are not
    /// self-consistent (RFC 9460 section 2.4.3): `mandatory` lists a key that is not present
    /// (section 8), or `no-default-alpn` is given without `alpn` (section 7.1.1).
    pub fn to_data(&self) -> Result<RecordData, RecordError> {
        Rdata::Svcb(self.clone()).into_data()
    }

    /// Reads canonical SVCB or HTTPS data; `NotCanonical` for raw provider text. The parameters
    /// come in ascending key order.
    pub fn from_data(data: &RecordData) -> Result<Svcb, RecordError> {
        match data.rdata(RecordType::SVCB)? {
            Rdata::Svcb(svcb) => Ok(svcb),
            _ => Err(syntax("not SVCB data")),
        }
    }

    /// Parameters checked, in canonical shape and ascending key order; duplicates refused.
    pub(crate) fn normalized(self) -> Result<Svcb, RecordError> {
        let mut params = self
            .params
            .into_iter()
            .map(SvcParam::normalized)
            .collect::<Result<Vec<_>, _>>()?;
        params.sort_by_key(SvcParam::key);
        if params
            .windows(2)
            .any(|pair| pair.first().map(SvcParam::key) == pair.get(1).map(SvcParam::key))
        {
            return Err(syntax("a service parameter key occurs twice"));
        }
        // RFC 9460 section 2.4.3: "zone-file implementations SHOULD enforce self-consistency",
        // and clients "MUST reject any RR whose recognized SvcParams are not self-consistent".
        // Self-consistency is defined for ServiceMode only; in AliasMode (priority 0) recipients
        // "MUST ignore any SvcParams that are present" (section 2.4.2), so they are kept as given.
        if self.priority != 0 {
            check_self_consistent(&params)?;
        }
        Ok(Svcb {
            priority: self.priority,
            target: self.target,
            params,
        })
    }

    pub(crate) fn parse_tokens(
        tokens: &[Token<'_>],
        origin: Option<&DomainName>,
    ) -> Result<Svcb, RecordError> {
        expect_min_fields(tokens, 2)?;
        let priority = text::parse_u16(field(tokens, 0)?, "priority")?;
        let target = parse_name(field(tokens, 1)?, origin)?;
        let params = tokens
            .get(2..)
            .unwrap_or_default()
            .iter()
            .map(parse_param)
            .collect::<Result<Vec<_>, _>>()?;
        Svcb {
            priority,
            target,
            params,
        }
        .normalized()
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Svcb, RecordError> {
        let priority = reader.u16()?;
        let target = reader.name()?;
        let mut params = Vec::new();
        let mut previous: Option<u16> = None;
        while !reader.is_empty() {
            let key = reader.u16()?;
            if previous.is_some_and(|previous| key <= previous) {
                return Err(syntax(
                    "service parameter keys are not in strictly increasing order",
                ));
            }
            previous = Some(key);
            let len = reader.u16()?;
            let value = reader.bytes(usize::from(len))?;
            params.push(decode_value(key, value)?);
        }
        Svcb {
            priority,
            target,
            params,
        }
        .normalized()
    }

    /// Encodes wire form. Expects a normalized value but checks order and duplicates again.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        out.extend_from_slice(&self.priority.to_be_bytes());
        out.extend_from_slice(self.target.wire());
        let mut previous: Option<u16> = None;
        for param in &self.params {
            let key = param.key();
            if previous.is_some_and(|previous| key <= previous) {
                return Err(syntax(
                    "service parameter keys are duplicated or out of order",
                ));
            }
            previous = Some(key);
            let value = param.encode_value()?;
            out.extend_from_slice(&key.to_be_bytes());
            wire::push_len16(out, value.len())?;
            out.extend_from_slice(&value);
        }
        Ok(())
    }

    pub(crate) fn write_text(&self, out: &mut String) {
        out.push_str(&format!("{} {}", self.priority, self.target));
        for param in &self.params {
            out.push(' ');
            param.write_text(out);
        }
    }
}

// `RecordData::from_provider` exists only in builds with a record-level client.
#[cfg(all(test, feature = "selectel_v2"))]
mod tests {
    use super::*;

    /// A provider read of a ServiceMode value that is not self-consistent (RFC 9460 section
    /// 2.4.3) falls back to non-canonical data with the provider's text, as any text the strict
    /// parser refuses does (design section 4.9); the read itself does not fail.
    #[test]
    fn a_provider_read_keeps_an_inconsistent_value_as_non_canonical() {
        use crate::record::TxtDialect;
        let origin = DomainName::parse("example.org").ok();
        for text in ["1 . no-default-alpn", "1 . mandatory=port alpn=h2"] {
            for rtype in [RecordType::SVCB, RecordType::HTTPS] {
                for origin in [None, origin.as_ref()] {
                    let data =
                        RecordData::from_provider(rtype, text, origin, TxtDialect::Presentation);
                    assert!(!data.is_canonical(), "{rtype} {text}");
                    assert_eq!(data.as_str(), text);
                }
            }
        }
        let alias = RecordData::from_provider(
            RecordType::HTTPS,
            "0 svc.example.org. no-default-alpn",
            None,
            TxtDialect::Presentation,
        );
        assert!(alias.is_canonical());
    }
}
