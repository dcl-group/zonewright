//! TLSA data (RFC 6698).

use super::data::{Rdata, expect_min_fields, field};
use super::text::{self, Token, syntax};
use super::wire::Reader;
use super::{RecordData, RecordError, RecordType};

/// TLSA data: `<usage> <selector> <matching type> <hex>`, at least one data octet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tlsa {
    /// Certificate usage.
    pub usage: u8,
    /// Selector.
    pub selector: u8,
    /// Matching type.
    pub matching_type: u8,
    /// Certificate association data; at least one octet.
    pub data: Vec<u8>,
}

impl Tlsa {
    /// The canonical `RecordData`. Fails for empty association data.
    pub fn to_data(&self) -> Result<RecordData, RecordError> {
        Rdata::Tlsa(self.clone()).into_data()
    }

    /// Reads canonical TLSA data; `NotCanonical` for raw provider text.
    pub fn from_data(data: &RecordData) -> Result<Tlsa, RecordError> {
        match data.rdata(RecordType::TLSA)? {
            Rdata::Tlsa(tlsa) => Ok(tlsa),
            _ => Err(syntax("not TLSA data")),
        }
    }

    pub(crate) fn parse_tokens(tokens: &[Token<'_>]) -> Result<Tlsa, RecordError> {
        expect_min_fields(tokens, 4)?;
        let data = text::decode_hex(tokens.get(3..).unwrap_or_default(), "association data")?;
        if data.is_empty() {
            return Err(syntax("TLSA association data is empty"));
        }
        Ok(Tlsa {
            usage: text::parse_u8(field(tokens, 0)?, "usage")?,
            selector: text::parse_u8(field(tokens, 1)?, "selector")?,
            matching_type: text::parse_u8(field(tokens, 2)?, "matching type")?,
            data,
        })
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Tlsa, RecordError> {
        let usage = reader.u8()?;
        let selector = reader.u8()?;
        let matching_type = reader.u8()?;
        let data = reader.rest().to_vec();
        if data.is_empty() {
            return Err(syntax("TLSA association data is empty"));
        }
        Ok(Tlsa {
            usage,
            selector,
            matching_type,
            data,
        })
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        if self.data.is_empty() {
            return Err(syntax("TLSA association data is empty"));
        }
        out.extend_from_slice(&[self.usage, self.selector, self.matching_type]);
        out.extend_from_slice(&self.data);
        Ok(())
    }

    pub(crate) fn write_text(&self, out: &mut String) {
        out.push_str(&format!(
            "{} {} {} ",
            self.usage, self.selector, self.matching_type
        ));
        text::hex_into(out, &self.data);
    }
}
