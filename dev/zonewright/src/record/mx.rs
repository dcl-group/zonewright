//! MX data (RFC 1035 section 3.3.9).

use super::data::{Rdata, expect_fields, field, parse_name};
use super::text::{self, Token, syntax};
use super::wire::Reader;
use super::{RecordData, RecordError, RecordType};
use crate::name::{DomainName, TargetName};

/// MX data: `<preference> <exchange>`. The exchange `.` is a null MX (RFC 7505).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mx {
    /// Lower values are preferred.
    pub preference: u16,
    /// The mail exchange.
    pub exchange: TargetName,
}

impl Mx {
    /// The canonical `RecordData`.
    pub fn to_data(&self) -> Result<RecordData, RecordError> {
        Rdata::Mx(self.clone()).into_data()
    }

    /// Reads canonical MX data; `NotCanonical` for raw provider text.
    pub fn from_data(data: &RecordData) -> Result<Mx, RecordError> {
        match data.rdata(RecordType::MX)? {
            Rdata::Mx(mx) => Ok(mx),
            _ => Err(syntax("not MX data")),
        }
    }

    pub(crate) fn parse_tokens(
        tokens: &[Token<'_>],
        origin: Option<&DomainName>,
    ) -> Result<Mx, RecordError> {
        expect_fields(tokens, 2)?;
        Ok(Mx {
            preference: text::parse_u16(field(tokens, 0)?, "preference")?,
            exchange: parse_name(field(tokens, 1)?, origin)?,
        })
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Mx, RecordError> {
        Ok(Mx {
            preference: reader.u16()?,
            exchange: reader.name()?,
        })
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.preference.to_be_bytes());
        out.extend_from_slice(self.exchange.wire());
    }

    pub(crate) fn write_text(&self, out: &mut String) {
        out.push_str(&format!("{} {}", self.preference, self.exchange));
    }
}
