//! SRV data (RFC 2782).

use super::data::{Rdata, expect_fields, field, parse_name};
use super::text::{self, Token, syntax};
use super::wire::Reader;
use super::{RecordData, RecordError, RecordType};
use crate::name::{DomainName, TargetName};

/// SRV data: `<priority> <weight> <port> <target>`. The target `.` means the service is not
/// available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srv {
    /// Lower values are tried first.
    pub priority: u16,
    /// Relative weight among records of the same priority.
    pub weight: u16,
    /// The port of the service.
    pub port: u16,
    /// The host providing the service.
    pub target: TargetName,
}

impl Srv {
    /// The canonical `RecordData`.
    pub fn to_data(&self) -> Result<RecordData, RecordError> {
        Rdata::Srv(self.clone()).into_data()
    }

    /// Reads canonical SRV data; `NotCanonical` for raw provider text.
    pub fn from_data(data: &RecordData) -> Result<Srv, RecordError> {
        match data.rdata(RecordType::SRV)? {
            Rdata::Srv(srv) => Ok(srv),
            _ => Err(syntax("not SRV data")),
        }
    }

    pub(crate) fn parse_tokens(
        tokens: &[Token<'_>],
        origin: Option<&DomainName>,
    ) -> Result<Srv, RecordError> {
        expect_fields(tokens, 4)?;
        Ok(Srv {
            priority: text::parse_u16(field(tokens, 0)?, "priority")?,
            weight: text::parse_u16(field(tokens, 1)?, "weight")?,
            port: text::parse_u16(field(tokens, 2)?, "port")?,
            target: parse_name(field(tokens, 3)?, origin)?,
        })
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Srv, RecordError> {
        Ok(Srv {
            priority: reader.u16()?,
            weight: reader.u16()?,
            port: reader.u16()?,
            target: reader.name()?,
        })
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.priority.to_be_bytes());
        out.extend_from_slice(&self.weight.to_be_bytes());
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(self.target.wire());
    }

    pub(crate) fn write_text(&self, out: &mut String) {
        out.push_str(&format!(
            "{} {} {} {}",
            self.priority, self.weight, self.port, self.target
        ));
    }
}
