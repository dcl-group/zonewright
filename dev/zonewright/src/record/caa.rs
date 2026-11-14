//! CAA data (RFC 8659, design section 4.5).

use super::data::{Rdata, expect_fields, field};
use super::text::{self, Token, syntax};
use super::wire::Reader;
use super::{RecordData, RecordError, RecordType};

/// The longest tag.
const MAX_TAG: usize = 255;

/// CAA data: `<flags> <tag> "<value>"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caa {
    /// Flags; see [`Caa::CRITICAL`].
    pub flags: u8,
    /// The property tag: 1 to 255 characters of `[a-z0-9]`.
    pub tag: String,
    /// The property value, not case-folded and not interpreted.
    pub value: Vec<u8>,
}

impl Caa {
    /// The issuer critical flag.
    pub const CRITICAL: u8 = 0b1000_0000;

    /// The issuer critical flag is set.
    pub fn is_critical(&self) -> bool {
        self.flags & Caa::CRITICAL != 0
    }

    /// The canonical `RecordData`. Fails for a tag outside `[a-z0-9]` or longer than 255
    /// characters.
    pub fn to_data(&self) -> Result<RecordData, RecordError> {
        Rdata::Caa(self.clone()).into_data()
    }

    /// Reads canonical CAA data; `NotCanonical` for raw provider text.
    pub fn from_data(data: &RecordData) -> Result<Caa, RecordError> {
        match data.rdata(RecordType::CAA)? {
            Rdata::Caa(caa) => Ok(caa),
            _ => Err(syntax("not CAA data")),
        }
    }

    pub(crate) fn parse_tokens(tokens: &[Token<'_>]) -> Result<Caa, RecordError> {
        expect_fields(tokens, 3)?;
        let flags = text::parse_u8(field(tokens, 0)?, "flags")?;
        let tag_token = field(tokens, 1)?;
        let tag = tag_token.plain("the tag")?.to_ascii_lowercase();
        check_tag(tag.as_bytes())?;
        let value_token = field(tokens, 2)?;
        if value_token.key.is_some() {
            return Err(syntax("field 3: malformed value"));
        }
        let value = text::unescape(value_token.text, value_token.index)?;
        Ok(Caa { flags, tag, value })
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Caa, RecordError> {
        let flags = reader.u8()?;
        let tag = reader.character_string()?.to_ascii_lowercase();
        check_tag(&tag)?;
        let tag = String::from_utf8(tag).map_err(|_| syntax("the tag is not ASCII"))?;
        let value = reader.rest().to_vec();
        Ok(Caa { flags, tag, value })
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        check_tag(self.tag.as_bytes())?;
        out.push(self.flags);
        let len = u8::try_from(self.tag.len()).map_err(|_| RecordError::TooLong)?;
        out.push(len);
        out.extend_from_slice(self.tag.as_bytes());
        out.extend_from_slice(&self.value);
        Ok(())
    }

    pub(crate) fn write_text(&self, out: &mut String) {
        out.push_str(&format!("{} {} ", self.flags, self.tag));
        text::quote_into(out, &self.value);
    }
}

/// A tag is 1 to 255 octets of `[a-z0-9]`.
fn check_tag(tag: &[u8]) -> Result<(), RecordError> {
    if tag.is_empty() {
        return Err(syntax("the CAA tag is empty"));
    }
    if tag.len() > MAX_TAG {
        return Err(RecordError::TooLong);
    }
    if !tag
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(syntax("the CAA tag must consist of a-z and 0-9"));
    }
    Ok(())
}
