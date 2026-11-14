//! TXT data (design section 4.4).

use super::data::Rdata;
use super::text::{self, Token, syntax};
use super::wire::{self, Reader};
use super::{RecordData, RecordError, RecordType};

/// The most data one TXT RDATA holds: 256 character-strings of up to 255 octets, each with a
/// length octet, in 65535 octets.
const MAX_TXT: usize = 65_279;
/// The length of a character-string.
const CHUNK: usize = 255;

/// TXT data as one byte string: the concatenation of the record's character-strings.
///
/// Where the boundaries between character-strings fall is not part of the value. The canonical
/// text cuts the data into 255-octet chunks, each quoted, separated by one space.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Txt(Vec<u8>);

impl Txt {
    /// At most 65279 octets (the most that fits one RDATA after splitting into 255-octet
    /// character-strings). Empty data is allowed.
    pub fn new(data: impl Into<Vec<u8>>) -> Result<Txt, RecordError> {
        let data = data.into();
        if data.len() > MAX_TXT {
            return Err(RecordError::TooLong);
        }
        Ok(Txt(data))
    }

    /// The data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// `Some` when the data is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// 1 ..= 255 octets, each in 0x21 ..= 0x7E and none of them `"` or `\`.
    /// ACME DNS-01 values are plain.
    pub fn is_plain(&self) -> bool {
        (1..=CHUNK).contains(&self.0.len())
            && self
                .0
                .iter()
                .all(|&b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
    }

    /// The canonical `RecordData`.
    pub fn to_data(&self) -> Result<RecordData, RecordError> {
        Rdata::Txt(self.clone()).into_data()
    }

    /// Reads canonical TXT data; `NotCanonical` for raw provider text.
    pub fn from_data(data: &RecordData) -> Result<Txt, RecordError> {
        match data.rdata(RecordType::TXT)? {
            Rdata::Txt(txt) => Ok(txt),
            _ => Err(syntax("not TXT data")),
        }
    }

    /// One or more quoted strings, or exactly one unquoted field.
    pub(crate) fn parse_tokens(tokens: &[Token<'_>]) -> Result<Txt, RecordError> {
        let mut data = Vec::new();
        match tokens {
            [single] if single.is_plain() => {
                data = text::unescape(single.text, single.index)?;
            }
            _ => {
                for token in tokens {
                    if !token.quoted || token.key.is_some() {
                        return Err(syntax(format!(
                            "field {}: TXT data is either quoted strings or one unquoted field \
                             without whitespace",
                            token.index
                        )));
                    }
                    data.extend(text::unescape(token.text, token.index)?);
                }
            }
        }
        Txt::new(data)
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Txt, RecordError> {
        if reader.is_empty() {
            return Err(syntax("TXT data needs at least one character-string"));
        }
        let mut data = Vec::with_capacity(reader.remaining());
        while !reader.is_empty() {
            data.extend_from_slice(reader.character_string()?);
        }
        Txt::new(data)
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        if self.0.is_empty() {
            out.push(0);
            return Ok(());
        }
        for chunk in self.0.chunks(CHUNK) {
            wire::push_character_string(out, chunk)?;
        }
        Ok(())
    }

    pub(crate) fn write_text(&self, out: &mut String) {
        if self.0.is_empty() {
            out.push_str("\"\"");
            return;
        }
        for (index, chunk) in self.0.chunks(CHUNK).enumerate() {
            if index > 0 {
                out.push(' ');
            }
            text::quote_into(out, chunk);
        }
    }
}
