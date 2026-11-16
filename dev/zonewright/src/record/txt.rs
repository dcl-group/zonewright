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

    /// The canonical presentation text: quoted 255-octet chunks (design section 4.4).
    #[cfg(any(
        feature = "beget",
        feature = "cloud_ru",
        feature = "cloudflare",
        feature = "digitalocean",
        feature = "dnsimple",
        feature = "gandi",
        feature = "hetzner",
        feature = "porkbun",
        feature = "nicru",
        feature = "regru",
        feature = "route53",
        feature = "selectel_v2",
        feature = "timeweb_cloud",
        feature = "vk_cloud",
        feature = "yandex_360",
        feature = "yandex_cloud"
    ))]
    pub(crate) fn to_presentation(&self) -> String {
        let mut out = String::with_capacity(self.0.len() + 2);
        self.write_text(&mut out);
        out
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

/// How a provider's API spells TXT data (design section 4.4). Each client declares one reading
/// rule and one writing rule; `Auto` is a reading rule only. Used by the HTTP clients that read
/// TXT records (acme-dns reads nothing; RFC 2136 works with wire data).
#[cfg(any(
    feature = "beget",
    feature = "cloud_ru",
    feature = "cloudflare",
    feature = "digitalocean",
    feature = "dnsimple",
    feature = "gandi",
    feature = "hetzner",
    feature = "porkbun",
    feature = "nicru",
    feature = "regru",
    feature = "route53",
    feature = "selectel_v2",
    feature = "timeweb_cloud",
    feature = "vk_cloud",
    feature = "yandex_360",
    feature = "yandex_cloud"
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxtDialect {
    /// Zone-file text: quoted character-strings with escapes. Read with the strict parser; write
    /// the canonical text.
    Presentation,
    /// The value itself, unquoted and unescaped. Read the string's bytes as the data; write the
    /// data as a string.
    Raw,
    /// Reading only: text that starts with `"` is `Presentation`, anything else `Raw`.
    // Design section 9.2: a shared helper; a build whose only client reads raw text (nic.ru)
    // does not construct it. The build with all providers does.
    #[cfg_attr(not(feature = "all-providers"), allow(dead_code))]
    Auto,
}

#[cfg(any(
    feature = "beget",
    feature = "cloud_ru",
    feature = "cloudflare",
    feature = "digitalocean",
    feature = "dnsimple",
    feature = "gandi",
    feature = "hetzner",
    feature = "porkbun",
    feature = "nicru",
    feature = "regru",
    feature = "route53",
    feature = "selectel_v2",
    feature = "timeweb_cloud",
    feature = "vk_cloud",
    feature = "yandex_360",
    feature = "yandex_cloud"
))]
impl TxtDialect {
    /// Decodes provider text. `None` when the text is not valid in this dialect; the caller then
    /// keeps the text as an opaque value (design sections 3.5 and 4.9).
    pub(crate) fn read(self, text: &str) -> Option<Txt> {
        match self {
            TxtDialect::Presentation => RecordData::parse(RecordType::TXT, text)
                .ok()
                .and_then(|data| Txt::from_data(&data).ok()),
            TxtDialect::Raw => Txt::new(text.as_bytes()).ok(),
            TxtDialect::Auto => {
                if text.trim_start().starts_with('"') {
                    TxtDialect::Presentation.read(text)
                } else {
                    TxtDialect::Raw.read(text)
                }
            }
        }
    }

    /// Encodes a value for the provider. `None` when this dialect cannot carry the value: in
    /// `Raw`, data that is not valid UTF-8; `Auto` is not a writing rule and always gives `None`.
    /// A client that is not known to pass other values through unchanged accepts only
    /// [`Txt::is_plain`] values before it gets here (design section 4.4).
    pub(crate) fn write(self, value: &Txt) -> Option<String> {
        match self {
            TxtDialect::Presentation => Some(value.to_presentation()),
            TxtDialect::Raw => value.as_str().map(str::to_owned),
            TxtDialect::Auto => None,
        }
    }
}

#[cfg(test)]
#[cfg(any(
    feature = "beget",
    feature = "cloud_ru",
    feature = "cloudflare",
    feature = "digitalocean",
    feature = "dnsimple",
    feature = "gandi",
    feature = "hetzner",
    feature = "porkbun",
    feature = "nicru",
    feature = "regru",
    feature = "route53",
    feature = "selectel_v2",
    feature = "timeweb_cloud",
    feature = "vk_cloud",
    feature = "yandex_360",
    feature = "yandex_cloud"
))]
mod tests {
    use super::{Txt, TxtDialect};

    fn txt(data: &str) -> Txt {
        Txt::new(data.as_bytes()).unwrap()
    }

    #[test]
    fn presentation_reads_quoted_and_escaped_text() {
        let d = TxtDialect::Presentation;
        assert_eq!(d.read(r#""a b" "c""#), Some(txt("a bc")));
        assert_eq!(d.read(r#""say \"hi\"""#), Some(txt("say \"hi\"")));
        assert_eq!(d.read("plain"), Some(txt("plain")));
        assert_eq!(d.read("two words"), None);
        assert_eq!(d.read(r#""open"#), None);
    }

    #[test]
    fn raw_reads_bytes_verbatim() {
        let d = TxtDialect::Raw;
        assert_eq!(d.read(r#""quoted""#), Some(txt("\"quoted\"")));
        assert_eq!(d.read("a b"), Some(txt("a b")));
    }

    #[test]
    fn auto_picks_by_leading_quote() {
        let d = TxtDialect::Auto;
        assert_eq!(d.read(r#""a" "b""#), Some(txt("ab")));
        assert_eq!(d.read("v=spf1 -all"), Some(txt("v=spf1 -all")));
        assert_eq!(d.read(r#""broken"#), None);
    }

    #[test]
    fn writing_rules() {
        let value = txt("say \"hi\"");
        assert_eq!(
            TxtDialect::Presentation.write(&value).as_deref(),
            Some(r#""say \"hi\"""#)
        );
        assert_eq!(TxtDialect::Raw.write(&value).as_deref(), Some("say \"hi\""));
        assert_eq!(TxtDialect::Auto.write(&value), None);
        let binary = Txt::new(vec![0xff, 0x00]).unwrap();
        assert_eq!(TxtDialect::Raw.write(&binary), None);
        assert_eq!(
            TxtDialect::Presentation.write(&binary).as_deref(),
            Some(r#""\255\000""#)
        );
    }
}
