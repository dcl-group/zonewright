//! Presentation format: the tokenizer, escapes and field parsers shared by all record types
//! (RFC 1035 section 5.1, design section 4.1).

use base64::Engine as _;

use super::RecordError;

/// A `Syntax` error with the given description.
pub(crate) fn syntax(detail: impl Into<String>) -> RecordError {
    RecordError::Syntax {
        detail: detail.into(),
    }
}

/// One field of presentation-format RDATA.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Token<'a> {
    /// The source text with escapes intact: the whole field if unquoted, the part between the
    /// quotes if quoted.
    pub(crate) text: &'a str,
    /// The field was a quoted string (or a `key="value"` field).
    pub(crate) quoted: bool,
    /// For a `key="value"` field (SVCB parameters), the key; `text` is the quoted value.
    pub(crate) key: Option<&'a str>,
    /// 1-based position among the fields, for error messages.
    pub(crate) index: usize,
}

impl Token<'_> {
    /// An unquoted field without a `key="…"` part.
    pub(crate) fn is_plain(&self) -> bool {
        !self.quoted && self.key.is_none()
    }

    /// The field as unquoted text, or a `Syntax` error naming `what`.
    pub(crate) fn plain(&self, what: &str) -> Result<&str, RecordError> {
        if self.is_plain() {
            Ok(self.text)
        } else {
            Err(syntax(format!(
                "field {}: {what} must not be quoted",
                self.index
            )))
        }
    }
}

/// Rejects octets that are not allowed anywhere in the text.
fn check_octet(b: u8, offset: usize, in_quotes: bool) -> Result<(), RecordError> {
    match b {
        b'\n' | b'\r' => Err(syntax(format!("line break at offset {offset}"))),
        b'\t' if in_quotes => Ok(()),
        0x00..=0x08 | 0x0a..=0x1f | 0x7f => {
            Err(syntax(format!("control character at offset {offset}")))
        }
        _ => Ok(()),
    }
}

/// Reads a quoted string whose opening quote is just before `pos`; returns the offset of the
/// closing quote.
fn read_quoted(bytes: &[u8], mut pos: usize, start: usize) -> Result<usize, RecordError> {
    loop {
        match bytes.get(pos) {
            None => {
                return Err(syntax(format!(
                    "unterminated quoted string starting at offset {start}"
                )));
            }
            Some(b'"') => return Ok(pos),
            Some(b'\\') => {
                pos += 1;
                match bytes.get(pos) {
                    None => {
                        return Err(syntax(format!(
                            "unterminated quoted string starting at offset {start}"
                        )));
                    }
                    Some(&b) => check_octet(b, pos, true)?,
                }
                pos += 1;
            }
            Some(&b) => {
                check_octet(b, pos, true)?;
                pos += 1;
            }
        }
    }
}

/// Splits presentation text into fields. Accepts any run of spaces and tabs between fields and
/// around them; rejects parentheses, comments and line breaks outside quotes, line breaks and
/// control characters anywhere, and a quote inside an unquoted field except directly after the
/// first `=` (the `key="value"` form of SVCB parameters).
pub(crate) fn tokenize(input: &str) -> Result<Vec<Token<'_>>, RecordError> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut pos = 0usize;
    let slice = |from: usize, to: usize| {
        input
            .get(from..to)
            .ok_or_else(|| syntax(format!("invalid text at offset {from}")))
    };
    while let Some(&b) = bytes.get(pos) {
        match b {
            b' ' | b'\t' => pos += 1,
            b'"' => {
                let close = read_quoted(bytes, pos + 1, pos)?;
                tokens.push(Token {
                    text: slice(pos + 1, close)?,
                    quoted: true,
                    key: None,
                    index: tokens.len() + 1,
                });
                pos = close + 1;
            }
            _ => {
                let start = pos;
                let mut first_eq: Option<usize> = None;
                let mut token: Option<Token<'_>> = None;
                while let Some(&c) = bytes.get(pos) {
                    match c {
                        b' ' | b'\t' => break,
                        b'\\' => {
                            pos += 1;
                            if let Some(&escaped) = bytes.get(pos) {
                                check_octet(escaped, pos, false)?;
                                pos += 1;
                            }
                        }
                        b'(' | b')' => {
                            return Err(syntax(format!(
                                "parentheses are not allowed (offset {pos})"
                            )));
                        }
                        b';' => {
                            return Err(syntax(format!("comments are not allowed (offset {pos})")));
                        }
                        b'"' => {
                            let eq = first_eq.filter(|&eq| eq + 1 == pos).ok_or_else(|| {
                                syntax(format!("quote inside an unquoted field at offset {pos}"))
                            })?;
                            let close = read_quoted(bytes, pos + 1, pos)?;
                            token = Some(Token {
                                text: slice(pos + 1, close)?,
                                quoted: true,
                                key: Some(slice(start, eq)?),
                                index: tokens.len() + 1,
                            });
                            pos = close + 1;
                            break;
                        }
                        b'=' => {
                            if first_eq.is_none() {
                                first_eq = Some(pos);
                            }
                            pos += 1;
                        }
                        _ => {
                            check_octet(c, pos, false)?;
                            pos += 1;
                        }
                    }
                }
                let token = match token {
                    Some(token) => token,
                    None => Token {
                        text: slice(start, pos)?,
                        quoted: false,
                        key: None,
                        index: tokens.len() + 1,
                    },
                };
                tokens.push(token);
            }
        }
    }
    Ok(tokens)
}

/// Resolves the escapes `\DDD` (value at most 255) and `\X` of a character-string. Literal
/// characters, including non-ASCII ones, are taken as their UTF-8 octets.
pub(crate) fn unescape(text: &str, index: usize) -> Result<Vec<u8>, RecordError> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut pos = 0usize;
    while let Some(&b) = bytes.get(pos) {
        if b != b'\\' {
            out.push(b);
            pos += 1;
            continue;
        }
        match bytes.get(pos + 1) {
            None => return Err(syntax(format!("field {index}: trailing backslash"))),
            Some(d) if d.is_ascii_digit() => {
                let digits = bytes
                    .get(pos + 1..pos + 4)
                    .filter(|digits| digits.iter().all(u8::is_ascii_digit))
                    .ok_or_else(|| syntax(format!("field {index}: malformed \\DDD escape")))?;
                let value = digits
                    .iter()
                    .fold(0u16, |acc, d| acc * 10 + u16::from(d - b'0'));
                let octet = u8::try_from(value)
                    .map_err(|_| syntax(format!("field {index}: \\DDD escape above 255")))?;
                out.push(octet);
                pos += 4;
            }
            Some(&other) => {
                // The octets of a multi-byte character after the first are copied by the
                // literal branch on the next iterations.
                out.push(other);
                pos += 2;
            }
        }
    }
    Ok(out)
}

/// Writes `bytes` with the character-string escapes of design section 4.4, without quotes:
/// `"` as `\"`, `\` as `\\`, 0x20–0x7E as themselves, every other octet as `\DDD`.
pub(crate) fn escape_into(out: &mut String, bytes: &[u8]) {
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => {
                out.push('\\');
                out.push(char::from(b'0' + b / 100));
                out.push(char::from(b'0' + (b / 10) % 10));
                out.push(char::from(b'0' + b % 10));
            }
        }
    }
}

/// Writes `bytes` as one quoted character-string.
pub(crate) fn quote_into(out: &mut String, bytes: &[u8]) {
    out.push('"');
    escape_into(out, bytes);
    out.push('"');
}

/// Parses an unsigned decimal field. Leading zeros are accepted; a value above `max` is
/// `OutOfRange`.
pub(crate) fn parse_decimal(
    token: &Token<'_>,
    field: &'static str,
    max: u64,
) -> Result<u64, RecordError> {
    let text = token.plain(field)?;
    decimal_str(text, field, max).map_err(|err| match err {
        RecordError::Syntax { .. } => syntax(format!(
            "field {}: {field} must be a decimal integer",
            token.index
        )),
        other => other,
    })
}

/// Parses an unsigned decimal string.
pub(crate) fn decimal_str(text: &str, field: &'static str, max: u64) -> Result<u64, RecordError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(syntax(format!("{field} must be a decimal integer")));
    }
    let mut value = 0u64;
    for d in text.bytes() {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(d - b'0')))
            .filter(|&v| v <= max)
            .ok_or(RecordError::OutOfRange { field })?;
    }
    Ok(value)
}

/// Parses a `u8` field.
pub(crate) fn parse_u8(token: &Token<'_>, field: &'static str) -> Result<u8, RecordError> {
    let value = parse_decimal(token, field, u64::from(u8::MAX))?;
    u8::try_from(value).map_err(|_| RecordError::OutOfRange { field })
}

/// Parses a `u16` field.
pub(crate) fn parse_u16(token: &Token<'_>, field: &'static str) -> Result<u16, RecordError> {
    let value = parse_decimal(token, field, u64::from(u16::MAX))?;
    u16::try_from(value).map_err(|_| RecordError::OutOfRange { field })
}

/// Parses a `u32` field.
pub(crate) fn parse_u32(token: &Token<'_>, field: &'static str) -> Result<u32, RecordError> {
    let value = parse_decimal(token, field, u64::from(u32::MAX))?;
    u32::try_from(value).map_err(|_| RecordError::OutOfRange { field })
}

/// Parses a `u32` number of seconds that may carry BIND time-unit suffixes (`1h`, `1w2d`,
/// `90m`): `s`, `m`, `h`, `d`, `w` in either case. A bare number is seconds.
pub(crate) fn parse_seconds(token: &Token<'_>, field: &'static str) -> Result<u32, RecordError> {
    let text = token.plain(field)?;
    let bad = || {
        syntax(format!(
            "field {}: {field} must be a number of seconds",
            token.index
        ))
    };
    if text.bytes().all(|b| b.is_ascii_digit()) {
        return parse_u32(token, field);
    }
    let mut total = 0u64;
    let mut rest = text;
    while !rest.is_empty() {
        let digits_len = rest.bytes().take_while(u8::is_ascii_digit).count();
        let digits = rest.get(..digits_len).ok_or_else(bad)?;
        if digits.is_empty() {
            return Err(bad());
        }
        let unit = rest
            .get(digits_len..digits_len + 1)
            .ok_or_else(bad)?
            .to_ascii_lowercase();
        let factor: u64 = match unit.as_str() {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            "w" => 604_800,
            _ => return Err(bad()),
        };
        let value = decimal_str(digits, field, u64::from(u32::MAX)).map_err(|_| bad())?;
        total = value
            .checked_mul(factor)
            .and_then(|v| total.checked_add(v))
            .filter(|&v| v <= u64::from(u32::MAX))
            .ok_or(RecordError::OutOfRange { field })?;
        rest = rest.get(digits_len + 1..).ok_or_else(bad)?;
    }
    u32::try_from(total).map_err(|_| RecordError::OutOfRange { field })
}

/// Writes lowercase hexadecimal.
pub(crate) fn hex_into(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(&d) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(d));
            }
        }
    }
}

/// Decodes hexadecimal spread over one or more unquoted fields; either case is accepted.
pub(crate) fn decode_hex(
    tokens: &[Token<'_>],
    field: &'static str,
) -> Result<Vec<u8>, RecordError> {
    let mut digits = Vec::new();
    for token in tokens {
        let text = token.plain(field)?;
        for b in text.bytes() {
            let value = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => {
                    return Err(syntax(format!(
                        "field {}: {field} must be hexadecimal",
                        token.index
                    )));
                }
            };
            digits.push(value);
        }
    }
    if digits.len() % 2 != 0 {
        return Err(syntax(format!(
            "{field} has an odd number of hexadecimal digits"
        )));
    }
    let (pairs, _) = digits.as_chunks::<2>();
    Ok(pairs.iter().map(|[high, low]| (high << 4) | low).collect())
}

/// Encodes standard base64 with padding.
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decodes standard base64 with padding.
pub(crate) fn base64_decode(text: &str, field: &'static str) -> Result<Vec<u8>, RecordError> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| syntax(format!("{field} is not valid base64")))
}

/// Parses an IPv4 address in dotted decimal. Leading zeros are refused: elsewhere they read as
/// octal.
pub(crate) fn parse_ipv4(text: &str) -> Option<std::net::Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty()
            || part.len() > 3
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(std::net::Ipv4Addr::from(octets))
}

/// Parses an IPv6 address in any RFC 4291 spelling, without a zone index.
pub(crate) fn parse_ipv6(text: &str) -> Option<std::net::Ipv6Addr> {
    text.parse().ok()
}
