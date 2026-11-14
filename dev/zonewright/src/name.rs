//! Domain names.
//!
//! [`DomainName`] is the strict type for zone names and the owner names of rrsets. [`TargetName`]
//! is the permissive type for names that occur inside RDATA, where a zone may point at any name
//! DNS can express.

use std::fmt;
use std::str::FromStr;

/// Maximum length of a domain name in text form without the trailing dot.
const MAX_TEXT_LEN: usize = 253;
/// Maximum length of a label in octets.
const MAX_LABEL_LEN: usize = 63;
/// Maximum length of a name in wire form (RFC 1035 section 3.1).
const MAX_WIRE_LEN: usize = 255;

/// An error in a domain name.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    /// The name is empty.
    #[error("the domain name is empty")]
    Empty,
    /// The name is longer than 253 octets without the trailing dot, or 255 octets in wire form.
    #[error("the domain name is too long")]
    TooLong,
    /// A label is empty or longer than 63 octets.
    #[error("a label of the domain name is empty or longer than 63 octets")]
    BadLabelLength,
    /// A character that is not allowed in this kind of name.
    #[error("the domain name contains a character that is not allowed")]
    BadCharacter,
    /// A label starts or ends with a hyphen.
    #[error("a label of the domain name starts or ends with a hyphen")]
    BadHyphen,
    /// `*` anywhere but as the whole leftmost label.
    #[error("\"*\" is allowed only as the whole leftmost label")]
    BadWildcard,
    /// IDNA processing failed, for example a label starting with `xn--` that is not valid
    /// Punycode.
    #[error("the domain name is not valid IDNA")]
    Idna,
    /// A malformed `\DDD` escape or a trailing backslash ([`TargetName`] only).
    #[error("the domain name contains a malformed escape")]
    BadEscape,
}

/// An absolute domain name in canonical form: lowercase ASCII (A-labels), every label valid,
/// stored with the trailing dot. The root name is ".".
///
/// Parsing rules: the input is not trimmed; one trailing dot is optional; IDNA (UTS 46 without
/// the STD3 ASCII restrictions) lowercases ASCII and turns U-labels into A-labels; the name is at
/// most 253 octets without the trailing dot and each label 1 to 63 octets; labels consist of
/// `a`–`z`, `0`–`9`, `-` and `_`, do not start or end with `-`; `*` is allowed only as the whole
/// leftmost label.
///
/// `Ord` is byte order of the canonical string, not DNSSEC canonical order.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainName(String);

impl DomainName {
    /// Parses an absolute name; a trailing dot is optional.
    pub fn parse(s: &str) -> Result<DomainName, NameError> {
        if s == "." {
            return Ok(DomainName::root());
        }
        // ASCII characters outside the owner-name alphabet are refused before IDNA, so that
        // whitespace and punctuation are reported as such rather than as an IDNA failure.
        if s.chars().any(|c| {
            c.is_ascii() && !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '*' | '.'))
        }) {
            return Err(NameError::BadCharacter);
        }
        let body = s.strip_suffix('.').unwrap_or(s);
        if body.is_empty() {
            return Err(NameError::Empty);
        }
        let ascii = idna::domain_to_ascii(body).map_err(|_| NameError::Idna)?;
        Self::from_ascii(ascii)
    }

    /// Validates the output of IDNA processing (no trailing dot) and builds the name.
    fn from_ascii(ascii: String) -> Result<DomainName, NameError> {
        if ascii.is_empty() {
            return Err(NameError::Empty);
        }
        if ascii.len() > MAX_TEXT_LEN {
            return Err(NameError::TooLong);
        }
        for (index, label) in ascii.split('.').enumerate() {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(NameError::BadLabelLength);
            }
            if label.contains('*') {
                if index != 0 || label != "*" {
                    return Err(NameError::BadWildcard);
                }
                continue;
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
            {
                return Err(NameError::BadCharacter);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(NameError::BadHyphen);
            }
        }
        let mut text = ascii;
        text.push('.');
        Ok(DomainName(text))
    }

    /// `relative` is a zone-file style name relative to `origin`: "" or "@" is the origin itself,
    /// "www" is `www.<origin>`. A name ending in a dot is taken as absolute.
    pub fn from_relative(relative: &str, origin: &DomainName) -> Result<DomainName, NameError> {
        if relative.is_empty() || relative == "@" {
            return Ok(origin.clone());
        }
        if relative.ends_with('.') || origin.is_root() {
            return DomainName::parse(relative);
        }
        DomainName::parse(&format!("{relative}.{}", origin.as_str()))
    }

    /// The root name ".".
    pub fn root() -> DomainName {
        DomainName(".".to_owned())
    }

    /// With the trailing dot: "www.example.org.". The root is ".".
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Without the trailing dot: "www.example.org". The root is "".
    pub fn without_dot(&self) -> &str {
        self.0.strip_suffix('.').unwrap_or(&self.0)
    }

    /// U-label form for display and for provider APIs that store Unicode names. Falls back to the
    /// A-label form for labels that do not decode. Keeps the trailing dot; the root is ".".
    pub fn to_unicode(&self) -> String {
        if self.is_root() {
            return ".".to_owned();
        }
        let mut out = String::with_capacity(self.0.len());
        for label in self.labels() {
            if label.starts_with("xn--") {
                let (unicode, result) = idna::domain_to_unicode(label);
                if result.is_ok() && !unicode.contains('.') {
                    out.push_str(&unicode);
                } else {
                    out.push_str(label);
                }
            } else {
                out.push_str(label);
            }
            out.push('.');
        }
        out
    }

    /// True for the root name.
    pub fn is_root(&self) -> bool {
        self.0 == "."
    }

    /// The leftmost label is "*".
    pub fn is_wildcard(&self) -> bool {
        self.0.starts_with("*.")
    }

    /// The number of labels; 0 for the root.
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Labels from the leftmost to the rightmost, without dots.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.without_dot()
            .split('.')
            .filter(|label| !label.is_empty())
    }

    /// `self` equals `zone` or is below it. Compared label by label, never by string suffix.
    pub fn is_within(&self, zone: &DomainName) -> bool {
        let own: Vec<&str> = self.labels().collect();
        let zone_labels: Vec<&str> = zone.labels().collect();
        own.len() >= zone_labels.len()
            && own
                .iter()
                .rev()
                .zip(zone_labels.iter().rev())
                .all(|(a, b)| a == b)
    }

    /// The part of `self` left of `zone`, without the separating dot; "" when `self == zone`;
    /// `None` when `self` is not within `zone`.
    pub fn relative_to(&self, zone: &DomainName) -> Option<&str> {
        if !self.is_within(zone) {
            return None;
        }
        let own = self.without_dot();
        if zone.is_root() {
            return Some(own);
        }
        let zone_len = zone.without_dot().len();
        if own.len() == zone_len {
            return Some("");
        }
        // `own` ends with "." + zone; cut that suffix.
        own.get(..own.len() - zone_len - 1)
    }

    /// The name without its leftmost label; `None` for the root.
    pub fn parent(&self) -> Option<DomainName> {
        if self.is_root() {
            return None;
        }
        let (_, rest) = self.0.split_once('.')?;
        if rest.is_empty() {
            Some(DomainName::root())
        } else {
            Some(DomainName(rest.to_owned()))
        }
    }

    /// The name with one more label on the left. `label` must be exactly one label.
    pub fn prepend(&self, label: &str) -> Result<DomainName, NameError> {
        let name = if self.is_root() {
            DomainName::parse(label)?
        } else {
            DomainName::parse(&format!("{label}.{}", self.as_str()))?
        };
        // A dot in `label` (or a Unicode full stop that IDNA maps to one) would add more than one
        // label.
        if name.label_count() != self.label_count() + 1 || label.ends_with('.') {
            return Err(NameError::BadCharacter);
        }
        Ok(name)
    }
}

impl FromStr for DomainName {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DomainName::parse(s)
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DomainName({:?})", self.0)
    }
}

impl serde::Serialize for DomainName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for DomainName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        DomainName::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// An absolute domain name as it occurs inside RDATA: any label contents DNS allows.
///
/// Labels are 1 to 63 arbitrary octets, the name at most 255 octets in wire form. The canonical
/// text lowercases ASCII letters and changes no other octet; a dot inside a label is written
/// `\.`, a backslash `\\`, and `"`, `$`, `(`, `)`, `;`, `@`, space and every octet outside
/// 0x21–0x7E are written `\DDD`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TargetName {
    /// Canonical text with the trailing dot. Determines `wire`, so ordering and equality follow
    /// the text.
    text: String,
    /// Uncompressed wire form, including the terminating root label.
    wire: Vec<u8>,
}

/// Why a wire-format name could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireNameError {
    /// The data ends inside the name.
    Truncated,
    /// A compression pointer or a reserved label type.
    Pointer,
    /// More than 255 octets.
    TooLong,
}

impl WireNameError {
    fn to_name_error(self) -> NameError {
        match self {
            WireNameError::Truncated | WireNameError::Pointer => NameError::BadLabelLength,
            WireNameError::TooLong => NameError::TooLong,
        }
    }

    /// A description for `RecordError::Syntax`.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            WireNameError::Truncated => "the data ends inside a domain name",
            WireNameError::Pointer => {
                "a domain name uses a compression pointer or a reserved label type"
            }
            WireNameError::TooLong => "a domain name is longer than 255 octets",
        }
    }
}

impl TargetName {
    /// Presentation format (RFC 1035 section 5.1) with the escapes `\DDD` and `\X`.
    /// A name without a trailing dot is taken as absolute. `@` is refused.
    pub fn parse(s: &str) -> Result<TargetName, NameError> {
        Self::parse_text(s, None)
    }

    /// Zone-file semantics: "@" is `origin`; a name without a trailing dot is below `origin`.
    pub fn from_relative(relative: &str, origin: &DomainName) -> Result<TargetName, NameError> {
        Self::parse_text(relative, Some(origin))
    }

    /// From one uncompressed wire-format name. The input must hold exactly one name.
    pub fn from_wire(name: &[u8]) -> Result<TargetName, NameError> {
        if name.is_empty() {
            return Err(NameError::Empty);
        }
        let (target, used) = Self::from_wire_prefix(name).map_err(WireNameError::to_name_error)?;
        if used != name.len() {
            return Err(NameError::BadLabelLength);
        }
        Ok(target)
    }

    /// Reads one uncompressed name from the start of `data`; returns it and the octets used.
    pub(crate) fn from_wire_prefix(data: &[u8]) -> Result<(TargetName, usize), WireNameError> {
        let mut labels = Vec::new();
        let mut pos = 0usize;
        loop {
            let len = usize::from(*data.get(pos).ok_or(WireNameError::Truncated)?);
            pos += 1;
            if len == 0 {
                break;
            }
            if len > MAX_LABEL_LEN {
                return Err(WireNameError::Pointer);
            }
            let label = data.get(pos..pos + len).ok_or(WireNameError::Truncated)?;
            pos += len;
            if pos > MAX_WIRE_LEN {
                return Err(WireNameError::TooLong);
            }
            labels.push(label.to_ascii_lowercase());
        }
        let name = Self::from_labels(labels).map_err(|_| WireNameError::TooLong)?;
        Ok((name, pos))
    }

    /// The root name ".".
    pub fn root() -> TargetName {
        TargetName {
            text: ".".to_owned(),
            wire: vec![0],
        }
    }

    /// Canonical text with the trailing dot.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// True for the root name.
    pub fn is_root(&self) -> bool {
        self.text == "."
    }

    /// `Some` when the name also satisfies the owner-name rules of [`DomainName`].
    pub fn to_domain_name(&self) -> Option<DomainName> {
        DomainName::parse(&self.text).ok()
    }

    /// The uncompressed wire form.
    pub(crate) fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// Builds a name from lowercased labels, checking label and name lengths.
    fn from_labels(labels: Vec<Vec<u8>>) -> Result<TargetName, NameError> {
        let mut wire = Vec::new();
        let mut text = String::new();
        for label in &labels {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(NameError::BadLabelLength);
            }
            // The length check above makes this conversion lossless.
            wire.push(u8::try_from(label.len()).map_err(|_| NameError::BadLabelLength)?);
            wire.extend_from_slice(label);
            write_label(&mut text, label);
            text.push('.');
        }
        wire.push(0);
        if wire.len() > MAX_WIRE_LEN {
            return Err(NameError::TooLong);
        }
        if text.is_empty() {
            text.push('.');
        }
        Ok(TargetName { text, wire })
    }

    /// Parses presentation text. `origin` is `None` for absolute semantics.
    fn parse_text(s: &str, origin: Option<&DomainName>) -> Result<TargetName, NameError> {
        if s.is_empty() {
            return Err(NameError::Empty);
        }
        if s == "@" {
            return origin.map(TargetName::from).ok_or(NameError::BadCharacter);
        }
        if s == "." {
            return Ok(TargetName::root());
        }

        // (label octets, label contains raw non-ASCII characters)
        let mut labels: Vec<(Vec<u8>, bool)> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        let mut unicode = false;
        let mut absolute = false;
        let bytes = s.as_bytes();
        let mut pos = 0usize;
        while let Some(&b) = bytes.get(pos) {
            match b {
                b'\\' => {
                    let (octets, used) = parse_escape(s, pos)?;
                    current.extend_from_slice(&octets);
                    pos += used;
                    continue;
                }
                b'.' => {
                    if current.is_empty() {
                        return Err(NameError::BadLabelLength);
                    }
                    labels.push((std::mem::take(&mut current), unicode));
                    unicode = false;
                    if pos + 1 == bytes.len() {
                        absolute = true;
                    }
                }
                b' ' | b'"' | b'(' | b')' | b';' => return Err(NameError::BadCharacter),
                0x00..=0x1f | 0x7f => return Err(NameError::BadCharacter),
                0x80..=0xff => {
                    current.push(b);
                    unicode = true;
                }
                _ => current.push(b),
            }
            pos += 1;
        }
        if !current.is_empty() {
            labels.push((current, unicode));
        }

        let mut out: Vec<Vec<u8>> = Vec::with_capacity(labels.len());
        for (label, has_unicode) in labels {
            if has_unicode {
                // A U-label is a display form of an A-label.
                let text = std::str::from_utf8(&label).map_err(|_| NameError::Idna)?;
                let ascii = idna::domain_to_ascii(text).map_err(|_| NameError::Idna)?;
                for part in ascii.split('.') {
                    if part.is_empty() {
                        return Err(NameError::BadLabelLength);
                    }
                    out.push(part.as_bytes().to_ascii_lowercase());
                }
            } else {
                out.push(label.to_ascii_lowercase());
            }
        }
        if !absolute && let Some(origin) = origin {
            out.extend(origin.labels().map(|label| label.as_bytes().to_vec()));
        }
        Self::from_labels(out)
    }
}

/// Parses the escape at `pos` (which holds a backslash). Returns the octets and the length of the
/// escape in the input.
fn parse_escape(s: &str, pos: usize) -> Result<(Vec<u8>, usize), NameError> {
    let rest = s.get(pos + 1..).ok_or(NameError::BadEscape)?;
    let mut chars = rest.chars();
    let first = chars.next().ok_or(NameError::BadEscape)?;
    if first.is_ascii_digit() {
        let digits = rest.get(..3).ok_or(NameError::BadEscape)?;
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(NameError::BadEscape);
        }
        let value: u16 = digits.parse().map_err(|_| NameError::BadEscape)?;
        let octet = u8::try_from(value).map_err(|_| NameError::BadEscape)?;
        return Ok((vec![octet], 4));
    }
    let mut buf = [0u8; 4];
    let encoded = first.encode_utf8(&mut buf);
    Ok((encoded.as_bytes().to_vec(), 1 + encoded.len()))
}

/// Writes one label in canonical text form (section 4.2 of the design).
fn write_label(out: &mut String, label: &[u8]) {
    for &b in label {
        match b {
            b'.' => out.push_str("\\."),
            b'\\' => out.push_str("\\\\"),
            b'"' | b'$' | b'(' | b')' | b';' | b'@' => push_decimal_escape(out, b),
            0x21..=0x7e => out.push(char::from(b)),
            _ => push_decimal_escape(out, b),
        }
    }
}

/// Writes `\DDD`.
fn push_decimal_escape(out: &mut String, b: u8) {
    out.push('\\');
    out.push(char::from(b'0' + b / 100));
    out.push(char::from(b'0' + (b / 10) % 10));
    out.push(char::from(b'0' + b % 10));
}

impl From<&DomainName> for TargetName {
    fn from(name: &DomainName) -> TargetName {
        // Owner-name labels are canonical target-name text as they are.
        let mut wire = Vec::with_capacity(name.as_str().len() + 1);
        for label in name.labels() {
            // Labels of a `DomainName` are at most 63 octets.
            wire.push(u8::try_from(label.len()).unwrap_or(0));
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        TargetName {
            text: name.as_str().to_owned(),
            wire,
        }
    }
}

impl From<DomainName> for TargetName {
    fn from(name: DomainName) -> TargetName {
        TargetName::from(&name)
    }
}

impl FromStr for TargetName {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TargetName::parse(s)
    }
}

impl fmt::Display for TargetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for TargetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TargetName({:?})", self.text)
    }
}

impl serde::Serialize for TargetName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text)
    }
}

impl<'de> serde::Deserialize<'de> for TargetName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        TargetName::parse(&text).map_err(serde::de::Error::custom)
    }
}
