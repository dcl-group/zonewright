//! Redaction of secrets from text that leaves the crate in errors.
//!
//! [`Detail`] is the bounded text an error carries: at most [`DETAIL_MAX_BYTES`] bytes and no
//! control characters, whoever built it. `Scrubber` (in `scrub`, compiled with `__http`) is the
//! only way the crate turns text taken from a provider's answer into a [`Detail`]: it knows every
//! secret its client holds and removes each of them, in every spelling an API can echo it in,
//! before the text is bounded.
//!
//! The limit, stated plainly: redaction is by substring. A secret echoed in a transformation not
//! listed on `Scrubber` (base64, a hash, a partial value) is not recognized. The defense for
//! those cases is that request bodies and headers never enter error text at all; the scrubber
//! covers what the provider sends back.

use std::fmt;

/// Upper bound of a [`Detail`] in bytes.
pub(crate) const DETAIL_MAX_BYTES: usize = 512;

/// Bounded text taken from a provider's answer or composed by the client.
///
/// A `Detail` is at most 512 bytes long and contains no control characters, whoever built it.
#[derive(Clone, PartialEq, Eq)]
pub struct Detail(Box<str>);

impl Detail {
    /// Replaces control characters by spaces and truncates to 512 bytes. It does not know any
    /// secret: whoever calls it is responsible for the text containing none.
    ///
    /// Besides the Unicode control characters (category Cc), the line and paragraph separators
    /// (U+2028, U+2029) and the bidirectional formatting characters are replaced too, so that a
    /// `Detail` cannot break a log line or reorder the text around it when displayed.
    /// Truncation happens on a character boundary.
    #[must_use]
    pub fn new(text: &str) -> Detail {
        Detail(bound(text).0.into_boxed_str())
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A `Detail` from text fixed in the crate's source. Such text contains no secret by
    /// construction; it is bounded and cleaned like any other.
    pub(crate) fn constant(text: &'static str) -> Detail {
        Detail::new(text)
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

/// True for characters a `Detail` never contains.
fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Line and paragraph separators.
            '\u{2028}' | '\u{2029}'
            // Bidirectional formatting: marks, embeddings, overrides and isolates.
            | '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

/// Replaces unsafe characters by spaces and truncates to [`DETAIL_MAX_BYTES`] on a character
/// boundary. The flag is true when the text was cut.
fn bound(text: &str) -> (String, bool) {
    let mut out = String::with_capacity(text.len().min(DETAIL_MAX_BYTES));
    for c in text.chars() {
        let c = if is_unsafe_char(c) { ' ' } else { c };
        if out.len() + c.len_utf8() > DETAIL_MAX_BYTES {
            return (out, true);
        }
        out.push(c);
    }
    (out, false)
}

#[cfg(feature = "__http")]
mod scrub;

#[cfg(feature = "__http")]
pub(crate) use scrub::{Scrubber, SecretSlot};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_new_bounds_and_cleans() {
        let detail = Detail::new("a\nb\rc\td\u{0}e\u{7f}f\u{85}g\u{2028}h\u{202e}i\u{2066}j");
        assert_eq!(detail.as_str(), "a b c d e f g h i j");
        assert_eq!(detail.to_string(), "a b c d e f g h i j");
        assert_eq!(format!("{detail:?}"), "\"a b c d e f g h i j\"");
        let long = "x".repeat(10_000);
        assert_eq!(Detail::new(&long).as_str().len(), DETAIL_MAX_BYTES);
        assert_eq!(
            Detail::new(&"я".repeat(300)).as_str().len(),
            DETAIL_MAX_BYTES
        );
        assert_eq!(Detail::new(&"€".repeat(200)).as_str().len(), 510);
        assert_eq!(Detail::new(&"\u{1F600}".repeat(200)).as_str().len(), 512);
        assert_eq!(Detail::constant("fixed text").as_str(), "fixed text");
        assert_eq!(Detail::new(""), Detail::new(""));
    }
}
