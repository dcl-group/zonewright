//! Redaction of secrets from text that leaves the crate in errors.
//!
//! [`Detail`] is the bounded text an error carries: at most [`DETAIL_MAX_BYTES`] bytes and no
//! control characters, whoever built it. [`Scrubber`] is the only way the crate turns text taken
//! from a provider's answer into a [`Detail`]: it knows every secret its client holds and removes
//! each of them, in every spelling an API can echo it in, before the text is bounded.
//!
//! The limit, stated plainly: redaction is by substring. A secret echoed in a transformation not
//! listed on [`Scrubber`] (base64, a hash, a partial value) is not recognized. The defense for
//! those cases is that request bodies and headers never enter error text at all; the scrubber
//! covers what the provider sends back.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Mutex, PoisonError};

use zeroize::Zeroizing;

/// Upper bound of a [`Detail`] in bytes.
pub(crate) const DETAIL_MAX_BYTES: usize = 512;

/// Marker that takes the place of a removed secret.
pub(crate) const REDACTED: &str = "[redacted]";

/// How many secrets registered at run time (tokens, signed assertions) a [`Scrubber`] keeps:
/// enough for the current and the previous token while one replaces the other.
const RUNTIME_SECRETS: usize = 4;

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

/// Removes the secrets of one client from text taken from a provider's answer.
///
/// Created in the client's constructor from every field of its credentials; every token the client
/// obtains at run time and every signed assertion it sends is added with
/// [`Scrubber::remember`]. The run-time list keeps the [`RUNTIME_SECRETS`] most recent entries.
///
/// For each secret the scrubber searches for the spellings in which an API can echo it:
///
/// - verbatim;
/// - `application/x-www-form-urlencoded` (WHATWG serializer), with `+` and with `%20` for a space;
/// - as the inside of a JSON string;
/// - JSON with `\/` and lowercase `\uXXXX` escapes for non-ASCII characters (the PHP
///   `json_encode` default);
/// - XML-escaped;
/// - and, for the truncation rule only in effect, each of these with its unsafe characters
///   replaced by spaces, the way [`Detail`] cleans them.
///
/// Every occurrence of any spelling, including overlapping ones, is replaced by `[redacted]`;
/// overlapping or adjacent occurrences become one marker. Empty secrets are ignored.
///
/// The needles are held in zeroizing memory, and `Debug` prints none of them.
pub(crate) struct Scrubber {
    fixed: Vec<Zeroizing<String>>,
    runtime: Mutex<VecDeque<RuntimeSecret>>,
}

/// A secret registered at run time with its spellings.
struct RuntimeSecret {
    secret: Zeroizing<String>,
    spellings: Vec<Zeroizing<String>>,
}

impl fmt::Debug for Scrubber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scrubber").finish_non_exhaustive()
    }
}

impl Scrubber {
    /// A scrubber for the given secrets; empty ones are ignored.
    pub(crate) fn new<'a>(secrets: impl IntoIterator<Item = &'a str>) -> Scrubber {
        let mut fixed: Vec<Zeroizing<String>> = secrets.into_iter().flat_map(spellings).collect();
        sort_longest_first(&mut fixed);
        Scrubber {
            fixed,
            runtime: Mutex::new(VecDeque::new()),
        }
    }

    /// Registers a secret obtained at run time: a token or a signed assertion. Only the
    /// [`RUNTIME_SECRETS`] most recent ones are kept; registering a secret that is already known
    /// makes it the most recent.
    pub(crate) fn remember(&self, secret: &str) {
        let spellings = spellings(secret);
        if spellings.is_empty() {
            return;
        }
        let entry = RuntimeSecret {
            secret: Zeroizing::new(secret.to_owned()),
            spellings,
        };
        // A panic while the lock was held cannot leave the list half-updated in a way that
        // matters here: every state of it is a valid list of secrets.
        let mut runtime = self.runtime.lock().unwrap_or_else(PoisonError::into_inner);
        runtime.retain(|known| known.secret.as_str() != secret);
        runtime.push_back(entry);
        while runtime.len() > RUNTIME_SECRETS {
            runtime.pop_front();
        }
    }

    /// The text with every registered secret replaced, not bounded. For bodies that are parsed
    /// after scrubbing.
    pub(crate) fn scrub(&self, text: &str) -> String {
        self.with_needles(|needles| redact(text, needles))
    }

    /// A [`Detail`] from text taken from a provider's answer.
    ///
    /// Order: scrub, then replace unsafe characters by spaces, then truncate to 512 bytes on a
    /// character boundary. When the text was cut, a trailing fragment that is a prefix of any
    /// registered spelling is removed as well, so that the head of a secret cut by the limit is
    /// not exposed.
    pub(crate) fn detail(&self, text: &str) -> Detail {
        self.with_needles(|needles| {
            let scrubbed = redact(text, needles);
            let (mut out, truncated) = bound(&scrubbed);
            if truncated {
                strip_cut_prefix(&mut out, needles);
            }
            Detail(out.into_boxed_str())
        })
    }

    /// Runs `f` with every needle, fixed and run-time.
    fn with_needles<R>(&self, f: impl FnOnce(&[&str]) -> R) -> R {
        let runtime = self.runtime.lock().unwrap_or_else(PoisonError::into_inner);
        let needles: Vec<&str> = self
            .fixed
            .iter()
            .chain(runtime.iter().flat_map(|entry| entry.spellings.iter()))
            .map(|needle| needle.as_str())
            .collect();
        f(&needles)
    }
}

/// Every spelling of `secret` the scrubber searches for, longest first, without duplicates.
fn spellings(secret: &str) -> Vec<Zeroizing<String>> {
    if secret.is_empty() {
        return Vec::new();
    }
    let json = json_inner(secret);
    let mut out = vec![
        Zeroizing::new(secret.to_owned()),
        form_urlencode(secret, "+"),
        form_urlencode(secret, "%20"),
        php_json_inner(&json),
        xml_escape(secret),
        json,
    ];
    let cleaned: Vec<Zeroizing<String>> = out
        .iter()
        .filter(|spelling| spelling.chars().any(is_unsafe_char))
        .map(|spelling| clean(spelling))
        .collect();
    out.extend(cleaned);
    out.retain(|spelling| !spelling.is_empty());
    sort_longest_first(&mut out);
    out
}

/// Sorts needles longest first and removes duplicates.
fn sort_longest_first(needles: &mut Vec<Zeroizing<String>>) {
    needles.sort_unstable_by(|a, b| {
        b.len()
            .cmp(&a.len())
            .then_with(|| a.as_str().cmp(b.as_str()))
    });
    needles.dedup_by(|a, b| a.as_str() == b.as_str());
}

/// Appends the lowercase or uppercase hexadecimal digit for the low four bits of `nibble`.
fn push_hex_digit(out: &mut String, nibble: u8, uppercase: bool) {
    let digit = char::from_digit(u32::from(nibble & 0x0f), 16).unwrap_or('0');
    out.push(if uppercase {
        digit.to_ascii_uppercase()
    } else {
        digit
    });
}

/// `application/x-www-form-urlencoded` per the WHATWG URL standard's serializer: ASCII letters,
/// digits and `*-._` as they are, a space as `space`, every other byte as `%XX` (uppercase).
fn form_urlencode(s: &str, space: &str) -> Zeroizing<String> {
    // Capacity for the worst case, so the buffer never reallocates and leaves no unwiped copy.
    let mut out = Zeroizing::new(String::with_capacity(s.len().saturating_mul(3)));
    for b in s.bytes() {
        match b {
            b'*' | b'-' | b'.' | b'_' => out.push(char::from(b)),
            b if b.is_ascii_alphanumeric() => out.push(char::from(b)),
            b' ' => out.push_str(space),
            b => {
                out.push('%');
                push_hex_digit(&mut out, b >> 4, true);
                push_hex_digit(&mut out, b, true);
            }
        }
    }
    out
}

/// The inside of a JSON string as `serde_json` (and most encoders) writes it: `"` and `\`
/// escaped, `\b \f \n \r \t` for those controls, `\u00xx` (lowercase) for the other C0
/// controls, everything else as it is.
fn json_inner(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len().saturating_mul(6)));
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                out.push_str("\\u00");
                let b = u8::try_from(u32::from(c)).unwrap_or(0);
                push_hex_digit(&mut out, b >> 4, false);
                push_hex_digit(&mut out, b, false);
            }
            c => out.push(c),
        }
    }
    out
}

/// The PHP `json_encode` default spelling, derived from [`json_inner`]: `/` as `\/` and every
/// non-ASCII character as lowercase `\uXXXX`, with UTF-16 surrogate pairs above U+FFFF.
fn php_json_inner(json: &str) -> Zeroizing<String> {
    // A non-ASCII character of n bytes becomes at most 12 bytes (a surrogate pair) for n = 4,
    // so three times the input is enough.
    let mut out = Zeroizing::new(String::with_capacity(json.len().saturating_mul(3)));
    for c in json.chars() {
        match c {
            '/' => out.push_str("\\/"),
            c if c.is_ascii() => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units).iter() {
                    out.push_str("\\u");
                    for shift in [12u16, 8, 4, 0] {
                        let nibble = u8::try_from((unit >> shift) & 0x0f).unwrap_or(0);
                        push_hex_digit(&mut out, nibble, false);
                    }
                }
                units.fill(0);
            }
        }
    }
    out
}

/// XML text and attribute escaping of the five predefined entities.
fn xml_escape(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len().saturating_mul(6)));
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// `s` with unsafe characters replaced by spaces, as [`bound`] does, without truncation.
fn clean(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    for c in s.chars() {
        out.push(if is_unsafe_char(c) { ' ' } else { c });
    }
    out
}

/// Replaces every occurrence of every needle in `text` by [`REDACTED`]. Occurrences are found
/// in the original text, overlapping ones included, and merged before replacement, so neither
/// the order of the needles nor the inserted markers affect what is found.
fn redact(text: &str, needles: &[&str]) -> String {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for needle in needles.iter().filter(|needle| !needle.is_empty()) {
        let mut from = 0;
        while let Some(rest) = text.get(from..) {
            let Some(pos) = rest.find(needle) else {
                break;
            };
            let start = from + pos;
            let end = start + needle.len();
            match ranges.last_mut() {
                // Occurrences of one needle come in increasing order; merge them as they come
                // so that a short needle repeated many times does not grow the list.
                Some(last) if last.0 <= start && start <= last.1 => last.1 = last.1.max(end),
                _ => ranges.push((start, end)),
            }
            // Step one character forward to find overlapping occurrences as well. A needle is
            // valid UTF-8, so it only matches at character boundaries.
            let step = text
                .get(start..)
                .and_then(|tail| tail.chars().next())
                .map_or(1, char::len_utf8);
            from = start + step;
        }
    }
    if ranges.is_empty() {
        return text.to_owned();
    }
    ranges.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut current: Option<(usize, usize)> = None;
    for (start, end) in ranges {
        match current.as_mut() {
            Some(cur) if start <= cur.1 => cur.1 = cur.1.max(end),
            _ => {
                if let Some((cur_start, cur_end)) = current {
                    out.push_str(text.get(copied..cur_start).unwrap_or(""));
                    out.push_str(REDACTED);
                    copied = cur_end;
                }
                current = Some((start, end));
            }
        }
    }
    if let Some((cur_start, cur_end)) = current {
        out.push_str(text.get(copied..cur_start).unwrap_or(""));
        out.push_str(REDACTED);
        copied = cur_end;
    }
    out.push_str(text.get(copied..).unwrap_or(""));
    out
}

/// Removes the longest trailing fragment of `out` that is a prefix of any needle.
fn strip_cut_prefix(out: &mut String, needles: &[&str]) {
    let mut longest = 0;
    for needle in needles {
        let max = needle.len().min(out.len());
        let found = (1..=max)
            .rev()
            .filter(|&k| needle.is_char_boundary(k))
            .find(|&k| needle.get(..k).is_some_and(|head| out.ends_with(head)));
        if let Some(k) = found {
            longest = longest.max(k);
        }
    }
    if longest > 0 {
        let end = out.len() - longest;
        // The fragment matched a prefix that ends on a character boundary of a valid UTF-8
        // needle, so `end` is a character boundary of `out`.
        if out.is_char_boundary(end) {
            out.truncate(end);
        } else {
            out.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canary that every listed encoding changes: `@`, a space, `/`, `+`, `&`, `"`, `<`, `'`,
    /// `>` and non-ASCII letters.
    const SECRET: &str = "p@ss w/rd+&ключ\"x<'>";

    /// The spellings of `SECRET`, written out by hand rather than by the functions under test.
    const SPELLINGS: [&str; 6] = [
        // Verbatim.
        "p@ss w/rd+&ключ\"x<'>",
        // Form-urlencoded, `+` for a space.
        "p%40ss+w%2Frd%2B%26%D0%BA%D0%BB%D1%8E%D1%87%22x%3C%27%3E",
        // Form-urlencoded, `%20` for a space.
        "p%40ss%20w%2Frd%2B%26%D0%BA%D0%BB%D1%8E%D1%87%22x%3C%27%3E",
        // Inside of a JSON string.
        "p@ss w/rd+&ключ\\\"x<'>",
        // PHP json_encode default.
        "p@ss w\\/rd+&\\u043a\\u043b\\u044e\\u0447\\\"x<'>",
        // XML-escaped.
        "p@ss w/rd+&amp;ключ&quot;x&lt;&apos;&gt;",
    ];

    fn assert_bounded(detail: &Detail) {
        let s = detail.as_str();
        assert!(s.len() <= DETAIL_MAX_BYTES, "{} bytes", s.len());
        assert!(!s.chars().any(is_unsafe_char), "{s:?}");
    }

    /// True when `s` ends with a prefix of `needle` at least `min` bytes long.
    fn ends_with_prefix(s: &str, needle: &str, min: usize) -> bool {
        (min..=needle.len().min(s.len()))
            .filter(|&k| needle.is_char_boundary(k))
            .any(|k| s.ends_with(&needle[..k]))
    }

    #[test]
    fn spellings_match_hand_written_forms() {
        let generated = spellings(SECRET);
        for expected in SPELLINGS {
            assert!(
                generated.iter().any(|s| s.as_str() == expected),
                "missing {expected}"
            );
        }
        assert_eq!(generated.len(), SPELLINGS.len());
        for pair in generated.windows(2) {
            assert!(pair[0].len() >= pair[1].len(), "not longest first");
        }
    }

    #[test]
    fn json_inner_agrees_with_serde_json() {
        for s in [
            SECRET,
            "plain",
            "tab\there\nnew\rline\u{08}\u{0c}",
            "\u{00}\u{01}\u{1f}\u{7f}",
            "back\\slash \"quoted\"",
            "emoji \u{1F600} and \u{FFFF}",
        ] {
            let full = serde_json::to_string(s).unwrap();
            let inner = &full[1..full.len() - 1];
            assert_eq!(json_inner(s).as_str(), inner, "{s:?}");
        }
    }

    #[test]
    fn php_json_uses_surrogate_pairs_above_the_bmp() {
        assert_eq!(
            php_json_inner(&json_inner("a/\u{1F600}é")).as_str(),
            "a\\/\\ud83d\\ude00\\u00e9"
        );
    }

    #[test]
    fn every_spelling_is_scrubbed() {
        let scrubber = Scrubber::new([SECRET, ""]);
        for spelling in SPELLINGS {
            let detail = scrubber.detail(&format!("error: {spelling} end"));
            assert_eq!(detail.as_str(), "error: [redacted] end", "{spelling}");
        }
        // Echoed inside a JSON document and a form body as an API would return them.
        let json = serde_json::json!({ "message": "bad", "password": SECRET }).to_string();
        let detail = scrubber.detail(&json);
        assert!(detail.as_str().contains(REDACTED), "{detail}");
        for spelling in SPELLINGS {
            assert!(!detail.as_str().contains(spelling));
        }
        assert!(!detail.as_str().contains("ключ") && !detail.as_str().contains("rd+"));
        let form = format!("user=u&password={}&x=1", SPELLINGS[1]);
        assert_eq!(
            scrubber.detail(&form).as_str(),
            "user=u&password=[redacted]&x=1"
        );
    }

    #[test]
    fn scrub_is_unbounded_and_detail_is_bounded() {
        let scrubber = Scrubber::new([SECRET]);
        let body = format!("{}{SECRET}", "a".repeat(10_000));
        let scrubbed = scrubber.scrub(&body);
        assert_eq!(scrubbed.len(), 10_000 + REDACTED.len());
        assert!(scrubbed.ends_with(REDACTED));
        assert_bounded(&scrubber.detail(&body));
    }

    #[test]
    fn repeated_occurrences_are_all_scrubbed() {
        let scrubber = Scrubber::new(["tok-123"]);
        assert_eq!(
            scrubber.scrub("tok-123 and tok-123,tok-123"),
            "[redacted] and [redacted],[redacted]"
        );
        // Adjacent occurrences become one marker.
        assert_eq!(scrubber.scrub("tok-123tok-123"), "[redacted]");
        // A secret that overlaps itself.
        let scrubber = Scrubber::new(["aXa"]);
        assert_eq!(scrubber.scrub("<aXaXa>"), "<[redacted]>");
    }

    #[test]
    fn overlapping_secrets_are_both_scrubbed() {
        let scrubber = Scrubber::new(["abcdef12", "ef12ghij"]);
        assert_eq!(scrubber.scrub("x abcdef12ghij y"), "x [redacted] y");
        // Order of registration does not matter.
        let scrubber = Scrubber::new(["ef12ghij", "abcdef12"]);
        assert_eq!(scrubber.scrub("x abcdef12ghij y"), "x [redacted] y");
        // One secret contained in another.
        let scrubber = Scrubber::new(["secret", "my-secret-value"]);
        assert_eq!(
            scrubber.scrub("a my-secret-value b secret"),
            "a [redacted] b [redacted]"
        );
    }

    #[test]
    fn one_character_and_empty_secrets() {
        let scrubber = Scrubber::new(["", "q"]);
        let detail = scrubber.detail("error: the key q was quoted");
        assert_eq!(
            detail.as_str(),
            "error: the key [redacted] was [redacted]uoted"
        );
        let detail = scrubber.detail(&"q".repeat(100_000));
        assert_bounded(&detail);
        assert_eq!(detail.as_str(), REDACTED);
        let detail = scrubber.detail(&"ab".repeat(1_000));
        assert_bounded(&detail);
        assert_eq!(detail.as_str(), "ab".repeat(256));
        // Only empty secrets: nothing changes.
        let scrubber = Scrubber::new(["", ""]);
        assert_eq!(scrubber.scrub("text"), "text");
        assert_eq!(scrubber.detail("").as_str(), "");
        scrubber.remember("");
        assert_eq!(scrubber.scrub("text"), "text");
    }

    #[test]
    fn full_secret_at_every_offset_around_the_cut() {
        let scrubber = Scrubber::new([SECRET]);
        for spelling in SPELLINGS {
            let start = DETAIL_MAX_BYTES - spelling.len() - 4;
            for fill in start..DETAIL_MAX_BYTES + 4 {
                let text = format!("{}{spelling} tail", "x".repeat(fill));
                let detail = scrubber.detail(&text);
                assert_bounded(&detail);
                for needle in SPELLINGS {
                    assert!(!ends_with_prefix(detail.as_str(), needle, 1), "{detail}");
                    assert!(!detail.as_str().contains(needle));
                }
            }
        }
    }

    #[test]
    fn head_of_a_secret_left_at_the_cut_is_removed() {
        // The provider itself cut its echo: only the head of the secret is in the text, and our
        // truncation ends inside it.
        let secret = "SECRETTOKEN-0123456789";
        let scrubber = Scrubber::new([secret]);
        let head = &secret[..secret.len() - 1];
        // Every fill for which the cut falls inside the head.
        for fill in DETAIL_MAX_BYTES - head.len() + 1..DETAIL_MAX_BYTES {
            let text = format!("{}{head} and more text", "x".repeat(fill));
            let detail = scrubber.detail(&text);
            assert_bounded(&detail);
            assert!(!ends_with_prefix(detail.as_str(), secret, 1), "{detail}");
            assert!(detail.as_str().chars().all(|c| c == 'x'), "{detail}");
        }
        // Text that was not cut keeps its end, even if it looks like a secret's head.
        assert_eq!(scrubber.detail("status 401 S").as_str(), "status 401 S");
    }

    #[test]
    fn multibyte_secret_at_the_cut() {
        let secret = "ключ-секрет-€-\u{1F600}-значение";
        let scrubber = Scrubber::new([secret]);
        let encodings = spellings(secret);
        for fill in DETAIL_MAX_BYTES - 60..DETAIL_MAX_BYTES {
            let filler = "я".repeat(fill / 2) + &"z".repeat(fill % 2);
            // Every head of the secret that our cut falls inside, followed by other text as if
            // the provider had cut its echo.
            let cuts = (1..secret.len())
                .filter(|&k| secret.is_char_boundary(k) && fill + k > DETAIL_MAX_BYTES);
            for cut in cuts {
                let text = format!("{filler}{} ZZZZZZZZ", &secret[..cut]);
                let detail = scrubber.detail(&text);
                assert_bounded(&detail);
                for needle in &encodings {
                    assert!(!ends_with_prefix(detail.as_str(), needle, 1), "{detail}");
                }
            }
        }
        // Filler of three-byte characters whose cut falls inside a character.
        let detail = scrubber.detail(&"€".repeat(400));
        assert_bounded(&detail);
        assert_eq!(detail.as_str().len(), 510);
    }

    #[test]
    fn secret_with_a_control_character() {
        // A PEM key spans lines: scrubbed verbatim and JSON-escaped before cleaning, and its
        // cleaned form is known to the truncation rule.
        let secret = "line-one\nline-two";
        let scrubber = Scrubber::new([secret]);
        assert_eq!(
            scrubber.detail("a line-one\nline-two b").as_str(),
            "a [redacted] b"
        );
        assert_eq!(
            scrubber.detail("a line-one\\nline-two b").as_str(),
            "a [redacted] b"
        );
        let text = format!("{}line-one\nline-", "x".repeat(DETAIL_MAX_BYTES - 10));
        let detail = scrubber.detail(&format!("{text}tw"));
        assert_bounded(&detail);
        assert!(!detail.as_str().contains("line"), "{detail}");
    }

    #[test]
    fn runtime_secrets_are_scrubbed_and_the_oldest_forgotten() {
        let scrubber = Scrubber::new(["pw-1"]);
        scrubber.remember("tok-aaaa");
        assert_eq!(scrubber.scrub("a tok-aaaa pw-1"), "a [redacted] [redacted]");
        for token in ["tok-bbbb", "tok-cccc", "tok-dddd"] {
            scrubber.remember(token);
        }
        // Registering a known secret again makes it the most recent instead of a duplicate.
        scrubber.remember("tok-aaaa");
        scrubber.remember("tok-eeee");
        assert_eq!(
            scrubber.scrub("tok-aaaa tok-bbbb tok-cccc tok-dddd tok-eeee"),
            "[redacted] tok-bbbb [redacted] [redacted] [redacted]"
        );
        // Run-time secrets are found in every spelling too.
        scrubber.remember("a b/c");
        assert_eq!(scrubber.scrub("x a+b%2Fc y"), "x [redacted] y");
        assert_eq!(scrubber.scrub("pw-1"), REDACTED);
    }

    #[test]
    fn debug_prints_no_secret() {
        let scrubber = Scrubber::new([SECRET, "fixed-canary"]);
        scrubber.remember("runtime-canary");
        let debug = format!("{scrubber:?} {scrubber:#?}");
        assert_eq!(format!("{scrubber:?}"), "Scrubber { .. }");
        for canary in ["fixed-canary", "runtime-canary", "ключ", "p@ss"] {
            assert!(!debug.contains(canary), "{debug}");
        }
    }

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

    #[test]
    fn detail_is_always_bounded() {
        let scrubber = Scrubber::new([SECRET, "x"]);
        let pieces = [
            "a",
            "я",
            "€",
            "\u{1F600}",
            "\n",
            "\u{85}",
            "\u{2028}",
            SECRET,
            "x",
        ];
        for len in [0, 1, 100, 509, 510, 511, 512, 513, 514, 1_000, 5_000] {
            for (i, piece) in pieces.iter().enumerate() {
                let mut text = String::new();
                let mut j = i;
                while text.len() < len {
                    text.push_str(piece);
                    text.push_str(pieces[j % pieces.len()]);
                    j += 1;
                }
                assert_bounded(&Detail::new(&text));
                let detail = scrubber.detail(&text);
                assert_bounded(&detail);
                assert!(!detail.as_str().contains('x'), "{detail}");
                assert!(!detail.as_str().contains("ключ"), "{detail}");
            }
        }
    }
}
