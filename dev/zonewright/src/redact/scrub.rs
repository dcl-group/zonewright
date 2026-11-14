//! The scrubber: removal of a client's secrets from text taken from a provider's answer (see the
//! parent module). Only HTTP provider clients take text from an answer into an error, so this is
//! compiled with `__http`.

// Design section 9.2: not every HTTP provider uses every part of the scrubber, so builds without
// `all-providers` allow unused code here; the build with all providers does not.
#![cfg_attr(not(feature = "all-providers"), allow(dead_code))]

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use zeroize::Zeroizing;

use super::{DETAIL_MAX_BYTES, Detail, bound, is_unsafe_char};

/// Marker that takes the place of a removed secret.
pub(crate) const REDACTED: &str = "[redacted]";

/// The whole text of a [`Detail`] whose source quoted a credential in a spelling the scrubber
/// cannot replace in place (see [`Scrubber`]).
pub(crate) const WITHHELD: &str = "[redacted] (the provider's message was withheld: it quoted a credential in an encoding that cannot be removed in place)";

/// Rounds of decoding applied to a text before the scrubber concludes it holds no secret.
const DECODE_ROUNDS: usize = 3;

/// Longest prefix of a scrubbed text that is decoded and searched again: what the [`Detail`]
/// shows, plus room for the longest needle in the widest encoding met (12 bytes per byte), at
/// most 64 KiB.
const DECODE_WINDOW_MAX: usize = 64 * 1024;

/// Identifies one source of secrets obtained at run time, such as one token cache or one signer
/// of assertions. The scrubber keeps the current and the previous secret of every slot, so that
/// a client with several token sources never loses the coverage of a live token.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SecretSlot(u64);

impl SecretSlot {
    /// A slot no other slot in the process equals.
    pub(crate) fn new() -> SecretSlot {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        SecretSlot(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// Removes the secrets of one client from text taken from a provider's answer.
///
/// Created in the client's constructor from every field of its credentials; every token the client
/// obtains at run time and every signed assertion it sends is added with [`Scrubber::remember`]
/// under the [`SecretSlot`] of its source, which keeps that source's current and previous secret.
///
/// Matching works in two ways.
///
/// 1. Encoded needles, replaced in place. For each secret the scrubber searches for the spellings
///    in which an API most often echoes it:
///    - verbatim;
///    - `application/x-www-form-urlencoded` (WHATWG serializer), with `+` and with `%20` for a
///      space;
///    - RFC 3986 percent-encoding (unreserved characters kept, uppercase hex), the encoding of
///      the crate's own URL builder;
///    - as the inside of a JSON string;
///    - JSON with `\/` and lowercase `\uXXXX` escapes for non-ASCII characters (the PHP
///      `json_encode` default);
///    - XML-escaped;
///    - and, for the truncation rule only in effect, each of these with its unsafe characters
///      replaced by spaces, the way [`Detail`] cleans them.
///
///    Every occurrence of any spelling, including overlapping ones, is replaced by `[redacted]`;
///    overlapping or adjacent occurrences become one marker. Empty secrets are ignored.
/// 2. A decoded haystack, for every other dialect (lowercase percent-hex, other percent-encoding
///    safe sets, numeric XML character references, partial escaping, uppercase or extra JSON
///    `\u` escapes, JSON inside JSON, form-encoded JSON). After the replacement above, the text
///    is decoded — percent-decoding of any hex case with and without `+` for a space, XML entity
///    decoding (the five named entities, decimal and hexadecimal references), JSON string
///    unescaping — in every combination, up to three rounds deep. If any needle appears in any
///    decoded layer, the secret cannot be cut out in place, and the whole [`Detail`] becomes the
///    constant [`WITHHELD`] text. Only the part of the text that can reach the `Detail` is
///    decoded: its first 512 bytes plus 12 bytes for every byte of the longest needle, at most
///    64 KiB. The work is therefore bounded by 84 decoded layers of at most 64 KiB, each
///    searched for every needle.
///
/// The needles are held in zeroizing memory, and `Debug` prints none of them.
pub(crate) struct Scrubber {
    fixed: Vec<Zeroizing<String>>,
    runtime: Mutex<Vec<SlotEntry>>,
}

/// The secrets of one [`SecretSlot`].
struct SlotEntry {
    slot: u64,
    current: RuntimeSecret,
    previous: Option<RuntimeSecret>,
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
            runtime: Mutex::new(Vec::new()),
        }
    }

    /// Registers a secret obtained at run time (a token, a signed assertion) as the current
    /// secret of `slot`; the slot's previous current secret stays registered as its previous
    /// one, and the one before is forgotten. Registering the slot's current secret again costs a
    /// comparison and changes nothing.
    pub(crate) fn remember(&self, slot: &SecretSlot, secret: &str) {
        if secret.is_empty() {
            return;
        }
        // A panic while the lock was held cannot leave the list half-updated in a way that
        // matters here: every state of it is a valid list of secrets.
        let mut runtime = self.runtime.lock().unwrap_or_else(PoisonError::into_inner);
        let index = runtime.iter().position(|entry| entry.slot == slot.0);
        if let Some(entry) = index.and_then(|i| runtime.get(i))
            && entry.current.secret.as_str() == secret
        {
            return;
        }
        let fresh = RuntimeSecret {
            secret: Zeroizing::new(secret.to_owned()),
            spellings: spellings(secret),
        };
        match index.and_then(|i| runtime.get_mut(i)) {
            Some(entry) => {
                let old = std::mem::replace(&mut entry.current, fresh);
                entry.previous = Some(old);
            }
            None => runtime.push(SlotEntry {
                slot: slot.0,
                current: fresh,
                previous: None,
            }),
        }
    }

    /// The text with every registered secret replaced, not bounded. For bodies that are parsed
    /// after scrubbing; only encoded needles are replaced here. The text taken from the parsed
    /// body then goes through [`Scrubber::detail`], which applies the decoded check as well.
    pub(crate) fn scrub(&self, text: &str) -> String {
        self.with_needles(|needles| redact(text, needles))
    }

    /// A [`Detail`] from text taken from a provider's answer.
    ///
    /// Order: replace encoded needles; if a needle remains in a decoded layer of the part of the
    /// text that can reach the `Detail`, return [`WITHHELD`]; otherwise replace unsafe characters
    /// by spaces, then truncate to 512 bytes on a character boundary. When the text was cut, a
    /// trailing fragment that is a prefix of any registered spelling is removed as well, so that
    /// the head of a secret cut by the limit is not exposed.
    pub(crate) fn detail(&self, text: &str) -> Detail {
        self.with_needles(|needles| {
            let scrubbed = redact(text, needles);
            let longest = needles.iter().map(|n| n.len()).max().unwrap_or(0);
            let window = window(&scrubbed, longest);
            if hidden_in_decoded(window, needles) {
                return Detail::constant(WITHHELD);
            }
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
            .chain(runtime.iter().flat_map(|entry| {
                entry
                    .current
                    .spellings
                    .iter()
                    .chain(entry.previous.iter().flat_map(|p| p.spellings.iter()))
            }))
            .map(|needle| needle.as_str())
            .collect();
        f(&needles)
    }
}

/// The prefix of `text` that is decoded: [`DETAIL_MAX_BYTES`] plus 12 bytes per byte of the
/// longest needle, at most [`DECODE_WINDOW_MAX`], on a character boundary.
fn window(text: &str, longest_needle: usize) -> &str {
    let want = DETAIL_MAX_BYTES
        .saturating_add(longest_needle.saturating_mul(12))
        .min(DECODE_WINDOW_MAX);
    if text.len() <= want {
        return text;
    }
    let mut end = want;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or("")
}

/// The decoders of the decoded check.
const DECODERS: &[fn(&str) -> Option<String>] = &[
    percent_decode_plus,
    percent_decode_keep_plus,
    entity_decode,
    json_unescape,
];

/// True when some needle occurs in a layer obtained from `text` by up to [`DECODE_ROUNDS`]
/// rounds of the [`DECODERS`] in every combination.
fn hidden_in_decoded(text: &str, needles: &[&str]) -> bool {
    if needles.is_empty() {
        return false;
    }
    let mut seen: Vec<String> = Vec::new();
    let mut frontier: Vec<String> = vec![text.to_owned()];
    for _ in 0..DECODE_ROUNDS {
        let mut next = Vec::new();
        for layer in &frontier {
            for decode in DECODERS.iter() {
                let Some(decoded) = decode(layer) else {
                    continue;
                };
                if seen.contains(&decoded) {
                    continue;
                }
                if needles.iter().any(|n| !n.is_empty() && decoded.contains(n)) {
                    return true;
                }
                seen.push(decoded.clone());
                next.push(decoded);
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    false
}

/// The value of an ASCII hexadecimal digit, either case.
fn hex_value(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// Percent-decoding with `%XX` in either hex case; `+` becomes a space when `plus` is set.
/// Malformed escapes stay as they are; bytes that are not UTF-8 are replaced. `None` when
/// nothing changes.
fn percent_decode(s: &str, plus: bool) -> Option<String> {
    if !s.contains('%') && !(plus && s.contains('+')) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'%' => {
                let hi = bytes.get(i + 1).copied().and_then(hex_value);
                let lo = bytes.get(i + 2).copied().and_then(hex_value);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push(hi << 4 | lo);
                    i += 3;
                    continue;
                }
                out.push(b);
            }
            b'+' if plus => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    let decoded = String::from_utf8_lossy(&out).into_owned();
    (decoded != s).then_some(decoded)
}

fn percent_decode_plus(s: &str) -> Option<String> {
    percent_decode(s, true)
}

fn percent_decode_keep_plus(s: &str) -> Option<String> {
    percent_decode(s, false)
}

/// XML entity decoding: `&amp; &lt; &gt; &quot; &apos;`, `&#NNN;` and `&#xHHH;` (either case).
/// Anything else stays as it is. `None` when nothing changes.
fn entity_decode(s: &str) -> Option<String> {
    if !s.contains('&') {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(rest.get(..pos).unwrap_or(""));
        let tail = rest.get(pos..).unwrap_or("");
        let entity = tail
            .get(1..)
            .and_then(|t| t.find(';').filter(|&end| end <= 10).map(|end| (t, end)));
        let decoded = entity.and_then(|(t, end)| {
            let name = t.get(..end)?;
            let c = match name {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                _ => {
                    let number = name.strip_prefix('#')?;
                    let value = match number.strip_prefix(['x', 'X']) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                        None => number.parse::<u32>().ok()?,
                    };
                    char::from_u32(value)?
                }
            };
            Some((c, end + 2))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = tail.get(len..).unwrap_or("");
            }
            None => {
                out.push('&');
                rest = tail.get(1..).unwrap_or("");
            }
        }
    }
    out.push_str(rest);
    (out != s).then_some(out)
}

/// Four hexadecimal digits of either case at the start of `s`.
fn hex4(s: &str) -> Option<u32> {
    let digits = s.get(..4)?;
    if digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        u32::from_str_radix(digits, 16).ok()
    } else {
        None
    }
}

/// JSON string unescaping: `\" \\ \/ \b \f \n \r \t` and `\uXXXX` in either hex case,
/// surrogate pairs joined, a lone surrogate replaced. Unknown escapes stay as they are. `None`
/// when nothing changes.
fn json_unescape(s: &str) -> Option<String> {
    if !s.contains('\\') {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let rest = s.get(i + 1..).unwrap_or("");
        let simple = match rest.chars().next() {
            Some('"') => Some('"'),
            Some('\\') => Some('\\'),
            Some('/') => Some('/'),
            Some('b') => Some('\u{08}'),
            Some('f') => Some('\u{0c}'),
            Some('n') => Some('\n'),
            Some('r') => Some('\r'),
            Some('t') => Some('\t'),
            _ => None,
        };
        if let Some(c) = simple {
            out.push(c);
            chars.next();
            continue;
        }
        let unit = rest.strip_prefix('u').and_then(hex4);
        match unit {
            Some(high @ 0xD800..=0xDBFF) => {
                let low = rest
                    .get(5..)
                    .and_then(|r| r.strip_prefix("\\u"))
                    .and_then(hex4)
                    .filter(|low| (0xDC00..=0xDFFF).contains(low));
                match low {
                    Some(low) => {
                        let code = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                        out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        for _ in 0..11 {
                            chars.next();
                        }
                    }
                    None => {
                        out.push('\u{FFFD}');
                        for _ in 0..5 {
                            chars.next();
                        }
                    }
                }
            }
            Some(unit) => {
                out.push(char::from_u32(unit).unwrap_or('\u{FFFD}'));
                for _ in 0..5 {
                    chars.next();
                }
            }
            None => out.push('\\'),
        }
    }
    (out != s).then_some(out)
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
        percent_rfc3986(secret),
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

/// RFC 3986 percent-encoding: the unreserved characters (`A-Z a-z 0-9 - . _ ~`) as they are,
/// every other byte as `%XX` (uppercase), a space as `%20`.
fn percent_rfc3986(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len().saturating_mul(3)));
    for b in s.bytes() {
        match b {
            b'-' | b'.' | b'_' | b'~' => out.push(char::from(b)),
            b if b.is_ascii_alphanumeric() => out.push(char::from(b)),
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
        scrubber.remember(&SecretSlot::new(), "");
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
    fn runtime_secrets_are_kept_per_slot_current_and_previous() {
        let scrubber = Scrubber::new(["pw-1"]);
        let tokens = SecretSlot::new();
        let other = SecretSlot::new();
        scrubber.remember(&tokens, "tok-aaaa");
        assert_eq!(scrubber.scrub("a tok-aaaa pw-1"), "a [redacted] [redacted]");
        // Any number of other slots does not evict this slot's secrets.
        for i in 0..20 {
            scrubber.remember(&SecretSlot::new(), &format!("other-{i:02}"));
        }
        scrubber.remember(&other, "jwt-1111");
        assert_eq!(scrubber.scrub("tok-aaaa"), REDACTED);
        // Current and previous are kept; the one before is forgotten.
        scrubber.remember(&tokens, "tok-bbbb");
        assert_eq!(scrubber.scrub("tok-aaaa tok-bbbb"), "[redacted] [redacted]");
        scrubber.remember(&tokens, "tok-cccc");
        assert_eq!(
            scrubber.scrub("tok-aaaa tok-bbbb tok-cccc"),
            "tok-aaaa [redacted] [redacted]"
        );
        // Registering the current secret again changes nothing.
        scrubber.remember(&tokens, "tok-cccc");
        assert_eq!(scrubber.scrub("tok-bbbb tok-cccc"), "[redacted] [redacted]");
        // The other slots are untouched.
        assert_eq!(
            scrubber.scrub("jwt-1111 other-00 other-19"),
            "[redacted] [redacted] [redacted]"
        );
        // Run-time secrets are found in every spelling too.
        scrubber.remember(&other, "a b/c");
        assert_eq!(scrubber.scrub("x a+b%2Fc y"), "x [redacted] y");
        assert_eq!(scrubber.scrub("pw-1"), REDACTED);
    }

    #[test]
    fn rfc3986_spelling_keeps_tilde_and_encodes_star() {
        let scrubber = Scrubber::new(["k~e*y v"]);
        assert_eq!(
            scrubber.detail("q=k~e%2Ay%20v&x").as_str(),
            "q=[redacted]&x"
        );
        assert_eq!(scrubber.detail("q=k%7Ee*y+v&x").as_str(), "q=[redacted]&x");
    }

    /// Dialects no encoded needle covers: the detail is withheld as a whole.
    #[test]
    fn secrets_in_other_dialects_withhold_the_detail() {
        let secret = "p\"a'ss &w<o>rd/x+y~z*=ключ";
        let scrubber = Scrubber::new([secret]);
        let json = serde_json::to_string(secret).unwrap();
        let dialects = [
            // Lowercase percent-hex.
            "p%22a%27ss%20%26w%3co%3erd%2fx%2by%7ez%2a%3d%d0%ba%d0%bb%d1%8e%d1%87".to_owned(),
            // Python `quote`: `/` kept.
            "p%22a%27ss%20%26w%3Co%3Erd/x%2By~z%2A%3D%D0%BA%D0%BB%D1%8E%D1%87".to_owned(),
            // `encodeURIComponent`: `~ * '` kept.
            "p%22a'ss%20%26w%3Co%3Erd%2Fx%2By~z*%3D%D0%BA%D0%BB%D1%8E%D1%87".to_owned(),
            // XML numeric references.
            "p&#34;a&#39;ss &#x26;w&#60;o&#x3E;rd&#x2F;x+y~z*=ключ".to_owned(),
            // Text-node escaping of `&` and `<` only.
            "p\"a'ss &amp;w&lt;o>rd/x+y~z*=ключ".to_owned(),
            // .NET-style JSON: uppercase `\u`, `+ & < > ' "` escaped.
            "p\\u0022a\\u0027ss \\u0026w\\u003Co\\u003Erd/x\\u002By~z*=\\u043A\\u043B\\u044E\\u0447".to_owned(),
            // JSON inside JSON.
            serde_json::to_string(&json).unwrap(),
            // Form-encoded JSON.
            form_urlencode(&json, "+").to_string(),
        ];
        for text in dialects {
            let detail = scrubber.detail(&format!("error: {text} end"));
            assert_eq!(detail.as_str(), WITHHELD, "{text}");
        }
        // A text without the secret is left alone, escapes and all.
        let clean = "error: a%2fb &#39;c&#39; \\u0041 end";
        assert_eq!(scrubber.detail(clean).as_str(), clean);
    }

    #[test]
    fn the_decoded_check_covers_what_reaches_the_detail() {
        let secret = "SECRET/token+1";
        let scrubber = Scrubber::new([secret]);
        // Straddling the cut, lowercase hex.
        let encoded = "SECRET%2ftoken%2b1";
        let text = format!("{}{encoded} tail", "x".repeat(DETAIL_MAX_BYTES - 6));
        assert_eq!(scrubber.detail(&text).as_str(), WITHHELD);
        // Far beyond what the detail shows: no effect.
        let text = format!("{}{encoded}", "x".repeat(DECODE_WINDOW_MAX));
        assert_eq!(
            scrubber.detail(&text).as_str(),
            "x".repeat(DETAIL_MAX_BYTES)
        );
        // A secret replaced in place does not trigger the withholding.
        assert_eq!(
            scrubber.detail("a SECRET/token+1 b").as_str(),
            "a [redacted] b"
        );
    }

    #[test]
    fn decoders() {
        assert_eq!(
            percent_decode_plus("a+b%2fc%2F%zz%").as_deref(),
            Some("a b/c/%zz%")
        );
        assert_eq!(percent_decode_keep_plus("a+b%41").as_deref(), Some("a+bA"));
        assert_eq!(percent_decode_plus("plain"), None);
        assert_eq!(percent_decode_keep_plus("%ff").as_deref(), Some("\u{FFFD}"));
        assert_eq!(
            entity_decode("&amp;&lt;&gt;&quot;&apos;&#39;&#x2F;&#X2f;&nbsp;&#;&").as_deref(),
            Some("&<>\"''//&nbsp;&#;&")
        );
        assert_eq!(entity_decode("&#99999999999;"), None);
        assert_eq!(
            json_unescape(r#"\"\\\/\b\f\n\r\t\u0041\u00e9\uD83D\uDE00\ud800x\q\u12"#).as_deref(),
            Some("\"\\/\u{8}\u{c}\n\r\tAé\u{1F600}\u{FFFD}x\\q\\u12")
        );
        assert_eq!(json_unescape("plain"), None);
    }

    #[test]
    fn debug_prints_no_secret() {
        let scrubber = Scrubber::new([SECRET, "fixed-canary"]);
        scrubber.remember(&SecretSlot::new(), "runtime-canary");
        let debug = format!("{scrubber:?} {scrubber:#?}");
        assert_eq!(format!("{scrubber:?}"), "Scrubber { .. }");
        for canary in ["fixed-canary", "runtime-canary", "ключ", "p@ss"] {
            assert!(!debug.contains(canary), "{debug}");
        }
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
