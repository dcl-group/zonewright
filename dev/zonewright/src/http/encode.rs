//! Encoders for request bodies and URL parts (design sections 5.2 and 5.7).
//!
//! Form encoding and percent-encoding are small private functions rather than dependency
//! features. Bodies that can carry a secret are built in zeroizing buffers and handed to the HTTP
//! client as [`Bytes`] that own those buffers: a retry re-sends the same memory, and it is wiped
//! when the last reference drops.

use std::io;

use bytes::Bytes;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::redact::Detail;

/// `Content-Type` of a form body.
pub(crate) const FORM: &str = "application/x-www-form-urlencoded";

/// `Content-Type` of a JSON body.
pub(crate) const JSON: &str = "application/json";

/// `Content-Type` of an XML body.
pub(crate) const XML: &str = "application/xml";

/// Owner of a zeroizing buffer behind a [`Bytes`].
struct Wiped(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for Wiped {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// `buf` as [`Bytes`] without a copy. The buffer is wiped when the last `Bytes` that refers to
/// it drops; cloning the `Bytes` (as a retry does) shares the buffer.
pub(crate) fn wiped(buf: Zeroizing<Vec<u8>>) -> Bytes {
    Bytes::from_owner(Wiped(buf))
}

/// [`wiped`] for text: the bytes of the string move into the buffer without a copy.
pub(crate) fn wiped_text(mut text: Zeroizing<String>) -> Bytes {
    wiped(Zeroizing::new(std::mem::take(&mut *text).into_bytes()))
}

/// The uppercase hexadecimal digit of the low four bits of `nibble`.
fn hex_upper(nibble: u8) -> char {
    char::from_digit(u32::from(nibble & 0x0f), 16)
        .unwrap_or('0')
        .to_ascii_uppercase()
}

/// Length of `s` after [`push_form`] with a space spelled as `space`.
fn form_len(s: &str, space: &str) -> usize {
    s.bytes()
        .map(|b| match b {
            b'*' | b'-' | b'.' | b'_' => 1,
            b' ' => space.len(),
            b if b.is_ascii_alphanumeric() => 1,
            _ => 3,
        })
        .sum()
}

/// Appends `s` form-encoded: ASCII letters, digits and `*-._` as they are, a space as `space`,
/// every other byte as `%XX`.
fn push_form(out: &mut String, s: &str, space: &str) {
    for b in s.bytes() {
        match b {
            b'*' | b'-' | b'.' | b'_' => out.push(char::from(b)),
            b if b.is_ascii_alphanumeric() => out.push(char::from(b)),
            b' ' => out.push_str(space),
            b => {
                out.push('%');
                out.push(hex_upper(b >> 4));
                out.push(hex_upper(b));
            }
        }
    }
}

/// An `application/x-www-form-urlencoded` body per the WHATWG URL standard's serializer.
///
/// The buffer is allocated once with its exact final length, so no partial copy of a secret is
/// left behind by a reallocation; it is wiped when dropped. Hand it to the request with
/// [`wiped_text`].
pub(crate) fn form(pairs: &[(&str, &str)]) -> Zeroizing<String> {
    let len = pairs
        .iter()
        .map(|(k, v)| form_len(k, "+") + 1 + form_len(v, "+"))
        .sum::<usize>()
        + pairs.len().saturating_sub(1);
    let mut out = Zeroizing::new(String::with_capacity(len));
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        push_form(&mut out, key, "+");
        out.push('=');
        push_form(&mut out, value, "+");
    }
    out
}

/// One form-encoded component with a space spelled as `space` (`+` or `%20`), in a zeroizing
/// buffer of exactly its length.
pub(crate) fn form_component(s: &str, space: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(form_len(s, space)));
    push_form(&mut out, s, space);
    out
}

/// Counts the bytes a serializer writes.
struct Count(usize);

impl io::Write for Count {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `value` as a JSON body in a zeroizing buffer of exactly its length.
///
/// The value is serialized twice: once to measure it, once into the buffer, so the buffer never
/// reallocates and leaves no unwiped partial copy. Used for every JSON body, secret or not.
pub(crate) fn json<T: Serialize + ?Sized>(value: &T) -> Result<Bytes, Error> {
    let fail = || Error::InvalidInput {
        detail: Detail::constant("the request body could not be encoded as JSON"),
        code: None,
    };
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value).map_err(|_| fail())?;
    let mut buf = Zeroizing::new(Vec::with_capacity(count.0));
    serde_json::to_writer(&mut *buf, value).map_err(|_| fail())?;
    Ok(wiped(buf))
}

/// Percent-encodes `s` for a URL path segment or a query component: the unreserved characters
/// of RFC 3986 (`A-Z a-z 0-9 - . _ ~`) as they are, every other byte as `%XX`. A space becomes
/// `%20`.
pub(crate) fn percent(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'-' | b'.' | b'_' | b'~' => out.push(char::from(b)),
            b if b.is_ascii_alphanumeric() => out.push(char::from(b)),
            b => {
                out.push('%');
                out.push(hex_upper(b >> 4));
                out.push(hex_upper(b));
            }
        }
    }
    out
}

/// XML text and attribute escaping of the five predefined entities. The one escaping function
/// of XML writing (design section 5.7).
pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_matches_the_whatwg_serializer() {
        // Expected output written by hand from the WHATWG serializer's rules.
        let pairs = [
            ("login", "user@example.org"),
            ("passwd", "p a+s/s&=%ключ*-._~!"),
            ("input_data", "{\"fqdn\":\"x.example\"}"),
        ];
        assert_eq!(
            form(&pairs).as_str(),
            "login=user%40example.org\
             &passwd=p+a%2Bs%2Fs%26%3D%25%D0%BA%D0%BB%D1%8E%D1%87*-._%7E%21\
             &input_data=%7B%22fqdn%22%3A%22x.example%22%7D"
        );
        assert_eq!(form(&[]).as_str(), "");
        assert_eq!(form(&[("a", "")]).as_str(), "a=");
    }

    #[test]
    fn form_components_spell_the_space_as_asked() {
        assert_eq!(form_component("a b/c", "+").as_str(), "a+b%2Fc");
        let percent = form_component("a b/c", "%20");
        assert_eq!(percent.as_str(), "a%20b%2Fc");
        assert_eq!(percent.capacity(), percent.len());
    }

    #[test]
    fn form_is_allocated_with_its_exact_length() {
        let body = form(&[("password", "s e/c+r&e=t ключ"), ("x", "1")]);
        assert_eq!(body.capacity(), body.len());
    }

    #[test]
    fn json_is_exact_and_valid() {
        let value = serde_json::json!({ "password": "p\"w/\u{1F600}", "n": [1, 2] });
        let body = json(&value).unwrap();
        assert_eq!(&body[..], serde_json::to_vec(&value).unwrap().as_slice());
    }

    #[test]
    fn wiped_bodies_keep_the_zeroizing_buffer() {
        let buf = Zeroizing::new(b"password=secret".to_vec());
        let ptr = buf.as_ptr();
        let body = wiped(buf);
        assert_eq!(body.as_ptr(), ptr);
        assert_eq!(body.clone().as_ptr(), ptr);
        assert_eq!(&body[..], b"password=secret");
        let text = form(&[("passwd", "secret")]);
        let ptr = text.as_ptr();
        let body = wiped_text(text);
        assert_eq!(body.as_ptr(), ptr);
        assert_eq!(&body[..], b"passwd=secret");
    }

    #[test]
    fn percent_keeps_only_unreserved_characters() {
        assert_eq!(percent("abc-._~XYZ09"), "abc-._~XYZ09");
        assert_eq!(
            percent("a b/c?d#e%f+g&h=i"),
            "a%20b%2Fc%3Fd%23e%25f%2Bg%26h%3Di"
        );
        assert_eq!(
            percent("пример.рф"),
            "%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.%D1%80%D1%84"
        );
        assert_eq!(percent(""), "");
    }

    #[test]
    fn xml_escape_covers_the_predefined_entities() {
        assert_eq!(
            xml_escape("<a & 'b'>\"ключ"),
            "&lt;a &amp; &apos;b&apos;&gt;&quot;ключ"
        );
    }
}
