//! Cryptographic helpers for provider authentication. Backend: `aws-lc-rs` only.
//!
//! Private to the crate: TSIG for RFC 2136 uses the HMAC functions, Route 53 uses [`sigv4`], and
//! Yandex Cloud uses `Ps256Key`. Nothing here is part of the public API.
//!
//! `Ps256Key` reads PEM with `rustls-pki-types`, which is a dependency of the internal `__http`
//! feature, so it is compiled only when `__http` is enabled as well. Its one user, Yandex Cloud,
//! enables both.

mod hmac;
#[cfg(feature = "__http")]
mod ps256;
pub(crate) mod sigv4;

// TEMPORARY (core phase): the re-exports have no user until the TSIG and Yandex Cloud clients
// land; `dead_code` on the module does not cover unused imports. Remove with the first user.
#[allow(unused_imports)]
pub(crate) use hmac::{hmac_sha256, hmac_sha256_verify, hmac_sha512, hmac_sha512_verify};
#[cfg(feature = "__http")]
#[allow(unused_imports)]
pub(crate) use ps256::Ps256Key;

use aws_lc_rs::{constant_time, digest};

/// Why a key could not be used or a signature could not be made. No variant carries input:
/// neither key material nor the text it was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum KeyError {
    /// The text holds no PEM section labeled `PRIVATE KEY` or `RSA PRIVATE KEY` that decodes.
    #[error("the key is not a PEM document with a PRIVATE KEY or RSA PRIVATE KEY section")]
    Pem,
    /// The key decodes but is not an RSA private key of 2048 to 8192 bits.
    #[error("the private key is not an RSA key of 2048 to 8192 bits")]
    UnsupportedKey,
    /// The backend failed to produce a signature.
    #[error("signing failed")]
    Sign,
    /// A SigV4 date is not of the form `YYYYMMDDTHHMMSSZ`.
    #[error("the request date is not of the form YYYYMMDDTHHMMSSZ")]
    Date,
    /// A SigV4 request has a part that cannot be signed as given: an empty or malformed method,
    /// host, path, scope or session token, or an extra header that is not a lowercase name, is
    /// duplicated, or is one the signer sets itself.
    #[error("the request cannot be signed as given")]
    Request,
}

/// SHA-256 (FIPS 180-4).
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    for (dst, src) in out.iter_mut().zip(digest.as_ref()) {
        *dst = *src;
    }
    out
}

/// Constant time in the contents; the lengths are not hidden.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// Lowercase hexadecimal.
pub(crate) fn hex_lower(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(2));
    for byte in data {
        push_hex_byte(&mut out, *byte, false);
    }
    out
}

/// Appends `byte` as two hexadecimal digits.
pub(crate) fn push_hex_byte(out: &mut String, byte: u8, uppercase: bool) {
    for nibble in [byte >> 4, byte & 0x0f] {
        let digit = char::from_digit(u32::from(nibble), 16).unwrap_or('0');
        out.push(if uppercase {
            digit.to_ascii_uppercase()
        } else {
            digit
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_nist_examples() {
        // "abc": NIST CSRC "Cryptographic Standards and Guidelines: Examples with Intermediate
        // Values", SHA-256, one-block message. Empty message: the payload hash on the last line
        // of `get-vanilla/header-canonical-request.txt` in the AWS SigV4 test suite (see the
        // tests in `sigv4`), which is SHA-256 of the empty body.
        assert_eq!(
            hex_lower(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_lower(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn ct_eq_compares_contents_and_lengths() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"a"));
    }

    #[test]
    fn hex_is_lowercase_and_complete() {
        assert_eq!(hex_lower(&[]), "");
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        let mut upper = String::new();
        push_hex_byte(&mut upper, 0xab, true);
        assert_eq!(upper, "AB");
    }

    #[test]
    fn key_error_text_is_fixed() {
        for error in [
            KeyError::Pem,
            KeyError::UnsupportedKey,
            KeyError::Sign,
            KeyError::Date,
            KeyError::Request,
        ] {
            assert!(!error.to_string().is_empty());
        }
    }
}
