//! HMAC (RFC 2104) with SHA-256 and SHA-512 over `aws-lc-rs`.
//!
//! Users: TSIG (RFC 8945, `hmac-sha256` and `hmac-sha512`) and AWS Signature Version 4. The key
//! is borrowed; these functions neither copy it into memory of their own nor keep it.

use aws_lc_rs::hmac as backend;

/// Copies a tag into a fixed-size array without a panicking path.
fn to_array<const N: usize>(tag: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (dst, src) in out.iter_mut().zip(tag) {
        *dst = *src;
    }
    out
}

/// HMAC-SHA-256.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let tag = backend::sign(&backend::Key::new(backend::HMAC_SHA256, key), data);
    to_array(tag.as_ref())
}

/// HMAC-SHA-512.
pub(crate) fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let tag = backend::sign(&backend::Key::new(backend::HMAC_SHA512, key), data);
    to_array(tag.as_ref())
}

/// Constant time in the contents; false for a tag of the wrong length (a truncated tag is not
/// accepted).
pub(crate) fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    backend::verify(&backend::Key::new(backend::HMAC_SHA256, key), data, tag).is_ok()
}

/// Constant time in the contents; false for a tag of the wrong length (a truncated tag is not
/// accepted).
pub(crate) fn hmac_sha512_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    backend::verify(&backend::Key::new(backend::HMAC_SHA512, key), data, tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex_lower;

    struct Case {
        name: &'static str,
        key: Vec<u8>,
        data: Vec<u8>,
        sha256: &'static str,
        sha512: &'static str,
    }

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn unspace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// RFC 4231, "Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384,
    /// and HMAC-SHA-512", section 4: test cases 1, 2, 3, 4, 6 and 7 (sections 4.2, 4.3, 4.4,
    /// 4.5, 4.7 and 4.8). Test case 5 is about truncated output and is not used.
    fn rfc4231() -> Vec<Case> {
        vec![
            Case {
                name: "4.2 test case 1",
                key: vec![0x0b; 20],
                data: b"Hi There".to_vec(),
                sha256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                sha512: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde
                         daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            },
            Case {
                name: "4.3 test case 2",
                key: b"Jefe".to_vec(),
                data: b"what do ya want for nothing?".to_vec(),
                sha256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                sha512: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554
                         9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            },
            Case {
                name: "4.4 test case 3",
                key: vec![0xaa; 20],
                data: vec![0xdd; 50],
                sha256: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
                sha512: "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39
                         bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
            },
            Case {
                name: "4.5 test case 4",
                key: unhex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                data: vec![0xcd; 50],
                sha256: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
                sha512: "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db
                         a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
            },
            Case {
                name: "4.7 test case 6",
                key: vec![0xaa; 131],
                data: b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                sha256: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                sha512: "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352
                         6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            },
            Case {
                name: "4.8 test case 7",
                key: vec![0xaa; 131],
                data: unhex(
                    "5468697320697320612074657374207573696e672061206c6172676572207468
                     616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074
                     68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565
                     647320746f20626520686173686564206265666f7265206265696e6720757365
                     642062792074686520484d414320616c676f726974686d2e",
                ),
                sha256: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
                sha512: "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944
                         b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
            },
        ]
    }

    #[test]
    fn rfc4231_vectors() {
        for case in rfc4231() {
            let tag256 = hmac_sha256(&case.key, &case.data);
            let tag512 = hmac_sha512(&case.key, &case.data);
            assert_eq!(
                hex_lower(&tag256),
                unspace(case.sha256),
                "{} sha256",
                case.name
            );
            assert_eq!(
                hex_lower(&tag512),
                unspace(case.sha512),
                "{} sha512",
                case.name
            );
            assert!(
                hmac_sha256_verify(&case.key, &case.data, &tag256),
                "{}",
                case.name
            );
            assert!(
                hmac_sha512_verify(&case.key, &case.data, &tag512),
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn rfc4231_test_case_7_data_is_the_published_text() {
        let case = rfc4231().pop().unwrap();
        assert_eq!(
            String::from_utf8(case.data).unwrap(),
            "This is a test using a larger than block-size key and a larger than block-size \
             data. The key needs to be hashed before being used by the HMAC algorithm."
        );
    }

    #[test]
    fn verify_rejects_flipped_bit_wrong_key_truncation_and_changed_message() {
        let tag = hmac_sha256(b"key", b"message");
        assert!(hmac_sha256_verify(b"key", b"message", &tag));
        for byte in 0..tag.len() {
            let mut flipped = tag;
            flipped[byte] ^= 0x01;
            assert!(!hmac_sha256_verify(b"key", b"message", &flipped));
        }
        assert!(!hmac_sha256_verify(b"key2", b"message", &tag));
        assert!(!hmac_sha256_verify(b"key", b"message", &tag[..16]));
        assert!(!hmac_sha256_verify(b"key", b"message", &tag[..31]));
        assert!(!hmac_sha256_verify(b"key", b"message", &[]));
        assert!(!hmac_sha256_verify(b"key", b"message!", &tag));
        let mut longer = tag.to_vec();
        longer.push(0);
        assert!(!hmac_sha256_verify(b"key", b"message", &longer));

        let tag = hmac_sha512(b"key", b"message");
        assert!(hmac_sha512_verify(b"key", b"message", &tag));
        let mut flipped = tag;
        flipped[63] ^= 0x80;
        assert!(!hmac_sha512_verify(b"key", b"message", &flipped));
        assert!(!hmac_sha512_verify(b"key2", b"message", &tag));
        assert!(!hmac_sha512_verify(b"key", b"message", &tag[..32]));
        assert!(!hmac_sha512_verify(b"key", b"message!", &tag));
        // A SHA-256 tag is not a SHA-512 tag.
        assert!(!hmac_sha512_verify(
            b"key",
            b"message",
            &hmac_sha256(b"key", b"message")
        ));
    }
}
