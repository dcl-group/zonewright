//! RSASSA-PKCS1-v1_5 with SHA-256 (JWS "RS256", RFC 7518 section 3.3) for signing assertions with
//! a service-account key.

use std::fmt;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

use super::KeyError;

/// An RSA private key for RSASSA-PKCS1-v1_5 with SHA-256 (JWS "RS256"). Parsed once.
///
/// Holds the backend's key object only; the DER bytes it was parsed from are not retained.
pub(crate) struct Rs256Key(RsaKeyPair);

impl fmt::Debug for Rs256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rs256Key").finish_non_exhaustive()
    }
}

impl Rs256Key {
    /// Accepts a PEM document with a "PRIVATE KEY" (PKCS#8) or "RSA PRIVATE KEY" (PKCS#1)
    /// section, as [`Ps256Key::from_pem`](super::Ps256Key) does. Errors never contain key
    /// material.
    pub(crate) fn from_pem(pem: &str) -> Result<Rs256Key, KeyError> {
        super::rsa_pem::rsa_key_pair(pem).map(Rs256Key)
    }

    /// Raw signature bytes. PKCS#1 v1.5 signing is deterministic; the random source the backend
    /// asks for is not used by this padding.
    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let mut signature = vec![0u8; self.0.public_modulus_len()];
        self.0
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message,
                &mut signature,
            )
            .map_err(|_| KeyError::Sign)?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    use super::*;

    /// The RSA key of RFC 7515 appendix A.2, as its JWK members (base64url).
    const N: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
    const E: &str = "AQAB";
    const D: &str = "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ";
    const P: &str = "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc";
    const Q: &str = "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc";
    const DP: &str = "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0";
    const DQ: &str = "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU";
    const QI: &str = "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U";

    /// The JWS Signing Input of RFC 7515 appendix A.2.1.
    const SIGNING_INPUT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

    /// The JWS Signature of RFC 7515 appendix A.2.1, base64url.
    const SIGNATURE: &str = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

    /// A DER length.
    fn der_len(len: usize, out: &mut Vec<u8>) {
        match len {
            0..=0x7f => out.push(len as u8),
            0x80..=0xff => out.extend([0x81, len as u8]),
            _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
    }

    /// A DER INTEGER of the unsigned big-endian `value`.
    fn der_uint(value: &[u8], out: &mut Vec<u8>) {
        let mut body = Vec::new();
        if value.first().is_some_and(|b| b & 0x80 != 0) {
            body.push(0);
        }
        body.extend_from_slice(value);
        out.push(0x02);
        der_len(body.len(), out);
        out.extend(body);
    }

    /// The PKCS#1 RSAPrivateKey (RFC 8017 appendix A.1.2) of the RFC 7515 A.2 key, as PEM.
    fn rfc7515_key_pem() -> String {
        let mut body = vec![0x02, 0x01, 0x00];
        for member in [N, E, D, P, Q, DP, DQ, QI] {
            der_uint(&URL_SAFE_NO_PAD.decode(member).unwrap(), &mut body);
        }
        let mut der = vec![0x30];
        der_len(body.len(), &mut der);
        der.extend(body);
        let mut pem = String::from("-----BEGIN RSA PRIVATE KEY-----\n");
        for line in STANDARD.encode(&der).as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END RSA PRIVATE KEY-----\n");
        pem
    }

    /// The known answer of RFC 7515 appendix A.2: the key, the signing input and the signature
    /// published there. PKCS#1 v1.5 is deterministic, so the signature must be that one exactly.
    #[test]
    fn rfc7515_appendix_a2_known_answer() {
        let key = Rs256Key::from_pem(&rfc7515_key_pem()).unwrap();
        let signature = key.sign(SIGNING_INPUT.as_bytes()).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(&signature), SIGNATURE);
        // Deterministic: the same input gives the same signature.
        assert_eq!(key.sign(SIGNING_INPUT.as_bytes()).unwrap(), signature);
        assert_ne!(key.sign(b"another input").unwrap(), signature);
    }

    #[test]
    fn errors_and_debug_carry_no_key_material() {
        assert_eq!(Rs256Key::from_pem("not a key").unwrap_err(), KeyError::Pem);
        let key = Rs256Key::from_pem(&rfc7515_key_pem()).unwrap();
        assert_eq!(format!("{key:?}"), "Rs256Key { .. }");
    }
}
