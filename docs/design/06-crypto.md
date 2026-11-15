# zonewright design: Crypto module

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 6. Crypto module

Private (`pub(crate)`), compiled only for the providers that need it, backed by `aws-lc-rs` alone
(decision 3, hard rule 5). Nothing in it is part of the public API: it serves three clients, and a
public signing API would be a second product with its own compatibility burden.

```rust
// crate::crypto
pub(crate) fn sha256(data: &[u8]) -> [u8; 32];
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32];
pub(crate) fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64];
/// Constant time in the contents; false for a tag of the wrong length.
pub(crate) fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool;
pub(crate) fn hmac_sha512_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool;
/// Into a caller's buffer, so that SigV4's derived keys stay in zeroizing memory.
pub(crate) fn hmac_sha256_into(key: &[u8], data: &[u8], out: &mut [u8; 32]);
pub(crate) fn hex_lower(data: &[u8]) -> String;
pub(crate) fn push_hex_byte(out: &mut String, byte: u8, uppercase: bool);

/// Why a key could not be used or a signature could not be made. Fixed texts; no variant
/// carries input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum KeyError { Pem, UnsupportedKey, Sign, Date, Request }

/// An RSA private key for RSASSA-PSS with SHA-256 (JWS "PS256"). Parsed once.
pub(crate) struct Ps256Key(/* aws_lc_rs::signature::RsaKeyPair */);
impl Ps256Key {
    /// Accepts a PEM document with a "PRIVATE KEY" (PKCS#8) or "RSA PRIVATE KEY" (PKCS#1)
    /// section; text before the section is ignored. Errors never contain key material.
    pub(crate) fn from_pem(pem: &str) -> Result<Ps256Key, KeyError>;
    /// Raw signature bytes; salt length equals the digest length (RFC 7518 section 3.5).
    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError>;
}

// crate::crypto::sigv4 — AWS Signature Version 4
pub(crate) struct Keys<'a> {
    pub access_key_id: &'a str,
    pub secret: &'a SecretString,
    pub session_token: Option<&'a SecretString>,
}
pub(crate) struct Scope<'a> { pub region: &'a str, pub service: &'a str }
pub(crate) struct Request<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,                    // already canonical
    pub query: &'a str,                   // from canonical_query
    pub headers: &'a [(&'a str, &'a str)], // extra signed headers, lowercase names
    pub payload_hash: &'a str,
}
pub(crate) fn canonical_query(pairs: &[(&str, &str)]) -> String;
pub(crate) fn payload_hash(body: &[u8]) -> String;
/// `amz_date` is "YYYYMMDDTHHMMSSZ". Returns the Authorization header value.
pub(crate) fn authorization(
    request: &Request<'_>,
    keys: &Keys<'_>,
    scope: Scope<'_>,
    amz_date: &str,
) -> Result<Zeroizing<String>, KeyError>;
```

Notes:

- Backend calls: `aws_lc_rs::digest`, `aws_lc_rs::hmac` (tag verification through
  `aws_lc_rs::hmac::verify`, which is constant time),
  `aws_lc_rs::signature::{RsaKeyPair, RSA_PSS_SHA256}`, `aws_lc_rs::rand::SystemRandom`. PEM is read
  with `rustls-pki-types` (`PrivateKeyDer::from_pem_slice`), which distinguishes the two labels and
  skips text outside the section; a PKCS#8 body goes to `RsaKeyPair::from_pkcs8`, a PKCS#1 body to
  `RsaKeyPair::from_der`. A key that is not RSA is `KeyError`, reported by the client as
  `Error::Config`.
- The key is parsed once at client construction and kept as the backend's key object; the DER bytes
  are not retained. (The earlier implementation kept the DER and re-parsed it for every signature,
  and proved the key type with a throwaway signature.)
- SigV4 intermediates that contain the secret key or the session token (the `AWS4`-prefixed key, the
  derived keys, the canonical request, the string to sign) are held in zeroizing buffers. The date
  part is taken from `amz_date` with checked slicing; a malformed date is an error, not a panic.
- Users: TSIG for RFC 2136 (HMAC), Route 53 (SigV4), Yandex Cloud (PS256).

Test vectors, all taken from their published sources and cited in the test code:

- HMAC-SHA-256 and HMAC-SHA-512: RFC 4231 test cases 1, 2, 3, 4, 6 and 7, plus negative verification
  (flipped bit, wrong key, truncated tag, changed message).
- SHA-256: the NIST example digest of `"abc"`, and the digest of the empty message as the payload
  hash of the AWS SigV4 suite's `get-vanilla` case.
- SigV4: from the AWS Signature Version 4 test suite, `get-vanilla` (canonical request, string to
  sign and authorization) and `get-vanilla-query-order-key-case`, which the earlier implementation
  already carries, plus `post-x-www-form-urlencoded`, `get-vanilla-with-session-token`,
  `post-sts-header-before` and `get-header-value-trim` from the same suite, copied from the suite's
  files and named after them in the test code; plus checks that the secret and the token do not
  occur in the output.
- PS256: signatures are randomized, so the test is a round trip: generate a 2048-bit key in the
  test, sign, verify with `RSA_PSS_2048_8192_SHA256`, which requires the salt length to equal the
  digest length; plus rejection of an EC key, of garbage and of a truncated PEM, each without
  echoing input. No key material is stored in the repository.
