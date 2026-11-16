# zonewright design: Crypto module

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 6. Crypto module

Private (`pub(crate)`), compiled only for the providers that need it, backed by `aws-lc-rs` alone
(decision 3, hard rule 5). Nothing in it is part of the public API: it serves three clients, and a
public signing API would be a second product with its own compatibility burden.

Items, all `pub(crate)`, in `src/crypto/` under `dev/zonewright/`:

- `sha256`, `hex_lower`, `push_hex_byte`, `KeyError` — `mod.rs`.
- `hmac_sha256`, `hmac_sha384`, `hmac_sha512`, `hmac_sha256_verify`, `hmac_sha384_verify`,
  `hmac_sha512_verify`, `hmac_sha256_into` — `hmac.rs`.
- `Ps256Key` (`from_pem`, `sign`) — `ps256.rs`.
- `sigv4`: `Keys`, `Scope`, `Request`, `ALGORITHM`, `canonical_query`, `payload_hash`,
  `authorization` — `sigv4.rs`.

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

- HMAC-SHA-256, HMAC-SHA-384 and HMAC-SHA-512: RFC 4231 test cases 1, 2, 3, 4, 6 and 7, plus
  negative verification (flipped bit, wrong key, truncated tag, changed message).
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
