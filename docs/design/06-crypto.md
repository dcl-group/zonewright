# zonewright design: Crypto module

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 6. Crypto module

Private (`pub(crate)`), compiled only for the providers that need it, backed by `aws-lc-rs` alone
(decision 3, hard rule 5). Nothing in it is part of the public API: it serves five clients, and a
public signing API would be a second product with its own compatibility burden.

Items, all `pub(crate)`, in `src/crypto/` under `dev/zonewright/`:

- `sha256`, `sha1` (compiled with `ovh` only), `hex_lower`, `push_hex_byte`, `KeyError` — `mod.rs`.
- `hmac_sha256`, `hmac_sha384`, `hmac_sha512`, `hmac_sha256_verify`, `hmac_sha384_verify`,
  `hmac_sha512_verify`, `hmac_sha256_into` — `hmac.rs`.
- `Ps256Key` (`from_pem`, `sign`) — `ps256.rs`; compiled with `yandex_cloud`.
- `Rs256Key` (`from_pem`, `sign`) — `rs256.rs`; compiled with `google_cloud`.
- `rsa_key_pair` (`pub(super)`) — `rsa_pem.rs`: the PEM reader shared by `Ps256Key` and `Rs256Key`;
  compiled with either feature.
- `sigv4`: `Keys`, `Scope`, `Request`, `ALGORITHM`, `canonical_query`, `payload_hash`,
  `authorization` — `sigv4.rs`.

Notes:

- Backend calls: `aws_lc_rs::digest`, `aws_lc_rs::hmac` (tag verification through
  `aws_lc_rs::hmac::verify`, which is constant time),
  `aws_lc_rs::signature::{RsaKeyPair, RSA_PSS_SHA256, RSA_PKCS1_SHA256}`,
  `aws_lc_rs::rand::SystemRandom`. PEM is read once, in `rsa_pem.rs`, with `rustls-pki-types`
  (`PrivateKeyDer::from_pem_slice`), which distinguishes the two labels and skips text outside the
  section; a PKCS#8 body goes to `RsaKeyPair::from_pkcs8`, a PKCS#1 body to `RsaKeyPair::from_der`.
  A key that is not RSA is `KeyError`, reported by the client as `Error::Config`.
- The key is parsed once at client construction and kept as the backend's key object; the DER bytes
  are not retained. (The earlier implementation kept the DER and re-parsed it for every signature,
  and proved the key type with a throwaway signature.)
- SigV4 intermediates that contain the secret key or the session token (the `AWS4`-prefixed key, the
  derived keys, the canonical request, the string to sign) are held in zeroizing buffers. The date
  part is taken from `amz_date` with checked slicing; a malformed date is an error, not a panic.
- `Rs256Key` is RSASSA-PKCS1-v1_5 with SHA-256 (JWS "RS256"), which Google Cloud DNS requires for
  the assertion signed with a service-account key. Its signatures are deterministic. The key checks
  (2048 to 8192 bits, no echo of input) are those of `Ps256Key`, because both call `rsa_key_pair`.
- Users: TSIG for RFC 2136 (HMAC), Route 53 (SigV4, with `sha256` and `hmac_sha256`), Yandex Cloud
  (PS256), Google Cloud DNS (RS256), OVHcloud (`sha1`, `hex_lower`).
- SHA-1 is present for one reason: the OVHcloud request signature is defined over SHA-1
  (`"$1$" + hex(SHA1(...))`), and the provider offers no other form for the application-key
  authentication the client implements. The function is compiled only with the `ovh` feature, takes
  its digest from `aws-lc-rs`'s legacy-use algorithm (`SHA1_FOR_LEGACY_USE_ONLY`, which the backend
  names that way on purpose) and has no other caller. It protects a request signature that is valid
  for one exact request and a short time; it is not used for a certificate, a stored hash or any new
  protocol. Section 11 repeats this in the OVHcloud note.

Test vectors, all taken from their published sources and cited in the test code:

- HMAC-SHA-256, HMAC-SHA-384 and HMAC-SHA-512: RFC 4231 test cases 1, 2, 3, 4, 6 and 7, plus
  negative verification (flipped bit, wrong key, truncated tag, changed message).
- SHA-1 (`ovh` only): RFC 3174 section 7.3, TEST1 (`"abc"`), TEST2 (the 56-byte message) and TEST3
  (one million times `"a"`), the same values as the NIST examples.
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
- RS256: the known answer of RFC 7515 appendix A.2 (the key, the signing input and the signature of
  A.2.1; PKCS#1 v1.5 is deterministic, so the signature itself is compared), the key rebuilt in the
  test as a PKCS#1 PEM from its JWK members; plus a refusal of text that is not PEM and a `Debug`
  output without key material. The PEM reader's own cases (PKCS#8 and PKCS#1, a section after other
  text, EC keys, garbage and truncation) are tested through `Ps256Key`.
