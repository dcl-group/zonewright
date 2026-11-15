# zonewright design: history

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

Sections that record how the crate came to be rather than how it works: checks run once before the
implementation, and the carrying over of the tests of the earlier implementations. They keep their
section numbers and are not updated.

### 9.4 Checks behind this section

Run on 2026-11-14 in a throwaway project with the dependency lines above:

- The set resolves and compiles. The highest `rust-version` declared in the tree is 1.88
  (`hickory-proto`, the `icu_*` crates under `idna`, and `rcgen` and `time` among the
  dev-dependencies).
- `ring`, `openssl-sys`, `native-tls`, `h2`, `moka` and `uuid` are not in the tree.
- A `reqwest::Client` built from a `rustls::ClientConfig` made as in section 5.1 builds with no
  process-wide provider installed and leaves none installed; it completes an HTTPS request to a
  loopback server whose certificate chains to a root passed through `new_with_extra_roots`, refuses
  the same server without that root, negotiates HTTP/1.1, and returns a 307 answer instead of
  following it.
- An RSA key in a PEM document with a line of text before the `BEGIN` line is read by
  `rustls-pki-types` as PKCS#8, signs with `RSA_PSS_SHA256` and verifies with
  `RSA_PSS_2048_8192_SHA256`.
- `jiff` with only `std` parses an RFC 3339 timestamp, formats `%Y%m%dT%H%M%SZ` and parses
  `Sun, 06 Nov 1994 08:49:37 GMT`.
- `hickory-proto` with only `std` encodes a query and decodes it back.

Read in source, not run: in `reqwest` 0.13.5, ALPN and `identity` are applied only to configurations
`reqwest` builds itself; in `aws-lc-rs` 1.19.0, `RSA_PSS_SHA256` uses a salt as long as the digest;
in `rustls-platform-verifier` 0.7.1, `Verifier::new` fails on Unix-like systems when no CA
certificate can be loaded and no extra root was given.

Checked on the final manifest: `cargo deny check bans licenses sources` passes with
`all-features = true`, with warnings for duplicate versions only; `ring` appears in `Cargo.lock`
only as an optional dependency of `hickory-proto` and `rustls-webpki` that no enabled feature
activates.

Not checked: the mock crate's dependency set as a whole (only that `axum` 0.8.9 has the named
features), Windows and Android builds. No CI configuration is part of the repository; the gates of
section 12.6 are run by hand.

### 12.4 Carrying over the earlier tests

The earlier TXT-only implementation has a test suite per provider against mocks of the same kind.
They are ported with their mocks, one provider at a time, and keep what they assert. Mapping:

| Earlier                                                   | Here                                                                       |
| --------------------------------------------------------- | -------------------------------------------------------------------------- |
| per-provider suites                                       | `tests/<id>.rs`, renamed to the scheme of sections 12.2 and 12.3           |
| a suite shared by three providers                         | split into the three providers' files                                      |
| the echo suite for all HTTP clients                       | `<id>_secret_echo` in each file, on the shared harness                     |
| the log and zone-boundary suite written for one provider  | `<id>_no_secret_in_logs`, `<id>_name_outside_zone_sends_nothing`           |
| unit tests that put a wrong zone ID into a client's cache | `<id>_stale_zone_id`, driven through the mock instead of a test hook       |
| a test tying endpoint constants to a research document    | a reference comment on every constant (hard rule 3) plus the `https` check |
| name, challenge and normalization unit tests              | `tests/names.rs`, `tests/dns01.rs`, `tests/records.rs`                     |
| crypto vectors                                            | unit tests in `crypto/`                                                    |
| inspector tests against a fake resolver                   | `tests/inspector.rs` on the mock DNS server                                |

Assertions that change because this design changes the behavior, each stated where the change is
described: `acme_dns` removal (`Unsupported`), blind writes (`Accepted`), a concurrent change at a
conditional-write provider (`Conflict` instead of a rejection), a rejected token on a non-idempotent
request (the request is not repeated), every acme-dns add (`Accepted`), a stale zone ID on removal,
a 429 on a non-idempotent request (not retried), the propagation-timeout setting (gone), error codes
(the application's concern now).

The record-level clients for Selectel v2 and Yandex Cloud come with tests that drive them through an
application's reconcile loop. Those are rewritten against `list_rrsets`, `get_rrset`, `set_rrset`
and `delete_rrset`; their stateful fakes are merged into the two providers' mocks, including forced
small pages, lost writes and the strict-write race.
