# zonewright design: Testing

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 12. Testing

### 12.1 Mocks

The default test run needs no network and no real credentials. Every client is tested against a
stateful mock of its provider's API in the workspace member `zonewright-mock`: an HTTP server on
`127.0.0.1` with an ephemeral port (for RFC 2136, a DNS server on TCP and UDP, the client using
TCP), holding zones and records in memory and behaving as the provider's documentation describes.
`zonewright-mock` is a published crate, released with `zonewright` under the same version number, so
that the tests can be built from the published package and applications can test their own use of
`zonewright` without live accounts. Stateful mocks rather than a request-matching library, because
the properties under test are about state: a foreign value is still there afterwards, a second
identical call writes nothing, a write is rejected when the set changed in between.

Every mock offers the same control surface: a seed, the list of requests received (method, path,
query, all headers, body and the status answered; for RFC 2136, the list of messages), direct access
to the stored records, and fault injection (answer the next N matching requests with a status, a
`Retry-After`, a redirect, an oversized or truncated body, slow headers, a delay, or a dropped
connection; insert a foreign change before the next write; recreate a zone under a new identifier).
Mocks that issue tokens can revoke them and count how many they issued. The Route 53 mock verifies
the SigV4 signature, the RFC 2136 mock verifies and produces TSIG, and the Yandex Cloud mock
verifies the PS256 signature, each with code that shares nothing with the crate under test.

Every provider mock also reports each change of the records it would publish as one type: the
complete rrset of a name and type after the change, in zone-file text, whatever the shape of the
provider's API. A mock computes its published state in one function, and the difference before and
after each change is emitted under the mock's lock, so subscribers see changes in order. A link
applies these changes to the mock DNS server, so that a test of an application that issues
certificates over DNS-01 can serve the provider's records to its ACME server: `settled` replaces
sleeping, and a hold or a delay models propagation. Mocks listen on loopback by default and on a
given address with `start_on`, for a stand whose parts run in different containers. What is stable
in the mock's API within a minor version is stated in its crate documentation.

The crate also holds the echo server of the secret tests (section 12.2), a forward proxy (`CONNECT`
and plain forwarding, optional Basic authentication) and a SOCKS5 proxy (optional username and
password) for the transport's proxy tests, and a loopback DNS server over UDP and TCP, either
authoritative or recursive, for the inspector tests.

Fixtures are synthetic. Keys are generated inside the tests.

### 12.2 Secret tests

For every client, in its own test file:

- `<id>_secret_echo`. The echo server answers every request with the chosen status and a body that
  repeats the request's body and its authentication headers inside the fields a client reads error
  text from (JSON or XML as the client expects); token endpoints hand out a canary token and the
  server then echoes that too. The credentials are canaries containing `@`, a space, `/`, `+`, both
  quotes, `& < > \ ~ * =`, non-ASCII letters (in the password canary) and (where a header does not
  carry them) a newline, so that every encoding and escaping changes them. The test runs for every
  dialect of the shared support in `tests/common/echo.rs`: each renderer of the echo server (JSON as
  `serde_json`, PHP, Go and .NET escape it, with `\uXXXX` and a plain `/`, PHP JSON after a notice
  line, JSON inside JSON, JSON under a key no client reads, form-encoded JSON, XML with named
  entities, numeric references or minimal escaping, plain text) with the text verbatim, and each
  spelling (form-encoding with `+`, `%20` or lowercase hex; the percent-encodings of Python,
  JavaScript, RFC 3986 and Go) inside JSON and plain text. It runs `check` and a write, requires the
  write to fail, and asserts on the `Display` and `Debug` of every error, on every
  `ZoneCheck::detail`, and on the client's `Debug`: no canary in any of those spellings, no fragment
  of one, no JWT; and the write's error does contain `[redacted]`, which proves the echo reached the
  error path and the test is not vacuous. It also asserts that the API endpoint, and for token
  clients the token endpoint, were actually reached. Every secret field of the credentials is
  covered.
- RFC 2136 has no HTTP echo. Its equivalent, `rfc2136_secret_not_in_errors`, asserts that the TSIG
  secret, in base64 and in hex, does not occur in any error or `Debug` output across the error paths
  of its mock.
- `<id>_no_secret_in_logs`. A `tracing` subscriber at `TRACE` captures everything while the client
  goes through a success, a 401 and a 500; the capture must contain the transport's event and none
  of the canaries or issued tokens.

In every provider's test file, a compile-time check that its client type and its credentials type
implement neither `Display` nor `Serialize`.

Once for the crate: unit tests of the scrubber (every spelling, every decoded dialect, the truncated
tail, run-time tokens per slot, its `Debug`); the transport's secret tests over every dialect and
every credential position (bearer, custom header, form body, JSON body, query), which also require
the message to be kept, with the canaries cut out in place, wherever the echo uses a spelling the
scrubber knows exactly; a test that a redirect is not followed and that the address it points to
receives no connection, with and without a client certificate (`src/http/tests.rs`); a source scan
for `bearer_auth` and `basic_auth` (`tests/transport.rs`).

### 12.3 Invariant tests

For every client, in its own test file, where the operation exists:

- `<id>_name_outside_zone_sends_nothing`: for a name in another zone, a name that merely ends with
  the zone's text, and a sibling zone, every mutating operation returns `NameOutsideZone` and the
  mock's request log is empty, token requests included.
- `<id>_add_is_idempotent`: `Created`, then `Appended` for a second value, then `AlreadyPresent`,
  with no write request for the last.
- `<id>_never_removes_foreign_value`: removing an absent value next to a foreign one writes nothing
  and returns `NotPresent`; adding and removing our value leaves the foreign value, its TTL and its
  attributes as they were.
- `<id>_remove_last_value_deletes_rrset` and `<id>_remove_is_idempotent`.
- `<id>_concurrent_adds_are_serialized`: two adds to one name from two clients sharing a `Context`
  both end up in the rrset, with the mock delaying the first write.
- For conditional-write providers, `<id>_concurrent_change_is_conflict`: a foreign change inserted
  between the read and the write is not lost.
- For providers with record-level operations, `<id>_failed_expectation_is_precondition_failed`:
  `Expect::Absent` on an existing set and `Expect::Matches` on a changed one return
  `PreconditionFailed` and write nothing; and, for those that can list rrsets,
  `<id>_listing_reports_skipped_sets`.
- `<id>_stale_zone_id`, for every client that caches zone identifiers: after the mock recreates the
  zone under a new identifier, the next operation succeeds or fails cleanly and the one after it
  succeeds; a removal never reports `NotPresent` for a value that is there.
- `<id>_writes_are_sent_once`, for every client that writes: with a `502`, a `429` and a `401`
  injected on each write request, the request log holds exactly one such request per operation.
- `<id>_unsupported_operations_send_nothing`, for every client with an unsupported operation.
- For Route 53, a throttled read (HTTP 400 `Throttling` or `PriorRequestNotComplete`) is retried and
  a throttled change batch is sent once and returns `RateLimited`.

`tests/conformance.rs` holds the checks that span providers: `parse(as_str(id)) == id` for all IDs,
serde round trip, the literal table of section 2.4, the comparison with `PROVIDERS.md`, the metadata
fields equal to the keys of the corresponding types (the non-secret keys equal the keys of the
`Config` type, read by serializing it; the secret keys equal the fields of the `Credentials` type,
read from its definition; and, through `AnyProvider::from_json` from the sample configuration with
one key changed at a time, a required key is required, an optional default is accepted, a secret key
and an unknown key are refused in the settings), an unsupported operation returning `Unsupported`
with zero requests (every endpoint of the sample configuration points at a loopback TCP listener and
UDP socket that must see nothing), every default endpoint being `https`, a scan that no file under
`src/providers/` calls `Detail::new` or a text-taking `Error` constructor, and a scan that every
provider's test file defines the required test names of sections 12.2 and 12.3, derived from the
provider's capabilities (and, for `stale_zone_id`, from whether its sources use the zone-ID cache),
with one explicit exception: `rfc2136` has its own secret test instead of `secret_echo`. It reports
every missing name of every provider at once. The scan is what keeps "tests cover this for every
client" true when a sixteenth provider is added.

Four of these checks compare the crate with files of the repository: the comparisons with
`PROVIDERS.md` (identifiers, names, verified flags) and the one that the license texts in the crate
directories, `zonewright` and `zonewright-mock`, equal those at the repository root. A published
package does not contain those files, so `packaged()` (the package carries `.cargo_vcs_info.json`)
makes the four return early when the tests run from the package; the other checks run there as well.

The generic value layer is additionally tested against an in-memory backend for all three native
shapes, including duplicates of a value, non-plain values and failures injected between the read and
the write.

Section 12.4, on carrying over the tests of the earlier implementations, is in
[`history.md`](./history.md).

### 12.5 Live tests

Live tests are `#[ignore]`, live in the provider's test file with names starting `live_`, and are
run only by the maintainer. They read:

- `ZONEWRIGHT_LIVE_<ID>_SETTINGS`: the settings JSON;
- `ZONEWRIGHT_LIVE_<ID>_CREDENTIALS`: the credentials JSON;
- `ZONEWRIGHT_LIVE_<ID>_ZONE`: a zone the test may write to;

with `<ID>` the provider ID in upper case (`ZONEWRIGHT_LIVE_SELECTEL_V2_ZONE`). A missing variable
fails the test with a message naming it. The inspector has no live test.

A live test works only under labels it generates (`_zw-live-<random>` or `zw-live-<random>` below
the zone). It runs its body as a separate task and afterwards, whether the body returned or
panicked, cleans up: a TXT value test (`live_<id>_add_and_remove`) removes exactly the values it
added, with the value operations; a record-level test (`live_<id>_record_round_trip`, or a
record-level part of the TXT value test) deletes only the rrsets of its own generated name. Nothing
is listed and deleted by pattern. acme-dns is the exception: it writes at the registration's own
name and has no delete, so its test needs a registration set aside for testing.

Every provider has a TXT value live test (`live_acme_dns_add` for acme-dns), and every provider with
record-level operations has `live_<id>_record_round_trip`; the TXT value tests of Cloud.ru and
reg.ru also carry a record-level part, and those of Selectel v2 and Cloud.ru a probe of two
concurrent creates.

A provider moves to "Verified against the live API" in `PROVIDERS.md`, and its `verified` flag turns
true, only by the maintainer's commit after these tests passed.

### 12.6 Gates

`cargo fmt --check`; `cargo clippy --all-features --all-targets` with warnings denied;
`cargo deny check`; `cargo test --all-features`; `cargo hack check --each-feature` over the public
features and `cargo hack test --each-feature` likewise, plus the no-feature build; `cargo doc` with
warnings denied; a build with the MSRV toolchain. Workspace lints: `unsafe_code = "deny"`,
`missing_docs = "deny"`, and, for the `zonewright` crate, the clippy lints `unwrap_used`,
`expect_used`, `panic`, `unreachable`, `todo`, `unimplemented`, `indexing_slicing`, `dbg_macro`,
`print_stdout` and `print_stderr` denied in library code (`zonewright-mock` does not inherit the
workspace lints; it sets `unsafe_code` and `missing_docs` itself); `clippy.toml` allows unwrap,
expect, panic, indexing, `dbg!` and printing in test code. The gates are run by hand from `dev/`; no
CI configuration is part of the repository.

Two public features change which transport tests exist. The SOCKS5 tests (`src/http/proxy.rs`,
`src/http/proxy_tests.rs`, `tests/transport.rs`) are compiled with `socks`, and the tests of the
platform verifier (its construction and a host without CA certificates, `src/http/tls.rs` and
`src/http/tests.rs`) with `platform-verifier`; without the feature, tests that the refusal is
`Error::Config` naming the feature are compiled instead. `cargo test --all-features` runs the first
kind, `cargo test --features <one provider>` the second. The trust tests use certificate authorities
generated at test time and the compiled-in roots only; nothing connects to a real host, and the
tests of the Russian root (`src/http/roots.rs`) read the file in the crate and never compare its
expiry with the current date.
