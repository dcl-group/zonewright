# zonewright design: Versioning and design choices

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 13. Versioning, choices, open points

### 13.1 MSRV

`rust-version = "1.99"`, one value for the whole crate. Decided by the maintainer on 2026-11-14.

The dependency tree would allow less: the highest `rust-version` any dependency declares, in every
feature combination, is 1.88 (the Unicode data crates under `idna`, and `hickory-proto` for the
inspector; section 9.4). The crate declares 1.99 because that is the toolchain its known consumers
build on and the oldest one the gates are run with; a lower value would be a promise nobody checks.
Raising it later is a one-line change and, before 1.0, a minor-version event.

### 13.2 SemVer notes

Before 1.0 a breaking change raises the second number. To keep that rare:

- `#[non_exhaustive]` enums: `ProviderId`, `Error` and each of its variants, `ErrorKind`,
  `Operation`, `NameError`, `RecordError`, `RrsetTtl`, `FieldKind`, `TypeSet`, `Preconditions`,
  `TtlSupport`, `ProviderDefaultTtl`, `ValueGuarantee`, `SkipReason`, `Expect`, `SetOutcome`,
  `DeleteOutcome`, `AddOutcome`, `RemoveOutcome`, `SvcParam`, `AnyProvider`, `CnameError`, and in
  the inspector `Answer`, `Condition`, `NsDiscovery`, `IpFamilies`, `NotAsked`, `AddressRefusal`,
  `InspectorError`.
- `#[non_exhaustive]` structs: `ProviderMeta`, `ConfigField`, `Capabilities`, `CheckReport`,
  `ZoneCheck`, `ZoneInfo`, `ZoneListing`, `SkippedRrset`, `ContextOptions`, `HttpProxy`, every
  `…Config` and `…Credentials`, `yandex_cloud::AuthorizedKey`, `CnameChain`, `InspectorConfig`,
  `NameServer`, `WaitOptions`, `ServerReport`, `Report`.
- Exhaustive on purpose: `Mx`, `Srv`, `Caa`, `Tlsa`, `Svcb`, `Question`, `Expectation`.
- The `#[non_exhaustive]` structs that an implementation of `Provider` has to return (`CheckReport`,
  `ZoneCheck`, `ZoneInfo`, `ZoneListing`, `SkippedRrset`) have `new` constructors taking today's
  fields. A field added later gets a default in `new` and a setter, so existing callers keep
  compiling.
- Not breaking: adding a provider (ID, feature, variant), an error kind with its constructor, a
  capability field, a setting with a default, a refreshed type-mnemonic table, a trait method with a
  default body, raising a listing or size limit.
- Breaking: renaming or removing a setting or credentials key, changing a persisted ID (never done),
  changing the canonical text of a type that already has one, adding a required trait method, and
  moving to an incompatible version of `secrecy`, because `SecretString` is in public signatures.
  Moving to a new version of a private dependency (`reqwest`, `rustls`, `hickory-proto`, `jiff`) is
  not breaking.
- Changing a type from "generic form" to its own canonical form (section 4.7) changes how existing
  values of that type are written. It is listed in the changelog and treated as breaking.
- Third-party types in public signatures: `secrecy::SecretString` (credentials), and the `serde`
  traits as implemented for public types. Nothing from `reqwest`, `rustls`, `hickory`, `jiff`,
  `serde_json`, `tokio` or `bytes`.
- The `tokio` runtime is required at run time by every provider client and by the inspector. This is
  part of the contract although no `tokio` type is public.

### 13.3 Design choices

Choices not fixed by `AGENTS.md`, each with its reason and, where there was one, the alternative
that was rejected. The maintainer can overrule any of them.

Foundations:

1. **Async runtime: tokio.** The HTTP client requires it and both known consumers run on it. A
   runtime-agnostic design would need its own timers, locks and sockets for no present user.
2. **MSRV 1.99.** Section 13.1.
3. **TLS: the crate builds its own `rustls::ClientConfig` with an explicit `aws-lc-rs` provider and
   hands it to the HTTP client.** With the `rustls-no-provider` feature the ordinary path panics if
   the application installed no process-wide provider, and library code must not panic; installing
   one from a library is ruled out by decision 3. Rejected: requiring the application to install a
   provider (a panic at a distance); `reqwest`'s `rustls` feature (not what `AGENTS.md` prescribes).
   Cost: `rustls` must match `reqwest`'s line (section 9.3).
4. **No system CA certificates is not a construction error.** A reject-all verifier is installed
   instead (section 5.1), so loopback tests and builds without HTTPS providers in use do not depend
   on the host's certificate store. Rejected: probing the store separately, as an earlier
   implementation did, which needed another dependency and a re-executed test binary.
5. **HTTP/1.1 only; `reqwest` without `json` and `http2`.** Section 5.1 and 9.3.
6. **`Cargo.lock` is committed.** The gates, in particular the ban on `ring`, are reproducible only
   with pinned versions; a library's lock file does not affect its users.
7. **Workspace layout `dev/zonewright` and `dev/mock`.** The mocks are several thousand lines used
   by integration tests of every provider; as a separate crate they compile once and cannot leak
   into `zonewright`. The mock crate is published too, as `zonewright-mock` with the same version,
   so that the tests build from the package and applications can test against the mocks.
8. **Stateful mock servers on `axum`, not a request-matching mock library.** Section 12.1. Rejected:
   rewriting the suites for a mock library, which would lose the state-based assertions.
9. **RFC 2136: hand-written wire format and TSIG, not a DNS client library.** It is existing,
   tested, self-contained code; its feature then needs no dependency beyond the HMAC, and
   `hickory-proto` offers TSIG signing only together with its DNSSEC machinery.
10. **Third-party public types: `secrecy` and `serde` trait impls only.** Section 13.2. In
    particular stored configuration enters as JSON text (`&str`, `&SecretString`), not as
    `serde_json::Value`.
11. **User agent `zonewright/<version>` with an optional application suffix.** Providers can
    identify the library; the application can identify itself without replacing that.

Names and records:

12. **Owner and zone names are one strict type, always absolute, shown with a trailing dot; names
    inside RDATA are a second, permissive type (`TargetName`).** A relative name is ambiguous
    without its zone, and the two earlier implementations each needed helper functions to convert at
    every provider boundary. The split exists because the crate chooses which names it will write
    records at, but not which names an existing zone points to. Rejected: separate zone, owner and
    relative types (more conversions, no extra safety, since "is this inside that zone" is checked
    at run time either way).
13. **Wildcard and underscore labels are valid; other non-LDH octets are not.** Covers every record
    the consumers produce; keeps path and query encoding of names trivial.
14. **`RecordType` is a code plus named pseudo-types, not a string.** Open as decision 4 requires,
    cheap to copy and compare, and a misspelled type is an error rather than a new type. ALIAS and
    ANAME are needed because two providers list them.
15. **TTL is `Ttl`, an integer newtype; an rrset states `Option<RrsetTtl>`, a number or the
    provider's default.** Sections 2.2 and 3.6. `None` is "not stated" in reads and writes alike, so
    a set read and written back keeps its TTL. Rejected: one four-state enum (keep / number /
    default / unknown), whose "keep" and "unknown" are one meaning; a magic number for the default.
16. **`RecordData` is canonical text without an embedded type.** The rrset carries the type. The
    text is what an application stores and compares; a tagged union of typed records would close the
    set that decision 4 opens.
17. **A TXT value is the joined byte string; character-string boundaries are not preserved.**
    Section 4.4. Rejected: keeping boundaries, which no two providers preserve alike.
18. **Unquoted TXT text containing whitespace is rejected by the parser.** Section 4.4.
19. **Provider text that does not parse is kept as non-canonical data instead of failing the
    listing.** Section 4.9.
20. **Unknown types use the RFC 3597 generic form.** It is the standard's own answer and needs no
    per-type code.

Operations:

21. **Writes take a precondition (`Expect`) instead of separate create and replace methods.** One
    parameter expresses create-only, replace and compare-and-swap, and it maps onto the conditional
    writes two providers have. It is how an application that edits rrsets of any type avoids
    overwriting a concurrent change, which the TXT value operations give only for TXT.
22. **Operations read before they write and report "no change".** Makes repeats cheap and outcomes
    truthful.
23. **Outcomes do not claim knowledge the client lacks**: `Accepted` for blind writes,
    `credentials_verified`, `Unsupported` for acme-dns removal. Rejected: the earlier behavior of
    answering a removal that cannot be done with "not present".
24. **An existing rrset keeps its TTL; the provider's default is requested, never implied.** Section
    3.6. Rejected: a fixed TTL on every write; reading "no TTL" in a write as "the provider's
    default", which would let a value added without a TTL reset an rrset's TTL.
25. **The lock key is the owner name; the locks live in `Context`.** Section 3.3.
26. **No overall deadline per operation; every part is bounded and the future can be dropped.**
    Section 3.7.
27. **A stale zone identifier is re-resolved once before "not found" is believed.** Section 3.8.
28. **Unsupported operations are default trait methods returning a typed error; the trait is not
    sealed.** Section 2.6.
29. **Capabilities and metadata are static per provider and present in every build.** An application
    can describe a provider it did not compile in.
30. **SOA and the apex NS set are not writable in this version.** A guard rail, lifted when a
    consumer needs it.
31. **Settings are strict (`deny_unknown_fields`).** A typo in a key is an error at construction,
    not a silently ignored setting.
32. **Automatic retries follow the letter of the engineering rule: idempotent requests only, also
    for rate-limit answers and rejected tokens.** Section 5.3 and open point 2.

Errors and secrets:

33. **`Error` is an enum with a separate `ErrorKind` and stable kind identifiers.** Variants carry
    typed context (zone, name, status, wait); the kind is what an application switches on and maps.
34. **Inside the crate, error text is built only through the scrubber; public constructors exist for
    implementations outside it.** Section 2.9. A source scan keeps provider clients off the public
    constructors. Rejected: private constructors only, which would make the unsealed trait
    impossible to implement.
35. **Errors carry no `source`.** Section 2.9.
36. **The crypto module is private and keeps a parsed key, not key bytes.** Section 6.

DNS-01 and the inspector:

37. **`challenge_name` drops a wildcard label.** That is what RFC 8555 prescribes; refusing
    wildcards, as one earlier implementation did, pushed the same step into every caller.
38. **CAA policy lookups and CNAME-target policy are out.** Section 7.4.
39. **Inspector: own transport over `hickory-proto`, discovery through recursive resolvers or a
    static list, no iterative descent.** Section 8.1.
40. **Every round asks every server; success is one round in which all agree.** Section 8.6.
41. **Default resolvers are three public ones; the application can replace them.** It works out of
    the box; see open point 4. **Discovered private addresses are refused by default** (section 8.3,
    open point 16).
42. **A static server list is ordinary configuration, not a test-only switch.** In a library the
    application writes the configuration in code; hiding the option would only force tests through a
    back door.
43. **Too many name servers is an error, not a truncated list.** Section 8.3.

Build:

44. **Provider feature names equal provider IDs, underscores included.** Section 9.1.
45. **Private `__` features for dependency groups.** Section 9.1.
46. **One directory per provider with metadata always compiled and the client behind the feature.**
    Section 10.
47. **A scan enforces the per-provider tests.** Section 12.3.

Added after review:

48. **`PreconditionFailed` and `Conflict` are different errors.** One is the caller's expectation
    not holding and never succeeds on repetition; the other is a race the provider caught and the
    next attempt resolves.
49. **A listing returns `ZoneListing` with a `skipped` list instead of a bare vector.** What the
    model cannot hold is reported rather than dropped, without widening `RecordType` to arbitrary
    strings. Rejected: omitting such sets with only a log line, which an application that reconciles
    a zone cannot act on.
50. **The full IANA mnemonic table is built in.** A provider's type name then maps to a code in
    every realistic case.
51. **`Capabilities::txt_values` states what the TXT value operations guarantee against outside
    writers.** The guarantee differs by provider and an application must be able to read it.
52. **No proxy from the environment; an explicit proxy setting only.** Section 5.1 and item 15 of
    section 13.4. Proxy environment variables are ignored with and without the setting.
53. **A rejected token or a failed unconditional whole-set write is not repeated by the transport.**
    Section 5.3.
54. **acme-dns adds always report `Accepted`, and its memory is bounded and expires.** Section 11.3.
55. **Response cap 4 MiB, page limit 1000.** Section 5.4.
56. **The provider's default TTL has three capability levels.** Section 2.5, `ProviderDefaultTtl`.
    Timeweb Cloud can request it only for new records; a bool would either overstate it or hide it.
    The `ttl` setting's spelling is `"provider_default"`, not `null` (section 2.8).
57. **An accepted write whose answer cannot be read is `Transient`, also outside a poll.** Section
    3.7. Hetzner's 2xx write answer without a readable action and an action or change with a status
    the client does not know leave the outcome unknown; `Protocol` would tell the caller not to
    repeat an operation that is safe to repeat.
58. **A raw member of a deserialized set is never parsed.** Sections 2.2 and 4.9. A client keeps
    some text non-canonical although the strict parser accepts it; parsing it on the way back from
    storage changed the set and could change what a record means.
59. **SVCB and HTTPS data in service mode must be self-consistent.** Section 4.6. RFC 9460 section
    2.4.3 asks it of both roles the crate plays; the rule is checked in one place, so the text,
    typed and wire paths cannot differ.
60. **The Route 53 TXT read uses the record-level rule for shared names.** Section 11.3. Asking for
    one rrset would rest on a property of the API that no source states.
61. **reg.ru compares owner names after trimming at both levels, and refuses a plan that would
    remove a record without a content before any write.** Section 11.3. Two levels that disagree
    about which records a name holds are worse than either reading; and the refusal that protects
    the other records of the type must come before the plan's creates, not after them.
62. **A whole-set client does not repair surplus singleton records.** Section 3.4. It answers
    `Error::Protocol` and writes nothing; no whole-set API is known to return such a set (decided by
    the maintainer on 2026-11-16).

Section 13.4, the open points, is in [`13-open-points.md`](./13-open-points.md).
