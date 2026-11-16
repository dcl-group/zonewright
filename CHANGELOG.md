# Changelog

All notable changes to this crate are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) as Cargo applies it.

## Unreleased

Nothing yet.

## 0.2.1 - 2026-11-16

Compatible with 0.2.0.

### Added

- `ProviderCode` and `Error::provider_code()`: `Error::Rejected` and `Error::InvalidInput` carry the
  provider's own machine-readable code for a refusal, when it gave one, in a new field `code`.
  Clients that read one: acme-dns, Beget, Cloud.ru, Cloudflare, DigitalOcean, Hetzner, nic.ru,
  reg.ru, RFC 2136 (the RCODE mnemonic of RFC 2136 section 2.2, or its number), Route 53, Timeweb
  Cloud, Yandex 360, Yandex Cloud. A code is kept whole or dropped, never altered. For the HTTP
  clients, a code is dropped when it contains a secret of the client (a credential, or a token or
  signed assertion it obtained and still remembers) in any ASCII case, as itself, as the hex
  spelling of its UTF-8 bytes, or as standard or URL-safe base64 with or without padding. Part of a
  secret, or any other spelling, is not detected.
- Every call of a `Provider` method on a client of the crate emits one `tracing` event when it
  completes, with the typed client and through `AnyProvider` alike: level `DEBUG`, target
  `zonewright::operation`, message `provider operation`. Fields: `provider`, `operation`, `zone` (or
  `zones`, the count, for `check`), `name` and `rtype` where the operation has them, `outcome` (`ok`
  or the error kind) and `elapsed_ms`. Record values, TTLs, error text, the provider's error code,
  configuration, and request or response data are never included. An implementation of `Provider`
  outside the crate emits nothing.
- `rfc2136`: TSIG algorithm `hmac-sha384` (RFC 8945 section 6), next to `hmac-sha256` and
  `hmac-sha512`.
- `zonewright-mock`: the RFC 2136 mock verifies and signs `hmac-sha384`; `Seed::standard()` gains
  the key `KEY_NAME_384` with `STANDARD_SECRET_384`.

### Changed

- Documentation: `ContextOptions::russian_trusted_root` and `extra_root_certificates` now state that
  the validity dates of a trust anchor are not enforced with `TrustRoots::Mozilla` and
  `TrustRoots::None`; the Russian Trusted Root CA stays trusted after 2032-02-27 until a release
  replaces it.
- Documentation: `TrustRoots::Platform` is not available on Android; with the `platform-verifier`
  feature the crate does not compile for that target.
- Documentation: `TrustRoots::Platform` and `TrustRoots::None` say that their failure is reported by
  `Context::new` only in a build with an HTTP provider, the only kind that uses the trust settings.
- The summary of the 0.2.0 section below also points to the behavior changes listed under its
  "Fixed".

### Fixed

- Route 53: the refusal of an operation at a name whose type is held by several sets, or by a set
  bound to a health check or a traffic policy, says so, for the TXT value operations and the record
  operations alike; the TXT value operations named only aliases and routing policies.
- `zonewright-mock`: a link with a delay too long to add to the current time no longer stops
  applying changes.
- `zonewright-mock`: `link::link` reads the source again until its state and its subscription agree
  (up to eight times), so that a change made while the link is being set up is not replayed over a
  newer state, which could briefly answer an older value.
- `zonewright-mock`: the SOA in the authority section of a negative answer of `dns::DnsMock` carries
  the smaller of its TTL and its MINIMUM (RFC 2308 section 3).
- `zonewright-mock`: `dns::Data::txt` panics on a string over 255 octets, and `DnsMock::add` and
  `DnsMock::set` panic on a name with a label over 63 octets or over 255 octets in all, instead of
  sending a message that cannot be decoded; a TCP answer over 65 535 octets is sent truncated (TC)
  instead of with a wrong length prefix. A link skips, and counts in `Link::skipped`, an rrset whose
  owner name cannot be encoded and a value whose RDATA would be over 65 535 octets.
- `zonewright-mock`: `dns::DnsMock` follows a chain of 16 CNAME records to its final record, and
  answers a longer chain or a loop with the first 16 records and no SOA.

## 0.2.0 - 2026-11-16

Incompatible with 0.1 in three places, each described under "Changed": the default trust anchors of
HTTPS, SOCKS5 proxies, and SVCB/HTTPS data that is not self-consistent. Several entries under
"Fixed" also change what an application observes where 0.1 was wrong: the error kind in some failure
situations of RFC 2136, Route 53, Hetzner and reg.ru, new refusals by the TXT value operations of
nic.ru and Route 53, and the deserialization of a `raw` member of an `RrSet`.

### Added

- `zonewright-mock`: provider mocks report every change of their published records as one type,
  `changes::Change`, through a `changes::Changes` hub (`subscribe`) and the `changes::ChangeSource`
  trait: the complete rrset of a name and type after the change, in zone-file text, whatever the
  shape of the provider's API.
- `zonewright-mock`: `link::link` makes a `dns::DnsMock` serve what a provider mock holds, now and
  as it changes, with `Link::settled`, `Link::hold` / `Link::release` and an optional delay
  (`LinkOptions`). A test of an application that issues certificates over DNS-01 can point its ACME
  server at the `DnsMock`.
- `zonewright-mock`: `start_on(addr, …)` for `MockServer`, `dns::DnsMock` and the provider mocks, to
  listen on an address other than loopback (for an isolated test network shared with an ACME
  server), and `Control::reset()` to return a provider mock to its seed.
- `zonewright-mock`: `dns::Data::caa` and `dns::DnsMock::set_authoritative_answers`.
- `ContextOptions::trust_roots` (`TrustRoots::Mozilla` by default, `Platform`, `None`) chooses the
  certificate authorities a `Context` trusts. `TrustRoots::None` trusts only the roots the options
  add; with none, `Context::new` is `Error::Config`. `TrustRoots::Platform` without the
  `platform-verifier` feature is `Error::Config`.
- `ContextOptions::russian_trusted_root` (default false) trusts the Russian Trusted Root CA of the
  Ministry of Digital Development and Communications of the Russian Federation, compiled into the
  crate, in addition to `trust_roots`; `extra_root_certificates` are trusted in addition to both.
- Cargo features `platform-verifier` and `socks`, enabled by no other feature (not by
  `all-providers`). `rustls-platform-verifier` is a direct dependency only with the first; it stays
  in the dependency tree through `reqwest`, which has no rustls feature without it, but is not used
  without the feature.

### Changed

- SVCB and HTTPS data in service mode (priority not 0) must be self-consistent (RFC 9460 section
  2.4.3): a `mandatory` parameter that lists a key the record does not have, and `no-default-alpn`
  without `alpn`, are now syntax errors in text parsing, typed construction (`Svcb::to_data`) and
  wire decoding. Values 0.1.0 accepted are now refused. A provider read keeps such a value as
  non-canonical data, the inspector reports the answer as failed, and a stored `RrSet` holding such
  a value as canonical text no longer deserializes.
- The default trust anchors of HTTPS are now Mozilla's root certificates compiled into the crate
  (`TrustRoots::Mozilla`, from `webpki-roots`); the operating system's trust store is no longer
  read. To keep the 0.1 behavior, enable the new cargo feature `platform-verifier` and set
  `ContextOptions::trust_roots = TrustRoots::Platform`. A corporate or internal certificate
  authority known only to the system store needs one of those, or its root in
  `extra_root_certificates`. With `TrustRoots::Mozilla` and `TrustRoots::None` certificate
  revocation is not checked; `TrustRoots::Platform` checks it as far as the platform does.
- SOCKS5 proxies need the new cargo feature `socks`. Without it a `socks5://` or `socks5h://` proxy
  URL is `Error::Config`. `reqwest` is no longer built with its `socks` feature unless this feature
  is on.

### Fixed

- Inspector: the TTL reported for an rrset counts a record's TTL with the most significant bit set
  as zero before the smallest TTL is taken (RFC 2181 section 8).
- nic.ru: a TXT value operation refuses a zone whose record listing reports staged changes made
  after the zone lookup, as the record-level operations do.
- RFC 2136: an answer that reports a TSIG error is `Error::Auth` only when it is an unsigned
  `BADKEY` or `BADSIG` (which RFC 8945 requires to be unsigned) or when its MAC verifies against the
  request; otherwise it is `Error::Protocol`.
- `zonewright-mock`: the RFC 2136 mock's BADTIME answer carries the client's time in Time Signed, as
  RFC 8945 section 5.2.3 requires.
- RFC 2136: the refusal text for a name that holds a CNAME no longer contains a run of spaces.
- Route 53: a change status other than `PENDING` or `INSYNC` after an accepted change is
  `Error::Transient` (the outcome is unknown), not `Error::Protocol`.
- Hetzner: an action with a status other than `running`, `success` or `error`, and a 2xx answer to a
  write that does not name an action in the expected form, are `Error::Transient` (the write was
  accepted and its outcome is unknown), not `Error::Protocol`.
- Route 53: the TXT value read asks for two rrsets and refuses a name where a second set shares the
  name and type of a plain-looking one, as the record-level read already did.
- A `{ "raw": … }` member of a deserialized `RrSet` stays non-canonical instead of being parsed. A
  stored set that a client read with non-canonical values now equals a fresh read, and writing it
  back no longer replaces those records. A hand-written `raw` member whose text parses is no longer
  turned into canonical data.
- The refusal of an explicit TTL at a provider that chooses the TTL itself says so instead of naming
  a range.
- reg.ru: the TXT value operations place a listed record at its name the way the record operations
  do, ignoring white space around the listed `subname`, so both levels see the same records.
- reg.ru: a `set_rrset` or `delete_rrset` that would have to remove a listed record without a
  content is refused with `Error::Rejected` before any write, instead of failing with `InvalidInput`
  after the records it had already created or removed.

## 0.1.0 - 2026-11-16

The first release.

### Added

- Names: `DomainName` for zone and owner names and `TargetName` for names inside record data, with
  IDNA conversion, wildcard labels and `NameError`.
- The record model: `RecordType` as an open set of type codes, `Ttl`, `RrsetTtl` (the TTL an rrset
  states: `Explicit(Ttl)` or `ProviderDefault`), `RecordData` in normalized zone-file text form
  (RFC 1035) with wire conversion, and `RrSet`, the unit of every record operation; `RecordError`.
  Typed construction and parsing for TXT (`Txt`), MX (`Mx`), SRV (`Srv`), CAA (`Caa`), TLSA (`Tlsa`)
  and SVCB/HTTPS (`Svcb`, `SvcParam`).
- Provider identifiers: `ProviderId`, one variant per provider, with the persisted string
  (`ProviderId::as_str`), parsing (`ProviderId::parse`, `FromStr` with `UnknownProviderId`),
  `ProviderId::ALL`, `ProviderId::available` (the client is compiled into this build) and
  `ProviderId::meta`. The list is complete in every build, whatever features are enabled.
- Provider metadata and capabilities, present for every provider in every build: `ProviderMeta`
  (name, `verified` flag, default propagation timeout, configuration fields as `ConfigField` and
  `FieldKind`, with `ProviderMeta::field`) and `Capabilities` (the operations offered, record types
  as a `TypeSet`, read-only types, `TtlSupport`, `provider_default_ttl` as `ProviderDefaultTtl`,
  `Preconditions`, `ValueGuarantee` for the TXT value operations, whether an rrset write is one
  request and whether writes are asynchronous at the provider), with `Capabilities::supports`,
  `can_read`, `can_write` and `accepts_ttl`.
- The provider's default TTL can be read, kept and requested: `RrSet::ttl()` is `Option<RrsetTtl>`
  (`None` when no TTL is stated: a read that cannot tell, a write that leaves the TTL alone), the
  same type is the `ttl` of `add_txt_value` and of every provider's `ttl` setting, and its JSON form
  is the number or `"provider_default"`. `Capabilities::provider_default_ttl` (`ProviderDefaultTtl`:
  `Absent`, `ForNewRecords`, `Requestable`) and `Capabilities::accepts_ttl` say where; a request
  elsewhere is `Error::InvalidInput` before any request, and such a setting `Error::Config`. Every
  `ttl` key has the metadata kind `FieldKind::Ttl`. Cloudflare (`ttl: 1`), Hetzner (`null`), nic.ru
  (no `<ttl>`), reg.ru and acme-dns are `Requestable`; Timeweb Cloud is `ForNewRecords`.
- The `Provider` trait: `check`, `list_zones`, `list_rrsets`, `get_rrset`, `set_rrset`,
  `delete_rrset`, `add_txt_value` and `remove_txt_value`, with `Expect` preconditions and the
  results `CheckReport`, `ZoneCheck`, `ZoneInfo`, `ZoneListing` (with `SkippedRrset` and
  `SkipReason` for rrsets the model cannot represent), `SetOutcome`, `DeleteOutcome`, `AddOutcome`
  and `RemoveOutcome`; the report types have `new` constructors. An operation a provider does not
  offer is `Error::Unsupported` before any network request.
- `AnyProvider`, an enum that dispatches to the clients compiled into the build, built from a
  provider ID and JSON settings and credentials (`AnyProvider::from_json`).
- `Context` and `ContextOptions`: the state shared by the clients of a process (HTTP client,
  per-name locks, timeouts, user agent suffix, extra root certificates, `loopback_only` for tests,
  proxy).
- `HttpProxy`, the explicit proxy of `ContextOptions::proxy`: an `http://` or `https://` proxy
  (`CONNECT` tunnels for HTTPS endpoints, optional Basic proxy authentication) or a SOCKS5 proxy
  (`socks5://`, `socks5h://`, optional username/password authentication) that every HTTP provider
  request goes through, except requests to the hosts in `HttpProxy::exclusions`. The password is a
  `SecretString`. Proxy environment variables are ignored with and without it; SOCKS4 and URLs with
  user info are refused. Proxy credentials the proxy refuses are `Error::ProxyAuth`
  (`ErrorKind::ProxyAuth`, `proxy_auth`). RFC 2136 and the inspector do not use the proxy.
- `Error` with `ErrorKind` (stable snake_case identifiers, all of them listed in `ErrorKind::ALL`),
  `Operation`, `Error::is_retryable`, `Error::retry_after`, a constructor per kind for
  implementations of `Provider` outside the crate, and `Detail`, the redacted text an error carries.
- DNS-01 helpers in the module `dns01`: `challenge_name` and `CHALLENGE_LABEL`; `follow_cname` over
  the `CnameLookup` trait, with `CnameChain`, `CnameError`, `LookupError` and the default limit
  `CNAME_CHAIN_MAX`; `select_zone` for the zone of a name.
- Propagation inspector in the module `inspector` (feature `inspector`): `Inspector`, configured by
  `InspectorConfig` (`NsDiscovery`, `NameServer`, `IpFamilies`, `PUBLIC_RESOLVERS`), discovers the
  authoritative name servers of a zone (`Inspector::name_servers`), asks a `Question` of any record
  type at one server (`query_server`), at every server of the zone (`observe`) or through the
  recursive resolvers (`query_recursive`), each answer an `Answer`, and waits (`wait`, with
  `WaitOptions`, whose interval between rounds is at least `WaitOptions::MIN_INTERVAL`, 1 s; at most
  `InspectorConfig::max_questions` expectations per call, default 32, and `max_questions_per_round`
  questions per round, default 1024) until an `Expectation` with a `Condition` (value present, exact
  set, absent) holds at every server, with a `Report` and a `ServerReport` per name server.
  Discovery never shortens the server list: a name server without an address in the configured
  families, or at an address the policy refuses, is returned with `NameServer::not_asked`
  (`NotAsked`, `AddressRefusal`) and reported as a row that never satisfies (`Answer::NotAsked`);
  with `WaitOptions::ignore_unaskable_name_servers` such servers are left out of the condition and
  counted in `Report::unaskable_ignored`. With `InspectorConfig::accept_static_without_aa` (off by
  default) an answer without AA from a server of a static list is read by its content, never a
  referral. Errors are `InspectorError`. It also implements `CnameLookup`.
- Features: one per provider, named like its ID; `all-providers`, which enables every provider;
  `inspector`. No feature is enabled by default.
- Configuration types per provider, in `providers::<id>`: a settings type and a credentials type,
  deserialized from JSON (unknown settings keys are refused): `AcmeDnsConfig`/`AcmeDnsCredentials`,
  `BegetConfig`/`BegetCredentials`, `CloudRuConfig`/`CloudRuCredentials`,
  `CloudflareConfig`/`CloudflareCredentials`, `DigitalOceanConfig`/`DigitalOceanCredentials`,
  `HetznerConfig`/`HetznerCredentials`, `NicruConfig`/`NicruCredentials`,
  `RegruConfig`/`RegruCredentials`, `Rfc2136Config`/`Rfc2136Credentials`,
  `Route53Config`/`Route53Credentials`, `SelectelV2Config`/`SelectelV2Credentials`,
  `TimewebCloudConfig`/`TimewebCloudCredentials`, `VkCloudConfig`/`VkCloudCredentials`,
  `Yandex360Config`/`Yandex360Credentials`, and `YandexCloudConfig`/`YandexCloudCredentials` with
  `AuthorizedKey`.
- Provider clients, one type per provider in `providers::<id>`, built with `new` from the settings,
  the credentials and a `Context`. With TXT value operations and record-level operations: Selectel
  v2 (`SelectelV2`), Cloudflare (`Cloudflare`), Yandex Cloud (`YandexCloud`), Route 53 (`Route53`),
  DigitalOcean (`DigitalOcean`), VK Cloud (`VkCloud`), RFC 2136 dynamic update with TSIG (`Rfc2136`,
  without zone or record listing), Yandex 360 (`Yandex360`), Timeweb Cloud (`TimewebCloud`),
  Cloud.ru (`CloudRu`), Hetzner (`Hetzner`), nic.ru (`Nicru`) and reg.ru (`Regru`, without zone
  listing). With TXT value operations only: acme-dns (`AcmeDns`, add only) and Beget (`Beget`). The
  record types and limits of each are in `PROVIDERS.md`.
- Selectel v2 deletes an rrset that a web resource manages (`managed_by`) like any other, by
  `delete_rrset` and by the removal of its last TXT value; the delete carries the managing resource
  in the `X-Managed-By` header as read. Taking a record over from an external tool is the
  application's decision.
- Guarantees: HTTP clients use `reqwest` with `rustls` and `aws-lc-rs`; `ring`, OpenSSL and
  `native-tls` are not in the dependency tree; the crate never installs a process-wide crypto
  provider. Secrets are held in `secrecy` wrappers and never appear in `Debug` output, error text or
  `tracing` events. The crate emits `tracing` events only, without request or response bodies or
  headers.
- Minimum supported Rust version 1.99, edition 2024.
- Selectel v2 is verified against the live API (`ProviderMeta::verified` is true for it); what the
  run covered is recorded in `PROVIDERS.md`. No other client is verified yet.
- `zonewright-mock`, the stateful mock provider APIs the test suite runs against, is a published
  crate with the same version: the tests build from the package, and an application can test its own
  use of `zonewright` without live accounts. Its API may change more freely.
