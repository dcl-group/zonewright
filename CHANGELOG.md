# Changelog

All notable changes to this crate are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) as Cargo applies it.

## Unreleased

The first version, 0.1.0. Not tagged yet.

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
- Guarantees: HTTP clients use `reqwest` with `rustls` and `aws-lc-rs`; `ring`, OpenSSL and
  `native-tls` are not in the dependency tree; the crate never installs a process-wide crypto
  provider. Secrets are held in `secrecy` wrappers and never appear in `Debug` output, error text or
  `tracing` events. The crate emits `tracing` events only, without request or response bodies or
  headers.
- Minimum supported Rust version 1.99, edition 2024.
