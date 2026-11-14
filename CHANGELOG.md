# Changelog

All notable changes to this crate are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) as Cargo applies it.

## Unreleased

The first version, 0.1.0. Not tagged yet.

### Added

- Names: `DomainName` for zone and owner names and `TargetName` for names inside record data, with
  IDNA conversion, wildcard labels and `NameError`.
- The record model: `RecordType` as an open set of type codes, `Ttl`, `RecordData` in normalized
  zone-file text form (RFC 1035) with wire conversion, and `RrSet`, the unit of every record
  operation; `RecordError`. Typed construction and parsing for TXT (`Txt`), MX (`Mx`), SRV (`Srv`),
  CAA (`Caa`), TLSA (`Tlsa`) and SVCB/HTTPS (`Svcb`, `SvcParam`).
- Provider identifiers: `ProviderId`, one variant per provider, with the persisted string, parsing
  (`UnknownProviderId`) and `ProviderId::ALL`. The list is complete in every build, whatever
  features are enabled.
- Provider metadata and capabilities, present for every provider in every build: `ProviderMeta`
  (name, `verified` flag, default propagation timeout, configuration fields as `ConfigField` and
  `FieldKind`) and `Capabilities` (the operations offered, record types as a `TypeSet`, read-only
  types, `TtlSupport`, `provider_default_ttl`, `Preconditions`, `ValueGuarantee` for the TXT value
  operations, whether an rrset write is one request and whether writes are asynchronous at the
  provider).
- The `Provider` trait: `check`, `list_zones`, `list_rrsets`, `get_rrset`, `set_rrset`,
  `delete_rrset`, `add_txt_value` and `remove_txt_value`, with `Expect` preconditions and the
  results `CheckReport`, `ZoneCheck`, `ZoneInfo`, `ZoneListing` (with `SkippedRrset` and
  `SkipReason` for rrsets the model cannot represent), `SetOutcome`, `DeleteOutcome`, `AddOutcome`
  and `RemoveOutcome`. An operation a provider does not offer is `Error::Unsupported` before any
  network request.
- `AnyProvider`, an enum that dispatches to the clients compiled into the build, built from a
  provider ID and JSON settings and credentials (`AnyProvider::from_json`).
- `Context` and `ContextOptions`: the state shared by the clients of a process (HTTP client,
  per-name locks, timeouts, user agent suffix, extra root certificates).
- `Error` with `ErrorKind` (stable snake_case identifiers), `Operation`, `Error::is_retryable`, and
  `Detail`, the redacted text an error carries.
- DNS-01 helpers in the module `dns01`: `challenge_name` and `CHALLENGE_LABEL`; `follow_cname` over
  the `CnameLookup` trait, with `CnameChain`, `CnameError`, `LookupError` and the default limit
  `CNAME_CHAIN_MAX`; `select_zone` for the zone of a name.
- Propagation inspector in the module `inspector` (feature `inspector`): `Inspector`, configured by
  `InspectorConfig` (`NsDiscovery`, `NameServer`, `IpFamilies`, `PUBLIC_RESOLVERS`), discovers the
  authoritative name servers of a zone, asks a `Question` of any record type at one server, at every
  server or through recursive resolvers (`Answer`), and waits (`WaitOptions`, with a pause between
  rounds of at least `WaitOptions::MIN_INTERVAL`, 1 s) until an `Expectation` with a `Condition`
  (value present, exact set, absent) holds, with a `Report` and a `ServerReport` per name server.
  Discovery fails with `InspectorError::NameServerWithoutAddress` instead of returning a shortened
  server list when an NS name has no usable address. It also implements `CnameLookup`.
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
- Provider clients with TXT value operations and record-level operations: Selectel v2
  (`selectel_v2`), Cloudflare (`cloudflare`), Yandex Cloud (`yandex_cloud`), Route 53 (`route53`),
  DigitalOcean (`digitalocean`), VK Cloud (`vk_cloud`), RFC 2136 dynamic update with TSIG
  (`rfc2136`, without zone or record listing), Yandex 360 (`yandex_360`), Timeweb Cloud
  (`timeweb_cloud`), Cloud.ru (`cloud_ru`), Hetzner (`hetzner`), nic.ru (`nicru`) and reg.ru
  (`regru`, without zone listing). The record types and limits of each are in `PROVIDERS.md`.
- Provider clients with TXT value operations only: acme-dns (`acme_dns`, add only) and Beget
  (`beget`).
- Guarantees: HTTP clients use `reqwest` with `rustls` and `aws-lc-rs`; `ring`, OpenSSL and
  `native-tls` are not in the dependency tree; the crate never installs a process-wide crypto
  provider. Secrets are held in `secrecy` wrappers and never appear in `Debug` output, error text or
  `tracing` events. The crate emits `tracing` events only, without request or response bodies or
  headers.
- Minimum supported Rust version 1.88, edition 2024.
