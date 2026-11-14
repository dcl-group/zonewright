# Changelog

All notable changes to this crate are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) as Cargo applies it.

## Unreleased

### Added

- Domain names (`DomainName`, `TargetName`) and the record model: `RecordType` as an open set,
  `Ttl`, `RecordData` in canonical zone-file text form, `RrSet`, and typed views for TXT, MX, SRV,
  CAA, TLSA and SVCB/HTTPS.
- The provider API: `ProviderId`, provider metadata and capabilities, the `Provider` trait, the
  `AnyProvider` dispatch enum, `Context`, and the typed `Error` with redacted detail.
- DNS-01 helpers: challenge name, zone selection for a name.
- HTTP transport for provider clients on `rustls` with `aws-lc-rs`; the crate installs no
  process-wide crypto provider.
- Selectel v2 client (`selectel_v2`): connection check, zone listing, TXT value operations.
- Cloudflare client (`cloudflare`): connection check, zone listing, TXT value operations.
