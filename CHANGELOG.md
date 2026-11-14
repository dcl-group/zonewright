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
- Yandex Cloud client (`yandex_cloud`): connection check, zone listing, TXT value operations with
  conditional writes.
- Route 53 client (`route53`): connection check, zone listing, TXT value operations with conditional
  change batches.
- DigitalOcean client (`digitalocean`): connection check, zone listing, TXT value operations.
- VK Cloud client (`vk_cloud`): connection check, zone listing, TXT value operations.
- RFC 2136 client (`rfc2136`): connection check and TXT value operations by dynamic update over TCP,
  authenticated with TSIG.
- Yandex 360 client (`yandex_360`): connection check, zone listing, TXT value operations.
- Timeweb Cloud client (`timeweb_cloud`): connection check, zone listing, TXT value operations.
- Cloud.ru client (`cloud_ru`): connection check, zone listing, TXT value operations.
- Hetzner client (`hetzner`): connection check, zone listing, TXT value operations through
  value-level rrset actions.
- nic.ru client (`nicru`): connection check, zone listing, TXT value operations with a zone-wide
  commit.
- reg.ru client (`regru`): connection check, TXT value operations; optional TLS client certificate.
- acme-dns client (`acme_dns`): adds TXT values through registrations; the API has no read and no
  removal.
