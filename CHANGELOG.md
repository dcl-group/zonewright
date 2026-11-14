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
- Beget client (`beget`): connection check, zone listing, TXT value operations at names that hold
  only TXT records.
- Propagation inspector (feature `inspector`): name-server discovery, queries for any record type at
  each authoritative server or through recursive resolvers, waiting for a value to be present, for
  an exact set or for absence, with a report per name server.
- Record-level operations (`list_rrsets`, `get_rrset`, `set_rrset`, `delete_rrset` with
  preconditions) for Selectel v2: A, AAAA, ALIAS, CAA, CNAME, MX, NS, SRV, SSHFP and TXT; SOA is
  read only.
- Record-level operations for DigitalOcean: A, AAAA, CAA, CNAME, MX, NS, SRV and TXT; SOA is read
  only.
- Record-level operations for Cloudflare: A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TLSA and TXT.
  Record attributes the model does not carry (proxy status, comment, tags) are kept.
- Record-level operations for Yandex Cloud: A, AAAA, ANAME, CAA, CNAME, HTTPS, MX, NS, PTR, SRV,
  SVCB and TXT with provider-checked preconditions; SOA is read only.
- Record-level operations for Route 53: A, AAAA, CAA, CNAME, DS, HTTPS, MX, NAPTR, NS, PTR, SPF,
  SRV, SSHFP, SVCB, TLSA and TXT through conditional change batches; SOA is read only. Alias and
  routing-policy record sets are reported as skipped and never written.
- Record-level operations for RFC 2136: get, set and delete of an rrset of any type with a wire
  form, with prerequisites checked by the server in the same update; listing is impossible in the
  protocol.
- Record-level operations for Hetzner: A, AAAA, CNAME, MX, NS, PTR, SRV, TLSA and TXT; SOA is read
  only. A protected rrset is refused; record comments are kept.
- Record-level operations for VK Cloud: A, AAAA, CNAME, MX, NS, SRV and TXT. A record is never
  updated in place: the documented update cannot change a TTL.
- Record-level operations for Cloud.ru: A, AAAA, CAA, CNAME, MX, NS, SPF, SRV and TXT, including
  wildcard names. Records with GSLB links are reported as skipped and never written.

### Changed

- Timeweb Cloud: records are created and deleted with the provider's v2 API instead of the
  deprecated v1 calls, and the listing of the record's own name is read. The client no longer
  remembers created record IDs, and `remove_txt_value` no longer returns `Accepted`. Settings and
  credentials keys are unchanged.
- `Rfc2136Config`: `algorithm` is a `String` and `ttl` a `u32` with the documented defaults; `null`
  is still read as the default.
- `Yandex360Config` no longer implements `Default`: `org_id` is required.
