# Providers

The state of every DNS provider client in `zonewright`. This file is the single list of providers:
other documents link here instead of repeating it. The list grows as providers are added.

## How to read this file

- **ID** — the identifier of a provider in code and configuration: a short stable string such as
  `cloudflare`. It names the provider, not an account at it. Applications store it, so an existing
  ID is never renamed or reused.
- **Levels** — a client works at one or both of two levels:
  - _TXT values_ — add or remove one TXT value, as the DNS-01 ACME challenge needs;
  - _Records_ — list zones, read the records of a zone, create, change and delete rrsets.
- **Verified** — the maintainer ran the live tests of the client against the provider's real API and
  they passed. The entry records the date and the levels that were covered. Tests against mocks,
  however thorough, do not count. Only the maintainer moves a provider into the verified section.

- **Notes** — the known limits, in the same words for every provider:
  - _Records:_ the types the record-level operations read and write; _read only_ types are read but
    never written;
  - _Not written:_ what the provider's API has but this client does not write, with the reason;
  - _TTL always the provider's_ — no TTL can be set: a requested number is refused, and the
    provider's default TTL is the only one a write can ask for; _provider's default TTL_ — an rrset
    can have no TTL of its own, reads report it as the provider's default and a write can request it
    (_for new records only_: not in place of an explicit TTL); _no zone listing_, _no record
    listing_ — the operation is not offered;
  - _Preconditions checked by the provider_ (or _by the server_) — the expectation of a write is
    checked in the same request that writes; for every other provider the client reads, compares and
    then writes.

A provider appears in exactly one of the three sections below.

## Verified against the live API

| Provider    | ID            | Levels              | Verified                                                                                                                                                                                                                                                           | Notes                                                                                                                                                                              |
| ----------- | ------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Selectel v2 | `selectel_v2` | TXT values, records | 2026-11-15: TXT values (add and remove, two values in one rrset), zone listing and the connection check, through a real DNS-01 issuance by an application that uses the client. Not covered: reading and writing records, rate limiting, the format of API errors. | Records: A, AAAA, ALIAS, CAA, CNAME, MX, NS, SRV, SSHFP, TXT; SOA read only. Not written: DNAME, HTTPS and SVCB, whose content form no source gives. The API does not accept TLSA. |

## Implemented, not yet verified

| Provider      | ID              | Levels                | Notes                                                                                                                                                                                                                                                                                                                                                                        |
| ------------- | --------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cloudflare    | `cloudflare`    | TXT values, records   | Records: A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TLSA, TXT. Not written: other types the API knows (HTTPS, SSHFP, SVCB, ...), whose fields are not established. Record attributes outside the model (proxy status, comment, tags) are kept. Provider's default TTL.                                                                                                           |
| Yandex Cloud  | `yandex_cloud`  | TXT values, records   | An earlier version of this client was proven against the live API. Records: A, AAAA, ANAME, CAA, CNAME, HTTPS, MX, NS, PTR, SRV, SVCB, TXT; SOA read only. The API does not accept TLSA. Preconditions checked by the provider.                                                                                                                                              |
| Route 53      | `route53`       | TXT values, records   | Records: A, AAAA, CAA, CNAME, DS, HTTPS, MX, NAPTR, NS, PTR, SPF, SRV, SSHFP, SVCB, TLSA, TXT; SOA read only. Not written: alias and routing-policy record sets. Preconditions checked by the provider.                                                                                                                                                                      |
| DigitalOcean  | `digitalocean`  | TXT values, records   | Records: A, AAAA, CAA, CNAME, MX, NS, SRV, TXT; SOA read only.                                                                                                                                                                                                                                                                                                               |
| VK Cloud      | `vk_cloud`      | TXT values, records   | Records: A, AAAA, CNAME, MX, NS, SRV, TXT. The API has no other type (no CAA, no TLSA).                                                                                                                                                                                                                                                                                      |
| RFC 2136      | `rfc2136`       | TXT values, records   | Records: any type with a wire form; SOA read only. Record listing by zone transfer (AXFR), which the key must be allowed to make; the records a DNSSEC signer keeps (DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM) are reported as skipped. No zone listing: the protocol has none. Preconditions checked by the server.                                                           |
| Yandex 360    | `yandex_360`    | TXT values, records   | Records: A, AAAA, CAA, CNAME, MX, SRV, TXT. Not written: NS, for which the documentation names no value field. If the live listing states full names without a trailing dot, the client cannot tell them from relative names and refuses every operation on a name and type that has records, until the form is confirmed against the live API.                              |
| Timeweb Cloud | `timeweb_cloud` | TXT values, records   | Records: A, AAAA, CNAME, MX, TXT. Not written: SRV, for which the documentation gives no complete fields. Provider's default TTL, for new records only.                                                                                                                                                                                                                      |
| Cloud.ru      | `cloud_ru`      | TXT values, records   | Records: A, AAAA, CAA, CNAME, MX, NS, SPF, SRV, TXT. Not written: records with GSLB links. The API has no SOA and no TLSA. Read-only zones are not listed and cannot be read or changed.                                                                                                                                                                                     |
| Hetzner       | `hetzner`       | TXT values, records   | Records: A, AAAA, CNAME, MX, NS, PTR, SRV, TLSA, TXT; SOA read only. Not written: CAA, DS, HTTPS, SVCB and other types whose value form is not documented; protected rrsets. Provider's default TTL. Only zones in primary mode can be read or changed.                                                                                                                      |
| nic.ru        | `nicru`         | TXT values, records   | Records: A, AAAA, CNAME, DNAME, MX, NS, PTR, SRV, TXT; SOA read only. Not written: types the documentation shows no record element for (CAA, TLSA, ...) or no canonical form for (HINFO, NAPTR, RP). Provider's default TTL.                                                                                                                                                 |
| reg.ru        | `regru`         | TXT values, records   | An earlier version of this client was proven against the live API. Records: A, AAAA, TXT. Not written: CAA, CNAME, HTTPS, MX, NS, SRV, whose listing form is not documented. TTL always the provider's. No zone listing. The documentation allows only alphanumeric characters in TXT text; whether the live API accepts the `-` and `_` of a DNS-01 value is not confirmed. |
| acme-dns      | `acme_dns`      | TXT values (add only) | TXT values only, add only: the acme-dns API offers nothing else. TTL always the provider's. No zone listing.                                                                                                                                                                                                                                                                 |
| Beget         | `beget`         | TXT values            | TXT values only; zone listing is offered. Names that hold other record types are refused. At most 10 TXT records per name. If the live API answers a name without records with no record list, as one of lego's test answers does, adding the first value at such a name fails with nothing written.                                                                         |

## Planned

None.

"An earlier version was proven" does not make the client verified here: it is verified again once it
is implemented in this crate.
