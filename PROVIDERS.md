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
  - _No TTL_ — the provider chooses the TTL and a requested TTL is refused; _no zone listing_, _no
    record listing_ — the operation is not offered;
  - _Preconditions checked by the provider_ (or _by the server_) — the expectation of a write is
    checked in the same request that writes; for every other provider the client reads, compares and
    then writes.

A provider appears in exactly one of the three sections below.

## Verified against the live API

None yet.

## Implemented, not yet verified

| Provider      | ID              | Levels                | Notes                                                                                                                                                                                                                                      |
| ------------- | --------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Selectel v2   | `selectel_v2`   | TXT values, records   | An earlier version of this client was proven against the live API. Records: A, AAAA, ALIAS, CAA, CNAME, MX, NS, SRV, SSHFP, TXT; SOA read only. The API does not accept TLSA.                                                              |
| Cloudflare    | `cloudflare`    | TXT values, records   | Records: A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TLSA, TXT. Not written: other types the API knows (HTTPS, SSHFP, SVCB, ...), whose fields are not established. Record attributes outside the model (proxy status, comment, tags) are kept. |
| Yandex Cloud  | `yandex_cloud`  | TXT values, records   | An earlier version of this client was proven against the live API. Records: A, AAAA, ANAME, CAA, CNAME, HTTPS, MX, NS, PTR, SRV, SVCB, TXT; SOA read only. The API does not accept TLSA. Preconditions checked by the provider.            |
| Route 53      | `route53`       | TXT values, records   | Records: A, AAAA, CAA, CNAME, DS, HTTPS, MX, NAPTR, NS, PTR, SPF, SRV, SSHFP, SVCB, TLSA, TXT; SOA read only. Not written: alias and routing-policy record sets. Preconditions checked by the provider.                                    |
| DigitalOcean  | `digitalocean`  | TXT values, records   | Records: A, AAAA, CAA, CNAME, MX, NS, SRV, TXT; SOA read only.                                                                                                                                                                             |
| VK Cloud      | `vk_cloud`      | TXT values, records   | Records: A, AAAA, CNAME, MX, NS, SRV, TXT. The API has no other type (no CAA, no TLSA).                                                                                                                                                    |
| RFC 2136      | `rfc2136`       | TXT values, records   | Records: any type with a wire form; SOA read only. No zone listing, no record listing: dynamic update has no such operation. Preconditions checked by the server.                                                                          |
| Yandex 360    | `yandex_360`    | TXT values, records   | Records: A, AAAA, CAA, CNAME, MX, SRV, TXT. Not written: NS, for which the documentation names no value field.                                                                                                                             |
| Timeweb Cloud | `timeweb_cloud` | TXT values, records   | Records: A, AAAA, CNAME, MX, TXT. Not written: SRV, for which the documentation gives no complete fields.                                                                                                                                  |
| Cloud.ru      | `cloud_ru`      | TXT values, records   | Records: A, AAAA, CAA, CNAME, MX, NS, SPF, SRV, TXT. Not written: records with GSLB links. The API has no SOA and no TLSA.                                                                                                                 |
| Hetzner       | `hetzner`       | TXT values, records   | Records: A, AAAA, CNAME, MX, NS, PTR, SRV, TLSA, TXT; SOA read only. Not written: CAA, DS, HTTPS, SVCB and other types whose value form is not documented; protected rrsets.                                                               |
| nic.ru        | `nicru`         | TXT values, records   | Records: A, AAAA, CNAME, DNAME, MX, NS, PTR, SRV, TXT; SOA read only. Not written: types the documentation shows no record element for (CAA, TLSA, ...) or no canonical form for (HINFO, NAPTR, RP).                                       |
| reg.ru        | `regru`         | TXT values, records   | An earlier version of this client was proven against the live API. Records: A, AAAA, TXT. Not written: CAA, CNAME, HTTPS, MX, NS, SRV, whose listing form is not documented. No TTL. No zone listing.                                      |
| acme-dns      | `acme_dns`      | TXT values (add only) | TXT values only, add only: the acme-dns API offers nothing else. No TTL. No zone listing.                                                                                                                                                  |
| Beget         | `beget`         | TXT values            | TXT values only. Names that hold other record types are refused. At most 10 TXT records per name.                                                                                                                                          |

## Planned

None.

"An earlier version was proven" does not make the client verified here: it is verified again once it
is implemented in this crate.
