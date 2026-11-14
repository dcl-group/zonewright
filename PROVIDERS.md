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

A provider appears in exactly one of the three sections below.

## Verified against the live API

None yet.

## Implemented, not yet verified

| Provider      | ID              | Levels                | Notes                                                                                            |
| ------------- | --------------- | --------------------- | ------------------------------------------------------------------------------------------------ |
| Selectel v2   | `selectel_v2`   | TXT values            | An earlier version of this client was proven against the live API. The API does not accept TLSA. |
| Cloudflare    | `cloudflare`    | TXT values            |                                                                                                  |
| Yandex Cloud  | `yandex_cloud`  | TXT values            | An earlier version of this client was proven against the live API. The API does not accept TLSA. |
| Route 53      | `route53`       | TXT values            |                                                                                                  |
| DigitalOcean  | `digitalocean`  | TXT values            |                                                                                                  |
| VK Cloud      | `vk_cloud`      | TXT values            |                                                                                                  |
| RFC 2136      | `rfc2136`       | TXT values            | Dynamic update has no operation that lists the records of a zone.                                |
| Yandex 360    | `yandex_360`    | TXT values            |                                                                                                  |
| Timeweb Cloud | `timeweb_cloud` | TXT values            |                                                                                                  |
| Cloud.ru      | `cloud_ru`      | TXT values            |                                                                                                  |
| Hetzner       | `hetzner`       | TXT values            |                                                                                                  |
| nic.ru        | `nicru`         | TXT values            |                                                                                                  |
| reg.ru        | `regru`         | TXT values            | An earlier version of this client was proven against the live API.                               |
| acme-dns      | `acme_dns`      | TXT values (add only) | TXT values only: the acme-dns API offers nothing else.                                           |
| Beget         | `beget`         | TXT values            |                                                                                                  |

## Planned

None.

"An earlier version was proven" does not make the client verified here: it is verified again once it
is implemented in this crate.
