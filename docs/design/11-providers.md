# zonewright design: Providers

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 11. Providers

`PROVIDERS.md` remains the list of providers and of what is implemented and verified. The tables
here record what each API is like and what this design plans on it. "Earlier version proven live"
repeats the note of `PROVIDERS.md`; it does not make a client verified. Which clients are verified,
and what each live run covered, is recorded in `PROVIDERS.md` only.

### 11.1 API facts

| ID              | Authentication                                                                                | Native unit                                                                                  | Zone listing                                               | `txt_values`                                               | `preconditions`                 | Provider-side operations         |
| --------------- | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------- | -------------------------------- |
| `acme_dns`      | `X-Api-User` and `X-Api-Key` headers of a registration                                        | two rotating TXT values per registration                                                     | no                                                         | `Rotating`                                                 | —                               | no                               |
| `azure_dns`     | OAuth 2.0 client credentials (service principal with a client secret), bearer token           | record set addressed by zone, type and relative name, replaced whole under its etag          | yes (public zones of one resource group)                   | `Conditional`                                              | `Atomic`                        | no                               |
| `beget`         | login and API password in the form body of every POST                                         | the TXT set of one name, replaced whole                                                      | yes                                                        | `ReadThenWrite`                                            | `ReadThenWrite`                 | no                               |
| `cloud_ru`      | access key exchanged for a bearer token (1 h)                                                 | one record per name and type holding a list of values                                        | yes                                                        | `ReadThenWrite` (re-read before the write)                 | `ReadThenWrite`                 | yes                              |
| `cloudflare`    | static bearer API token                                                                       | individual record with an ID                                                                 | yes (active zones)                                         | `PerValue`                                                 | `ReadThenWrite`                 | no                               |
| `desec`         | static token, `Authorization: Token`                                                          | rrset addressed by zone, subname and type                                                    | yes                                                        | `ReadThenWrite`                                            | `ReadThenWrite`                 | no                               |
| `digitalocean`  | static bearer token                                                                           | individual record with an ID                                                                 | yes                                                        | `PerValue`                                                 | `ReadThenWrite`                 | no                               |
| `dnsimple`      | static bearer API access token (account token; a user token with `account_id`)                | individual record with an ID                                                                 | yes                                                        | `PerValue`                                                 | `ReadThenWrite`                 | no                               |
| `edgecenter`    | permanent API token, `Authorization: APIKey`                                                  | rrset addressed by zone, name and type, replaced whole                                       | yes                                                        | `ReadThenWrite`                                            | `ReadThenWrite`                 | no                               |
| `gandi`         | static personal access token, `Authorization: Bearer` (the deprecated API key is not offered) | rrset addressed by domain, relative name and type, with value-level add and remove (`PATCH`) | yes (personal organization, or the one `sharing_id` names) | `PerValue`                                                 | `ReadThenWrite`                 | no                               |
| `gcore`         | permanent API token, `Authorization: APIKey`                                                  | rrset addressed by zone, name and type, replaced whole                                       | yes                                                        | `ReadThenWrite`                                            | `ReadThenWrite`                 | no                               |
| `google_cloud`  | service account key, RS256 JWT exchanged for an OAuth 2.0 access token                        | rrset addressed by name and type, changed by an atomic change (`deletions` and `additions`)  | yes (public managed zones of the project)                  | `Conditional`                                              | `Atomic`                        | yes (change `pending` to `done`) |
| `hetzner`       | static bearer project token (Cloud API, not the legacy DNS API)                               | rrset with value-level add and remove actions                                                | yes (primary zones)                                        | `PerValue`                                                 | `ReadThenWrite`                 | yes (actions)                    |
| `nicru`         | OAuth 2 password grant, bearer token                                                          | individual record with an ID, staged until a zone-wide commit                                | yes                                                        | `PerValue` (a zone with foreign staged changes is refused) | `ReadThenWrite`                 | no                               |
| `ovh`           | application key, application secret and consumer key; every request signed (SHA-1)            | individual record with an ID, staged until a zone-wide refresh                               | yes                                                        | `PerValue`                                                 | `ReadThenWrite`                 | no                               |
| `porkbun`       | API key and secret API key: in the JSON body of every write, in headers on every read         | individual record with an ID                                                                 | yes (every domain of the account)                          | `PerValue`                                                 | `ReadThenWrite`                 | no                               |
| `regru`         | user name and API password in every form POST; optional client certificate                    | individual record without an ID                                                              | no                                                         | `PerValue`                                                 | `ReadThenWrite`                 | no                               |
| `rfc2136`       | TSIG (HMAC-SHA-256, -384 or -512) on every message, DNS over TCP                              | individual RR                                                                                | no (the protocol has none)                                 | `PerValue`                                                 | `Atomic` (update prerequisites) | no                               |
| `route53`       | AWS Signature Version 4; optional session token                                               | rrset, changed by an atomic change batch                                                     | yes (public zones)                                         | `Conditional`                                              | `Atomic`                        | yes (`INSYNC`)                   |
| `selectel_v2`   | Keystone password exchanged for an `X-Auth-Token` (24 h)                                      | rrset with an ID                                                                             | yes (own project, enabled zones)                           | `ReadThenWrite`                                            | `ReadThenWrite`                 | no                               |
| `timeweb_cloud` | static bearer token                                                                           | individual record with an ID                                                                 | yes                                                        | `PerValue`                                                 | `ReadThenWrite`                 | no                               |
| `vk_cloud`      | Keystone password exchanged for an `X-Auth-Token`                                             | individual record with an ID, on paths of its own for each type                              | yes                                                        | `PerValue`                                                 | `ReadThenWrite`                 | no                               |
| `yandex_360`    | static OAuth token                                                                            | individual record with an ID                                                                 | yes (domains delegated to Yandex)                          | `PerValue`                                                 | `ReadThenWrite`                 | no                               |
| `yandex_cloud`  | service-account key, PS256 JWT exchanged for an IAM token (≤ 12 h)                            | rrset addressed by name and type                                                             | yes (public zones of the folder)                           | `Conditional`                                              | `Atomic`                        | yes (operations)                 |

`txt_values` and `preconditions` are the capability values of section 2.5; what they mean for a
concurrent writer outside the process is in sections 3.5 and 3.4. `preconditions` matters only for
providers with record-level operations; for Beget, which has none in this crate, it is listed as
what the provider's API allows. For acme-dns it has no meaning (the field holds `ReadThenWrite`).

### 11.2 Support in this version

"TXT only until established" means: the record-level operations stay unsupported for this provider
until its record-level API (endpoints, the shape of each record type, TTL rules) has been taken from
the provider's documentation or observed against the live API, as hard rule 3 requires. Nothing in
this table is a guess about such an API.

| ID              | TXT values                                                                                                     | Record level                                                                                                      | Record types (record level)                                                                           | Default `ttl` setting | Default propagation timeout | TXT dialect, read / write                                                                                    | Source of API knowledge                                                                                    |
| --------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `acme_dns`      | add only; plain values                                                                                         | impossible: the API has no read, no delete and nothing but TXT                                                    | —                                                                                                     | not settable          | 60 s                        | none / Raw                                                                                                   | acme-dns README and server source                                                                          |
| `azure_dns`     | yes; strings of printable ASCII without `"` and `\`                                                            | list, get, set, delete; alias record sets are skipped and refused                                                 | A, AAAA, CAA, CNAME, MX, NS, PTR, SOA (read only), SRV, TXT                                           | 60                    | 120 s                       | strings of a record / strings, split at 255 octets                                                           | Azure DNS REST API reference (2018-05-01), Microsoft identity platform documentation, lego                 |
| `beget`         | yes; plain values                                                                                              | TXT only until established (the write form of the A and MX records a write must repeat)                           | —                                                                                                     | 300                   | —                           | Auto / Raw                                                                                                   | Beget.API documentation, lego. Whether the API accepts POST is unconfirmed (section 13.4)                  |
| `cloud_ru`      | yes; plain values                                                                                              | list, get, set, delete; GSLB records are skipped and refused                                                      | A, AAAA, CAA, CNAME, MX, NS, SPF, SRV, TXT                                                            | 60                    | —                           | Auto / Raw                                                                                                   | Evolution DNS OpenAPI specification and documentation                                                      |
| `cloudflare`    | yes; plain values                                                                                              | list, get, set, delete (several requests per set)                                                                 | A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TLSA, TXT                                                      | 120                   | 120 s                       | Auto / Presentation                                                                                          | Cloudflare API v4 documentation, lego                                                                      |
| `desec`         | yes; any value                                                                                                 | list, get, set, delete                                                                                            | A, AAAA, CAA, CNAME, DNAME, HTTPS, MX, NS, PTR, SRV, SSHFP, SVCB, TLSA, TXT                           | 3600                  | 120 s                       | Presentation (quoted, with the documented escapes) / Presentation                                            | deSEC API documentation, lego                                                                              |
| `digitalocean`  | yes; plain values                                                                                              | list, get, set, delete (several requests per set)                                                                 | A, AAAA, CAA, CNAME, MX, NS, SOA (read only), SRV, TXT                                                | 30                    | 120 s                       | Auto / Raw                                                                                                   | DigitalOcean API v2 reference, lego                                                                        |
| `dnsimple`      | yes; plain values                                                                                              | list, get, set, delete (several requests per set); system records and regional records are refused                | A, AAAA, CAA, CNAME, MX, NS, SOA (read only), SRV, TXT                                                | 120                   | 60 s                        | Auto / Raw                                                                                                   | DNSimple API v2 reference and OpenAPI description, support articles, lego, dns-update, dnsimple-go         |
| `edgecenter`    | yes; plain values                                                                                              | list, get, set, delete; dynamic rrsets are skipped and refused                                                    | A, AAAA, CAA, CNAME, MX, NS, SOA (read only), SRV, TXT                                                | 300                   | 360 s                       | Raw / Raw                                                                                                    | EdgeCenter API description and SDK, lego                                                                   |
| `gandi`         | yes; values the record level can write (one string of 1 to 255 printable ASCII characters without `"` and `\`) | list, get, set, delete                                                                                            | A, AAAA, CNAME, MX, NS, SRV, TXT                                                                      | 300                   | 1200 s                      | Auto / Presentation                                                                                          | Gandi LiveDNS API reference, lego, dns-update                                                              |
| `gcore`         | yes; plain values                                                                                              | list, get, set, delete; dynamic rrsets are skipped and refused                                                    | A, AAAA, CAA, CNAME, MX, NS, SOA (read only), SRV, TXT                                                | 300                   | 360 s                       | Raw / Raw                                                                                                    | Gcore DNS API reference and description, lego, dns-update                                                  |
| `google_cloud`  | yes; plain values                                                                                              | list, get, set, delete; routing-policy and signed rrsets are skipped and refused                                  | A, AAAA, CAA, CNAME, MX, NS, SOA (read only), SRV, TLSA, TXT                                          | 120                   | 180 s                       | Presentation (quoted strings or one unquoted string) / Presentation                                          | Cloud DNS API v1 reference and discovery document, Google OAuth 2.0 service account page, lego, dns-update |
| `hetzner`       | yes; plain values                                                                                              | list, get, set, delete (a TTL change of an existing set is a second request)                                      | A, AAAA, CNAME, MX, NS, PTR, SOA (read only), SRV, TLSA, TXT                                          | 60                    | 120 s                       | Auto / Presentation                                                                                          | Hetzner Cloud API reference, lego, hcloud-go schema                                                        |
| `nicru`         | yes; plain values                                                                                              | list, get, set, delete; one commit per operation                                                                  | A, AAAA, CNAME, DNAME, MX, NS, PTR, SOA (read only), SRV, TXT                                         | 30                    | 1200 s                      | Raw / Raw                                                                                                    | the provider's request description (2013, read in the Internet Archive copy), lego                         |
| `ovh`           | yes; plain values                                                                                              | list, get, set, delete (several requests per set); one refresh per operation, and before a read while one is owed | A, AAAA, CAA, CNAME, MX, NS, SRV, TLSA, TXT                                                           | 120                   | 60 s                        | Auto / Raw                                                                                                   | the provider's API schema, go-ovh, the provider's guides and Terraform provider, lego, dns-update          |
| `porkbun`       | yes; plain values                                                                                              | list, get, set, delete (several requests per set; a change of only the priority of an MX or SRV value is refused) | A, AAAA, CAA, CNAME, MX, NS, SRV, TLSA, TXT                                                           | 600                   | 600 s                       | Auto / Raw                                                                                                   | Porkbun API v3 OpenAPI description and knowledge base, lego, dns-update                                    |
| `regru`         | yes; plain values                                                                                              | list, get, set, delete for A, AAAA, TXT (several requests per set)                                                | A, AAAA, TXT                                                                                          | not settable          | —                           | Auto / Raw                                                                                                   | reg.ru API 2 documentation, lego. Earlier version proven live                                              |
| `rfc2136`       | yes                                                                                                            | list by zone transfer (AXFR), get, set, delete with server-checked prerequisites                                  | any type with a wire form; SOA read only                                                              | 60                    | —                           | wire format                                                                                                  | RFC 2136, RFC 8945, RFC 5936, RFC 7766, RFC 1035                                                           |
| `route53`       | yes; plain values                                                                                              | list, get, set, delete; alias and routing-policy sets are skipped and refused                                     | A, AAAA, CAA, CNAME, DS, HTTPS, MX, NAPTR, NS, PTR, SOA (read only), SPF, SRV, SSHFP, SVCB, TLSA, TXT | 60                    | 120 s                       | Auto / Presentation                                                                                          | Amazon Route 53 API reference, lego                                                                        |
| `selectel_v2`   | yes; plain values                                                                                              | list, get, set, delete                                                                                            | A, AAAA, ALIAS, CAA, CNAME, MX, NS, SOA (read only), SRV, SSHFP, TXT                                  | 60                    | —                           | Presentation, quoted content only / Presentation                                                             | Selectel DNS API v2 and authorization documentation                                                        |
| `timeweb_cloud` | yes; plain values                                                                                              | list, get, set, delete (several requests per set)                                                                 | A, AAAA, CNAME, MX, TXT                                                                               | `provider_default`    | —                           | Auto / Raw                                                                                                   | the public API description (OpenAPI document), lego                                                        |
| `vk_cloud`      | yes; plain values                                                                                              | list, get, set, delete (several requests per set)                                                                 | A, AAAA, CNAME, MX, NS, SRV, TXT                                                                      | 60                    | —                           | Auto / Raw                                                                                                   | the provider's published API description, lego                                                             |
| `yandex_360`    | yes; plain values                                                                                              | list, get, set, delete (several requests per set)                                                                 | A, AAAA, CAA, CNAME, MX, SRV, TXT                                                                     | 300                   | —                           | Auto / Raw                                                                                                   | Yandex 360 API documentation, lego                                                                         |
| `yandex_cloud`  | yes; plain values                                                                                              | list, get, set, delete                                                                                            | A, AAAA, ANAME, CAA, CNAME, HTTPS, MX, NS, PTR, SOA (read only), SRV, SVCB, TXT                       | 60                    | —                           | master-file strings / Raw (in double quotes with `;`, `(`, `)`) for TXT values, Presentation at record level | Yandex Cloud DNS, IAM and Operation API documentation, lego. Earlier version proven live                   |

Notes on the table:

- "plain values" is `Capabilities::txt_plain_only` and concerns the TXT value operations. It is
  lifted per provider when the encoding of other values is established.
- At record level, Selectel v2, Yandex Cloud, Cloudflare and Hetzner write TXT as quoted chunks of
  at most 255 octets. For Selectel v2 and Yandex Cloud the earlier record-level implementation
  establishes that form for printable ASCII without `"` and `\` (SPF, DKIM, DMARC and similar values
  of any length). A value that would need an escape is refused with `InvalidInput` until the
  provider's handling of escapes is established. Route 53 writes quoted strings with its documented
  octal escapes and `\"`; a TXT value with a backslash is not sent. Cloud.ru writes the text itself
  and refuses values that would need an escape. DigitalOcean, reg.ru, Timeweb Cloud, VK Cloud,
  Yandex 360, Gcore, EdgeCenter, DNSimple, Porkbun and OVHcloud write plain values only
  (`Txt::is_plain`), as their TXT value operations do. Gandi writes one quoted string of at most 255
  printable ASCII octets, and Azure DNS strings of at most 255 octets, with no `"` or `\` in either;
  Google Cloud DNS writes quoted strings and refuses a value that needs an escape; deSEC writes the
  documented presentation-format escapes, so any bytes.
- TLSA is absent from the record types of Selectel v2 and Yandex Cloud because neither API accepts
  it. SOA is read only wherever a provider lists it, and the apex NS set is not writable (section
  3.4).
- Yandex Cloud writes plain TXT values unquoted in the value operations, as the version proven live
  did, except a value with `;`, `(` or `)`, which is written in double quotes (the documentation's
  TXT section: to use `;`, "enclose the string containing it in double quotes"); at record level it
  writes quoted canonical text, as its documentation describes for values with spaces. Both levels
  read TXT by one rule, the master-file format the TXT section names: strings separated by
  whitespace, each quoted (with the escapes of RFC 1035) or unquoted, joined into one value, so
  `"ab" "c"`, `ab c` and `abc` all hold `abc`. Data the rule leaves undecided (an unquoted string
  with `;`, `(` or `)`, strings not separated by whitespace, an unterminated quote, text outside
  ASCII) is non-canonical data at record level and never a value of the client's in the value
  operations. What each level writes reads back as the same value at both levels. The same page's
  ANAME section shows unquoted TXT with spaces and `;`, which the TXT section's rule reads as
  several strings and a comment; the client follows the TXT section (section 13.4, item 26).
- Selectel v2 reads TXT by one rule at both levels: content that starts with `"` is read by the
  strict presentation parser (one quoted string or several), anything else (unquoted, mixed or
  unterminated content) is non-canonical data at record level and never a value of the client's in
  the value operations, since its sources show TXT content only "wrapped in `\"`".
- Every provider whose API allows it has record-level operations. Beget waits until the write form
  of the A and MX records is established: a write at a name must repeat them or deletes them
  (section 11.3, section 13.4 item 20).

### 11.3 Provider-specific design points

Settings and credentials keep the key names of the earlier TXT-only implementation, with these
differences:

- Every provider: the application-owned key for a propagation timeout is not a setting of the crate.
  The provider's recommendation is `ProviderMeta::default_propagation_timeout`.
- `selectel_v2`: the project is given by exactly one of `project_id` and `project_name` (Keystone
  scope by ID, or by name within the account's domain), because the two earlier implementations each
  used one form.
- `yandex_cloud`: `folder_id` becomes optional and `zone_ids` (an object mapping zone names to zone
  IDs) is added; at least one of them is required. A configured zone ID is verified against the
  zone's name before first use and serves accounts whose role is granted on a zone rather than on
  the folder. Zones without a configured ID are looked up in the folder; of several zones with the
  same name only a public one is used, and two public ones are `Error::Config`.

Behavior that the design fixes because the generic sections cannot:

- `acme_dns`. The server keeps the two most recent values of a registration and has no read. A value
  sent while it is already in one slot overwrites the other slot, so a needless repeat can displace
  a live neighbor (the wildcard and the base name of one certificate share a challenge name). The
  client therefore keeps, in `Context`, per server URL and name, at most two values this process
  sent, each with the time of the send and whether it was confirmed (a 2xx answer) or had an unknown
  outcome (timeout, connection lost, 5xx). An entry is forgotten 15 minutes after it was recorded,
  when a third value for the name displaces the oldest, and on a definite refusal of its send; the
  memory holds at most 1024 names and drops the least recently used. `add_txt_value` behaves as
  follows. A value with a live confirmed entry is not sent again. A value with a live unconfirmed
  entry is sent again only if the name has no other live entry. Anything else is sent. Every one of
  these paths returns `AddOutcome::Accepted`, the two that send nothing included: the client cannot
  observe the server, another writer may have displaced the value since, and `AlreadyPresent` would
  claim knowledge it does not have. A send that displaces a remembered live value is logged at
  `WARN`. The name must equal the `fulldomain` of a configured registration, and the value must be
  43 characters of the base64url alphabet, the only thing the server accepts; otherwise
  `Error::InvalidInput`, before any request.
- `beget`. A write happens only after a complete read whose answer names the requested name. A name
  that holds records of other types is refused (`Error::Rejected`) for both add and remove, because
  a write that omits them deletes them: a report in lego's issue tracker (issue 2774, 2025-12-30)
  quotes the provider's support saying that all existing A, MX and TXT records of the name must be
  sent "in their entirety, otherwise the rest will be deleted", and the write spelling of A and MX
  records is not documented. The client therefore writes TXT only and only at names that hold
  nothing but TXT. An outside writer's A or MX record added between the client's read and its write
  is lost; this is part of open point 14. A name holds at most 10 TXT records, the API's limit per
  type; a larger set is `InvalidInput`. Credentials go in the POST body, never in the query string.
  An answer whose `records` key is missing or `null` is `Error::Protocol` with nothing written,
  although lego's test answer for an empty name has no such key (open point 29).
- `cloud_ru`. More than one TXT record for a name is `Error::Protocol`. A record marked read-only is
  `Error::Rejected`. A zone marked read-only is left out of `list_zones`, is reported by `check` as
  not found with a detail, and every operation on it, reads included, is `Error::Rejected`. A list
  field absent from a listing page is an empty page (the provider's API description does not mark it
  required, and Proto3 JSON omits empty repeated fields); a list given as `null` or as a non-array,
  or a non-string page token, is `Error::Protocol`. A record name without a trailing dot that can be
  read both as relative to the zone and as a full name inside it is `Error::Protocol` when either
  reading is the requested name: the form the API uses is not documented, and the client does not
  guess. Two zones with one name, and a listed record of another zone, are `Error::Protocol`. A
  record with GSLB links answers from its links, not from its values: it is not an rrset (section
  3.4), a listing skips it, and every record-level operation and TXT value operation at its name and
  type is `Error::Rejected` after the read. The read again before every write (section 3.5) is the
  layers' `reread_before_write`. In the record layer the refusal of a read-only record, which needs
  the read, and that of a wildcard NS record are made before that second read
  (`WholeSet::check_write`); in the TXT value operations a read-only record is refused at the write,
  after it.
- `hetzner`. Only zones in primary mode are usable; a secondary zone is reported by `check` as not
  found with a detail, and operations on it are `Error::Rejected`. Values are removed using exactly
  the text the API returned. An rrset with `ttl: null` ("If not set, the Zone's Default TTL is
  used") reads as the provider's default (`Requestable`). A new rrset with the default is created
  without `ttl`, a TXT value is added with `add_records` without `ttl`, and an explicit TTL is
  turned back into the default with `change_ttl` and `ttl: null`: the OpenAPI schema requires the
  key and allows `null` with that description; no live run has confirmed it yet (section 13.4, item
  25).
- `nicru`. Changes are staged and published by a commit that covers the whole zone, including edits
  staged by anyone else; a rollback (`POST …/rollback`) discards every staged change. The client
  therefore (a) takes a per-zone lock in `Context` for the whole read, edit and commit; (b) refuses
  to work in a zone that has staged changes it did not make (`Error::Rejected`, nothing committed);
  (c) marks the zone in `Context` before every request that can change its staged state: before a
  TXT edit as pending commit, before each edit of a record-level operation as pending rollback
  (pending commit once every edit is staged), and before a commit or a rollback as what it attempts;
  (d) tries the commit, or the rollback, up to three times and returns `Error::Transient` if all
  fail. A mark starts unconfirmed. After an edit fails with an unknown outcome, or a record-level
  operation fails, the zone is listed again under the zone lock: without staged changes the mark is
  cleared, with them the client commits (a single edit) or rolls back (a record-level operation,
  which is never published half-applied); an edit that was certainly refused only clears the mark.
  After the last failed commit or rollback attempt the zone is listed once more: a clean zone (an
  attempt applied with its answer lost) loses the mark, and staged changes confirm it. Only a
  confirmed mark is acted on by a later operation, read or write, which commits or rolls back as the
  mark says before it goes on. A zone with staged changes and an unconfirmed mark (an operation
  dropped while a request was in flight, or a settling listing that failed) is refused by every
  operation (`Error::Rejected`; `check` reports it with its own detail) until the staged changes are
  committed or rolled back by hand; a zone found without staged changes loses its mark, confirmed or
  not. A confirmation establishes that the staged changes include this process's; it does not
  exclude a writer outside the process that staged changes in the meantime or after the zone lock is
  released, and the next operation then commits or rolls back that writer's changes too. The
  documentation does not say whether the record listing shows staged or published records (Docs
  4.5.2 speaks only of "resource records which are already created in the zone file"; its example in
  a zone with staged changes lists records just created, which suggests a staged view but is no
  rule), so the client cannot compare the staged state with what it staged and keeps no fingerprint
  of it (section 13.4, item 22). The mark is process memory; after a restart a zone left with staged
  changes needs a commit or a rollback by hand. Reads (`get_rrset`, `list_rrsets`) take the zone
  lock too and refuse a zone with staged changes that are not under a confirmed mark of this process
  (`Error::Rejected`). A record without `<ttl>` takes the zone's default (Docs 4.6) and reads as the
  provider's default (`Requestable`): a record staged without `<ttl>` gets it, and a switch to it
  from a number, like any TTL change, stages the value again (without `<ttl>`) and deletes the old
  record. A zone under a Secondary service, or listed under more than one DNS-master service, is not
  usable.
- `regru`. `check` calls the API's no-operation request, which the documentation describes as
  requiring valid credentials, on every call; `credentials_verified` is always true. No function
  sets a TTL and the listing states none: every set reads with the provider's default, which a write
  may request (`Requestable`). The owner name of a listed record is compared after trimming white
  space around `subname`, at the record level and for the TXT value operations alike; a removal
  always sends the client's own relative name. A plan that would remove a record whose listed
  content is empty or blank is refused with `Error::Rejected` before any write, since
  `zone/remove_record` without a content removes every record of the type at the name (documentation
  9.18).
- `beget`. `check` calls the domain listing, which like every method of the API requires the login
  and password; `credentials_verified` is true also with an empty zone list.
- `rfc2136`. DNS over TCP to the configured `server` (an IP literal or a host name, with an optional
  port, default 53).
  - Timeouts: `ContextOptions::connect_timeout` covers name resolution and the TCP connect;
    `ContextOptions::request_timeout` covers one exchange, from sending a message to having read the
    whole response. A response is at most 65535 octets by the framing. Queries and the single-RR add
    and delete of the TXT value operations are idempotent on the server (RFC 2136 section 3.4.2) and
    get at most 3 attempts with the back-off of section 5.3; `SERVFAIL` counts as a transient
    failure. Record-level updates, which carry value-dependent prerequisites, are sent once.
  - Listing. `list_rrsets` makes one zone transfer (AXFR, RFC 5936) over TCP, signed with the
    client's key. Every message is verified (RFC 8945 section 5.3.1): the first and the last must be
    signed, at most 99 in a row may be unsigned, each signed one over the prior MAC with its length,
    the unsigned messages since and its timers, as BIND 9, Knot DNS and PowerDNS compute it (their
    source read on 2026-11-16); `dig` 9.10.6 verified the mock's transfers on 2026-11-16, and a
    transfer from a real name server is still to be checked. Records of unsigned messages are taken
    only after the next signed message verifies; a failure is `Protocol`, is not repeated, and
    returns nothing. A signed REFUSED is `Forbidden`, a signed NOTAUTH `ZoneNotFound`; a server that
    answers a denied transfer unsigned (Knot DNS, by its source: NOTAUTH without TSIG) gives
    `Protocol`, since an unsigned error is not believed. The transfer begins and ends with the same
    SOA; another serial in a signed closing message is `Transient`, as are a cut connection,
    SERVFAIL, a read timeout and the deadline, repeated as a query is. Section 3.7 sets no overall
    deadline because every part of an operation is bounded; a transfer has up to 100 000 parts, so
    one attempt is bounded at 20 times `request_timeout`. Each attempt is also bounded at 64 MiB on
    the wire, 100 000 messages and 256 MiB of records held once decoded; reaching one is `Protocol`
    naming it. Values are read as `get_rrset` reads them, so a listed set the record-level
    operations can address is `Unchanged` when written back; glue and occluded sets are listed but
    answer `Rejected`, and SOA and apex NS are listed but not writable. DNSKEY, RRSIG, NSEC, NSEC3,
    NSEC3PARAM and query or meta types are skipped as `NotPlainRecords`; CDS, CDNSKEY, ZONEMD and
    private types are listed.
  - `ContextOptions::loopback_only`: a `server` that is not a loopback IP literal is `Error::Config`
    at construction. Host names are refused in that mode, since classifying one would need a lookup.
  - A response whose TSIG does not verify against the request is `Error::Protocol` whatever its
    response code, so a forged negative answer cannot turn a removal into `NotPresent`. TSIG errors
    are `Error::Auth`, with a hint about clock skew for `BADTIME`: `BADKEY` and `BADSIG` unverified,
    since RFC 8945 requires those answers to be unsigned (a forged one can therefore make an applied
    update look refused), every other TSIG error only when its MAC verifies. `NOTAUTH` is
    `ZoneNotFound`; `REFUSED` on an update is `Forbidden`; `REFUSED` on the query before a TXT value
    operation is tolerated and leads to the blind path of section 3.5, while at record level it is
    `Forbidden`, since `SetOutcome` has no blind outcome. The TSIG key is at least 16 octets.
  - Preconditions: the protocol's update prerequisites (RFC 2136 section 2.4) are evaluated by the
    server atomically with the update, hence `Preconditions::Atomic`. The record-level operations
    send `Expect::Absent` as "RRset does not exist" and `Expect::Matches`, as well as the client's
    own read, as "RRset exists (value dependent)"; a failed prerequisite (`YXRRSET`, `NXRRSET`) is
    `Conflict`, and the layer repeats the operation once from a new read, which ends in
    `PreconditionFailed` when the expectation no longer holds (section 3.4). A CNAME write also
    carries "name is not in use"; its `YXDOMAIN` answer is `Rejected`. An update longer than 65535
    octets is `InvalidInput`. A prerequisite cannot express a TTL, so a TTL in `Matches` is compared
    by the client after its read.
  - The TXT value operations send single-RR changes (`PerValue`); deleting a whole rrset is never
    sent by them. An add carries one prerequisite, "no CNAME at the name" (RFC 2136 section 2.4.3):
    without it a server silently ignores a TXT add at a name that owns a CNAME (section 3.4.2.2),
    and the client would report a value as created that was not. The server's `YXRRSET` answer is
    `Error::Rejected`.
  - TTL: with read access an add carries the TTL of the existing rrset. Without it the exception of
    section 3.6 applies: the add carries the client's `ttl`, and the server may apply it to the
    whole rrset. A requested TTL may be anything the protocol carries, 0 to 2^31 − 1 (RFC 2181
    section 8), a delegation's 172800 included; the `ttl` setting keeps 1 to 86400.
- `route53`. The zone is found by exact name among public hosted zones; several with the same name
  are `Error::Config` unless `hosted_zone_id` selects one. Region `us-east-1` and service `route53`
  are constants. A signature rejected for clock skew is `Error::Auth` with that hint. A requested
  TTL may be 0 to 2147483647, as the API accepts (`ResourceRecordSet.TTL`); the `ttl` setting keeps
  1 to 86400. The read before a TXT value operation asks for two rrsets at the name and type, as the
  record-level read does: a second set of the same name and type makes the name not plain records,
  and the operation is `Error::Rejected` with nothing written, whatever the first set carries. The
  API reference does not state that a set without `SetIdentifier` never shares its name and type
  with another set, so the client does not rely on it.
- `selectel_v2`. Names are sent in Unicode form. Records with the `disabled` flag follow section
  3.4. An rrset holds at most 100 records; a larger request is `InvalidInput`. An rrset is addressed
  by reading it by name and type on every operation, not by a remembered ID. The answer to a create
  of an existing rrset is not documented, so a refused create is followed by a read (section 3.5);
  the delete of the rrset is sent once. An update sends back the comment and, in the documented
  `X-Managed-By` header, the managing resource as read, since whether an update without them clears
  them is not established. An rrset that a web resource manages (`managed_by` read) is deleted like
  any other, by `delete_rrset` and by the removal of its last TXT value; taking a record over from
  an external tool is the application's decision (decided by the maintainer on 2026-11-14). The
  delete carries the managing resource in the `X-Managed-By` header as read, which the OpenAPI
  documents for `DELETE` as for `PATCH`; the provider's own Go client sends the delete without it,
  and whether the API needs it is not documented. A refused delete is the error its status maps to
  and is not sent again in another form. A listing follows a positive `next_offset` until the items
  received reach the stated `count`, and past it while pages still bring items and name a next
  offset, since an earlier page's `count` may be stale; a listing that ends short of its `count` is
  `Error::Protocol`. Inside a value, a name without the trailing dot and `@` are read as
  non-canonical data (section 4.9), since the sources do not say whether they are relative to the
  zone. TXT content is read by one rule at both levels (section 11.2): unquoted or mixed content is
  non-canonical at record level, and the TXT value operations never take it for a value of theirs,
  so an add puts the value next to it and a removal answers `NotPresent`. A project given by name is
  scoped within the account's Keystone domain, and the project ID the identity service states for
  the token tells the project's zones from others; of several zones with the requested name, the one
  of that project is used. `check` exchanges the credentials for a new token even when one is
  cached.
- `timeweb_cloud`. Records are created, updated and deleted with the `v2` calls
  (`POST /v2/domains/{name}/dns-records`, `PATCH` and `DELETE /v2/domains/{name}/dns-records/{id}`),
  where `name` is the owner name: the domain for the apex, the full name below it. The deprecated
  `v1` create and delete are not used (section 13.4, item 12). The API has no `v2` listing; every
  read uses the `v1` calls, which are not marked deprecated: `GET /v1/domains/{zone}` for the
  subdomains the domain states, then `GET /v1/domains/{fqdn}/dns-records` for the zone and for each
  of those subdomains. Each listed record is placed at its owner name by deciding, per listing,
  whether it states names relative to the zone or in full (`names.rs`); a name that reads both ways
  and that no listing settles is `Error::Protocol` on a read of it and is reported in `skipped` by a
  zone listing. An empty or `@` name in the listing of a subdomain is `Protocol`. A relative name is
  read relative to the zone in every listing, also in the listing of a subdomain. This is an
  assumption from the wording of the `v2` record schema, "Имя поддомена (только поддомен без
  основного домена, например `sub` для `sub.example.com`)" ("only the subdomain without the main
  domain"): the part left out is the main domain, not the listed subdomain (section 13.4, item 28).
  Where a listing shows evidence of the other reading, the client refuses rather than misplaces: a
  record at the listed subdomain itself would be stated without a name, a record below it would name
  something not at or below the subdomain, and a record the zone's listing also shows would be at
  two names, each `Protocol`. A record shown by several listings is taken once by its identifier
  only when every listing shows it at the same name with the same type, value, priority and TTL; one
  identifier at two names or with different contents is `Protocol`. A `404` on the domain's answer
  or on the zone's listing is `ZoneNotFound`; a `404` on a create is told apart by a lookup of the
  zone (`ZoneNotFound`, or `Rejected` for a name the provider refused); a `404` on an update is
  `Conflict`; a `404` on a delete counts as done once a new read no longer shows the value. Nothing
  is remembered between operations. No subdomain is created before a create: the API description
  says one must exist, while lego does not create one and a user's run recorded in its tracker
  succeeded without it. A record without `ttl` (optional in the create; absent or `null` in the
  listing) has the provider's choice and reads as the provider's default. It can be requested for
  records a write creates (`ForNewRecords`): whether a `PATCH` without `ttl` clears an explicit TTL
  is not documented, so a write that would need it is refused after the read, with nothing written.
  The `ttl` setting's default is `"provider_default"`; `null` and a missing key mean the same.
- `cloudflare`. Record attributes the model does not carry (`comment`, `tags`, `proxied`,
  `private_routing`, `settings`) survive: a record that keeps its value is not touched, and a TTL
  change or the in-place change of a CNAME is a `PATCH` whose body carries the record type and only
  the changed field. A new record in an existing rrset takes over `proxied`, `private_routing` and
  `settings` when every record read agrees on them; when they disagree, a write that has to create a
  record is `InvalidInput`. A TTL of 1 means automatic and reads as the provider's default; a create
  and a `PATCH` with `ttl: 1` request it, also in place of an explicit TTL (`Requestable`; the API
  schema of `ttl` is the same for create and edit, "Setting to 1 means 'automatic'"). A requested
  explicit TTL for a proxied record is `InvalidInput`; the provider's default is what a proxied
  record has anyway. The `ttl` setting accepts `"provider_default"` and, with the same meaning, the
  stored `1`. Both refusals are made in the record layer's `check_plan` hook, over the whole plan,
  before any write.
- `digitalocean`. A host name stated as exactly `@` in the data of a CNAME, NS, MX or SRV record
  reads as the domain's name.
- `vk_cloud`. The documented update (`PUT`) carries no TTL and, for A, AAAA and SRV, no value, so a
  replacement deletes and creates records, except a CNAME, which is replaced by one in-place `PUT`
  of its target. A TTL change of a record that stays (a CNAME changed in place included) is refused
  with `InvalidInput` in `check_plan`, before any write.
- `yandex_360`. The listing has no filter by name or type, and its documentation leaves the name
  form open: the list page describes the record field `name` as "Полное доменное имя" ("full domain
  name", word for word the description of the `domain` path parameter, with the example `example`),
  the create page as "Имя записи." ("record name"), and lego sends names relative to the domain. The
  form is decided once per listing from what it states, and only the relative form can be proven (by
  `@`, or by a dotless name that is not within the zone). The full form cannot: every set of dotless
  names a full-form listing can state is also a possible relative-form listing, since the documented
  create form writes `name: "www.example.org"` as a record at `www.example.org.example.org`. A name
  whose relative reading would be longer than a domain name can be is placed at its full reading in
  a listing that has not proven the relative form; in one that has, it is not placed. A record whose
  dotless name reads as two different names in a listing that does not decide the form is
  `Error::Protocol` for `get_rrset`, `set_rrset`, `delete_rrset` and the TXT value operations of its
  type at either name (a record of another type counts there as data of an unknown type), and is
  reported in `skipped` by `list_rrsets`. If the live listing states full names, every operation on
  a name and type that has records is refused this way until the form is confirmed (section 13.4,
  item 27). Names are written relative to the domain, `@` for the apex. A CNAME is replaced in place
  by the edit call.
- `yandex_cloud`. The strict write must repeat the existing set exactly, including fields this crate
  does not model, so the client keeps the JSON object it read and sends that object as the deletion.
  TTL travels as a JSON string. Inside a value of a type other than TXT, a name without the trailing
  dot (one that reads differently relative to the zone than absolute) and `@` are non-canonical data
  (section 4.9), never read as relative or as absolute: the documentation's examples spell names
  with the trailing dot and describe the fields as an "FQDN", say nothing of dotless names or `@`
  inside values, and show dotless names that are plainly absolute in the ANAME section; its
  statement of the master-file format stands in the TXT section. Names are written absolute with the
  trailing dot. TXT is read by one rule at both levels, and the value operations write a value with
  `;`, `(` or `)` in double quotes (section 11.2).
- `azure_dns`. Azure Resource Manager (`management_url`, default `https://management.azure.com`),
  API version `2018-05-01` (the only stable one; lego's `armdns` v1.2.0 uses it), every path below
  `/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/dnsZones`.
  Authentication is OAuth 2.0 client credentials with a client secret at
  `{login_url}/{tenant_id}/oauth2/v2.0/token` (default host `https://login.microsoftonline.com`),
  form body `client_id`, `scope`, `client_secret`, `grant_type`. The scope defaults to
  `https://management.azure.com//.default`, as the identity platform's section on the trailing slash
  and `.default` prescribes for Resource Manager, and is a setting of its own, not derived from
  `management_url`: the documentation states the identifier for the public cloud only. The token is
  cached and renewed before `expires_in`; `check` always obtains a new one. A `400` from the token
  endpoint is `Auth`, as is a `401`. The client secret travels only in that form body; `login_url`
  therefore receives the secret and `management_url` the token, and both settings must be trusted
  like the credentials (section 5.1). The zone name is a path key (no identifiers to cache). Reads
  are `GET …/{zone}/{type}/{name}`; a `404` is "no record set" (as lego reads it), and the zone is
  then read: its `404` is `ZoneNotFound` (assumed). Writes, each sent once: `PUT` with the whole
  record set and `If-None-Match: *` (create) or `If-Match: <etag as returned>` (replace), and
  `DELETE` with `If-Match`. The status of a failed condition is not documented, so any refusal of a
  write is followed by a new read: a record set that appeared, vanished or has another etag is
  `Conflict` (the layers then run the operation once more from the read), otherwise the refusal is
  `Rejected` with `error.code` as the provider code. A `DELETE` answered `204` ("not found") or
  refused is done when the new read finds no record set. The body of a replacement is the properties
  as read without `fqdn` and `provisioningState`, with the type's record property and `TTL`;
  `metadata` is kept, and record objects of values that stay are sent back as returned. A record set
  with `targetResource.id` (alias) is skipped in a listing (`NotPlainRecords`) and refused by every
  operation (`Rejected`, status `None`); one with a property the reference does not list is read but
  not written (assumed, conservative); a listed set of a type outside the ten of `2018-05-01` is
  skipped as `NotPlainRecords`. Names inside records are written without the trailing dot and read
  as absolute (the documentation's examples). TXT: a record is a list of strings; a string of
  printable ASCII without `"` and `\` stands for itself (assumed for the space); values are split
  into strings of at most 255 octets; any other record is a foreign value kept as non-canonical
  data. Listings send no `$top`, take only the `$skipToken` of `nextLink` (spelled with a literal
  `$`, as the documentation's example) and never request the link; that the link carries nothing
  else the service needs is assumed (the documentation says to request it). They end at a page
  without `nextLink`, also an empty one; an empty page with a `nextLink` is followed. A link without
  `$skipToken`, a token that does not advance and a repeated page are `Protocol`, and the shared
  page limit bounds a run of empty pages. Zones with `zoneType` `Private` are left out (defensive).
  `429` with `Retry-After` is handled by the transport, also for
  `RetryableErrorDueToAnotherOperation`: reads are repeated, writes end with `RateLimited`. A
  national cloud needs `management_url`, `login_url` and `scope` (the defaults are the public
  cloud's). Removing the last TXT value deletes the record set together with its `metadata` (section
  3.5; no source says the service keeps a TXT record set without records). The documented limits (20
  records per set, 400 per TXT set, 4,096 TXT characters per set, raisable through support) are not
  checked before a request.
- `desec`. API `https://desec.io/api/v1`, `Authorization: Token <token>`. The zone name is the key
  of every path (no identifiers to cache); the owner is the `subname` relative to the zone, `@` in a
  path and `""` in a body. Reads are `GET …/rrsets/{subname}/{type}/`; a `404` covers a missing
  rrset and a domain the account does not own, so the domain is then read. Writes, each sent once:
  `POST …/rrsets/` (a `400` on create is followed by a new read: an rrset found there is
  `Conflict`), `PATCH …/rrsets/{subname}/{type}/` with `records` and `ttl` (a `404` is taken for
  "gone since the read", `Conflict`: assumed), `DELETE` (`204` also for a missing rrset; a `404` is
  the domain, reported by a new read). A record list over 4091 entries or over 64,000 characters of
  JSON is refused before the write (documented limits). Record content is presentation format
  (documented): values are written as canonical text and read with the strict parser; a name without
  the trailing dot and unquoted TXT are non-canonical data. Escapes are documented for TXT only, so
  a value of another type whose canonical text needs a backslash is not sent unless already held.
  Listings always send `cursor=` (so a listing of any length is in pagination mode), read every
  `Link` field line (a list-valued header may be split, RFC 9110 section 5.3; the transport's
  `Response::header_fields` returns all of them) and follow only the `cursor` of the `rel="next"`
  link, never the URL; they end at a page without `next`. A `Link` field that is not readable text
  or not in RFC 8288 form, a `next` link without a cursor, an empty page with a `next` link, a
  cursor that does not advance and a repeated page are `Protocol`, never a shorter listing. `check`
  reads the first page of the domain listing and each domain. The message is `detail`, else the
  strings of the body; no machine-readable error code is documented for these calls, so errors carry
  no `ProviderCode`. `429` with `Retry-After` is handled by the transport (reads repeated when the
  wait is at most 30 s, writes end with `RateLimited`); the client does not pace requests. TTL 1 to
  86400 is accepted by the client; the floor is the zone's `minimum_ttl`, set by the provider per
  domain and not read ahead, so a lower TTL costs one write and comes back `Rejected`; default 3600
  (the documentation's "common choice", lego's default). Token policies restrict writes while reads
  stay allowed, so `check` can pass for a token that may not write; a token's `allowed_subnets` may
  refuse requests from other addresses (answer not documented). Bulk writes are not used.
- `dnsimple`. Every path starts with the numeric account: `account_id` from the settings, or for an
  account token the account of `GET /whoami`, read on the first call that needs it and kept for the
  client's life. A user token without `account_id` is `Config`; only `check` compares `account_id`
  with an account token's own (a wrong one otherwise shows as `ZoneNotFound`, the provider's 404).
  Record reads list the zone's records by `type` only and match the name on the client's side (the
  `name` filter's handling of case and of `""`, the apex, is not documented). A record with
  `system_record` is never updated or deleted (`check_plan`, `InvalidInput`); a name and type with a
  record whose `regions` are not empty or `global` is refused (`Rejected`) and skipped in listings
  (`NotPlainRecords`). Host names are written without a trailing dot, as every API example states
  them. The API defines 404 as "doesn't exist or ... doesn't have permissions": a 404 to a create is
  `ZoneNotFound` only when a read of the zone is 404 too, and a 404 to an update or a delete by
  identifier is the provider's refusal when a new read still finds the record (otherwise the record
  went away: `Conflict` for an update, done or `Conflict` for a delete as before). Listings send
  `per_page=100` and follow `pagination`: the stated `current_page` must be the one asked for, a
  page before the last must not be empty or repeat the previous one, and the items must add up to
  `total_entries`, else `Protocol`; totals that change between pages are `Transient` (the zone
  changed while it was read). The documented quota answer (429 with `X-RateLimit-Reset`, no
  `Retry-After`) gives the wait (section 5.3): a read waits for a window that ends within the
  transport's inline bound (30 s) and is repeated, otherwise `RateLimited` with the wait; writes are
  sent once. Lego's cleanup deletes every TXT record at the name; the client deletes only the
  records holding the value.
- `edgecenter`. Shares the implementation of `gcore` (`providers/gcore_shared`), configured by its
  own specification, with the same record types (no DNAME). EdgeCenter spaces its requests
  (`min_request_interval_ms`, default 250 ms, the documented 4 per second). A create of an existing
  rrset is answered `409`, which is `Conflict`; any other refusal of a create is followed by a read,
  as for Gcore.
- `gandi`. Authentication is a personal access token only: the deprecated API key cannot be created
  any more by an account that has none (authentication page) and is not offered. A wrong, expired or
  insufficient token is `Forbidden`, not `Auth`: the reference answers a bearer token that "has
  expired, does not have enought permission or does not exists" with `403` (its `401` is for "a
  wrong API Key"), and the cases cannot be told apart. The zone listing sends `sharing_id` when it
  is set; record routes do not (none is documented for them). TXT value operations use
  `PATCH …/records/{name}/TXT` with `add_rrset_values` or `remove_rrset_values`, so a foreign value
  is never part of a request; the `PATCH` carries `rrset_ttl` with the TTL the read stated (the
  reference does not say what a change without it does to the TTL, and its only example sends it),
  and none when the read stated none. A `200` to the `PATCH` counts only when the rrset it states
  holds the added value, or no longer holds the removed one (compared as decoded values); an answer
  without values is confirmed by a read; otherwise `Protocol`. A new rrset is created with `POST`,
  whose documented `409` (other values) or `200` (same values) for an existing rrset is `Conflict`,
  and any other success status `Protocol`. The last value is removed by the same `PATCH` (`204`, "no
  longer exists"); the TXT value operations never send `DELETE`. Record-level writes are one `POST`
  or `PUT` with all values and a TTL; the client always sends a TTL (an rrset read without
  `rrset_ttl` reads with no TTL stated and is written back with the `ttl` setting). A `404` on an
  rrset read is followed by a domain read; a `404` there is `ZoneNotFound`. A `404` on a `PATCH`
  remove or a `DELETE` is done only when a new read no longer finds the value or the rrset. Inside
  values, a name without the trailing dot (the reference shows both spellings and does not say
  whether it is relative) is non-canonical data; names are written with the dot. TXT is read `Auto`
  (quoted text as presentation, bare text without whitespace or `"` as the value, anything with a
  backslash non-canonical) and written as one quoted string of at most 255 printable ASCII octets
  without `"` or `\`, at both levels. Listings page by `page` without `per_page` until an empty
  page; `Total-Count` is a cross-check, and a repeated page is `Protocol`. The provider's error
  `code` (an integer) is carried as `ProviderCode`. The mock models the `PATCH` cases the reference
  leaves open in several readings (`PatchReading`: TTL kept or reset to a default, duplicate add
  ignored or refused, absent remove ignored or refused, missing rrset `404` or created by an add),
  and the tests run the client under each.
- `gcore`. One implementation (`providers/gcore_shared`) serves `gcore` and `edgecenter`, each
  configured by its own specification. The API token goes in `Authorization: APIKey`. A 404 on an
  rrset is followed by a zone lookup. Dynamic rrsets (pickers, filters, a filter set or rrset
  metadata) are skipped in listings and never written; a non-zero `filter_set_id` is treated as
  dynamic (assumed). Any refused create is followed by a read, and only an rrset found there makes
  it `Conflict`, since Gcore documents no answer for a create of an existing rrset. Listings end on
  an empty page; `total_amount` is a cross-check, and a repeated page is `Protocol`. `name` and
  `type` may be missing from a single-rrset answer. TXT `content` is one raw string. SOA is read
  only.
- `google_cloud`. API `https://dns.googleapis.com/dns/v1/projects/{project}`; settings `project_id`
  (required), `managed_zones` (zone name to managed zone name or ID, an object or its JSON text),
  `ttl`, `change_poll_ms`, `dns_url`, `token_url`; credentials `service_account_key`, the key file
  as an object or its JSON text (`client_email`, `private_key_id`, `private_key`; `type` must be
  `service_account` when present; the key file's `token_uri` is ignored). A JWT (`alg` RS256, `typ`,
  `kid` = `private_key_id`; `iss` = `client_email`, `scope` `ndev.clouddns.readwrite`, `aud` =
  `token_url`, `iat`, `exp` = `iat` + 3600) signed with `aws-lc-rs` (`crypto::Rs256Key`,
  known-answer test RFC 7515 A.2) is posted as a form to `token_url` (default
  `https://oauth2.googleapis.com/token`, the URL and `aud` of Google's service-account page; the
  documentation's own key-file examples disagree on `token_uri`). The token is cached by
  `expires_in` and sent as a bearer token; a `400` from the token endpoint is `Auth` (RFC 6749
  section 5.2). Zones: `managedZones.list?dnsName=<zone>.`, only a zone whose `visibility` is
  `public` (or absent without `privateVisibilityConfig`, as lego) and without forwarding, peering,
  reverse-lookup or service-directory configuration; two such zones of one name are `Config`
  (`check` says to set `managed_zones`); a configured managed zone is read with `managedZones.get`
  and verified against its DNS name. The zone is cached by its ID (preferred over its name: a
  recreated zone gets a new ID and a stale entry meets a `404`). Reads:
  `rrsets.list?name=<fqdn>.&type=<T>` (a missing rrset is an empty list; a `404` is the zone, looked
  up again). Writes: one `changes.create` with the rrset JSON exactly as read in `deletions` (no
  normalization, members the model does not carry included) and the new rrset (the read object with
  `rrdatas` replaced, the TTL only when requested) in `additions`; a new rrset is an addition only,
  a delete a deletion only; sent once. The provider checks the precondition for an rrset that exists
  (the deletion must match exactly; documented). That an addition of an rrset that exists is refused
  is assumed (the error messages page lists `alreadyExists` without naming the case); if the service
  applied it as a replacement, an rrset another writer creates between the read and the addition
  would be replaced without an error, and the guarantee would hold only for rrsets that exist at the
  read. No client code can detect that; the ignored test `live_google_cloud_change_semantics`
  decides it. Any refusal is followed by a new read: a changed rrset (exact JSON comparison, since
  the API's deletion match is exact) or a zone under another ID is `Conflict`, which both layers
  repeat once; a delete whose rrset is gone is done. lego's two-change replacement and its
  whole-rrset cleanup are not copied, nor its treatment of a `404` to a change as success. A
  `pending` change is polled with `changes.get` (section 3.7); a look that fails, a change still
  pending or an unknown status is `Transient`. Errors: the message is `error.message` (token
  endpoint `error_description`), the provider code `error.errors[0].reason` (the body shape of
  google-api-go-client, which lego uses; no Cloud DNS page shows it); `413` (the quotas page) is a
  rate limit like `429`, except that either status with the reason `quotaExceeded` (a resource
  quota, "an impending change would exceed your current quota") is `Rejected` with that code and is
  not repeated. rrdata are presentation format (RFC 1035 section 5, per the discovery document):
  names with the trailing dot, a dotless name or `@` is non-canonical data; TXT is read by the
  strict parser (quoted strings, or one unquoted string as lego writes) and written quoted;
  canonical text with a backslash is not sent, nor TXT rrdata over 1000 characters (counted on the
  text sent). An rrset with `routingPolicy` or `signatureRrdatas` is skipped (`NotPlainRecords`) and
  refused (`Rejected`). TTL 1 to 2147483647 (int32, "positive integer"); default 120 (lego);
  propagation timeout 180 s (lego). `dns_url` and `token_url` receive the access token and the
  signed JWT: they need the same trust as the credentials (section 5.1). `list_zones` needs
  `dns.managedZones.list` on the project even when every zone is in `managed_zones`; `check` uses
  `managedZones.get` for configured zones and `managedZones.list` for the others.
- `ovh`. Settings `application_key` (sent in `X-Ovh-Application`), `endpoint` (`ovh-eu`, `ovh-ca`,
  `ovh-us`, mapped to the `api.{eu,ca,us}.ovhcloud.com/1.0` hosts of go-ovh, the provider's client;
  the API schema and dns-update still name `eu.api.ovh.com`), `base_url` (overrides `endpoint`, for
  tests), `ttl` and `read_retry_ms` (first pause before a listed record that answered 404 is read
  again, 1 to 60000, default 1000, doubling); credentials `application_secret` (never sent) and
  `consumer_key` (sent in `X-Ovh-Consumer`), both visible ASCII without whitespace. Every request
  but `GET /auth/time` carries `X-Ovh-Timestamp` and
  `X-Ovh-Signature: "$1$" + hex(SHA1(AS+"+"+CK+"+"+METHOD+"+"+URL+"+"+BODY+"+"+TS))`, computed per
  attempt over the exact URL (query included) and body, in a buffer sized up front and wiped. The
  timestamp is the last reading of `/auth/time` plus the time elapsed since, on a monotonic clock;
  the reading is made before the first signed request and again after an hour (the client's choice;
  go-ovh reads once and keeps a wall-clock difference). No documented refusal names the timestamp,
  so none triggers a new reading. The answer is unsigned and trusted: forging it can make requests
  fail or yield future-dated signatures for one exact request each, no secret. SHA-1 comes from
  `aws-lc-rs` (`crypto::sha1`, compiled with `ovh` only). A 403 is `Forbidden`, which at this
  provider can also mean an expired or revoked consumer key (go-ovh README); no documented `class`
  separates the cases. OAuth2 service accounts are not implemented: the provider's guide
  (`www.ovh.com/auth/oauth2/token`) and go-ovh (`auth.eu.ovhcloud.com/oauth2/token`) disagree on the
  token endpoint. The record API stages every change; `POST /domain/zone/{zone}/refresh` publishes
  all staged changes of the zone, including others', and nothing discards them. Assumed without a
  source: the record endpoints report the staged state. The client refreshes at the end of every
  write operation that reached the provider, whatever its outcome (an unchanged result and a
  `PreconditionFailed` included: what the read found may be an earlier operation's change whose
  refresh failed, in any process); one that fails before any request sends none. It also keeps per
  zone, in the client only, the record writes no successful refresh has covered yet (a refresh
  covers only the writes that had ended when it was sent; a write still in flight stays owed); while
  one is owed, every write operation refreshes on every exit and `get_rrset` and `list_rrsets`
  refresh before reading (as nic.ru settles its own staged changes before a read), failing with the
  refresh's error if it fails. A write that ended without a certain outcome (no answer, a 5xx, or
  its future dropped in flight) stays owed until a second refresh succeeds, so the client's next
  operation in the zone refreshes once more. If the provider applies such a write only after that,
  no refresh of this client publishes it; the next write operation in the zone does. A dropped
  operation is thus published by the client's next operation in the zone; once the client is gone,
  by the next write operation in the zone in any process, and not by a read elsewhere. A failed
  refresh after a successful operation is its error, prefixed "stored ... but not published" where
  the kind has a text (`RateLimited` has none); nothing is undone. The refresh runs after the name
  lock is released; the writes of one replacement are published together unless another refresh of
  the zone runs between them. Reads list identifiers with `fieldType` and, except at the apex or for
  a name with a backslash, `subDomain` (pattern filters, LIKE and ILIKE; assumed never to leave out
  an exact match), then read each record (N + 1 requests; at the apex every record of the type; at
  most 1000 records, else `Protocol`), and compare type and name exactly. TXT reads and writes cover
  `fieldType` TXT only: records of the types SPF, DKIM and DMARC at a name are not part of its TXT
  rrset, and whether the name servers serve them as TXT is not established. A listed record whose
  read answers 404 is read again (pauses of `read_retry_ms` doubling; Terraform retries such reads
  for a minute) while the listing still holds it, then `Transient`; one the listing no longer holds
  is left out. A 404 is `ZoneNotFound` only when `GET /domain/zone` no longer lists the zone; a 404
  to an update is `Conflict` when a new read no longer finds the record, else the refusal; a 404 to
  a delete follows the per-record rule. The create answer is not read (it may lack the `id`,
  Terraform). Updates send `target` and `ttl`, and `subDomain` when not empty, as read unless they
  change. A record's `ttl` of `0` or `null` reads as no TTL (`ProviderDefaultTtl::Absent`); a record
  created next to such records gets their form (`0`, or no `ttl` member; Terraform sends `0` when
  unset), not the `ttl` setting. The error `class` is the provider code. Lego deletes the record by
  the id it remembered from its create; this client deletes only records that hold the value, found
  by a read.
- `porkbun`. Writes (`POST`) carry the keys as `apikey` and `secretapikey`, the first members of the
  JSON body, and no key header: the request schemas of the writes list them as required, the
  description calls the body "the standard method", and lego and dns-update do the same; the delete
  sends the keys only. Reads (`GET`) carry them as the headers `X-API-Key` and `X-Secret-API-Key`,
  which the spec declares on those operations. Every read is `GET /dns/retrieve/{domain}`, the whole
  domain, matched by fully qualified name and type on the client's side, so the client knows whether
  a CNAME or other data is at a name. The calls by name and type (`editByNameType`,
  `deleteByNameType`) act on every record of a name and type and are never used. Refusals are HTTP
  400 with a `code`, carried as the provider code; `INVALID_API_KEYS_001`, `API_KEY_REQUIRED` and
  `INVALID_USER` are `Auth`, `API_ACCESS_DISABLED` (a domain not opted in to API access) and the key
  restrictions are `Forbidden`, `INVALID_DOMAIN` and `DOMAIN_NOT_FOUND` are `ZoneNotFound`,
  `INVALID_INPUT`, `INVALID_TYPE` and `MISSING_PARAMETER` are `InvalidInput`, `RATE_LIMIT_EXCEEDED`
  is a rate limit whatever the status. `DUPLICATE_RECORD` on a create is followed by a read: the
  value found there is `Conflict`, otherwise the refusal is the error. Because the provider compares
  name, type and content, and the priority of MX and SRV is outside the content, a plan that would
  create a record whose content a record of the type at the name has already (or that the plan
  creates twice) is refused with `InvalidInput` before any write. `INVALID_RECORD_ID` on a delete is
  done only when a new read no longer finds the value; on an edit it is `Conflict`. An edit sends
  the whole record (`name`, `type`, `content`, `ttl`, `prio`), new values where they change and the
  read ones otherwise, which is correct under the partial edit of v3.48 and the whole-record edit
  before it; `notes` is left out and so kept. `check` pings with the keys (`credentialsValid` must
  be true) and looks each domain up with `/domain/listAll?domain=`: a domain with `apiAccess` 0 is
  not found (with a detail), one with `notLocal` 1 is found with a warning that writes are stored
  but not published. `list_zones` pages `/domain/listAll` by offset; a page of fewer than 1000
  domains ends it, a repeated page is `Protocol`. TTL from 600 (the documentation's minimum, not
  lego's 300) to RFC 2181's maximum, since none is documented; the default `ttl` is 600, and a
  create always carries a TTL, since without one the provider applies the account's minimum.
