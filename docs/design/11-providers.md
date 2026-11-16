# zonewright design: Providers

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 11. Providers

`PROVIDERS.md` remains the list of providers and of what is implemented and verified. The tables
here record what each API is like and what this design plans on it. "Earlier version proven live"
repeats the note of `PROVIDERS.md`; it does not make a client verified. Which clients are verified,
and what each live run covered, is recorded in `PROVIDERS.md` only.

### 11.1 API facts

| ID              | Authentication                                                             | Native unit                                                     | Zone listing                      | `txt_values`                                               | `preconditions`                 | Provider-side operations |
| --------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------- | --------------------------------- | ---------------------------------------------------------- | ------------------------------- | ------------------------ |
| `acme_dns`      | `X-Api-User` and `X-Api-Key` headers of a registration                     | two rotating TXT values per registration                        | no                                | `Rotating`                                                 | —                               | no                       |
| `beget`         | login and API password in the form body of every POST                      | the TXT set of one name, replaced whole                         | yes                               | `ReadThenWrite`                                            | `ReadThenWrite`                 | no                       |
| `cloud_ru`      | access key exchanged for a bearer token (1 h)                              | one record per name and type holding a list of values           | yes                               | `ReadThenWrite` (re-read before the write)                 | `ReadThenWrite`                 | yes                      |
| `cloudflare`    | static bearer API token                                                    | individual record with an ID                                    | yes (active zones)                | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `digitalocean`  | static bearer token                                                        | individual record with an ID                                    | yes                               | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `hetzner`       | static bearer project token (Cloud API, not the legacy DNS API)            | rrset with value-level add and remove actions                   | yes (primary zones)               | `PerValue`                                                 | `ReadThenWrite`                 | yes (actions)            |
| `nicru`         | OAuth 2 password grant, bearer token                                       | individual record with an ID, staged until a zone-wide commit   | yes                               | `PerValue` (a zone with foreign staged changes is refused) | `ReadThenWrite`                 | no                       |
| `regru`         | user name and API password in every form POST; optional client certificate | individual record without an ID                                 | no                                | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `rfc2136`       | TSIG (HMAC-SHA-256, -384 or -512) on every message, DNS over TCP           | individual RR                                                   | no (the protocol has none)        | `PerValue`                                                 | `Atomic` (update prerequisites) | no                       |
| `route53`       | AWS Signature Version 4; optional session token                            | rrset, changed by an atomic change batch                        | yes (public zones)                | `Conditional`                                              | `Atomic`                        | yes (`INSYNC`)           |
| `selectel_v2`   | Keystone password exchanged for an `X-Auth-Token` (24 h)                   | rrset with an ID                                                | yes (own project, enabled zones)  | `ReadThenWrite`                                            | `ReadThenWrite`                 | no                       |
| `timeweb_cloud` | static bearer token                                                        | individual record with an ID                                    | yes                               | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `vk_cloud`      | Keystone password exchanged for an `X-Auth-Token`                          | individual record with an ID, on paths of its own for each type | yes                               | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `yandex_360`    | static OAuth token                                                         | individual record with an ID                                    | yes (domains delegated to Yandex) | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `yandex_cloud`  | service-account key, PS256 JWT exchanged for an IAM token (≤ 12 h)         | rrset addressed by name and type                                | yes (public zones of the folder)  | `Conditional`                                              | `Atomic`                        | yes (operations)         |

`txt_values` and `preconditions` are the capability values of section 2.5; what they mean for a
concurrent writer outside the process is in sections 3.5 and 3.4. `preconditions` matters only for
providers with record-level operations; for Beget, which has none in this crate, it is listed as
what the provider's API allows. For acme-dns it has no meaning (the field holds `ReadThenWrite`).

### 11.2 Support in this version

"TXT only until established" means: the record-level operations stay unsupported for this provider
until its record-level API (endpoints, the shape of each record type, TTL rules) has been taken from
the provider's documentation or observed against the live API, as hard rule 3 requires. Nothing in
this table is a guess about such an API.

| ID              | TXT values             | Record level                                                                            | Record types (record level)                                                                           | Default `ttl` setting | Default propagation timeout | TXT dialect, read / write                                                                                    | Source of API knowledge                                                                   |
| --------------- | ---------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `acme_dns`      | add only; plain values | impossible: the API has no read, no delete and nothing but TXT                          | —                                                                                                     | not settable          | 60 s                        | none / Raw                                                                                                   | acme-dns README and server source                                                         |
| `beget`         | yes; plain values      | TXT only until established (the write form of the A and MX records a write must repeat) | —                                                                                                     | 300                   | —                           | Auto / Raw                                                                                                   | Beget.API documentation, lego. Whether the API accepts POST is unconfirmed (section 13.4) |
| `cloud_ru`      | yes; plain values      | list, get, set, delete; GSLB records are skipped and refused                            | A, AAAA, CAA, CNAME, MX, NS, SPF, SRV, TXT                                                            | 60                    | —                           | Auto / Raw                                                                                                   | Evolution DNS OpenAPI specification and documentation                                     |
| `cloudflare`    | yes; plain values      | list, get, set, delete (several requests per set)                                       | A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TLSA, TXT                                                      | 120                   | 120 s                       | Auto / Presentation                                                                                          | Cloudflare API v4 documentation, lego                                                     |
| `digitalocean`  | yes; plain values      | list, get, set, delete (several requests per set)                                       | A, AAAA, CAA, CNAME, MX, NS, SOA (read only), SRV, TXT                                                | 30                    | 120 s                       | Auto / Raw                                                                                                   | DigitalOcean API v2 reference, lego                                                       |
| `hetzner`       | yes; plain values      | list, get, set, delete (a TTL change of an existing set is a second request)            | A, AAAA, CNAME, MX, NS, PTR, SOA (read only), SRV, TLSA, TXT                                          | 60                    | 120 s                       | Auto / Presentation                                                                                          | Hetzner Cloud API reference, lego, hcloud-go schema                                       |
| `nicru`         | yes; plain values      | list, get, set, delete; one commit per operation                                        | A, AAAA, CNAME, DNAME, MX, NS, PTR, SOA (read only), SRV, TXT                                         | 30                    | 1200 s                      | Raw / Raw                                                                                                    | the provider's request description (2013, read in the Internet Archive copy), lego        |
| `regru`         | yes; plain values      | list, get, set, delete for A, AAAA, TXT (several requests per set)                      | A, AAAA, TXT                                                                                          | not settable          | —                           | Auto / Raw                                                                                                   | reg.ru API 2 documentation, lego. Earlier version proven live                             |
| `rfc2136`       | yes                    | get, set, delete with server-checked prerequisites; listing impossible                  | any type with a wire form; SOA read only                                                              | 60                    | —                           | wire format                                                                                                  | RFC 2136, RFC 8945, RFC 7766, RFC 1035                                                    |
| `route53`       | yes; plain values      | list, get, set, delete; alias and routing-policy sets are skipped and refused           | A, AAAA, CAA, CNAME, DS, HTTPS, MX, NAPTR, NS, PTR, SOA (read only), SPF, SRV, SSHFP, SVCB, TLSA, TXT | 60                    | 120 s                       | Auto / Presentation                                                                                          | Amazon Route 53 API reference, lego                                                       |
| `selectel_v2`   | yes; plain values      | list, get, set, delete                                                                  | A, AAAA, ALIAS, CAA, CNAME, MX, NS, SOA (read only), SRV, SSHFP, TXT                                  | 60                    | —                           | Presentation, quoted content only / Presentation                                                             | Selectel DNS API v2 and authorization documentation                                       |
| `timeweb_cloud` | yes; plain values      | list, get, set, delete (several requests per set)                                       | A, AAAA, CNAME, MX, TXT                                                                               | `provider_default`    | —                           | Auto / Raw                                                                                                   | the public API description (OpenAPI document), lego                                       |
| `vk_cloud`      | yes; plain values      | list, get, set, delete (several requests per set)                                       | A, AAAA, CNAME, MX, NS, SRV, TXT                                                                      | 60                    | —                           | Auto / Raw                                                                                                   | the provider's published API description, lego                                            |
| `yandex_360`    | yes; plain values      | list, get, set, delete (several requests per set)                                       | A, AAAA, CAA, CNAME, MX, SRV, TXT                                                                     | 300                   | —                           | Auto / Raw                                                                                                   | Yandex 360 API documentation, lego                                                        |
| `yandex_cloud`  | yes; plain values      | list, get, set, delete                                                                  | A, AAAA, ANAME, CAA, CNAME, HTTPS, MX, NS, PTR, SOA (read only), SRV, SVCB, TXT                       | 60                    | —                           | master-file strings / Raw (in double quotes with `;`, `(`, `)`) for TXT values, Presentation at record level | Yandex Cloud DNS, IAM and Operation API documentation, lego. Earlier version proven live  |

Notes on the table:

- "plain values" is `Capabilities::txt_plain_only` and concerns the TXT value operations. It is
  lifted per provider when the encoding of other values is established.
- At record level, Selectel v2, Yandex Cloud, Cloudflare and Hetzner write TXT as quoted chunks of
  at most 255 octets. For Selectel v2 and Yandex Cloud the earlier record-level implementation
  establishes that form for printable ASCII without `"` and `\` (SPF, DKIM, DMARC and similar values
  of any length). A value that would need an escape is refused with `InvalidInput` until the
  provider's handling of escapes is established. Route 53 writes quoted strings with its documented
  octal escapes and `\"`; a TXT value with a backslash is not sent. Cloud.ru writes the text itself
  and refuses values that would need an escape. DigitalOcean, reg.ru, Timeweb Cloud, VK Cloud and
  Yandex 360 write plain values only (`Txt::is_plain`), as their TXT value operations do.
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
