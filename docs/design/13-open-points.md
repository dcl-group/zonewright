# zonewright design: Open points

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

### 13.4 Open points for the maintainer

The maintainer reviewed these points on 2026-11-14. Decided then: the MSRV is 1.99 (item 1); the
inspector stays without iterative resolution from the root (item 5); Timeweb Cloud writes through
the v2 calls only, and reading through the listing calls that are not deprecated is accepted (item
12); the reading of hard rule 2 for providers without a conditional write is accepted (item 14); an
explicit proxy setting is added (item 15); a write can request the provider's default TTL where the
provider has one (sections 2.2 and 3.6, `ProviderDefaultTtl`); an rrset that a web resource manages
at Selectel v2 is deleted like any other (section 11.3); `atomic_rrset_write` stays false for
nic.ru, since a replacement there is several requests even though one commit publishes it (section
11.3). Accepted as they stand: the retry rule for non-idempotent requests (item 2), the inspector's
default resolvers (item 4) and its refusal of private addresses by default (item 16), strict
settings keys, and the provider's own published client code as a source of API facts next to its
documentation. The remaining items stay open until a live check or a concrete need settles them.

Status of every point at a glance. Open points come first in the lists below, settled ones last; the
numbers never change.

| Item | Subject                                       | Status         | Provider                     |
| ---- | --------------------------------------------- | -------------- | ---------------------------- |
| 1    | MSRV 1.99                                     | Settled        | -                            |
| 2    | Rate-limit answers to non-idempotent requests | Settled        | -                            |
| 3    | Honest outcomes                               | Settled        | -                            |
| 4    | Default resolvers of the inspector            | Settled        | -                            |
| 5    | No iterative resolution from the root         | Settled        | -                            |
| 6    | TXT character-string boundaries               | Open: decision | -                            |
| 7    | SOA and apex NS not writable                  | Open: decision | -                            |
| 8    | Beget POST for credentials                    | Open: live run | Beget                        |
| 9    | Order of record-level work                    | Settled        | -                            |
| 10   | Trust anchors                                 | Settled        | -                            |
| 11   | Strict settings                               | Settled        | -                            |
| 12   | Timeweb Cloud v2 endpoints                    | Settled        | Timeweb Cloud                |
| 13   | Typed views for more types                    | Open: decision | -                            |
| 14   | Hard rule 2 outside the process               | Settled        | Selectel v2, Beget, Cloud.ru |
| 15   | Proxy                                         | Settled        | -                            |
| 16   | Private name-server addresses                 | Settled        | -                            |
| 17   | Value forms that only a live run shows        | Open: live run | several                      |
| 18   | Timeweb Cloud subdomains                      | Open: live run | Timeweb Cloud                |
| 19   | VK Cloud in-place updates                     | Open: live run | VK Cloud                     |
| 20   | Beget record level                            | Open: live run | Beget                        |
| 21   | Types listed but not written                  | Open: live run | several                      |
| 22   | nic.ru staging                                | Open: live run | nic.ru                       |
| 23   | RFC 2136 servers                              | Open: decision | RFC 2136                     |
| 24   | reg.ru INVALID_DOMAIN_NAME_FORMAT             | Open: decision | reg.ru                       |
| 25   | Default TTL where only the schema speaks      | Open: live run | Hetzner, Timeweb Cloud       |
| 26   | Yandex Cloud TXT without quotes               | Open: live run | Yandex Cloud                 |
| 27   | Yandex 360 name form                          | Open: live run | Yandex 360                   |
| 28   | Timeweb Cloud names in a subdomain listing    | Open: live run | Timeweb Cloud                |
| 29   | Beget answer for a name without records       | Open: live run | Beget                        |
| 30   | reg.ru TXT text alphabet                      | Open: live run | reg.ru                       |
| 31   | Live check of the Gcore client                | Open: live run | Gcore                        |
| 32   | Live check of the EdgeCenter client           | Open: live run | EdgeCenter                   |
| 33   | Live check of the deSEC client                | Open: live run | deSEC                        |
| 34   | Live check of the DNSimple client             | Open: live run | DNSimple                     |
| 35   | Live check of the Gandi client                | Open: live run | Gandi                        |
| 36   | Live check of the Porkbun client              | Open: live run | Porkbun                      |
| 37   | Live check of the OVHcloud client             | Open: live run | OVHcloud                     |
| 38   | Live check of the Google Cloud DNS client     | Open: live run | Google Cloud DNS             |
| 39   | Live check of the Azure DNS client            | Open: live run | Azure DNS                    |

#### Open: needs a live run

Only a run against the provider's real API can answer these. Running it is the maintainer's
initiative (`AGENTS.md`).

**8.** **Beget.** The client sends credentials in a POST body so they stay out of URLs and proxy
logs. Whether the API accepts POST for these functions is not confirmed by any source; the reference
client uses GET with credentials in the query string. It needs a live check before the client is
relied on. If POST is not accepted, the choice is between sending the password in a URL and not
supporting the provider; this design would not do the former without the maintainer's decision.

**17.** **Value forms that only a live run shows.** Where the provider's sources are silent, the
clients assume a form and refuse what they cannot send safely: names in listings (trailing dot,
relative names, `@` for the apex) at DigitalOcean, Timeweb Cloud, VK Cloud, Yandex 360 and Yandex
Cloud; names inside values without the trailing dot, read as non-canonical data at Selectel v2 and
Yandex Cloud (section 11.3); the spelling of TXT content in listings at reg.ru (a removal must
repeat it exactly), Cloud.ru, Selectel v2 (unquoted content is non-canonical at both levels) and
Yandex Cloud (how unquoted text with spaces is stored, and whether a value the client writes in
double quotes comes back as written); how escapes inside TXT values are stored at Cloudflare,
Hetzner, Route 53 and Selectel v2. Items 26 to 28 are the cases where the assumed form can make a
client refuse or misread a whole listing. The `live_<id>_record_round_trip` tests exercise the
common forms. Which providers should be run first? Selectel v2: the live run of 2026-11-15 covered
TXT values (add and remove, two values in one rrset), zone listing and the connection check, and not
reading and writing records (`PROVIDERS.md`). It bears only on the TXT part of this item, and
`PROVIDERS.md` does not record that it showed the spelling of unquoted or escaped TXT content or
names inside values; those stay open.

**18.** **Timeweb Cloud subdomains.** Does a create at a name that is not yet a subdomain make one,
and does the zone's listing show records of subdomains? If neither, `list_rrsets` can miss such a
record. The client's `PATCH` assumes omitted fields are kept. A live run settles both.

**19.** **VK Cloud in-place updates.** The documented update cannot change a TTL or the value of A,
AAAA and SRV records, so the client deletes and creates instead. If a live run shows `PUT` can,
should the client switch to in-place updates? Also unconfirmed: whether names such as
`_acme-challenge` and `*` pass the documented character rules.

**20.** **Beget record level.** A `changeRecords` that omits the A and MX records of a name deletes
them (section 11.3); record-level operations wait for how A and MX are spelled on write, which is
not documented (point 8 comes first: if POST is refused, no call works).

**21.** **Types listed but not written.** Each needs one observed answer to add: the NS value field
at Yandex 360; the value forms of CAA, DS, HTTPS and SVCB at Hetzner; the listing form of CAA,
CNAME, HTTPS, MX, NS and SRV at reg.ru; the SRV fields at Timeweb Cloud; DNAME, HTTPS and SVCB at
Selectel v2. Which of them does a consumer need? Selectel v2: the live run of 2026-11-15 did not
cover records (`PROVIDERS.md`), so DNAME, HTTPS and SVCB stay open.

**22.** **nic.ru staging.** Whether the record listing shows staged or published records, and what
commit and rollback answer on a zone without staged changes, are not documented. A live run settles
both before the client is relied on. Until the listing's view is known, the client cannot tell its
own staged changes from a foreign writer's by comparing listings, so it acts only on a mark
confirmed by a listing and otherwise refuses the zone until a person commits or rolls back (section
11.3). Knowing the view could allow a check of the staged state against what the client staged.

**25.** **The provider's default TTL where only the schema speaks.** Hetzner: `change_ttl` with
`null` is how the client turns an explicit TTL back into the zone's default; the schema allows
`null` with the description "If not set, the Zone's Default TTL is used", but no sentence says it
resets the TTL and no live run has shown it. If it does not, the provider becomes `ForNewRecords`.
Timeweb Cloud stays `ForNewRecords` until a live run shows whether a `PATCH` without `ttl` clears an
explicit TTL, which would make it `Requestable`.

**26.** **Yandex Cloud TXT without quotes.** The provider's page on record types contradicts itself:
its TXT section says the service uses the master-file format, that `;` outside double quotes starts
a comment and that spaces separate strings, while its ANAME section shows unquoted TXT values with
spaces and `;`. The client follows the TXT section at both levels (section 11.2): an unquoted string
with `;`, `(` or `)` is non-canonical data and never a value of the client's, and the value
operations write a value with these characters in double quotes. A live run shows how the API stores
and returns unquoted TXT with spaces or `;` and a quoted `"a;b"`.

**27.** **Yandex 360 name form.** If the live listing states full names without a trailing dot, the
client cannot tell them from relative names, and every operation on a name and type that has records
is `Error::Protocol` (section 11.3). A live listing that holds a record created with a known
relative name settles the form; if it is the full form, the client needs a decision on how to read
it.

**28.** **Timeweb Cloud names in a subdomain's listing.** The client reads a relative `subdomain` in
the listing of a subdomain as relative to the zone, by the wording of the `v2` schema (section
11.3). A live run settles whether it is relative to the zone or to that subdomain.

**29.** **Beget answer for a name without records.** The client accepts a name without records only
when `getData` states `records` as an empty list (an assumption: what an empty PHP array encodes to)
or as an object of placeholders (the DNS page's example). lego's test answer `getData_empty.json`,
for an `_acme-challenge` name, has no `records` key; nothing shows whether it was observed. The
client refuses that answer (`Error::Protocol`, nothing written), because the write that follows
replaces the records of the name and a missing key may be an incomplete answer. If the live API
answers a fresh name that way, adding the first TXT value at a fresh name, the usual DNS-01 case,
fails. One `getData` for a name that holds no records settles the shape; the client then accepts
exactly that shape. Item 8 comes first.

**30.** **reg.ru TXT text alphabet.** The documentation allows only alphanumeric ASCII characters in
the text of a TXT record and names the refusal `TEXT_CONTAINS_INVALID_CHARACTERS`. A DNS-01 value is
base64url text and usually contains `-` or `_`. The client sends such a value as it is and reports
the API's refusal as `Error::InvalidInput`. If the live API enforces the documented alphabet, most
DNS-01 values cannot be added at reg.ru. One add of a value with `-` and `_` settles it.

**31.** **Live check of the Gcore client.** `live_gcore_assumptions` (ignored) is the run. What only
the live API settles: a missing rrset or zone answers 404 (Gcore documents only 400); a PUT replaces
the whole record list; names in `content` carry no trailing dot; TXT `content` is one raw string;
the MX and CAA forms as dns-update and the SDK write them hold, against the specification's own MX
example; `total_amount` is the total count and the server's default page size is used; the TTL
range, and that the plan's minimum is refused with 400; what Gcore answers to a create of an
existing rrset; whether the auth word is case-sensitive (`APIKey` or `apikey`); writes to disabled
or secondary zones; that dynamic rrsets are exactly those with non-empty pickers, filters or meta,
and whether a plain rrset carries `filter_set_id`; how `*` in a path is treated.

**32.** **Live check of the EdgeCenter client.** `live_edgecenter_assumptions` (ignored) is the run.
The assumptions are those of item 31, with these of its own: the shape of the zone answer (wrapped
or flat). The `409` EdgeCenter documents for a create of an existing rrset is handled as `Conflict`.

**33.** **Live check of the deSEC client.** `desec_live_assumptions` (ignored; environment
`ZONEWRIGHT_LIVE_DESEC_*`; it paces writes 4.1 s apart, about 40 writes, run it at most once an
hour) is the run. Settled by it: the content form of CAA, DNAME, HTTPS, PTR, SRV, SSHFP and SVCB,
for which only the general presentation-format rule is documented (the API's canonical text must
read back equal to the crate's; HTTPS and SVCB parameter spelling and long hex are the likeliest to
differ; the mock canonicalizes only A, AAAA, names, MX, SRV, CAA and TXT); TXT values with a space,
`"`, `\`, non-ASCII bytes and over 255 octets; a wildcard subname percent-encoded in a path; a
refused create of an existing rrset as `400`; and, with a scoped token, that a policy-restricted
token can list domains. Not covered by any step: what a `PATCH` of a missing rrset answers (`404`
assumed, taken as `Conflict`; a manual request settles it), the answers to an invalid token and to
an `allowed_subnets` violation.

**34.** **Live check of the DNSimple client.** `dnsimple_live_assumptions` (ignored) is the run.
Settled by it: the TTL range 60 to 259200, both bounds from the web editor (the API documents only a
minimum of 0; the test writes 60); that `per_page=100` is accepted on `/zones` and
`/zones/:zone/records`; that `total_entries` counts the items under the `type` filter; host names in
`content` as absolute names, written without the dot; TXT `content` as answered; SRV `content` as
`<weight> <port> <target>` and CAA `content` as `flags tag "value"` (dns-update and the support
article); that a record created without `regions` answers `["global"]` or `[]`; that a PATCH with
only `ttl` or only `content` keeps the other members. Not covered: the `404` answers of update and
delete, and the status a scoped token without write permission gets; whether a scoped token can call
`whoami`; records of a secondary or inactive zone; the quota answer (`X-RateLimit-Reset`, no
`Retry-After`; it needs 2400 requests in an hour).

**35.** **Live check of the Gandi client.** `gandi_live_assumptions` (ignored;
`ZONEWRIGHT_LIVE_GANDI_PREFIX`) is the run. Settled by it: a `PATCH` with `rrset_ttl` set to the
rrset's TTL leaves it so and answers `200` with the rrset, and removing the last value answers `204`
and leaves no rrset; `404` for a domain that is not the account's (not 403); names in MX, NS and SRV
values come back with the trailing dot (the single-rrset example shows one without it: if the API
strips it, every such value reads as non-canonical); a quoted TXT value with a space is returned as
written; `*` in a path (`%2A`) addresses a wildcard owner; the default page size, the meaning of
`Total-Count` and an empty page past the last; a create racing another create gives `Created`,
`Replaced` or `Conflict`, never `Rejected`. Not covered: whether record routes need `sharing_id` for
another organization's domain, which token scopes are needed, the status of a refused body and of
rate limiting, what the `PATCH` does with a duplicate add or an absent remove (the client fails
safely under each reading the mock offers).

**36.** **Live check of the Porkbun client.** `porkbun_live_assumptions` (ignored) is the run.
Settled by it: the `GET` reads take the keys as the headers `X-API-Key` and `X-Secret-API-Key` and
`/ping` answers `credentialsValid: true`; `/dns/retrieve` states names fully qualified, for the apex
and for a wildcard as well; the `content` forms the client writes read back as written (host names
without the dot, SRV `weight port target`, CAA `flags tag "value"`, TLSA
`usage selector matching hex`, TXT the value itself; CAA and TLSA rest on dns-update's code alone);
a TTL of 600 is accepted and an edit of the whole record with a new `ttl` changes only the TTL; a
delete of a record already gone is answered `INVALID_RECORD_ID`. Not exercised: that a TTL below an
account's minimum is refused rather than raised, the real maximum TTL, and that only the last page
of `/domain/listAll` holds fewer than 1000 domains.

**37.** **Live check of the OVHcloud client.** `ovh_live_assumptions` (ignored) is the run; the
consumer key needs GET, POST, PUT and DELETE on `/domain/zone/*` (inferred from the endpoints; lego
names only POST and DELETE). Settled by it: the host `api.eu.ovhcloud.com` serves `/domain/zone`
(the CA and US hosts are not checked); the signature over the URL as sent, with the percent-encoded
query, is accepted; the `subDomain` filter never leaves out a record whose name equals it (names
with `_` and `*` included) and the `fieldType` filter matches the type; `subDomain` of a record is
answered relative to the zone, `""` or `null` at the apex; TXT `target` quoted or as the value reads
the same; host names in `target` are absolute, written with the dot; CAA as
`0 issue "letsencrypt.org"` and TLSA as `3 1 1 <hex>` are accepted and read back equal; TTL 60 is
accepted and a PUT with `target`, `ttl` and `subDomain` changes the TTL; a refresh of a zone without
staged changes succeeds. Not covered: the TTL upper bound 86400, what `ttl` `0` and `null` mean on
read, whether a PUT without `ttl` leaves the TTL, the status and `class` of an unknown zone and of
the signature and key failures, how long a refreshed zone takes to be served (60 s assumed), and
when a new record becomes readable (the client waits 7 s at most).

**38.** **Live check of the Google Cloud DNS client.** `google_cloud_live_assumptions` and the two
`live_google_cloud_*` tests (ignored) are the run. Settled by it: a missing managed zone is answered
`404` by `managedZones.get` (and by `rrsets.list`, which is not probed live); `rrsets.list` with
`name` and `type` answers a missing rrset with an empty list; a failed deletion match and an
addition of an existing rrset are refused synchronously with some 4xx (the client re-reads whatever
the status; the test races two clients and prints the outcomes); `changes.create` answers `pending`
or `done` and `changes.get` answers it by `id`; a plain TXT value written quoted reads back to the
same value, also with spaces and 300 characters; a managed zone without `visibility` is public
unless it has `privateVisibilityConfig` (lego's reading); TTL range 1 to 2147483647 (not probed
beyond 120). Not live steps: the conservative refusals (values needing backslash escapes, TXT rrdata
over 1000 characters, rrsets with `signatureRrdatas`, zones with forwarding, peering, reverse-lookup
or service-directory configuration, a change with an unknown status).

**39.** **Live check of the Azure DNS client.** `azure_dns_live_assumptions` (ignored) is the run.
Settled by it: the scope `https://management.azure.com//.default` is accepted for the client
credentials grant; `GET` of a missing record set is `404` (lego relies on it) and of a zone the
resource group does not hold is `404` (not documented); a space in a TXT string stands for itself,
and 300 octets split into 255 and 45 read back as one value; names in CNAME, MX, SRV, NS and PTR
records written without the trailing dot read back as the same absolute names, and CAA values
round-trip; a wildcard name percent-encoded in a path is decoded; `If-Match` and `If-None-Match: *`
are enforced (two clients adding values to one name at once never lose a value; the losers end in
`Conflict`); the listing of a zone holds every set created. Not covered: the status and code of a
failed condition (the client does not depend on them); whether a `nextLink`'s `$skipToken` works
with the client's own path and `api-version` (needs a zone with over 100 record sets or a resource
group with over 100 zones); whether the service returns TXT strings with RFC 1035 escapes it applied
on write; whether a record set can have an empty record list; national clouds (the China identity
host is `login.partner.microsoftonline.cn` on the national-cloud page and `login.chinacloudapi.cn`
in the Go SDK, and the scope for the US Government and China Resource Manager is not stated; both
are settings, `login_url` and `scope`).

#### Open: needs the maintainer's decision

Questions of policy or scope. Item 23 also lacks a run against a server implementation.

**6.** **TXT character-string boundaries are not preserved.** Records whose meaning depends on the
boundaries (DNS-SD attribute lists) cannot be written faithfully through this crate.

**7.** **SOA and apex NS are not writable** (section 3.4). Say if a consumer needs either.

**13.** **Typed views for more record types** (SSHFP, SOA) exist as canonical forms only. Typed
structs are added on request.

**23.** **RFC 2136 servers.** The messages and the TSIG computation are verified against the mock,
and the mock is cross-checked against BIND's `nsupdate` and `dig` (9.10.6, on 2026-11-15) by ignored
tests in `tests/rfc2136_interop.rs`, which need those tools and touch loopback only: updates,
prerequisites, TSIG refusals and the TXT forms agree in both directions. The cross-check found three
defects, all in the mock (compressed names in request RDATA, no SOA in negative answers, no UDP) and
none in the client. No server implementation (BIND's `named`, Knot, PowerDNS) has been tried. How a
server implementation signs a BADTIME answer has not been observed; the client accepts it only when
its MAC verifies against the request MAC (RFC 8945 section 5.2.3). A synthesized wildcard answer at
a name that does not exist looks like a value there, so an add can report `AlreadyPresent` wrongly;
without DNSSEC this cannot be detected. Is that limitation acceptable as documented?

**24.** **reg.ru `INVALID_DOMAIN_NAME_FORMAT`** is classed as "zone not found" by assumption (the
documentation does not say when it is returned). Keep, or report it as `Rejected`?

#### Settled

Decided by the maintainer or settled in the code.

**1.** **MSRV: decided by the maintainer on 2026-11-14 — 1.99** (section 13.1).

**2.** **Rate-limit answers to non-idempotent requests.** The earlier TXT-only implementation
retried any request after a 429, on the grounds that a rate-limited request was not executed.
`AGENTS.md` says only idempotent requests are retried automatically, and this design follows it:
such a request returns `RateLimited` and the caller repeats the operation. Allowing the retry is a
one-line change in the transport if the rule is meant to permit it. The same reading is applied to a
401 for a cached token: an idempotent request is repeated with a new token, a non-idempotent one is
not and returns a retryable error (section 5.3). The earlier implementation repeated both. Settled:
the maintainer accepted the rule as it stands (introduction); the transport marks requests
idempotent or not (`src/http/request.rs`).

**3.** **Honest outcomes.** Settled in the code: acme-dns removal returns `Unsupported` and every
acme-dns add `Accepted`; blind RFC 2136 writes return `Accepted`; `check` reports in
`credentials_verified` whether credentials were actually tested. Applications ported from the
earlier implementation handle these three changes. Settled: in the code (acme-dns, RFC 2136 and
`CheckReport::credentials_verified`, `src/provider.rs`).

**4.** **Default resolvers of the inspector.** Cloudflare, Google and Quad9 by default means the
zone names an application inspects are sent to those services unless it configures others. The
alternative is no default and a required list. Settled: the maintainer accepted the defaults
(introduction); the defaults are in `src/inspector/config.rs`.

**5.** **No iterative resolution from the root: decided by the maintainer on 2026-11-14 — not
added.** One earlier implementation has it, with detection of intercepted port 53 and a fallback
mode. This design replaces it by resolver-based discovery and static lists (section 8.1). Should
"what the internet sees, independent of any resolver" become a requirement, it is an addition to
`NsDiscovery`, not a redesign.

**9.** **Order of record-level work.** Settled in the code: every provider whose API allows it has
record-level operations (section 11.2). What remains is Beget, point 20.

**10.** **Trust anchors.** Settled (decided by the maintainer on 2026-11-16, section 5.1): the
application chooses the set with `ContextOptions::trust_roots`. The default is Mozilla's root
certificates compiled into the crate; the operating system's store is used only with the
`platform-verifier` feature and `TrustRoots::Platform`; the Russian Trusted Root CA is compiled in
and trusted only with `ContextOptions::russian_trusted_root`; the certificates of
`ContextOptions::extra_root_certificates` are trusted in addition.

**11.** **Strict settings.** Settled in the code: every `…Config` refuses unknown keys
(`deny_unknown_fields`), so an application strips its own keys before calling the crate.

**12.** **Timeweb Cloud: decided by the maintainer on 2026-11-14 — the v2 endpoints only.** Records
are written with v2. The API has no v2 listing, so reads use the v1 listing calls, which are not
marked deprecated (section 11.3); say if that is not acceptable. The v1 writes, which the provider's
API description marks as deprecated, are not used: lego's issue tracker (issue 3119, 2026-05-22)
shows the v1 create refusing `_acme-challenge` names with `bad_subdomain_name` while v2 accepted
them.

**14.** **Hard rule 2 against writers outside the process: accepted by the maintainer on
2026-11-14.** At Selectel v2, Beget and Cloud.ru the API offers neither a per-value call nor a
conditional write, so a TXT value operation cannot rule out overwriting a value that another
process, or a person in the control panel, adds between the client's read and its write; at Beget
the same holds for an A or MX record added at the name in that window. Inside one process the
per-name lock closes the gap; outside it nothing can. The capability `txt_values == ReadThenWrite`
states this. The accepted reading of hard rule 2 is: guaranteed within a process, best effort beyond
it where the API gives no means.

**15.** **Proxy: decided by the maintainer on 2026-11-14 — an explicit setting; implemented.**
`ContextOptions::proxy` takes an `HttpProxy` (URL, optional user name, password as `SecretString`,
exclusions). Supported: `http://` and `https://` proxies with `CONNECT` tunnels for HTTPS providers
and Basic proxy authentication; SOCKS5 (`socks5://`, `socks5h://`) with username/password
authentication; a list of hosts reached directly. Environment variables stay ignored (section 5.1).
Decided by the maintainer on 2026-11-15: refused proxy credentials are `Error::ProxyAuth`, a kind of
their own; an `http://` proxy on another host stays allowed, with the unencrypted proxy credentials
described in the documentation; SOCKS5 and the exclusion list are added. A refused certificate of an
`https://` proxy is `Error::Config`; a proxy that cannot be reached, stalls or refuses the tunnel
gives `Error::Transient` (section 5.3).

**16.** **Private name-server addresses are refused by default** in the inspector. Deployments whose
authoritative servers are internal must set `allow_private_addresses` or use `NsDiscovery::Static`.
The earlier implementation accepted them by default. Settled: the maintainer accepted the refusal by
default (introduction); `allow_private_addresses` is `false` by default in
`src/inspector/config.rs`.
