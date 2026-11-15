# zonewright design: Inspector

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 8. Inspector

Optional feature `inspector`. It observes DNS; it has no connection to provider clients and holds no
secrets.

### 8.1 Approach

Two earlier implementations exist. One discovers the name servers of a zone through public recursive
resolvers and queries each server through a high-level resolver library. The other resolves
iteratively from the root with its own UDP and TCP transport over a DNS message codec, and accepts
only authoritative answers.

This design takes the query layer of the second and the discovery of the first:

- Queries are sent by the crate's own small transport using `hickory-proto` only for encoding and
  decoding messages. The transport is what makes per-server observation exact: it sees the AA flag,
  the response code and truncation, so "this server is not authoritative for the zone", "refused",
  "no such name" and "no data" are different answers instead of an error string to pattern-match. It
  also removes the resolver library and its dependency tree (a cache crate, a system configuration
  reader) from the build, which lowers the crate's MSRV to that of the core (section 13.1), and ties
  an application that pins or vendors `hickory-*` to one crate instead of three.
- The name servers of a zone are found by asking configured recursive resolvers for the zone's NS
  set and the servers' addresses, or are given by the application. Iterative descent from the root
  is not implemented. It cannot see zones that exist only inside an organization, needs a maintained
  list of root servers and a fallback for networks that intercept port 53, and is several times the
  code; and the caller of this API already knows the zone, which is the question descent answers.
  Its one advantage, independence from a resolver's cache after a re-delegation, is covered by
  letting the application pass the server list (`NsDiscovery::Static`) and by not caching failures.

No `hickory` type appears in a public signature. Record values are produced by this crate's
normalization, never by a dependency's `Display`.

### 8.2 Public API

```rust
// zonewright::inspector — compiled with feature "inspector"

pub struct Inspector { /* private */ }

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct InspectorConfig {
    /// Recursive resolvers, tried in order. Default: PUBLIC_RESOLVERS. At most 16, each once.
    pub resolvers: Vec<std::net::SocketAddr>,
    pub discovery: NsDiscovery,
    /// Address families of discovered name servers to query. Default: V4.
    pub ip_families: IpFamilies,
    /// Limit for one question to one server, including a TCP retry. Default 3 s.
    pub query_timeout: std::time::Duration,
    /// How long a discovered server list is reused. Default 300 s. Zero disables the cache.
    pub ns_cache_ttl: std::time::Duration,
    /// Upper bound on the name servers (addresses) of one zone. Default 32.
    pub max_servers: usize,
    /// Limit for the whole discovery of one zone's servers. Default 10 s.
    pub discovery_timeout: std::time::Duration,
    /// Ask discovered name servers at private addresses (section 8.3). Default false.
    pub allow_private_addresses: bool,
    /// Read an answer without AA from a server of a static list by its content (section 8.4).
    /// Default false.
    pub accept_static_without_aa: bool,
    /// Expectations or questions per call. Default 32; 1 to QUESTIONS_CEILING.
    pub max_questions: usize,
    /// Asked servers × questions of one round (in `wait`, identical questions count once).
    /// Default 1024; from `max_questions` to QUESTIONS_PER_ROUND_CEILING.
    pub max_questions_per_round: usize,
}
impl InspectorConfig {
    pub const QUESTIONS_CEILING: usize = 256;
    pub const QUESTIONS_PER_ROUND_CEILING: usize = 8192;
    pub const QUESTIONS_IN_FLIGHT: usize = 128;
}
impl Default for InspectorConfig {}

/// 1.1.1.1:53, 8.8.8.8:53, 9.9.9.9:53.
pub const PUBLIC_RESOLVERS: &[std::net::SocketAddr];

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum NsDiscovery {
    /// Ask the resolvers for the zone's NS rrset and the servers' addresses.
    Recursive,
    /// Use exactly these servers for every zone.
    Static(Vec<NameServer>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpFamilies { V4, V6, Both }

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NameServer {
    /// The NS name, when known.
    pub name: Option<TargetName>,
    /// For a server that is not asked: the refused address, or None (no address in the families).
    pub addr: Option<std::net::SocketAddr>,
    /// Why the server is not asked; None for a server that is asked.
    pub not_asked: Option<NotAsked>,
}
impl NameServer {
    /// A server that is asked.
    pub fn new(name: Option<TargetName>, addr: std::net::SocketAddr) -> NameServer;
    /// `addr` when the server is asked, None otherwise.
    pub fn query_addr(&self) -> Option<std::net::SocketAddr>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NotAsked {
    /// The resolvers answered NODATA or NXDOMAIN for every configured family.
    NoAddress,
    AddressRefused(AddressRefusal),
}

/// Why the address policy refuses an address (section 8.3, step 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AddressRefusal {
    Unspecified, Loopback, LinkLocal, Multicast, Reserved, ProtocolAssignment, Relay6to4,
    Benchmarking, NotGlobalUnicast, Ipv4Mapped, Ipv4Compatible,
    // lifted by allow_private_addresses:
    Private, SharedAddressSpace, UniqueLocal, SiteLocal, LocalTranslation,
}
// NotAsked and AddressRefusal have `as_str` and `Display`.

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question { pub name: DomainName, pub rtype: RecordType }

/// What one server said about one question.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Answer {
    /// The rrset, normalized. `ttl` is the smallest TTL among its records.
    Records { ttl: Ttl, records: Vec<RecordData> },
    /// The name exists, there is no rrset of this type.
    NoData,
    NxDomain,
    /// The name is a CNAME; the server did not answer the question itself.
    Cname(TargetName),
    Refused,
    ServFail,
    /// An answer without the AA flag, or a referral, from a server queried as authoritative.
    NotAuthoritative,
    Timeout,
    /// Anything else: another response code, a malformed message, a network error.
    Failed(String),
    /// The server was not asked (only in `observe` and `wait` results).
    NotAsked(NotAsked),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Condition {
    /// The rrset contains all of these values; other values may be present.
    Present(Vec<RecordData>),
    /// The rrset is exactly this set. An empty list means: there is no such rrset.
    Exact(Vec<RecordData>),
    /// The rrset contains none of these values, or does not exist.
    Absent(Vec<RecordData>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expectation { pub question: Question, pub condition: Condition }

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct WaitOptions {
    /// Total time to wait. At least one round always runs.
    pub timeout: std::time::Duration,
    /// Pause between rounds. Default 5 s; at least MIN_INTERVAL.
    pub interval: std::time::Duration,
    /// The pause varies by up to this percentage either way. Default 20; at most 50.
    pub jitter_percent: u8,
    /// Leave the servers that are not asked out of "every server agrees". Default false.
    pub ignore_unaskable_name_servers: bool,
}
impl WaitOptions {
    /// 1 s.
    pub const MIN_INTERVAL: std::time::Duration;
    pub fn new(timeout: std::time::Duration) -> WaitOptions;
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ServerReport {
    pub server: NameServer,
    /// All expectations held at this server in the last round. Always false when not asked.
    pub satisfied: bool,
    /// The last round's answers, one per expectation, in the order given.
    pub answers: Vec<Answer>,
    /// When this server first satisfied all expectations, from the start of the wait.
    pub first_satisfied_after: Option<std::time::Duration>,
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Report {
    pub servers: Vec<ServerReport>,
    pub rounds: u32,
    pub elapsed: std::time::Duration,
    /// Servers left out of the condition; 0 unless `ignore_unaskable_name_servers` is set.
    pub unaskable_ignored: usize,
}

#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InspectorError {
    #[error("invalid inspector configuration: {detail}")]
    Config { detail: String },
    #[error("invalid request: {detail}")]
    InvalidInput { detail: String },
    /// The complete server list could not be established; transient, nothing cached.
    #[error("no usable name servers for zone {zone}: {detail}")]
    NoNameServers { zone: DomainName, detail: String },
    #[error("zone {zone} has {count} name server addresses, more than the configured limit")]
    TooManyNameServers { zone: DomainName, count: usize },
    #[error("expectations not met within the timeout")]
    Timeout { report: Report },
}

impl Inspector {
    pub fn new(config: InspectorConfig) -> Result<Inspector, InspectorError>;

    /// The authoritative servers of `zone`, by the configured discovery, those not asked included.
    pub async fn name_servers(&self, zone: &DomainName) -> Result<Vec<NameServer>, InspectorError>;

    /// One question to one server, recursion not desired. No address policy applies.
    pub async fn query_server(&self, server: std::net::SocketAddr, question: &Question) -> Answer;

    /// One question to every configured resolver, recursion desired.
    pub async fn query_recursive(&self, question: &Question) -> Vec<(std::net::SocketAddr, Answer)>;

    /// One round: every question at every name server of the zone.
    pub async fn observe(
        &self,
        zone: &DomainName,
        questions: &[Question],
    ) -> Result<Vec<(NameServer, Vec<Answer>)>, InspectorError>;

    /// Polls until every name server of the zone satisfies every expectation in the same round.
    pub async fn wait(
        &self,
        zone: &DomainName,
        expectations: &[Expectation],
        options: &WaitOptions,
    ) -> Result<Report, InspectorError>;
}

impl crate::dns01::CnameLookup for Inspector {}
```

All durations are `std::time::Duration`. Strings in `Answer::Failed` and in the error details are at
most 512 bytes without control characters.

A server that is not asked is a row, not an omission. `observe` gives it an `Answer::NotAsked` per
question and sends nothing to it; `wait` gives it a `ServerReport` whose answers are
`Answer::NotAsked`, whose `satisfied` is false and whose `first_satisfied_after` is `None`, so
"every server agrees" cannot hold while it exists: the wait runs to its timeout and the report in
`InspectorError::Timeout` says why. That is the default. With
`WaitOptions::ignore_unaskable_name_servers` set, the servers that are not asked are left out of the
condition (section 8.6); their rows stay in the report unchanged, and `Report::unaskable_ignored`
counts them (it is 0 when the option is off). `observe` gives no verdict, so the option does not
apply to it. `query_server` takes a socket address, not a `NameServer`; a server that is not asked
has no `query_addr` to pass, and an address given to `query_server` is the caller's choice, like a
static list.

### 8.3 Name-server discovery

`NsDiscovery::Recursive`, for a zone:

1. Ask each resolver in order, one at a time, for `zone NS` with recursion desired. Use the first
   answer that contains at least one NS record whose owner is the zone itself; records with any
   other owner are ignored. A negative answer, an empty answer or a failure moves on to the next
   resolver. If no resolver yields a set: `NoNameServers`. There is no walking up the labels: the
   name given must be the zone.
2. If the set has more than 16 distinct NS names: `TooManyNameServers`, before any address lookup.
3. For each NS name, ask for `A` and/or `AAAA` according to `ip_families`, taking the answers of the
   first resolver that answers; a negative answer (NODATA, NXDOMAIN) is an answer. At most 8 of
   these lookups run at a time. At most 8 addresses per name and family are used; more is
   `TooManyNameServers`. When no resolver answers for a name and family (a lookup failure, as
   opposed to an answer that there is no address), the addresses of that name are not established:
   `NoNameServers`, naming the NS name. An NS value or an address that cannot be read makes that
   resolver's NS answer unusable (step 1) or fails the discovery with `NoNameServers` (step 3);
   nothing is skipped.
4. Apply the address policy. It follows the IANA special-purpose address registries for IPv4 and
   IPv6 (both as updated 2025-10-09) and the IPv6 address space registry; the reason is an
   `AddressRefusal`:
   - Always refused: unspecified (`0.0.0.0/8`, `::`), loopback, link-local, multicast, `240.0.0.0/4`
     with the limited broadcast address, `192.0.0.0/24` (IETF protocol assignments) except
     `192.0.0.9` (PCP anycast, RFC 7723) and `192.0.0.10` (TURN anycast, RFC 8155), which the
     registry marks globally reachable, `192.88.99.0/24` (deprecated 6to4 relay anycast),
     `198.18.0.0/15` (benchmarking), IPv4-mapped `::ffff:0:0/96` and IPv4-compatible `::/96`
     whatever IPv4 address they carry, every other IPv6 address outside the global unicast space
     `2000::/3` except the two translation prefixes below (this covers `100::/64`, `100:0:0:1::/64`,
     `5f00::/16`), and the parts of `2001::/23` the registry does not mark globally reachable
     (`2001:2::/48`, `2001:10::/28` and the unassigned rest; `2001:1::1` to `::3`, `2001:3::/32`,
     `2001:4:112::/48`, `2001:20::/28` and `2001:30::/28` are accepted). The IPv4-mapped block is
     marked neither a destination nor globally reachable: an AAAA record holding one names an IPv4
     host as if it were an IPv6 server, which a dual-stack socket would reach over IPv4 outside the
     configured families. The IPv4-compatible form is deprecated (RFC 4291 section 2.5.5.1). Both
     are refused also for a global IPv4 address.
   - Refused unless `allow_private_addresses` is set: private use (RFC 1918), shared (RFC 6598),
     unique-local (RFC 4193), the deprecated site-local `fec0::/10`, and the local-use translation
     prefix `64:ff9b:1::/48` (RFC 8215), which the registry marks forwardable but not globally
     reachable.
   - IPv6 forms that route to an embedded IPv4 address get the IPv4 rules for that address: the
     NAT64 well-known prefix `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/32` (the server
     address and the de-obfuscated client address), and an ISATAP interface identifier
     (`0:5efe:a.b.c.d`; the universal/local and group bits of its first octet are free, so
     `100:5efe:`, `200:5efe:` and `300:5efe:` count too; RFC 5214 section 6.1) under any global
     prefix.
   - Accepted on purpose, although the registries mark them not globally reachable: the
     documentation blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`,
     `3fff::/20`). They are routed nowhere, so a query to them times out and satisfies nothing; they
     cannot point the process at a host of its own network; and test fixtures use them.

   The default is to refuse private addresses: the answers of a discovered server end up in reports,
   and a zone's NS records should not be able to point this process at hosts inside its own network.
   A deployment whose authoritative servers are internal sets the option or uses a static list (open
   point 16).

5. Each usable address becomes a `NameServer` on port 53; an address seen under an earlier NS name
   is not repeated. A server that cannot be asked is kept as a `NameServer` with `not_asked` set,
   because leaving it out would let a wait succeed without it: each refused address is one entry
   with its address and `NotAsked::AddressRefused(reason)`, also when the same name has other,
   usable addresses; an NS name for which the resolvers answered that it has no address in the
   configured families (NODATA or NXDOMAIN for every family asked) is one entry without an address
   and with `NotAsked::NoAddress`. Each such entry is logged at `WARN`. This holds also when no
   server of the zone can be asked. Another `ip_families` choice, the option or a static list makes
   such a server askable. More than `max_servers` entries, those not asked included:
   `TooManyNameServers`. The list is never truncated, because success means "every server", and a
   silently shortened list would turn that into "some servers".
6. Steps 1 to 5 together are bounded by `discovery_timeout`; when it passes, the result is
   `NoNameServers` with a detail that says so. With three resolvers and both families that is at
   most 3 + 16 × 2 × 3 questions, each bounded by `query_timeout` as well (the default `ip_families`
   is `V4`, which halves the address lookups).
7. The result is cached per zone for `ns_cache_ttl`, at most 256 zones (the oldest entry is
   evicted). Only a complete list is cached, entries that are not asked included; failures, and
   whatever a failed discovery found before it failed, are not. Concurrent discoveries of one zone
   are not merged; each is bounded on its own.

`NsDiscovery::Static` uses the given list as is, without the address filter and without the cache:
the application chose those addresses. It serves hidden primaries, split-horizon setups and tests.
More entries than `max_servers`, or an entry that is not asked (no address, or `not_asked` set), is
`InspectorError::Config`.

### 8.4 Queries

- UDP first, with EDNS and a 1232-octet payload size. A truncated answer is repeated over TCP, also
  when the truncated UDP message cannot be decoded (a datagram with the query's ID and the QR and TC
  flags). A TCP answer with the TC flag is a failed query: it is incomplete and there is no larger
  transport. A `FORMERR` answer to a query with EDNS is repeated once without EDNS.
- Every question uses a new UDP socket, bound to the wildcard address with a port chosen by the
  operating system and connected to the server, and closed when the question is answered or times
  out. Sockets are not pooled or reused, so neither a source port nor an ID is shared between
  questions. A TCP retry likewise opens its own connection.
- Message IDs are the ones `hickory-proto` assigns to a new query: 16 bits from the `rand` crate's
  thread-local generator, a cryptographically strong generator seeded from the operating system.
  `fastrand` is not used for anything an off-path attacker would have to guess.
- A UDP datagram is accepted only from the queried address and only if its ID and question match the
  query (name compared case-insensitively); others are ignored until the timeout. A decodable answer
  with the query's ID and the TC flag but without a question section is accepted too: over UDP it
  only sends the question to TCP, where the answer is checked in full.
- `query_timeout` bounds the whole question to one server, all of the above included.
- To a name server: recursion not desired. The answer is classified as follows. Response code
  REFUSED or SERVFAIL: the variant of that name. Any other code than NOERROR and NXDOMAIN: `Failed`.
  AA not set: `NotAuthoritative`. Records of the asked type owned by the asked name: `Records`, or
  `Failed` when the response code is NXDOMAIN (a contradiction that must not read as absence). No
  such records but a CNAME owned by the asked name (and the question was not for CNAME): `Cname`,
  whatever the response code (section 8.9). Otherwise `NxDomain` for NXDOMAIN and `NoData` for
  NOERROR.
- AA without the flag, for a static list only (`accept_static_without_aa`, off by default; asked for
  by an application whose test DNS server answers correctly but never sets AA). In a round over
  `NsDiscovery::Static` an answer without AA is then classified by its content as above, with one
  exception: a referral — an empty answer section with NS and no SOA in the authority section —
  stays `NotAuthoritative` whatever the response code, so that a delegation never reads as "no such
  data" (RFC 2308, sections 2.1 and 2.2.1). With the option on, a recursive resolver put into the
  static list is believed; that is the application's choice, like the list itself. Discovered
  servers always need AA, and so does `query_server`, whatever the address.
- To a resolver: recursion desired; AA is not required. A CNAME chain inside the answer is followed
  within the answer (at most 8 links, loops rejected) to the records of the asked type.
- The inspector does not validate DNSSEC and does not use DoT or DoH.

### 8.5 Values

Answer records are converted to `RecordData` through the typed constructors and `from_wire` of
section 4: fields are taken from the decoded message for the types whose RDATA can contain
compressed names (NS, CNAME, PTR, MX, SOA, SRV), and the raw RDATA goes through
`RecordData::from_wire` for everything else, including types the codec does not know. TXT
character-strings are concatenated as bytes; nothing is lossily converted to UTF-8. Names inside
RDATA become `TargetName` values, for which every valid wire name has a text form, so an unusual
target does not fail. Only RDATA that is malformed for its type makes the answer `Failed`.

The result compares directly with what a provider client returns for the same record, which is the
point of section 4.

### 8.6 Expectations and the wait loop

An expectation holds at a server according to its answer:

| Condition                  | Holds when the answer is                                         |
| -------------------------- | ---------------------------------------------------------------- |
| `Present(values)`          | `Records` containing every value                                 |
| `Exact(values)`, non-empty | `Records` whose set equals `values`                              |
| `Exact([])`                | `NoData` or `NxDomain`                                           |
| `Absent(values)`           | `NoData`, `NxDomain`, or `Records` containing none of the values |

`Cname`, `Refused`, `ServFail`, `NotAuthoritative`, `Timeout`, `Failed` and `NotAsked` satisfy
nothing. In particular an unreachable server never counts as "the value is absent", and it is not
skipped: a resolver elsewhere may ask exactly that server. Expected values must be canonical; a
non-canonical value is `InvalidInput`. `Present` and `Absent` need at least one value.

`wait`:

1. Validate: 1 to `max_questions` expectations, every name within the zone, `interval` at least
   `WaitOptions::MIN_INTERVAL` (1 s; with the largest jitter the shortest pause is 500 ms; a round
   can ask up to `max_questions_per_round` questions of servers the application does not run),
   jitter at most 50, the expected values valid. All of this happens before discovery, so an invalid
   request sends nothing. Discover the servers.
2. A round asks every server that is asked every question, at most 128 questions at a time (each
   bounded by `query_timeout`, each holding one socket), evaluates the expectations and builds the
   report, with a row for every server that is not asked (section 8.2).
3. If every server satisfies every expectation in this round: `Ok(report)`. With
   `ignore_unaskable_name_servers`, "every server" is every server that is asked, and at least one
   server must be asked: a zone none of whose servers can be asked never succeeds and runs to the
   timeout. Only a server that is not asked for a reason known before any query (`NotAsked`) is left
   out; a server that was asked and timed out, refused, failed or disagreed always counts. A success
   with servers left out is logged at `WARN` with their number. The option exists for zones such as
   one with an IPv6-only name server observed over IPv4; it is off by default because a resolver
   elsewhere may ask exactly the server that was left out.
4. If the time since the start is at least `timeout`: `Err(Timeout { report })`.
5. Sleep `interval`, varied uniformly by ±`jitter_percent`, but not past the deadline; go to 2. If
   less time is left than the shortest pause the jitter allows (`interval` less `jitter_percent`),
   the pause is not cut below it: no further round runs, and the result is `Err(Timeout { report })`
   with this round's report.

Properties: at least one round runs even with a zero timeout; no pause is shorter than `interval`
less the jitter, so never shorter than 500 ms; the last round starts no later than `timeout` after
the start (possibly up to one shortest pause earlier), so the call returns within `timeout` plus one
round (at most `ceil(servers × questions / 128) × query_timeout`) plus discovery; every round asks
every server again, so a server that had the value and lost it is seen (the earlier implementation
stopped asking a server once it was satisfied, which is acceptable only for a value that is about to
be consumed). A wait for several zones is several calls, which the application may run concurrently.

### 8.7 CNAME lookup by quorum

`Inspector` implements `dns01::CnameLookup` over the resolvers: it asks them in order for the CNAME
of the name and stops when two agree (or when all have answered, if fewer than two are configured).
A resolver address may appear only once in the configuration (`Config` error otherwise), so one
resolver cannot make a quorum alone. A negative answer is a vote for "no CNAME". A CNAME record
counts only if its owner is the asked name. Two different votes are an error at once; timeouts and
failures are not votes; running out of resolvers before two agree is an error that says how many
answered. One resolver's cache or one tampered answer therefore cannot redirect a challenge on its
own. A target that is not a valid `DomainName` cannot be an owner name the challenge could be
written at; it is reported as a lookup error.

### 8.8 Bounds

| Bound                                       | Value                                                                                     |
| ------------------------------------------- | ----------------------------------------------------------------------------------------- |
| NS names of one zone                        | 16                                                                                        |
| Addresses per NS name and family            | 8                                                                                         |
| Servers per zone, those not asked included  | `max_servers`, default 32                                                                 |
| Time for one discovery                      | `discovery_timeout`, default 10 s                                                         |
| Concurrent address lookups during discovery | 8                                                                                         |
| Expectations or questions per call          | `max_questions`, default 32, at most 256                                                  |
| Questions per round                         | asked servers × questions ≤ `max_questions_per_round`, default 1024, at most 8192         |
| Network exchanges per round                 | at most 3 × `max_questions_per_round`                                                     |
| Time for one round                          | at most `ceil(max_questions_per_round / 128) × query_timeout`; 24 s with the defaults     |
| Questions of a round in flight at once      | 128                                                                                       |
| Pause between rounds                        | `interval` ≥ 1 s, ± up to 50 % jitter                                                     |
| Network exchanges per question              | 3 (UDP, UDP without EDNS, TCP)                                                            |
| Sockets per question                        | a new UDP socket per UDP exchange (at most 2), one new TCP connection, one open at a time |
| Time per question                           | `query_timeout`, default 3 s                                                              |
| CNAME links (in an answer, in a chain)      | 8, with loop detection                                                                    |
| Message size                                | 4096 octets UDP, 65535 TCP                                                                |
| Cached zones                                | 256                                                                                       |

The two question limits are settings (decided by the maintainer on 2026-11-15, for an application
that waits for about a hundred names of one zone in one call). The per-round limit is a setting of
its own rather than `max_servers × max_questions`, so that every earlier configuration behaves as
before, also one with `max_servers` above 32; its ceiling is 256 × 32. The number of questions in
flight stays 128, so a larger round takes longer rather than opening more sockets. The limits bound
the load on name servers the application does not run, which is why they have ceilings at all.

### 8.9 Decisions made in the implementation

Points this section left open, as implemented:

- An NXDOMAIN answer that carries a CNAME for the asked name is reported as a CNAME answer, not as
  absence (RFC 6604): the name exists. `Absent` and an empty exact set therefore never hold for it.
- An error answer without a question section is accepted when its ID matches the query; otherwise a
  FORMERR answer to an EDNS query could never trigger the retry without EDNS. The same holds for a
  NOERROR answer with the TC flag, which otherwise would end in a timeout instead of the TCP retry.
- A UDP reply that cannot be decoded or exceeds the size bound is a failed query when it carries the
  query's ID and is ignored otherwise. A TCP reply that does not match the query, and a failed TCP
  retry after a truncated UDP answer, are failed queries.
- The address policy of section 8.3, step 4, is the implementation's reading of the IANA registries
  as updated 2025-10-09.
- The wait timeout counts from the first round of queries, after discovery; discovery has its own
  deadline.
- Refused as invalid input: jitter above 50 percent, an interval below 1 s, expected values that
  have no wire form for the question's type, pseudo-types and meta-types, more than `max_questions`
  questions in a call or more than `max_questions_per_round` in one round. Refused as configuration
  errors: zero timeouts, `max_servers` of zero, `max_questions` outside 1 to 256,
  `max_questions_per_round` below `max_questions` or above 8192, more than 16 resolvers, a resolver
  listed twice, recursive discovery without resolvers, an empty static list, a static list longer
  than `max_servers` or with an entry that is not asked.
- The values of an answer are deduplicated and sorted; a TTL with the high bit set is read as zero
  (RFC 2181 section 8); in `wait`, identical questions are asked once per round (`observe` asks each
  question it is given).

### 8.10 Tracing and testing

Events, target `zonewright::inspector`:

- `DEBUG`, one per query: server address, record type, recursion flag, answer kind and duration. No
  question name and no record value.
- `WARN`, one per discovered name server that is not asked: the zone, the NS name, the address when
  there is one, and the reason.
- `WARN`, one per wait that succeeds with servers that are not asked left out (section 8.6): the
  zone, the number left out, the rounds and the elapsed time in milliseconds.

NS names and their addresses are public delegation data, not secrets (hard rule 1 concerns secrets).
No event carries a value of a record the application asks about, and none carries a question name
other than the zone.

Testing without the network:

- The transport sits behind a private trait with one method (send this message to this address, get
  a message or a classified failure). Unit tests of discovery, classification, quorum and the wait
  loop use a table-driven implementation and tokio's paused clock, so a "five minute" wait runs
  instantly and deterministically.
- Integration tests use the mock crate's DNS server (section 12.1) on loopback over real UDP and
  TCP: truncation and TCP retry, `FORMERR` without EDNS, wrong-ID datagrams, silent servers, lame
  servers, lagging servers, CNAME answers. They reach it through `NsDiscovery::Static` and through
  `resolvers`, both of which accept loopback addresses because the application supplies them.
