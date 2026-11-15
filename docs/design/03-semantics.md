# zonewright design: Semantics and invariants

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 3. Semantics and invariants

### 3.1 Checks made before any request

Every operation that takes a zone and a name performs these checks first, in this order, and makes
no network request if one fails. Token requests count as network requests.

1. The operation is supported (`Error::Unsupported`), and for record-level operations the type can
   be read or written (`Error::UnsupportedRecordType`).
2. The zone is neither the root nor a wildcard name, and the type is not a meta type
   (`Error::InvalidInput`).
3. `name.is_within(zone)` (`Error::NameOutsideZone`). The comparison is by labels: `badexample.org.`
   is not within `example.org.`.
4. The request fits the provider: a TTL that `Capabilities::accepts_ttl` accepts, a TXT value the
   client's encoding can carry (section 4.4), the number of records within the provider's limit, an
   `Expect::Matches` set with the operation's name and type (`Error::InvalidInput`).

One validation cannot happen before a request: whether a non-canonical member of a set may be
written depends on what is at the provider (section 4.9). It is made right after the operation's
read and before any write.

A test per client asserts check 3 together with an empty request log at the mock.

### 3.2 Idempotency

Every operation can be repeated after any outcome, including an error and a dropped future, and
converges on the same provider state:

- a repeated `add_txt_value` finds the value and returns `AlreadyPresent`;
- a repeated `remove_txt_value` returns `NotPresent`;
- a repeated `set_rrset` returns `Unchanged`; a repeated `delete_rrset` returns `NotPresent`;
- reads have no effect.

To make the "no change" outcomes true, a write operation always reads the current state first and
skips the write when nothing would change. The exceptions are the two providers that cannot be read
(section 3.5, "blind writes").

Dropping the future of an operation is allowed at any await point. What it can leave behind is a
write whose outcome the caller does not know, which is the same situation as `Error::Transient`.
Per-name locks are released on drop. Clients that keep process-local memory of unfinished writes
record their intent before the request that creates the unfinished state, not after it fails
(section 11.3, nic.ru), so a dropped future cannot make the client mistake its own leftovers for
someone else's. At nic.ru that record stays unconfirmed when the future is dropped while a request
is in flight, and the client does not act on staged changes it cannot show to be its own: if the
zone has staged changes, it is refused until a person commits or rolls them back, so there a repeat
after such a drop can end in `Error::Rejected` rather than in the converged state.

### 3.3 Per-name serialization

All mutating operations on one owner name are serialized inside a process (hard rule 2).

- The lock is an async mutex keyed by the absolute owner name (`DomainName`). The key does not
  include the record type, the zone or the provider. Two accounts that happen to host the same name
  contend needlessly; that is harmless and rare, while a key that included the client would stop
  serializing two clients of the same account, which an application creates whenever it rebuilds a
  client after a settings change.
- The locks live in `Context`. They are created on first use and removed when no operation holds or
  waits for them, so the map does not grow with the number of names ever touched.
- A lock is taken after the checks of section 3.1 and held for the whole operation: the read, the
  write, automatic retries and the polling of a provider-side operation. An operation takes at most
  one name lock. A client that also needs a zone-wide lock (nic.ru) takes the name lock first and
  the zone lock second.
- Read operations (`list_rrsets`, `get_rrset`, `list_zones`, `check`) take no name lock. The nic.ru
  client's `list_rrsets` and `get_rrset` take its zone lock, so that they never see this process's
  edits between staging and commit, and refuse a zone with staged changes that are not under a
  confirmed mark of this process (section 11.3).
- Waiting for the lock has no timeout of its own. Its length is bounded by the bounded duration of
  the operations ahead (section 3.7). An application that wants a deadline wraps the call in its own
  timeout; dropping the future is safe (section 3.2).

What this does and does not guarantee:

- Within one process and one `Context`: two operations on the same name never interleave, so a
  read-modify-write by this crate is never overwritten by another one from this crate.
- Across processes, or against changes made in the provider's control panel, the lock gives nothing.
  What holds there depends on the provider and is described per operation in sections 3.4 and 3.5
  and per provider in the table of section 11.

### 3.4 Record-level operations

`list_rrsets(zone)` returns every rrset the provider reports for the zone, of every type, including
SOA and the apex NS set, sorted by name and then type. All pages are read; a listing that does not
end within the client's page limit is `Error::Protocol`, never a truncated result (the limits are in
section 5.4). Values are canonical `RecordData` where the provider's text parses, and non-canonical
data otherwise (section 4.9). Records a provider marks as disabled are not part of the result. A
type the provider reports that is outside `Capabilities::record_types` is still listed. What cannot
be an `RrSet` at all is not dropped: it gets an entry in `ZoneListing::skipped` with the owner name,
the provider's type name and the reason (a type name that maps to no `RecordType`, a set that is not
plain records, an owner name outside the rules of section 2.1), and the client logs one `WARN` event
per listing with the number of skipped sets. An application that reconciles a zone can thus see that
there is something at a name it must not treat as empty. The result is a snapshot; nothing
guarantees it is still current when the application acts on it, which is what `Expect` is for.

`get_rrset(zone, name, rtype)` returns that one rrset or `None`. It is the same data `list_rrsets`
would return for that name and type.

`set_rrset(zone, rrset, expect)`:

1. Checks of section 3.1; lock the name; read the current rrset.
2. Evaluate `expect` against what was read. `Absent` with an existing rrset, or `Matches(prev)` with
   a different or missing rrset, is `Error::PreconditionFailed` and nothing is written. `Matches`
   compares the member sets, and the TTL only if `prev` has one.
3. If the current rrset already equals the requested one (members, and TTL when the request has
   one), return `Unchanged` without a write.
4. Write. The result is `Created` or `Replaced`.

"Replace" means: after the call the published values of that name and type are exactly the members
of `rrset`. How it is carried out depends on the provider's native unit:

- Rrset APIs with a conditional whole-set write (`Preconditions::Atomic`: Route 53, Yandex Cloud;
  RFC 2136 through update prerequisites, section 11.3): one request carries the full new set
  together with the old set as the client read it (Route 53 `DELETE` + `CREATE` in one change batch,
  Yandex Cloud `deletions` + `additions`), so the provider refuses the write if the rrset changed in
  between. This holds for every write, not only when `expect` is `Matches`. After such a refusal the
  client runs the operation once more from step 1. That evaluates `expect` against the new state and
  can end in `PreconditionFailed`; if the second write is refused as well, the result is
  `Error::Conflict`.
- Rrset APIs with an unconditional whole-set write (`Preconditions::ReadThenWrite`: Selectel v2,
  Cloud.ru, Hetzner): one request carries the full new set (at Hetzner, a TTL change of an existing
  rrset is a second request, the `change_ttl` action, so its `atomic_rrset_write` is false), and the
  comparison in step 2 and the write in step 4 are separate requests. A change made by another
  process between them is overwritten and not detected. To keep that window at one round trip, the
  transport does not repeat such a write on its own (section 5.3): a failed write is the operation's
  error, and the caller's repeat starts with a fresh read.
- Per-record APIs (Cloudflare, DigitalOcean, nic.ru, reg.ru, Timeweb Cloud, VK Cloud, Yandex 360):
  the client computes the difference between the records read and the records wanted, creates the
  missing ones and deletes the extra ones by their identifiers. Records present in both are not
  touched. All requests are computed from the one read and handed to the client as a whole (the
  `check_plan` hook) before the first is sent, so a request the client knows the API refuses ends
  the operation with nothing written. They are sent in a fixed order: records in the order of the
  read, new values in the order of the requested set. For types that allow only one record (CNAME,
  SOA, DNAME, ALIAS, ANAME), two published records never exist, not even for one request: surplus
  records are deleted first, and the last of them is updated in place to the new value if the API
  can; otherwise the new value is created after the deletes. For all other types the order is:
  enabling of disabled records with a requested value, TTL changes, creates, deletes; so the name
  never loses all its values. A TTL change is applied to every record. The sequence is not atomic:
  if it fails part-way the rrset holds a mixture, the error is returned, and repeating the call
  completes the change because step 1 reads the mixture and step 4 computes the remaining
  difference. A name that holds several published records of a singleton type (which `get_rrset`
  answers with `Error::Protocol`, since the model cannot hold it) is repaired by `set_rrset` and
  `delete_rrset` instead of refused: the rrset counts as present and equal to no set, the surplus
  records are deleted first, and a record that already holds the requested value is the one kept.
- At a name where the client's read shows a CNAME (hook `holds_cname`) or other data (hook
  `holds_other_data`), a `set_rrset` of other data, or of a CNAME, is `Error::InvalidInput` after
  the read and before any write. Where the read does not tell, the write is sent and a refusal by
  the provider is mapped as any other. A whole-set client can also ask for a second read immediately
  before each write (hook `reread_before_write`, used by Cloud.ru); a change since the first read is
  then `Error::Conflict` with nothing written.

Attributes of existing records that the model does not carry (a per-record disabled flag, a comment,
a description) are preserved by a write wherever the API returns them. A requested value that exists
as a disabled record is enabled rather than duplicated. Disabled records that are not among the
requested values stay disabled and stay in place.

`delete_rrset(zone, name, rtype, expect)` removes all published values of that name and type.
`Expect::Absent` is `Error::InvalidInput`. A missing rrset is `NotPresent`. `Matches` is evaluated
as for `set_rrset`. On per-record APIs every record of the set is deleted by identifier. A delete
answered "not found", of one record or of a whole rrset, is done only when a new read, under a zone
identifier looked up afresh, no longer finds the record's value or the rrset; otherwise the zone
changed after the read and the result is `Error::Conflict` (sections 3.5 and 3.8).

Guard rails in this version, as `read_only_types` or explicit refusals:

- SOA is never writable.
- The NS rrset at the zone apex is not writable (`Error::InvalidInput`): at the providers covered so
  far it belongs to the provider. NS rrsets below the apex (delegations) are ordinary data.
- Rrsets a provider cannot express as plain records (Route 53 alias and routing-policy sets,
  Cloud.ru records with GSLB links) are never modified. A TXT value operation that meets one fails
  with `Error::Rejected`. A listing reports them in `ZoneListing::skipped` with
  `SkipReason::NotPlainRecords`.
- A CNAME owner has no other data (RFC 1034 section 3.6.2; RRSIG and NSEC excepted, RFC 4035 section
  2.5). The operations read one name and type, so whether the name holds other data is known only
  where the client's read already shows it (a read that returns every record of the name). There, a
  `set_rrset` of a CNAME at a name with other data, or of another type at a name with a CNAME, is
  `Error::InvalidInput` after the read and before any write. Elsewhere the write is sent and the
  provider's refusal is returned as any other refusal; no request is made only to find out.

### 3.5 TXT value operations

Contract of `add_txt_value(zone, name, value, ttl)`:

- After `Ok`, the TXT rrset at `name` contains `value`.
- No other value of the rrset is removed or altered, and the TTL of an existing rrset is not changed
  (section 3.6).
- If the value is already present, nothing is written and the result is `AlreadyPresent`.

Contract of `remove_txt_value(zone, name, value)`:

- After `Ok`, the TXT rrset at `name` does not contain `value`.
- No other value is removed. The rrset is deleted only when `value` was its only value. A value that
  is not present is never a reason to delete anything: an rrset holding a single foreign value is
  left alone and the result is `NotPresent`.
- A missing rrset or a missing value is `NotPresent`, a success.

Values are compared as TXT data, byte for byte, after the provider's text has been decoded by the
rules of section 4.4; quoting and splitting into character-strings play no role. If a provider holds
several records with the same value, removal removes all of them.

How "never overwrite, never delete a foreign value" is achieved depends on the native unit, and with
it what holds across processes:

| Native unit                                                          | Add                                                               | Remove                                                      | Against a concurrent writer outside this process                                                         |
| -------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Individual records with identifiers                                  | read the name's TXT records; create one record                    | read; delete the records with that value by identifier      | Foreign values are never part of a request, so they cannot be lost. A duplicate of our value is possible |
| Rrset with value-level add/remove calls (Hetzner)                    | read; ask the provider to add the value                           | read; ask the provider to remove the value                  | Same as above                                                                                            |
| Rrset replaced whole, with a conditional write (Route 53, Yandex)    | read; write old set + value, conditional on the old set           | read; write old set − value (or delete), conditional        | The provider rejects the write if the rrset changed; the client returns `Error::Conflict`                |
| Rrset replaced whole, no conditional write (Selectel v2, Beget)      | read; write old set + value                                       | read; write old set − value (or delete)                     | A value another process adds between the read and the write is lost. Not detectable                      |
| Rrset replaced whole, no conditional write, re-read first (Cloud.ru) | read; modify; read again and compare; write                       | same; a sole value is re-read immediately before the delete | The window shrinks to one request but does not close. A detected change is `Error::Conflict`             |
| DNS UPDATE (RFC 2136)                                                | read by query; send "add this RR"                                 | read; send "delete this RR"                                 | The server applies the single-RR change; other RRs are not in the message                                |
| Add-only slots (acme-dns)                                            | send the value unless this process already sent it (section 11.3) | not possible                                                | Not applicable                                                                                           |

Rules common to all of them:

- The read in "read, then write" is mandatory and must be complete. A client never writes a whole
  set after a read that failed, was truncated, or did not have the expected shape.
- When a whole-set write carries foreign values, they are written back exactly as the provider
  returned them (same text, same per-record attributes), not re-encoded from the crate's model. A
  foreign value whose text the client's dialect cannot decode is treated the same way: it is kept as
  opaque text, is never equal to the value being added or removed, and is written back unchanged. It
  does not make the operation fail.
- A delete answered "not found" is not done on the strength of that answer alone. The record may be
  gone, by an earlier attempt of this operation or by someone else; but the same answer comes when
  the zone identifier the client used went stale, or when the domain was deleted and created again
  with the value under a new record identifier, while the value is still published. For one record
  of a per-record API the delete is done when a new read, under a zone identifier looked up afresh,
  no longer finds the record's value; when it still finds it, the result is `Error::Conflict`
  (section 3.8). The delete of a whole rrset (the last value of a whole-set provider) is sent once,
  and its "not found" is a success only when a new read finds no rrset; otherwise the result is
  `Error::Conflict` as well.
- A create of a whole rrset whose refusal the provider does not document for an existing rrset is
  followed by a new read: an rrset found there now was created by another writer after the
  operation's read, nothing of it was overwritten, and the result is `Error::Conflict`; otherwise
  the refusal is the error.
- Each row of the table corresponds to a value of `Capabilities::txt_values`: `PerValue` for the
  first two rows and for RFC 2136, `Conditional` for Route 53 and Yandex Cloud, `ReadThenWrite` for
  Selectel v2, Beget and Cloud.ru, `Rotating` for acme-dns. At the three `ReadThenWrite` providers
  hard rule 2 ("someone else's value is never deleted") holds against this process and every other
  user of the same `Context`, but not against a writer outside it; no client code can change that,
  because their APIs offer neither a per-value call nor a condition. An application for which that
  is not acceptable reads the capability and does not share such names with other writers (open
  point 14).
- `Conflict` is retryable: the next attempt reads the new state. On a conditional-write provider the
  client itself repeats the read-and-write once before returning `Conflict`; this is the one place a
  client repeats a write, and it is safe because the rejected write did not happen.
- Blind writes. Two clients cannot always read: an RFC 2136 server may allow the key to update but
  refuse its queries, and acme-dns has no read at all. In that case the client sends the idempotent
  change and returns `AddOutcome::Accepted` or `RemoveOutcome::Accepted`. It does not guess
  `Created` or `Removed`.
- acme-dns cannot remove a value. `remove_txt_value` returns `Error::Unsupported` and its capability
  flag is false. The application decides that a missing removal is acceptable there (the server
  keeps the two most recent values); the crate does not report a success it did not perform.

The value operations are implemented once, generically (`values.rs`), over three private traits on a
common base trait `TxtBase`, one per native shape: `PerRecord` (which RFC 2136 also uses),
`ValueCalls` and `WholeSet`; a client supplies the reads and writes of its API. acme-dns, which has
no read, is outside this layer. The outcome computation and the foreign-value rules are therefore
the same code for every provider and are tested once against an in-memory backend in addition to the
per-provider tests.

### 3.6 TTL policy

One rule for every write: **an existing rrset keeps its TTL unless the caller asked for another
one.** A write can say three things about the TTL (`RrSet::ttl()`, section 2.2): nothing (`None`), a
number (`Some(Explicit(n))`), or the provider's default (`Some(ProviderDefault)`).

- `add_txt_value` and `remove_txt_value` never change the TTL of an existing rrset. The `ttl`
  argument of `add_txt_value` is used only when the rrset is created: a number, the provider's
  default, or with `None` the client's `ttl` setting.
- `set_rrset` with a number sets it, and with the provider's default gives the rrset the provider's
  default. With `None` it keeps the TTL of the existing rrset, a provider's default included, and
  uses the client's `ttl` setting for a new one.
- The `ttl` setting is itself a number or the provider's default (section 2.8), so "the provider's
  default" can be the client's default for new sets.
- A request is checked before any request (section 3.1, check 4) by `Capabilities::accepts_ttl`: a
  number within `Capabilities::ttl`; the provider's default where `provider_default_ttl` is not
  `Absent`. At a `ForNewRecords` provider (Timeweb Cloud) a write that would turn an existing
  explicit TTL into the default is `InvalidInput` after the read and before any write.
- Where the provider cannot set a TTL (`TtlSupport::NotSettable`), a number is `InvalidInput`; the
  provider's default and `None` are accepted, and every set it reads has the provider's default.
- Where the API stores a TTL per record (`TtlSupport::PerRecord`), the TTL of a set that was read is
  the smallest explicit TTL among its records, else the provider's default when a record has it,
  else not stated. A write with a TTL (a number or the default) sets it on every record and is
  `Unchanged` only when every record already has it; a record added to an existing set gets the
  set's TTL as read. A set whose records mix the default and numbers therefore reads with the
  smallest number, does not match an expectation of the default, and a round trip writes that number
  to its records with the default, as it does for records with larger numbers.
- Where the provider has a default (`provider_default_ttl` not `Absent`), a set that has it reads as
  `Some(ProviderDefault)`; a write with `None` leaves it so, and a write of the set as read is
  `Unchanged`. How each client asks for the default is in section 11.3 (Cloudflare `ttl: 1`; Hetzner
  a create without `ttl` and `change_ttl` with `null`; nic.ru a record without `<ttl>`; Timeweb
  Cloud a create without `ttl`).
- Where it is `Absent`, every set the client reads should carry a TTL. If a read cannot state one (a
  value the model cannot hold, an answer without the field), the set reads with `None`, and a write
  with `None` sends the provider's value back where the client has it, and the client's `ttl`
  setting otherwise; it never sends "no TTL". A conformance test lists the level per provider with
  its reason.
- One exception, RFC 2136 without read access: when the server refuses the client's queries, the TTL
  of the existing rrset is unknown, the add is sent with the client's `ttl`, and common servers then
  apply that TTL to the whole rrset (RFC 2136 section 3.4.2.2 leaves the rrset with one TTL). The
  outcome is `Accepted`, which already says the prior state was not seen.
- Where a provider requires all records of an rrset to share a TTL and takes it per request
  (Hetzner), the client sends the TTL it read (none for the zone's default).

The earlier record-level implementation set a fixed 3600 seconds on every add and update. That
silently rewrote the TTL of values it did not own, including short-lived challenge rrsets created by
others, because a TTL belongs to the whole rrset (RFC 2181 section 5.2). It is not carried over: an
application that wants one TTL everywhere passes it in `set_rrset`.

### 3.7 Bounded duration and provider-side operations

Every network call has a timeout, retries are bounded (section 5.3), and polling is bounded:

- Four providers complete writes asynchronously. After the write is accepted, the client polls the
  provider's operation until it finishes, at a configurable interval with a floor of 250 ms, for a
  fixed maximum number of polls:

  | Provider     | What is polled         | Default interval | Maximum polls | Setting             |
  | ------------ | ---------------------- | ---------------- | ------------- | ------------------- |
  | Hetzner      | action status          | 1000 ms          | 120           | `action_poll_ms`    |
  | Route 53     | change status `INSYNC` | 2000 ms          | 60            | `change_poll_ms`    |
  | Yandex Cloud | operation `done`       | 1000 ms          | 60            | `operation_poll_ms` |
  | Cloud.ru     | operation `done`       | 1000 ms          | 60            | `operation_poll_ms` |

- An operation that finished with an error is `Error::Rejected` with the provider's message, or goes
  down the conditional-write path of section 3.4 (one re-run, then `Error::Conflict`) when the
  provider reports that its condition on the old set did not hold.
- An operation still running after the last poll, or a poll that fails, is `Error::Transient`: the
  write was accepted and its outcome is unknown. Repeating the call is safe.
- The operation returns only after the provider-side operation is done. It never waits for DNS
  propagation.

The worst-case duration of one operation is therefore a sum of bounded terms: lock wait, at most
three attempts of each idempotent request at `request_timeout` each plus back-off, pacing delays
(section 5.7), and `interval × maximum polls`. The crate does not impose a single deadline on top,
because cutting an operation at an arbitrary point is exactly what the caller can already do by
dropping the future.

### 3.8 Zone identifiers and stale caches

Clients cache the provider's identifier for a zone name for the life of the client. A cached
identifier can go stale when a zone is deleted and created again.

- A "not found" answer to a request that used a cached identifier evicts the entry.
- If that answer cannot tell a missing zone from a missing rrset (the same status for both), the
  client resolves the zone again once and repeats the read before it concludes anything. In
  particular `remove_txt_value` does not return `NotPresent` on the strength of a stale identifier.
- `check` always resolves zones afresh and refreshes the cache.
