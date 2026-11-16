# zonewright design

Status: describes the crate as implemented in `dev/zonewright` (version 0.2.0). Where this document
and the code disagree, one of them is fixed in the same change.

Binding rules live in [`AGENTS.md`](../../AGENTS.md) (settled decisions, hard rules, engineering
rules). They are referred to here as "decision N" and "hard rule N" and are not repeated. The list
of providers and their state is [`PROVIDERS.md`](../../PROVIDERS.md).

Conventions used below:

- "Client" is the code that talks to one provider. "Application" is the program that uses the crate.
- "An earlier TXT-only implementation" and "an earlier record-level implementation" are the two
  bodies of prior code this crate replaces. They are sources of behavior, not of API shape.
- The design does not repeat declarations. Where a section introduces types or functions, it names
  them and their source file under `dev/zonewright/`; signatures, fields, defaults and variants are
  read in the source and its rustdoc. The design states what the source does not: rules, reasons,
  limits that span several items, and facts about providers. Under "Not stated in the rustdoc" a
  section lists facts about an item that its documentation does not carry.
- Facts about dependencies were checked on 2026-11-14 against the published crate sources; the
  checks that were run are listed in section 9.4.

## Where each section is

The design is one document in several files. Section numbers run through all of them and do not
change when a file is renamed; the code refers to a place as "design section 3.6".

| Section                                   | File                                                           |
| ----------------------------------------- | -------------------------------------------------------------- |
| 1. Scope and non-goals                    | this file                                                      |
| 2. Public API                             | [`02-public-api.md`](./02-public-api.md)                       |
| 3. Semantics and invariants               | [`03-semantics.md`](./03-semantics.md)                         |
| 4. Record value normalization             | [`04-normalization.md`](./04-normalization.md)                 |
| 5. HTTP transport                         | [`05-http-transport.md`](./05-http-transport.md)               |
| 6. Crypto module                          | [`06-crypto.md`](./06-crypto.md)                               |
| 7. DNS-01 helpers                         | [`07-dns01.md`](./07-dns01.md)                                 |
| 8. Inspector                              | [`08-inspector.md`](./08-inspector.md)                         |
| 9. Features and dependencies (9.1 to 9.3) | [`09-features-dependencies.md`](./09-features-dependencies.md) |
| 9.4 Checks behind this section            | [`history.md`](./history.md)                                   |
| 10. Layout                                | [`10-layout.md`](./10-layout.md)                               |
| 11. Providers                             | [`11-providers.md`](./11-providers.md)                         |
| 12. Testing (12.1 to 12.3, 12.5, 12.6)    | [`12-testing.md`](./12-testing.md)                             |
| 12.4 Carrying over the earlier tests      | [`history.md`](./history.md)                                   |
| 13. Versioning, choices (13.1 to 13.3)    | [`13-decisions.md`](./13-decisions.md)                         |
| 13.4 Open points for the maintainer       | [`13-open-points.md`](./13-open-points.md)                     |

## 1. Scope and non-goals

Scope and out-of-scope are defined in `AGENTS.md` ("What this is"). In one sentence: the crate knows
how to read and change records at a provider and how to observe DNS; it never decides what a zone
should contain or when, and it persists nothing.

Consequences that shape the API:

- There is no "desired state", no diff, no ownership marker. The record-level unit is the rrset
  (decision 8); the application computes the rrset it wants and asks for it to be set, optionally
  under a precondition (section 3.4).
- The TXT value operations exist because DNS-01 needs to add and remove one value while other
  parties write to the same rrset. They are a separate layer with their own guarantees (section
  3.5).
- Waiting for propagation is the inspector's job (section 8), never a provider operation's.
- The crate holds process-local state only: caches of zone identifiers and tokens, per-name locks,
  and for two providers (acme-dns, nic.ru) a small memory of its own writes, owned by `Context`
  (section 11.3). Losing that state on restart never leads to a wrong write. In one case it leaves
  work for a person: a nic.ru zone left with staged, uncommitted changes that the client cannot show
  to be its own (after a restart, or after an operation that was dropped mid-request or whose
  outcome stayed unknown) is refused until it is committed or rolled back by hand.

Explicitly not in the crate: ACME, certificate-authority policy checks (including CAA tree climbing,
section 7.4), mail-specific record construction, metrics, any UI text beyond the English labels of
configuration fields.
