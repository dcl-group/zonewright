# AGENTS.md

Instructions for agents that write code or documents in this repository.

Think, write code, write documents and brief other agents in English. README, rustdoc, code
comments, commit messages and everything else stored in the repository are in English. Plain
technical prose: no marketing, no emoji.

If `AGENTS.local.md` exists next to this file, read it too. It holds working notes that are not part
of the repository (current phase, local source material, limits). It is ignored by git and must
never be committed; nothing from it is copied into tracked files, commit messages or code comments.

## What this is

`zonewright` is a public Rust crate for managing DNS zones at DNS hosting providers: one code base
for "how to read and change records at provider X".

Licence: `MIT OR Apache-2.0`.

Repository: <https://github.com/dcl-vc/zonewright>.

What records should exist, and when, is the business of the application that uses the crate. The
crate only knows how to talk to providers and how to observe DNS.

### In scope

- Provider clients: acme-dns, Beget, Cloud.ru, Cloudflare, DigitalOcean, Hetzner, nic.ru, reg.ru,
  RFC 2136, Route 53, Selectel v2, Timeweb Cloud, VK Cloud, Yandex 360, Yandex Cloud, etc. The list
  is the current set and will grow. Authentication, token caching, retries and rate-limit handling
  live inside the clients.
- Record operations: list zones, read the records of a zone, create, change, delete.
- TXT value operations for the DNS-01 ACME challenge: add one value to an rrset without overwriting
  others, remove only that value, idempotently.
- Connection check: credentials are valid and the given zones are visible.
- Types and errors: names, record model, typed errors with secrets redacted, provider metadata
  (configuration fields, verified-against-live-API flag, default propagation timeout).
- DNS-01 helpers: challenge name, CNAME chain following, zone selection for a name.
- Inspector (optional feature): discover authoritative name servers, query any record type at each
  of them or through a recursive resolver, wait until an expectation holds (value present / exact
  set / absent), report per name server.

### Out of scope

Everything that decides what a zone should contain or when to change it, and everything that
persists state:

- ACME orders and their lifecycle.
- Building a desired record set, diffing it against the actual one, record ownership.
- Persistence. The crate keeps nothing on disk and has no database. The application stores its
  configured provider accounts (provider kind, settings, credentials) and its list of zones,
  encrypts the credentials at rest, and passes configuration and credentials to the crate when it
  constructs a client.
- Scheduling, audit, metrics, UI.

## Repository layout

Three top-level directories; they appear as the work reaches them.

- `docs/` — documentation.
- `dev/` — code.
- `todo/` — short documents, one per concrete task. A task's file is deleted when the task is
  closed; finished tasks are not archived here.

## Settled decisions — do not reopen

1. Name: `zonewright`.
2. `dns-update` and Go's lego (`github.com/go-acme/lego`, `providers/dns/`) are references for
   provider API behaviour only.
3. Crypto: `rustls` + `aws-lc-rs` only. No `ring` feature, no RustCrypto `rsa`. The crate never
   installs a process-wide crypto provider; the application does that.
4. The record model covers any DNS record type — an open set, not a closed enum. Each provider
   reports which types and operations it supports.
5. The inspector works for any record type and is an optional feature.
6. Every provider is its own cargo feature. No provider is enabled by default. The umbrella feature
   `all-providers` enables them all.
7. The public API exposes only `std::time`. `jiff` is a private dependency with minimal features; no
   type from `jiff`, `time` or `chrono` may appear in a public signature.
8. The unit of a record operation is the rrset — all values of one name and type. Providers whose
   API works with individual records map onto it inside the client.
9. Record values are carried in zone-file text form (RFC 1035) with normalisation, so values read
   from a provider and values seen by the inspector compare directly. Typed construction and parsing
   exist for MX, SRV, CAA, TLSA and HTTPS/SVCB.
10. The crate emits `tracing` events only. No dependency on `metrics` or `prometheus`.
11. README, rustdoc and code comments are in English.
12. Licence: `MIT OR Apache-2.0`.

Design choices not listed here are the lead agent's to make. Each one is recorded in the design
document with its reason, so the maintainer can overrule it.

## Facts to design around

- The API is designed at the record level from the start; TXT value operations are a layer on top. A
  provider that only does TXT so far says so through its capabilities rather than failing at the
  API.
- Not every provider can do everything: acme-dns can only update TXT; RFC 2136 cannot list records;
  neither Selectel nor Yandex Cloud accepts TLSA, etc.
- The `verified` flag must stay honest.
- Provider kind strings are persisted by applications and must not change: `selectel_v2`, `regru`,
  `yandex_cloud`, `nicru`, `acme_dns`, `rfc2136`, `cloudflare`, `hetzner`, `digitalocean`,
  `route53`, `timeweb_cloud`, `beget`, `vk_cloud`, `cloud_ru`, `yandex_360`, `unmanaged`, etc. New
  kinds are added as providers are added; an existing string is never renamed or reused. The list of
  kinds is complete in any build, whatever features are enabled; only the client code is
  feature-gated.
- Applications may pin or vendor their own `hickory-*`; this is one reason the inspector is an
  optional feature.
- Depend on `reqwest` with `default-features = false` and `rustls-no-provider`.

## Hard rules

1. **Secrets never leak.** Tokens, keys and passwords live only in `secrecy` wrappers; no
   `Debug`/`Display` with contents; nothing secret in error text, `tracing` events or panics. An API
   that echoes a credential back must not get it into an error or a log line; tests cover this for
   every client.
2. **Client invariants.** The name is inside the zone; a TXT value operation never overwrites an
   rrset; someone else's value is never deleted; operations on one name are serialised.
3. **Nothing invented.** Provider endpoints, request shapes, limits and error codes come from the
   provider's documentation, lego or `dns-update`, with a reference in the code, or from behaviour a
   developer observed while testing against the provider's live API, with a comment saying what was
   observed and when. Where documentation and observed behaviour disagree, the code follows the
   observed behaviour and the comment records the discrepancy.
4. **No real credentials** in code, tests, fixtures, logs or reports.
5. **`ring`, OpenSSL and `native-tls` never appear in the dependency tree.** Enforced by
   `cargo deny`.

## Engineering rules

- Edition 2024; `unsafe_code = "deny"`; errors with `thiserror`; secrets with `secrecy` + `zeroize`.
- No `async-trait`. Async traits use native `async fn` / `-> impl Future<Output = …> + Send`. The
  set of providers is dispatched through an enum, not `dyn Trait`.
- Check every dependency version and feature name against current documentation (context7, docs.rs)
  before adding it. Do not rely on memory.
- Gates: `cargo fmt --check`, `cargo clippy`, `cargo deny check`, `cargo test`. CI builds with no
  features, with each feature alone and with all features (`cargo hack --each-feature`).
- Tests run against mocks. Live-API tests are `#[ignore]`, read credentials from environment
  variables, and run only when the maintainer says so.

## Formatting on save

Every file creation or update ends with the formatter, run on the touched paths. If the formatter
rewrites the file, that is part of the same change.

Markdown, JSON and YAML — Prettier, configured in `.prettierrc.json` and `.prettierignore`:

```bash
npx --yes prettier@3 --write --ignore-path .prettierignore -- <paths>
```

Rust — Prettier does not touch `.rs`:

```bash
rustfmt --edition 2024 -- <paths>
```

Not formatted: `target/`, lock files, test fixtures (compared byte for byte).

## Limits

- Do not create a remote repository, push, tag a release or publish to crates.io without the
  maintainer's explicit instruction for that specific action.
- When a decision belongs to the maintainer and blocks you, ask one precise question and carry on
  with whatever does not depend on the answer.

## How to work

- Delegate independent pieces (one provider, one module) to subagents in parallel. Each brief is
  self-contained: goal, files to read, constraints, what done looks like.
- A subagent's report is a claim, not proof. Read the diff and run the gates before telling the
  maintainer something works.
- In reports, separate what was verified from what was inferred, and say plainly what is not done or
  not checked.

## Git

- Small sequential commits, one finished piece of work each. Subject in Conventional Commits style
  (`feat(selectel): …`, `fix(inspector): …`), body to the point.
- Every commit is authored and committed as `Dmitry Bikman <db@dcl.vc>`. Check
  `git config user.name` and `git config user.email` in a fresh clone before the first commit.
- Create and merge branches only on the maintainer's instruction.
- The remote is `origin` (`git@github.com:dcl-vc/zonewright.git`), default branch `main`.
- Never push without an explicit instruction for that push.

### Branches and releases

- `main` is the development trunk. It always builds and passes the gates, and it may contain work
  that is not released yet. Its history is never rewritten.
- A release is an annotated tag `vX.Y.Z` on a commit of `main`. A published tag is never moved or
  deleted: builds of other projects are pinned to it.
- Work reaches `main` from short-lived branches, one per task.
- A version branch `X.Y.x` is created only when it is needed: `main` already carries incompatible
  work for the next version and an older line needs a fix. It starts from the last tag of that line.
  The fix lands in `main` first, is then cherry-picked to the version branch, and the new tag is put
  there.
- Version numbers follow [Semantic Versioning 2.0.0](https://semver.org/) as Cargo applies it
  ([SemVer compatibility](https://doc.rust-lang.org/cargo/reference/semver.html)). Before 1.0 Cargo
  treats the second number as the breaking one: an incompatible change to the public API raises it
  (`0.1.z` → `0.2.0`); anything else raises the third.
