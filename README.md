# zonewright

`zonewright` is a Rust crate for managing DNS zones at DNS hosting providers: one code base for "how
to read and change records at provider X". It offers provider clients, record operations (list
zones, read the records of a zone, create, change, delete), the TXT value operations that the DNS-01
ACME challenge needs, a connection check, DNS-01 helpers, and an optional inspector that observes
DNS at authoritative name servers and resolvers.

The crate deliberately decides nothing. What records should exist, and when they change, is the
business of the application that uses it. It has no persistence (it keeps nothing on disk, and the
application passes configuration and credentials in when it builds a client), no ACME orders, no
desired-state diffing, no scheduling, no audit and no metrics.

## Status

Version 0.2.1. The provider clients are implemented and tested against mocks. One client, Selectel
v2, is verified against the live API for TXT values, zone listing and the connection check; its
record operations and the other clients are not yet.

[`PROVIDERS.md`](https://github.com/dcl-group/zonewright/blob/main/PROVIDERS.md) is the single list
of providers, with the state of each client and the definition of "verified". Each provider reports
its capabilities at run time (`Provider::capabilities`), and a client answers an operation it does
not support with an `Unsupported` error rather than failing in some other way.

## Installation

```toml
[dependencies]
zonewright = { version = "0.2", features = ["cloudflare", "inspector"] }
```

No feature is enabled by default. A provider that is not compiled in is still a valid `ProviderId`;
building a client for it returns an `Error` of kind `NotCompiled`.

| Feature             | Enables                                                                |
| ------------------- | ---------------------------------------------------------------------- |
| one per provider    | The client of that provider, named by its ID (`cloudflare`, `route53`) |
| `all-providers`     | Every provider client                                                  |
| `inspector`         | The propagation inspector                                              |
| `socks`             | SOCKS5 proxies (`socks5://`, `socks5h://`) in `ContextOptions::proxy`  |
| `platform-verifier` | The operating system's trust store, as `TrustRoots::Platform`          |

The provider IDs are listed in
[`PROVIDERS.md`](https://github.com/dcl-group/zonewright/blob/main/PROVIDERS.md).

## Usage

There are two ways to build a client, and they give the same result. The examples in this file need
the features `cloudflare` and `inspector`, as in the installation snippet above.

### A client from typed values

Every provider has a module under `zonewright::providers` with its client, a settings struct and a
credentials struct. This is the way to build a client when the code knows which provider it talks
to.

```rust,no_run
use secrecy::SecretString;
use zonewright::providers::cloudflare::{Cloudflare, CloudflareConfig, CloudflareCredentials};
use zonewright::{
    AddOutcome, Context, ContextOptions, DomainName, Error, ErrorKind, Provider, Txt, dns01,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new(ContextOptions::default())?;

    let credentials =
        CloudflareCredentials::new(SecretString::from("placeholder-not-a-real-token"));
    let provider = Cloudflare::new(CloudflareConfig::default(), credentials, &ctx)?;

    let zone = DomainName::parse("example.org")?;
    let report = provider.check([&zone]).await?;
    println!(
        "credentials verified: {}, zone visible: {}",
        report.credentials_verified,
        report.zones.iter().all(|z| z.found),
    );

    // DNS-01: add one value to _acme-challenge.www.example.org without touching other values,
    // then remove only that value.
    let name = dns01::challenge_name(&DomainName::parse("www.example.org")?)?;
    let value = Txt::new("placeholder-challenge-digest")?;

    match provider.add_txt_value(&zone, &name, &value, None).await {
        Ok(AddOutcome::AlreadyPresent) => println!("the value was already there"),
        Ok(outcome) => println!("added: {outcome:?}"),
        Err(e) => return Err(explain(&e).into()),
    }

    // ... wait for propagation, let the CA validate ...

    provider.remove_txt_value(&zone, &name, &value).await?;
    Ok(())
}

fn explain(e: &Error) -> String {
    match e.kind() {
        ErrorKind::Auth | ErrorKind::Forbidden => format!("check the credentials: {e}"),
        ErrorKind::ZoneNotFound => format!("the account does not see the zone: {e}"),
        // RateLimited, Conflict and Transient: repeating the operation later can succeed.
        _ if e.is_retryable() => format!("try again later: {e}"),
        kind => format!("{kind}: {e}"),
    }
}
```

`AnyProvider::from(provider)` turns the client into `AnyProvider`, the enum over all providers, for
code that handles several of them through one type.

### A client from stored configuration

An application that lets its users add provider accounts keeps each account in its own storage, and
since every provider has different fields, what it keeps is a provider ID as a string, a JSON object
of settings and a JSON object of credentials. `AnyProvider::from_json` builds the client from
exactly these three values, so the application needs no `match` over providers and no change to its
code when a new provider is added. It deserializes the two objects into the provider's settings and
credentials structs and calls the same `new`.

```rust,no_run
use secrecy::SecretString;
use zonewright::{AnyProvider, Context, Error, ProviderId};

// `id`, `settings` and `credentials` are what the application stored for one account,
// for example "cloudflare", "{}" and {"api_token": "..."}.
fn client_of_account(
    id: &str,
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<AnyProvider, Box<dyn std::error::Error>> {
    let id: ProviderId = id.parse()?;
    match AnyProvider::from_json(id, settings, credentials, ctx) {
        Ok(provider) => Ok(provider),
        // The ID is valid, but this build does not include that provider's feature.
        Err(Error::NotCompiled { .. }) => Err(format!("{id} is not in this build").into()),
        Err(e) => Err(e.into()),
    }
}
```

`ProviderId` is an enum; its string form is stable, because applications persist it, and every ID
parses in any build, whatever features are enabled. The credentials are passed as one `SecretString`
holding the JSON text, so a secret is never held in a plain string on its way to the client.
`ProviderId::meta` describes the settings and credentials fields of a provider, for an application
that builds its account form from them.

`Error::kind` returns an `ErrorKind` with a stable snake_case identifier (`ErrorKind::as_str`) that
an application can map to its own error codes. `ErrorKind::ALL` lists every kind, so that a test of
that mapping notices a kind added by a newer version.

### Inspector

With the `inspector` feature, `zonewright::inspector::Inspector` discovers the authoritative name
servers of a zone, asks any record type at one server or at every server of the zone, and waits
until an expectation holds (a value is present, the rrset is exactly a given set, or a value is
absent) at all of them, reporting per name server. A name server that cannot be asked is reported,
with the reason, and never counts as agreeing. It needs a `tokio` runtime with the I/O and time
drivers enabled and holds no secrets.

```rust,no_run
use std::time::Duration;
use zonewright::inspector::{
    Condition, Expectation, Inspector, InspectorConfig, InspectorError, Question, WaitOptions,
};
use zonewright::{DomainName, RecordType, Txt};

async fn wait_for_txt() -> Result<(), Box<dyn std::error::Error>> {
let inspector = Inspector::new(InspectorConfig::default())?;
let zone = DomainName::parse("example.org")?;
let name = DomainName::parse("_acme-challenge.example.org")?;
let value = Txt::new("placeholder-challenge-digest")?.to_data()?;

let expectation = Expectation::new(
    Question::new(name, RecordType::TXT),
    Condition::Present(vec![value]),
);
match inspector
    .wait(&zone, &[expectation], &WaitOptions::new(Duration::from_secs(120)))
    .await
{
    Ok(report) => println!("every name server agrees after {:?}", report.elapsed),
    Err(InspectorError::Timeout { report }) => {
        for server in &report.servers {
            match server.server.not_asked {
                Some(reason) => println!("{:?}: not asked: {reason}", server.server.name),
                None => println!("{:?}: satisfied = {}", server.server.addr, server.satisfied),
            }
        }
    }
    Err(err) => return Err(err.into()),
}
Ok(())
}
```

A name server that cannot be asked (no address in the configured address families, or an address the
policy refuses) is reported with its reason and, by default, keeps the wait from succeeding. Set
`WaitOptions::ignore_unaskable_name_servers` to wait only for the name servers that can be asked;
`Report::unaskable_ignored` then says how many were left out.

`InspectorConfig` bounds what one call may ask: `max_questions` (default 32, at most 256) per call
and `max_questions_per_round` (default 1024) for the servers × questions of one round. Answers must
carry the AA flag; `accept_static_without_aa` lifts that for the servers of a static list only, for
example a test DNS server that never sets it.

### DNS-01 for a delegated challenge

When `_acme-challenge.www.example.org` is a CNAME into another zone, the TXT value belongs at the
end of the chain, possibly at another provider. The helpers in `zonewright::dns01` cover the three
steps; none of them talks to a provider:

1. `dns01::challenge_name(&identifier)` gives the challenge name (a leading wildcard label is
   dropped).
2. `dns01::follow_cname(&lookup, &name, max_links)` follows the CNAME records and returns a
   `CnameChain`; `chain.effective()` is the name to write at. `lookup` is anything that implements
   `dns01::CnameLookup`; with the `inspector` feature the `Inspector` does, by asking its resolvers.
3. `dns01::select_zone(&effective, &zones)` picks, from the application's own list of
   `(zone, payload)` pairs, the zone with the most labels that contains the name. The payload is
   whatever the application attaches to a zone, for example which account holds it.

The value is then added with `add_txt_value(&zone, &effective, &value, None)` at the client of that
account and removed with `remove_txt_value` after validation.

### Timeouts and cancellation

Every network call has a timeout (`ContextOptions::connect_timeout` and `request_timeout`), and only
idempotent requests are retried, a bounded number of times. An operation as a whole has no deadline
of its own: an application that wants one wraps the call in its own timeout and drops the future.
Dropping is safe. After a dropped or failed write the outcome at the provider is unknown, and
repeating the same call converges on the same state: a repeated `add_txt_value` answers
`AlreadyPresent` (`Accepted` at acme-dns, whose records cannot be read), a repeated
`remove_txt_value` `NotPresent`, a repeated `set_rrset` `Unchanged`. One provider needs care: nic.ru
stages changes and publishes them with a commit, and a zone left with staged changes by an operation
that was dropped in mid-request is refused by later operations until the staged changes are
committed or rolled back in the provider's panel.

## What the crate does not do

These are left to the application on purpose, and are not planned:

- **Desired state.** No "make the zone look like this file", no diff between desired and actual
  records, no dry run. The crate reads and writes rrsets; deciding which is the application's work.
- **Ownership markers.** The crate does not tag the records it wrote and does not track which
  records are whose. The TXT value operations never remove a value they were not asked to remove.
- **ACME.** No orders, no account keys, no challenge lifecycle, no CAA policy check before issuance.
  The crate adds and removes the TXT value and can watch it propagate.
- **Persistence and secrets at rest.** Nothing is written to disk. The application stores its
  provider accounts and encrypts their credentials.
- **Scheduling, audit and metrics.** The crate emits `tracing` events and nothing else.
- **Several providers at once.** No secondary-DNS fan-out and no cross-provider transaction; each
  client talks to one account.
- **Creating and deleting zones.** Zones are listed, never created or removed.
- **DNSSEC.** The inspector does not validate signatures, and nothing signs a zone.
- **Provider-specific constructs that are not rrsets**, such as Route 53 alias and routing-policy
  record sets: they are reported when listed and never written.

## Testing an ACME application

The crate [`zonewright-mock`](https://crates.io/crates/zonewright-mock) has a stateful mock of every
provider's API and a mock DNS server. Together they stand in for both sides of a DNS-01 test: the
provider API the application writes to, and the DNS server the ACME server reads from.

```text
use zonewright_mock::dns::{DnsMock, Role};
use zonewright_mock::link::{LinkOptions, link};
use zonewright_mock::selectel_v2::{Seed, SelectelV2Mock};

let provider = SelectelV2Mock::start(Seed::standard()).await;
let dns = DnsMock::start(Role::Authoritative).await;
let link = link(&provider, &dns, LinkOptions::new());
// ACME server (for Pebble: -dnsserver) -> dns.addr()
// ... the application writes _acme-challenge TXT through provider.base_url() ...
link.settled().await;
```

`link::link` makes the `DnsMock` serve every zone and record the provider mock holds, and every
later change. `Link::settled` returns once what was written is being answered, so a test does not
sleep. `Link::hold` and `Link::release`, or `LinkOptions::delay`, model propagation that has not
happened yet; faults on the `DnsMock` (SERVFAIL for a name, answers without the AA flag) model a
broken name server. For a stand where the ACME server runs in another container, start the mocks
with `start_on`, for example on `0.0.0.0` with a fixed port, on an isolated test network only: a
mock is an open server with test credentials. The RFC 2136 mock answers queries itself, so an ACME
server can be pointed at it directly.

## TLS and crypto

HTTP clients use `reqwest` with `rustls` and `aws-lc-rs`. The crate builds its own TLS configuration
for its requests and never installs a process-wide crypto provider; if the application needs one for
its own TLS, the application installs it.

Server certificates are verified against the certificate authorities `ContextOptions` selects. By
default (`TrustRoots::Mozilla`) these are Mozilla's root certificates, compiled into the crate; the
operating system's trust store is not read. With the `platform-verifier` feature,
`TrustRoots::Platform` uses the operating system's trust store instead, as version 0.1 did.
`TrustRoots::None` trusts only the certificates the options add, for an application that must trust
a fixed set. `ContextOptions::russian_trusted_root` adds the Russian Trusted Root CA, which the
crate carries and which neither Mozilla's list nor a typical system store has; it is off by default,
because every additional authority can issue certificates for any provider's host. The crate does
not enforce that root's expiry date (2032-02-27); a later release replaces or removes it.
DER-encoded certificates in `ContextOptions::extra_root_certificates` are trusted in addition to all
of these. With `TrustRoots::Mozilla` and `TrustRoots::None` certificate revocation is not checked.

```rust
use zonewright::{Context, ContextOptions, TrustRoots};

fn main() -> Result<(), zonewright::Error> {
    let mut options = ContextOptions::default();
    options.trust_roots = TrustRoots::Mozilla; // the default
    options.russian_trusted_root = true;
    let _ctx = Context::new(options)?;
    Ok(())
}
```

Proxy environment variables are ignored; a proxy is used only when set in `ContextOptions::proxy`.
It may be an HTTP or HTTPS proxy (requests to HTTPS endpoints go through it in a `CONNECT` tunnel)
or, with the `socks` feature, a SOCKS5 proxy (`socks5://`, `socks5h://`; without the feature
`Context::new` refuses such a URL); the provider's certificate is verified as without it, and the
hosts listed in `HttpProxy::exclusions` are reached directly. With an `http://` or SOCKS5 proxy the
proxy credentials travel to the proxy unencrypted; the provider traffic stays inside TLS. A proxy
that refuses its credentials gives `Error::ProxyAuth`. `ring`, OpenSSL and `native-tls` are never
built: no feature of the crate enables them, and `cargo deny` bans them from the resolved dependency
graph. `Cargo.lock` still names `ring`, because `rustls-webpki` and `hickory-proto` declare it as an
optional dependency; nothing enables it. Building needs a C compiler (for `aws-lc-rs`) when an HTTP
provider or `rfc2136` is enabled.

## Secrets and logging

Tokens, keys and passwords are held in `secrecy` wrappers and are not printed by `Debug` or
`Display`. Credentials are passed in as `SecretString`. The text of an `Error` is redacted, and
provider responses that echo a credential do not reach error text. The crate emits `tracing` events
only (no `metrics` or `prometheus`) and installs no subscriber.

Each provider operation (`check`, `list_zones`, `add_txt_value` and the others) emits one `DEBUG`
event with target `zonewright::operation` when it completes. The event names the provider, the
operation, the zone, the owner name and record type where there are any, the outcome (`ok` or the
error kind), and the elapsed milliseconds. Below that, the HTTP transport logs one `DEBUG` event per
attempt (`zonewright::http`: the method, the path without the query string, the status code and the
duration) and the RFC 2136 client one per DNS exchange (`zonewright::rfc2136`). Record values, TTLs,
error text, credentials, and request and response bodies and headers are never logged. A provider's
own error code is not logged either; it is on the error, as `Error::provider_code()`.

## MSRV and versioning

The minimum supported Rust version is 1.99, edition 2024. The crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) as Cargo applies it: before 1.0 an
incompatible change to the public API raises the second number. The public API uses only `std::time`
for time, and its public enums and structs that will grow (provider IDs, error kinds, capabilities,
configuration) are `#[non_exhaustive]`, so adding a provider is not a breaking change.

## Development

Cargo commands run from `dev/`:

```bash
cd dev
cargo fmt --check
cargo clippy
cargo deny check
cargo test
```

No CI configuration is part of the repository; the gates are run by hand, also with no features,
with each feature alone (`cargo hack --each-feature`) and with all features. The default test run
needs no network: clients are tested against mocks with synthetic fixtures. Tests against a live API
are `#[ignore]`d, read credentials from environment variables, and are run only by the maintainer.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
