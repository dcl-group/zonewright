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

Pre-release, version 0.1.0. The crate is not published to crates.io; use it as a git dependency
pinned by tag. The provider clients are implemented and tested against mocks. No client is verified
against a live API yet.

[`PROVIDERS.md`](./PROVIDERS.md) is the single list of providers, with the state of each client and
the definition of "verified". Each provider reports its capabilities at run time
(`Provider::capabilities`), and a client answers an operation it does not support with an
`Unsupported` error rather than failing in some other way.

## Installation

```toml
[dependencies]
# The tag does not exist until the first release is tagged.
zonewright = { git = "https://github.com/dcl-vc/zonewright", tag = "v0.1.0", features = ["cloudflare", "inspector"] }
```

No feature is enabled by default. A provider that is not compiled in is still a valid `ProviderId`;
building a client for it returns an `Error` of kind `NotCompiled`.

| Feature          | Enables                                                                |
| ---------------- | ---------------------------------------------------------------------- |
| one per provider | The client of that provider, named by its ID (`cloudflare`, `route53`) |
| `all-providers`  | Every provider client                                                  |
| `inspector`      | The propagation inspector                                              |

The provider IDs are listed in [`PROVIDERS.md`](./PROVIDERS.md).

## Usage

A client is built from the provider ID, a JSON object of settings and a JSON object of credentials,
as an application would keep them in its own storage. Settings and credentials are different for
each provider; `ProviderId::meta` describes the fields. The examples in this file need the features
`cloudflare` and `inspector`, as in the installation snippet above.

```rust,no_run
use secrecy::SecretString;
use zonewright::{
    AddOutcome, AnyProvider, Context, ContextOptions, DomainName, Error, ErrorKind, Provider,
    ProviderId, Txt, dns01,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new(ContextOptions::default())?;

    let id: ProviderId = "cloudflare".parse()?;
    let credentials = SecretString::from(r#"{"api_token": "placeholder-not-a-real-token"}"#);
    let provider = AnyProvider::from_json(id, "{}", &credentials, &ctx)?;

    let zone = DomainName::parse("example.org")?;
    let report = provider.check(std::slice::from_ref(&zone)).await?;
    println!(
        "credentials verified: {}, zone visible: {}",
        report.credentials_verified,
        report.zones.iter().all(|z| z.found),
    );

    // DNS-01: add one value to _acme-challenge.example.org without touching other values,
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

`Error::kind` returns an `ErrorKind` with a stable snake_case identifier (`ErrorKind::as_str`) that
an application can map to its own error codes.

### Inspector

With the `inspector` feature, `zonewright::inspector::Inspector` discovers the authoritative name
servers of a zone, asks any record type at one server or at every server of the zone, and waits
until an expectation holds (a value is present, the rrset is exactly a given set, or a value is
absent) at all of them, reporting per name server. Discovery fails rather than return an incomplete
list when a name server has no usable address. It needs a `tokio` runtime with the I/O and time
drivers enabled and holds no secrets.

```rust,no_run
use std::time::Duration;
use zonewright::inspector::{Condition, Expectation, Inspector, InspectorConfig, Question, WaitOptions};
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
let report = inspector
    .wait(&zone, &[expectation], &WaitOptions::new(Duration::from_secs(120)))
    .await?;
for server in &report.servers {
    println!("{}: satisfied = {}", server.server.addr, server.satisfied);
}
Ok(())
}
```

## TLS and crypto

HTTP clients use `reqwest` with `rustls` and `aws-lc-rs`. The crate builds its own TLS configuration
for its requests and never installs a process-wide crypto provider; if the application needs one for
its own TLS, the application installs it. Server certificates are verified against the platform's
trust store plus any DER-encoded certificates the application passes in
`ContextOptions::extra_root_certificates`. `ring`, OpenSSL and `native-tls` are not in the
dependency tree. Building needs a C compiler (for `aws-lc-rs`) when an HTTP provider or `rfc2136` is
enabled.

## Secrets and logging

Tokens, keys and passwords are held in `secrecy` wrappers and are not printed by `Debug` or
`Display`. Credentials are passed in as `SecretString`. The text of an `Error` is redacted, and
provider responses that echo a credential do not reach error text. The crate emits `tracing` events
only (no `metrics` or `prometheus`); an HTTP event carries the method, the path without the query
string, the status code and the duration, and request and response bodies and headers are never
logged.

## MSRV and versioning

The minimum supported Rust version is 1.88, edition 2024. The crate follows
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
