# zonewright design: Features and dependencies

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 9. Features and dependencies

### 9.1 Cargo features

No feature is enabled by default (decision 6).

| Feature                | Enables                                              | Optional dependencies it turns on                                                    |
| ---------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------ |
| one per provider (2.4) | that provider's client and its `AnyProvider` variant | see the feature list below                                                           |
| `all-providers`        | all fifteen provider features                        | their union                                                                          |
| `inspector`            | `zonewright::inspector`                              | `hickory-proto`, `futures-util`, `fastrand`, `tracing`; `tokio/net`, `tokio/io-util` |

Provider feature names are the provider IDs, underscores included: `acme_dns`, `cloud_ru`,
`selectel_v2`, `timeweb_cloud`, `vk_cloud`, `yandex_360`, `yandex_cloud` and the eight one-word IDs.
A provider then has one spelling everywhere: the persisted ID, the feature, the module, the test
file. `all-providers` and `inspector` are the only other public features.

Three private features group optional dependencies. Their names start with two underscores, they are
documented as internal, and they are not part of the SemVer surface:

| Private feature | Dependencies                                                                                                              | Used by                              |
| --------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `__http`        | `reqwest`, `rustls`, `rustls-platform-verifier`, `rustls-pki-types`, `bytes`, `jiff`, `fastrand`, `serde_json`, `tracing` | every provider except `rfc2136`      |
| `__crypto`      | `aws-lc-rs`                                                                                                               | `rfc2136`, `route53`, `yandex_cloud` |
| `__xml`         | `roxmltree`                                                                                                               | `route53`, `nicru`                   |

```toml
[features]
default = []
all-providers = [
    "acme_dns", "beget", "cloud_ru", "cloudflare", "digitalocean", "hetzner", "nicru", "regru",
    "rfc2136", "route53", "selectel_v2", "timeweb_cloud", "vk_cloud", "yandex_360", "yandex_cloud",
]
inspector = [
    "dep:hickory-proto", "dep:futures-util", "dep:fastrand", "dep:tracing", "tokio/net", "tokio/io-util",
]

acme_dns = ["__http"]
beget = ["__http"]
cloud_ru = ["__http"]
cloudflare = ["__http"]
digitalocean = ["__http"]
hetzner = ["__http"]
nicru = ["__http", "__xml"]
regru = ["__http"]
rfc2136 = ["__crypto", "dep:fastrand", "dep:serde_json", "dep:tracing", "tokio/net", "tokio/io-util"]
route53 = ["__http", "__crypto", "__xml"]
selectel_v2 = ["__http"]
timeweb_cloud = ["__http"]
vk_cloud = ["__http"]
yandex_360 = ["__http"]
yandex_cloud = ["__http", "__crypto"]

__http = [
    "dep:reqwest", "dep:rustls", "dep:rustls-platform-verifier", "dep:rustls-pki-types",
    "dep:bytes", "dep:jiff", "dep:fastrand", "dep:serde_json", "dep:tracing",
]
__crypto = ["dep:aws-lc-rs"]
__xml = ["dep:roxmltree"]
```

### 9.2 What compiles with no features

Names, the record model with normalization and the typed records, `Ttl`, errors and `Detail`,
`ProviderId`, metadata and capabilities of all fifteen providers, the `Provider` trait,
`AnyProvider` (with no variants), `Context` (options and locks only), and `dns01`. The TXT value
layer (`values.rs`) comes with any provider feature, the record-level layer (`rrsets.rs`) with any
provider except `acme_dns` and `beget`, and the scrubber (`redact/scrub.rs`) with `__http`.
Dependencies of that build: `serde`, `secrecy`, `zeroize`, `thiserror`, `idna`, `base64`, `tokio`
with `sync` and `time`; `serde_json` and `tracing` come with the first HTTP provider, `rfc2136` or
(`tracing` only) the inspector. No TLS stack, no C compilation.

An application that only needs the inspector enables `inspector` and gets `hickory-proto` and
UDP/TCP sockets on top of that, still without a TLS stack.

Shared helpers are not all used by every provider. In builds without `all-providers`, `http/`,
`crypto/`, `values.rs`, `rrsets.rs` and `redact/scrub.rs` allow `dead_code`, as do the `Auto`
variant of the TXT text form (`record/txt.rs`) and two helpers of `Ttl` (`record/ttl.rs`) in builds
without the providers that use them; the build with all features does not, so code no provider uses
is still found.

### 9.3 Dependencies

Versions are the latest stable releases on 2026-11-14.

```toml
[dependencies]
serde = { version = "1.0.229", features = ["derive"] }
secrecy = { version = "0.10.3", features = ["serde"] }
zeroize = { version = "1.9.1", features = ["derive"] }
thiserror = "2.0.21"
idna = "1.1.0"
base64 = "0.23.1"
tokio = { version = "1.54.1", features = ["sync", "time"] }

# __http (serde_json and tracing also serve rfc2136; tracing also serves the inspector)
serde_json = { version = "1.0.154", optional = true }
tracing = { version = "0.1.44", default-features = false, features = ["std"], optional = true }
reqwest = { version = "0.13.5", default-features = false, features = ["rustls-no-provider", "socks"], optional = true }
# Must stay on the same 0.23 line as the rustls inside reqwest.
rustls = { version = "0.23.46", default-features = false, features = ["std", "tls12", "aws_lc_rs"], optional = true }
rustls-platform-verifier = { version = "0.7.1", optional = true }
rustls-pki-types = { version = "1.16.0", optional = true }
bytes = { version = "1.12.1", optional = true }
jiff = { version = "0.2.43", default-features = false, features = ["std"], optional = true }
fastrand = { version = "2.5.0", optional = true }

# __crypto
aws-lc-rs = { version = "1.19.0", optional = true }

# __xml
roxmltree = { version = "0.21.2", optional = true }

# inspector
hickory-proto = { version = "0.26.3", default-features = false, features = ["std"], optional = true }
futures-util = { version = "0.3.34", default-features = false, features = ["std"], optional = true }

[dev-dependencies]
serde_json = "1.0.154"
tracing = { version = "0.1.44", default-features = false, features = ["std"] }
zonewright-mock = { version = "0.1.0", path = "../mock" }
tokio = { version = "1.54.1", features = ["macros", "rt", "rt-multi-thread", "test-util", "net", "io-util"] }
tracing-subscriber = { version = "0.3.23", default-features = false, features = ["std", "fmt"] }
rcgen = { version = "0.14.10", default-features = false, features = ["crypto", "pem", "aws_lc_rs"] }
```

Why each is there, and what is deliberately absent:

- `reqwest` with `default-features = false` and `rustls-no-provider` only, as `AGENTS.md` requires.
  Not enabled: `json` (bodies are built and parsed by the transport so that secret-bearing bodies
  stay in zeroizing buffers and every response goes through the size cap), `http2`, `charset`,
  `gzip`, `cookies`, `system-proxy`, `form`, `query`. `socks` is enabled for SOCKS5 proxies (section
  5.1); in `reqwest` 0.13.5 it is an empty feature that adds no crate.
- `rustls` is a direct dependency only to build the `ClientConfig` of section 5.1; its `aws_lc_rs`
  feature provides the provider the crate passes explicitly. It must stay on the same `0.23` line as
  the `rustls` inside `reqwest`: `tls_backend_preconfigured` recognizes the configuration by type,
  and a second `rustls` version in the tree would make it an "unknown backend" error at
  `Context::new`. `rustls` 0.24 (pre-release at the time of writing) removes built-in providers; the
  move is made together with `reqwest`.
- `rustls-platform-verifier` for the system trust store; on Unix-like systems it reads the system CA
  files, so containers need them installed.
- `rustls-pki-types` reads PEM (RSA key for Yandex Cloud, client certificate and key for reg.ru,
  extra roots given as PEM in tests).
- `jiff` is private (decision 7) and minimal: RFC 3339 timestamps of token expiry, the `x-amz-date`
  format, and HTTP dates in `Retry-After` (its RFC 2822 parser accepts the HTTP date form), which
  makes a separate HTTP-date crate unnecessary. No time-zone database feature is enabled.
- `fastrand` supplies retry jitter, wait jitter and message IDs for RFC 2136 (which runs over TCP
  with every message authenticated). It is not used where unpredictability matters.
- `hickory-proto` with `std` only: message encoding and decoding. No resolver, no DNSSEC feature,
  therefore no crypto and no `ring` (hard rule 5).
- `futures-util` for running the inspector's queries concurrently without spawning tasks, so
  dropping `wait` cancels everything it started.
- `aws-lc-rs` needs a C compiler at build time (and NASM or the `prebuilt-nasm` feature on Windows
  x86-64); this cost is confined to builds with an HTTP provider or `rfc2136`.
- Not dependencies: `url` and `percent-encoding` (the transport uses `reqwest::Url` and its own
  encoders, which avoids a second copy of a type that must match `reqwest`'s), `httpdate`, `hex`,
  `async-trait`, `metrics`, `chrono`, `time`, `hickory-resolver`, `hickory-net`, any mock library.

The mock crate (published as `zonewright-mock`, with the same version as `zonewright`) depends on
`axum` 0.8.9 with `default-features = false` and the features `http1`, `tokio`, `json`, `query`,
`form`; `tokio`; `serde`; `serde_json`; `aws-lc-rs` (its own verification of SigV4, TSIG and PS256,
independent of the crate under test); `base64`; `roxmltree`; `hickory-proto` with `std` only (the
DNS server for the inspector tests). It does not depend on `zonewright`. It does not inherit
`[workspace.lints]`: its own `[lints.rust]` denies `unsafe_code` and warns on `missing_docs`, and
the workspace clippy denials do not apply to it.

`tracing` is also a dev-dependency because the secret tests' `tracing` capture
(`tests/common/echo.rs`) builds without any feature. The crate's manifest also sets
`[package.metadata.docs.rs] all-features = true` and `[lints] workspace = true`.

`cargo deny` (`dev/deny.toml`): `ring`, `openssl`, `openssl-sys` and `native-tls` are banned;
`[graph] all-features = true`; wildcard versions denied except for path dependencies (the mock
crate); duplicate versions are a warning; only the crates.io registry is allowed; licenses allowed:
MIT, Apache-2.0, ISC, Unicode-3.0, Unlicense, BSD-3-Clause, CDLA-Permissive-2.0 (confidence 0.8).
`openssl-probe`, a certificate-path helper pulled in by the platform verifier, is not OpenSSL and is
not banned.
