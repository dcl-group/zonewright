# zonewright design: Layout

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 10. Layout

```text
README.md, CHANGELOG.md, PROVIDERS.md, AGENTS.md, CLAUDE.md, LICENSE-MIT, LICENSE-APACHE,
.gitignore, .prettierrc.json, .prettierignore
docs/
  design/                this document: README.md (the index and section 1), 02-public-api.md to
                         13-open-points.md (one file per section, two for section 13), and
                         history.md (sections 9.4 and 12.4)
dev/
  Cargo.toml             virtual workspace: members "zonewright", "mock"; resolver "3";
                         [workspace.package] edition, rust-version, license, repository;
                         [workspace.lints.rust] and [workspace.lints.clippy] (section 12.6)
  Cargo.lock             committed
  deny.toml              section 9.3
  clippy.toml            lets test code use unwrap, expect, panic, indexing, dbg and print
  zonewright/
    Cargo.toml           features and dependencies (section 9); [lints] workspace = true
    LICENSE-MIT, LICENSE-APACHE
                         copies of the repository's, so that the published package carries
                         them; a conformance test compares them byte for byte
    README.md            symbolic link to the repository's README.md (`readme = "README.md"`)
    roots/               the Russian Trusted Root CA (PEM) and a README with its origin and
                         fingerprints; compiled into `src/http/roots.rs`
    src/
      lib.rs             module tree, re-exports, crate docs
      name.rs            DomainName, TargetName
      record/            mod.rs, rtype.rs, ttl.rs, data.rs, rrset.rs, text.rs (tokenizer and
                         escapes), wire.rs, txt.rs, mx.rs, srv.rs, caa.rs, tlsa.rs, svcb.rs
      error.rs           Error, ErrorKind, Operation
      operation.rs       the operation event: one `tracing` event per call of a Provider method
                         (section 5.6)
      redact.rs          Detail
      redact/scrub.rs    Scrubber                                                 (__http)
      id.rs              ProviderId
      meta.rs            ProviderMeta, ConfigField, FieldKind, Capabilities
      provider.rs        Provider, Expect, outcomes, CheckReport, ZoneInfo, ZoneListing
      context.rs         Context, ContextOptions
      locks.rs           per-name locks
      values.rs          the generic TXT value layer (section 3.5)          (any provider)
      rrsets.rs          the record-level layer (sections 3.1-3.4, 3.6)     (any provider but
                                                                            acme_dns, beget)
      dns01.rs
      http/              mod.rs, tls.rs, request.rs, retry.rs, token.rs, keystone.rs, gate.rs,
                         poll.rs, pager.rs, zone_cache.rs, encode.rs, url.rs, proxy.rs, roots.rs;
                         testing.rs, tests.rs and proxy_tests.rs (test builds only) (__http)
      crypto/            mod.rs (SHA-256; SHA-1 with ovh), hmac.rs (rfc2136, route53),
                         ps256.rs (yandex_cloud), rs256.rs (google_cloud), rsa_pem.rs (the
                         PEM reader of the two RSA signers), sigv4.rs (route53)  (__crypto)
      inspector/         mod.rs, config.rs, exchange.rs, discovery.rs, answer.rs,
                         wait.rs, cname.rs; testing.rs (test builds only)         (inspector)
      providers/
        mod.rs           one `pub mod` per provider; AnyProvider; the forwarding macro
        gcore_shared/    private; the code `gcore` and `edgecenter` share (below)
        <id>/
          mod.rs         `pub(crate) mod meta;` always; the other modules and the re-exports
                         (client, configuration types, `from_json`) behind the provider's feature
          meta.rs        the provider's ProviderMeta: fields, capabilities, defaults
          config.rs      <Name>Config, <Name>Credentials
          client.rs      the client and its Provider impl
          api.rs         requests and answers of the provider's API (all but rfc2136; `gcore` and
                         `edgecenter` use `gcore_shared/`)
          records.rs     record-level operations (all but acme_dns, beget)
          txt.rs         TXT value operations (all but acme_dns)
          ...            further files as the client needs: acme_dns state.rs; azure_dns,
                         cloud_ru, gandi content.rs, rrset.rs; desec, google_cloud, hetzner,
                         selectel_v2, yandex_cloud rrset.rs; route53 content.rs; rfc2136
                         transport.rs, tsig.rs, wire.rs, axfr.rs (zone transfer), listing.rs
                         (`list_rrsets` from a transfer); timeweb_cloud names.rs;
                         azure_dns, google_cloud live.rs (ignored live tests that call the
                         client's low-level operations, section 12.5)
        gcore_shared/    mod.rs (the shared client core), api.rs, content.rs, records.rs, txt.rs;
                         `gcore` and `edgecenter` each keep mod.rs, meta.rs, config.rs and
                         client.rs
    tests/
      common/            mod.rs (context and client builders, sample configurations), echo.rs
                         (canaries, echo dialects, tracing capture), link.rs (helpers for the
                         tests of the link between a provider mock and the DNS mock),
                         gcore_shared.rs (the test cases `gcore` and `edgecenter` share)
      <id>.rs            one file per provider, `#![cfg(feature = "<id>")]`, live tests #[ignore]d
      conformance.rs     IDs, metadata, PROVIDERS.md, capability/behavior agreement, source
                         scans, required tests
      names.rs, records.rs, dns01.rs, transport.rs, inspector.rs
      operation_event.rs the operation event (section 5.6)
      mock_dns_link.rs   a provider mock's records served by the DNS mock
      rfc2136_interop.rs cross-checks of the RFC 2136 mock and client against `nsupdate` and
                         `dig`; #[ignore]d
  mock/
    Cargo.toml           zonewright-mock, published with the same version as the crate; its own
                         [lints.rust]
    README.md            what the mock crate is and how a test uses it; the page on crates.io
    LICENSE-MIT, LICENSE-APACHE
                         copies of the repository's, checked by the same conformance test
    src/
      lib.rs             module tree, MockServer, re-exports
      conn.rs            listener and connection type under every mock server
      log.rs             request log
      fault.rs           fault injection
      echo.rs            the echo server of section 12.2
      dns.rs             UDP+TCP DNS server for the inspector tests and for tests of an
                         application
      changes.rs         the change reports of the provider mocks
      link.rs            serves a provider mock's records from the DNS mock
      gcore_shared.rs    the core of the Gcore and EdgeCenter mocks; `gcore.rs` and
                         `edgecenter.rs` start it with their provider's answers
      proxy.rs           HTTP forward proxy (CONNECT and plain) for the transport tests
      socks.rs           SOCKS5 proxy for the transport tests
      <id>.rs            one stateful mock per provider
    tests/
      harness.rs         tests of the mock servers themselves
```

There is no fixtures directory: fixtures are written inline in the test files. There is no CI
configuration.

Ownership, so that every provider can be written in parallel without touching the same file:

- Shared files, edited by one developer at a time: everything outside `providers/<id>/`,
  `tests/<id>.rs` and `mock/src/<id>.rs`. That includes both `Cargo.toml` files, `providers/mod.rs`,
  `id.rs`, `context.rs`, `values.rs`, `rrsets.rs`, the whole `http/`, `crypto/`, `record/`,
  `redact/` and `inspector/` trees, `tests/common/`, the mock's `lib.rs`, `conn.rs`, `log.rs`,
  `fault.rs`, `echo.rs`, `dns.rs`, `changes.rs`, `link.rs` and `tests/harness.rs`, and
  `PROVIDERS.md`, `CHANGELOG.md` and this document.
- Files of one provider, edited by the developer of that provider: `src/providers/<id>/**`,
  `tests/<id>.rs`, `mock/src/<id>.rs`.
- `providers/gcore_shared/` is a third module beside `gcore/` and `edgecenter/` rather than a
  directory inside one of them, because the two providers' API is one ancestry and their code is
  one. It is not a provider: it has no feature, ID or metadata, and is compiled when either feature
  is on. It sits outside both provider directories because the conformance tests read a provider's
  own directory (`src/providers/<id>/`) for what its client does (the operation event and the use of
  the zone-ID cache); the shared code is therefore in a directory that belongs to neither provider,
  the `Provider` implementations stay in the provider's directory where the scans look, and the test
  cases are shared in `tests/common/gcore_shared.rs` and called from `tests/gcore.rs` and
  `tests/edgecenter.rs`, which hold the required test names. It is a shared file in the sense above,
  edited by one developer at a time; so are `tests/common/gcore_shared.rs` and
  `mock/src/gcore_shared.rs`.
- Every provider has its feature, its `AnyProvider` variant, its module with a complete `meta.rs`,
  its test file and its mock module, so a provider developer never needs a shared file. A need for a
  new shared helper, or a change to one, is settled before the provider work goes on.
- Provider state that must outlive a client (nic.ru, acme-dns; section 11.3) is a type defined in
  the provider's directory and held by `Context` in a field behind the provider's feature.
