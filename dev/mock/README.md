# zonewright-mock

Stateful mock DNS provider APIs for tests. Each mock is a small server on `127.0.0.1` that behaves
like one provider's API: it keeps zones and records in memory, checks credentials, and answers the
requests a [`zonewright`](https://crates.io/crates/zonewright) client sends. A test points a real
client at it and then looks at what the mock holds and what it received.

The crate serves two purposes:

- the test suite of `zonewright` runs against it, so the tests build from the published package;
- an application that uses `zonewright` can test its own code without accounts at the providers and
  without touching real DNS.

It is test tooling, and its API follows the needs of those tests. Stable within a minor version are:
starting a mock (`start`, `start_on`), the seeds, the methods of the control handles, faults, the
request log, the change reports and the link to the DNS mock. Everything else — the routes a mock
serves beyond those a client uses, error texts, the exact answers where a provider's documentation
leaves room — may change in a patch release. Every incompatible change is listed in the changelog.
Both crates are released with the same version number; use the same version of both.

## Use in a test

```toml
[dev-dependencies]
zonewright = { version = "0.2", features = ["cloudflare"] }
zonewright-mock = "0.2"
secrecy = "0.10"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

A test starts a mock, builds the client with the mock's address as the API endpoint, runs the
operation, and asserts on the mock's state and its request log:

```rust
use secrecy::SecretString;
use zonewright::providers::cloudflare::{Cloudflare, CloudflareConfig, CloudflareCredentials};
use zonewright::{AddOutcome, Context, ContextOptions, DomainName, Provider, Txt};
use zonewright_mock::Fault;
use zonewright_mock::cloudflare::{CloudflareMock, Seed};

#[tokio::test]
async fn a_txt_value_is_added_once() {
    // The mock starts with the zone `example.org` and accepts the token `cf-test-token`.
    let mock = CloudflareMock::start(Seed::standard()).await;

    // The mock speaks plain HTTP on 127.0.0.1. A context limited to loopback accepts that.
    let mut options = ContextOptions::default();
    options.loopback_only = true;
    let ctx = Context::new(options).unwrap();

    // Point the client at the mock instead of the provider.
    let mut config = CloudflareConfig::default();
    config.base_url = mock.base_url();
    let credentials = CloudflareCredentials::new(SecretString::from("cf-test-token"));
    let client = Cloudflare::new(config, credentials, &ctx).unwrap();

    let zone = DomainName::parse("example.org").unwrap();
    let name = DomainName::parse("_acme-challenge.example.org").unwrap();
    let value = Txt::new("a-challenge-value").unwrap();

    // Make the mock answer the next record listing with 503: the client repeats a read.
    mock.faults()
        .push(Fault::on("GET", "/client/v4/zones/*/dns_records").times(1).status(503));

    let outcome = client.add_txt_value(&zone, &name, &value, None).await.unwrap();
    assert_eq!(outcome, AddOutcome::Created);

    // What the mock holds now, and what it was sent.
    assert_eq!(
        mock.control().txt_values("_acme-challenge.example.org"),
        ["a-challenge-value"]
    );
    assert_eq!(mock.log().count(Some("POST"), "/client/v4/zones/*/dns_records"), 1);
    assert_eq!(mock.log().count(Some("GET"), "/client/v4/zones/*/dns_records"), 2);
}
```

An application that builds its clients from stored configuration does the same through
`AnyProvider::from_json`: the settings object names the mock as the endpoint.

```rust
let settings = format!(r#"{{"base_url": "{}"}}"#, mock.base_url());
let credentials = SecretString::from(r#"{"api_token": "cf-test-token"}"#);
let client = AnyProvider::from_json("cloudflare".parse()?, &settings, &credentials, &ctx)?;
```

The name of the endpoint setting differs between providers; `ProviderId::meta` lists the settings of
each.

## What a mock gives a test

Every provider mock is a module named after the provider ID, with the same parts:

- **A seed** (`Seed`, with `Seed::standard()`) — the zones and credentials the mock starts with.
- **A handle** (`CloudflareMock`, `Route53Mock`, …) — started with `start(seed)`, stopped when
  dropped. It listens on `127.0.0.1` with an ephemeral port, so any number of mocks run side by side
  in one test binary, and nothing is global. `start_on(addr, seed)` listens on a given address
  instead, for a stand where the client runs in another container; use it on an isolated test
  network only.
- **State control** (`control()`) — reads what the mock holds and changes it directly, as another
  writer at the provider would: insert a record behind the client's back, change a zone's status,
  or, where the provider issues tokens, revoke them. `reset()` returns the mock to its seed, so one
  mock serves several test cases.
- **Change reports** (`changes()`, the trait `changes::ChangeSource`) — every change of the records
  the provider would publish, as one type for all providers: the complete rrset of a name and type
  after the change, in zone-file text. `changes().subscribe()` delivers them in order.
- **The request log** (`log()`) — every request the mock received: method, path, query, all headers,
  body, and the status it answered with. `count` and `matching` take a method and a path pattern in
  which `*` matches within one path segment and `**` across segments.
- **Fault injection** (`faults()`) — a queue of behaviors applied before the mock sees a request:
  answer with a status, `429` with `Retry-After`, a redirect, an oversized or truncated body, a
  delay, a dropped connection, slow headers, or a hook that changes the mock's state between two
  requests of the client.

Request and response shapes follow each provider's public documentation, with the reference in the
module. Error texts are invented. A mock is not the provider: it shows that the client sends what
the documentation asks for and handles the answers the documentation describes, not that the real
API behaves that way.

## Serving a provider mock's records over DNS

An application that issues certificates over DNS-01 writes TXT records through a provider API, and
an ACME server then asks a DNS server for them. `link::link` connects the two mocks:

```rust
use zonewright_mock::dns::{DnsMock, Role};
use zonewright_mock::link::{LinkOptions, link};
use zonewright_mock::selectel_v2::{Seed, SelectelV2Mock};

// Inside an async test:
let provider = SelectelV2Mock::start(Seed::standard()).await;
let dns = DnsMock::start(Role::Authoritative).await;
let link = link(&provider, &dns, LinkOptions::new());
// Point the ACME server's DNS resolver at `dns.addr()` (for Pebble: `-dnsserver`), and the
// application's client at `provider.base_url()`.
link.settled().await; // everything written so far is being answered
```

The `DnsMock` serves every zone and record the provider mock holds, with the AA flag, and follows
every later change. `Link::settled` replaces sleeping; `Link::hold` and `Link::release`, or
`LinkOptions::delay`, model propagation that has not happened yet. The link converts A, AAAA, TXT,
CNAME, NS, MX and CAA; other types are skipped and counted (`Link::skipped`). An application that
keeps a DNS server of its own subscribes to the changes instead and mirrors them itself.

## Mocks

| Module          | Provider      | Handle             |
| --------------- | ------------- | ------------------ |
| `acme_dns`      | acme-dns      | `AcmeDnsMock`      |
| `beget`         | Beget         | `BegetMock`        |
| `cloud_ru`      | Cloud.ru      | `CloudRuMock`      |
| `cloudflare`    | Cloudflare    | `CloudflareMock`   |
| `digitalocean`  | DigitalOcean  | `DigitalOceanMock` |
| `hetzner`       | Hetzner       | `HetznerMock`      |
| `nicru`         | nic.ru        | `NicruMock`        |
| `regru`         | reg.ru        | `RegruMock`        |
| `rfc2136`       | RFC 2136      | `Rfc2136Mock`      |
| `route53`       | Route 53      | `Route53Mock`      |
| `selectel_v2`   | Selectel v2   | `SelectelV2Mock`   |
| `timeweb_cloud` | Timeweb Cloud | `TimewebCloudMock` |
| `vk_cloud`      | VK Cloud      | `VkCloudMock`      |
| `yandex_360`    | Yandex 360    | `Yandex360Mock`    |
| `yandex_cloud`  | Yandex Cloud  | `YandexCloudMock`  |

The RFC 2136 mock is a DNS server that accepts signed dynamic updates, on TCP and UDP, not an HTTP
server.

Further servers, for tests that are not about one provider:

- `dns::DnsMock` — a DNS server, authoritative or recursive, on loopback or on a given address
  (`start_on`), for tests of the `inspector` feature of `zonewright` and as the DNS server of an
  ACME test (above).
- `proxy::ProxyServer` and `socks::SocksServer` — an HTTP forward proxy and a SOCKS5 proxy, with
  optional authentication, for tests of a proxy setting.
- `echo::EchoServer` — a server that quotes each request back in its error messages, credentials
  included, for tests that a secret never reaches an error text or a log line.
- `MockServer` — the HTTP server the provider mocks are built on, with the request log and the fault
  queue, for writing a mock of your own.

## License

Licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
