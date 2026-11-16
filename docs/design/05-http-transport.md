# zonewright design: HTTP transport

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 5. HTTP transport

One private module serves every HTTP client. A client describes a request and how to read the
answer; connection handling, timeouts, retries, rate-limit handling, the size cap, redaction and
logging are not reimplemented per provider. (The earlier TXT-only implementation had one shared
helper used by three clients and nine hand-written variants of it.)

### 5.1 Client construction

`Context::new` builds one `reqwest::Client`:

- TLS: the crate builds its own `rustls::ClientConfig` with
  `ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))`,
  safe default protocol versions, the platform certificate verifier
  (`rustls_platform_verifier::Verifier::new_with_extra_roots(extra_roots, provider)`) and
  `alpn_protocols = ["http/1.1"]`, and passes it to `ClientBuilder::tls_backend_preconfigured`.
  Nothing is installed process-wide and no process-wide default is consulted (decision 3). With
  `reqwest`'s `rustls-no-provider` feature the ordinary builder path panics when no process-wide
  provider is installed; the preconfigured path does not reach that code.
- Two consequences of the preconfigured path, both read in the `reqwest` 0.13.5 source: `reqwest`
  sets ALPN only on configurations it builds itself, so the crate sets it; and
  `ClientBuilder::identity` is not applied to a preconfigured configuration, so a client that needs
  a TLS client certificate (reg.ru) gets a second `ClientConfig` built with `with_client_auth_cert`
  and its own `reqwest::Client` with otherwise identical options, through one private constructor in
  the transport.
- Trust anchors: the platform's, plus `ContextOptions::extra_root_certificates`. On Unix-like
  systems without system CA certificates the platform verifier cannot be built. `Context::new` then
  logs one warning and installs a verifier that rejects every certificate with a clear message,
  instead of failing: plain-HTTP loopback endpoints (tests) keep working, and an HTTPS request fails
  with `Error::Config` whose detail says that no CA certificates are available. The condition is
  permanent for the process, so it is not reported as retryable. An invalid extra certificate is
  `Error::Config`.
- HTTP/1.1 only. No provider needs HTTP/2, request rates are a few per second at most, and leaving
  it out removes a dependency subtree.
- Redirects are never followed (`redirect::Policy::none()`). Credentials travel in headers and
  bodies, and a 307 or 308 would replay them to another host. A 3xx answer is returned to the client
  code like any other status and becomes `Error::Rejected { status: Some(3xx) }`.
- Timeouts: `connect_timeout` (default 10 s) and `request_timeout` (default 30 s, whole request
  including the body).
- User agent: `zonewright/<crate version>`, plus a space and the application's suffix if given.
- No proxy from the environment: the client is built with `no_proxy()`. `reqwest` reads
  `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` from the environment even without its `system-proxy`
  feature; left alone, a variable set for some other purpose would route provider credentials
  through a proxy, plain-HTTP loopback requests included, and `loopback_only` would not mean what it
  says.
- An explicit proxy, `ContextOptions::proxy` (decided by the maintainer on 2026-11-14, item 15 of
  section 13.4), is the only way to configure one. It is added with `ClientBuilder::proxy` after
  `no_proxy()` as one `Proxy::custom`, which in `reqwest` 0.13.5 also turns off reading the
  environment (`auto_sys_proxy = false`): the environment, `NO_PROXY` included, stays ignored with
  the setting as without it, and every HTTP request of the context goes through the proxy except
  requests to the hosts in `HttpProxy::exclusions`. Without the setting the client is exactly the
  one described above.
  - Schemes: `http://` and `https://` proxies, and SOCKS5 as `socks5://` (the client resolves the
    provider's host name and gives the proxy an address) or `socks5h://` (the proxy resolves it),
    through `reqwest`'s `socks` feature (section 9.3). `socks4`, `socks4a` and every other scheme
    are refused with `Error::Config`, also because `hyper-util`'s matcher silently ignores a scheme
    it does not know and the request would go out directly. Through SOCKS5 every request is a SOCKS5
    `CONNECT` (RFC 1928) with the TLS session to the provider inside it; the connection to the
    SOCKS5 proxy itself is not encrypted.
  - An `http://` proxy on another host is allowed (decided by the maintainer on 2026-11-15): the
    proxy credentials then travel to the proxy unencrypted, as they do to any SOCKS5 proxy, while
    the provider traffic stays inside TLS. The rustdoc of `HttpProxy` says so; whether that is
    acceptable on a given network is the application's decision.
  - Exclusions (decided by the maintainer on 2026-11-15). Each entry is a host name
    (`api.example.com`: exactly that host), `*.` and a host name (`*.example.com`: every name below
    it, not the name itself), an IP address (IPv6 without brackets) or a CIDR block with zero host
    bits and a prefix of at least 1. Nothing else is accepted: no `*` alone, no leading dot, no
    port, no scheme. An entry is compared with the host of the request URL as written, for every
    port; nothing is resolved, so `127.0.0.0/8` does not cover `localhost`. A bad entry is
    `Error::Config` naming its position only. `reqwest::NoProxy` is not used: each of its host-name
    entries also matches every name below it, so it cannot express an exact host, and its `*`
    matches everything. The crate's own matcher, called from `Proxy::custom`, is the only routing
    decision, and the transport uses the same matcher to know whether a request went through the
    proxy.
  - An `https://` target behind an HTTP proxy goes through a `CONNECT` tunnel. The proxy sees the
    target's host and port and nothing else; the TLS session with the provider runs inside the
    tunnel with the crate's `ClientConfig`, so the provider's certificate is verified exactly as
    without a proxy, and ALPN is the crate's `http/1.1`. For an `https://` proxy, `reqwest` uses a
    clone of the same `ClientConfig` with ALPN cleared for the TLS connection to the proxy
    (`connect.rs`, `new_rustls_tls`): the proxy's certificate is verified with the context's trust
    anchors and the explicit `aws-lc-rs` provider. A client with a TLS client certificate (reg.ru)
    presents it to an `https://` proxy that asks for one, since the clone carries it.
  - A plain-HTTP loopback target (tests) is forwarded in absolute form by an HTTP proxy and relayed
    by a SOCKS5 one. It is refused before any connection when the proxy is not itself a loopback IP
    literal: plain HTTP is accepted only because it never leaves the host, and a proxy elsewhere
    would carry it over the network (and reach its own loopback, not this host's).
  - Checks at `Context::new`, each `Error::Config` with a fixed text that names the setting and
    quotes nothing: the URL parses and has a host that is an IP literal or a name of letters,
    digits, `.`, `-` and `_`; no user info; one of the four schemes; no path, query or fragment;
    with `loopback_only`, a loopback IP literal; a password requires a user name; the user name is
    not empty and has no `:` or control character, the password no control character (RFC 7617);
    every exclusion is valid.
  - Credentials: `Proxy-Authorization: Basic` (RFC 7617), built in a zeroizing buffer and marked
    sensitive, set with `Proxy::custom_http_auth`. `Proxy::basic_auth` is not used: it writes the
    password into the proxy URL, which `reqwest` keeps as an ordinary string and prints in its
    `Debug`. The header goes to the proxy only: in the `CONNECT` request, or as a hop-by-hop header
    of a forwarded request. With an `http://` proxy it travels unencrypted to the proxy; provider
    traffic is still TLS inside the tunnel. Limit: `hyper-util` writes the `CONNECT` request into an
    ordinary buffer that is not wiped.
  - SOCKS5 credentials: the username/password method (RFC 1929), which needs both, each not empty,
    together at most 128 bytes (`hyper-util` writes the whole handshake into one 262-byte buffer).
    The only route `reqwest` offers for them is the user info of the proxy URL, so the crate builds
    that URL percent-encoded in a wiped buffer and hands `reqwest` a fresh copy per connection.
    Limit: `reqwest` and `hyper-util` keep plain, unwiped copies of the password for the lifetime of
    a connection attempt; `hyper-util`'s SOCKS5 connector derives a `Debug` that would show them,
    and `reqwest` 0.13.5 never formats it. A test checks that the password is in no error, `Debug`
    output or `tracing` event of the crate; check again when `reqwest` changes.
  - Limits of `reqwest` 0.13.5: through any proxy an `https://` endpoint written as an IPv6 literal
    cannot be reached, and through `socks5://` neither can a plain-HTTP one. Providers' endpoints
    are host names, so this affects tests only.
  - The URL policy, `loopback_only`, the endpoint binding of section 5.2 and the certificate checks
    apply to the request URL as before; the proxy changes none of them. `connect_timeout` covers the
    whole connector: TCP to the proxy, the `CONNECT` exchange and both TLS handshakes.
  - RFC 2136 (DNS over TCP) and the inspector (DNS over UDP and TCP) do not use the proxy.
- No cookie store, no automatic decompression, no HTTP caching.

URL policy for every configurable endpoint (`*_url` settings), enforced in the client constructor:
`https` is always accepted; `http` only when the host is a loopback IP literal (`127.0.0.0/8`,
`[::1]`); host names, including `localhost`, and private addresses require `https`. A URL with user
info, a query or a fragment is refused. With `ContextOptions::loopback_only`, any URL whose host is
not a loopback literal is `Error::Config`; the test suites set it so that a test which forgets to
point a client at a mock fails at construction instead of contacting a provider.

Provider-supplied identifiers placed in a URL path must match `[A-Za-z0-9_-]{1,128}` (or the
provider's documented narrower form); otherwise `Error::Protocol`. Pagination follows cursors, page
numbers and tokens only; a URL returned by the provider is never requested.

### 5.2 Requests and secrets

- A secret is never part of a URL, neither path nor query.
- Header values that carry a secret are built in a zeroizing buffer and marked sensitive
  (`HeaderValue::set_sensitive`). `RequestBuilder::bearer_auth` and `basic_auth` are not used: they
  do mark the header sensitive, but they build its value with an ordinary `format!`, which leaves a
  copy of the secret in memory that is never wiped. A test greps the sources for them.
- A body that carries a secret (password grant, form-encoded password, key exchange) is built in a
  zeroizing buffer and handed to the HTTP client as `bytes::Bytes` that owns that buffer, so a retry
  re-sends the same memory and it is wiped when the last reference drops.
- Form encoding (WHATWG `application/x-www-form-urlencoded`) and percent-encoding of path segments
  and query values are small private functions with tests, not dependency features.
- Credentials go only to the client's own endpoints. A client declares every endpoint it uses (API,
  identity or token service) when it builds its transport handle; a request to any other origin
  (scheme, host, port) is refused with `Error::Config` before a connection is made. A client with a
  static credential or a client certificate cannot be built without a declared endpoint, and a
  request with a cached token is refused when none is declared.
- A TLS client key is held in a buffer that is wiped when the transport handle is built; `rustls`
  receives a copy, parses it with `aws-lc-rs` and drops that copy without wiping it.
- Limit, stated plainly: the response side is not covered by these buffers. An issued token arrives
  in an answer's headers (`X-Subject-Token`) or body; the transport reads bodies into a buffer that
  is wiped when dropped (allocated once when the length is declared), but the HTTP stack's own read
  buffers and the `HeaderMap` of the answer are ordinary memory that is not wiped.

### 5.3 Retries

Each request is marked idempotent or not by the client code. A request is idempotent when executing
it twice leaves the same state as executing it once: reads, deletes of one record by identifier at a
per-record API, token requests, and whole-set replacements that carry a condition the provider
checks. Creating a record and appending a value are not. An unconditional whole-set replacement is
idempotent in the strict sense but is marked "send once" all the same: every automatic repeat would
lengthen the time between the operation's read and its last write, and with it the window in which
another writer's change is overwritten (section 3.4). The same holds for an unconditional delete of
a whole rrset, which can hold values another writer added after the read: it is sent once.

- At most 3 attempts per request, counting the first.
- An idempotent request is retried after a connection or timeout error and after a 5xx answer.
  Back-off before attempt `n + 1` is `500 ms × n` plus a random 0–25 %.
- A non-idempotent request is sent once. Whatever goes wrong becomes the operation's error;
  repeating the operation is safe because it starts with a read (section 3.2).
- 429 and other rate-limit answers: a client declares the answers it treats as rate limits besides
  429 with a classifier (`HttpBuilder::rate_limit`; Route 53 answers HTTP 400 with the codes
  `Throttling`, `ThrottlingException` and `PriorRequestNotComplete`), and such an answer is handled
  exactly like a 429. The wait is taken from `Retry-After` (delay-seconds or an HTTP date in the
  IMF-fixdate form; the obsolete RFC 850 and asctime forms are not read) or `RateLimit-Reset` (a
  value above 10⁹ is a Unix time, as Hetzner sends it, a smaller one delay-seconds). For an
  idempotent request with attempts left and a wait of at most 30 s, the transport sleeps for the
  wait or the back-off, whichever is longer, and retries, so a wait of zero or a time in the past
  does not produce three requests in a few milliseconds; without a header it uses the back-off.
  Otherwise the result is `Error::RateLimited { retry_after }`, with the wait clamped to 24 hours so
  that a caller can add it to an `Instant`.
- A request that fails because a redirect was refused, because `loopback_only` or the endpoint
  binding of section 5.2 blocked it, or because a TLS certificate was refused (the server's, or the
  client certificate by the server) is never retried. A refused certificate is `Error::Config`: the
  next attempt would be refused the same way. It is recognized by the type of the `rustls` error in
  the error's source chain, never by its text.
- A 401 answer to a request made with a cached token (section 5.7) follows the same rule. For an
  idempotent request with attempts left, the transport discards the token, obtains a new one and
  repeats the request; the repeat counts toward the three attempts, and a 401 for the new token is
  `Error::Auth`; so is a 401 for a token fetched during the same call. For a non-idempotent request,
  or when no attempt is left, it discards the token and returns `Error::Transient` ("token
  rejected"); the caller's repeat of the operation starts with a read, which obtains the new token.
  The token is discarded also when the 401 answer is over the size limit. Tokens are renewed well
  before they expire, so this path is for revoked tokens, not for normal expiry.
- A delete of one record by identifier that is answered "not found" counts as done only after a
  fresh read no longer finds the value; while the value is still published the result is
  `Error::Conflict`, because the zone identifier the delete used may be stale (sections 3.5 and
  3.8).
- A request can carry a finisher (`Request::finish_with`), which the transport calls for every
  attempt right before it is sent, with exactly the method, URL and body of that attempt; the
  headers it returns are inserted last. Route 53 signs with it, so every attempt carries its own
  `x-amz-date` and a signature over what is sent. A finisher that fails is the request's error and
  nothing is sent.
- With the context's proxy, for a request that goes through it (its host is not excluded): a refusal
  of the proxy credentials is `Error::ProxyAuth` and is never retried, idempotent or not (its own
  kind by the maintainer's decision of 2026-11-15; before that it was `Config`). The kind is not
  `Auth`, which means the provider's credentials; the next attempt would be refused the same way.
  Three cases map to it. A `407` to `CONNECT`: `hyper-util` reports it as
  `TunnelError::ProxyAuthRequired`, a type in a private module that cannot be named, so the
  transport compares the error's text with that library's constant; the proxy cannot choose the
  text, and the `407` body is never read. A `407` answer to a plain-HTTP request forwarded by an
  HTTP proxy, recognized by its status before the client's kept statuses. A SOCKS5 proxy's refusal
  of the username and password or of every offered authentication method, recognized the same way by
  `hyper-util`'s constant texts; the proxy sends only a status byte. A `407` that arrives through a
  tunnel or a SOCKS5 relay, or from an excluded host, comes from the provider and is handled like
  any other status. Any other failure to get through the proxy (refused or closed `CONNECT`,
  unreachable or stalled proxy) is a connection failure: `Error::Transient` ("could not connect to
  the provider through the proxy"), retried only for an idempotent request. A refused certificate,
  the provider's or an `https://` proxy's, is `Error::Config` as above.
- `Http::try_send` returns, with the error, whether the request certainly never reached the
  provider: refused before any connection (the URL policy, a header value, a failed token fetch or
  finisher), or every attempt failed while its connection was being established (TCP connect or TLS
  handshake, a connect timeout included). A timeout or broken connection after the connection was
  established, any answer, and a refused certificate are never "certainly unsent". With a proxy,
  establishing the connection includes the connection to the proxy and the `CONNECT` exchange: a
  proxy that cannot be reached, stalls, closes, refuses the tunnel or answers `407` to `CONNECT`
  leaves the request certainly unsent. A forwarded plain-HTTP request is written to the proxy once
  the TCP connection stands, so anything after that, a `407` answer included, is not. acme-dns uses
  it to tell a refused write from one whose outcome is unknown (section 11.3). The public `Error`
  carries no such flag.

### 5.4 Responses

- A response body is read up to 4 MiB; a larger one is `Error::Protocol` whose detail names the
  limit. The cap applies to error bodies too.
- Listings read at most 1000 pages; reaching the page limit is `Error::Protocol` whose detail names
  it. Page sizes are the documented maxima where a source states one, otherwise the documented
  default (Cloudflare's record listing states a far larger maximum and uses the default): 1000
  rrsets (Selectel v2), 1000 record sets (Yandex Cloud), 100 records (Cloudflare records, Cloud.ru,
  Timeweb Cloud), 200 (DigitalOcean), 300 rrsets and 100 zones (Route 53), 50 (Hetzner zones and
  rrsets, Cloudflare zones, Yandex 360 records), 10 (Yandex 360 domains). With 1000 pages the
  smallest of these still covers 10 000 entries. A client whose provider returns a whole zone in one
  response (VK Cloud's zone and record listings, reg.ru, nic.ru) is bounded by the 4 MiB cap alone,
  and its rustdoc says so. Raising either constant is not a breaking change. A zone beyond them
  fails to list with an error that says why; it is never returned in part.
- Status mapping shared by all clients unless a client documents an exception: 401 → `Auth`, 403 →
  `Forbidden`, 429 → section 5.3, 5xx → `Transient`, other non-success → the client's classifier,
  which returns `Rejected`, `Conflict`, `ZoneNotFound` or `Protocol`. Providers that answer 200 with
  an error envelope (reg.ru, Beget, nic.ru, Cloudflare's `success: false`) supply a classifier for
  the body.
- Text for a `Detail` is taken from the provider's error message field where the body has a known
  shape, otherwise from the start of the body, and always passes through the scrubber.

### 5.5 Redaction

Each client owns a `Scrubber` (private), created in its constructor from every secret the client
holds. It is the only way to make a `Detail` from dynamic text.

- Registered at construction: every field of the credentials, and the context's proxy password, its
  base64 Basic credentials and, for a SOCKS5 proxy, its percent-encoded form (a forwarding proxy's
  error answer can echo them), each also in its form-encoded and percent-encoded forms, so that a
  value the client sent encoded and the API echoes encoded once more is replaced in place. Private
  key material (a TLS client key, a signing key) is not registered: it is never sent, so no API can
  echo it, and a multi-line PEM document makes needles that match nothing. Registered at run time:
  every token the client obtains (Keystone, IAM, OAuth) and every signed assertion it sends (JWT),
  each under the slot of its source (a token cache, a signer). A slot keeps its current and its
  previous secret, so a client with several token sources never loses the coverage of a live token.
  The transport registers each token it sends; registering the slot's current token again costs a
  comparison.
- Encoded needles, replaced in place: for each secret, the spellings in which an API most often
  echoes it — verbatim; form-urlencoded with `+` and with `%20` for a space; RFC 3986
  percent-encoding (the crate's own URL encoding); as the inside of a JSON string; JSON with `\/`
  and lowercase `\uXXXX` escapes for non-ASCII characters; XML-escaped. Each occurrence is replaced
  by `[redacted]`. Occurrences are found in the original text, overlapping ones included, and
  overlapping or adjacent occurrences become one marker. The spellings are searched longest first.
  Empty secrets are ignored.
- A decoded haystack, for every other dialect: lowercase percent-hex, other percent-encoding safe
  sets (Python, JavaScript, Go), numeric XML character references, escaping of `&` and `<` only,
  uppercase or additional JSON `\u` escapes (Go, .NET), JSON inside JSON, form-encoded JSON. After
  the replacement above, the text is decoded — percent-decoding of either hex case with and without
  `+` for a space, XML entity decoding (named, decimal, hexadecimal), JSON string unescaping — in
  every combination, up to three rounds deep (at most 84 layers). If any needle appears in a decoded
  layer, the whole `Detail` is replaced by a constant text that starts with `[redacted]`. Only the
  part of the text that can reach the `Detail` is decoded: its first 512 bytes plus 12 bytes per
  byte of the longest needle, at most 64 KiB, which bounds the work.
- Text from a JSON body: the client's message field where the body has a known shape; otherwise the
  decoded string values of the JSON document, never its raw text.
- Order: replace encoded needles, check the decoded layers, then replace control characters by
  spaces, then truncate to 512 bytes on a character boundary. Because truncation could otherwise
  expose the head of a secret cut by the limit, a trailing fragment that is a prefix of any
  registered spelling is removed as well.
- Texts with special handling: Route 53 authentication errors can quote the canonical request, so
  only the first sentence of the message is used, and the scrubber runs over the whole body before
  parsing.
- The scrubber holds its needles in zeroizing memory and has a `Debug` that prints nothing.
- Limit, stated plainly: redaction is by substring, on the text and its decoded layers. A secret
  echoed in a transformation not listed above (base64, a hash, a partial value, more than three
  layers of encoding) is not recognized. The defense for those cases is that request bodies and
  headers never enter error text at all; the scrubber covers what the provider sends back.

The same rules apply to `ZoneCheck::detail`.

### 5.6 Tracing

The transport emits one event per HTTP attempt at `DEBUG`, target `zonewright::http`, with the
fields `provider` (the ID), `method`, `path` (URL path, no query string), `status` (absent when
there was no answer), `attempt` and `elapsed_ms`. Nothing else in an HTTP provider client logs a
request. The RFC 2136 client emits its own event per DNS exchange at `DEBUG`, target
`zonewright::rfc2136`, with the fields `op` (the operation), `rcode` (absent when there was no
answer) and `elapsed_ms`.

Never written to `tracing`, at any level: request or response bodies, any header, query strings,
`Detail` text (it is derived from a body), TXT values. The proxy setting adds nothing to the event:
neither the proxy's address nor its credentials are written. (`reqwest` itself writes the proxy's
host and port, never its credentials, to the `log` crate at `DEBUG`; the crate does not forward
`log` records.)

`WARN` events exist for conditions an operator should see and carry no request data: no system CA
certificates; acme-dns about to evict an older value; an inspector name server skipped by the
address policy; a zone listing that holds rrsets the record model cannot represent (target
`zonewright::rrsets`, fields `provider` and `skipped`); a token whose stated lifetime is implausibly
short (field `lifetime_s`, section 5.7).

A test installs a subscriber at `TRACE`, drives a client through success, 401 and 500 paths with
canary credentials, and asserts that the log is not empty and contains none of the canaries (section
12.2).

### 5.7 Shared helpers for provider families

- `TokenSource`: caches a token obtained by an exchange (Keystone password, IAM JWT, OAuth password
  grant, access-key exchange). The fetch returns the token and its lifetime. The token is renewed
  ahead of time: at the expiry minus `max(10 min, 5 % of the lifetime)`, but at most half the
  lifetime, optionally capped by a maximum age (50 min for Yandex Cloud); a token without a stated
  expiry is assumed to live 1 h, and a stated lifetime longer than 30 days is taken as 30 days. A
  short-lived token is therefore still cached for half its life; a lifetime under two minutes (a
  system clock that runs ahead makes a stated expiry look close) is logged as one `WARN` event per
  token, with the lifetime and nothing else. Expiry timestamps are parsed with the private `jiff`
  dependency and turned into a lifetime at once; the `tokio::time::Instant` deadline is computed
  when the token is stored. Single flight: the fetch runs inside the first caller's future while it
  holds the source's async lock, and the others wait for the lock. If that future is dropped
  mid-fetch, the lock is released with nothing stored and the next waiter fetches; there is no
  detached task and no state that a canceled fetch can leave half-written. Every token has a
  generation number, and a 401 invalidates only the generation the failed request used, so a late
  401 for an old token does not discard a fresh one. What happens to the request after a 401 is the
  retry rule of section 5.3. A provider that rejects a token in an answer the transport passes on
  (nic.ru's error 4097 in a `200` body) discards exactly the token that answer was sent with
  (`TokenSource::discard_rejected`: every response to a request with a cached token records the
  token's generation). A connection check forces a new exchange with `TokenSource::renew`, which
  discards the cached token and fetches under the source's lock, so a cached token never stands in
  for credentials that are no longer accepted.
- `Keystone`: the OpenStack Identity v3 password exchange with project scope, shared by Selectel v2
  and VK Cloud. The request body, which carries the password, is built once into a zeroizing buffer;
  `401` is `Error::Auth`; so is `400`, and a `200` is accepted like the documented `201`: both are
  assumptions, marked in the code, and neither can cause a write.
- `RateGate`: at most one request per configured interval per client, for providers with
  undocumented limits (reg.ru 1000 ms, Beget 1000 ms, nic.ru 500 ms; `min_request_interval_ms`).
- `Poller`: the bounded polling of section 3.7.
- `pager::collect`: one page loop over a cursor the client defines (page number, offset, token),
  with the hard limit `MAX_PAGES` = 1000 and `Error::Protocol` for a cursor that does not advance;
  the helpers `next_page_of_total` and `next_token` compute the common cursors. Route 53, whose
  cursor is a next name and type, runs its own loop on the same limit.
- `ZoneCache`: section 3.8. Only the read phase is repeated after a stale identifier: the cache runs
  the client's read and returns the identifier it ended with, and the client performs its write
  afterwards, outside the cache, so a write never runs twice. A write answered "not found" evicts
  the entry and fails; the repeat of the operation starts with a read.
- XML reading (Route 53, nic.ru) uses `roxmltree`; XML writing is string building with one escaping
  function.

Time in these helpers is `tokio::time`, so tests run them under a paused clock.
