# zonewright design: Public API

Part of the [zonewright design](./README.md). Section numbers are those of the whole design.

## 2. Public API

Everything below is re-exported from the crate root unless a module path is shown. Names and records
are also reachable through the public modules `name` and `record`; the provider clients and their
configuration types live in `providers::<id>`; `dns01` (section 7) and `inspector` (section 8,
feature `inspector`) are modules too.

### 2.1 Names

One type represents zone names and the owner names of rrsets. Names inside RDATA have a second, more
permissive type, introduced at the end of this section.

- `DomainName`, `NameError` — `src/name.rs`.

Not stated in the rustdoc:

- `DomainName` serializes as the canonical string with the trailing dot and deserializes through
  `parse`. Its `Display` is the same string; `Debug` prints `DomainName("www.example.org.")`.
- `NameError` is `#[non_exhaustive]`.

Parsing rules, in order:

1. `"."` is the root.
2. The input is not trimmed. An ASCII character other than a letter, a digit, `-`, `_`, `*` and `.`
   is `BadCharacter` before any other processing, so leading or trailing whitespace is
   `BadCharacter`; callers trim where their source needs it. One trailing dot is removed if present;
   an empty remainder is `Empty`. A name with and without the trailing dot parses to the same value:
   every `DomainName` is absolute. Relative names enter only through `from_relative`.
3. All input goes through the same IDNA processing (`idna::domain_to_ascii`: UTS 46 without the STD3
   ASCII restrictions). ASCII is lowercased, U-labels become A-labels, and a label that starts with
   `xn--` must be valid Punycode whether or not the rest of the name is ASCII. Failure is `Idna`.
   Underscore and `*` pass this step (checked against `idna` 1.1.0) and are judged by rules 5 and 6.
4. Length: at most 253 octets without the trailing dot; each label 1 to 63 octets.
5. Label alphabet: `a`–`z`, `0`–`9`, `-`, `_`. A label does not start or end with `-`. Underscore is
   allowed in any position (`_acme-challenge`, `_dmarc`, `_25._tcp`).
6. `*` is accepted only as the whole leftmost label (`*.example.org.`).

Names that DNS allows but these rules reject (labels with other octets, such as the `/` of RFC 2317
delegations, or a label with a leading hyphen) cannot be owner or zone names in this crate. Names
inside RDATA are a different matter: there the crate has to carry whatever a zone contains, such as
an SOA mailbox `first\.last.example.org.` or a CNAME target with unusual labels. They have their own
type with a permissive grammar, `TargetName`.

There is no separate zone type. Functions that take a zone reject the root and wildcard names with
`Error::InvalidInput`. `Ord` is byte order of the canonical string, not DNSSEC canonical order; it
exists so names can be map keys and sorted deterministically.

- `TargetName` — `src/name.rs`, with `From<DomainName>` and `From<&DomainName>`.

Not stated in the rustdoc: `Display`, `Debug`, `FromStr`, `Serialize` and `Deserialize` behave as
for `DomainName`; `Debug` prints `TargetName("…")`.

`TargetName` accepts labels of 1 to 63 arbitrary octets and names of at most 255 octets in wire
form. Its canonical text and the one rule that serves both wire data and provider text are in
section 4.2. A `DomainName` is always a valid `TargetName`; the reverse conversion can fail.

### 2.2 Record model

- `RecordType` — `src/record/rtype.rs`: the constants `A`, `AAAA`, `NS`, `CNAME`, `SOA`, `PTR`,
  `MX`, `TXT`, `SRV`, `DNAME`, `CAA`, `TLSA`, `SSHFP`, `SVCB`, `HTTPS` and the pseudo-types `ALIAS`,
  `ANAME`; `from_code` and `code`; `FromStr`, `Display`, `Debug`, `Serialize`, `Deserialize`.

Not stated in the rustdoc: `RecordType` serializes as its `Display` form and deserializes through
`FromStr`.

The crate carries the complete mnemonic table of the IANA "Resource Record (RR) TYPEs" registry as
of the release, as a hand-maintained table (`MNEMONICS` in `record/rtype.rs`) with the registry's
date and source recorded next to it; the `RecordType` constants are only the types that also have a
canonical form (section 4.3). `Display` prints the registry mnemonic for a registered code and
`TYPE<code>` (RFC 3597) for any other. One departure: code 255, which the registry spells `*`, is
printed as `ANY`; both `ANY` and `*` are accepted on input. `FromStr` is case-insensitive and
accepts the registry mnemonics, the two pseudo-type names and `TYPE<code>`; `TYPE1` and `A` are the
same value. Any other string is an error: a typo is not a new type. A code the registry does not
know yet is always expressible as `TYPE<code>`. Refreshing the table changes how a code is printed
and parsed, not which values exist.

A provider can still report a type under a name that is neither in the registry nor one of the
pseudo-types (a product-specific record kind). Such an rrset cannot be a `RrSet`; a listing reports
it separately instead of dropping it (`ZoneListing::skipped`, section 2.6).

Code 0, OPT (41) and the range 128 ..= 255 that RFC 6895 section 3.1 reserves for query and meta
types (TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY and future ones) are representable but rejected by
every operation with `Error::InvalidInput`.

- `Ttl`, `RrsetTtl` — `src/record/ttl.rs`.

Not stated in the rustdoc: `Ttl` serializes as an integer number of seconds.

TTL is an integer type, not `Duration`: a DNS TTL has no sub-second part and a 31-bit range, and a
`Duration` field would admit values that cannot be sent. The conversions keep `std::time` available
at the boundary (decision 7). `RrsetTtl` adds the one thing a number cannot say: that the rrset has
no TTL of its own and the provider's default applies. It is a separate type so that `Ttl` stays the
number everywhere else (inspector answers, `TtlSupport` bounds), and no number is reserved to mean
"default" (`0` and `1` are valid TTLs).

- `RecordData` — `src/record/data.rs`.
- `RrSet` — `src/record/rrset.rs`.
- `RecordError` — `src/record/mod.rs`.

Not stated in the rustdoc: `RecordData` has no `Deserialize`, because the type is needed to parse
it. `Display` is the text, `Debug` prints `RecordData("…")` or `RecordData(raw "…")`.

`RecordError::Syntax::detail` describes the position and kind of the problem and never quotes the
input.

`RecordData` does not know its type; the rrset does. `RrSet::new` therefore validates each canonical
member against the set's type: it parses the member's text with `RecordData::parse(rtype, …)` and
requires the identical text, otherwise `Syntax`. That rejects MX data in an A set and data that is
canonical for another type only. Non-canonical members are taken as they are.

Equality and hashing of `RecordData` use the text and the canonical flag. Deserialization restores
exactly what was serialized: a `{ "raw": … }` member stays non-canonical and is never parsed,
because a client may keep text the strict parser accepts as non-canonical where its provider's
reading of that text is not established (section 4.9). A non-canonical value never equals a
canonical one, also when their texts are equal. Deserializing a set with `raw` members is the only
public way to obtain non-canonical data; it exists so that a listed set survives a round trip
through an application's storage. Section 4.9 limits what a write accepts.

`RrSet::ttl()` is `Option<RrsetTtl>`, with one meaning for reads and writes:

- `Some(Explicit(n))`: a TTL of `n` seconds. In a write, a request for `n`.
- `Some(ProviderDefault)`: the rrset has no TTL of its own; the provider's default applies. In a
  write, a request for that, refused where `Capabilities::provider_default_ttl` does not allow it
  (section 3.6).
- `None`: no TTL is stated. In a set read, the read cannot tell (an answer without the field, a
  value outside the model's range). In a write, nothing is requested: an existing rrset keeps its
  TTL and a new one gets the client's `ttl` setting (section 3.6).

So a set read from a provider and written back unchanged keeps its TTL in every case: a number stays
that number, the provider's default stays the default and never acquires a number, and an unstated
TTL is left as the provider has it.

`RrSet == RrSet` compares name, type, members and TTL. `RrSet::new` does not check DNS rules that
span rrsets (CNAME next to other data, records at the apex); the provider is the judge of those.

### 2.3 Typed records

Typed views exist for the types named in decision 9, and for TXT. Each converts to and from
`RecordData` in the canonical form of section 4. They are plain data: the fields of MX, SRV, CAA and
TLSA are fixed by their RFCs, so these structs are exhaustive.

- `Txt` — `src/record/txt.rs`.
- `Mx` — `src/record/mx.rs`.
- `Srv` — `src/record/srv.rs`.
- `Caa` — `src/record/caa.rs`.
- `Tlsa` — `src/record/tlsa.rs`.
- `Svcb`, `SvcParam` — `src/record/svcb.rs`.

Each has `to_data` and `from_data`. `SvcParam` is `#[non_exhaustive]`.

`to_data` fails only for field values that have no valid encoding (a CAA tag outside `[a-z0-9]`,
duplicate SVCB parameter keys, data too long). `from_data` fails with `NotCanonical` for raw
provider text and with `Syntax` when the text is not valid RDATA of the struct's type. Because
`RecordData` carries no type, data of another type whose text happens to parse is accepted; taking
the data from an `RrSet` of the right type is what makes the conversion meaningful. `Svcb::to_data`
produces data valid for both `RecordType::SVCB` and `RecordType::HTTPS`.

### 2.4 Provider identifiers

- `ProviderId`, `UnknownProviderId` — `src/id.rs`.

`as_str` and `parse` are hand-written `match` expressions over this table and are the only place the
strings exist. The serde impls call them; no derive with rename rules is used, because a derived
spelling can drift from a persisted one without a compile error.

| Variant        | String          | Cargo feature   |
| -------------- | --------------- | --------------- |
| `AcmeDns`      | `acme_dns`      | `acme_dns`      |
| `Beget`        | `beget`         | `beget`         |
| `CloudRu`      | `cloud_ru`      | `cloud_ru`      |
| `Cloudflare`   | `cloudflare`    | `cloudflare`    |
| `DigitalOcean` | `digitalocean`  | `digitalocean`  |
| `Hetzner`      | `hetzner`       | `hetzner`       |
| `Nicru`        | `nicru`         | `nicru`         |
| `Regru`        | `regru`         | `regru`         |
| `Rfc2136`      | `rfc2136`       | `rfc2136`       |
| `Route53`      | `route53`       | `route53`       |
| `SelectelV2`   | `selectel_v2`   | `selectel_v2`   |
| `TimewebCloud` | `timeweb_cloud` | `timeweb_cloud` |
| `VkCloud`      | `vk_cloud`      | `vk_cloud`      |
| `Yandex360`    | `yandex_360`    | `yandex_360`    |
| `YandexCloud`  | `yandex_cloud`  | `yandex_cloud`  |

A test parses `PROVIDERS.md` and asserts that its set of IDs equals `ProviderId::ALL` and that the
IDs under "Verified against the live API" are exactly those whose metadata has `verified == true`
(section 12.3).

### 2.5 Provider metadata and capabilities

Metadata is static data, present for every provider in every build. An application can show a
configuration form or decide what to offer for a provider whose client is not compiled in.

- `ProviderMeta`, `ConfigField`, `FieldKind`, `Capabilities`, `TypeSet`, `Preconditions`,
  `TtlSupport`, `ProviderDefaultTtl`, `ValueGuarantee` — `src/meta.rs`.
- `Operation` — `src/error.rs`.

Not stated in the rustdoc:

- `Capabilities::can_read`: `TypeSet::AnyWithCode` excludes the pseudo-types, which have no code
  (section 2.2).
- `ProviderDefaultTtl::ForNewRecords` is the level of Timeweb Cloud.
- `ProviderDefaultTtl::Requestable` is the level of Cloudflare, Hetzner, nic.ru, and both providers
  whose `TtlSupport` is `NotSettable`, whose TTL is always the provider's.

Capabilities are per provider, not per client instance, and describe this version of the crate: a
provider without record-level operations in this crate (acme-dns, Beget) has `list_rrsets == false`
and so on. They are the same whether or not the provider's feature is enabled.

An unsupported operation is reported in exactly one way:
`Err(Error::Unsupported { provider, operation })`, or
`Err(Error::UnsupportedRecordType { provider, rtype })` for a type outside `record_types` or a write
to a read-only type. Both are returned before any network request. A client never panics on an
unsupported call and never answers it with a success value. A conformance test calls every operation
whose capability flag is false and asserts the error and zero requests (section 12.3).

### 2.6 The provider trait

- `Provider` — `src/provider.rs`.

`id` and `check` are the only methods without a default body. Every other method has a default that
returns `Error::Unsupported` for its operation, so a client implements exactly what its capabilities
announce. The trait is declared with `-> impl Future<Output = …> + Send` so the futures are `Send`
by contract; implementations write `async fn`. There is no `async-trait` and no `dyn Provider`. The
checks every operation makes before any request, and their order, are in section 3.1.

The trait is not sealed: an application can implement it for a test double. Everything an
implementation has to return can be built outside the crate: the report types below have `new`
constructors, and `Error` has a constructor function for each kind (section 2.9). Adding a method
with a default body is not a breaking change; adding a required method is (section 13.2).

- `Expect`, `SetOutcome`, `DeleteOutcome`, `AddOutcome`, `RemoveOutcome`, `CheckReport`,
  `ZoneCheck`, `ZoneInfo`, `ZoneListing`, `SkippedRrset`, `SkipReason` — `src/provider.rs`.

### 2.7 Dispatch

- `AnyProvider`, with `AnyProvider::from_json`, `impl Provider for AnyProvider` and one `From<…>`
  impl per client — `src/providers/mod.rs`.

`from_json` returns `Error::NotCompiled { provider }` for an ID whose feature is off. With no
provider feature enabled the enum has no variants; it still compiles and `from_json` returns
`NotCompiled` for every ID. Forwarding is generated by one private macro that expands to a `match`
with a `#[cfg]` on each arm.

### 2.8 Configuration, credentials and the shared context

- `Context`, `ContextOptions`, `HttpProxy`, `TrustRoots` — `src/context.rs`.

Not stated in the rustdoc:

- The proxy rules, including what `proxy` and `exclusions` accept, are in section 5.1.
- `HttpProxy`'s `Debug` shows the URL, withheld if it contains `@`, and whether credentials are set
  (a code comment in the `Debug` impl in `src/context.rs`, not rustdoc).

`ContextOptions` selects the certificate authorities of HTTPS (section 5.1): `trust_roots`, a
`TrustRoots` (`Mozilla`, the default: Mozilla's roots compiled in; `Platform`: the operating
system's trust store, with the `platform-verifier` feature; `None`: only the roots the options add),
`russian_trusted_root` (default false: the compiled-in Russian Trusted Root CA in addition), and
`extra_root_certificates` (DER certificates in addition to both). `TrustRoots` has its three
variants in every build, like `ContextOptions` itself, and no type of `rustls`, `rustls-pki-types`
or `webpki-roots` appears in these signatures.

`Context::new` checks the options and fails with `Error::Config` for an empty or longer user agent
suffix or one outside printable ASCII, a zero timeout, and, when an HTTP provider is compiled in, an
extra root certificate that is not a usable DER trust anchor, `TrustRoots::Platform` without the
`platform-verifier` feature, `TrustRoots::None` with no root added by the options, or a proxy
setting that section 5.1 refuses (a SOCKS5 proxy without the `socks` feature included). It makes no
connection and needs no `tokio` runtime.

The proxy setting is a struct rather than a URL string so that the proxy password lives in a
`SecretString` like every other credential: a URL with embedded user info would carry it as plain
text, and is refused for that reason with a fixed text that does not repeat the URL.

The application creates one `Context` per process and builds every client from it. Per-name
serialization (hard rule 2) holds between clients that share a `Context` and not between clients
built from different ones (section 3.3).

Each provider module has the same three public types (Yandex Cloud adds `AuthorizedKey`, the typed
form of its key file). Examples in the source: one provider with a static token and one with
required settings.

- `CloudflareConfig`, `CloudflareCredentials`, `Cloudflare` — `src/providers/cloudflare/config.rs`
  and `src/providers/cloudflare/client.rs`.
- `SelectelV2Config::new` — `src/providers/selectel_v2/config.rs`.
- `AuthorizedKey` — `src/providers/yandex_cloud/config.rs`.

Rules that hold for every provider module:

- Type names are the provider ID in upper camel case: `AcmeDns`, `CloudRu`, `DigitalOcean`,
  `Rfc2136`, `SelectelV2`, `TimewebCloud`, `VkCloud`, `Yandex360`, `YandexCloud`, with `…Config` and
  `…Credentials`.
- Two ways to build a client, giving the same result. An application that stores
  `(provider ID, settings JSON, credentials JSON)` calls `AnyProvider::from_json`. An application
  with typed values builds `…Config` and `…Credentials` and calls `…::new`, then `AnyProvider::from`
  if it wants the enum. `from_json` is exactly: deserialize both objects, call `new`.
- `…Config` rejects unknown keys. A key that belongs to the application (its own timeout, a label)
  must be removed before the JSON reaches the crate. Settings keys and the keys of the credentials
  object are a compatibility surface once released, because applications persist them: a key is
  never renamed or given a different meaning. The keys of the earlier TXT-only implementation are
  kept where a provider had one (section 11.3 lists the differences).
- `…Credentials` holds every field in a `secrecy` wrapper (optional secrets as
  `Option<SecretString>`, Yandex Cloud's key as `AuthorizedKey`, a struct of wrapped fields),
  including values that are identifiers rather than secrets but arrive in the secret object. A
  credentials type with optional secrets has a second constructor that takes them
  (`RegruCredentials::with_client_certificate`, `Route53Credentials::with_session_token`). It
  implements `Deserialize` and nothing that can print or serialize its contents; unknown keys are
  ignored. A credentials object that does not deserialize yields `Error::Config` with a fixed text
  naming the expected keys, never the deserializer's message, which can quote input.
- No configuration error quotes a value. A settings object that does not deserialize yields
  `Error::Config` whose text is fixed apart from the line and column of the problem and, for a
  missing required key, that key's name (a constant of the crate). An unknown key is reported by
  position, not by name. A setting that fails validation is named by its key; its value is not
  repeated, so a `base_url` refused because it carries user info cannot leak the password in it.
  These texts are built from constants and numbers before any scrubber exists, which is safe for
  exactly that reason.
- Defaults are declared per field (`#[serde(default = "…")]`). A config in which every field has a
  default may use the container-level `#[serde(default)]` with a hand-written `Default`, as
  `CloudflareConfig` does. A config with required fields has no `Default` impl and no
  container-level default, so a missing required key is an error, not an empty string. Yandex
  Cloud's requirement is one of two keys (`folder_id` or `zone_ids`): its config has per-field
  defaults, a `Default` impl and a `new(folder_id)`, and the client's `new` checks that one of the
  two is set.
- `new` validates everything that can be validated without the network: URL policy (section 5.1),
  ranges, identifier formats, key material. It makes no request.
- A client type implements `Debug` by hand, printing non-secret settings only. It does not implement
  `Display`, `Serialize` or `Clone`. A compile-time test asserts the absence of `Display` and
  `Serialize` for every client and credentials type (section 12.2).
- Fields that hold a default TTL are named `ttl`; fields that override an endpoint end in `_url`;
  polling intervals end in `_poll_ms`; request spacing is `min_request_interval_ms`.
- Every `ttl` setting has the type `RrsetTtl` and the metadata kind `FieldKind::Ttl`. It is a number
  of seconds within the provider's bounds, or the string `"provider_default"`, which is accepted
  exactly where `Capabilities::provider_default_ttl.can_request()` holds and is `Error::Config`
  naming the key elsewhere. Earlier values keep their meaning: every number means what it meant
  (Cloudflare's `1`, the API's "automatic", is the provider's default); a missing key is the
  provider's documented default (Timeweb Cloud: the provider's default); `null` keeps its
  per-provider meaning where one was accepted (RFC 2136: the default 60; Timeweb Cloud: the
  provider's default) and is refused elsewhere. `null` is not the spelling of the provider's default
  because RFC 2136 already reads it as "the default number", and in `RrSet` it means "not stated".
  All providers share the type, so a provider that later gains a write form for its default changes
  what validation accepts, not a public field's type.

### 2.9 Errors

- `Error`, `ErrorKind`, `Operation`, `ProviderCode` — `src/error.rs`.
- `Detail` — `src/redact.rs`.

Properties:

- `Error` is `Clone + Send + Sync + 'static`. It has no `source()`: the errors of the HTTP stack are
  not exposed, and their text can contain a URL with a query string.
- `Detail` is at most 512 bytes and contains no control characters, whoever built it.
- Inside the crate a `Detail` comes from three places: a constant text; text composed only of
  constants, static key names and numbers (`Error::settings_syntax`, the transport's configuration
  errors); or `Scrubber::detail(&str)`, which applies the redaction of section 5.5 before the
  bounding. Provider clients do not call `Detail::new` or the public `Error` constructors that take
  text; a source scan in the conformance tests fails if a file under `src/providers/` does. This is
  the mechanism behind hard rule 1 for errors; the tests of section 12.2 check its result.
- `Detail::new` and the `Error` constructors are public so that the trait can be implemented outside
  the crate (a test double has to return errors). They bound and clean the text and nothing more.
  There is no scrubber behind them, so keeping secrets out of that text is the caller's duty.
- Request bodies and request headers never contribute to a `Detail`.
- `ErrorKind::as_str` is what an application maps to its own error codes. The identifiers are part
  of the public API.
- `Error::Rejected` and `Error::InvalidInput` carry `code: Option<ProviderCode>`, the provider's own
  code for the refusal; `Error::provider_code()` returns it, and `None` for every other kind. A
  `ProviderCode` is 1 to 64 bytes of ASCII letters, digits and `_ - . :`; a numeric code is written
  in decimal. It has no public constructor, so an error built outside the crate has none. Inside the
  crate it is taken only from the field the provider's documentation (or lego, or its client code)
  names as the error code, and built only by `Scrubber::code`, which drops the code when scrubbing
  would change it in any way and then applies the alphabet and length check. A code is never cut or
  altered, only kept or dropped. The value belongs to the provider and is only as stable as the
  provider keeps it, so an application matches on `(ProviderId, code)` and treats `ErrorKind` as the
  primary classification. `None` means the provider gave no code, the crate does not read one for
  that provider, or the client refused the request itself.
- Retryability is a property of the kind. `Transient` after a write means the write may or may not
  have happened; every operation is safe to repeat (section 3.2). `PreconditionFailed` is not
  retryable and `Conflict` is: the first is the caller's expectation being wrong, the second a race
  the next attempt resolves by reading again.

The inspector has its own error type (section 8.2); names and records have `NameError` and
`RecordError`. None of them wraps a third-party type.
