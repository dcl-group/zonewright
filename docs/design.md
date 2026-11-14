# zonewright design

Status: proposal for review. No crate code exists yet. This document is what the crate is
implemented from; where it and the code later disagree, one of them is fixed in the same change.

Binding rules live in [`AGENTS.md`](../AGENTS.md) (settled decisions, hard rules, engineering
rules). They are referred to here as "decision N" and "hard rule N" and are not repeated. The list
of providers and their state is [`PROVIDERS.md`](../PROVIDERS.md).

Conventions used below:

- "Client" is the code that talks to one provider. "Application" is the program that uses the crate.
- "An earlier TXT-only implementation" and "an earlier record-level implementation" are the two
  bodies of prior code this crate replaces. They are sources of behavior, not of API shape.
- Code blocks are the intended public signatures. Private items are described in prose.
- Facts about dependencies were checked on 2026-11-14 against the published crate sources; the
  checks that were run are listed in section 9.4.

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
  and for three providers (acme-dns, nic.ru, Timeweb Cloud) a small memory of its own writes, owned
  by `Context` (section 11.3). Losing that state on restart never leads to a wrong write. In one
  case it leaves work for a person: a nic.ru zone left with this process's staged, uncommitted
  changes has to be committed by hand.

Explicitly not in the crate: ACME, certificate-authority policy checks (including CAA tree climbing,
section 7.4), mail-specific record construction, metrics, any UI text beyond the English labels of
configuration fields.

## 2. Public API

Everything below is re-exported from the crate root unless a module path is shown.

### 2.1 Names

One type represents zone names and the owner names of rrsets. Names inside RDATA have a second, more
permissive type, introduced at the end of this section.

```rust
/// An absolute domain name in canonical form: lowercase ASCII (A-labels), every label valid,
/// stored with the trailing dot. The root name is ".".
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainName(/* private */);

impl DomainName {
    pub fn parse(s: &str) -> Result<DomainName, NameError>;
    /// `relative` is a zone-file style name relative to `origin`: "" or "@" is the origin itself,
    /// "www" is "www.<origin>". A name ending in a dot is taken as absolute.
    pub fn from_relative(relative: &str, origin: &DomainName) -> Result<DomainName, NameError>;
    pub fn root() -> DomainName;

    /// With the trailing dot: "www.example.org.". The root is ".".
    pub fn as_str(&self) -> &str;
    /// Without the trailing dot: "www.example.org". The root is "".
    pub fn without_dot(&self) -> &str;
    /// U-label form for display and for provider APIs that store Unicode names. Falls back to the
    /// A-label form for labels that do not decode.
    pub fn to_unicode(&self) -> String;

    pub fn is_root(&self) -> bool;
    /// The leftmost label is "*".
    pub fn is_wildcard(&self) -> bool;
    pub fn label_count(&self) -> usize;
    /// Labels from the leftmost to the rightmost, without dots.
    pub fn labels(&self) -> impl Iterator<Item = &str>;

    /// `self` equals `zone` or is below it. Compared label by label, never by string suffix.
    pub fn is_within(&self, zone: &DomainName) -> bool;
    /// The part of `self` left of `zone`, without the separating dot; "" when `self == zone`;
    /// `None` when `self` is not within `zone`.
    pub fn relative_to(&self, zone: &DomainName) -> Option<&str>;
    /// The name without its leftmost label; `None` for the root.
    pub fn parent(&self) -> Option<DomainName>;
    pub fn prepend(&self, label: &str) -> Result<DomainName, NameError>;
}

impl std::str::FromStr for DomainName { type Err = NameError; }
impl std::fmt::Display for DomainName {}   // same as as_str()
impl std::fmt::Debug for DomainName {}     // DomainName("www.example.org.")
impl serde::Serialize for DomainName {}    // as_str()
impl<'de> serde::Deserialize<'de> for DomainName {}  // through parse()

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    Empty,
    TooLong,            // more than 253 octets without the trailing dot
    BadLabelLength,     // a label is empty or longer than 63 octets
    BadCharacter,
    BadHyphen,          // a label starts or ends with "-"
        BadWildcard,        // "*" anywhere but as the whole leftmost label
    Idna,
    BadEscape,          // TargetName only: a malformed "\DDD" or a trailing "\"
}
```

Parsing rules, in order:

1. The input is not trimmed. Leading or trailing whitespace is `BadCharacter`; callers trim where
   their source needs it.
2. `"."` is the root. Otherwise one trailing dot is removed if present; an empty remainder is
   `Empty`. A name with and without the trailing dot parses to the same value: every `DomainName` is
   absolute. Relative names enter only through `from_relative`.
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

```rust
/// An absolute domain name as it occurs inside RDATA: any label contents DNS allows.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TargetName(/* private */);

impl TargetName {
    /// Presentation format (RFC 1035 section 5.1) with the escapes `\DDD` and `\X`.
    /// A name without a trailing dot is taken as absolute.
    pub fn parse(s: &str) -> Result<TargetName, NameError>;
    /// Zone-file semantics: "@" is `origin`; a name without a trailing dot is below `origin`.
    pub fn from_relative(relative: &str, origin: &DomainName) -> Result<TargetName, NameError>;
    /// From one uncompressed wire-format name.
    pub fn from_wire(name: &[u8]) -> Result<TargetName, NameError>;
    pub fn root() -> TargetName;
    /// Canonical text with the trailing dot (section 4.2).
    pub fn as_str(&self) -> &str;
    pub fn is_root(&self) -> bool;
    /// `Some` when the name also satisfies the owner-name rules above.
    pub fn to_domain_name(&self) -> Option<DomainName>;
}
impl From<DomainName> for TargetName {}
impl From<&DomainName> for TargetName {}
// Display, Debug, FromStr, Serialize and Deserialize as for DomainName.
```

`TargetName` accepts labels of 1 to 63 arbitrary octets and names of at most 255 octets in wire
form. Its canonical text and the one rule that serves both wire data and provider text are in
section 4.2. A `DomainName` is always a valid `TargetName`; the reverse conversion can fail.

### 2.2 Record model

```rust
/// A DNS record type: any 16-bit type code, plus the provider pseudo-types that have no code.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordType(/* private */);

impl RecordType {
    pub const A: RecordType;      pub const AAAA: RecordType;  pub const NS: RecordType;
    pub const CNAME: RecordType;  pub const SOA: RecordType;   pub const PTR: RecordType;
    pub const MX: RecordType;     pub const TXT: RecordType;   pub const SRV: RecordType;
    pub const DNAME: RecordType;  pub const CAA: RecordType;   pub const TLSA: RecordType;
    pub const SSHFP: RecordType;  pub const SVCB: RecordType;  pub const HTTPS: RecordType;
    /// Provider pseudo-types: address records synthesized from a target name. No type code.
    pub const ALIAS: RecordType;  pub const ANAME: RecordType;

    pub const fn from_code(code: u16) -> RecordType;
    /// `None` for pseudo-types.
    pub const fn code(self) -> Option<u16>;
}

impl std::str::FromStr for RecordType { type Err = RecordError; }
impl std::fmt::Display for RecordType {}
impl std::fmt::Debug for RecordType {}
impl serde::Serialize for RecordType {}              // the Display form
impl<'de> serde::Deserialize<'de> for RecordType {}  // through FromStr
```

The crate carries the complete mnemonic table of the IANA "Resource Record (RR) TYPEs" registry as
of the release, as a generated table with the registry's date recorded in the source; the constants
above are only the types that also have a canonical form (section 4.3). `Display` prints the
registry mnemonic for a registered code and `TYPE<code>` (RFC 3597) for any other. `FromStr` is
case-insensitive and accepts the registry mnemonics, the two pseudo-type names and `TYPE<code>`;
`TYPE1` and `A` are the same value. Any other string is an error: a typo is not a new type. A code
the registry does not know yet is always expressible as `TYPE<code>`. Refreshing the table changes
how a code is printed and parsed, not which values exist.

A provider can still report a type under a name that is neither in the registry nor one of the
pseudo-types (a product-specific record kind). Such an rrset cannot be a `RrSet`; a listing reports
it separately instead of dropping it (`ZoneListing::skipped`, section 2.6).

Query-only and meta types (OPT, TSIG, TKEY, IXFR, AXFR, ANY) are representable but rejected by every
operation with `Error::InvalidInput`.

```rust
/// Time to live in seconds, 0 ..= 2^31 - 1 (RFC 2181 section 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ttl(/* private u32 */);

impl Ttl {
    pub const MAX: Ttl;
    pub fn from_secs(secs: u32) -> Result<Ttl, RecordError>;
    pub const fn as_secs(self) -> u32;
}
impl From<Ttl> for std::time::Duration {}
impl TryFrom<std::time::Duration> for Ttl { type Error = RecordError; }  // whole seconds only
// Serialize / Deserialize as an integer number of seconds.
```

TTL is an integer type, not `Duration`: a DNS TTL has no sub-second part and a 31-bit range, and a
`Duration` field would admit values that cannot be sent. The conversions keep `std::time` available
at the boundary (decision 7).

```rust
/// The RDATA of one record in normalized zone-file text form (section 4).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordData(/* private */);

impl RecordData {
    /// Strict parse of presentation-format RDATA. Domain names without a trailing dot are taken
    /// as absolute. Fails for text that is not valid for `rtype`.
    pub fn parse(rtype: RecordType, text: &str) -> Result<RecordData, RecordError>;
    /// Zone-file semantics: a domain name without a trailing dot is relative to `origin`,
    /// and "@" is `origin`.
    pub fn parse_relative(
        rtype: RecordType,
        text: &str,
        origin: &DomainName,
    ) -> Result<RecordData, RecordError>;
    /// From uncompressed wire-format RDATA.
    pub fn from_wire(rtype: RecordType, rdata: &[u8]) -> Result<RecordData, RecordError>;
    /// Wire-format RDATA without name compression. Fails for non-canonical data and pseudo-types.
    pub fn to_wire(&self, rtype: RecordType) -> Result<Vec<u8>, RecordError>;

    pub fn as_str(&self) -> &str;
    /// False for a value a provider returned that the crate could not parse (section 4.9).
    pub fn is_canonical(&self) -> bool;
}
impl std::fmt::Display for RecordData {}  // as_str()
impl std::fmt::Debug for RecordData {}
impl serde::Serialize for RecordData {}   // canonical: a string; otherwise { "raw": text }.
                                          // No Deserialize: the type is needed to parse.

/// All records of one owner name and type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RrSet { /* private */ }

impl RrSet {
        /// `records` must not be empty. Duplicates are removed and the records are kept sorted by
    /// their text, so two sets with the same members are equal. Every canonical member is
    /// parsed again for `rtype` and must give the same text.
    pub fn new(
        name: DomainName,
        rtype: RecordType,
        ttl: Option<Ttl>,
        records: impl IntoIterator<Item = RecordData>,
    ) -> Result<RrSet, RecordError>;

    pub fn name(&self) -> &DomainName;
    pub fn rtype(&self) -> RecordType;
    pub fn ttl(&self) -> Option<Ttl>;
    pub fn records(&self) -> &[RecordData];
    pub fn contains(&self, record: &RecordData) -> bool;
    /// Same name, type and members; TTL ignored.
    pub fn same_records(&self, other: &RrSet) -> bool;
    pub fn with_ttl(self, ttl: Option<Ttl>) -> RrSet;
}
// Serialize / Deserialize as { "name", "type", "ttl", "records": [...] }. A canonical record is a
// string, parsed with RecordData::parse for the set's type; a non-canonical one is
// { "raw": text }.

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecordError {
    UnknownType,                 // RecordType::from_str
    Syntax { detail: String },   // text or wire data not valid for the type
    OutOfRange { field: &'static str },
    TooLong,                     // RDATA would exceed 65535 octets, or a character-string 255
    Name(NameError),             // a domain name inside RDATA
    EmptySet,                    // RrSet::new with no records
    NotSingleton,                // more than one record for CNAME, SOA, DNAME, ALIAS, ANAME
    NotCanonical,                // an operation that needs canonical data got raw provider text
}
```

`RecordError::Syntax::detail` describes the position and kind of the problem and never quotes the
input.

`RecordData` does not know its type; the rrset does. `RrSet::new` therefore validates each canonical
member against the set's type: it parses the member's text with `RecordData::parse(rtype, …)` and
requires the identical text, otherwise `Syntax`. That rejects MX data in an A set and data that is
canonical for another type only. Non-canonical members are taken as they are.

Equality and hashing of `RecordData` use the text and the canonical flag. Within a set the two never
disagree: text that parses for the set's type is stored as canonical, also when it arrives as
`{ "raw": … }` during deserialization. Deserializing a set with `raw` members is the only public way
to obtain non-canonical data; it exists so that a listed set survives a round trip through an
application's storage. Section 4.9 limits what a write accepts.

`RrSet::ttl()` is `Option<Ttl>`:

- in a set read from a provider, `None` means the provider does not report a TTL for it;
- in a set passed to a write, `None` means "keep the TTL of the existing rrset; for a new rrset use
  the client's configured default" (section 3.6).

`RrSet == RrSet` compares name, type, members and TTL. `RrSet::new` does not check DNS rules that
span rrsets (CNAME next to other data, records at the apex); the provider is the judge of those.

### 2.3 Typed records

Typed views exist for the types named in decision 9, and for TXT. Each converts to and from
`RecordData` in the canonical form of section 4. They are plain data: the fields of MX, SRV, CAA and
TLSA are fixed by their RFCs, so these structs are exhaustive.

```rust
/// TXT data as one byte string: the concatenation of the record's character-strings.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Txt(/* private Vec<u8> */);
impl Txt {
    /// At most 65279 octets (the most that fits one RDATA after splitting into 255-octet
    /// character-strings). Empty data is allowed.
    pub fn new(data: impl Into<Vec<u8>>) -> Result<Txt, RecordError>;
    pub fn as_bytes(&self) -> &[u8];
    /// `Some` when the data is valid UTF-8.
    pub fn as_str(&self) -> Option<&str>;
    /// 1 ..= 255 octets, each in 0x21 ..= 0x7E and none of them `"` or `\`.
    /// ACME DNS-01 values are plain.
    pub fn is_plain(&self) -> bool;
}

pub struct Mx  { pub preference: u16, pub exchange: TargetName }
pub struct Srv { pub priority: u16, pub weight: u16, pub port: u16, pub target: TargetName }
pub struct Caa { pub flags: u8, pub tag: String, pub value: Vec<u8> }
impl Caa { pub const CRITICAL: u8 = 0b1000_0000; pub fn is_critical(&self) -> bool; }
pub struct Tlsa { pub usage: u8, pub selector: u8, pub matching_type: u8, pub data: Vec<u8> }

/// RDATA shared by SVCB and HTTPS (RFC 9460).
pub struct Svcb { pub priority: u16, pub target: TargetName, pub params: Vec<SvcParam> }

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SvcParam {
    Mandatory(Vec<u16>),
    Alpn(Vec<Vec<u8>>),
    NoDefaultAlpn,
    Port(u16),
    Ipv4Hint(Vec<std::net::Ipv4Addr>),
    Ech(Vec<u8>),
    Ipv6Hint(Vec<std::net::Ipv6Addr>),
    Other { key: u16, value: Vec<u8> },
}

// For each of Txt, Mx, Srv, Caa, Tlsa, Svcb (all derive Clone, Debug, PartialEq, Eq):
impl Mx {
    pub fn to_data(&self) -> Result<RecordData, RecordError>;
    pub fn from_data(data: &RecordData) -> Result<Mx, RecordError>;
}
```

`to_data` fails only for field values that have no valid encoding (a CAA tag outside `[a-z0-9]`,
duplicate SVCB parameter keys, data too long). `from_data` fails with `NotCanonical` for raw
provider text and with `Syntax` when the text is not valid RDATA of the struct's type. Because
`RecordData` carries no type, data of another type whose text happens to parse is accepted; taking
the data from an `RrSet` of the right type is what makes the conversion meaningful. `Svcb::to_data`
produces data valid for both `RecordType::SVCB` and `RecordType::HTTPS`.

### 2.4 Provider identifiers

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ProviderId {
    AcmeDns, Beget, CloudRu, Cloudflare, DigitalOcean, Hetzner, Nicru, Regru, Rfc2136, Route53,
    SelectelV2, TimewebCloud, VkCloud, Yandex360, YandexCloud,
}

impl ProviderId {
    /// Every identifier, in the order of the table in PROVIDERS.md. Complete in every build.
    pub const ALL: &'static [ProviderId];
    /// The persisted string. Never changes for an existing variant.
    pub const fn as_str(self) -> &'static str;
    /// Exact, case-sensitive match of `as_str`.
    pub fn parse(s: &str) -> Option<ProviderId>;
    /// The client for this provider is compiled into this build (its cargo feature is enabled).
    pub const fn available(self) -> bool;
    pub fn meta(self) -> &'static ProviderMeta;
}

impl std::fmt::Display for ProviderId {}             // as_str()
impl std::str::FromStr for ProviderId { type Err = UnknownProviderId; }
impl serde::Serialize for ProviderId {}              // as_str()
impl<'de> serde::Deserialize<'de> for ProviderId {}  // through parse()

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub struct UnknownProviderId(/* private; Display does not echo more than 64 bytes of input */);
```

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

```rust
#[derive(Debug)]
#[non_exhaustive]
pub struct ProviderMeta {
    pub id: ProviderId,
    /// Human-readable name, as in PROVIDERS.md.
    pub name: &'static str,
    /// True only for providers listed under "Verified against the live API" in PROVIDERS.md.
    pub verified: bool,
    /// How long the application should be prepared to wait for a change to reach all name
    /// servers, when the provider is known to need more or less than usual. `None`: no
    /// provider-specific value; the application uses its own default.
    pub default_propagation_timeout: Option<std::time::Duration>,
    /// Every key of the settings object and of the credentials object.
    pub fields: &'static [ConfigField],
    pub capabilities: Capabilities,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct ConfigField {
    /// Key in the JSON object: the credentials object when `secret`, else the settings object.
    pub key: &'static str,
    pub secret: bool,
    pub required: bool,
    pub kind: FieldKind,
    /// Default as text, for display. `None` for required fields and for fields with no default.
    pub default: Option<&'static str>,
    /// English label and one-sentence help text.
    pub label: &'static str,
    pub help: &'static str,
    /// Rarely changed (endpoint overrides, polling intervals).
    pub advanced: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldKind {
    Text,
    /// Long or multi-line text (a PEM block, a JSON document).
    Multiline,
    Url,
    Integer { min: i64, max: i64 },
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Capabilities {
    pub list_zones: bool,
    pub list_rrsets: bool,
    pub get_rrset: bool,
    pub set_rrset: bool,
    pub delete_rrset: bool,
    pub add_txt_value: bool,
    pub remove_txt_value: bool,
    /// Types the record-level operations accept.
    pub record_types: TypeSet,
    /// Types within `record_types` that can be read but not written.
    pub read_only_types: &'static [RecordType],
        /// The TXT value operations accept only `Txt::is_plain` values.
    pub txt_plain_only: bool,
    /// What the TXT value operations guarantee against writers outside this process.
    pub txt_values: ValueGuarantee,
    pub preconditions: Preconditions,
    /// Replacing an rrset is one request at the provider. False where the API works with
    /// individual records and a replacement is several requests.
    pub atomic_rrset_write: bool,
        pub ttl: TtlSupport,
    /// The provider can choose a TTL itself (an "automatic" TTL, or a default it applies when
    /// none is sent). Such an rrset reads as `ttl() == None`.
    pub provider_default_ttl: bool,
    /// Writes complete through a provider-side operation that the client polls.
    pub asynchronous: bool,
}

impl Capabilities {
    pub fn supports(&self, operation: Operation) -> bool;
    pub fn can_read(&self, rtype: RecordType) -> bool;
    pub fn can_write(&self, rtype: RecordType) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TypeSet {
    /// Exactly these types. An empty list: no record-level support.
    Listed(&'static [RecordType]),
    /// Every type that has a type code and a wire form (a protocol-level client such as RFC 2136).
    AnyWithCode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Preconditions {
    /// The provider checks the precondition in the same request that writes.
    Atomic,
    /// The client reads, compares and then writes; a change by another writer between the read
    /// and the write is not detected.
    ReadThenWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TtlSupport {
    /// One TTL per rrset, within the given bounds (seconds).
    PerRrset { min: u32, max: u32 },
    /// The API stores a TTL on every record. The crate writes the same TTL to all records of an
    /// rrset and reports the smallest one it reads.
    PerRecord { min: u32, max: u32 },
    /// The provider chooses the TTL; a requested TTL is refused.
    NotSettable,
}

/// How far "a TXT value operation never overwrites or deletes a foreign value" holds when
/// someone outside this process writes to the same rrset at the same time (section 3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueGuarantee {
    /// Requests name only our value. Foreign values cannot be lost.
    PerValue,
    /// The whole set is written under a condition the provider checks. A concurrent change
    /// makes the write fail instead of being overwritten.
    Conditional,
    /// The whole set is written after a read, unconditionally. A value added by another writer
    /// between the read and the write is lost. Hard rule 2 holds only inside one process.
    ReadThenWrite,
    /// The provider keeps a fixed number of most recent values and drops the oldest (acme-dns).
    Rotating,
        /// The provider has no TXT value operations in this crate.
    NotOffered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Operation {
    Check, ListZones, ListRrsets, GetRrset, SetRrset, DeleteRrset, AddTxtValue, RemoveTxtValue,
}
impl std::fmt::Display for Operation {}  // "check", "list_zones", ...
```

Capabilities are per provider, not per client instance, and describe this version of the crate: a
provider whose record-level client is not written yet has `list_rrsets == false` and so on. They are
the same whether or not the provider's feature is enabled.

An unsupported operation is reported in exactly one way:
`Err(Error::Unsupported { provider, operation })`, or
`Err(Error::UnsupportedRecordType { provider, rtype })` for a type outside `record_types` or a write
to a read-only type. Both are returned before any network request. A client never panics on an
unsupported call and never answers it with a success value. A conformance test calls every operation
whose capability flag is false and asserts the error and zero requests (section 12.3).

### 2.6 The provider trait

```rust
pub trait Provider: Send + Sync {
    fn id(&self) -> ProviderId;

    fn capabilities(&self) -> &'static Capabilities {
        &self.id().meta().capabilities
    }

    /// Verifies the credentials and reports, for each zone, whether it is visible and usable.
    fn check(
        &self,
        zones: &[DomainName],
    ) -> impl Future<Output = Result<CheckReport, Error>> + Send;

    /// Zones in which these credentials can change records.
    fn list_zones(&self) -> impl Future<Output = Result<Vec<ZoneInfo>, Error>> + Send;

    /// Every rrset of the zone, of every type the provider reports.
        fn list_rrsets(
        &self,
        zone: &DomainName,
    ) -> impl Future<Output = Result<ZoneListing, Error>> + Send;

    fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> impl Future<Output = Result<Option<RrSet>, Error>> + Send;

    /// Makes the rrset at `rrset.name()` / `rrset.rtype()` equal to `rrset`.
    fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> impl Future<Output = Result<SetOutcome, Error>> + Send;

    fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        expect: Expect<'_>,
    ) -> impl Future<Output = Result<DeleteOutcome, Error>> + Send;

    /// Adds one value to the TXT rrset at `name` without touching its other values.
    /// `ttl` is used only if the rrset has to be created; `None` is the client's default.
    fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<Ttl>,
    ) -> impl Future<Output = Result<AddOutcome, Error>> + Send;

    /// Removes that one value from the TXT rrset at `name` and nothing else.
    fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> impl Future<Output = Result<RemoveOutcome, Error>> + Send;
}
```

`check` is the only method without a default body. Every other method has a default that returns
`Error::Unsupported` for its operation, so a client implements exactly what its capabilities
announce. The trait is declared with `-> impl Future<Output = …> + Send` so the futures are `Send`
by contract; implementations write `async fn`. There is no `async-trait` and no `dyn Provider`.

The trait is not sealed: an application can implement it for a test double. Everything an
implementation has to return can be built outside the crate: the report types below have `new`
constructors, and `Error` has a constructor function for each kind (section 2.9). Adding a method
with a default body is not a breaking change; adding a required method is (section 13.2).

```rust
/// Precondition of a write, evaluated against the rrset as it is at the provider.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Expect<'a> {
    /// No precondition: create or replace.
    Any,
    /// The rrset must not exist: create only.
    Absent,
        /// The rrset must have exactly these records and, if the given set has a TTL, that TTL.
    /// The given set must have the name and type the operation is about; anything else is
    /// `Error::InvalidInput` before any request.
    Matches(&'a RrSet),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetOutcome { Created, Replaced, Unchanged }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteOutcome { Deleted, NotPresent }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddOutcome {
    /// The rrset did not exist and now holds the value.
    Created,
    /// The rrset existed with other values and now also holds the value.
    Appended,
    /// The value was already there; nothing was written.
    AlreadyPresent,
        /// The value was sent and not refused; the state before and after could not be observed.
    Accepted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoveOutcome {
    /// The value was removed; other values remain.
    Removed,
    /// The value was the only one; the rrset no longer exists.
    RrsetDeleted,
    /// The value was not there; nothing was written.
    NotPresent,
        /// The removal was sent and not refused; the state before and after could not be observed.
    Accepted,
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CheckReport {
    /// The credentials were exercised against the provider and accepted. False only when the
    /// provider offers no request that tests credentials without naming a zone and `zones` was
    /// empty.
    pub credentials_verified: bool,
    /// One entry per requested zone, in the order given.
    pub zones: Vec<ZoneCheck>,
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ZoneCheck {
    pub zone: DomainName,
    /// The zone exists at the provider, is visible to these credentials and accepts changes.
    pub found: bool,
        /// Why the zone is not usable, or a warning about a usable one.
    pub detail: Option<Detail>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ZoneInfo {
    pub name: DomainName,
}

/// The result of `list_rrsets`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ZoneListing {
    /// Sorted by name, then type.
    pub rrsets: Vec<RrSet>,
    /// What the provider reported for the zone but the model cannot hold. Never silently empty:
    /// every such rrset has an entry.
    pub skipped: Vec<SkippedRrset>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkippedRrset {
    pub name: DomainName,
    /// The type as the provider spells it, at most 32 characters, control characters removed.
    pub type_name: String,
    pub reason: SkipReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// The type name is neither a registered mnemonic, nor `TYPE<code>`, nor a pseudo-type.
    UnknownType,
    /// Not a plain rrset: an alias to a provider resource, a routing-policy set and the like.
    NotPlainRecords,
    /// The owner name is not a valid `DomainName` (section 2.1).
    UnsupportedName,
}

impl CheckReport { pub fn new(credentials_verified: bool, zones: Vec<ZoneCheck>) -> CheckReport; }
impl ZoneCheck { pub fn new(zone: DomainName, found: bool, detail: Option<Detail>) -> ZoneCheck; }
impl ZoneInfo { pub fn new(name: DomainName) -> ZoneInfo; }
impl ZoneListing { pub fn new(rrsets: Vec<RrSet>, skipped: Vec<SkippedRrset>) -> ZoneListing; }
impl SkippedRrset {
    pub fn new(name: DomainName, type_name: &str, reason: SkipReason) -> SkippedRrset;
}
```

### 2.7 Dispatch

```rust
/// One client of any provider compiled into this build.
#[derive(Debug)]
#[non_exhaustive]
pub enum AnyProvider {
    #[cfg(feature = "acme_dns")]
    AcmeDns(providers::acme_dns::AcmeDns),
    #[cfg(feature = "beget")]
    Beget(providers::beget::Beget),
    // ... one variant per ProviderId, each behind its feature
}

impl AnyProvider {
    /// Builds the client for `id` from stored configuration: `settings` is the text of a JSON
    /// object with the non-secret fields, `credentials` the text of a JSON object with the
    /// secret fields (see ProviderMeta::fields).
    pub fn from_json(
        id: ProviderId,
        settings: &str,
        credentials: &secrecy::SecretString,
        ctx: &Context,
    ) -> Result<AnyProvider, Error>;
}

impl Provider for AnyProvider { /* forwards every method to the variant */ }
// impl From<providers::cloudflare::Cloudflare> for AnyProvider, and so on for every client.
```

`from_json` returns `Error::NotCompiled { provider }` for an ID whose feature is off. With no
provider feature enabled the enum has no variants; it still compiles and `from_json` returns
`NotCompiled` for every ID. Forwarding is generated by one private macro that expands to a `match`
with a `#[cfg]` on each arm.

### 2.8 Configuration, credentials and the shared context

```rust
/// State shared by all clients of one process: the HTTP client, the per-name locks and the
/// process-local memory of the providers that need one. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Context { /* private Arc */ }

impl Context {
    pub fn new(options: ContextOptions) -> Result<Context, Error>;
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ContextOptions {
    /// Appended to the user agent: "zonewright/<version> <suffix>". At most 128 characters,
    /// printable ASCII.
    pub user_agent_suffix: Option<String>,
    /// TCP and TLS connect timeout. Default 10 s.
    pub connect_timeout: std::time::Duration,
    /// Limit for one HTTP request from start to the end of the body. Default 30 s.
    pub request_timeout: std::time::Duration,
    /// DER-encoded certificates trusted in addition to the platform's roots.
    pub extra_root_certificates: Vec<Vec<u8>>,
    /// Refuse to connect to anything but loopback addresses. For tests. Default false.
    pub loopback_only: bool,
}
impl Default for ContextOptions {}
```

The application creates one `Context` per process and builds every client from it. Per-name
serialization (hard rule 2) holds between clients that share a `Context` and not between clients
built from different ones (section 3.3).

Each provider module has the same three public types. Shown for one provider with a static token and
one with required settings:

```rust
// zonewright::providers::cloudflare — compiled with feature "cloudflare"

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct CloudflareConfig {
    pub base_url: String,   // default "https://api.cloudflare.com/client/v4"
    pub ttl: u32,           // default 120; 1 ("automatic") or 60 ..= 86400
}
impl Default for CloudflareConfig {}

#[derive(Debug, serde::Deserialize)]
#[non_exhaustive]
pub struct CloudflareCredentials {
    pub api_token: secrecy::SecretString,
}
impl CloudflareCredentials {
    pub fn new(api_token: secrecy::SecretString) -> CloudflareCredentials;
}

pub struct Cloudflare { /* private */ }
impl Cloudflare {
    pub fn new(
        config: CloudflareConfig,
        credentials: CloudflareCredentials,
        ctx: &Context,
    ) -> Result<Cloudflare, Error>;
}
impl Provider for Cloudflare {}
impl std::fmt::Debug for Cloudflare {}  // non-secret settings only

// zonewright::providers::selectel_v2 — a config with required fields has a constructor that
// takes them; the remaining fields are public and start at their defaults.
impl SelectelV2Config {
    pub fn new(account_id: String, username: String) -> SelectelV2Config;
}
```

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
- `…Credentials` holds every field in a `secrecy` wrapper, including values that are identifiers
  rather than secrets but arrive in the secret object. It implements `Deserialize` and nothing that
  can print or serialize its contents; unknown keys are ignored. A credentials object that does not
  deserialize yields `Error::Config` with a fixed text naming the expected keys, never the
  deserializer's message, which can quote input.
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
  container-level default, so a missing required key is an error, not an empty string.
- `new` validates everything that can be validated without the network: URL policy (section 5.1),
  ranges, identifier formats, key material. It makes no request.
- A client type implements `Debug` by hand, printing non-secret settings only. It does not implement
  `Display`, `Serialize` or `Clone`. A compile-time test asserts the absence of `Display` and
  `Serialize` for every client and credentials type (section 12.2).
- Fields that hold a default TTL are named `ttl`; fields that override an endpoint end in `_url`;
  polling intervals end in `_poll_ms`; request spacing is `min_request_interval_ms`.

### 2.9 Errors

```rust
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
        /// Settings or credentials are malformed, the context could not be built, or it cannot do
    /// what is asked of it (no CA certificates to verify an HTTPS endpoint with).
    #[error("invalid provider configuration: {detail}")]
    #[non_exhaustive]
    Config { detail: Detail },

    #[error("provider {provider} is not compiled into this build")]
    #[non_exhaustive]
    NotCompiled { provider: ProviderId },

    #[error("provider {provider} does not support {operation}")]
    #[non_exhaustive]
    Unsupported { provider: ProviderId, operation: Operation },

    #[error("provider {provider} does not support record type {rtype}")]
    #[non_exhaustive]
    UnsupportedRecordType { provider: ProviderId, rtype: RecordType },

    /// The request cannot be sent as given: a value the provider's encoding cannot carry, a TTL
    /// outside the provider's range, a wildcard zone, an rrset over the provider's size limit.
    #[error("invalid request: {detail}")]
    #[non_exhaustive]
    InvalidInput { detail: Detail },

    #[error("name {name} is outside zone {zone}")]
    #[non_exhaustive]
    NameOutsideZone { name: DomainName, zone: DomainName },

    #[error("zone {zone} not found at the provider")]
    #[non_exhaustive]
    ZoneNotFound { zone: DomainName },

    #[error("provider authentication failed: {detail}")]
    #[non_exhaustive]
    Auth { detail: Detail },

    #[error("provider denied access: {detail}")]
    #[non_exhaustive]
    Forbidden { detail: Detail },

    /// `retry_after` is how long to wait, counted from the moment the error was returned.
    #[error("provider rate limit reached")]
    #[non_exhaustive]
    RateLimited { retry_after: Option<std::time::Duration> },

        /// The caller's `Expect` does not hold for the rrset as it is at the provider. Repeating the
    /// same call gives the same answer until someone changes the rrset or the expectation.
    #[error("precondition failed: {detail}")]
    #[non_exhaustive]
    PreconditionFailed { detail: Detail },

    /// The provider detected that the rrset changed between this operation's read and its
    /// write, and nothing was written. Repeating the call reads the new state.
    #[error("concurrent change: {detail}")]
    #[non_exhaustive]
    Conflict { detail: Detail },

    /// Network failure, timeout, a 5xx answer, or a provider-side operation still running.
    /// The outcome of a write may be unknown.
    #[error("transient provider error: {detail}")]
    #[non_exhaustive]
    Transient { detail: Detail },

    /// The provider understood the request and refused it. `status` is the HTTP status when the
    /// refusal was an HTTP-level one.
    #[error("provider rejected the request: {detail}")]
    #[non_exhaustive]
    Rejected { status: Option<u16>, detail: Detail },

    /// The provider answered with something the client cannot interpret.
    #[error("unexpected provider response: {detail}")]
    #[non_exhaustive]
    Protocol { detail: Detail },
}

impl Error {
    pub fn kind(&self) -> ErrorKind;
    /// True for RateLimited, Conflict and Transient: repeating the same operation later can
    /// succeed without anyone changing anything.
    pub fn is_retryable(&self) -> bool;
        pub fn retry_after(&self) -> Option<std::time::Duration>;

    // Constructors, one per kind, for implementations of `Provider` outside the crate.
    // Text arguments become a `Detail` through `Detail::new`.
    pub fn config(detail: &str) -> Error;
    pub fn not_compiled(provider: ProviderId) -> Error;
    pub fn unsupported(provider: ProviderId, operation: Operation) -> Error;
    pub fn unsupported_record_type(provider: ProviderId, rtype: RecordType) -> Error;
    pub fn invalid_input(detail: &str) -> Error;
    pub fn name_outside_zone(name: DomainName, zone: DomainName) -> Error;
    pub fn zone_not_found(zone: DomainName) -> Error;
    pub fn auth(detail: &str) -> Error;
    pub fn forbidden(detail: &str) -> Error;
    pub fn rate_limited(retry_after: Option<std::time::Duration>) -> Error;
    pub fn precondition_failed(detail: &str) -> Error;
    pub fn conflict(detail: &str) -> Error;
    pub fn transient(detail: &str) -> Error;
    pub fn rejected(status: Option<u16>, detail: &str) -> Error;
    pub fn protocol(detail: &str) -> Error;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
        Config, NotCompiled, Unsupported, UnsupportedRecordType, InvalidInput, NameOutsideZone,
    ZoneNotFound, Auth, Forbidden, RateLimited, PreconditionFailed, Conflict, Transient, Rejected,
    Protocol,
}
impl ErrorKind {
    /// Stable snake_case identifier: "config", "not_compiled", ..., "protocol".
    pub const fn as_str(self) -> &'static str;
}

/// Bounded text taken from a provider's answer or composed by the client.
#[derive(Clone, PartialEq, Eq)]
pub struct Detail(/* private */);
impl Detail {
    /// Replaces control characters by spaces and truncates to 512 bytes. It does not know any
    /// secret: whoever calls it is responsible for the text containing none.
    pub fn new(text: &str) -> Detail;
    pub fn as_str(&self) -> &str;
}
impl std::fmt::Display for Detail {}
impl std::fmt::Debug for Detail {}
```

Properties:

- `Error` is `Clone + Send + Sync + 'static`. It has no `source()`: the errors of the HTTP stack are
  not exposed, and their text can contain a URL with a query string.
- `Detail` is at most 512 bytes and contains no control characters, whoever built it.
- Inside the crate a `Detail` comes from exactly two places: a constant text, or
  `Scrubber::detail(&str)`, which applies the redaction of section 5.5 before the bounding. Provider
  clients do not call `Detail::new` or the public `Error` constructors that take text; a source scan
  in the conformance tests fails if a file under `src/providers/` does. This is the mechanism behind
  hard rule 1 for errors; the tests of section 12.2 check its result.
- `Detail::new` and the `Error` constructors are public so that the trait can be implemented outside
  the crate (a test double has to return errors). They bound and clean the text and nothing more.
  There is no scrubber behind them, so keeping secrets out of that text is the caller's duty.
- Request bodies and request headers never contribute to a `Detail`.
- `ErrorKind::as_str` is what an application maps to its own error codes. The identifiers are part
  of the public API.
- Retryability is a property of the kind. `Transient` after a write means the write may or may not
  have happened; every operation is safe to repeat (section 3.2). `PreconditionFailed` is not
  retryable and `Conflict` is: the first is the caller's expectation being wrong, the second a race
  the next attempt resolves by reading again.

The inspector has its own error type (section 8.2); names and records have `NameError` and
`RecordError`. None of them wraps a third-party type.

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
4. The request fits the provider: TTL within `Capabilities::ttl`, a TXT value the client's encoding
   can carry (section 4.4), the number of records within the provider's limit, an `Expect::Matches`
   set with the operation's name and type (`Error::InvalidInput`).

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
someone else's.

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
- Read operations (`list_rrsets`, `get_rrset`, `list_zones`, `check`) take no lock.
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
  Cloud.ru, Beget): one request carries the full new set, and the comparison in step 2 and the write
  in step 4 are separate requests. A change made by another process between them is overwritten and
  not detected. To keep that window at one round trip, the transport does not repeat such a write on
  its own (section 5.3): a failed write is the operation's error, and the caller's repeat starts
  with a fresh read.
- Per-record APIs (`atomic_rrset_write == false`): the client computes the difference between the
  records read and the records wanted, creates the missing ones and deletes the extra ones by their
  identifiers. Records present in both are not touched. For types that allow only one record (CNAME,
  SOA, DNAME, ALIAS, ANAME), the client updates the record in place if the API can, otherwise
  deletes and then creates. For all other types it creates before it deletes, so the name never
  loses all its values. A TTL change is applied to every record. The sequence is not atomic: if it
  fails part-way the rrset holds a mixture, the error is returned, and repeating the call completes
  the change because step 1 reads the mixture and step 4 computes the remaining difference.

Attributes of existing records that the model does not carry (a per-record disabled flag, a comment,
a description) are preserved by a write wherever the API returns them. A requested value that exists
as a disabled record is enabled rather than duplicated. Disabled records that are not among the
requested values stay disabled and stay in place.

`delete_rrset(zone, name, rtype, expect)` removes all published values of that name and type.
`Expect::Absent` is `Error::InvalidInput`. A missing rrset is `NotPresent`. `Matches` is evaluated
as for `set_rrset`. On per-record APIs every record of the set is deleted by identifier.

Guard rails in this version, as `read_only_types` or explicit refusals:

- SOA is never writable.
- The NS rrset at the zone apex is not writable (`Error::InvalidInput`): at the providers covered so
  far it belongs to the provider. NS rrsets below the apex (delegations) are ordinary data.
- Rrsets a provider cannot express as plain records (Route 53 alias and routing-policy sets) are
  never modified. A TXT value operation that meets one fails with `Error::Rejected`. A listing
  reports them in `ZoneListing::skipped` with `SkipReason::NotPlainRecords`.

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
- A delete by identifier that is answered "not found" counts as done, on the first attempt and on a
  repeated one: the record is gone, by an earlier attempt of this operation or by someone else. This
  holds for one record of a per-record API. The delete of a whole rrset (the last value of a
  whole-set provider) is sent once, and its "not found" is a success only when a new read finds no
  rrset: the answer can also mean that the zone identifier went stale while the rrset, and with it
  the value, is still published; then the result is `Error::Conflict`.
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

The value operations are implemented once, generically, over a private trait with the three native
shapes (per-record, value-level calls, whole-set replace); a client supplies the reads and writes of
its API. The outcome computation and the foreign-value rules are therefore the same code for every
provider and are tested once against an in-memory backend in addition to the per-provider tests.

### 3.6 TTL policy

One rule for every write: **an existing rrset keeps its TTL unless the caller asked for another
one.**

- `add_txt_value` and `remove_txt_value` never change the TTL of an existing rrset. The `ttl`
  argument of `add_txt_value` is used only when the rrset is created; `None` means the client's
  configured `ttl`.
- `set_rrset` with `rrset.ttl() == Some(t)` sets the TTL to `t`. With `None` it keeps the TTL of the
  existing rrset, and uses the client's configured `ttl` for a new one.
- Where the provider cannot set a TTL (`TtlSupport::NotSettable`), `Some(t)` is `InvalidInput` and
  `None` is the only accepted value.
- Where the API stores a TTL per record (`TtlSupport::PerRecord`), `RrSet::ttl()` of a set that was
  read is the smallest TTL among its records, a write with `Some(t)` sets `t` on every record, and a
  record added to an existing set gets the set's TTL as read.
- Where the provider can choose the TTL (`provider_default_ttl`): a set whose TTL the provider
  manages reads as `None`. The client's `ttl` setting has a spelling for "let the provider choose"
  (Cloudflare: the value `1`, which the API defines as automatic; Timeweb Cloud: the setting left
  unset), and a new set created with `None` then gets no explicit TTL.
- One exception, RFC 2136 without read access: when the server refuses the client's queries, the TTL
  of the existing rrset is unknown, the add is sent with the client's `ttl`, and common servers then
  apply that TTL to the whole rrset (RFC 2136 section 3.4.2.2 leaves the rrset with one TTL). The
  outcome is `Accepted`, which already says the prior state was not seen.
- Where a provider requires all records of an rrset to share a TTL and takes it per request
  (Hetzner), the client sends the TTL it read.

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

## 4. Record value normalization

Decision 9: values are zone-file text (RFC 1035 section 5) in one canonical spelling per type, so a
value read from a provider and a value seen on the wire by the inspector are equal as `RecordData`
exactly when they are the same record.

### 4.1 General rules

- Canonical text is ASCII. Fields are separated by exactly one space; there is no leading or
  trailing whitespace, no comment, no parentheses, no `$` directive.
- Parsing accepts any run of spaces and tabs between fields, and leading and trailing whitespace. It
  rejects parentheses, comments and line breaks.
- Decimal integers are written without sign and without leading zeros. Parsing accepts leading zeros
  and rejects values outside the field's range (`OutOfRange`).
- Hexadecimal data is written lowercase without spaces. Parsing accepts either case and whitespace
  between groups.
- Base64 data is written in the standard alphabet with padding, without spaces. Parsing accepts
  whitespace between groups.
- The comparison rule: two `RecordData` are equal iff their text is byte-for-byte equal. Two rrsets
  have the same records iff their sorted, deduplicated member lists are equal. There is no
  type-aware comparison beyond canonicalization, so the rule is the same in the crate, in an
  application's database and in a test.

### 4.2 Domain names inside RDATA

Applies to NS, CNAME, PTR, DNAME, the pseudo-types ALIAS and ANAME, the exchange of MX, the target
of SRV and SVCB/HTTPS, and both names of SOA. These are `TargetName` values (section 2.1), not
`DomainName`: a zone may point at any name DNS can express, and the crate has to carry it and
compare it, whether or not it could be an owner name here.

One rule, used for provider text and for wire data alike:

- A name is a sequence of labels, each 1 to 63 octets, at most 255 octets in wire form, always
  absolute. The root is `.` (SRV "service not available", null MX, SVCB "same as owner").
- Canonical text: labels joined by `.`, with a trailing dot. ASCII letters are lowercased; no other
  octet is changed. Inside a label, the octets `a`–`z`, `0`–`9`, `-`, `_`, `*`, `/` and every other
  printable ASCII octet except those named next are written as themselves; a dot is written `\.` and
  a backslash `\\`; and `"`, `$`, `(`, `)`, `;`, `@`, space and every octet outside 0x21–0x7E are
  written `\DDD` with three decimal digits.
- Parsing text accepts `\DDD` (value at most 255) and `\X` for any other character `X`, in addition
  to literal characters. A `\` followed by one or two digits, or at the end, is `BadEscape`. Text
  with non-ASCII characters is first converted with IDNA to A-labels, since a U-label is a display
  form of an A-label; if that conversion fails the parse fails.
- `RecordData::parse` treats a name without a trailing dot as absolute, because that is how nearly
  every provider API spells an absolute name; `@` is rejected. `RecordData::parse_relative` applies
  zone-file semantics with an origin; clients use it for providers that return names relative to the
  zone.
- From the wire, the labels are taken as they are and lowercased. No valid wire name fails to
  convert, so an unusual target never turns an inspector answer into a failure, and the text built
  from the wire equals the text built from a provider's spelling of the same name.

The earlier record-level implementation lowercased the whole value and stripped trailing dots. That
left relative and absolute spellings unequal and turned the SRV value `0 0 0 .` into text with a
trailing space; both are closed by parsing fields instead of editing strings.

### 4.3 Canonical form per type

| Type                                | Canonical text                                                         | Notes                                                                                           |
| ----------------------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| A                                   | `192.0.2.1`                                                            | Four decimal octets. Leading zeros are a syntax error (they read as octal elsewhere)            |
| AAAA                                | `2001:db8::1`                                                          | RFC 5952: lowercase, longest zero run compressed. IPv4-mapped addresses as `::ffff:192.0.2.1`   |
| NS, CNAME, PTR, DNAME, ALIAS, ANAME | `host.example.org.`                                                    | One name (section 4.2)                                                                          |
| MX                                  | `10 mail.example.org.`                                                 | Preference `u16`, then a name                                                                   |
| SRV                                 | `0 5 443 host.example.org.`                                            | Priority, weight, port (`u16` each), then a name                                                |
| TXT                                 | `"v=spf1 mx -all"`                                                     | Section 4.4                                                                                     |
| CAA                                 | `0 issue "ca.example.net"`                                             | Section 4.5                                                                                     |
| TLSA                                | `3 1 1 0a1b…`                                                          | Usage, selector, matching type (`u8` each), then hex. At least one data octet                   |
| SSHFP                               | `4 2 0a1b…`                                                            | Algorithm, fingerprint type (`u8` each), then hex                                               |
| SVCB, HTTPS                         | `1 . alpn="h2,h3" port=8443`                                           | Section 4.6                                                                                     |
| SOA                                 | `ns1.example.org. admin.example.org. 2026111401 7200 3600 1209600 300` | Two names, five `u32` in seconds. Time-unit suffixes (`1h`) are accepted and written as seconds |
| any other code                      | `\# 4 0a000001`                                                        | RFC 3597 (section 4.7)                                                                          |

### 4.4 TXT

Model: the value of a TXT record is one byte string, the concatenation of its character-strings.
Where the boundaries between character-strings fall is not part of the value. Provider APIs split,
join and re-split long values on their own, so a form that kept the boundaries could not compare
equal across providers or against the wire. The cost is stated in section 13.4.

Canonical text:

- The bytes are cut into chunks of 255 octets; the last chunk holds the remainder. Empty data is one
  empty chunk.
- Each chunk is written between double quotes; chunks are separated by one space.
- Inside the quotes: `"` is written `\"`, `\` is written `\\`, bytes 0x20 to 0x7E are written as
  themselves, every other byte is written `\DDD` with three decimal digits. A multi-byte UTF-8
  character is therefore several `\DDD` groups, and a chunk boundary may fall inside it.

`RecordData::parse(RecordType::TXT, text)` accepts:

- one or more quoted strings separated by optional whitespace (`"a" "b"`, `"a""b"`), with the
  escapes `\DDD` (value at most 255) and `\X` for any other character `X`, and raw non-ASCII
  characters taken as their UTF-8 bytes; a quoted string longer than 255 octets is accepted and
  re-chunked;
- or exactly one unquoted token without whitespace, with the same escapes.

It rejects unquoted text that contains whitespace. Zone-file syntax would read `v=spf1 mx -all` as
three character-strings and join them into `v=spf1mx-all`; whoever wrote it meant one string with
spaces. Rejecting the ambiguous form removes the trap. A caller with a plain string uses
`Txt::new("v=spf1 mx -all")?.to_data()`.

Provider dialects. Clients do not pass TXT through `RecordData::parse` blindly, because providers
disagree on what the text in their API means. Each client declares one reading rule and one writing
rule from this private set, and the provider table records which:

- `Presentation`: the API carries zone-file text as above. Read with the strict parser; write the
  canonical text.
- `Raw`: the API carries the value itself, unquoted and unescaped. Read the string's bytes as the
  data; write the data as a string. A value that is not valid UTF-8, or that the provider is not
  known to accept unchanged, cannot be written and is `InvalidInput`.
- `Auto` (read only): text that starts with `"` is read as `Presentation`, anything else as `Raw`.
  For APIs observed or documented to return both spellings.

Until a source establishes how a provider treats quotes, backslashes, spaces and non-ASCII bytes in
TXT, its client sets `txt_plain_only` and accepts only `Txt::is_plain` values in the TXT value
operations. Plain values are spelled the same in every dialect apart from the surrounding quotes, so
no client has to guess an escaping rule (hard rule 3).

Gaps of the earlier implementations closed here: no escape handling on read or write (a `\"` inside
a value flipped the quote state; `"` and `\` were written raw), text after the last closing quote
silently dropped, unquoted text with embedded quotes passed through, chunking that could not round
trip values containing quotes, and comparison by string equality of provider text in the paths that
select a value to change.

### 4.5 CAA

`<flags> <tag> "<value>"`:

- flags: `u8` decimal;
- tag: 1 to 255 characters of `[a-z0-9]`, written lowercase; parsing accepts uppercase (RFC 8659
  section 4.1: tags are matched case-insensitively);
- value: always written as one quoted string with the escapes of section 4.4 and no length limit
  other than the RDATA size; parsing accepts a quoted or an unquoted value. The value is not
  case-folded and not interpreted.

### 4.6 SVCB and HTTPS

`<priority> <target> [<param> ...]` (RFC 9460 section 2.1):

- priority `u16`; target a name. Parameters are kept as given in both modes; alias mode (priority 0)
  normally has none.
- Parameters are written in ascending order of their numeric key, each once. Duplicate keys are a
  syntax error.
- Keys are written by name where RFC 9460 defines one (`mandatory`, `alpn`, `no-default-alpn`,
  `port`, `ipv4hint`, `ech`, `ipv6hint`) and as `key<number>` otherwise. Parsing accepts both forms
  for a defined key.
- Values: `mandatory` is a comma-separated list of key names in ascending numeric order; `alpn` is
  written quoted, comma-separated in the given order, with `,` and `\` inside an identifier escaped
  as RFC 9460 appendix A.1 prescribes; `no-default-alpn` has no value; `port` is decimal; `ipv4hint`
  and `ipv6hint` are comma-separated addresses in the canonical forms of section 4.3, in the given
  order; `ech` is base64; `key<number>` values are written as one quoted string with the escapes of
  section 4.4.

### 4.7 Unknown types

For a type code without a row in section 4.3 the only accepted and the canonical form is the generic
one of RFC 3597 section 5: `\# <length> <hex>`, length in decimal, hex lowercase without spaces,
`\# 0` for empty RDATA.

For a type that has a row, the generic form is accepted on input and converted: the wire data is
decoded and written in the type's own canonical form. So `\# 4 c0000201` for type A is the same
`RecordData` as `192.0.2.1`.

A provider that returns its own text for a type the crate has no row for cannot be normalized: the
value is carried as non-canonical data (section 4.9) and will not compare equal to what the
inspector sees for the same record. Adding a row for a type fixes that for the type; it changes the
canonical text of that type's values and is called out in the changelog.

### 4.8 Wire conversion

`RecordData::from_wire` and `to_wire` implement the RDATA formats of the types in section 4.3 (RFC
1035, 3596, 2782, 8659, 6698, 4255, 9460, 6672). `from_wire` takes uncompressed RDATA; a compression
pointer is a syntax error. TXT wire data is the character-strings in order; `from_wire` concatenates
them and `to_wire` emits 255-octet chunks. Pseudo-types have no wire form.

The inspector converts answers through the same typed constructors (section 8.5), so there is one
definition of each canonical form.

### 4.9 Non-canonical data

A client reads provider text with a private constructor that first tries the strict parser (with the
provider's TXT dialect and name convention). If that fails, the value is kept as the provider's
text, trimmed of surrounding whitespace, and marked non-canonical.

- `is_canonical()` is false; `to_wire` and the typed `from_data` fail with `NotCanonical`.
- It still compares by text, so an application sees it as a distinct value and a listing never fails
  because of one odd record.
- A write accepts a non-canonical member only when the rrset currently at the provider, as read at
  the start of the write, contains a record with exactly that text; the record is then left as it
  is. Otherwise the write is `InvalidInput`. In practice an application can write back a set it
  listed, with members added or removed, also after storing it (section 2.2); it cannot introduce a
  record through non-canonical data. This is the validation that section 3.1 says happens after the
  read.

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
- No proxy: the client is built with `no_proxy()`. `reqwest` reads `HTTP_PROXY`, `HTTPS_PROXY` and
  `ALL_PROXY` from the environment even without its `system-proxy` feature; left alone, a variable
  set for some other purpose would route provider credentials through a proxy, plain-HTTP loopback
  requests included, and `loopback_only` would not mean what it says. Neither earlier implementation
  had a proxy setting, so none is offered (open point 15).
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
- 429 and other rate-limit answers: the wait is taken from `Retry-After` (delay-seconds or an HTTP
  date in the IMF-fixdate form; the obsolete RFC 850 and asctime forms are not read) or
  `RateLimit-Reset` (a value above 10⁹ is a Unix time, as Hetzner sends it, a smaller one
  delay-seconds). For an idempotent request with attempts left and a wait of at most 30 s, the
  transport sleeps for the wait or the back-off, whichever is longer, and retries, so a wait of zero
  or a time in the past does not produce three requests in a few milliseconds; without a header it
  uses the back-off. Otherwise the result is `Error::RateLimited { retry_after }`, with the wait
  clamped to 24 hours so that a caller can add it to an `Instant`.
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
- A delete of one record by identifier that is repeated and answered "not found" is a success
  (section 3.5).

### 5.4 Responses

- A response body is read up to 4 MiB; a larger one is `Error::Protocol` whose detail names the
  limit. The cap applies to error bodies too.
- Listings read at most 1000 pages; reaching the page limit is `Error::Protocol` whose detail names
  it. Page sizes are those of the earlier implementations, which are the documented maxima where a
  source states one: 1000 rrsets (Selectel v2), 1000 record sets (Yandex Cloud), 100 records
  (Cloudflare, Cloud.ru, Timeweb Cloud), 200 (DigitalOcean), 50 (Hetzner zones, Yandex 360). With
  1000 pages the smallest of these still covers 50 000 entries. A client whose provider returns a
  whole zone in one response (VK Cloud's TXT list, reg.ru, nic.ru) is bounded by the 4 MiB cap
  alone, and its rustdoc says so. Raising either constant is not a breaking change. A zone beyond
  them fails to list with an error that says why; it is never returned in part.
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

- Registered at construction: every field of the credentials, each also in its form-encoded and
  percent-encoded forms, so that a value the client sent encoded and the API echoes encoded once
  more is replaced in place. Private key material (a TLS client key, a signing key) is not
  registered: it is never sent, so no API can echo it, and a multi-line PEM document makes needles
  that match nothing. Registered at run time: every token the client obtains (Keystone, IAM, OAuth)
  and every signed assertion it sends (JWT), each under the slot of its source (a token cache, a
  signer). A slot keeps its current and its previous secret, so a client with several token sources
  never loses the coverage of a live token. The transport registers each token it sends; registering
  the slot's current token again costs a comparison.
- Encoded needles, replaced in place: for each secret, the spellings in which an API most often
  echoes it — verbatim; form-urlencoded with `+` and with `%20` for a space; RFC 3986
  percent-encoding (the crate's own URL encoding); as the inside of a JSON string; JSON with `\/`
  and lowercase `\uXXXX` escapes for non-ASCII characters; XML-escaped. Each occurrence is replaced
  by `[redacted]`. Longer spellings are tried first. Empty secrets are ignored.
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
there was no answer), `attempt` and `elapsed_ms`. Nothing else in a provider client logs a request.

Never written to `tracing`, at any level: request or response bodies, any header, query strings,
`Detail` text (it is derived from a body), TXT values.

`WARN` events exist for conditions an operator should see and carry no request data: no system CA
certificates; acme-dns about to evict an older value; an inspector name server skipped by the
address policy.

A test installs a subscriber at `TRACE`, drives a client through success, 401 and 500 paths with
canary credentials, and asserts that the log is not empty and contains none of the canaries (section
12.2).

### 5.7 Shared helpers for provider families

- `TokenSource`: caches a token obtained by an exchange (Keystone password, IAM JWT, OAuth password
  grant, access-key exchange). The fetch returns the token and its lifetime. The token is renewed
  ahead of time: at the expiry minus `max(10 min, 5 % of the lifetime)`, but at most half the
  lifetime, optionally capped by a maximum age (50 min for Yandex Cloud); a token without a stated
  expiry is assumed to live 1 h. A short-lived token is therefore still cached for half its life; a
  lifetime under two minutes (a system clock that runs ahead makes a stated expiry look close) is
  logged as one `WARN` event per token, with the lifetime and nothing else. Expiry timestamps are
  parsed with the private `jiff` dependency and turned into `tokio::time::Instant` deadlines
  immediately. Single flight: the fetch runs inside the first caller's future while it holds the
  source's async lock, and the others wait for the lock. If that future is dropped mid-fetch, the
  lock is released with nothing stored and the next waiter fetches; there is no detached task and no
  state that a cancelled fetch can leave half-written. Every token has a generation number, and a
  401 invalidates only the generation the failed request used, so a late 401 for an old token does
  not discard a fresh one. What happens to the request after a 401 is the retry rule of section 5.3.
- `Keystone`: the OpenStack Identity v3 password exchange with project scope, shared by Selectel v2
  and VK Cloud. The request body, which carries the password, is built once into a zeroizing buffer;
  `400` and `401` are `Error::Auth`.
- `RateGate`: at most one request per configured interval per client, for providers with
  undocumented limits (reg.ru 1000 ms, Beget 1000 ms, nic.ru 500 ms; `min_request_interval_ms`).
- `Poller`: the bounded polling of section 3.7.
- `Pager`: page loops for the cursor styles in use (page number with total pages, next-page number,
  offset with total, offset with next offset, page token), each with a hard page limit.
- `ZoneCache`: section 3.8. Only the read phase is repeated after a stale identifier: the cache runs
  the client's read and returns the identifier it ended with, and the client performs its write
  afterwards, outside the cache, so a write never runs twice. A write answered "not found" evicts
  the entry and fails; the repeat of the operation starts with a read.
- XML reading (Route 53, nic.ru) uses `roxmltree`; XML writing is string building with one escaping
  function.

Time in these helpers is `tokio::time`, so tests run them under a paused clock.

## 6. Crypto module

Private (`pub(crate)`), compiled only for the providers that need it, backed by `aws-lc-rs` alone
(decision 3, hard rule 5). Nothing in it is part of the public API: it serves three clients, and a
public signing API would be a second product with its own compatibility burden.

```rust
// crate::crypto
pub(crate) fn sha256(data: &[u8]) -> [u8; 32];
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32];
pub(crate) fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64];
/// Constant time in the contents; false for a tag of the wrong length.
pub(crate) fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool;
pub(crate) fn hmac_sha512_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool;
/// Constant time in the contents; the lengths are not hidden.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool;
pub(crate) fn hex_lower(data: &[u8]) -> String;

/// An RSA private key for RSASSA-PSS with SHA-256 (JWS "PS256"). Parsed once.
pub(crate) struct Ps256Key(/* aws_lc_rs::signature::RsaKeyPair */);
impl Ps256Key {
    /// Accepts a PEM document with a "PRIVATE KEY" (PKCS#8) or "RSA PRIVATE KEY" (PKCS#1)
    /// section; text before the section is ignored. Errors never contain key material.
    pub(crate) fn from_pem(pem: &str) -> Result<Ps256Key, KeyError>;
    /// Raw signature bytes; salt length equals the digest length (RFC 7518 section 3.5).
    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError>;
}

// crate::crypto::sigv4 — AWS Signature Version 4
pub(crate) struct Keys<'a> {
    pub access_key_id: &'a str,
    pub secret: &'a SecretString,
    pub session_token: Option<&'a SecretString>,
}
pub(crate) struct Scope<'a> { pub region: &'a str, pub service: &'a str }
pub(crate) struct Request<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,                    // already canonical
    pub query: &'a str,                   // from canonical_query
    pub headers: &'a [(&'a str, &'a str)], // extra signed headers, lowercase names
    pub payload_hash: &'a str,
}
pub(crate) fn canonical_query(pairs: &[(&str, &str)]) -> String;
pub(crate) fn payload_hash(body: &[u8]) -> String;
/// `amz_date` is "YYYYMMDDTHHMMSSZ". Returns the Authorization header value.
pub(crate) fn authorization(
    request: &Request<'_>,
    keys: &Keys<'_>,
    scope: Scope<'_>,
    amz_date: &str,
) -> Result<Zeroizing<String>, KeyError>;
```

Notes:

- Backend calls: `aws_lc_rs::digest`, `aws_lc_rs::hmac`, `aws_lc_rs::constant_time`,
  `aws_lc_rs::signature::{RsaKeyPair, RSA_PSS_SHA256}`, `aws_lc_rs::rand::SystemRandom`. PEM is read
  with `rustls-pki-types` (`PrivateKeyDer::from_pem_slice`), which distinguishes the two labels and
  skips text outside the section; a PKCS#8 body goes to `RsaKeyPair::from_pkcs8`, a PKCS#1 body to
  `RsaKeyPair::from_der`. A key that is not RSA is `KeyError`, reported by the client as
  `Error::Config`.
- The key is parsed once at client construction and kept as the backend's key object; the DER bytes
  are not retained. (The earlier implementation kept the DER and re-parsed it for every signature,
  and proved the key type with a throwaway signature.)
- SigV4 intermediates that contain the secret key or the session token (the `AWS4`-prefixed key, the
  derived keys, the canonical request, the string to sign) are held in zeroizing buffers. The date
  part is taken from `amz_date` with checked slicing; a malformed date is an error, not a panic.
- Users: TSIG for RFC 2136 (HMAC), Route 53 (SigV4), Yandex Cloud (PS256).

Test vectors, all taken from their published sources and cited in the test code:

- HMAC-SHA-256 and HMAC-SHA-512: RFC 4231 test cases 1, 2, 3, 4, 6 and 7, plus negative verification
  (flipped bit, wrong key, truncated tag, changed message).
- SHA-256: the NIST example digests of the empty message and of `"abc"`.
- SigV4: from the AWS Signature Version 4 test suite, `get-vanilla` (canonical request, string to
  sign and authorization) and `get-vanilla-query-order-key-case`, which the earlier implementation
  already carries, plus one POST case with a body and one session-token case from the same suite,
  copied from the suite's files and named after them in the test code; plus checks that the secret
  and the token do not occur in the output.
- PS256: signatures are randomized, so the test is a round trip: generate a 2048-bit key in the
  test, sign, verify with `RSA_PSS_2048_8192_SHA256`, which requires the salt length to equal the
  digest length; plus rejection of an EC key, of garbage and of a truncated PEM, each without
  echoing input. No key material is stored in the repository.

## 7. DNS-01 helpers

Module `zonewright::dns01`. Pure functions and one trait; no network code and no dependency on the
inspector. The inspector implements the trait when its feature is on.

```rust
pub const CHALLENGE_LABEL: &str = "_acme-challenge";
/// Default limit for follow_cname.
pub const CNAME_CHAIN_MAX: usize = 8;

/// The name at which the DNS-01 TXT record for `identifier` is expected (RFC 8555 section 8.4).
/// A leading wildcard label is dropped: the challenge for "*.example.org" is at
/// "_acme-challenge.example.org".
pub fn challenge_name(identifier: &DomainName) -> Result<DomainName, NameError>;

/// Something that can say whether a name is a CNAME.
pub trait CnameLookup {
    /// `Ok(Some(target))`: the name is a CNAME to `target`. `Ok(None)`: it is not (no such
    /// record or no such name). `Err`: no trustworthy answer was obtained.
    fn cname(
        &self,
        name: &DomainName,
    ) -> impl Future<Output = Result<Option<DomainName>, LookupError>> + Send;
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct LookupError { /* private */ }
impl LookupError { pub fn new(detail: impl Into<String>) -> LookupError; }

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CnameChain {
    pub start: DomainName,
    /// The targets in order; empty when `start` is not a CNAME.
    pub links: Vec<DomainName>,
}
impl CnameChain {
    /// The last target, or `start` when there are no links: the name whose TXT rrset must hold
    /// the challenge value.
    pub fn effective(&self) -> &DomainName;
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CnameError {
    #[error("CNAME loop at {name}")]
    Loop { name: DomainName },
    #[error("CNAME chain from {start} is longer than {max} links")]
    TooLong { start: DomainName, max: usize },
    #[error("lookup of {name} failed: {detail}")]
    Lookup { name: DomainName, detail: String },
}
impl CnameError { pub fn is_retryable(&self) -> bool; }  // true for Lookup only

pub async fn follow_cname<L: CnameLookup>(
    lookup: &L,
    start: &DomainName,
    max_links: usize,
) -> Result<CnameChain, CnameError>;

/// Of the given zones, the one with the most labels that contains `name`.
pub fn select_zone<'a, T>(
    name: &DomainName,
    zones: &'a [(DomainName, T)],
) -> Option<&'a (DomainName, T)>;
```

### 7.1 Challenge name

`challenge_name` prepends `_acme-challenge` to the identifier after removing a wildcard label. It
fails only when the result would be too long.

### 7.2 CNAME chains

`follow_cname` asks `lookup` for `start`, then for each target in turn. A target equal to any name
already seen, including `start`, is `Loop`. A chain of exactly `max_links` links is accepted; one
more is `TooLong`. A lookup error stops with `Lookup`, the only retryable case; its detail is
truncated to 512 bytes and stripped of control characters.

### 7.3 Zone selection

`select_zone` returns the entry whose zone contains `name` and has the most labels; matching is by
labels. If two entries have the same zone, the first wins. The payload `T` is whatever the
application attaches to a zone (an account, a provider ID). The function never walks up the labels
asking a provider; the application supplies the zones it knows.

### 7.4 What is deliberately not here

- CAA tree climbing (RFC 8659 section 3) and any judgement on whether a CA may issue. That decides
  what a zone should contain. The typed `Caa` record and the inspector's generic queries are what an
  application needs to build it.
- "The CNAME target must not be a zone apex" and similar rules about where challenges may be
  delegated. Application policy.
- Computing the TXT value from a key authorization. That is ACME.

## 8. Inspector

Optional feature `inspector`. It observes DNS; it has no connection to provider clients and holds no
secrets.

### 8.1 Approach

Two earlier implementations exist. One discovers the name servers of a zone through public recursive
resolvers and queries each server through a high-level resolver library. The other resolves
iteratively from the root with its own UDP and TCP transport over a DNS message codec, and accepts
only authoritative answers.

This design takes the query layer of the second and the discovery of the first:

- Queries are sent by the crate's own small transport using `hickory-proto` only for encoding and
  decoding messages. The transport is what makes per-server observation exact: it sees the AA flag,
  the response code and truncation, so "this server is not authoritative for the zone", "refused",
  "no such name" and "no data" are different answers instead of an error string to pattern-match. It
  also removes the resolver library and its dependency tree (a cache crate, a system configuration
  reader) from the build, which lowers the crate's MSRV to that of the core (section 13.1), and ties
  an application that pins or vendors `hickory-*` to one crate instead of three.
- The name servers of a zone are found by asking configured recursive resolvers for the zone's NS
  set and the servers' addresses, or are given by the application. Iterative descent from the root
  is not implemented. It cannot see zones that exist only inside an organization, needs a maintained
  list of root servers and a fallback for networks that intercept port 53, and is several times the
  code; and the caller of this API already knows the zone, which is the question descent answers.
  Its one advantage, independence from a resolver's cache after a re-delegation, is covered by
  letting the application pass the server list (`NsDiscovery::Static`) and by not caching failures.

No `hickory` type appears in a public signature. Record values are produced by this crate's
normalization, never by a dependency's `Display`.

### 8.2 Public API

```rust
// zonewright::inspector — compiled with feature "inspector"

pub struct Inspector { /* private */ }

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct InspectorConfig {
    /// Recursive resolvers, tried in order. Default: PUBLIC_RESOLVERS.
    pub resolvers: Vec<std::net::SocketAddr>,
    pub discovery: NsDiscovery,
    /// Address families of discovered name servers to query. Default: V4.
    pub ip_families: IpFamilies,
    /// Limit for one question to one server, including a TCP retry. Default 3 s.
    pub query_timeout: std::time::Duration,
    /// How long a discovered server list is reused. Default 300 s. Zero disables the cache.
    pub ns_cache_ttl: std::time::Duration,
    /// Upper bound on the name servers (addresses) of one zone. Default 32.
    pub max_servers: usize,
        /// Limit for the whole discovery of one zone's servers. Default 10 s.
    pub discovery_timeout: std::time::Duration,
    /// Accept discovered name-server addresses in private ranges. Default false.
    pub allow_private_addresses: bool,
}
impl Default for InspectorConfig {}

/// 1.1.1.1:53, 8.8.8.8:53, 9.9.9.9:53.
pub const PUBLIC_RESOLVERS: &[std::net::SocketAddr];

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum NsDiscovery {
    /// Ask the resolvers for the zone's NS rrset and the servers' addresses.
    Recursive,
    /// Use exactly these servers for every zone.
    Static(Vec<NameServer>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpFamilies { V4, V6, Both }

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NameServer {
        /// The NS name, when known.
    pub name: Option<TargetName>,
    pub addr: std::net::SocketAddr,
}
impl NameServer { pub fn new(name: Option<TargetName>, addr: std::net::SocketAddr) -> NameServer; }

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question { pub name: DomainName, pub rtype: RecordType }

/// What one server said about one question.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Answer {
    /// The rrset, normalized. `ttl` is the smallest TTL among its records.
    Records { ttl: Ttl, records: Vec<RecordData> },
    /// The name exists, there is no rrset of this type.
    NoData,
    NxDomain,
        /// The name is a CNAME; the server did not answer the question itself.
    Cname(TargetName),
    Refused,
    ServFail,
    /// An answer without the AA flag, or a referral, from a server queried as authoritative.
    NotAuthoritative,
    Timeout,
    /// Anything else: another response code, a malformed message, a network error.
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Condition {
    /// The rrset contains all of these values; other values may be present.
    Present(Vec<RecordData>),
    /// The rrset is exactly this set. An empty list means: there is no such rrset.
    Exact(Vec<RecordData>),
    /// The rrset contains none of these values, or does not exist.
    Absent(Vec<RecordData>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expectation { pub question: Question, pub condition: Condition }

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct WaitOptions {
    /// Total time to wait. At least one round always runs.
    pub timeout: std::time::Duration,
    /// Pause between rounds. Default 5 s.
    pub interval: std::time::Duration,
    /// The pause varies by up to this percentage either way. Default 20; at most 50.
    pub jitter_percent: u8,
}
impl WaitOptions { pub fn new(timeout: std::time::Duration) -> WaitOptions; }

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ServerReport {
    pub server: NameServer,
    /// All expectations held at this server in the last round.
    pub satisfied: bool,
    /// The last round's answers, one per expectation, in the order given.
    pub answers: Vec<Answer>,
    /// When this server first satisfied all expectations, from the start of the wait.
    pub first_satisfied_after: Option<std::time::Duration>,
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Report {
    pub servers: Vec<ServerReport>,
    pub rounds: u32,
    pub elapsed: std::time::Duration,
}

#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InspectorError {
    #[error("invalid inspector configuration: {detail}")]
    Config { detail: String },
    #[error("invalid request: {detail}")]
    InvalidInput { detail: String },
    #[error("no usable name servers for zone {zone}: {detail}")]
    NoNameServers { zone: DomainName, detail: String },
    #[error("zone {zone} has {count} name server addresses, more than the configured limit")]
    TooManyNameServers { zone: DomainName, count: usize },
    #[error("expectations not met within the timeout")]
    Timeout { report: Report },
}

impl Inspector {
    pub fn new(config: InspectorConfig) -> Result<Inspector, InspectorError>;

    /// The authoritative servers of `zone`, by the configured discovery.
    pub async fn name_servers(&self, zone: &DomainName) -> Result<Vec<NameServer>, InspectorError>;

    /// One question to one server, recursion not desired.
    pub async fn query_server(&self, server: std::net::SocketAddr, question: &Question) -> Answer;

    /// One question to every configured resolver, recursion desired.
    pub async fn query_recursive(&self, question: &Question) -> Vec<(std::net::SocketAddr, Answer)>;

    /// One round: every question at every name server of the zone.
    pub async fn observe(
        &self,
        zone: &DomainName,
        questions: &[Question],
    ) -> Result<Vec<(NameServer, Vec<Answer>)>, InspectorError>;

    /// Polls until every name server of the zone satisfies every expectation in the same round.
    pub async fn wait(
        &self,
        zone: &DomainName,
        expectations: &[Expectation],
        options: &WaitOptions,
    ) -> Result<Report, InspectorError>;
}

impl crate::dns01::CnameLookup for Inspector {}
```

All durations are `std::time::Duration`. Strings in `Answer::Failed` and in the error details are at
most 512 bytes without control characters.

### 8.3 Name-server discovery

`NsDiscovery::Recursive`, for a zone:

1. Ask each resolver in order, one at a time, for `zone NS` with recursion desired. Use the first
   answer that contains at least one NS record whose owner is the zone itself; records with any
   other owner are ignored. A negative answer, an empty answer or a failure moves on to the next
   resolver. If no resolver yields a set: `NoNameServers`. There is no walking up the labels: the
   name given must be the zone.
2. If the set has more than 16 distinct NS names: `TooManyNameServers`, before any address lookup.
3. For each NS name, ask for `A` and/or `AAAA` according to `ip_families`, taking the answers of the
   first resolver that answers. At most 8 of these lookups run at a time. At most 8 addresses per
   name and family are used; more is `TooManyNameServers`.
4. Drop addresses that are unspecified, loopback, link-local, multicast or broadcast, including the
   IPv4-mapped forms of these, and, unless `allow_private_addresses` is set, private (RFC 1918),
   unique-local (RFC 4193) and shared (RFC 6598) addresses. Each dropped address and each NS name
   left without an address is logged at `WARN`. The default is to drop private addresses: the
   answers of a discovered server end up in reports, and a zone's NS records should not be able to
   point this process at hosts inside its own network. A deployment whose authoritative servers are
   internal sets the option or uses a static list (open point 16).
5. Each remaining address becomes a `NameServer` on port 53. None left: `NoNameServers`. More than
   `max_servers`: `TooManyNameServers`. The list is never truncated, because success means "every
   server", and a silently shortened list would turn that into "some servers".
6. Steps 1 to 5 together are bounded by `discovery_timeout`; when it passes, the result is
   `NoNameServers` with a detail that says so. With the defaults that is at most 3 + 16 × 2 × 3
   questions, each bounded by `query_timeout` as well.
7. The result is cached per zone for `ns_cache_ttl`, at most 256 zones (the oldest entry is
   evicted). Failures are not cached. Concurrent discoveries of one zone are not merged; each is
   bounded on its own.

`NsDiscovery::Static` uses the given list as is, without the address filter and without the cache:
the application chose those addresses. It serves hidden primaries, split-horizon setups and tests.
More entries than `max_servers` is `InspectorError::Config`.

### 8.4 Queries

- UDP first, with EDNS and a 1232-octet payload size. A truncated answer is repeated over TCP. A
  `FORMERR` answer to a query with EDNS is repeated once without EDNS.
- Every question uses a new UDP socket, bound to the wildcard address with a port chosen by the
  operating system and connected to the server, and closed when the question is answered or times
  out. Sockets are not pooled or reused, so neither a source port nor an ID is shared between
  questions. A TCP retry likewise opens its own connection.
- Message IDs are the ones `hickory-proto` assigns to a new query: 16 bits from the `rand` crate's
  thread-local generator, a cryptographically strong generator seeded from the operating system.
  `fastrand` is not used for anything an off-path attacker would have to guess.
- A UDP datagram is accepted only from the queried address and only if its ID and question match the
  query (name compared case-insensitively); others are ignored until the timeout.
- `query_timeout` bounds the whole question to one server, all of the above included.
- To a name server: recursion not desired. The answer is classified as follows. Response code
  REFUSED or SERVFAIL: the variant of that name. Any other code than NOERROR and NXDOMAIN: `Failed`.
  AA not set: `NotAuthoritative`. NXDOMAIN: `NxDomain`. Records of the asked type owned by the asked
  name: `Records`. No such records but a CNAME owned by the asked name (and the question was not for
  CNAME): `Cname`. Otherwise `NoData`.
- To a resolver: recursion desired; AA is not required. A CNAME chain inside the answer is followed
  within the answer (at most 8 links, loops rejected) to the records of the asked type.
- The inspector does not validate DNSSEC and does not use DoT or DoH.

### 8.5 Values

Answer records are converted to `RecordData` through the typed constructors and `from_wire` of
section 4: fields are taken from the decoded message for the types whose RDATA can contain
compressed names (NS, CNAME, PTR, MX, SOA, SRV, DNAME), and the raw RDATA goes through
`RecordData::from_wire` for everything else, including types the codec does not know. TXT
character-strings are concatenated as bytes; nothing is lossily converted to UTF-8. Names inside
RDATA become `TargetName` values, for which every valid wire name has a text form, so an unusual
target does not fail. Only RDATA that is malformed for its type makes the answer `Failed`.

The result compares directly with what a provider client returns for the same record, which is the
point of section 4.

### 8.6 Expectations and the wait loop

An expectation holds at a server according to its answer:

| Condition                  | Holds when the answer is                                         |
| -------------------------- | ---------------------------------------------------------------- |
| `Present(values)`          | `Records` containing every value                                 |
| `Exact(values)`, non-empty | `Records` whose set equals `values`                              |
| `Exact([])`                | `NoData` or `NxDomain`                                           |
| `Absent(values)`           | `NoData`, `NxDomain`, or `Records` containing none of the values |

`Cname`, `Refused`, `ServFail`, `NotAuthoritative`, `Timeout` and `Failed` satisfy nothing. In
particular an unreachable server never counts as "the value is absent", and it is not skipped: a
resolver elsewhere may ask exactly that server. Expected values must be canonical; a non-canonical
value is `InvalidInput`. `Present` and `Absent` need at least one value.

`wait`:

1. Validate: 1 to 32 expectations, every name within the zone. Discover the servers.
2. A round asks every server every question concurrently (each question bounded by `query_timeout`),
   evaluates the expectations and builds the report.
3. If every server satisfies every expectation in this round: `Ok(report)`.
4. If the time since the start is at least `timeout`: `Err(Timeout { report })`.
5. Sleep `interval`, varied uniformly by ±`jitter_percent`, but not past the deadline; go to 2.

Properties: at least one round runs even with a zero timeout; the last round starts no later than
`timeout` after the start, so the call returns within `timeout + query_timeout` plus discovery;
every round asks every server again, so a server that had the value and lost it is seen (the earlier
implementation stopped asking a server once it was satisfied, which is acceptable only for a value
that is about to be consumed). A wait for several zones is several calls, which the application may
run concurrently.

### 8.7 CNAME lookup by quorum

`Inspector` implements `dns01::CnameLookup` over the resolvers: it asks them in order for the CNAME
of the name and stops when two agree (or when all have answered, if fewer than two are configured).
A negative answer is a vote for "no CNAME". A CNAME record counts only if its owner is the asked
name. Two different votes are an error at once; timeouts and failures are not votes; running out of
resolvers before two agree is an error that says how many answered. One resolver's cache or one
tampered answer therefore cannot redirect a challenge on its own. A target that is not a valid
`DomainName` cannot be an owner name the challenge could be written at; it is reported as a lookup
error.

### 8.8 Bounds

| Bound                                       | Value                                      |
| ------------------------------------------- | ------------------------------------------ |
| NS names of one zone                        | 16                                         |
| Addresses per NS name and family            | 8                                          |
| Servers (addresses) per zone                | `max_servers`, default 32                  |
| Time for one discovery                      | `discovery_timeout`, default 10 s          |
| Concurrent address lookups during discovery | 8                                          |
| Expectations or questions per call          | 32                                         |
| Questions per round, all sent concurrently  | servers × questions ≤ 1024                 |
| Network exchanges per question              | 3 (UDP, UDP without EDNS, TCP)             |
| Sockets per question                        | one new UDP socket, one new TCP connection |
| Time per question                           | `query_timeout`, default 3 s               |
| CNAME links (in an answer, in a chain)      | 8, with loop detection                     |
| Message size                                | 4096 octets UDP, 65535 TCP                 |
| Cached zones                                | 256                                        |

### 8.9 Tracing and testing

Events: target `zonewright::inspector`, `DEBUG` per query with server address, record type, answer
kind and duration; no record values and no names beyond the zone.

Testing without the network:

- The transport sits behind a private trait with one method (send this message to this address, get
  a message or a classified failure). Unit tests of discovery, classification, quorum and the wait
  loop use a table-driven implementation and tokio's paused clock, so a "five minute" wait runs
  instantly and deterministically.
- Integration tests use the mock crate's DNS server (section 12.1) on loopback over real UDP and
  TCP: truncation and TCP retry, `FORMERR` without EDNS, wrong-ID datagrams, silent servers, lame
  servers, lagging servers, CNAME answers. They reach it through `NsDiscovery::Static` and through
  `resolvers`, both of which accept loopback addresses because the application supplies them.

## 9. Features and dependencies

### 9.1 Cargo features

No feature is enabled by default (decision 6).

| Feature                | Enables                                              | Optional dependencies it turns on                                         |
| ---------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------- |
| one per provider (2.4) | that provider's client and its `AnyProvider` variant | see the feature list below                                                |
| `all-providers`        | all fifteen provider features                        | their union                                                               |
| `inspector`            | `zonewright::inspector`                              | `hickory-proto`, `futures-util`, `fastrand`; `tokio/net`, `tokio/io-util` |

Provider feature names are the provider IDs, underscores included: `acme_dns`, `cloud_ru`,
`selectel_v2`, `timeweb_cloud`, `vk_cloud`, `yandex_360`, `yandex_cloud` and the eight one-word IDs.
A provider then has one spelling everywhere: the persisted ID, the feature, the module, the test
file. `all-providers` and `inspector` are the only other public features.

Three private features group optional dependencies. Their names start with two underscores, they are
documented as internal, and they are not part of the SemVer surface:

| Private feature | Dependencies                                                                                     | Used by                              |
| --------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------ |
| `__http`        | `reqwest`, `rustls`, `rustls-platform-verifier`, `rustls-pki-types`, `bytes`, `jiff`, `fastrand` | every provider except `rfc2136`      |
| `__crypto`      | `aws-lc-rs`                                                                                      | `rfc2136`, `route53`, `yandex_cloud` |
| `__xml`         | `roxmltree`                                                                                      | `route53`, `nicru`                   |

```toml
[features]
default = []
all-providers = [
    "acme_dns", "beget", "cloud_ru", "cloudflare", "digitalocean", "hetzner", "nicru", "regru",
    "rfc2136", "route53", "selectel_v2", "timeweb_cloud", "vk_cloud", "yandex_360", "yandex_cloud",
]
inspector = ["dep:hickory-proto", "dep:futures-util", "dep:fastrand", "tokio/net", "tokio/io-util"]

acme_dns = ["__http"]
beget = ["__http"]
cloud_ru = ["__http"]
cloudflare = ["__http"]
digitalocean = ["__http"]
hetzner = ["__http"]
nicru = ["__http", "__xml"]
regru = ["__http"]
rfc2136 = ["__crypto", "dep:fastrand", "tokio/net", "tokio/io-util"]
route53 = ["__http", "__crypto", "__xml"]
selectel_v2 = ["__http"]
timeweb_cloud = ["__http"]
vk_cloud = ["__http"]
yandex_360 = ["__http"]
yandex_cloud = ["__http", "__crypto"]

__http = [
    "dep:reqwest", "dep:rustls", "dep:rustls-platform-verifier", "dep:rustls-pki-types",
    "dep:bytes", "dep:jiff", "dep:fastrand",
]
__crypto = ["dep:aws-lc-rs"]
__xml = ["dep:roxmltree"]
```

### 9.2 What compiles with no features

Names, the record model with normalization and the typed records, `Ttl`, errors, `ProviderId`,
metadata and capabilities of all fifteen providers, the `Provider` trait, `AnyProvider` (with no
variants), `Context` (locks only), and `dns01`. Dependencies of that build: `serde`, `serde_json`,
`secrecy`, `zeroize`, `thiserror`, `tracing`, `idna`, `base64`, `tokio` with `sync` and `time`. No
TLS stack, no C compilation.

An application that only needs the inspector enables `inspector` and gets `hickory-proto` and
UDP/TCP sockets on top of that, still without a TLS stack.

Shared helpers under `__http` are not all used by every provider. In builds without `all-providers`
the `http`, `crypto` and helper modules allow `dead_code`; the build with all features does not, so
code no provider uses is still found.

### 9.3 Dependencies

Versions are the latest stable releases on 2026-11-14.

```toml
[dependencies]
serde = { version = "1.0.229", features = ["derive"] }
serde_json = "1.0.154"
secrecy = { version = "0.10.3", features = ["serde"] }
zeroize = { version = "1.9.1", features = ["derive"] }
thiserror = "2.0.21"
tracing = { version = "0.1.44", default-features = false, features = ["std"] }
idna = "1.1.0"
base64 = "0.23.1"
tokio = { version = "1.54.1", features = ["sync", "time"] }

# __http
reqwest = { version = "0.13.5", default-features = false, features = ["rustls-no-provider"], optional = true }
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
zonewright-mock = { path = "../mock" }
serde_json = "1.0.154"
tokio = { version = "1.54.1", features = ["macros", "rt", "test-util", "net", "io-util"] }
tracing-subscriber = { version = "0.3.23", default-features = false, features = ["std", "fmt"] }
rcgen = { version = "0.14.10", default-features = false, features = ["crypto", "pem", "aws_lc_rs"] }
```

Why each is there, and what is deliberately absent:

- `reqwest` with `default-features = false` and `rustls-no-provider` only, as `AGENTS.md` requires.
  Not enabled: `json` (bodies are built and parsed by the transport so that secret-bearing bodies
  stay in zeroizing buffers and every response goes through the size cap), `http2`, `charset`,
  `gzip`, `cookies`, `system-proxy`, `form`, `query`.
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

The mock crate (`publish = false`) depends on `axum` 0.8.9 with `default-features = false` and the
features `http1`, `tokio`, `json`, `query`, `form`; `tokio`; `serde`; `serde_json`; `aws-lc-rs` (its
own verification of SigV4, TSIG and PS256, independent of the crate under test); `base64`;
`roxmltree`; `fastrand`. It does not depend on `zonewright`.

`cargo deny` (`dev/deny.toml`): `ring`, `openssl`, `openssl-sys` and `native-tls` are banned;
`[graph] all-features = true`; wildcard versions denied; licenses allowed: MIT, Apache-2.0, ISC,
Unicode-3.0, Unlicense, BSD-3-Clause, CDLA-Permissive-2.0. `openssl-probe`, a certificate-path
helper pulled in by the platform verifier, is not OpenSSL and is not banned.

### 9.4 Checks behind this section

Run on 2026-11-14 in a throwaway project with the dependency lines above:

- The set resolves and compiles. The highest `rust-version` declared in the tree is 1.88
  (`hickory-proto`, the `icu_*` crates under `idna`, and `rcgen` and `time` among the
  dev-dependencies).
- `ring`, `openssl-sys`, `native-tls`, `h2`, `moka` and `uuid` are not in the tree.
- A `reqwest::Client` built from a `rustls::ClientConfig` made as in section 5.1 builds with no
  process-wide provider installed and leaves none installed; it completes an HTTPS request to a
  loopback server whose certificate chains to a root passed through `new_with_extra_roots`, refuses
  the same server without that root, negotiates HTTP/1.1, and returns a 307 answer instead of
  following it.
- An RSA key in a PEM document with a line of text before the `BEGIN` line is read by
  `rustls-pki-types` as PKCS#8, signs with `RSA_PSS_SHA256` and verifies with
  `RSA_PSS_2048_8192_SHA256`.
- `jiff` with only `std` parses an RFC 3339 timestamp, formats `%Y%m%dT%H%M%SZ` and parses
  `Sun, 06 Nov 1994 08:49:37 GMT`.
- `hickory-proto` with only `std` encodes a query and decodes it back.

Read in source, not run: in `reqwest` 0.13.5, ALPN and `identity` are applied only to configurations
`reqwest` builds itself; in `aws-lc-rs` 1.19.0, `RSA_PSS_SHA256` uses a salt as long as the digest;
in `rustls-platform-verifier` 0.7.1, `Verifier::new` fails on Unix-like systems when no CA
certificate can be loaded and no extra root was given.

Not checked: the mock crate's dependency set as a whole (only that `axum` 0.8.9 has the named
features), Windows and Android builds, and `cargo deny` with `all-features = true` on the final
manifest.

## 10. Layout

```text
dev/
  Cargo.toml             virtual workspace: members "zonewright", "mock"; resolver "3";
                         [workspace.package] edition, rust-version, license, repository;
                         [workspace.lints]
  Cargo.lock             committed
  deny.toml
  clippy.toml            lets tests use unwrap, expect, panic and indexing
  zonewright/
    Cargo.toml
    src/
      lib.rs             module tree, re-exports, crate docs
      name.rs            DomainName
      record/            mod.rs, rtype.rs, ttl.rs, data.rs, rrset.rs, text.rs (tokenizer and
                         escapes), wire.rs, txt.rs, mx.rs, srv.rs, caa.rs, tlsa.rs, svcb.rs
      error.rs           Error, ErrorKind, Operation
      redact.rs          Detail, Scrubber
      id.rs              ProviderId
      meta.rs            ProviderMeta, ConfigField, FieldKind, Capabilities
      provider.rs        Provider, Expect, outcomes, CheckReport, ZoneInfo
      context.rs         Context, ContextOptions
      locks.rs           per-name locks
      values.rs          the generic TXT value layer (section 3.5)
      dns01.rs
      http/              mod.rs, tls.rs, request.rs, retry.rs, token.rs, keystone.rs, gate.rs,
                         poll.rs, pager.rs, zone_cache.rs, encode.rs, url.rs      (__http)
      crypto/            mod.rs, hmac.rs, ps256.rs, sigv4.rs                      (__crypto)
      inspector/         mod.rs, config.rs, exchange.rs, discovery.rs, answer.rs,
                         wait.rs, cname.rs                                        (inspector)
      providers/
        mod.rs           one `pub mod` per provider; AnyProvider; the forwarding macro
        <id>/
          mod.rs         `pub(crate) mod meta;` always; `mod client;` and re-exports behind
                         the provider's feature
          meta.rs        the provider's ProviderMeta: fields, capabilities, defaults
          client.rs      Config, Credentials, the client, its Provider impl
          ...            further files as the client needs (rfc2136: wire.rs, tsig.rs)
    tests/
      common/            mod.rs (context and client builders, canaries), echo.rs, live.rs
      <id>.rs            one file per provider, `#![cfg(feature = "<id>")]`
      conformance.rs     IDs, metadata, PROVIDERS.md, capability/behavior agreement, required
                         tests
      names.rs, records.rs, values.rs, dns01.rs, transport.rs, secret_types.rs, inspector.rs
      fixtures/<id>/     synthetic fixtures, compared byte for byte
  mock/
    Cargo.toml           zonewright-mock, publish = false
    src/
      lib.rs             server start/stop, request log, fault injection
      echo.rs            the echo server of section 12.2
      dns.rs             UDP+TCP DNS server for the inspector tests
      <id>.rs            one stateful mock per provider
```

Ownership, so that fifteen providers can be written in parallel without touching the same file:

- Shared files, edited only by the lead: everything outside `providers/<id>/`, `tests/<id>.rs`,
  `tests/fixtures/<id>/` and `mock/src/<id>.rs`. That includes both `Cargo.toml` files,
  `providers/mod.rs`, `id.rs`, `context.rs`, the whole `http/`, `crypto/`, `record/` and
  `inspector/` trees, `tests/common/`, `mock/src/lib.rs`, and `PROVIDERS.md`, `CHANGELOG.md` and
  this document.
- Files of one provider, edited by the developer of that provider: `src/providers/<id>/**`,
  `tests/<id>.rs`, `tests/fixtures/<id>/**`, `mock/src/<id>.rs`.
- The core phase creates, for all fifteen providers, the feature, the `AnyProvider` variant, the
  module with a complete `meta.rs` and a stub `client.rs` whose operations all return
  `Error::Unsupported`, the empty test file and the empty mock module. A provider developer then
  never needs a shared file. A need for a new shared helper, or a change to one, goes to the lead.
- Provider state that must outlive a client (nic.ru, acme-dns, Timeweb Cloud; section 11.3) is a
  type defined in the provider's directory and held by `Context` in a field behind the provider's
  feature. The field is added in the core phase.

## 11. Providers

`PROVIDERS.md` remains the list of providers and of what is implemented and verified. The tables
here record what each API is like and what this design plans on it. "Earlier version proven live"
repeats the note of `PROVIDERS.md`; it does not make a client verified.

### 11.1 API facts

| ID              | Authentication                                                             | Native unit                                                   | Zone listing                      | `txt_values`                                               | `preconditions`                 | Provider-side operations |
| --------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------- | --------------------------------- | ---------------------------------------------------------- | ------------------------------- | ------------------------ |
| `acme_dns`      | `X-Api-User` and `X-Api-Key` headers of a registration                     | two rotating TXT values per registration                      | no                                | `Rotating`                                                 | —                               | no                       |
| `beget`         | login and API password in the form body of every POST                      | the TXT set of one name, replaced whole                       | yes                               | `ReadThenWrite`                                            | `ReadThenWrite`                 | no                       |
| `cloud_ru`      | access key exchanged for a bearer token (1 h)                              | one record per name and type holding a list of values         | yes                               | `ReadThenWrite` (re-read before the write)                 | `ReadThenWrite`                 | yes                      |
| `cloudflare`    | static bearer API token                                                    | individual record with an ID                                  | yes (active zones)                | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `digitalocean`  | static bearer token                                                        | individual record with an ID                                  | yes                               | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `hetzner`       | static bearer project token (Cloud API, not the legacy DNS API)            | rrset with value-level add and remove actions                 | yes (primary zones)               | `PerValue`                                                 | `ReadThenWrite`                 | yes (actions)            |
| `nicru`         | OAuth 2 password grant, bearer token                                       | individual record with an ID, staged until a zone-wide commit | yes                               | `PerValue` (a zone with foreign staged changes is refused) | `ReadThenWrite`                 | no                       |
| `regru`         | user name and API password in every form POST; optional client certificate | individual record without an ID                               | no                                | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `rfc2136`       | TSIG (HMAC-SHA-256 or -512) on every message, DNS over TCP                 | individual RR                                                 | no (the protocol has none)        | `PerValue`                                                 | `Atomic` (update prerequisites) | no                       |
| `route53`       | AWS Signature Version 4; optional session token                            | rrset, changed by an atomic change batch                      | yes (public zones)                | `Conditional`                                              | `Atomic`                        | yes (`INSYNC`)           |
| `selectel_v2`   | Keystone password exchanged for an `X-Auth-Token` (24 h)                   | rrset with an ID                                              | yes (own project, enabled zones)  | `ReadThenWrite`                                            | `ReadThenWrite`                 | no                       |
| `timeweb_cloud` | static bearer token                                                        | individual record with an ID                                  | yes                               | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `vk_cloud`      | Keystone password exchanged for an `X-Auth-Token`                          | individual record with an ID (TXT-specific paths)             | yes                               | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `yandex_360`    | static OAuth token                                                         | individual record with an ID                                  | yes (domains delegated to Yandex) | `PerValue`                                                 | `ReadThenWrite`                 | no                       |
| `yandex_cloud`  | service-account key, PS256 JWT exchanged for an IAM token (≤ 12 h)         | rrset addressed by name and type                              | yes (public zones of the folder)  | `Conditional`                                              | `Atomic`                        | yes (operations)         |

`txt_values` and `preconditions` are the capability values of section 2.5; what they mean for a
concurrent writer outside the process is in sections 3.5 and 3.4. `preconditions` matters only once
a provider has record-level operations; until then it is listed as what the provider's API allows.
For acme-dns it has no meaning.

### 11.2 Support planned by this design

"TXT only until established" means: the record-level operations stay unsupported for this provider
until its record-level API (endpoints, the shape of each record type, TTL rules) has been taken from
the provider's documentation or observed against the live API, as hard rule 3 requires. Nothing in
this table is a guess about such an API.

| ID              | TXT values             | Record level                                                                             | Record types (record level)                                                  | Default `ttl` setting | Default propagation timeout | TXT dialect, read / write                               | Source of API knowledge                                                                            |
| --------------- | ---------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | --------------------- | --------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `acme_dns`      | add only; plain values | impossible: the API has no read, no delete and nothing but TXT                           | —                                                                            | not settable          | 60 s                        | none / Raw                                              | acme-dns README and server source                                                                  |
| `beget`         | yes; plain values      | TXT only until established (what a write of one type does to other types is unconfirmed) | —                                                                            | 300                   | —                           | Auto / Raw                                              | Beget.API documentation, lego. Whether the API accepts POST is unconfirmed (section 13.4)          |
| `cloud_ru`      | yes; plain values      | TXT only until established (native unit already fits; the type list is not established)  | —                                                                            | 60                    | —                           | Auto / Raw                                              | Evolution DNS OpenAPI specification and documentation                                              |
| `cloudflare`    | yes; plain values      | TXT only until established                                                               | —                                                                            | 120                   | 120 s                       | Auto / Presentation                                     | Cloudflare API v4 documentation, lego                                                              |
| `digitalocean`  | yes; plain values      | TXT only until established                                                               | —                                                                            | 30                    | 120 s                       | Auto / Raw                                              | DigitalOcean API v2 reference, lego                                                                |
| `hetzner`       | yes; plain values      | TXT only until established (rrset listing and whole-set calls not established)           | —                                                                            | 60                    | 120 s                       | Auto / Presentation                                     | Hetzner Cloud API reference, lego, hcloud-go schema                                                |
| `nicru`         | yes; plain values      | TXT only until established                                                               | —                                                                            | 30                    | 1200 s                      | Raw / Raw                                               | lego and third-party clients; the official documentation was not readable                          |
| `regru`         | yes; plain values      | TXT only until established                                                               | —                                                                            | not settable          | —                           | Auto / Raw                                              | lego and a third-party client library. Earlier version proven live                                 |
| `rfc2136`       | yes                    | get, set, delete possible by the protocol, planned; listing impossible                   | any type with a wire form                                                    | 60                    | —                           | wire format                                             | RFC 2136, RFC 8945, RFC 7766, RFC 1035                                                             |
| `route53`       | yes; plain values      | TXT only until established (alias and routing-policy sets need a decision first)         | —                                                                            | 60                    | 120 s                       | Auto / Presentation                                     | Amazon Route 53 API reference, lego                                                                |
| `selectel_v2`   | yes; plain values      | list, get, set, delete                                                                   | A, AAAA, ALIAS, CAA, CNAME, DNAME, HTTPS, MX, NS, SOA, SRV, SVCB, SSHFP, TXT | 60                    | —                           | Auto / Presentation                                     | Selectel DNS API v2 and authorization documentation. Earlier TXT-level version proven live         |
| `timeweb_cloud` | yes; plain values      | TXT only until established (the v1 endpoints in use are marked deprecated)               | —                                                                            | provider default      | —                           | Auto / Raw                                              | a client generated from the public OpenAPI description, lego                                       |
| `vk_cloud`      | yes; plain values      | TXT only until established (only TXT endpoints are known)                                | —                                                                            | 60                    | —                           | Auto / Raw                                              | lego only; the provider's documentation was not readable                                           |
| `yandex_360`    | yes; plain values      | TXT only until established                                                               | —                                                                            | 300                   | —                           | Auto / Raw                                              | Yandex 360 API documentation, lego                                                                 |
| `yandex_cloud`  | yes; plain values      | list, get, set, delete                                                                   | A, AAAA, ANAME, CAA, CNAME, HTTPS, MX, NS, PTR, SOA, SRV, SVCB, TXT          | 60                    | —                           | Auto / Raw for TXT values, Presentation at record level | Yandex Cloud DNS, IAM and Operation API documentation, lego. Earlier TXT-level version proven live |

Notes on the table:

- "plain values" is `Capabilities::txt_plain_only` and concerns the TXT value operations. It is
  lifted per provider when the encoding of other values is established.
- At record level, Selectel v2 and Yandex Cloud write TXT as quoted chunks of at most 255 octets.
  The earlier record-level implementation establishes that form for printable ASCII without `"` and
  `\` (SPF, DKIM, DMARC and similar values of any length). A value that would need an escape is
  refused with `InvalidInput` until the provider's handling of escapes is established.
- TLSA is absent from both record-type lists because neither API accepts it; SOA is read-only
  everywhere, and the apex NS set is not writable (section 3.4).
- Yandex Cloud writes plain TXT values unquoted in the value operations, as the version proven live
  did, and quoted canonical text at record level, as its documentation describes for values with
  spaces. Both are read back with `Auto`.
- The order in which further providers get record-level support is set by the maintainer.

### 11.3 Provider-specific design points

Settings and credentials keep the key names of the earlier TXT-only implementation, with these
differences:

- Every provider: the application-owned key for a propagation timeout is not a setting of the crate.
  The provider's recommendation is `ProviderMeta::default_propagation_timeout`.
- `selectel_v2`: the project is given by exactly one of `project_id` and `project_name` (Keystone
  scope by ID, or by name within the account's domain), because the two earlier implementations each
  used one form.
- `yandex_cloud`: `folder_id` becomes optional and `zone_ids` (an object mapping zone names to zone
  IDs) is added; at least one of them is required. A configured zone ID is verified against the
  zone's name before first use and serves accounts whose role is granted on a zone rather than on
  the folder. Zones without a configured ID are looked up in the folder; of several zones with the
  same name only a public one is used, and two public ones are `Error::Config`.

Behavior that the design fixes because the generic sections cannot:

- `acme_dns`. The server keeps the two most recent values of a registration and has no read. A value
  sent while it is already in one slot overwrites the other slot, so a needless repeat can displace
  a live neighbour (the wildcard and the base name of one certificate share a challenge name). The
  client therefore keeps, in `Context`, per server URL and name, at most two values this process
  sent, each with the time of the send and whether it was confirmed (a 2xx answer) or had an unknown
  outcome (timeout, connection lost, 5xx). An entry is forgotten 15 minutes after it was recorded,
  when a third value for the name displaces the oldest, and on a definite refusal of its send; the
  memory holds at most 1024 names and drops the least recently used. `add_txt_value` behaves as
  follows. A value with a live confirmed entry is not sent again. A value with a live unconfirmed
  entry is sent again only if the name has no other live entry. Anything else is sent. Every one of
  these paths returns `AddOutcome::Accepted`, the two that send nothing included: the client cannot
  observe the server, another writer may have displaced the value since, and `AlreadyPresent` would
  claim knowledge it does not have. A send that displaces a remembered live value is logged at
  `WARN`. The name must equal the `fulldomain` of a configured registration, and the value must be
  43 characters of the base64url alphabet, the only thing the server accepts; otherwise
  `Error::InvalidInput`, before any request.
- `beget`. A write happens only after a complete read whose answer names the requested name. A name
  that holds records of other types is refused (`Error::Rejected`) for both add and remove, because
  it is not established that a TXT write leaves them alone. Credentials go in the POST body, never
  in the query string.
- `cloud_ru`. More than one TXT record for a name is `Error::Protocol`. A record marked read-only is
  `Error::Rejected`. A missing list in a listing answer is `Error::Protocol`, never an empty result.
- `hetzner`. Only zones in primary mode are usable; a secondary zone is reported by `check` as not
  found with a detail, and operations on it are `Error::Rejected`. Values are removed using exactly
  the text the API returned.
- `nicru`. Changes are staged and published by a commit that covers the whole zone, including edits
  staged by anyone else. The client therefore (a) takes a per-zone lock in `Context` for the whole
  read, edit and commit; (b) refuses to work in a zone that has staged changes it did not make
  (`Error::Rejected`, nothing committed); (c) records the zone as "has our staged changes" in
  `Context` before it stages an edit and clears the mark after a successful commit, so that an
  operation that failed or was dropped between the two is finished by the next operation instead of
  being mistaken for a foreign edit; (d) tries the commit up to three times and returns
  `Error::Transient` if all fail. The mark is process memory; after a restart a zone left with
  staged changes needs a commit by hand.
- `regru`, `beget`. With an empty zone list `check` has no request that tests the credentials;
  `credentials_verified` is false.
- `rfc2136`. DNS over TCP to the configured `server` (an IP literal or a host name, with an optional
  port, default 53).
  - Timeouts: `ContextOptions::connect_timeout` covers name resolution and the TCP connect;
    `ContextOptions::request_timeout` covers one exchange, from sending a message to having read the
    whole response. A response is at most 65535 octets by the framing. Queries and the single-RR add
    and delete are idempotent on the server (RFC 2136 section 3.4.2) and get at most 3 attempts with
    the back-off of section 5.3; `SERVFAIL` counts as a transient failure.
  - `ContextOptions::loopback_only`: a `server` that is not a loopback IP literal is `Error::Config`
    at construction. Host names are refused in that mode, since classifying one would need a lookup.
  - A response that is not signed with the key is `Error::Protocol` whatever its response code, so a
    forged negative answer cannot turn a removal into `NotPresent`. TSIG errors are `Error::Auth`,
    with a hint about clock skew for `BADTIME`. `NOTAUTH` is `ZoneNotFound`; `REFUSED` on an update
    is `Forbidden`; `REFUSED` on the preceding query is tolerated and leads to the blind path of
    section 3.5. The TSIG key is at least 16 octets.
  - Preconditions: the protocol's update prerequisites (RFC 2136 section 2.4) are evaluated by the
    server atomically with the update, hence `Preconditions::Atomic`. The record-level operations,
    when added, send `Expect::Absent` as "RRset does not exist" and `Expect::Matches`, as well as
    the client's own read, as "RRset exists (value dependent)"; a failed prerequisite (`YXRRSET`,
    `NXRRSET`) is handled as section 3.4 describes for a refused conditional write. A prerequisite
    cannot express a TTL, so a TTL in `Matches` is compared by the client after its read.
  - The TXT value operations send single-RR changes and need no prerequisite (`PerValue`). Deleting
    a whole rrset is never sent by them.
  - TTL: with read access an add carries the TTL of the existing rrset. Without it the exception of
    section 3.6 applies: the add carries the client's `ttl`, and the server may apply it to the
    whole rrset.
- `route53`. The zone is found by exact name among public hosted zones; several with the same name
  are `Error::Config` unless `hosted_zone_id` selects one. Region `us-east-1` and service `route53`
  are constants. A signature rejected for clock skew is `Error::Auth` with that hint.
- `selectel_v2`. Names are sent in Unicode form. Records with the `disabled` flag follow section
  3.4. An rrset holds at most 100 records; a larger request is `InvalidInput`. An rrset is addressed
  by reading it by name and type on every operation, not by a remembered ID. The answer to a create
  of an existing rrset is not documented, so a refused create is followed by a read (section 3.5);
  the delete of the rrset is sent once. An update sends back the comment and, in the documented
  `X-Managed-By` header, the managing resource as read, since whether an update without them clears
  them is not established. A listing ends when the items received reach its stated `count`; one that
  stops short of it is `Error::Protocol`. A project given by name is scoped within the account's
  Keystone domain, and the project ID the identity service states for the token tells the project's
  zones from others; of several zones with the requested name, the one of that project is used.
  `check` exchanges the credentials for a new token even when one is cached.
- `timeweb_cloud`. A record this process created is remembered by ID so it can be removed even if
  the listing does not show it. The memory is in `Context`, holds at most 1024 records, and drops an
  entry when the record is removed or 24 hours after it was created.
- `yandex_cloud`. The strict write must repeat the existing set exactly, including fields this crate
  does not model, so the client keeps the JSON object it read and sends that object as the deletion.
  TTL travels as a JSON string.

## 12. Testing

### 12.1 Mocks

The default test run needs no network and no real credentials. Every client is tested against a
stateful mock of its provider's API in the workspace member `zonewright-mock`: an HTTP server on
`127.0.0.1` with an ephemeral port (for RFC 2136, a DNS-over-TCP server), holding zones and records
in memory and behaving as the provider's documentation describes. Stateful mocks rather than a
request-matching library, because the properties under test are about state: a foreign value is
still there afterwards, a second identical call writes nothing, a write is rejected when the set
changed in between.

Every mock offers the same control surface: a seed, the list of requests received (method, path,
selected headers, body), direct access to the stored records, and fault injection (answer the next N
matching requests with a status, a `Retry-After`, a delay, or a dropped connection; insert a foreign
change before the next write; recreate a zone under a new identifier). Mocks that issue tokens can
revoke them and count how many they issued. The Route 53 mock verifies the SigV4 signature, the RFC
2136 mock verifies and produces TSIG, and the Yandex Cloud mock verifies the PS256 signature, each
with code that shares nothing with the crate under test.

Fixtures are synthetic. Keys are generated inside the tests.

### 12.2 Secret tests

For every client, in its own test file:

- `<id>_secret_echo`. The echo server answers every request with the chosen status and a body that
  repeats the request's body and its authentication headers inside the fields a client reads error
  text from (JSON or XML as the client expects); token endpoints hand out a canary token and the
  server then echoes that too. The credentials are canaries containing `@`, a space, `/`, `+`, both
  quotes, `& < > \ ~ * =`, non-ASCII letters and (where a header does not carry them) a newline, so
  that every encoding and escaping changes them. The test runs for every dialect of the shared
  support in `tests/common/echo.rs`: each renderer of the echo server (JSON as `serde_json`, PHP, Go
  and .NET escape it, with `\uXXXX` and a plain `/`, PHP JSON after a notice line, JSON inside JSON,
  JSON under a key no client reads, form-encoded JSON, XML with named entities, numeric references
  or minimal escaping, plain text) with the text verbatim, and each spelling (form-encoding with
  `+`, `%20` or lowercase hex; the percent-encodings of Python, JavaScript, RFC 3986 and Go) inside
  JSON and plain text. It runs `check` and a write, requires the write to fail, and asserts on the
  `Display` and `Debug` of every error, on every `ZoneCheck::detail`, and on the client's `Debug`:
  no canary in any of those spellings, no fragment of one, no JWT; and the write's error does
  contain `[redacted]`, which proves the echo reached the error path and the test is not vacuous. It
  also asserts that the API endpoint, and for token clients the token endpoint, were actually
  reached. Every secret field of the credentials is covered.
- RFC 2136 has no HTTP echo. Its equivalent asserts that the TSIG secret, in base64 and in hex, does
  not occur in any error or `Debug` output across the error paths of its mock.
- `<id>_no_secret_in_logs`. A `tracing` subscriber at `TRACE` captures everything while the client
  goes through a success, a 401 and a 500; the capture must contain the transport's event and none
  of the canaries or issued tokens.

Once for the crate: a compile-time test that no client type and no credentials type implements
`Display` or `Serialize`; unit tests of the scrubber (every spelling, every decoded dialect, the
truncated tail, run-time tokens per slot, its `Debug`); the transport's secret tests over every
dialect and every credential position (bearer, custom header, basic, form body, JSON body, query),
which also require the message to be kept, with the canaries cut out in place, wherever the echo
uses a spelling the scrubber knows exactly; a test that a redirect is not followed and that the
address it points to receives no connection, with and without a client certificate; a source scan
for `bearer_auth` and `basic_auth`.

### 12.3 Invariant tests

For every client, in its own test file, where the operation exists:

- `<id>_name_outside_zone_sends_nothing`: for a name in another zone, a name that merely ends with
  the zone's text, and a sibling zone, every mutating operation returns `NameOutsideZone` and the
  mock's request log is empty, token requests included.
- `<id>_add_is_idempotent`: `Created`, then `Appended` for a second value, then `AlreadyPresent`,
  with no write request for the last.
- `<id>_never_removes_foreign_value`: removing an absent value next to a foreign one writes nothing
  and returns `NotPresent`; adding and removing our value leaves the foreign value, its TTL and its
  attributes as they were.
- `<id>_remove_last_value_deletes_rrset` and `<id>_remove_is_idempotent`.
- `<id>_concurrent_adds_are_serialized`: two adds to one name from two clients sharing a `Context`
  both end up in the rrset, with the mock delaying the first write.
- For conditional-write providers, `<id>_concurrent_change_is_conflict`: a foreign change inserted
  between the read and the write is not lost.
- For providers with record-level operations, `<id>_failed_expectation_is_precondition_failed`:
  `Expect::Absent` on an existing set and `Expect::Matches` on a changed one return
  `PreconditionFailed` and write nothing; and `<id>_listing_reports_skipped_sets`.
- `<id>_stale_zone_id`: after the mock recreates the zone under a new identifier, the next operation
  succeeds or fails cleanly and the one after it succeeds; a removal never reports `NotPresent` for
  a value that is there.
- `<id>_writes_are_sent_once`, for every client that writes: with a `502`, a `429` and a `401`
  injected on each write request, the request log holds exactly one such request per operation.
- `<id>_unsupported_operations_send_nothing`, for every client with an unsupported operation.

`tests/conformance.rs` holds the checks that span providers: `parse(as_str(id)) == id` for all IDs,
serde round trip, the literal table of section 2.4, the comparison with `PROVIDERS.md`, every
metadata field key present in the corresponding `Config` or `Credentials` type, an unsupported
operation returning `Unsupported` with zero requests, every default endpoint being `https`, a scan
that no file under `src/providers/` calls `Detail::new` or a text-taking `Error` constructor, and a
scan that every provider's test file defines the required test names of sections 12.2 and 12.3 (with
an explicit list of the exceptions: `acme_dns` has no removal, `rfc2136` has its own secret test).
The scan is what keeps "tests cover this for every client" true when a sixteenth provider is added.

The generic value layer is additionally tested against an in-memory backend for all three native
shapes, including duplicates of a value, non-plain values and failures injected between the read and
the write.

### 12.4 Carrying over the earlier tests

The earlier TXT-only implementation has a test suite per provider against mocks of the same kind.
They are ported with their mocks, one provider at a time, and keep what they assert. Mapping:

| Earlier                                                   | Here                                                                       |
| --------------------------------------------------------- | -------------------------------------------------------------------------- |
| per-provider suites                                       | `tests/<id>.rs`, renamed to the scheme of sections 12.2 and 12.3           |
| a suite shared by three providers                         | split into the three providers' files                                      |
| the echo suite for all HTTP clients                       | `<id>_secret_echo` in each file, on the shared harness                     |
| the log and zone-boundary suite written for one provider  | `<id>_no_secret_in_logs`, `<id>_name_outside_zone_sends_nothing`           |
| unit tests that put a wrong zone ID into a client's cache | `<id>_stale_zone_id`, driven through the mock instead of a test hook       |
| a test tying endpoint constants to a research document    | a reference comment on every constant (hard rule 3) plus the `https` check |
| name, challenge and normalization unit tests              | `tests/names.rs`, `tests/dns01.rs`, `tests/records.rs`                     |
| crypto vectors                                            | unit tests in `crypto/`                                                    |
| inspector tests against a fake resolver                   | `tests/inspector.rs` on the mock DNS server                                |

Assertions that change because this design changes the behavior, each stated where the change is
described: `acme_dns` removal (`Unsupported`), blind writes (`Accepted`), a concurrent change at a
conditional-write provider (`Conflict` instead of a rejection), a rejected token on a non-idempotent
request (the request is not repeated), every acme-dns add (`Accepted`), a stale zone ID on removal,
a 429 on a non-idempotent request (not retried), the propagation-timeout setting (gone), error codes
(the application's concern now).

The record-level clients for Selectel v2 and Yandex Cloud come with tests that drive them through an
application's reconcile loop. Those are rewritten against `list_rrsets`, `get_rrset`, `set_rrset`
and `delete_rrset`; their stateful fakes are merged into the two providers' mocks, including forced
small pages, lost writes and the strict-write race.

### 12.5 Live tests

Live tests are `#[ignore]`, live in the provider's test file with names starting `live_`, and are
run only by the maintainer. They read:

- `ZONEWRIGHT_LIVE_<ID>_SETTINGS`: the settings JSON;
- `ZONEWRIGHT_LIVE_<ID>_CREDENTIALS`: the credentials JSON;
- `ZONEWRIGHT_LIVE_<ID>_ZONE`: a zone the test may write to;

with `<ID>` the provider ID in upper case (`ZONEWRIGHT_LIVE_SELECTEL_V2_ZONE`). A missing variable
fails the test with a message naming it. The inspector's live test reads `ZONEWRIGHT_LIVE_ZONE`.

A live test works only under a label it generates (`_zw-live-<random>` below the zone), registers
every name it writes with a guard, and the harness runs the guard's cleanup after the test body
whether it returned or panicked. Cleanup removes exactly the values the test added, with the value
operations; it never deletes an rrset it did not create and never lists-and-deletes by pattern.

A provider moves to "Verified against the live API" in `PROVIDERS.md`, and its `verified` flag turns
true, only by the maintainer's commit after these tests passed.

### 12.6 Gates

`cargo fmt --check`; `cargo clippy --all-features --all-targets` with warnings denied;
`cargo deny check`; `cargo test --all-features`; `cargo hack check --each-feature` over the public
features and `cargo hack test --each-feature` likewise, plus the no-feature build; `cargo doc` with
warnings denied; a build with the MSRV toolchain. Workspace lints: `unsafe_code = "deny"`,
`missing_docs`, and the clippy lints `unwrap_used`, `expect_used`, `panic`, `unreachable`, `todo`,
`unimplemented` and `indexing_slicing` denied in library code and allowed in tests.

## 13. Versioning, choices, open points

### 13.1 MSRV

`rust-version = "1.88"`, one value for the whole crate.

It is the highest `rust-version` any dependency declares, in every feature combination: the Unicode
data crates under `idna` (always present) and `hickory-proto` (inspector) both declare 1.88; nothing
declares more (section 9.4). The language itself needs less (edition 2024 is 1.85). Both known
consumers build on a newer toolchain.

This differs from the value first proposed for this design, 1.89. That value came from a cache crate
underneath a DNS resolver library; section 8.1 does not use that library, so the reason is gone and
the same rule, "the lowest value that is true for every feature", now gives 1.88. Raising it later
is a one-line change and, before 1.0, a minor-version event.

### 13.2 SemVer notes

Before 1.0 a breaking change raises the second number. To keep that rare:

- `#[non_exhaustive]` enums: `ProviderId`, `Error` and each of its variants, `ErrorKind`,
  `Operation`, `NameError`, `RecordError`, `FieldKind`, `TypeSet`, `Preconditions`, `TtlSupport`,
  `ValueGuarantee`, `SkipReason`, `Expect`, `SetOutcome`, `DeleteOutcome`, `AddOutcome`,
  `RemoveOutcome`, `SvcParam`, `AnyProvider`, `CnameError`, and in the inspector `Answer`,
  `Condition`, `NsDiscovery`, `IpFamilies`, `InspectorError`.
- `#[non_exhaustive]` structs: `ProviderMeta`, `ConfigField`, `Capabilities`, `CheckReport`,
  `ZoneCheck`, `ZoneInfo`, `ZoneListing`, `SkippedRrset`, `ContextOptions`, every `…Config` and
  `…Credentials`, `CnameChain`, `InspectorConfig`, `NameServer`, `WaitOptions`, `ServerReport`,
  `Report`.
- Exhaustive on purpose: `Mx`, `Srv`, `Caa`, `Tlsa`, `Svcb`, `Question`, `Expectation`.
- The `#[non_exhaustive]` structs that an implementation of `Provider` has to return (`CheckReport`,
  `ZoneCheck`, `ZoneInfo`, `ZoneListing`, `SkippedRrset`) have `new` constructors taking today's
  fields. A field added later gets a default in `new` and a setter, so existing callers keep
  compiling.
- Not breaking: adding a provider (ID, feature, variant), an error kind with its constructor, a
  capability field, a setting with a default, a refreshed type-mnemonic table, a trait method with a
  default body, raising a listing or size limit.
- Breaking: renaming or removing a setting or credentials key, changing a persisted ID (never done),
  changing the canonical text of a type that already has one, adding a required trait method, and
  moving to an incompatible version of `secrecy`, because `SecretString` is in public signatures.
  Moving to a new version of a private dependency (`reqwest`, `rustls`, `hickory-proto`, `jiff`) is
  not breaking.
- Changing a type from "generic form" to its own canonical form (section 4.7) changes how existing
  values of that type are written. It is listed in the changelog and treated as breaking.
- Third-party types in public signatures: `secrecy::SecretString` (credentials), and the `serde`
  traits as implemented for public types. Nothing from `reqwest`, `rustls`, `hickory`, `jiff`,
  `serde_json`, `tokio` or `bytes`.
- The `tokio` runtime is required at run time by every provider client and by the inspector. This is
  part of the contract although no `tokio` type is public.

### 13.3 Design choices

Choices not fixed by `AGENTS.md`, each with its reason and, where there was one, the alternative
that was rejected. The maintainer can overrule any of them.

Foundations:

1. **Async runtime: tokio.** The HTTP client requires it and both known consumers run on it. A
   runtime-agnostic design would need its own timers, locks and sockets for no present user.
2. **MSRV 1.88.** Section 13.1.
3. **TLS: the crate builds its own `rustls::ClientConfig` with an explicit `aws-lc-rs` provider and
   hands it to the HTTP client.** With the `rustls-no-provider` feature the ordinary path panics if
   the application installed no process-wide provider, and library code must not panic; installing
   one from a library is ruled out by decision 3. Rejected: requiring the application to install a
   provider (a panic at a distance); `reqwest`'s `rustls` feature (not what `AGENTS.md` prescribes).
   Cost: `rustls` must match `reqwest`'s line (section 9.3).
4. **No system CA certificates is not a construction error.** A reject-all verifier is installed
   instead (section 5.1), so loopback tests and builds without HTTPS providers in use do not depend
   on the host's certificate store. Rejected: probing the store separately, as an earlier
   implementation did, which needed another dependency and a re-executed test binary.
5. **HTTP/1.1 only; `reqwest` without `json` and `http2`.** Section 5.1 and 9.3.
6. **`Cargo.lock` is committed.** The gates, in particular the ban on `ring`, are reproducible only
   with pinned versions; a library's lock file does not affect its users.
7. **Workspace layout `dev/zonewright` and `dev/mock`.** The mocks are several thousand lines used
   by integration tests of every provider; as a separate unpublished crate they compile once and
   cannot leak into the published one.
8. **Stateful mock servers on `axum`, not a request-matching mock library.** Section 12.1. Rejected:
   rewriting the suites for a mock library, which would lose the state-based assertions.
9. **RFC 2136: hand-written wire format and TSIG, not a DNS client library.** It is existing,
   tested, self-contained code; its feature then needs no dependency beyond the HMAC, and
   `hickory-proto` offers TSIG signing only together with its DNSSEC machinery.
10. **Third-party public types: `secrecy` and `serde` trait impls only.** Section 13.2. In
    particular stored configuration enters as JSON text (`&str`, `&SecretString`), not as
    `serde_json::Value`.
11. **User agent `zonewright/<version>` with an optional application suffix.** Providers can
    identify the library; the application can identify itself without replacing that.

Names and records:

12. **Owner and zone names are one strict type, always absolute, shown with a trailing dot; names
    inside RDATA are a second, permissive type (`TargetName`).** A relative name is ambiguous
    without its zone, and the two earlier implementations each needed helper functions to convert at
    every provider boundary. The split exists because the crate chooses which names it will write
    records at, but not which names an existing zone points to. Rejected: separate zone, owner and
    relative types (more conversions, no extra safety, since "is this inside that zone" is checked
    at run time either way).
13. **Wildcard and underscore labels are valid; other non-LDH octets are not.** Covers every record
    the consumers produce; keeps path and query encoding of names trivial.
14. **`RecordType` is a code plus named pseudo-types, not a string.** Open as decision 4 requires,
    cheap to copy and compare, and a misspelled type is an error rather than a new type. ALIAS and
    ANAME are needed because two providers list them.
15. **TTL is `Ttl`, an integer newtype, optional in `RrSet`.** Section 2.2 and 3.6.
16. **`RecordData` is canonical text without an embedded type.** The rrset carries the type. The
    text is what an application stores and compares; a tagged union of typed records would close the
    set that decision 4 opens.
17. **A TXT value is the joined byte string; character-string boundaries are not preserved.**
    Section 4.4. Rejected: keeping boundaries, which no two providers preserve alike.
18. **Unquoted TXT text containing whitespace is rejected by the parser.** Section 4.4.
19. **Provider text that does not parse is kept as non-canonical data instead of failing the
    listing.** Section 4.9.
20. **Unknown types use the RFC 3597 generic form.** It is the standard's own answer and needs no
    per-type code.

Operations:

21. **Writes take a precondition (`Expect`) instead of separate create and replace methods.** One
    parameter expresses create-only, replace and compare-and-swap, and it maps onto the conditional
    writes two providers have. It is how an application that edits rrsets of any type avoids
    overwriting a concurrent change, which the TXT value operations give only for TXT.
22. **Operations read before they write and report "no change".** Makes repeats cheap and outcomes
    truthful.
23. **Outcomes do not claim knowledge the client lacks**: `Accepted` for blind writes,
    `credentials_verified`, `Unsupported` for acme-dns removal. Rejected: the earlier behavior of
    answering a removal that cannot be done with "not present".
24. **An existing rrset keeps its TTL.** Section 3.6. Rejected: a fixed TTL on every write.
25. **The lock key is the owner name; the locks live in `Context`.** Section 3.3.
26. **No overall deadline per operation; every part is bounded and the future can be dropped.**
    Section 3.7.
27. **A stale zone identifier is re-resolved once before "not found" is believed.** Section 3.8.
28. **Unsupported operations are default trait methods returning a typed error; the trait is not
    sealed.** Section 2.6.
29. **Capabilities and metadata are static per provider and present in every build.** An application
    can describe a provider it did not compile in.
30. **SOA and the apex NS set are not writable in this version.** A guard rail, lifted when a
    consumer needs it.
31. **Settings are strict (`deny_unknown_fields`).** A typo in a key is an error at construction,
    not a silently ignored setting.
32. **Automatic retries follow the letter of the engineering rule: idempotent requests only, also
    for rate-limit answers and rejected tokens.** Section 5.3 and open point 2.

Errors and secrets:

33. **`Error` is an enum with a separate `ErrorKind` and stable kind identifiers.** Variants carry
    typed context (zone, name, status, wait); the kind is what an application switches on and maps.
34. **Inside the crate, error text is built only through the scrubber; public constructors exist for
    implementations outside it.** Section 2.9. A source scan keeps provider clients off the public
    constructors. Rejected: private constructors only, which would make the unsealed trait
    impossible to implement.
35. **Errors carry no `source`.** Section 2.9.
36. **The crypto module is private and keeps a parsed key, not key bytes.** Section 6.

DNS-01 and the inspector:

37. **`challenge_name` drops a wildcard label.** That is what RFC 8555 prescribes; refusing
    wildcards, as one earlier implementation did, pushed the same step into every caller.
38. **CAA policy lookups and CNAME-target policy are out.** Section 7.4.
39. **Inspector: own transport over `hickory-proto`, discovery through recursive resolvers or a
    static list, no iterative descent.** Section 8.1.
40. **Every round asks every server; success is one round in which all agree.** Section 8.6.
41. **Default resolvers are three public ones; the application can replace them.** It works out of
    the box; see open point 4. **Discovered private addresses are refused by default** (section 8.3,
    open point 16).
42. **A static server list is ordinary configuration, not a test-only switch.** In a library the
    application writes the configuration in code; hiding the option would only force tests through a
    back door.
43. **Too many name servers is an error, not a truncated list.** Section 8.3.

Build:

44. **Provider feature names equal provider IDs, underscores included.** Section 9.1.
45. **Private `__` features for dependency groups.** Section 9.1.
46. **One directory per provider with metadata always compiled and the client behind the feature.**
    Section 10.
47. **A scan enforces the per-provider tests.** Section 12.3.

Added after review:

48. **`PreconditionFailed` and `Conflict` are different errors.** One is the caller's expectation
    not holding and never succeeds on repetition; the other is a race the provider caught and the
    next attempt resolves.
49. **A listing returns `ZoneListing` with a `skipped` list instead of a bare vector.** What the
    model cannot hold is reported rather than dropped, without widening `RecordType` to arbitrary
    strings. Rejected: omitting such sets with only a log line, which an application that reconciles
    a zone cannot act on.
50. **The full IANA mnemonic table is built in.** A provider's type name then maps to a code in
    every realistic case.
51. **`Capabilities::txt_values` states what the TXT value operations guarantee against outside
    writers.** The guarantee differs by provider and an application must be able to read it.
52. **No proxy.** Section 5.1.
53. **A rejected token or a failed unconditional whole-set write is not repeated by the transport.**
    Section 5.3.
54. **acme-dns adds always report `Accepted`, and its memory is bounded and expires.** Section 11.3.
55. **Response cap 4 MiB, page limit 1000.** Section 5.4.

### 13.4 Open points for the maintainer

1. **MSRV 1.88 or 1.89.** The design uses 1.88 (section 13.1). If the inspector should use a
   resolver library after all, it is 1.89.
2. **Rate-limit answers to non-idempotent requests.** The earlier TXT-only implementation retried
   any request after a 429, on the grounds that a rate-limited request was not executed. `AGENTS.md`
   says only idempotent requests are retried automatically, and this design follows it: such a
   request returns `RateLimited` and the caller repeats the operation. Allowing the retry is a
   one-line change in the transport if the rule is meant to permit it. The same reading is applied
   to a 401 for a cached token: an idempotent request is repeated with a new token, a non-idempotent
   one is not and returns a retryable error (section 5.3). The earlier implementation repeated both.
3. **Honest outcomes change three earlier behaviors**: acme-dns removal returns `Unsupported`
   instead of "not present", and an acme-dns add always returns `Accepted`; blind RFC 2136 writes
   return `Accepted` instead of a guessed outcome; `check` reports whether credentials were actually
   tested. Applications ported from the earlier implementation must handle them.
4. **Default resolvers of the inspector.** Cloudflare, Google and Quad9 by default means the zone
   names an application inspects are sent to those services unless it configures others. The
   alternative is no default and a required list.
5. **No iterative resolution from the root.** One earlier implementation has it, with detection of
   intercepted port 53 and a fallback mode. This design replaces it by resolver-based discovery and
   static lists (section 8.1). If "what the internet sees, independent of any resolver" is a
   requirement, it is an addition to `NsDiscovery`, not a redesign.
6. **TXT character-string boundaries are not preserved.** Records whose meaning depends on the
   boundaries (DNS-SD attribute lists) cannot be written faithfully through this crate.
7. **SOA and apex NS are not writable** (section 3.4). Say if a consumer needs either.
8. **Beget.** The client sends credentials in a POST body so they stay out of URLs and proxy logs.
   Whether the API accepts POST for these functions is not confirmed by any source; the reference
   client uses GET with credentials in the query string. It needs a live check before the client is
   relied on. If POST is not accepted, the choice is between sending the password in a URL and not
   supporting the provider; this design would not do the former without the maintainer's decision.
9. **Order of record-level work** after Selectel v2 and Yandex Cloud, and for each further provider
   whether its documentation is enough or a live observation is required first.
10. **Trust anchors.** The crate trusts the platform's roots plus certificates the application
    passes. It ships no certificates of its own. An application that needs additional national roots
    supplies them through `ContextOptions`.
11. **Strict settings.** An application that stores its own keys next to the provider's settings
    must strip them before calling the crate. The alternative, ignoring unknown keys, hides typos.
12. **Timeweb Cloud** uses endpoints its own API description marks as deprecated, because the newer
    ones have no listing and were reported to reject challenge names. It stays as ported; a live
    check decides when to move.
13. **Typed views for more record types** (SSHFP, SOA) exist as canonical forms only. Typed structs
    are added on request.
14. **Hard rule 2 against writers outside the process.** At Selectel v2, Beget and Cloud.ru the API
    offers neither a per-value call nor a conditional write, so a TXT value operation cannot rule
    out overwriting a value that another process, or a person in the control panel, adds between the
    client's read and its write. Inside one process the per-name lock closes the gap; outside it
    nothing can. The capability `txt_values == ReadThenWrite` states this. The question for the
    maintainer is whether that reading of hard rule 2 ("guaranteed within a process, best effort
    beyond it where the API gives no means") is acceptable, or whether these three providers need a
    restriction such as writing only below a dedicated label.
15. **No proxy support.** The HTTP client ignores proxy environment variables on purpose (section
    5.1). A deployment that can reach providers only through a proxy cannot use the crate until an
    explicit `ContextOptions` proxy setting is added; say if that is needed.
16. **Private name-server addresses are refused by default** in the inspector. Deployments whose
    authoritative servers are internal must set `allow_private_addresses` or use
    `NsDiscovery::Static`. The earlier implementation accepted them by default.
