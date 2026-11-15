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
of the release, as a hand-maintained table (`MNEMONICS` in `record/rtype.rs`) with the registry's
date and source recorded next to it; the constants above are only the types that also have a
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

/// The TTL an rrset states: a number, or the provider's default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RrsetTtl {
    Explicit(Ttl),
    /// No TTL of the caller's: the provider's default applies (Cloudflare's "automatic", the zone
    /// default of Hetzner, nic.ru and Timeweb Cloud, the TTL a provider that sets every TTL itself
    /// chooses).
    ProviderDefault,
}
impl RrsetTtl {
    pub fn from_secs(secs: u32) -> Result<RrsetTtl, RecordError>;  // Explicit
    pub const fn explicit(self) -> Option<Ttl>;                    // None for ProviderDefault
}
impl From<Ttl> for RrsetTtl {}
// Serialize / Deserialize as the number of seconds, or the string "provider_default".
```

TTL is an integer type, not `Duration`: a DNS TTL has no sub-second part and a 31-bit range, and a
`Duration` field would admit values that cannot be sent. The conversions keep `std::time` available
at the boundary (decision 7). `RrsetTtl` adds the one thing a number cannot say: that the rrset has
no TTL of its own and the provider's default applies. It is a separate type so that `Ttl` stays the
number everywhere else (inspector answers, `TtlSupport` bounds), and no number is reserved to mean
"default" (`0` and `1` are valid TTLs).

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
    /// parsed again for `rtype` and must give the same text. CNAME, SOA, DNAME, ALIAS and ANAME
    /// sets hold exactly one record.
    pub fn new(
        name: DomainName,
        rtype: RecordType,
        ttl: Option<RrsetTtl>,
        records: impl IntoIterator<Item = RecordData>,
    ) -> Result<RrSet, RecordError>;

    pub fn name(&self) -> &DomainName;
    pub fn rtype(&self) -> RecordType;
    pub fn ttl(&self) -> Option<RrsetTtl>;
    pub fn records(&self) -> &[RecordData];
    pub fn contains(&self, record: &RecordData) -> bool;
    /// Same name, type and members; TTL ignored.
    pub fn same_records(&self, other: &RrSet) -> bool;
    pub fn with_ttl(self, ttl: Option<RrsetTtl>) -> RrSet;
}
// Serialize / Deserialize as { "name", "type", "ttl", "records": [...] }. "ttl" is a number, the
// string "provider_default", or null (also when missing) for a set that states no TTL. A
// canonical record is a string, parsed with RecordData::parse for the set's type; a
// non-canonical one is { "raw": text }.

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

```rust
/// TXT data as one byte string: the concatenation of the record's character-strings.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
    /// Every identifier, in alphabetical order of the persisted strings. Complete in every build.
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
impl ProviderMeta {
    /// The field with this key, if any.
    pub fn field(&self, key: &str) -> Option<&'static ConfigField>;
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
    /// A TTL: a number of seconds within the bounds, and, when `provider_default`, also the
    /// string "provider_default" (equal to `ProviderDefaultTtl::can_request` of the provider's
    /// capabilities). Every key named `ttl` has this kind.
    Ttl { min: u32, max: u32, provider_default: bool },
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
    /// individual records (or individual values) and a replacement is several requests, and
    /// where the API cannot replace a set at all. For a provider without record-level operations
    /// in this crate, the flag says what a set replacement is at the provider's API.
    pub atomic_rrset_write: bool,
    pub ttl: TtlSupport,
    /// Whether an rrset can have the provider's default TTL instead of an explicit one
    /// (`RrsetTtl::ProviderDefault`), and whether a write can ask for it (section 3.6).
    pub provider_default_ttl: ProviderDefaultTtl,
    /// Writes complete through a provider-side operation that the client polls.
    pub asynchronous: bool,
}

impl Capabilities {
    /// The operation is offered; `Operation::Check` always is.
    pub fn supports(&self, operation: Operation) -> bool;
    /// In `record_types` and not a query or meta type (section 2.2). `AnyWithCode` excludes the
    /// pseudo-types, which have no code.
    pub fn can_read(&self, rtype: RecordType) -> bool;
    /// `can_read` and not in `read_only_types`.
    pub fn can_write(&self, rtype: RecordType) -> bool;
    /// A number within `ttl`, or the provider's default where `provider_default_ttl` allows a
    /// request for it. Anything else is `InvalidInput` before any request.
    pub fn accepts_ttl(&self, ttl: RrsetTtl) -> bool;
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
    /// rrset and reports the smallest one it reads; a requested TTL counts as already set only
    /// when every record has it.
    PerRecord { min: u32, max: u32 },
    /// The provider chooses the TTL; a requested number is refused, and the provider's default
    /// is the only TTL a write can ask for.
    NotSettable,
}
impl TtlSupport {
    /// `secs` is within the bounds; always false for `NotSettable`.
    pub fn accepts(&self, secs: u32) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderDefaultTtl {
    /// Every rrset has an explicit TTL; every request for the provider's default is refused
    /// before any request, and the `ttl` setting cannot be "provider_default".
    Absent,
    /// An rrset can have the provider's default (it reads so), and a write can ask for it for
    /// the records it creates; a write that would turn an existing explicit TTL into it is
    /// refused after the read and before any write (Timeweb Cloud).
    ForNewRecords,
    /// Every write can ask for it, also in place of an explicit TTL (Cloudflare, Hetzner, nic.ru,
    /// and both NotSettable providers, whose TTL is always the provider's).
    Requestable,
}
impl ProviderDefaultTtl {
    pub const fn exists(self) -> bool;               // not Absent: reads can report it
    pub const fn can_request(self) -> bool;          // not Absent: writes and the setting
    pub const fn can_replace_explicit(self) -> bool; // Requestable
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
impl Operation {
    /// Stable snake_case identifier: "check", "list_zones", ...
    pub const fn as_str(self) -> &'static str;
}
impl std::fmt::Display for Operation {}  // as_str()
```

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
    /// `ttl` is used only if the rrset has to be created: a number, the provider's default, or
    /// `None` for the client's `ttl` setting. An existing rrset keeps its TTL.
    fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<RrsetTtl>,
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

`id` and `check` are the only methods without a default body. Every other method has a default that
returns `Error::Unsupported` for its operation, so a client implements exactly what its capabilities
announce. The trait is declared with `-> impl Future<Output = …> + Send` so the futures are `Send`
by contract; implementations write `async fn`. There is no `async-trait` and no `dyn Provider`. The
checks every operation makes before any request, and their order, are in section 3.1.

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
    /// The rrset must have exactly these records and, if the given set states a TTL, that TTL:
    /// `Explicit(n)` holds for an rrset that reads with n, `ProviderDefault` for one that has
    /// the provider's default, and no stated TTL for any TTL. The given set must have the name
    /// and type the operation is about; anything else is `Error::InvalidInput` before any
    /// request.
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
    /// The credentials were exercised against the provider and accepted. False when the provider
    /// offers no request that tests credentials without changing anything (acme-dns), or none
    /// that does so without naming a zone and `zones` was empty.
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
/// Sorts `rrsets` by name, then type.
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
#[derive(Clone)]
pub struct Context { /* private Arc */ }
impl std::fmt::Debug for Context {}  // the options and the locks, nothing else

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
    /// With a proxy, the proxy must be a loopback IP literal too.
    pub loopback_only: bool,
    /// The HTTP proxy of every HTTP provider request. Default None. Section 5.1.
    pub proxy: Option<HttpProxy>,
}
impl Default for ContextOptions {}

#[derive(Clone)]
#[non_exhaustive]
pub struct HttpProxy {
    /// "http://", "https://", "socks5://" or "socks5h://", then host:port (without a port, 80,
    /// 443 or 1080); no user info, path, query or fragment.
    pub url: String,
    /// Proxy authentication: not empty, no ':' and no control characters.
    pub username: Option<String>,
    /// No control characters; requires `username`, and is required with it for SOCKS5.
    pub password: Option<secrecy::SecretString>,
    /// Hosts reached directly, bypassing the proxy. Default empty. Section 5.1.
    pub exclusions: Vec<String>,
}
impl HttpProxy {
    pub fn new(url: String) -> HttpProxy;
    pub fn with_credentials(self, username: String, password: secrecy::SecretString) -> HttpProxy;
    pub fn with_exclusions(self, exclusions: Vec<String>) -> HttpProxy;
}
impl std::fmt::Debug for HttpProxy {}  // the URL (withheld if it contains '@'), whether credentials are set
```

`Context::new` checks the options and fails with `Error::Config` for an empty or longer user agent
suffix or one outside printable ASCII, a zero timeout, and, when an HTTP provider is compiled in, an
extra root certificate that is not a usable DER trust anchor or a proxy setting that section 5.1
refuses. It makes no connection and needs no `tokio` runtime.

The proxy setting is a struct rather than a URL string so that the proxy password lives in a
`SecretString` like every other credential: a URL with embedded user info would carry it as plain
text, and is refused for that reason with a fixed text that does not repeat the URL.

The application creates one `Context` per process and builds every client from it. Per-name
serialization (hard rule 2) holds between clients that share a `Context` and not between clients
built from different ones (section 3.3).

Each provider module has the same three public types (Yandex Cloud adds `AuthorizedKey`, the typed
form of its key file). Shown for one provider with a static token and one with required settings:

```rust
// zonewright::providers::cloudflare — the module exists in every build (its metadata);
// these types are compiled with feature "cloudflare"

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct CloudflareConfig {
    pub base_url: String,   // default "https://api.cloudflare.com/client/v4"
    pub ttl: RrsetTtl,      // default 120; 60 ..= 86400, or "provider_default" (also spelled 1)
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

    /// The context's proxy refused the proxy credentials or demanded credentials that are not
    /// configured. Never retried. Section 5.3.
    #[error("the proxy refused the proxy credentials; check proxy.username and proxy.password")]
    #[non_exhaustive]
    ProxyAuth {},

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
    /// The wait the provider asked for, for RateLimited; None otherwise.
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
    pub fn proxy_auth() -> Error;
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
    ZoneNotFound, ProxyAuth, Auth, Forbidden, RateLimited, PreconditionFailed, Conflict, Transient,
    Rejected, Protocol,
}
impl ErrorKind {
    /// Every kind of this version, each once, in declaration order. An application's test walks
    /// it to notice a kind added later, which its wildcard `match` arm would absorb silently.
    pub const ALL: &'static [ErrorKind];
    /// Stable snake_case identifier: "config", "not_compiled", ..., "protocol".
    pub const fn as_str(self) -> &'static str;
}
impl std::fmt::Display for ErrorKind {}  // as_str()

/// Bounded text taken from a provider's answer or composed by the client.
#[derive(Clone, PartialEq, Eq)]
pub struct Detail(/* private */);
impl Detail {
    /// Replaces control characters, line and paragraph separators and bidirectional formatting
    /// characters by spaces and truncates to at most 512 bytes on a character boundary. It does
    /// not know any secret: whoever calls it is responsible for the text containing none.
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
- Retryability is a property of the kind. `Transient` after a write means the write may or may not
  have happened; every operation is safe to repeat (section 3.2). `PreconditionFailed` is not
  retryable and `Conflict` is: the first is the caller's expectation being wrong, the second a race
  the next attempt resolves by reading again.

The inspector has its own error type (section 8.2); names and records have `NameError` and
`RecordError`. None of them wraps a third-party type.
