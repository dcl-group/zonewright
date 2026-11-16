//! Metadata of the Gcore provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. The client and the shared code of `providers::gcore_shared` carry the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types whose content form a source establishes (the shared
//! `content.rs` gives the sources; PTR, HTTPS, SVCB and DS are in the API's type list without
//! one), and the TXT value operations on plain values.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of Gcore.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Gcore,
    name: "Gcore",
    verified: false,
    // Source: lego providers/dns/internal/gcore/provider.go:19 (`DefaultPropagationTimeout =
    // 360 * time.Second`), which lego's Gcore provider uses (providers/dns/gcore/gcore.go).
    default_propagation_timeout: Some(Duration::from_secs(360)),
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "api_token",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Permanent API token",
        help: "A permanent API token of the Gcore account with a Managed DNS role that may change records.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 1,
            max: 2_147_483_647,
            provider_default: false,
        },
        default: Some("300"),
        label: "Record TTL, s",
        help: "TTL of a new rrset, in seconds; the account's plan may set a higher minimum.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.gcore.com/dns"),
        label: "DNS API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Gcore.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::TXT,
    ]),
    // The provider's own (see the shared `records.rs`); its content form is not documented
    // either, which is harmless for a type that is only read.
    read_only_types: &[RecordType::SOA],
    // Only plain values (`Txt::is_plain`) in the TXT value operations: an ACME value is one, and
    // no source says how the API treats a quote, a backslash or a non-ASCII byte inside the
    // string. A space inside is carried as is at the record level (the shared `content.rs`
    // gives its source); the value operations do not need one (design section 4.4).
    txt_plain_only: true,
    // The rrset is replaced whole by PUT, which carries no condition (design section 3.5).
    txt_values: ValueGuarantee::ReadThenWrite,
    preconditions: Preconditions::ReadThenWrite,
    // One POST or PUT carries the whole rrset with its TTL.
    atomic_rrset_write: true,
    // One TTL per rrset (`InputRRSet.ttl`, `uint32`). No range is documented: the client takes
    // RFC 2181's and leaves a plan's minimum (`min_ttl` of the client's limits in the Gcore spec)
    // to the API.
    ttl: TtlSupport::PerRrset {
        min: 1,
        max: 2_147_483_647,
    },
    // An rrset written without `ttl` gets 300 (`InputRRSet.ttl`, `default: 300`, the Gcore spec),
    // which a read shows as a number: there is no TTL of the provider's own to read or ask for.
    provider_default_ttl: ProviderDefaultTtl::Absent,
    asynchronous: false,
};
