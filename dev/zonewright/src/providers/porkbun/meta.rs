//! Metadata of the Porkbun provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. The client carries the references to the provider's documentation
//! (hard rule 3); `config.rs` gives the sources of the defaults and ranges, `records.rs` those of
//! the record types.
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types whose content form a source establishes, and the TXT
//! value operations on plain values.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of Porkbun.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Porkbun,
    name: "Porkbun",
    verified: false,
    // Source: lego providers/dns/porkbun/porkbun.go line 50 (`PropagationTimeout`, default 10
    // minutes), at commit `436c8b7`.
    default_propagation_timeout: Some(Duration::from_secs(600)),
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "api_key",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "API key",
        help: "The API key (pk1_...), created at porkbun.com/account/api. Each domain must also be opted in to API access.",
        advanced: false,
    },
    ConfigField {
        key: "secret_api_key",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Secret API key",
        help: "The secret API key (sk1_...) shown once when the key was created. A restricted key needs the read and dns permissions.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 600,
            max: 2_147_483_647,
            provider_default: false,
        },
        default: Some("600"),
        label: "Record TTL, s",
        help: "TTL of new records, in seconds; at least 600.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.porkbun.com/api/json/v3"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Porkbun.
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
        RecordType::SRV,
        RecordType::TLSA,
        RecordType::TXT,
    ]),
    // The API lists no SOA record ("SOA records and Porkbun default NS records are excluded",
    // `/dns/retrieve`), so SOA is not among the types at all.
    read_only_types: &[],
    // How the API treats TXT values with spaces, quotes, backslashes or more than 255 octets is
    // not documented (design section 4.4).
    txt_plain_only: true,
    // Every value is a record of its own, created and deleted by identifier (design section
    // 3.5).
    txt_values: ValueGuarantee::PerValue,
    preconditions: Preconditions::ReadThenWrite,
    // Individual records with identifiers: a replacement is several requests (creates, then
    // deletes), and no request carries a condition on the rrset as read.
    atomic_rrset_write: false,
    // The minimum is documented; no maximum is, so RFC 2181's stands (`config.rs`).
    ttl: TtlSupport::PerRecord {
        min: 600,
        max: 2_147_483_647,
    },
    // Every record carries a TTL: one created without `ttl` gets the account's minimum, which
    // a read shows as a number.
    provider_default_ttl: ProviderDefaultTtl::Absent,
    asynchronous: false,
};
