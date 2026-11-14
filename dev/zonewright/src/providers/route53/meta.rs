//! Metadata of the Route 53 provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations on the types the provider's documentation gives a value format for
//! (`content.rs`), and the TXT value operations on plain values.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of Route 53.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Route53,
    name: "Route 53",
    verified: false,
    default_propagation_timeout: Some(Duration::from_secs(120)),
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "access_key_id",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Access key ID",
        help: "ID of an IAM access key limited to the Route 53 actions the client uses.",
        advanced: false,
    },
    ConfigField {
        key: "secret_access_key",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Secret access key",
        help: "The secret of the access key.",
        advanced: false,
    },
    ConfigField {
        key: "session_token",
        secret: true,
        required: false,
        kind: FieldKind::Text,
        default: None,
        label: "Session token",
        help: "Only for temporary security credentials; it expires with them.",
        advanced: true,
    },
    ConfigField {
        key: "hosted_zone_id",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: None,
        label: "Hosted zone ID",
        help: "Selects one hosted zone when several public zones share a name.",
        advanced: true,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 1,
            max: 86400,
            provider_default: false,
        },
        default: Some("60"),
        label: "Record TTL, s",
        help: "TTL of a new rrset, in seconds.",
        advanced: true,
    },
    ConfigField {
        key: "change_poll_ms",
        secret: false,
        required: false,
        kind: FieldKind::Integer {
            min: 250,
            max: 60000,
        },
        default: Some("2000"),
        label: "Polling interval, ms",
        help: "Interval between two polls of a provider-side operation, in milliseconds; at least 250.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://route53.amazonaws.com"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// The record types of the record-level operations: every type for which the Developer Guide,
/// "Supported DNS record types", gives the `Value` format, and which `ChangeResourceRecordSets`
/// accepts (`ResourceRecordSet.Type`, "Valid values for basic resource record sets").
const RECORD_TYPES: &[RecordType] = &[
    RecordType::A,
    RecordType::AAAA,
    RecordType::CAA,
    RecordType::CNAME,
    // DS
    RecordType::from_code(43),
    RecordType::HTTPS,
    RecordType::MX,
    // NAPTR
    RecordType::from_code(35),
    RecordType::NS,
    RecordType::PTR,
    RecordType::SOA,
    // SPF
    RecordType::from_code(99),
    RecordType::SRV,
    RecordType::SSHFP,
    RecordType::SVCB,
    RecordType::TLSA,
    RecordType::TXT,
];

/// What this version of the crate implements for Route 53.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    record_types: TypeSet::Listed(RECORD_TYPES),
    // Route 53 creates the SOA record with the hosted zone; the crate never writes SOA (design
    // section 3.4).
    read_only_types: &[RecordType::SOA],
    // Values outside printable ASCII are written by the API as octal escapes, unlike zone-file
    // text; until that is mapped, only plain values are accepted (design section 4.4).
    txt_plain_only: true,
    // Every write repeats the old set as a DELETE in the same atomic change batch (design
    // sections 3.4 and 3.5).
    txt_values: ValueGuarantee::Conditional,
    preconditions: Preconditions::Atomic,
    atomic_rrset_write: true,
    // What the API accepts for a TTL a caller requests: 0 to 2147483647 (API reference,
    // `ResourceRecordSet.TTL`).
    // The narrower range of the `ttl` setting (config.rs) concerns the configured default only.
    ttl: TtlSupport::PerRrset {
        min: 0,
        max: 2_147_483_647,
    },
    provider_default_ttl: ProviderDefaultTtl::Absent,
    asynchronous: true,
};
