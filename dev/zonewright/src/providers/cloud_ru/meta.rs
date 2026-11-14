//! Metadata of the Cloud.ru provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types whose value form the provider documents (see the
//! client's `content.rs`), and the TXT value operations on plain values.

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of Cloud.ru.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::CloudRu,
    name: "Cloud.ru",
    verified: false,
    default_propagation_timeout: None,
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "project_id",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Project ID",
        help: "The Evolution project that holds the public DNS zones.",
        advanced: false,
    },
    ConfigField {
        key: "key_id",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Access key ID",
        help: "ID of a service account access key with a DNS role in this project.",
        advanced: false,
    },
    ConfigField {
        key: "secret",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Access key secret",
        help: "The secret of the access key, shown once when the key is created.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 60,
            max: 86400,
            provider_default: false,
        },
        default: Some("60"),
        label: "Record TTL, s",
        help: "TTL of a new rrset, in seconds.",
        advanced: true,
    },
    ConfigField {
        key: "operation_poll_ms",
        secret: false,
        required: false,
        kind: FieldKind::Integer {
            min: 250,
            max: 60000,
        },
        default: Some("1000"),
        label: "Polling interval, ms",
        help: "Interval between two polls of a provider-side operation, in milliseconds; at least 250.",
        advanced: true,
    },
    ConfigField {
        key: "dns_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://dns.api.cloud.ru"),
        label: "DNS API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
    ConfigField {
        key: "iam_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://iam.api.cloud.ru/api/v1/auth/token"),
        label: "Token URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Cloud.ru.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // The types of the API (`v1CreatePublicRecordSoleRequest.type`) whose value form the
    // provider's record types page documents; SPF is type code 99 (see the client's
    // `content.rs`). SOA is not among the API's types and is not offered.
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::from_code(99),
        RecordType::SRV,
        RecordType::TXT,
    ]),
    read_only_types: &[],
    // The encoding of values with spaces, quotes, backslashes or non-ASCII bytes is not
    // established for this API (design section 4.4).
    txt_plain_only: true,
    // The record is replaced whole by PATCH, which carries no condition; the client re-reads it
    // immediately before every write, at the TXT value level and at record level (design
    // section 3.5).
    txt_values: ValueGuarantee::ReadThenWrite,
    preconditions: Preconditions::ReadThenWrite,
    // One create or update request carries the whole record.
    atomic_rrset_write: true,
    ttl: TtlSupport::PerRrset {
        min: 60,
        max: 86_400,
    },
    provider_default_ttl: ProviderDefaultTtl::Absent,
    asynchronous: true,
};
