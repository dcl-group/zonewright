//! Metadata of the Yandex 360 provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types whose fields the API reference documents (see the
//! client's `records.rs`), and the TXT value operations on plain values.

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of Yandex 360.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Yandex360,
    name: "Yandex 360",
    verified: false,
    default_propagation_timeout: None,
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "org_id",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Organization ID",
        help: "The numeric ID of the Yandex 360 organization.",
        advanced: false,
    },
    ConfigField {
        key: "oauth_token",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "OAuth token",
        help: "An application token with the directory:read_domains and directory:manage_dns scopes.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Integer {
            min: 60,
            max: 86400,
        },
        default: Some("300"),
        label: "Record TTL, s",
        help: "TTL of new records, in seconds.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api360.yandex.net"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Yandex 360.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // The types of the API's type enum whose fields the API reference documents (Create, List,
    // Edit). NS is in the enum, but no page names the field of its value.
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::SRV,
        RecordType::TXT,
    ]),
    read_only_types: &[],
    // The encoding of values with spaces, quotes, backslashes or non-ASCII bytes is not
    // established for this API (design section 4.4).
    txt_plain_only: true,
    // Every value is a record of its own, created and deleted by identifier (design section
    // 3.5).
    txt_values: ValueGuarantee::PerValue,
    preconditions: Preconditions::ReadThenWrite,
    // Individual records with IDs: a replacement is several requests.
    atomic_rrset_write: false,
    // Every record carries its own `ttl` (Create, List). The range is an assumption, see
    // `config.rs`.
    ttl: TtlSupport::PerRecord {
        min: 60,
        max: 86_400,
    },
    provider_default_ttl: false,
    asynchronous: false,
};
