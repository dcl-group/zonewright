//! Metadata of the Cloud.ru provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones` and
//! the TXT value operations on plain values. The record-level operations are not written yet, so
//! their flags are false and `record_types` is empty.

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};

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
        kind: FieldKind::Integer {
            min: 60,
            max: 86400,
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
    list_rrsets: false,
    get_rrset: false,
    set_rrset: false,
    delete_rrset: false,
    add_txt_value: true,
    remove_txt_value: true,
    record_types: TypeSet::Listed(&[]),
    read_only_types: &[],
    // The encoding of values with spaces, quotes, backslashes or non-ASCII bytes is not
    // established for this API (design section 4.4).
    txt_plain_only: true,
    // The record is replaced whole by PATCH, which carries no condition; the client re-reads it
    // immediately before the write (design section 3.5).
    txt_values: ValueGuarantee::ReadThenWrite,
    preconditions: Preconditions::ReadThenWrite,
    atomic_rrset_write: true,
    ttl: TtlSupport::PerRrset {
        min: 60,
        max: 86_400,
    },
    provider_default_ttl: false,
    asynchronous: true,
};
