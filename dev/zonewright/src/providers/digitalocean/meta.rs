//! Metadata of the DigitalOcean provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones` and
//! the TXT value operations on plain values. The record-level operations are not written yet,
//! so their flags are false and `record_types` is empty.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};

/// The metadata of DigitalOcean.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::DigitalOcean,
    name: "DigitalOcean",
    verified: false,
    default_propagation_timeout: Some(Duration::from_secs(120)),
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
        label: "Personal access token",
        help: "A custom-scoped token with domain read, create and delete, and account read.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Integer {
            min: 30,
            max: 86400,
        },
        default: Some("30"),
        label: "Record TTL, s",
        help: "TTL of new records, in seconds; at least 30.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.digitalocean.com/v2"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for DigitalOcean.
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
    // Every value is a record of its own, created and deleted by identifier (design section
    // 3.5).
    txt_values: ValueGuarantee::PerValue,
    preconditions: Preconditions::ReadThenWrite,
    // Individual records with IDs: a replacement is several requests.
    atomic_rrset_write: false,
    ttl: TtlSupport::PerRecord {
        min: 30,
        max: 86_400,
    },
    provider_default_ttl: false,
    asynchronous: false,
};
