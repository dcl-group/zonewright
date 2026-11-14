//! Metadata of the Cloudflare provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones` and
//! the TXT value operations on plain values. The record-level operations are not written yet, so
//! their flags are false and `record_types` is empty.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};

/// The metadata of Cloudflare.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Cloudflare,
    name: "Cloudflare",
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
        label: "API token",
        help: "An API token (not the Global API Key) with Zone:DNS:Edit and Zone:Zone:Read on the zones to manage.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Integer { min: 1, max: 86400 },
        default: Some("120"),
        label: "Record TTL, s",
        help: "TTL of new records, in seconds: 1 means automatic, any other value is at least 60.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.cloudflare.com/client/v4"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Cloudflare.
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
    // The API documents TXT content as quoted character strings, but how it treats quotes,
    // backslashes and non-ASCII bytes inside them is not established (design section 4.4).
    txt_plain_only: true,
    // Every value is a record of its own; requests name only our records (design section 3.5).
    txt_values: ValueGuarantee::PerValue,
    preconditions: Preconditions::ReadThenWrite,
    atomic_rrset_write: false,
    ttl: TtlSupport::PerRecord {
        min: 60,
        max: 86_400,
    },
    // A TTL of 1 means "automatic" (design section 3.6).
    provider_default_ttl: true,
    asynchronous: false,
};
