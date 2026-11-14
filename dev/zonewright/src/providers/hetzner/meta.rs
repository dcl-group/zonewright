//! Metadata of the Hetzner provider: configuration fields, capabilities and defaults.
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

/// The metadata of Hetzner.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Hetzner,
    name: "Hetzner",
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
        label: "Project API token",
        help: "A Read & Write API token of the Hetzner Console project that holds the zones; only zones in primary mode are usable.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Integer {
            min: 60,
            max: 2_147_483_647,
        },
        default: Some("60"),
        label: "Record TTL, s",
        help: "TTL of a new rrset, in seconds; at least 60. An existing rrset keeps its TTL.",
        advanced: true,
    },
    ConfigField {
        key: "action_poll_ms",
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
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.hetzner.cloud/v1"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Hetzner.
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
    // The reference says only that a TXT value "has to be quoted"; how the API treats spaces,
    // quotes, backslashes and non-ASCII bytes inside the quotes is not established (design
    // section 4.4).
    txt_plain_only: true,
    // The API adds and removes values of an rrset by value (design section 3.5).
    txt_values: ValueGuarantee::PerValue,
    preconditions: Preconditions::ReadThenWrite,
    // Values are added and removed by value actions, so a replacement is several requests; a
    // whole-set call is not established for this client (design section 11.2).
    atomic_rrset_write: false,
    // Source: the reference, Zone RRSets, `ttl`: 60 to 2147483647 seconds, one per rrset.
    ttl: TtlSupport::PerRrset {
        min: 60,
        max: 2_147_483_647,
    },
    provider_default_ttl: false,
    asynchronous: true,
};
