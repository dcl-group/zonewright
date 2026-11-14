//! Metadata of the Hetzner provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! TXT value operations on plain values, and the record-level operations for the types whose
//! value form the provider's documentation gives (the client's `records.rs` cites each).

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

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
        kind: FieldKind::Ttl {
            min: 60,
            max: 2_147_483_647,
            provider_default: true,
        },
        default: Some("60"),
        label: "Record TTL, s",
        help: "TTL of a new rrset, in seconds (at least 60), or provider_default for the zone's default TTL; an existing rrset keeps its TTL.",
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
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // The types whose value form a source gives (the client's `records.rs`). CAA, DS, HINFO,
    // HTTPS, RP and SVCB are in the API's enumeration, but their value form is not documented;
    // they are listed, not read alone or written.
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::PTR,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::TLSA,
        RecordType::TXT,
    ]),
    // Created and kept by the provider with the zone (design section 3.4; the client's
    // `records.rs`).
    read_only_types: &[RecordType::SOA],
    // The reference says only that a TXT value "has to be quoted"; how the API treats spaces,
    // quotes, backslashes and non-ASCII bytes inside the quotes is not established (design
    // section 4.4).
    txt_plain_only: true,
    // The API adds and removes values of an rrset by value (design section 3.5).
    txt_values: ValueGuarantee::PerValue,
    // No write carries a condition on the rrset as read (the reference has none).
    preconditions: Preconditions::ReadThenWrite,
    // Not in every case: the records of an rrset are replaced by one request (`set_records`
    // for an existing rrset, `POST /zones/{id}/rrsets` for a new one), but a replacement that
    // also changes the TTL of an existing rrset is two, `set_records` and then the separate
    // `change_ttl` action, and the first can be applied while the second fails.
    atomic_rrset_write: false,
    // Source: the reference, Zone RRSets, `ttl`: 60 to 2147483647 seconds, one per rrset.
    ttl: TtlSupport::PerRrset {
        min: 60,
        max: 2_147_483_647,
    },
    // An rrset whose `ttl` is `null` uses the zone's default TTL ("If not set, the Zone's
    // Default TTL is used") and reads as the provider's default. A create, an `add_records` and
    // a `change_ttl` without a TTL (`change_ttl` with `ttl: null`, which its schema allows)
    // request it, also in place of an explicit TTL (see the client's `records.rs`).
    provider_default_ttl: ProviderDefaultTtl::Requestable,
    asynchronous: true,
};
