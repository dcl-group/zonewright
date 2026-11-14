//! Metadata of the Cloudflare provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types whose fields the sources establish (see the client's
//! `records.rs`) and the TXT value operations on plain values.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};
use crate::record::RecordType;

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
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // The types whose fields the provider's documentation or dns-update establish for reading
    // and writing (the client's `records.rs`). SSHFP, HTTPS, SVCB and the other types the API
    // knows appear in a listing only. The API has no SOA record.
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::PTR,
        RecordType::SRV,
        RecordType::TLSA,
        RecordType::TXT,
    ]),
    // Every listed type can be written; the apex NS set is refused by the record layer.
    read_only_types: &[],
    // The API documents TXT content as quoted character strings, but how it treats quotes,
    // backslashes and non-ASCII bytes inside them is not established (design section 4.4).
    txt_plain_only: true,
    // Every value is a record of its own; requests name only our records (design section 3.5).
    txt_values: ValueGuarantee::PerValue,
    // The expectation is evaluated on a read; the writes carry no condition.
    preconditions: Preconditions::ReadThenWrite,
    // Individual records with IDs: a replacement is several requests (the batch endpoint is not
    // used, see the client's `records.rs`).
    atomic_rrset_write: false,
    ttl: TtlSupport::PerRecord {
        min: 60,
        max: 86_400,
    },
    // A TTL of 1 means "automatic" (design section 3.6); such a record reads as no TTL, and a
    // set can be created with it through the `ttl` setting only. The TTL of a proxied record is
    // always automatic and cannot be requested.
    provider_default_ttl: true,
    asynchronous: false,
};
