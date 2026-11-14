//! Metadata of the Timeweb Cloud provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! TXT value operations and the record-level operations for the types whose write fields and
//! listing fields the API description establishes (see `records.rs`).

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of Timeweb Cloud.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::TimewebCloud,
    name: "Timeweb Cloud",
    verified: false,
    default_propagation_timeout: None,
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "token",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "API token",
        help: "An API token from the API and Terraform section of the Timeweb Cloud panel.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 60,
            max: 86400,
            provider_default: true,
        },
        default: Some("provider_default"),
        label: "Record TTL, s",
        help: "TTL of new records, in seconds, or provider_default (also null) to leave the choice to the provider.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.timeweb.cloud/api"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Timeweb Cloud.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // The types whose create object (`create-dns-v2`) and listing fields (`dns-record`) the API
    // description gives. SRV is left out: the listing documents no fields for its priority,
    // weight, port and target, and the create has no weight. The API documents no other type.
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::TXT,
    ]),
    read_only_types: &[],
    // The encoding of values with spaces, quotes, backslashes or non-ASCII bytes is not
    // established for this API (design section 4.4).
    txt_plain_only: true,
    // Every value is a record of its own, created and deleted by identifier (design section
    // 3.5).
    txt_values: ValueGuarantee::PerValue,
    // No request carries a condition on the rrset as read.
    preconditions: Preconditions::ReadThenWrite,
    // Individual records with IDs: a replacement is several requests (creates, then deletes).
    atomic_rrset_write: false,
    // Every record has its own `ttl` (a number of seconds); no range is documented, so the
    // range is the settings form's (an assumption, see the client).
    ttl: TtlSupport::PerRecord {
        min: 60,
        max: 86_400,
    },
    // A record created without `ttl` (optional in the create schema) has the provider's choice
    // and lists without one: it reads as the provider's default. Whether a `PATCH` without
    // `ttl` turns an explicit TTL into that choice is not documented, so the default can be
    // requested only for new records.
    provider_default_ttl: ProviderDefaultTtl::ForNewRecords,
    asynchronous: false,
};
