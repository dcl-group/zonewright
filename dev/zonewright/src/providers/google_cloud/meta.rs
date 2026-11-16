//! Metadata of the Google Cloud DNS provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. The client carries the references to the provider's documentation
//! (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types whose data form a source establishes (the client's
//! `records.rs` gives the sources), and the TXT value operations on plain values. Every write is
//! one change whose deletions must match the rrset at the provider exactly, so the provider
//! refuses a write when the rrset changed after the read.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of Google Cloud DNS.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::GoogleCloud,
    name: "Google Cloud DNS",
    verified: false,
    // Source: lego providers/dns/gcloud/googlecloud.go:76 (`PropagationTimeout:
    // env.GetOrDefaultSecond(EnvPropagationTimeout, 180*time.Second)`).
    default_propagation_timeout: Some(Duration::from_secs(180)),
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
        help: "The project whose public managed zones are used.",
        advanced: false,
    },
    ConfigField {
        key: "managed_zones",
        secret: false,
        required: false,
        kind: FieldKind::Multiline,
        default: None,
        label: "Managed zones (JSON)",
        help: "A JSON object mapping zone names to managed zone names or IDs, for a service account whose role is granted on managed zones or for a name held by several managed zones.",
        advanced: true,
    },
    ConfigField {
        key: "service_account_key",
        secret: true,
        required: true,
        kind: FieldKind::Multiline,
        default: None,
        label: "Service account key (JSON)",
        help: "The JSON key file of a service account with the DNS Administrator role (roles/dns.admin) on the project or the managed zones.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 1,
            max: 2_147_483_647,
            provider_default: false,
        },
        default: Some("120"),
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
        default: Some("1000"),
        label: "Polling interval, ms",
        help: "Interval between two looks at a pending change, in milliseconds; at least 250.",
        advanced: true,
    },
    ConfigField {
        key: "dns_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://dns.googleapis.com/dns/v1"),
        label: "Cloud DNS API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
    ConfigField {
        key: "token_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://oauth2.googleapis.com/token"),
        label: "Token URL",
        help: "OAuth 2.0 token endpoint, also the audience of the signed JWT; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Google Cloud DNS.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // The types of the supported record types page whose data form a source shows (design
    // section 11.2; the client's `records.rs`).
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::TLSA,
        RecordType::TXT,
    ]),
    // Created with the zone and not deletable through the API (the client's `records.rs`).
    read_only_types: &[RecordType::SOA],
    // Values that need an escape are not sent (design section 4.4; the client's `records.rs`).
    txt_plain_only: true,
    // Every write carries the old rrset in the change's deletions, which must match the stored
    // rrset exactly (design sections 3.4 and 3.5).
    txt_values: ValueGuarantee::Conditional,
    preconditions: Preconditions::Atomic,
    // One `changes.create` replaces the rrset atomically (design section 11.1).
    atomic_rrset_write: true,
    // The API's `ttl` is an int32 of seconds; the console asks for a positive integer
    // (config.rs).
    ttl: TtlSupport::PerRrset {
        min: 1,
        max: 2_147_483_647,
    },
    provider_default_ttl: ProviderDefaultTtl::Absent,
    asynchronous: true,
};
