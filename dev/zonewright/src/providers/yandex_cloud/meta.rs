//! Metadata of the Yandex Cloud provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types whose data form a source establishes (the client's
//! `records.rs` gives the sources), and the TXT value operations on plain values.

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of Yandex Cloud.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::YandexCloud,
    name: "Yandex Cloud",
    verified: false,
    default_propagation_timeout: None,
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "folder_id",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: None,
        label: "Folder ID",
        help: "The folder whose public zones are used; at least one of folder_id and zone_ids is required.",
        advanced: false,
    },
    ConfigField {
        key: "zone_ids",
        secret: false,
        required: false,
        kind: FieldKind::Multiline,
        default: None,
        label: "Zone IDs (JSON)",
        help: "A JSON object mapping zone names to zone IDs, for accounts whose role is granted on zones; at least one of folder_id and zone_ids is required.",
        advanced: true,
    },
    ConfigField {
        key: "authorized_key",
        secret: true,
        required: true,
        kind: FieldKind::Multiline,
        default: None,
        label: "Service account authorized key (JSON)",
        help: "The authorized key of a service account with the dns.editor role on the zones to manage.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Integer {
            min: 60,
            max: 604800,
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
        default: Some("https://dns.api.cloud.yandex.net/dns/v1"),
        label: "DNS API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
    ConfigField {
        key: "iam_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://iam.api.cloud.yandex.net/iam/v1/tokens"),
        label: "IAM token URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
    ConfigField {
        key: "operation_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://operation.api.cloud.yandex.net/operations"),
        label: "Operation API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Yandex Cloud.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // The types of the Cloud DNS record types page (design section 11.2). TLSA is not accepted
    // by the API.
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::ANAME,
        RecordType::CAA,
        RecordType::CNAME,
        RecordType::HTTPS,
        RecordType::MX,
        RecordType::NS,
        RecordType::PTR,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::SVCB,
        RecordType::TXT,
    ]),
    // Created with the zone (design section 3.4; the client's `records.rs`).
    read_only_types: &[RecordType::SOA],
    // The encoding of values with spaces, quotes, backslashes or non-ASCII bytes is not
    // established for this API (design section 4.4).
    txt_plain_only: true,
    // Every write carries the old set in the strict call's deletions (design sections 3.4 and
    // 3.5).
    txt_values: ValueGuarantee::Conditional,
    preconditions: Preconditions::Atomic,
    // One `updateRecordSets` call replaces the record set (design section 11.1).
    atomic_rrset_write: true,
    // What the API accepts for a TTL a caller requests: 0 to 2147483647
    // (https://yandex.cloud/en/docs/dns/api-ref/DnsZone/updateRecordSets, `ttl`). The narrower
    // range of the `ttl` setting (config.rs) concerns the configured default only.
    ttl: TtlSupport::PerRrset {
        min: 0,
        max: 2_147_483_647,
    },
    provider_default_ttl: false,
    asynchronous: true,
};
