//! Metadata of the OVHcloud provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. The client carries the references to the provider's documentation
//! (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types whose content form a source establishes (the client's
//! `records.rs` gives the sources), and the TXT value operations on plain values. Every write
//! ends with a refresh of the zone, which publishes the staged record changes (see the client's
//! documentation).

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of OVHcloud.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Ovh,
    name: "OVHcloud",
    verified: false,
    // lego providers/dns/ovh/ovh.go: `OVH_PROPAGATION_TIMEOUT` defaults to
    // `dns01.DefaultPropagationTimeout`, 60 seconds (challenge/dns01/dns_challenge.go).
    default_propagation_timeout: Some(Duration::from_secs(60)),
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "application_key",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Application key",
        help: "The application key (AK) of the API application; it is sent with every request.",
        advanced: false,
    },
    ConfigField {
        key: "application_secret",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Application secret",
        help: "The application secret (AS) of the API application; it signs every request.",
        advanced: false,
    },
    ConfigField {
        key: "consumer_key",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Consumer key",
        help: "The consumer key (CK) validated for the account, with GET, POST, PUT and DELETE on /domain/zone/*; create it with unlimited validity for unattended use, since an expired or revoked key is refused with 403 (Forbidden).",
        advanced: false,
    },
    ConfigField {
        key: "endpoint",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: Some("ovh-eu"),
        label: "API endpoint",
        help: "The API region of the account: ovh-eu, ovh-ca or ovh-us.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 60,
            max: 86_400,
            provider_default: false,
        },
        default: Some("120"),
        label: "Record TTL, s",
        help: "TTL of new records, in seconds; 60 to 86400.",
        advanced: true,
    },
    ConfigField {
        key: "read_retry_ms",
        secret: false,
        required: false,
        kind: FieldKind::Integer { min: 1, max: 60000 },
        default: Some("1000"),
        label: "Read retry pause, ms",
        help: "First pause before a listed record that is not readable yet is read again; it doubles for each of three repeats.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: None,
        label: "API URL",
        help: "An API URL used instead of the endpoint; set it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for OVHcloud.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::SRV,
        RecordType::TLSA,
        RecordType::TXT,
    ]),
    // The SOA has its own endpoint and is not a record of the record API.
    read_only_types: &[],
    // How the API treats values with spaces, quotes or backslashes is not established: it
    // quotes and splits TXT values itself (design section 4.4).
    txt_plain_only: true,
    // Every value is a record of its own, created and deleted by identifier (design section
    // 3.5).
    txt_values: ValueGuarantee::PerValue,
    preconditions: Preconditions::ReadThenWrite,
    // Individual records with IDs: a replacement is several requests (creates, then deletes),
    // and no request carries a condition on the rrset. They are published together by the
    // operation's refresh unless another refresh of the zone (by another operation, process or
    // the control panel) runs while they are being sent.
    atomic_rrset_write: false,
    // The range is partly an assumption, marked and explained in `config.rs`.
    ttl: TtlSupport::PerRecord {
        min: 60,
        max: 86_400,
    },
    // The client writes an explicit TTL on every record; a record read with a TTL of 0 or none
    // is reported without a TTL (see the client's `records.rs`).
    provider_default_ttl: ProviderDefaultTtl::Absent,
    asynchronous: false,
};
