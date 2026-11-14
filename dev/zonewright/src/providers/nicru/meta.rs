//! Metadata of the nic.ru provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! TXT value operations for plain values, and the record-level operations for the types whose
//! record element the provider's documentation shows and the record model can hold.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of nic.ru.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Nicru,
    name: "nic.ru",
    verified: false,
    default_propagation_timeout: Some(Duration::from_secs(1200)),
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "username",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Contract number",
        help: "The contract identifier used as the user name, for example 123/NIC-REG.",
        advanced: false,
    },
    ConfigField {
        key: "password",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Password",
        help: "Password of the technical API account.",
        advanced: false,
    },
    ConfigField {
        key: "client_id",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Application ID",
        help: "ID of the OAuth application registered in the account.",
        advanced: false,
    },
    ConfigField {
        key: "client_secret",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Application secret",
        help: "Secret of the OAuth application.",
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
        help: "TTL of new records, in seconds.",
        advanced: true,
    },
    ConfigField {
        key: "scope",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: Some(".+:/dns-master/.+"),
        label: "OAuth scope",
        help: "The OAuth scope requested for the token; it can be narrowed to the zones to manage.",
        advanced: true,
    },
    ConfigField {
        key: "min_request_interval_ms",
        secret: false,
        required: false,
        kind: FieldKind::Integer { min: 0, max: 60000 },
        default: Some("500"),
        label: "Minimum request interval, ms",
        help: "Minimum time between two requests to the provider, in milliseconds.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.nic.ru/dns-master"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
    ConfigField {
        key: "token_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.nic.ru/oauth/token"),
        label: "OAuth token URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// The types of the record-level operations: those whose record element the provider's
/// documentation shows (section 4.6) and that have a canonical text form (design section 4.3).
/// HINFO, NAPTR and RP are shown too but have no canonical form; listings carry them as
/// non-canonical data.
const RECORD_TYPES: &[RecordType] = &[
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::DNAME,
    RecordType::MX,
    RecordType::NS,
    RecordType::PTR,
    RecordType::SOA,
    RecordType::SRV,
    RecordType::TXT,
];

/// What this version of the crate implements for nic.ru.
///
/// `atomic_rrset_write` is false: a replacement is several requests (staged edits and a
/// commit). The publication is one step all the same: no edit is published before the one
/// commit that publishes all of them, and an operation that fails before its commit has its
/// edits rolled back. `preconditions` is `ReadThenWrite`: neither the edits nor the commit carry
/// a condition on the rrset as read.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    record_types: TypeSet::Listed(RECORD_TYPES),
    read_only_types: &[RecordType::SOA],
    txt_plain_only: true,
    txt_values: ValueGuarantee::PerValue,
    preconditions: Preconditions::ReadThenWrite,
    atomic_rrset_write: false,
    ttl: TtlSupport::PerRecord {
        min: 30,
        max: 86_400,
    },
    provider_default_ttl: false,
    asynchronous: false,
};
