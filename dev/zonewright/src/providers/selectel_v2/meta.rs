//! Metadata of the Selectel v2 provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types whose content form a source establishes (the client's
//! `records.rs` gives the sources; DNAME, HTTPS and SVCB are left out until theirs is), and the
//! TXT value operations on plain values.

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of Selectel v2.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::SelectelV2,
    name: "Selectel v2",
    verified: false,
    default_propagation_timeout: None,
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "account_id",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Account number",
        help: "The Selectel account number, not the login.",
        advanced: false,
    },
    ConfigField {
        key: "project_id",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: None,
        label: "Project ID",
        help: "The project that holds the zones; give exactly one of project_id and project_name.",
        advanced: false,
    },
    ConfigField {
        key: "project_name",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: None,
        label: "Project name",
        help: "The name of the project that holds the zones; give exactly one of project_id and project_name.",
        advanced: false,
    },
    ConfigField {
        key: "username",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Service user",
        help: "A service user with access to this project only.",
        advanced: false,
    },
    ConfigField {
        key: "password",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Service user password",
        help: "Password of the service user.",
        advanced: false,
    },
    ConfigField {
        key: "user_domain_name",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: None,
        label: "User domain",
        help: "The Keystone domain of the service user; the account number by default.",
        advanced: true,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 60,
            max: 604_800,
            provider_default: false,
        },
        default: Some("60"),
        label: "Record TTL, s",
        help: "TTL of a new rrset, in seconds.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.selectel.ru/domains/v2"),
        label: "DNS API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
    ConfigField {
        key: "auth_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://cloud.api.selcloud.ru/identity/v3"),
        label: "Keystone URL",
        help: "Endpoint of the provider's identity service; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Selectel v2.
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
        RecordType::ALIAS,
        RecordType::CAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::SSHFP,
        RecordType::TXT,
    ]),
    // Created with the zone and not editable (design section 3.4; the provider's documentation,
    // see the client's `records.rs`).
    read_only_types: &[RecordType::SOA],
    // The encoding of values with spaces, quotes, backslashes or non-ASCII bytes is not
    // established for this API (design section 4.4).
    txt_plain_only: true,
    // The rrset is replaced whole by PATCH, which carries no condition (design section 3.5).
    txt_values: ValueGuarantee::ReadThenWrite,
    preconditions: Preconditions::ReadThenWrite,
    // One create or update request carries the whole rrset.
    atomic_rrset_write: true,
    ttl: TtlSupport::PerRrset {
        min: 60,
        max: 604_800,
    },
    provider_default_ttl: ProviderDefaultTtl::Absent,
    asynchronous: false,
};
