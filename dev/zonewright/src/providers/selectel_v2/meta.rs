//! Metadata of the Selectel v2 provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones` and
//! the TXT value operations on plain values. The record-level operations are not written yet, so
//! their flags are false and `record_types` is empty.

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};

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
    list_rrsets: false,
    get_rrset: false,
    set_rrset: false,
    delete_rrset: false,
    add_txt_value: true,
    remove_txt_value: true,
    record_types: TypeSet::Listed(&[]),
    read_only_types: &[],
    // The encoding of values with spaces, quotes, backslashes or non-ASCII bytes is not
    // established for this API (design section 4.4).
    txt_plain_only: true,
    // The rrset is replaced whole by PATCH, which carries no condition (design section 3.5).
    txt_values: ValueGuarantee::ReadThenWrite,
    preconditions: Preconditions::ReadThenWrite,
    atomic_rrset_write: false,
    ttl: TtlSupport::PerRrset {
        min: 60,
        max: 604_800,
    },
    provider_default_ttl: false,
    asynchronous: false,
};
