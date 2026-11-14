//! Metadata of the Beget provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements. Until the client is ported,
//! every operation flag is false, `record_types` is empty and `txt_values` is `NotOffered`; the
//! provider's developer switches them on together with the client code that implements them.

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};

/// The metadata of Beget.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Beget,
    name: "Beget",
    verified: false,
    default_propagation_timeout: None,
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "login",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Login",
        help: "Login of the Beget hosting account.",
        advanced: false,
    },
    ConfigField {
        key: "password",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "API password",
        help: "The password from the API section of the Beget control panel, not the sign-in password.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Integer {
            min: 60,
            max: 86400,
        },
        default: Some("300"),
        label: "Record TTL, s",
        help: "TTL of a new TXT rrset, in seconds.",
        advanced: true,
    },
    ConfigField {
        key: "min_request_interval_ms",
        secret: false,
        required: false,
        kind: FieldKind::Integer { min: 0, max: 60000 },
        default: Some("1000"),
        label: "Minimum request interval, ms",
        help: "Minimum time between two requests to the provider, in milliseconds.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.beget.com/api"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Beget.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: false,
    list_rrsets: false,
    get_rrset: false,
    set_rrset: false,
    delete_rrset: false,
    add_txt_value: false,
    remove_txt_value: false,
    record_types: TypeSet::Listed(&[]),
    read_only_types: &[],
    txt_plain_only: true,
    txt_values: ValueGuarantee::NotOffered,
    preconditions: Preconditions::ReadThenWrite,
    atomic_rrset_write: false,
    ttl: TtlSupport::PerRrset {
        min: 60,
        max: 86_400,
    },
    provider_default_ttl: false,
    asynchronous: false,
};
