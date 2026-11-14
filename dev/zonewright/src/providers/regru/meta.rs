//! Metadata of the reg.ru provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check` and the TXT value
//! operations on plain values. The API has no zone listing, and the record-level operations are
//! not written yet, so their flags are false and `record_types` is empty.

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};

/// The metadata of reg.ru.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Regru,
    name: "reg.ru",
    verified: false,
    default_propagation_timeout: None,
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
        label: "Login",
        help: "Login of the reg.ru account.",
        advanced: false,
    },
    ConfigField {
        key: "password",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "API password",
        help: "The alternative API password set in the account, not the sign-in password.",
        advanced: false,
    },
    ConfigField {
        key: "tls_cert_pem",
        secret: true,
        required: false,
        kind: FieldKind::Multiline,
        default: None,
        label: "Client certificate (PEM)",
        help: "The API client certificate, when certificate access is enabled in the account; given together with its key.",
        advanced: true,
    },
    ConfigField {
        key: "tls_key_pem",
        secret: true,
        required: false,
        kind: FieldKind::Multiline,
        default: None,
        label: "Client certificate key (PEM)",
        help: "The private key of the client certificate (PEM: PKCS#8, PKCS#1 or SEC1); given together with the certificate.",
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
        default: Some("https://api.reg.ru/api/regru2"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for reg.ru.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: false,
    list_rrsets: false,
    get_rrset: false,
    set_rrset: false,
    delete_rrset: false,
    add_txt_value: true,
    remove_txt_value: true,
    record_types: TypeSet::Listed(&[]),
    read_only_types: &[],
    // The documentation allows only alphanumeric ASCII characters in the text of a TXT record
    // (9.9); the encoding of anything else is not established (design section 4.4).
    txt_plain_only: true,
    // Every value is a record of its own, identified by its content and removed by it (design
    // section 3.5).
    txt_values: ValueGuarantee::PerValue,
    preconditions: Preconditions::ReadThenWrite,
    atomic_rrset_write: false,
    // `zone/add_txt` has no TTL parameter (documentation 9.9).
    ttl: TtlSupport::NotSettable,
    provider_default_ttl: true,
    asynchronous: false,
};
