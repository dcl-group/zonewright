//! Metadata of the reg.ru provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, the TXT value
//! operations on plain values, and the record-level operations for A, AAAA and TXT. The API has no
//! zone listing.

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

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
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // The types whose add function, listing form and removal the documentation gives (9.2, 9.3,
    // 9.9, 9.11, 9.18). CAA, CNAME, HTTPS, MX, NS and SRV have add functions, but the listing's
    // content form for them is not documented (see `records.rs`).
    record_types: TypeSet::Listed(&[RecordType::A, RecordType::AAAA, RecordType::TXT]),
    read_only_types: &[],
    // The documentation allows only alphanumeric ASCII characters in the text of a TXT record
    // (9.9); the encoding of anything else is not established (design section 4.4).
    txt_plain_only: true,
    // Every value is a record of its own, identified by its content and removed by it (design
    // section 3.5).
    txt_values: ValueGuarantee::PerValue,
    // The client reads, compares and writes; no request carries a condition on the rrset.
    preconditions: Preconditions::ReadThenWrite,
    // Individual records without IDs: a replacement is several requests.
    atomic_rrset_write: false,
    // No add function has a TTL parameter (documentation 9.2, 9.3, 9.9), and the listing states
    // none per record (9.11).
    ttl: TtlSupport::NotSettable,
    // The provider's TTL is the only one: records read with it, and a write may ask for it.
    provider_default_ttl: ProviderDefaultTtl::Requestable,
    asynchronous: false,
};
