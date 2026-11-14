//! Metadata of the RFC 2136 provider: configuration fields, capabilities and defaults.
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

/// The metadata of RFC 2136.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Rfc2136,
    name: "RFC 2136",
    verified: false,
    default_propagation_timeout: None,
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "server",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "DNS server",
        help: "The primary server of the zone that accepts dynamic updates over TCP: host, host:port or [IPv6]:port; port 53 by default.",
        advanced: false,
    },
    ConfigField {
        key: "key_name",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "TSIG key name",
        help: "The name of the TSIG key as configured on the server, for example acme-update.",
        advanced: false,
    },
    ConfigField {
        key: "algorithm",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: Some("hmac-sha256"),
        label: "TSIG algorithm",
        help: "hmac-sha256 or hmac-sha512.",
        advanced: false,
    },
    ConfigField {
        key: "secret",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "TSIG secret (base64)",
        help: "The base64 secret of the TSIG key; at least 16 bytes.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Integer { min: 1, max: 86400 },
        default: Some("60"),
        label: "Record TTL, s",
        help: "TTL of new records, in seconds.",
        advanced: true,
    },
];

/// What this version of the crate implements for RFC 2136.
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
    preconditions: Preconditions::Atomic,
    atomic_rrset_write: false,
    ttl: TtlSupport::PerRrset {
        min: 1,
        max: 86_400,
    },
    provider_default_ttl: false,
    asynchronous: false,
};
