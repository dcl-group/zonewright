//! Metadata of the acme-dns provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements. Until the client is ported,
//! every operation flag is false, `record_types` is empty and `txt_values` is `NotOffered`; the
//! provider's developer switches them on together with the client code that implements them.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};

/// The metadata of acme-dns.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::AcmeDns,
    name: "acme-dns",
    verified: false,
    default_propagation_timeout: Some(Duration::from_secs(60)),
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "server_url",
        secret: false,
        required: true,
        kind: FieldKind::Url,
        default: None,
        label: "acme-dns server URL",
        help: "Base URL of the acme-dns server, for example https://auth.example.org.",
        advanced: false,
    },
    ConfigField {
        key: "registrations",
        secret: true,
        required: true,
        kind: FieldKind::Multiline,
        default: None,
        label: "Registrations (JSON)",
        help: "The answer of the server's register call: an object or an array of objects with username, password, subdomain and fulldomain; every challenge name needs a CNAME to its fulldomain.",
        advanced: false,
    },
];

/// What this version of the crate implements for acme-dns.
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
    ttl: TtlSupport::NotSettable,
    provider_default_ttl: true,
    asynchronous: false,
};
