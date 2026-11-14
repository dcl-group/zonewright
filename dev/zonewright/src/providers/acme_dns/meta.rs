//! Metadata of the acme-dns provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check` and `add_txt_value`.
//! The API has one operation, an update that stores a value in one of two rotating slots of a
//! registration, so there is no removal, no zone listing and no record-level operation.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
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
    // The API has no read.
    list_zones: false,
    list_rrsets: false,
    get_rrset: false,
    set_rrset: false,
    delete_rrset: false,
    add_txt_value: true,
    // The API has no delete: the server keeps the two most recent values (design section 11.3).
    remove_txt_value: false,
    record_types: TypeSet::Listed(&[]),
    read_only_types: &[],
    // The server accepts exactly 43 characters of the base64url alphabet, which are plain.
    txt_plain_only: true,
    // The server keeps two values per registration and drops the oldest.
    txt_values: ValueGuarantee::Rotating,
    // No meaning: there is no read and no record-level write (design section 11.1).
    preconditions: Preconditions::ReadThenWrite,
    // No rrset can be replaced: the API only adds a value to a rotating pair.
    atomic_rrset_write: false,
    // The server serves every value with a TTL of its own choosing.
    ttl: TtlSupport::NotSettable,
    // The server's TTL is the only one: an add may ask for it.
    provider_default_ttl: ProviderDefaultTtl::Requestable,
    asynchronous: false,
};
