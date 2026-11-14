//! Metadata of the Route 53 provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones` and
//! the TXT value operations on plain values. The record-level operations are not written yet, so
//! their flags are false and `record_types` is empty.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};

/// The metadata of Route 53.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Route53,
    name: "Route 53",
    verified: false,
    default_propagation_timeout: Some(Duration::from_secs(120)),
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "access_key_id",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Access key ID",
        help: "ID of an IAM access key limited to the Route 53 actions the client uses.",
        advanced: false,
    },
    ConfigField {
        key: "secret_access_key",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Secret access key",
        help: "The secret of the access key.",
        advanced: false,
    },
    ConfigField {
        key: "session_token",
        secret: true,
        required: false,
        kind: FieldKind::Text,
        default: None,
        label: "Session token",
        help: "Only for temporary security credentials; it expires with them.",
        advanced: true,
    },
    ConfigField {
        key: "hosted_zone_id",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: None,
        label: "Hosted zone ID",
        help: "Selects one hosted zone when several public zones share a name.",
        advanced: true,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Integer { min: 1, max: 86400 },
        default: Some("60"),
        label: "Record TTL, s",
        help: "TTL of a new rrset, in seconds.",
        advanced: true,
    },
    ConfigField {
        key: "change_poll_ms",
        secret: false,
        required: false,
        kind: FieldKind::Integer {
            min: 250,
            max: 60000,
        },
        default: Some("2000"),
        label: "Polling interval, ms",
        help: "Interval between two polls of a provider-side operation, in milliseconds; at least 250.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://route53.amazonaws.com"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Route 53.
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
    // Values outside printable ASCII are written by the API as octal escapes, unlike zone-file
    // text; until that is mapped, only plain values are accepted (design section 4.4).
    txt_plain_only: true,
    // Every write repeats the old set as a DELETE in the same atomic change batch (design
    // section 3.5).
    txt_values: ValueGuarantee::Conditional,
    preconditions: Preconditions::Atomic,
    atomic_rrset_write: true,
    ttl: TtlSupport::PerRrset {
        min: 1,
        max: 86_400,
    },
    provider_default_ttl: false,
    asynchronous: true,
};
