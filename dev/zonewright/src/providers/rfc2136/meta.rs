//! Metadata of the RFC 2136 provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, the TXT value
//! operations for any TXT value (they travel as wire-format RDATA, one RR per message), and the
//! record-level `get`, `set` and `delete` for every type with a type code and a wire form
//! (design sections 2.5 and 11.2), SOA read-only. The protocol has no listing of zones or of the
//! records of a zone (dynamic update has no such operation, RFC 2136 section 2.5), so
//! `list_zones` and `list_rrsets` are false.

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};
use crate::record::RecordType;

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
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // Every type with a code and a wire form; query and meta types are refused by every
    // operation (design section 2.2).
    record_types: TypeSet::AnyWithCode,
    // SOA is never writable (design section 3.4); the apex NS RRset is refused by the record
    // layer.
    read_only_types: &[RecordType::SOA],
    txt_plain_only: false,
    txt_values: ValueGuarantee::PerValue,
    // Prerequisites are evaluated by the server with the update, in one transaction (RFC 2136
    // sections 3.2 and 3.4.2.1).
    preconditions: Preconditions::Atomic,
    // One UPDATE can delete the RRset and add its new RRs, applied as one transaction (RFC 2136
    // sections 2.5.2, 3.3.2 and 3.4.2.1; design section 11.1).
    atomic_rrset_write: true,
    // What the protocol carries for a TTL a caller requests: 0 to 2^31 - 1 (RFC 2181 section
    // 8; RFC 1035 section 3.2.1). A delegation NS at 172800, the common parent-side TTL, is
    // accepted. The narrower range of the `ttl` setting (config.rs) concerns the configured
    // default only.
    ttl: TtlSupport::PerRrset {
        min: 0,
        max: 2_147_483_647,
    },
    provider_default_ttl: false,
    asynchronous: false,
};
