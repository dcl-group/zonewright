//! Metadata of the Gandi provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. The client carries the references to the provider's documentation
//! (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types whose value form a source gives (the client's
//! `content.rs` cites each), and the TXT value operations on plain values, which use the API's
//! per-value `PATCH`.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of Gandi.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Gandi,
    name: "Gandi",
    verified: false,
    // Source: lego providers/dns/gandiv5/gandiv5.go:59 (`PropagationTimeout:
    // env.GetOrDefaultSecond(EnvPropagationTimeout, 20*time.Minute)`); gandiv5.toml ("Default:
    // 1200").
    default_propagation_timeout: Some(Duration::from_secs(1200)),
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "personal_access_token",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Personal access token",
        help: "A Gandi personal access token with access to the organization's LiveDNS domains and the permission to manage their records.",
        advanced: false,
    },
    ConfigField {
        key: "sharing_id",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: None,
        label: "Organization ID",
        help: "The ID of the organization whose domains the zone listing shows; without it, the API lists the domains of the personal organization only.",
        advanced: true,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 300,
            max: 2_592_000,
            provider_default: false,
        },
        default: Some("300"),
        label: "Record TTL, s",
        help: "TTL of a new rrset, in seconds, 300 to 2592000.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.gandi.net/v5/livedns"),
        label: "LiveDNS API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for Gandi.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // Only types whose value form a source shows for this API (the client's `content.rs`).
    // CAA, TLSA and the other types of the API's enumeration are listed, not written.
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::SRV,
        RecordType::TXT,
    ]),
    read_only_types: &[],
    // Only plain values (`Txt::is_plain`) in the TXT value operations: an ACME value is one, and
    // no source says how the API treats a quote, a backslash or a byte outside printable ASCII
    // inside a value.
    txt_plain_only: true,
    // `PATCH` with `add_rrset_values` / `remove_rrset_values` names only our value; a new rrset
    // is created by a `POST` that the API refuses (`409`) when the rrset exists. A foreign value
    // is never part of a request.
    txt_values: ValueGuarantee::PerValue,
    // `PUT` replaces the rrset without a condition the provider checks.
    preconditions: Preconditions::ReadThenWrite,
    // One `POST` or `PUT` carries the whole rrset with its TTL.
    atomic_rrset_write: true,
    // `rrset_ttl`: "Minimum: 300", "Maximum: 2592000" (LiveDNS API reference).
    ttl: TtlSupport::PerRrset {
        min: 300,
        max: 2_592_000,
    },
    // No source says what an rrset written without `rrset_ttl` gets, nor that a read can show
    // "no TTL of its own"; the client always sends a number.
    provider_default_ttl: ProviderDefaultTtl::Absent,
    asynchronous: false,
};
