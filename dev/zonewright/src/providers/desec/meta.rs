//! Metadata of the deSEC provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. The client carries the references to the provider's documentation
//! (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types the provider's documentation names in presentation
//! format (the client's `records.rs` gives the sources), and the TXT value operations, on any
//! value: the documentation gives the escapes of TXT content.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of deSEC.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Desec,
    name: "deSEC",
    verified: false,
    // Source: lego providers/dns/desec/desec.go, `NewDefaultConfig` (`PropagationTimeout:
    // env.GetOrDefaultSecond(EnvPropagationTimeout, 120*time.Second)`).
    default_propagation_timeout: Some(Duration::from_secs(120)),
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "api_token",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "API token",
        help: "An API token of the deSEC account with write permission for the rrsets the client changes.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 1,
            max: 86_400,
            provider_default: false,
        },
        default: Some("3600"),
        label: "Record TTL, s",
        help: "TTL of a new rrset, in seconds; the zone's minimum TTL, set by the provider, also applies.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://desec.io/api/v1"),
        label: "API URL",
        help: "Endpoint of the provider's API; change it only to point the client at a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for deSEC.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // Types the documentation lists as supported, whose records are "given in presentation
    // format" (the client's `records.rs`). The documentation shows a value for A, AAAA, CNAME,
    // MX, NS, TLSA and TXT; for CAA, DNAME, HTTPS, PTR, SRV, SSHFP and SVCB the only source is
    // that general rule, so that the API's canonical text of those types reads back equal to the
    // crate's (and a listed set written back is a no-op) is inferred, not observed, until the
    // maintainer's live run (`desec_live_assumptions`). SOA cannot be read or written through the
    // API; the DNSSEC types are managed by the provider; the other listed types (AFSDB, HINFO,
    // LOC, …) have no canonical form in the crate beyond RFC 3597 and are listed, not read alone
    // or written.
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CAA,
        RecordType::CNAME,
        RecordType::DNAME,
        RecordType::HTTPS,
        RecordType::MX,
        RecordType::NS,
        RecordType::PTR,
        RecordType::SRV,
        RecordType::SSHFP,
        RecordType::SVCB,
        RecordType::TLSA,
        RecordType::TXT,
    ]),
    read_only_types: &[],
    // The documentation gives TXT content as quoted presentation text with escapes, and binary
    // data in `\DDD` form (rrsets.html, "TXT record"), which is the canonical text of design
    // section 4.4: any value is written in that form and read back by the same rule.
    txt_plain_only: false,
    // The rrset is replaced whole by PATCH, which carries no condition (design section 3.5).
    txt_values: ValueGuarantee::ReadThenWrite,
    preconditions: Preconditions::ReadThenWrite,
    // One POST or PATCH carries the whole rrset with its TTL.
    atomic_rrset_write: true,
    // One TTL per rrset, at most 86400. The floor is the zone's `minimum_ttl`, which the server
    // sets per domain (documentation example 900; 3600 is what lego and dns-update assume): it is
    // not a constant, so the client's floor is 1, and a TTL between 1 and the zone's minimum
    // passes the client's checks and is refused by the API (`400`, `Error::Rejected`) at the cost
    // of one write of the per-domain write quota.
    ttl: TtlSupport::PerRrset {
        min: 1,
        max: 86_400,
    },
    // `ttl` is mandatory on every rrset ("This field is mandatory when creating an RRset"):
    // there is no TTL of the provider's own to read or ask for.
    provider_default_ttl: ProviderDefaultTtl::Absent,
    asynchronous: false,
};
