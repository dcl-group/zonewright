//! Metadata of the DNSimple provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. The client carries the references to the provider's documentation
//! (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the types whose content form a source establishes (the client's
//! `records.rs` gives the sources), and the TXT value operations on plain values.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of DNSimple.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::Dnsimple,
    name: "DNSimple",
    verified: false,
    // lego providers/dns/dnsimple/dnsimple.go: `DNSIMPLE_PROPAGATION_TIMEOUT` defaults to
    // `dns01.DefaultPropagationTimeout`, 60 seconds (challenge/dns01/dns_challenge.go).
    default_propagation_timeout: Some(Duration::from_secs(60)),
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
        label: "API access token",
        help: "An account token (recommended) or a user token; a user token needs the account ID.",
        advanced: false,
    },
    ConfigField {
        key: "account_id",
        secret: false,
        required: false,
        kind: FieldKind::Integer {
            min: 1,
            max: i64::MAX,
        },
        default: None,
        label: "Account ID",
        help: "The numeric account ID; required with a user token, read from an account token when empty.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 60,
            max: 259_200,
            provider_default: false,
        },
        default: Some("120"),
        label: "Record TTL, s",
        help: "TTL of new records, in seconds; 60 to 259200.",
        advanced: true,
    },
    ConfigField {
        key: "base_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://api.dnsimple.com/v2"),
        label: "API URL",
        help: "Endpoint of the provider's API; https://api.sandbox.dnsimple.com/v2 for the Sandbox, or a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for DNSimple.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    record_types: TypeSet::Listed(&[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::TXT,
    ]),
    // A system record "is not modifiable" (OpenAPI `ZoneRecord.system_record`); the SOA record of
    // the documented listing is one. Design section 3.4: SOA is never writable.
    read_only_types: &[RecordType::SOA],
    // How the API treats values with spaces, quotes, backslashes or non-ASCII bytes is not
    // established for the API (design section 4.4).
    txt_plain_only: true,
    // Every value is a record of its own, created and deleted by identifier (design section
    // 3.5).
    txt_values: ValueGuarantee::PerValue,
    preconditions: Preconditions::ReadThenWrite,
    // Individual records with IDs: a replacement is several requests (creates, then deletes),
    // and no request carries a condition on the rrset as read. The batch endpoint is not used.
    atomic_rrset_write: false,
    // The range is an assumption, marked and explained in `config.rs`.
    ttl: TtlSupport::PerRecord {
        min: 60,
        max: 259_200,
    },
    // `ttl` is a required member of every record in an answer (OpenAPI `ZoneRecord`).
    provider_default_ttl: ProviderDefaultTtl::Absent,
    asynchronous: false,
};
