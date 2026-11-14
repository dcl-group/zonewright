//! Metadata of the VK Cloud provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. Field keys, defaults and ranges are those of the earlier TXT-only
//! implementation, with the changes listed in design section 11.3; the client carries the
//! references to the provider's documentation (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the seven types the provider's API documents, and the TXT value
//! operations on plain values.

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of VK Cloud.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::VkCloud,
    name: "VK Cloud",
    verified: false,
    default_propagation_timeout: None,
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "project_id",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Project ID",
        help: "The project ID shown on the API access page of the project settings.",
        advanced: false,
    },
    ConfigField {
        key: "username",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "User name",
        help: "Login (e-mail address) of a project user with API access and a DNS role.",
        advanced: false,
    },
    ConfigField {
        key: "password",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Password",
        help: "Password of this user.",
        advanced: false,
    },
    ConfigField {
        key: "user_domain",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: Some("users"),
        label: "User domain",
        help: "The user domain name shown on the API access page.",
        advanced: true,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Integer {
            min: 60,
            max: 86400,
        },
        default: Some("60"),
        label: "Record TTL, s",
        help: "TTL of new records, in seconds.",
        advanced: true,
    },
    ConfigField {
        key: "identity_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://infra.mail.ru/identity/v3"),
        label: "Keystone URL",
        help: "Endpoint of the identity API; change it for another region or a test server.",
        advanced: true,
    },
    ConfigField {
        key: "dns_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://mcs.mail.ru/public-dns/v2/dns"),
        label: "DNS API URL",
        help: "Endpoint of the DNS API; change it for another region or a test server.",
        advanced: true,
    },
];

/// What this version of the crate implements for VK Cloud.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    // The types with documented paths and fields (the provider's OpenAPI description). The API
    // has no SOA record (the zone carries the SOA fields) and no other type.
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
    // The encoding of values with spaces, quotes, backslashes or non-ASCII bytes is not
    // established for this API (design section 4.4).
    txt_plain_only: true,
    // One record per value, created and deleted by identifier (design section 3.5).
    txt_values: ValueGuarantee::PerValue,
    preconditions: Preconditions::ReadThenWrite,
    // Individual records with IDs: a replacement is several requests (creates, then deletes),
    // and no request carries a condition on the rrset as read.
    atomic_rrset_write: false,
    // The OpenAPI, `ttl`: 60 to 2147483648, on every record; the model's largest TTL is
    // 2147483647. No documented call changes the TTL of an existing record.
    ttl: TtlSupport::PerRecord {
        min: 60,
        max: 2_147_483_647,
    },
    provider_default_ttl: false,
    asynchronous: false,
};
