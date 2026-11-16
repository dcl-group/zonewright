//! Metadata of the Azure DNS provider: configuration fields, capabilities and defaults.
//!
//! Present in every build. The client carries the references to the provider's documentation
//! (hard rule 3).
//!
//! Capabilities describe what this version of the crate implements: `check`, `list_zones`, the
//! record-level operations for the ten record types of the stable API version `2018-05-01`
//! (SOA read-only), and the TXT value operations. Every write is a `PUT` or `DELETE` of the whole
//! record set conditional on the etag the client read (`If-Match`) or on its absence
//! (`If-None-Match: *`), which the service checks.

use std::time::Duration;

use crate::id::ProviderId;
use crate::meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
use crate::record::RecordType;

/// The metadata of Azure DNS.
pub(crate) static META: ProviderMeta = ProviderMeta {
    id: ProviderId::AzureDns,
    name: "Azure DNS",
    verified: false,
    // Source: lego providers/dns/azuredns/azuredns.go, `NewDefaultConfig` (`PropagationTimeout:
    // env.GetOrDefaultSecond(EnvPropagationTimeout, 2*time.Minute)`).
    default_propagation_timeout: Some(Duration::from_secs(120)),
    fields: FIELDS,
    capabilities: CAPABILITIES,
};

/// Settings keys (non-secret) and credentials keys (secret).
const FIELDS: &[ConfigField] = &[
    ConfigField {
        key: "client_secret",
        secret: true,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Client secret",
        help: "A client secret of the application registration of the service principal.",
        advanced: false,
    },
    ConfigField {
        key: "tenant_id",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Tenant ID",
        help: "The Microsoft Entra tenant of the service principal: its ID or a domain name of the tenant.",
        advanced: false,
    },
    ConfigField {
        key: "client_id",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Client ID",
        help: "The application (client) ID of the service principal.",
        advanced: false,
    },
    ConfigField {
        key: "subscription_id",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Subscription ID",
        help: "The Azure subscription that holds the zones.",
        advanced: false,
    },
    ConfigField {
        key: "resource_group",
        secret: false,
        required: true,
        kind: FieldKind::Text,
        default: None,
        label: "Resource group",
        help: "The resource group that holds the zones; zones in other groups are not seen.",
        advanced: false,
    },
    ConfigField {
        key: "ttl",
        secret: false,
        required: false,
        kind: FieldKind::Ttl {
            min: 1,
            max: 2_147_483_647,
            provider_default: false,
        },
        default: Some("60"),
        label: "Record TTL, s",
        help: "TTL of a new rrset, in seconds.",
        advanced: true,
    },
    ConfigField {
        key: "management_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://management.azure.com"),
        label: "Resource Manager URL",
        help: "Endpoint of Azure Resource Manager, which receives the access token; set it only to a host trusted like the credentials (a national cloud, a test server).",
        advanced: true,
    },
    ConfigField {
        key: "login_url",
        secret: false,
        required: false,
        kind: FieldKind::Url,
        default: Some("https://login.microsoftonline.com"),
        label: "Identity platform URL",
        help: "Host of the Microsoft identity platform, which receives the client secret; set it only to a host trusted like the credentials (a national cloud, a test server).",
        advanced: true,
    },
    ConfigField {
        key: "scope",
        secret: false,
        required: false,
        kind: FieldKind::Text,
        default: Some("https://management.azure.com//.default"),
        label: "Token scope",
        help: "The scope of the token request; a national cloud needs its Resource Manager identifier followed by /.default.",
        advanced: true,
    },
];

/// The record types of the stable API version `2018-05-01` (the `RecordType` enumeration of
/// the "Record Sets - Create Or Update" reference, which also shows the body of each).
const RECORD_TYPES: &[RecordType] = &[
    RecordType::A,
    RecordType::AAAA,
    RecordType::CAA,
    RecordType::CNAME,
    RecordType::MX,
    RecordType::NS,
    RecordType::PTR,
    RecordType::SOA,
    RecordType::SRV,
    RecordType::TXT,
];

/// What this version of the crate implements for Azure DNS.
const CAPABILITIES: Capabilities = Capabilities {
    list_zones: true,
    list_rrsets: true,
    get_rrset: true,
    set_rrset: true,
    delete_rrset: true,
    add_txt_value: true,
    remove_txt_value: true,
    record_types: TypeSet::Listed(RECORD_TYPES),
    // The SOA record set is created with the zone and only updated by the service's owner; the
    // crate never writes SOA (design section 3.4).
    read_only_types: &[RecordType::SOA],
    // TXT strings are sent and read as printable ASCII without `"` and `\`, which need the
    // service's escape rules; any value of such characters is accepted, also with spaces and
    // longer than 255 octets (the client splits it). The client's `content.rs` states the rule.
    txt_plain_only: false,
    // Every write carries `If-Match` with the etag read, or `If-None-Match: *` for a create; the
    // service refuses it when the record set changed (design section 3.5).
    txt_values: ValueGuarantee::Conditional,
    preconditions: Preconditions::Atomic,
    // One PUT carries the whole record set with its TTL.
    atomic_rrset_write: true,
    // "Azure DNS supports any TTL value between 1 and 2,147,483,647 seconds" (dns-zones-records).
    ttl: TtlSupport::PerRrset {
        min: 1,
        max: 2_147_483_647,
    },
    // What a record set written without `TTL` gets is not documented; the client always sends
    // a number, and a set read without one reads with no TTL stated.
    provider_default_ttl: ProviderDefaultTtl::Absent,
    asynchronous: false,
};
