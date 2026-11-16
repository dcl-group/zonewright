//! Azure DNS (provider ID `azure_dns`): public DNS zones through the Azure Resource Manager REST
//! API (`Microsoft.Network/dnsZones`, API version `2018-05-01`), authenticated as a service
//! principal with a client secret.
//!
//! The metadata is present in every build. The client, `AzureDns`, with its settings
//! `AzureDnsConfig` and credentials `AzureDnsCredentials`, is compiled with the cargo feature
//! `azure_dns`.
//!
//! This version offers `check`, `list_zones` (the zones of the configured resource group), the
//! record-level operations (`list_rrsets`, `get_rrset`, `set_rrset`, `delete_rrset`) for A, AAAA,
//! CAA, CNAME, MX, NS, PTR, SRV and TXT (SOA read-only), and the TXT value operations. Every
//! write is conditional on the record set's etag, which the service checks (see
//! [`Preconditions::Atomic`](crate::Preconditions::Atomic) and
//! [`ValueGuarantee::Conditional`](crate::ValueGuarantee::Conditional)).
//!
//! Out of scope: private DNS zones (a different resource type), alias record sets (a reference
//! to an Azure resource; listed as skipped, never written), and every other way to authenticate
//! (managed identity, workload identity federation, certificate credentials, the Azure CLI).

pub(crate) mod meta;

#[cfg(feature = "azure_dns")]
mod api;
#[cfg(feature = "azure_dns")]
mod client;
#[cfg(feature = "azure_dns")]
mod config;
#[cfg(feature = "azure_dns")]
mod content;
#[cfg(feature = "azure_dns")]
mod records;
#[cfg(feature = "azure_dns")]
mod rrset;
#[cfg(feature = "azure_dns")]
mod txt;

#[cfg(feature = "azure_dns")]
pub use client::AzureDns;
#[cfg(feature = "azure_dns")]
pub(crate) use client::from_json;
#[cfg(feature = "azure_dns")]
pub use config::{AzureDnsConfig, AzureDnsCredentials};
