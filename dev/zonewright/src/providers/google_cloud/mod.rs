//! Google Cloud DNS (provider ID `google_cloud`): the Cloud DNS API v1, authenticated with a
//! service account key through the OAuth 2.0 token endpoint.
//!
//! The metadata is present in every build. The client, `GoogleCloud`, with its settings
//! `GoogleCloudConfig` and credentials `GoogleCloudCredentials` (holding a `ServiceAccountKey`),
//! is compiled with the cargo feature `google_cloud`.
//!
//! This version offers `check`, `list_zones`, the record-level operations and the TXT value
//! operations. The TXT value operations accept plain values only. Every write reads the rrset
//! and sends one change whose deletions carry the rrset exactly as read; the provider applies a
//! change atomically and refuses it when a deletion does not match the stored rrset, so a
//! concurrent writer outside this process cannot lose its change (see
//! [`ValueGuarantee::Conditional`](crate::ValueGuarantee::Conditional) and
//! [`Preconditions::Atomic`](crate::Preconditions::Atomic)).
//!
//! Authentication is the service account key only: a JWT signed with the key (RS256) is
//! exchanged for an access token. Credentials from the metadata server, workload identity
//! federation, application default credentials and service account impersonation are out of
//! scope. Only public managed zones are used; private zones, and zones that forward or peer
//! queries, are not.

pub(crate) mod meta;

#[cfg(feature = "google_cloud")]
mod api;
#[cfg(feature = "google_cloud")]
mod client;
#[cfg(feature = "google_cloud")]
mod config;
#[cfg(feature = "google_cloud")]
mod records;
#[cfg(feature = "google_cloud")]
mod rrset;
#[cfg(feature = "google_cloud")]
mod txt;

#[cfg(feature = "google_cloud")]
pub use client::GoogleCloud;
#[cfg(feature = "google_cloud")]
pub(crate) use client::from_json;
#[cfg(feature = "google_cloud")]
pub use config::{GoogleCloudConfig, GoogleCloudCredentials, ServiceAccountKey};
