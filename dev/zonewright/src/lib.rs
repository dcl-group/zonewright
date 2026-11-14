//! `zonewright`: manage DNS zones at DNS hosting providers.
//!
//! The crate knows how to talk to providers and how to observe DNS. What records should exist,
//! and when, is the business of the application that uses it; the crate persists nothing.
//!
//! # Overview
//!
//! - Names and records: [`DomainName`] for zone and owner names, [`TargetName`] for names inside
//!   record data, [`RecordType`], [`Ttl`], [`RecordData`] in normalized zone-file text, and
//!   [`RrSet`], the unit of every record operation. Typed views exist for [`Txt`], [`Mx`],
//!   [`Srv`], [`Caa`], [`Tlsa`] and [`Svcb`].
//! - Providers: [`ProviderId`] names a provider and is what an application stores;
//!   [`ProviderMeta`] describes its configuration fields and [`Capabilities`] in every build. The
//!   [`Provider`] trait is implemented by each client in [`providers`], and [`AnyProvider`]
//!   dispatches to the clients compiled into this build.
//! - [`Context`] is the state shared by all clients of a process: the HTTP client, the per-name
//!   locks and the process-local memory of the providers that need one.
//! - [`Error`] is the error of every provider operation; [`ErrorKind`] has stable identifiers.
//! - [`dns01`] holds the DNS-01 helpers: the challenge name, CNAME chains and zone selection.
//!
//! # Features
//!
//! No feature is enabled by default. Each provider is its own feature, named like its ID
//! (`cloudflare`, `selectel_v2`, ...); `all-providers` enables them all. `inspector` enables the
//! propagation inspector. Features whose names start with two underscores are internal and not
//! part of the public API.
//!
//! Every provider client needs a `tokio` runtime.

pub mod dns01;
#[cfg(feature = "inspector")]
pub mod inspector;
pub mod name;
pub mod providers;
pub mod record;

mod context;
mod error;
mod id;
mod meta;
mod provider;

mod locks;
mod redact;
// The TXT value layer is the shared implementation of the clients' TXT value operations.
#[cfg(any(
    feature = "acme_dns",
    feature = "beget",
    feature = "cloud_ru",
    feature = "cloudflare",
    feature = "digitalocean",
    feature = "hetzner",
    feature = "nicru",
    feature = "regru",
    feature = "rfc2136",
    feature = "route53",
    feature = "selectel_v2",
    feature = "timeweb_cloud",
    feature = "vk_cloud",
    feature = "yandex_360",
    feature = "yandex_cloud"
))]
mod values;

// The record-level layer is the shared implementation of the clients' record-level operations;
// compiled with the providers whose clients implement them.
#[cfg(feature = "selectel_v2")]
mod rrsets;

#[cfg(feature = "__http")]
mod http;

#[cfg(feature = "__crypto")]
mod crypto;

pub use context::{Context, ContextOptions};
pub use error::{Error, ErrorKind, Operation};
pub use id::{ProviderId, UnknownProviderId};
pub use meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderMeta, TtlSupport, TypeSet,
    ValueGuarantee,
};
pub use name::{DomainName, NameError, TargetName};
pub use provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome,
    SkipReason, SkippedRrset, ZoneCheck, ZoneInfo, ZoneListing,
};
pub use providers::AnyProvider;
pub use record::{
    Caa, Mx, RecordData, RecordError, RecordType, RrSet, Srv, SvcParam, Svcb, Tlsa, Ttl, Txt,
};
pub use redact::Detail;

/// Compiles the examples of the README as documentation tests when the features they use are on.
#[cfg(all(doctest, feature = "cloudflare", feature = "inspector"))]
#[doc = include_str!("../../../README.md")]
struct ReadmeExamples;
