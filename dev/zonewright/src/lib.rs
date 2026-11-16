//! `zonewright`: manage DNS zones at DNS hosting providers.
//!
//! The crate knows how to talk to providers and how to observe DNS. What records should exist,
//! and when, is the business of the application that uses it; the crate persists nothing.
//!
//! # Overview
//!
//! - Names and records: [`DomainName`] for zone and owner names, [`TargetName`] for names inside
//!   record data, [`RecordType`], [`Ttl`] and [`RrsetTtl`] (a number or the provider's default),
//!   [`RecordData`] in normalized zone-file text, and [`RrSet`], the unit of every record
//!   operation. Typed views exist for [`Txt`], [`Mx`], [`Srv`], [`Caa`], [`Tlsa`] and [`Svcb`].
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
//! propagation inspector. `socks` enables SOCKS5 proxies ([`HttpProxy`]), and
//! `platform-verifier` the operating system's trust store ([`TrustRoots::Platform`]); neither is
//! enabled by another feature. Features whose names start with two underscores are internal and
//! not part of the public API.
//!
//! Every provider client needs a `tokio` runtime.
//!
//! # Observability
//!
//! The crate emits `tracing` events only; it installs no subscriber.
//!
//! Every call of a [`Provider`] method on a client of this crate emits exactly one event when it
//! completes, whether the call goes to the typed client or through [`AnyProvider`]: level
//! `DEBUG`, target `zonewright::operation`, message `provider operation`, with these fields:
//!
//! - `provider`: the provider ID ([`ProviderId::as_str`]).
//! - `operation`: the method ([`Operation::as_str`]: `check`, `list_zones`, `add_txt_value`, ...).
//! - `zones`: for `check`, the number of zones given.
//! - `zone`: the zone, for every operation that takes one.
//! - `name` and `rtype`: the owner name and the record type, for the operations on one rrset
//!   (`rtype` is `TXT` for the TXT value operations).
//! - `outcome`: `ok`, or the error's kind ([`ErrorKind::as_str`]).
//! - `elapsed_ms`: the wall time of the call in milliseconds.
//!
//! A failed operation is reported at `DEBUG` as well: the error goes to the caller, who decides
//! how loud it is. An unsupported operation is reported too, with `outcome` `unsupported`. The
//! event never carries a record value or any other record data, a TTL, the text of an error, the
//! provider's error code (it comes from a response body; the caller has it on the error, through
//! [`Error::provider_code`]), the client's configuration, or anything else from a request or a
//! response; zone and owner names, which the caller passed in, are included. An implementation
//! of [`Provider`] outside the crate emits nothing.
//!
//! Below the operation, the HTTP transport emits one `DEBUG` event per attempt (target
//! `zonewright::http`: method, path without the query string, status, attempt, duration) and the
//! RFC 2136 client one per DNS exchange (target `zonewright::rfc2136`). Request and response
//! bodies and headers are never written to `tracing`, at any level.

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
    feature = "porkbun",
    feature = "gandi",
    feature = "dnsimple",
    feature = "desec",
    feature = "edgecenter",
    feature = "gcore",
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

// The operation event of every client's trait methods; compiled with every provider client.
#[cfg(any(
    feature = "acme_dns",
    feature = "beget",
    feature = "cloud_ru",
    feature = "cloudflare",
    feature = "digitalocean",
    feature = "porkbun",
    feature = "gandi",
    feature = "dnsimple",
    feature = "desec",
    feature = "edgecenter",
    feature = "gcore",
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
mod operation;

// The record-level layer is the shared implementation of the clients' record-level operations;
// compiled with the providers whose clients implement them.
#[cfg(any(
    feature = "selectel_v2",
    feature = "digitalocean",
    feature = "porkbun",
    feature = "gandi",
    feature = "dnsimple",
    feature = "desec",
    feature = "cloudflare",
    feature = "yandex_cloud",
    feature = "hetzner",
    feature = "vk_cloud",
    feature = "yandex_360",
    feature = "timeweb_cloud",
    feature = "regru",
    feature = "nicru",
    feature = "route53",
    feature = "rfc2136",
    feature = "cloud_ru",
    feature = "gcore",
    feature = "edgecenter"
))]
mod rrsets;

#[cfg(feature = "__http")]
mod http;

#[cfg(feature = "__crypto")]
mod crypto;

// `platform-verifier` without an HTTP provider builds the dependency but has no transport to use
// it in; this keeps Cargo's `unused_dependencies` lint quiet in that build.
#[cfg(all(feature = "platform-verifier", not(feature = "__http")))]
use rustls_platform_verifier as _;

pub use context::{Context, ContextOptions, HttpProxy, TrustRoots};
pub use error::{Error, ErrorKind, Operation, ProviderCode};
pub use id::{ProviderId, UnknownProviderId};
pub use meta::{
    Capabilities, ConfigField, FieldKind, Preconditions, ProviderDefaultTtl, ProviderMeta,
    TtlSupport, TypeSet, ValueGuarantee,
};
pub use name::{DomainName, NameError, TargetName};
pub use provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome,
    SkipReason, SkippedRrset, ZoneCheck, ZoneInfo, ZoneListing,
};
pub use providers::AnyProvider;
pub use record::{
    Caa, Mx, RecordData, RecordError, RecordType, RrSet, RrsetTtl, Srv, SvcParam, Svcb, Tlsa, Ttl,
    Txt,
};
pub use redact::Detail;

/// Compiles the examples of the README as documentation tests when the features they use are on.
#[cfg(all(doctest, feature = "cloudflare", feature = "inspector"))]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;
