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
pub mod name;
pub mod providers;
pub mod record;

mod context;
mod error;
mod id;
mod meta;
mod provider;

// TEMPORARY (core phase): the locks and the TXT value layer are used by provider clients, none
// of which is ported yet; until then only their unit tests use them.
#[allow(dead_code)]
mod locks;
#[allow(dead_code)]
mod values;

// TEMPORARY (core phase): the scrubber has no user until the transport and the clients land.
#[allow(dead_code)]
mod redact;

// TEMPORARY (core phase): nothing uses these modules until the transport and the clients land.
#[cfg(feature = "__crypto")]
#[allow(dead_code)]
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
