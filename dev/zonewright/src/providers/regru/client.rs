//! The reg.ru client: construction, `Debug` and the [`Provider`] implementation.
//!
//! The module follows the layout of every provider module: `meta.rs` (static metadata),
//! `config.rs` (settings and credentials), `api.rs` (the HTTP API), `txt.rs` (the TXT value
//! operations over one shape of the value layer), `records.rs` (the record-level operations over
//! one shape of the record layer) and this file.
//!
//! The domain's name is the key of every call, so there are no zone identifiers to cache and
//! none to go stale.

use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::error::Error;
use crate::http::Http;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::name::DomainName;
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneCheck,
    ZoneListing,
};
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::{rrsets, values};

use super::api::{self, Api};
use super::config::{self, RegruConfig, RegruCredentials};

/// The reg.ru client (API 2).
///
/// Authenticates with the account's user name and API password, sent in the form body of every
/// request (never in a URL), and optionally with a TLS client certificate. The native unit is the
/// individual record, identified by owner name, type and content: TXT value operations create one
/// record for the value being added and remove only the records that hold the value being
/// removed, under the per-name lock of the [`Context`]. Values of other writers are never part of
/// a request (`ValueGuarantee::PerValue`); a writer outside this process can at worst cause a
/// duplicate of our own value.
///
/// The record-level operations cover A, AAAA and TXT, the types whose add function and listing
/// form the documentation gives. Replacing an rrset is several requests (creates, then removals by
/// content) and not atomic (`atomic_rrset_write` is false), and a writer outside this process that
/// changes the rrset between the read and the writes is not detected
/// (`Preconditions::ReadThenWrite`).
///
/// The API has no zone listing, so `list_zones` is unsupported. No add function has a TTL
/// parameter: the zone's settings decide, and a requested TTL is refused. Every call is a `POST`,
/// reads included; only the reads are repeated automatically.
///
/// A zone is read whole, in one answer, before anything is written; a zone whose records do not
/// fit the transport's 4 MiB limit cannot be used and fails with `Error::Protocol`.
pub struct Regru {
    config: RegruConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
}

impl fmt::Debug for Regru {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The user name is left out: it is sent in every request body next to the password, and
        // an API that echoes the form must not be able to put it into a printed error.
        f.debug_struct("Regru")
            .field("base_url", &self.config.base_url)
            .field(
                "min_request_interval_ms",
                &self.config.min_request_interval_ms,
            )
            .finish_non_exhaustive()
    }
}

impl Regru {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: RegruConfig,
        credentials: RegruCredentials,
        ctx: &Context,
    ) -> Result<Regru, Error> {
        let settings = config.validate(ctx)?;
        let password = credentials.password.expose_secret();
        if password.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("password must not be empty"),
            });
        }
        let mut builder = Http::builder(ctx, ProviderId::Regru)
            .endpoint(&settings.api)
            // Both are form fields of every request; an API that echoes the form must not get
            // either into an error.
            .secret(&config.username)
            .secret(password)
            .pacing(settings.interval)
            .message(api::error_message);
        if let Some((cert, key)) = credentials.identity()? {
            builder = builder.client_identity(cert, key);
        }
        let http = builder.build()?;
        Ok(Regru {
            api: Api::new(
                http,
                settings.api,
                config.username.clone(),
                SecretString::from(password.to_owned()),
            ),
            locks: ctx.locks().clone(),
            config,
        })
    }

    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        Ok(match self.api.zone_nop(zone).await {
            Ok(()) => ZoneCheck::new(zone.clone(), true, None),
            Err(Error::ZoneNotFound { .. }) => ZoneCheck::new(zone.clone(), false, None),
            // The zone exists but cannot be managed (for example, it is served by other name
            // servers): the provider's reason is the detail.
            Err(Error::Rejected { detail, .. }) => {
                ZoneCheck::new(zone.clone(), false, Some(detail))
            }
            Err(e) => return Err(e),
        })
    }
}

impl Provider for Regru {
    fn id(&self) -> ProviderId {
        ProviderId::Regru
    }

    /// Calls `nop`, which authenticates and does nothing else, so the credentials are exercised
    /// on every call whether or not a zone is given, and looks every zone up afresh with
    /// `zone/nop`.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        let zones = zones.as_slice();
        self.api.nop().await?;
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            checks.push(self.check_zone(zone).await?);
        }
        Ok(CheckReport::new(true, checks))
    }

    /// Every record of the zone, in one answer, grouped into rrsets.
    async fn list_rrsets(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        self.list_zone(zone).await
    }

    async fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Option<RrSet>, Error> {
        rrsets::get_per_record(self, zone, name, rtype).await
    }

    async fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> Result<SetOutcome, Error> {
        rrsets::set_per_record(self, zone, rrset, expect).await
    }

    async fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        expect: Expect<'_>,
    ) -> Result<DeleteOutcome, Error> {
        rrsets::delete_per_record(self, zone, name, rtype, expect).await
    }

    async fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<RrsetTtl>,
    ) -> Result<AddOutcome, Error> {
        values::add_per_record(self, zone, name, value, ttl).await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        values::remove_per_record(self, zone, name, value).await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`Regru::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Regru, Error> {
    Regru::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
