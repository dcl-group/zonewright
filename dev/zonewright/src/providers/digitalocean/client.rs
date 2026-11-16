//! The DigitalOcean client: construction, `Debug` and the [`Provider`] implementation.
//!
//! The module follows the layout of every provider module: `meta.rs` (static metadata),
//! `config.rs` (settings and credentials), `api.rs` (the HTTP API), `txt.rs` (the TXT value
//! operations over one shape of the value layer), `records.rs` (the record-level operations over
//! one shape of the record layer, and the mapping of each record type) and this file.
//!
//! The domain's name is the key of every path, so there are no zone identifiers to cache and
//! none to go stale.

use std::collections::BTreeSet;
use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::error::Error;
use crate::http::Http;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::name::DomainName;
use crate::operation::Call;
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneCheck,
    ZoneInfo, ZoneListing,
};
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::{rrsets, values};

use super::api::{self, Api};
use super::config::{self, DigitalOceanConfig, DigitalOceanCredentials};

/// The DigitalOcean DNS client (API v2).
///
/// Authenticates with a personal access token sent as `Authorization: Bearer`. The native unit
/// is the individual record with an identifier: TXT value operations create one record for
/// the value being added and delete only the records that hold the value being removed, under
/// the per-name lock of the [`Context`]. Values of other writers are never part of a request
/// (`ValueGuarantee::PerValue`); a writer outside this process can at worst cause a duplicate
/// of our own value.
///
/// Record-level writes work on the same records: a replacement creates the missing values first
/// and deletes the surplus records last, so the name never loses all its values; it is several
/// requests and not atomic (`atomic_rrset_write` is false), and a writer outside this process
/// that changes the rrset between the read and the writes is not detected
/// (`Preconditions::ReadThenWrite`).
///
/// A listing of records is read in full, page by page, before anything is written; the answer
/// of a listing that ends before the total it states is `Error::Protocol`.
pub struct DigitalOcean {
    config: DigitalOceanConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new record.
    pub(super) ttl: u32,
}

impl fmt::Debug for DigitalOcean {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("DigitalOcean")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DigitalOcean {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: DigitalOceanConfig,
        credentials: DigitalOceanCredentials,
        ctx: &Context,
    ) -> Result<DigitalOcean, Error> {
        let settings = config.validate(ctx)?;
        let raw = credentials.api_token.expose_secret();
        let token = raw.trim();
        if token.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("api_token must not be empty"),
            });
        }
        let http = Http::builder(ctx, ProviderId::DigitalOcean)
            .endpoint(&settings.api)
            .bearer("api_token", token)
            // The token as given is registered too, whether or not it was trimmed.
            .secret(raw)
            .message(api::error_message)
            .code(api::error_code)
            .build()?;
        Ok(DigitalOcean {
            api: Api::new(http, settings.api),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        Ok(match self.api.domain(zone).await? {
            None => ZoneCheck::new(zone.clone(), false, None),
            Some(stated) => {
                // The answer must be about the domain asked for.
                if DomainName::parse(&stated).as_ref() != Ok(zone) {
                    return Err(Error::Protocol {
                        detail: Detail::constant(
                            "the provider answered with a domain other than the one asked for",
                        ),
                    });
                }
                ZoneCheck::new(zone.clone(), true, None)
            }
        })
    }
}

impl Provider for DigitalOcean {
    fn id(&self) -> ProviderId {
        ProviderId::DigitalOcean
    }

    /// Reads the account, which exercises the token on every call, and looks every zone up
    /// afresh.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        Call::check(zones.len())
            .observe(self, async {
                let zones = zones.as_slice();
                self.api.account().await?;
                let mut checks = Vec::with_capacity(zones.len());
                for zone in zones {
                    checks.push(self.check_zone(zone).await?);
                }
                Ok(CheckReport::new(true, checks))
            })
            .await
    }

    /// Every domain of the account, all pages.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones()
            .observe(self, async {
                let names: BTreeSet<DomainName> = self
                    .api
                    .domains()
                    .await?
                    .iter()
                    .filter_map(|domain| DomainName::parse(&domain.name).ok())
                    .collect();
                Ok(names.into_iter().map(ZoneInfo::new).collect())
            })
            .await
    }

    /// Every record of the domain, all pages, grouped into rrsets. Records of types outside the
    /// record-level type list are listed too.
    async fn list_rrsets(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        Call::list_rrsets(zone)
            .observe(self, self.list_zone(zone))
            .await
    }

    async fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Option<RrSet>, Error> {
        Call::get_rrset(zone, name, rtype)
            .observe(self, rrsets::get_per_record(self, zone, name, rtype))
            .await
    }

    async fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> Result<SetOutcome, Error> {
        Call::set_rrset(zone, rrset)
            .observe(self, rrsets::set_per_record(self, zone, rrset, expect))
            .await
    }

    async fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        expect: Expect<'_>,
    ) -> Result<DeleteOutcome, Error> {
        Call::delete_rrset(zone, name, rtype)
            .observe(
                self,
                rrsets::delete_per_record(self, zone, name, rtype, expect),
            )
            .await
    }

    async fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<RrsetTtl>,
    ) -> Result<AddOutcome, Error> {
        Call::add_txt_value(zone, name)
            .observe(self, values::add_per_record(self, zone, name, value, ttl))
            .await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        Call::remove_txt_value(zone, name)
            .observe(self, values::remove_per_record(self, zone, name, value))
            .await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`DigitalOcean::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<DigitalOcean, Error> {
    DigitalOcean::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
