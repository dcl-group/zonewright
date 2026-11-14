//! The Timeweb Cloud client: construction, `Debug` and the [`Provider`] implementation.
//!
//! The module follows the layout of every provider module: `meta.rs` (static metadata),
//! `config.rs` (settings and credentials), `api.rs` (the HTTP API), `txt.rs` (the TXT value
//! operations over one shape of the value layer) and this file.
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
use crate::provider::{AddOutcome, CheckReport, Provider, RemoveOutcome, ZoneCheck, ZoneInfo};
use crate::record::{Ttl, Txt};
use crate::redact::Detail;
use crate::values;

use super::api::{self, Api, Deleted};
use super::config::{self, TimewebCloudConfig, TimewebCloudCredentials};
use super::txt;

/// The Timeweb Cloud client.
///
/// Authenticates with an API token sent as `Authorization: Bearer`. The native unit is the
/// individual record with an identifier: TXT value operations create one record for the value
/// being added and delete only the records that hold the value being removed, under the
/// per-name lock of the [`Context`]. Values of other writers are never part of a request
/// (`ValueGuarantee::PerValue`); a writer outside this process can at worst cause a duplicate
/// of our own value.
///
/// The API lists the whole zone, page by page; every operation reads it in full before it
/// writes, so a very large zone costs many requests. A listing that ends before the total it
/// states is `Error::Protocol`.
///
/// A record this client created is remembered by its identifier in the `Context`, for at most
/// 1024 records and 24 hours. When the listing shows no record with the value being removed,
/// `remove_txt_value` deletes the remembered records by identifier, but only those whose
/// identifier a new complete listing does not show at all, and reports `Accepted`.
///
/// The create and delete endpoints are the `v1` ones, which the provider's API description
/// marks as deprecated (see the module documentation of the API calls).
pub struct TimewebCloud {
    config: TimewebCloudConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// The context, which holds the memory of created records.
    pub(super) ctx: Context,
    /// TTL of a new record; `None` leaves the choice to the provider.
    pub(super) ttl: Option<u32>,
}

impl fmt::Debug for TimewebCloud {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("TimewebCloud")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl TimewebCloud {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: TimewebCloudConfig,
        credentials: TimewebCloudCredentials,
        ctx: &Context,
    ) -> Result<TimewebCloud, Error> {
        let settings = config.validate(ctx)?;
        let raw = credentials.token.expose_secret();
        let token = raw.trim();
        if token.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("token must not be empty"),
            });
        }
        let http = Http::builder(ctx, ProviderId::TimewebCloud)
            .endpoint(&settings.api)
            .bearer("token", token)
            // The token as given is registered too, whether or not it was trimmed.
            .secret(raw)
            .message(api::error_message)
            .build()?;
        Ok(TimewebCloud {
            api: Api::new(http, settings.api),
            locks: ctx.locks().clone(),
            ctx: ctx.clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// Called after the value layer's complete listing showed no record with `value`: deletes
    /// the records this process created for `value` at `name`, by the identifiers it
    /// remembered, but only those that a new complete listing, read under the per-name lock,
    /// does not show at all.
    ///
    /// An identifier proves nothing about what the record holds now: the API changes records
    /// in place under the same identifier (`PATCH .../dns-records/{record_id}`), so a person or
    /// another program may have turned our record into theirs. A listed identifier is
    /// therefore never deleted from memory, whatever it holds now; its entry is dropped and the
    /// listing decides. A listing with a record without an identifier cannot prove that a
    /// remembered identifier is absent, so then nothing is deleted from memory either.
    async fn remove_remembered(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        let state = self.ctx.timeweb_cloud();
        let endpoint = self.api.endpoint_key();
        if state
            .recall(endpoint, zone, name, value.as_bytes())
            .is_empty()
        {
            return Ok(RemoveOutcome::NotPresent);
        }
        let _guard = self.locks.lock(name).await;
        // Recall again under the lock: an operation that held it may have used or changed the
        // entries.
        let remembered = state.recall(endpoint, zone, name, value.as_bytes());
        if remembered.is_empty() {
            return Ok(RemoveOutcome::NotPresent);
        }
        let records = self.api.records(zone).await?;
        let mut hidden = Vec::with_capacity(remembered.len());
        for id in remembered {
            if records.iter().any(|record| record.id() == Some(id)) {
                state.forget(endpoint, zone, id);
            } else {
                hidden.push(id);
            }
        }
        if records
            .iter()
            .any(|record| txt::holds(record, zone, name, value))
        {
            // The value is listed now, after the value layer's read found it absent: it was
            // added, or became visible, in between. The listing decides on the next attempt.
            return Err(Error::Conflict {
                detail: Detail::constant(
                    "the value appeared in the listing while it was being removed; repeat the \
                     removal",
                ),
            });
        }
        if hidden.is_empty() || records.iter().any(|record| record.id().is_none()) {
            return Ok(RemoveOutcome::NotPresent);
        }
        let mut deleted = false;
        for id in hidden {
            if let Deleted::Done = self.api.delete_record(zone, id).await? {
                deleted = true;
            }
            state.forget(endpoint, zone, id);
        }
        Ok(if deleted {
            // The listing did not show the record, so what else is at the name is unknown.
            RemoveOutcome::Accepted
        } else {
            // The listing showed no record with the value, and the records are gone.
            RemoveOutcome::NotPresent
        })
    }
}

impl Provider for TimewebCloud {
    fn id(&self) -> ProviderId {
        ProviderId::TimewebCloud
    }

    /// Reads one page of the account's domains, which exercises the token on every call without
    /// naming a zone, and looks every zone up afresh.
    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        self.api.probe().await?;
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            let found = self.api.zone_exists(zone).await?;
            checks.push(ZoneCheck::new(zone.clone(), found, None));
        }
        Ok(CheckReport::new(true, checks))
    }

    /// Every domain of the account, all pages.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let names: BTreeSet<DomainName> = self
            .api
            .domains()
            .await?
            .iter()
            .filter_map(|domain| DomainName::parse(&domain.fqdn).ok())
            .collect();
        Ok(names.into_iter().map(ZoneInfo::new).collect())
    }

    async fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<Ttl>,
    ) -> Result<AddOutcome, Error> {
        values::add_per_record(self, zone, name, value, ttl).await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        let outcome = values::remove_per_record(self, zone, name, value).await?;
        match outcome {
            RemoveOutcome::NotPresent => self.remove_remembered(zone, name, value).await,
            other => Ok(other),
        }
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`TimewebCloud::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<TimewebCloud, Error> {
    TimewebCloud::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
