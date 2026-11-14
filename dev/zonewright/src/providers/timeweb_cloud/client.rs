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

use super::api::{self, Api};
use super::config::{self, TimewebCloudConfig, TimewebCloudCredentials};

/// The Timeweb Cloud client.
///
/// Authenticates with an API token sent as `Authorization: Bearer`. The native unit is the
/// individual record with an identifier: TXT value operations create one record for the value
/// being added and delete only the records that hold the value being removed, under the
/// per-name lock of the [`Context`]. Values of other writers are never part of a request
/// (`ValueGuarantee::PerValue`); a writer outside this process can at worst cause a duplicate
/// of our own value.
///
/// Records are created and deleted with the `v2` calls, addressed to the record's owner name,
/// and read with the listing of that name (the domain's, or the subdomain's), page by page;
/// every operation reads it in full before it writes. A listing that ends before the total it
/// states is `Error::Protocol`. The client keeps no state between operations.
pub struct TimewebCloud {
    config: TimewebCloudConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
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
            ttl: settings.ttl,
            config,
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
        values::remove_per_record(self, zone, name, value).await
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
