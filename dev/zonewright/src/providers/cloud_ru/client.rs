//! The Cloud.ru client: construction, `Debug`, zone resolution and the [`Provider`]
//! implementation. The layout of the module is described in `providers/selectel_v2/client.rs`.

use std::collections::BTreeSet;
use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::error::Error;
use crate::http::{Http, ZoneCache, path_id, poll_interval};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::name::DomainName;
use crate::provider::{AddOutcome, CheckReport, Provider, RemoveOutcome, ZoneCheck, ZoneInfo};
use crate::record::{Ttl, Txt};
use crate::redact::Detail;
use crate::values;

use super::api::{self, Api, Zone};
use super::config::{self, CloudRuConfig, CloudRuCredentials, DEFAULT_POLL_MS};

/// Why a zone that exists cannot be used.
const ZONE_READ_ONLY: &str = "the zone is read-only at the provider";

/// The Cloud.ru Evolution DNS client (public zones).
///
/// Authenticates with an access key, exchanged for a bearer token that lives one hour. The
/// service keeps one record per name and type, holding all values of that name and type, and
/// replaces its values whole with no condition: TXT value operations read the record, read it
/// again immediately before the write and refuse with `Error::Conflict` if it changed, then
/// write the values back with the value added or removed, under the per-name lock of the
/// [`Context`]. A writer outside this process that changes the record between that second read
/// and the write can lose its change (`ValueGuarantee::ReadThenWrite`). Every write completes
/// through a provider-side operation that the client polls.
///
/// Zone identifiers are cached for the life of the client; a stale one is detected and resolved
/// again. A record listing reads the whole zone; the service allows 500 records per zone by
/// default, so that is a few pages of 100.
pub struct CloudRu {
    config: CloudRuConfig,
    /// The API.
    pub(super) api: Api,
    /// Zone name to zone identifier.
    pub(super) zones: ZoneCache,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new record.
    pub(super) ttl: u32,
}

impl fmt::Debug for CloudRu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key ID is registered with the scrubber like a secret, so it is left out here.
        f.debug_struct("CloudRu")
            .field("project_id", &self.config.project_id)
            .field("ttl", &self.config.ttl)
            .field("operation_poll_ms", &self.config.operation_poll_ms)
            .field("dns_url", &self.config.dns_url)
            .field("iam_url", &self.config.iam_url)
            .finish_non_exhaustive()
    }
}

impl CloudRu {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: CloudRuConfig,
        credentials: CloudRuCredentials,
        ctx: &Context,
    ) -> Result<CloudRu, Error> {
        let settings = config.validate(ctx)?;
        if credentials.is_empty() {
            return Err(config::config("secret must not be empty"));
        }
        let secret = credentials.secret;
        let http = Http::builder(ctx, ProviderId::CloudRu)
            .endpoint(&settings.dns)
            .endpoint(&settings.iam)
            .secret(secret.expose_secret())
            .secret(&config.key_id)
            .message(api::error_message)
            .build()?;
        let api = Api::new(
            http,
            settings.dns,
            &settings.iam,
            config.key_id.clone(),
            secret,
            poll_interval(Some(config.operation_poll_ms), DEFAULT_POLL_MS),
        );
        Ok(CloudRu {
            api,
            zones: ZoneCache::new(),
            locks: ctx.locks().clone(),
            ttl: config.ttl,
            config,
        })
    }

    /// The zone's identifier, looked up afresh. A missing zone is `Error::ZoneNotFound`, a
    /// read-only one `Error::Rejected`.
    pub(super) async fn resolve_zone(&self, zone: &DomainName) -> Result<String, Error> {
        match self.find_zone(zone).await? {
            Lookup::Found(id) => Ok(id),
            Lookup::Missing => Err(Error::zone_not_found(zone.clone())),
            Lookup::ReadOnly => Err(Error::Rejected {
                status: None,
                detail: Detail::constant(ZONE_READ_ONLY),
            }),
        }
    }

    /// Drops the cached identifier of `zone`.
    pub(super) fn forget_zone(&self, zone: &DomainName) {
        if let Some(id) = self.zones.get(zone) {
            self.zones.evict(zone, &id);
        }
    }

    /// Looks the zone up by name in the project's listing: there is no endpoint for one zone by
    /// name, and the listing's filter is not used (see `Api::zones`).
    async fn find_zone(&self, zone: &DomainName) -> Result<Lookup, Error> {
        let zones = self.api.zones(&self.config.project_id).await?;
        let Some(found) = zones
            .iter()
            .filter(|z| self.own(z))
            .find(|z| z.name().as_ref() == Some(zone))
        else {
            return Ok(Lookup::Missing);
        };
        if found.read_only {
            return Ok(Lookup::ReadOnly);
        }
        let id = found.id.as_deref().unwrap_or_default();
        Ok(Lookup::Found(path_id(id)?.to_owned()))
    }

    /// True unless the zone states another project than the configured one.
    fn own(&self, zone: &Zone) -> bool {
        zone.project_id
            .as_deref()
            .is_none_or(|p| p == self.config.project_id)
    }

    /// Looks the zone up afresh and reads its records once, which proves that the token may
    /// read them.
    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        self.forget_zone(zone);
        Ok(match self.find_zone(zone).await? {
            Lookup::Found(id) => match self.api.records(zone, &id).await {
                Ok(_) => {
                    self.zones.insert(zone, &id);
                    ZoneCheck::new(zone.clone(), true, None)
                }
                Err(Error::ZoneNotFound { .. }) => ZoneCheck::new(zone.clone(), false, None),
                Err(e) => return Err(e),
            },
            Lookup::Missing => ZoneCheck::new(zone.clone(), false, None),
            Lookup::ReadOnly => {
                ZoneCheck::new(zone.clone(), false, Some(Detail::constant(ZONE_READ_ONLY)))
            }
        })
    }
}

/// What a lookup by name found.
enum Lookup {
    Found(String),
    Missing,
    ReadOnly,
}

impl Provider for CloudRu {
    fn id(&self) -> ProviderId {
        ProviderId::CloudRu
    }

    /// Exchanges the access key for a new token (which verifies it), then looks every zone up
    /// afresh and reads its records.
    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        self.api.authenticate().await?;
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            checks.push(self.check_zone(zone).await?);
        }
        Ok(CheckReport::new(true, checks))
    }

    /// Every public zone of the configured project that is not read-only, all pages. The
    /// identifiers are cached.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let zones = self.api.zones(&self.config.project_id).await?;
        let mut names = BTreeSet::new();
        for zone in zones.iter().filter(|z| self.own(z) && !z.read_only) {
            let (Some(name), Some(Ok(id))) = (zone.name(), zone.id.as_deref().map(path_id)) else {
                continue;
            };
            self.zones.insert(&name, id);
            names.insert(name);
        }
        Ok(names.into_iter().map(ZoneInfo::new).collect())
    }

    async fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<Ttl>,
    ) -> Result<AddOutcome, Error> {
        values::add_whole_set(self, zone, name, value, ttl).await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        values::remove_whole_set(self, zone, name, value).await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`CloudRu::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<CloudRu, Error> {
    CloudRu::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
