//! The VK Cloud client: construction, `Debug`, zone resolution and the [`Provider`]
//! implementation. The layout of a provider module is described in the Selectel v2 client.

use std::collections::BTreeSet;
use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::error::Error;
use crate::http::keystone::ProjectScope;
use crate::http::{Http, Keystone, ZoneCache, path_id};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::name::DomainName;
use crate::provider::{AddOutcome, CheckReport, Provider, RemoveOutcome, ZoneCheck, ZoneInfo};
use crate::record::{Ttl, Txt};
use crate::redact::Detail;
use crate::values;

use super::api::Api;
use super::config::{self, VkCloudConfig, VkCloudCredentials};

/// The VK Cloud public DNS client.
///
/// Authenticates with the OpenStack Keystone password exchange, scoped to one project, and
/// sends the token in `X-Auth-Token`. The native unit is the individual TXT record: TXT value
/// operations create one record per value and delete only the records that hold the value, by
/// identifier, so a writer outside this process cannot lose a value to this client
/// (`ValueGuarantee::PerValue`); a duplicate of a value is possible.
///
/// The API returns the zone listing and the TXT records of a zone in one answer each, without
/// paging, so a listing is bounded by the transport's 4 MiB body limit; a larger one fails.
///
/// Zone identifiers are cached for the life of the client; a stale one is detected and
/// resolved again.
pub struct VkCloud {
    config: VkCloudConfig,
    /// The API.
    pub(super) api: Api,
    /// Zone name to zone identifier.
    pub(super) zones: ZoneCache,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
}

impl fmt::Debug for VkCloud {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("VkCloud")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl VkCloud {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: VkCloudConfig,
        credentials: VkCloudCredentials,
        ctx: &Context,
    ) -> Result<VkCloud, Error> {
        let settings = config.validate(ctx)?;
        let password = &credentials.password;
        if password.expose_secret().is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("password must not be empty"),
            });
        }
        let http = Http::builder(ctx, ProviderId::VkCloud)
            .endpoint(&settings.dns)
            .endpoint(&settings.identity)
            .secret(password.expose_secret())
            .build()?;
        // Source: the provider's token documentation and lego vkcloud.go:102-108 (gophercloud
        // `AuthOptions` with `TenantID`): the token is scoped to the project by its ID.
        let keystone = Keystone::new(
            &settings.identity,
            &config.username,
            &config.user_domain,
            ProjectScope::Id(&config.project_id),
            password,
        )?;
        Ok(VkCloud {
            api: Api::new(http, settings.dns, keystone),
            zones: ZoneCache::new(),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// The zone's identifier, looked up afresh. A missing zone is `Error::ZoneNotFound`.
    pub(super) async fn resolve_zone(&self, zone: &DomainName) -> Result<String, Error> {
        self.find_zone(zone)
            .await?
            .ok_or_else(|| Error::zone_not_found(zone.clone()))
    }

    /// The identifier a write goes to: the cached one (the read of the same operation has just
    /// resolved or confirmed it), else a fresh lookup.
    pub(super) async fn write_zone_id(&self, zone: &DomainName) -> Result<String, Error> {
        match self.zones.get(zone) {
            Some(id) => Ok(id),
            None => {
                let id = self.resolve_zone(zone).await?;
                self.zones.insert(zone, &id);
                Ok(id)
            }
        }
    }

    /// Drops the cached identifier of `zone`.
    pub(super) fn forget_zone(&self, zone: &DomainName) {
        if let Some(id) = self.zones.get(zone) {
            self.zones.evict(zone, &id);
        }
    }

    /// Looks the zone up by name in the project's listing and compares the names exactly.
    // Source: the OpenAPI has no zone-by-name path; lego vkcloud.go:132-143 lists the zones
    // and compares `zone.Zone` with the zone name without the trailing dot.
    async fn find_zone(&self, zone: &DomainName) -> Result<Option<String>, Error> {
        let found = self
            .api
            .zones()
            .await?
            .into_iter()
            .find(|z| DomainName::parse(&z.zone).is_ok_and(|name| &name == zone));
        match found {
            None => Ok(None),
            Some(z) => {
                let id = z.id().ok_or(Error::Protocol {
                    detail: Detail::constant("the provider listed the zone without an identifier"),
                })?;
                Ok(Some(path_id(id)?.to_owned()))
            }
        }
    }

    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        self.forget_zone(zone);
        Ok(match self.find_zone(zone).await? {
            Some(id) => {
                self.zones.insert(zone, &id);
                ZoneCheck::new(zone.clone(), true, None)
            }
            None => ZoneCheck::new(zone.clone(), false, None),
        })
    }
}

impl Provider for VkCloud {
    fn id(&self) -> ProviderId {
        ProviderId::VkCloud
    }

    /// Obtains a token (which verifies the credentials) and looks every zone up afresh.
    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        self.api.authenticate().await?;
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            checks.push(self.check_zone(zone).await?);
        }
        Ok(CheckReport::new(true, checks))
    }

    /// Every zone of the project, in one answer. The identifiers are cached.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let mut names = BTreeSet::new();
        for zone in self.api.zones().await? {
            let (Ok(name), Some(Ok(id))) = (DomainName::parse(&zone.zone), zone.id().map(path_id))
            else {
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
/// [`VkCloud::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<VkCloud, Error> {
    VkCloud::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
