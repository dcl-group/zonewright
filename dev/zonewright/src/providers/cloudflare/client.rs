//! The Cloudflare client: construction, `Debug`, zone resolution and the [`Provider`]
//! implementation. The layout of a provider module is described in the Selectel v2 client.

use std::collections::BTreeSet;
use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::error::Error;
use crate::http::{Http, ZoneCache, path_id};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::name::DomainName;
use crate::provider::{AddOutcome, CheckReport, Provider, RemoveOutcome, ZoneCheck, ZoneInfo};
use crate::record::{Ttl, Txt};
use crate::redact::Detail;
use crate::values;

use super::api::{self, Api};
use super::config::{self, CloudflareConfig, CloudflareCredentials};

/// Why a zone that exists cannot be used.
const ZONE_NOT_ACTIVE: &str = "the zone is not active at the provider";

/// The Cloudflare DNS client (API v4).
///
/// Authenticates with an API token in `Authorization: Bearer`. The native unit is the
/// individual record: TXT value operations create one record per value and delete only the
/// records that hold the value, by identifier, so a writer outside this process cannot lose a
/// value to this client (`ValueGuarantee::PerValue`); a duplicate of a value is possible.
///
/// Zone identifiers are cached for the life of the client; a stale one is detected and
/// resolved again.
pub struct Cloudflare {
    config: CloudflareConfig,
    /// The API.
    pub(super) api: Api,
    /// Zone name to zone identifier.
    pub(super) zones: ZoneCache,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
}

impl fmt::Debug for Cloudflare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("Cloudflare")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Cloudflare {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: CloudflareConfig,
        credentials: CloudflareCredentials,
        ctx: &Context,
    ) -> Result<Cloudflare, Error> {
        let settings = config.validate(ctx)?;
        let raw = credentials.api_token.expose_secret();
        let token = raw.trim();
        if token.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("api_token must not be empty"),
            });
        }
        let http = Http::builder(ctx, ProviderId::Cloudflare)
            .endpoint(&settings.api)
            // The value as stored too, in case an API echoes it with its whitespace.
            .secret(raw)
            .bearer("api_token", token)
            .message(api::error_message)
            .build()?;
        Ok(Cloudflare {
            api: Api::new(http, settings.api),
            zones: ZoneCache::new(),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// The zone's identifier, looked up afresh. A missing zone is `Error::ZoneNotFound`, an
    /// inactive one `Error::Rejected`.
    pub(super) async fn resolve_zone(&self, zone: &DomainName) -> Result<String, Error> {
        match self.find_zone(zone).await? {
            Lookup::Found(id) => Ok(id),
            Lookup::Missing => Err(Error::zone_not_found(zone.clone())),
            Lookup::NotActive => Err(Error::Rejected {
                status: None,
                detail: Detail::constant(ZONE_NOT_ACTIVE),
            }),
        }
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

    /// Looks the zone up by name and compares the names exactly. Of several zones with the
    /// name, an active one is preferred.
    async fn find_zone(&self, zone: &DomainName) -> Result<Lookup, Error> {
        let named: Vec<api::Zone> = self
            .api
            .zones(Some(zone.without_dot()))
            .await?
            .into_iter()
            .filter(|z| DomainName::parse(&z.name).is_ok_and(|name| &name == zone))
            .collect();
        let found = named.iter().find(|z| z.is_active()).or(named.first());
        match found {
            None => Ok(Lookup::Missing),
            Some(z) if !z.is_active() => Ok(Lookup::NotActive),
            Some(z) => Ok(Lookup::Found(path_id(&z.id)?.to_owned())),
        }
    }

    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        self.forget_zone(zone);
        Ok(match self.find_zone(zone).await? {
            Lookup::Found(id) => {
                self.zones.insert(zone, &id);
                ZoneCheck::new(zone.clone(), true, None)
            }
            Lookup::Missing => ZoneCheck::new(zone.clone(), false, None),
            Lookup::NotActive => {
                ZoneCheck::new(zone.clone(), false, Some(Detail::constant(ZONE_NOT_ACTIVE)))
            }
        })
    }
}

/// What a lookup by name found.
enum Lookup {
    Found(String),
    Missing,
    NotActive,
}

impl Provider for Cloudflare {
    fn id(&self) -> ProviderId {
        ProviderId::Cloudflare
    }

    /// Makes an authenticated request (the token is static, so every call proves it afresh)
    /// and looks every zone up afresh.
    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        self.api.probe().await?;
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            checks.push(self.check_zone(zone).await?);
        }
        Ok(CheckReport::new(true, checks))
    }

    /// Every active zone the token can see, all pages. The identifiers are cached.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let mut names = BTreeSet::new();
        for zone in self.api.zones(None).await? {
            if !zone.is_active() {
                continue;
            }
            let (Ok(name), Ok(id)) = (DomainName::parse(&zone.name), path_id(&zone.id)) else {
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
/// [`Cloudflare::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Cloudflare, Error> {
    Cloudflare::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
