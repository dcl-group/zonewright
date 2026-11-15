//! The VK Cloud client: construction, `Debug`, zone resolution and the [`Provider`]
//! implementation. The layout of a provider module is described in the Selectel v2 client.

use std::collections::BTreeMap;
use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::error::Error;
use crate::http::keystone::ProjectScope;
use crate::http::{Http, Keystone, ZoneCache, path_id};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::name::DomainName;
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneCheck,
    ZoneInfo, ZoneListing,
};
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::{rrsets, values};

use super::api::{Api, Zone};
use super::config::{self, VkCloudConfig, VkCloudCredentials};

/// Why a zone is not usable when the project lists more than one zone of its name.
const AMBIGUOUS: &str = "the project lists more than one zone of this name, with different \
                         identifiers; the client cannot tell which one to change";

/// The result of looking a zone up by name.
enum Lookup {
    /// Exactly one identifier.
    Found(String),
    /// No zone of the name.
    Missing,
    /// Several zones of the name with different identifiers.
    Ambiguous,
}

/// The VK Cloud public DNS client.
///
/// Authenticates with the OpenStack Keystone password exchange, scoped to one project, and
/// sends the token in `X-Auth-Token`. The native unit is the individual record, on paths of its
/// own for each type: TXT value operations create one record per value and delete only the
/// records that hold the value, by identifier, so a writer outside this process cannot lose a
/// value to this client (`ValueGuarantee::PerValue`); a duplicate of a value is possible.
///
/// The record-level operations cover A, AAAA, CNAME, MX, NS, SRV and TXT. Replacing an rrset is
/// several requests (creates, then deletes) and not atomic (`atomic_rrset_write` is false), and a
/// writer outside this process that changes the rrset between the read and the writes is not
/// detected (`Preconditions::ReadThenWrite`). A CNAME is replaced by one in-place update of its
/// target, so a refused change leaves the old record. The API cannot change the TTL of an
/// existing record: a requested TTL that differs from that of a record which stays (a CNAME
/// changed in place included) is `Error::InvalidInput`, and nothing is written.
///
/// The API returns the zone listing and the records of one type in one answer each, without
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

    /// The zone's identifier, looked up afresh. A missing zone is `Error::ZoneNotFound`; a name
    /// that several zones of the project carry is `Error::Config`.
    pub(super) async fn resolve_zone(&self, zone: &DomainName) -> Result<String, Error> {
        match self.find_zone(zone).await? {
            Lookup::Found(id) => Ok(id),
            Lookup::Missing => Err(Error::zone_not_found(zone.clone())),
            Lookup::Ambiguous => Err(Error::Config {
                detail: Detail::constant(AMBIGUOUS),
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

    /// Looks the zone up by name in the project's listing and compares the names exactly.
    /// Every zone of the name counts: two with different identifiers are ambiguous, never "the
    /// first one".
    // Source: the OpenAPI has no zone-by-name path; lego vkcloud.go:132-143 lists the zones
    // and compares `zone.Zone` with the zone name without the trailing dot (lego takes the
    // first match; this client refuses to guess between several).
    async fn find_zone(&self, zone: &DomainName) -> Result<Lookup, Error> {
        let listed = self.api.zones().await?;
        let mut found: Option<String> = None;
        for z in listed.iter().filter(|z| is_zone(z, zone)) {
            let id = z.id().ok_or(Error::Protocol {
                detail: Detail::constant("the provider listed the zone without an identifier"),
            })?;
            let id = path_id(id)?;
            match &found {
                None => found = Some(id.to_owned()),
                Some(first) if first == id => {}
                Some(_) => return Ok(Lookup::Ambiguous),
            }
        }
        Ok(found.map_or(Lookup::Missing, Lookup::Found))
    }

    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        self.forget_zone(zone);
        Ok(match self.find_zone(zone).await? {
            Lookup::Found(id) => {
                self.zones.insert(zone, &id);
                ZoneCheck::new(zone.clone(), true, None)
            }
            Lookup::Missing => ZoneCheck::new(zone.clone(), false, None),
            Lookup::Ambiguous => {
                ZoneCheck::new(zone.clone(), false, Some(Detail::constant(AMBIGUOUS)))
            }
        })
    }
}

impl Provider for VkCloud {
    fn id(&self) -> ProviderId {
        ProviderId::VkCloud
    }

    /// Obtains a token (which verifies the credentials) and looks every zone up afresh.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        let zones = zones.as_slice();
        self.api.authenticate().await?;
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            checks.push(self.check_zone(zone).await?);
        }
        Ok(CheckReport::new(true, checks))
    }

    /// Every zone of the project, in one answer. The identifiers are cached, except for a name
    /// that several zones carry with different identifiers: it is listed, and an operation on
    /// it is `Error::Config`.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let mut ids: BTreeMap<DomainName, Option<String>> = BTreeMap::new();
        for zone in self.api.zones().await? {
            let (Ok(name), Some(Ok(id))) = (DomainName::parse(&zone.zone), zone.id().map(path_id))
            else {
                continue;
            };
            ids.entry(name)
                .and_modify(|seen| {
                    if seen.as_deref() != Some(id) {
                        *seen = None;
                    }
                })
                .or_insert_with(|| Some(id.to_owned()));
        }
        for (name, id) in &ids {
            match id {
                Some(id) => self.zones.insert(name, id),
                None => self.forget_zone(name),
            }
        }
        Ok(ids.into_keys().map(ZoneInfo::new).collect())
    }

    /// Every record of the zone, one listing per type, grouped into rrsets.
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

/// Whether the listed zone `listed` is `zone`.
fn is_zone(listed: &Zone, zone: &DomainName) -> bool {
    DomainName::parse(&listed.zone).is_ok_and(|name| &name == zone)
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
