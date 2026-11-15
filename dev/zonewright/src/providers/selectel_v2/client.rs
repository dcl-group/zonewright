//! The Selectel v2 client: construction, `Debug`, zone resolution and the [`Provider`]
//! implementation.
//!
//! # Layout of a provider module
//!
//! Every provider module follows this layout; this one is the model.
//!
//! - `mod.rs`: the module's rustdoc and re-exports. The metadata is compiled in every build;
//!   everything else behind the provider's cargo feature.
//! - `meta.rs`: `META`, the static metadata: settings and credentials keys, defaults, and the
//!   capabilities, switched on exactly for what the client implements.
//! - `config.rs`: the public `…Config` (settings) and `…Credentials` types, their defaults,
//!   `validate` (everything that can be checked without the network, error texts naming keys,
//!   never values) and the parsing of the JSON objects for `from_json`.
//! - `api.rs`: the provider's HTTP API and nothing else: endpoint constants, wire types, one
//!   function per endpoint, paging, the error-message extractor and the mapping of statuses the
//!   transport leaves to the client. Every fact carries its source.
//! - `rrset.rs`: the provider's native unit as both layers use it (read one by name and type,
//!   create, update, delete), with the rules for each answer, on top of `api.rs`.
//! - `records.rs`: the record-level operations: the mapping between the API's content text and
//!   `RecordData`, the implementation of one shape of the record layer (`crate::rrsets`), and the
//!   zone listing.
//! - `txt.rs`: the TXT value operations: the provider's TXT dialect and the implementation of
//!   one shape of the value layer (`crate::values`).
//! - `client.rs` (this file): the client type, its constructor and `from_json`, `Debug`,
//!   zone resolution with the zone-ID cache, and `impl Provider`, whose record-level methods call
//!   the record layer and whose TXT methods call the value layer.
//!
//! Tests live in `tests/<id>.rs` against the stateful mock in `dev/mock/src/<id>.rs`.

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
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneCheck,
    ZoneInfo, ZoneListing,
};
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::{rrsets, values};

use super::api::{self, Api, Zone};
use super::config::{self, Project, SelectelV2Config, SelectelV2Credentials};

/// Why a zone that exists cannot be used.
const ZONE_DISABLED: &str = "the zone is disabled at the provider";

/// The Selectel DNS v2 client.
///
/// Authenticates with the OpenStack Keystone password exchange, scoped to one project, and
/// sends the token in `X-Auth-Token`. The native unit is the rrset, replaced whole: record-level
/// writes and TXT value operations read the rrset and write it back, under the per-name lock of
/// the [`Context`]. A writer outside this process that changes the same rrset between that read
/// and that write can lose its change (`Preconditions::ReadThenWrite`,
/// `ValueGuarantee::ReadThenWrite`).
///
/// Zone identifiers are cached for the life of the client; a stale one is detected and
/// resolved again.
pub struct SelectelV2 {
    config: SelectelV2Config,
    /// The API.
    pub(super) api: Api,
    /// Zone name to zone identifier.
    pub(super) zones: ZoneCache,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
}

impl fmt::Debug for SelectelV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("SelectelV2")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SelectelV2 {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: SelectelV2Config,
        credentials: SelectelV2Credentials,
        ctx: &Context,
    ) -> Result<SelectelV2, Error> {
        let settings = config.validate(ctx)?;
        let password = &credentials.password;
        if password.expose_secret().is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("password must not be empty"),
            });
        }
        let http = Http::builder(ctx, ProviderId::SelectelV2)
            .endpoint(&settings.api)
            .endpoint(&settings.identity)
            .secret(password.expose_secret())
            .message(api::error_message)
            .build()?;
        // A project name is looked up within the account's domain (design section 11.3; the
        // authorization documentation's example scopes by name with the account number as the
        // domain).
        let project = match &settings.project {
            Project::Id(id) => ProjectScope::Id(id),
            Project::Name(name) => ProjectScope::Name {
                name,
                domain: &config.account_id,
            },
        };
        let keystone = Keystone::new(
            &settings.identity,
            &config.username,
            &settings.user_domain,
            project,
            password,
        )?;
        Ok(SelectelV2 {
            api: Api::new(http, settings.api, keystone),
            zones: ZoneCache::new(),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// The zone's identifier, looked up afresh. A missing zone is `Error::ZoneNotFound`, a
    /// disabled one `Error::Rejected`.
    pub(super) async fn resolve_zone(&self, zone: &DomainName) -> Result<String, Error> {
        match self.find_zone(zone).await? {
            Lookup::Found(id) => Ok(id),
            Lookup::Missing => Err(Error::zone_not_found(zone.clone())),
            Lookup::Disabled => Err(Error::Rejected {
                status: None,
                detail: Detail::constant(ZONE_DISABLED),
            }),
        }
    }

    /// The project the token is scoped to: the configured ID, or for a project given by name
    /// the ID the identity service stated for the token. Known once a token was obtained.
    fn own_project(&self) -> Result<String, Error> {
        match &self.config.project_id {
            Some(id) => Ok(id.clone()),
            None => self.api.token_project().ok_or(Error::Protocol {
                detail: Detail::constant(
                    "the identity service did not state the project of the token, so the \
                     zones of the configured project cannot be told from others",
                ),
            }),
        }
    }

    /// Drops the cached identifier of `zone`.
    pub(super) fn forget_zone(&self, zone: &DomainName) {
        if let Some(id) = self.zones.get(zone) {
            self.zones.evict(zone, &id);
        }
    }

    /// Looks the zone up by name. There is no endpoint for one zone by name: the listing is
    /// filtered by the name in Unicode and compared exactly, since the filter matches
    /// substrings. Of several zones with the name, one of the token's project is preferred:
    /// zones of other projects cannot be changed with this token.
    // Source: the OpenAPI has no zone-by-name path (`GET /zones/{zone_id}` only); lego `getZone`
    // (providers/dns/selectelv2/selectelv2.go) converts with `idna.ToUnicode` and compares
    // `zone.Name` with the FQDN.
    async fn find_zone(&self, zone: &DomainName) -> Result<Lookup, Error> {
        let unicode = zone.to_unicode();
        let filter = unicode.strip_suffix('.').unwrap_or(&unicode);
        let named: Vec<Zone> = self
            .api
            .zones(Some(filter))
            .await?
            .into_iter()
            .filter(|z| DomainName::parse(&z.name).is_ok_and(|name| &name == zone))
            .collect();
        // The listing obtained a token, so the project is normally known now.
        let project = self.own_project().ok();
        let own = |z: &&Zone| project.is_some() && z.project_id == project;
        let found = named.iter().find(own).or_else(|| named.first());
        match found {
            None => Ok(Lookup::Missing),
            Some(z) if z.disabled == Some(true) => Ok(Lookup::Disabled),
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
            Lookup::Disabled => {
                ZoneCheck::new(zone.clone(), false, Some(Detail::constant(ZONE_DISABLED)))
            }
        })
    }
}

/// What a lookup by name found.
enum Lookup {
    Found(String),
    Missing,
    Disabled,
}

impl Provider for SelectelV2 {
    fn id(&self) -> ProviderId {
        ProviderId::SelectelV2
    }

    /// Obtains a token (which verifies the credentials) and looks every zone up afresh. A zone
    /// of another project that the API lists is reported as found; writing to it is
    /// `Error::Forbidden`.
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

    /// Every enabled zone of the configured project, all pages. Zones of other projects that
    /// the API lists are left out; with a project given by name, its ID is the one the identity
    /// service states for the token. The identifiers are cached.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let zones = self.api.zones(None).await?;
        let project = self.own_project()?;
        let project = Some(project.as_str());
        let mut names = BTreeSet::new();
        for zone in zones {
            let foreign = zone
                .project_id
                .as_deref()
                .is_some_and(|owner| Some(owner) != project);
            if zone.disabled == Some(true) || foreign {
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

    /// Every rrset of the zone, all pages. Rrsets of types outside the record-level type list
    /// (DNAME, HTTPS, SVCB) are listed too; what the model cannot hold is in `skipped`.
    async fn list_rrsets(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        self.list_zone(zone).await
    }

    async fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Option<RrSet>, Error> {
        rrsets::get_whole_set(self, zone, name, rtype).await
    }

    async fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> Result<SetOutcome, Error> {
        rrsets::set_whole_set(self, zone, rrset, expect).await
    }

    async fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        expect: Expect<'_>,
    ) -> Result<DeleteOutcome, Error> {
        rrsets::delete_whole_set(self, zone, name, rtype, expect).await
    }

    async fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<RrsetTtl>,
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
/// [`SelectelV2::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<SelectelV2, Error> {
    SelectelV2::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
