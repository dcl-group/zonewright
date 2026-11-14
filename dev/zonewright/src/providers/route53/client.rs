//! The Route 53 client: construction, `Debug`, zone resolution and the [`Provider`]
//! implementation. The layout of the module follows the reference client (`selectel_v2`).

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::error::Error;
use crate::http::{Http, ZoneCache};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::name::DomainName;
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneCheck,
    ZoneInfo, ZoneListing,
};
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::rrsets;
use crate::values;

use super::api::{self, Api};
use super::config::{self, Route53Config, Route53Credentials};

/// Why `hosted_zone_id` cannot be used.
const OVERRIDE_PRIVATE: &str = "hosted_zone_id names a private hosted zone";
const OVERRIDE_MISSING: &str = "hosted_zone_id names no hosted zone of this account";

/// Why a zone name cannot be resolved to one hosted zone.
const AMBIGUOUS: &str = "several public hosted zones have this name; set hosted_zone_id";

/// The Amazon Route 53 client.
///
/// Every request is signed with AWS Signature Version 4 (Region `us-east-1`, service
/// `route53`), with the session token of temporary credentials when one is given. The native
/// unit is the rrset, changed by an atomic change batch: every write reads the rrset and
/// submits the old set as a `DELETE` together with the new set as a `CREATE`, so that a change
/// made by anyone in between makes the provider refuse the batch instead of losing it
/// (`ValueGuarantee::Conditional`, `Preconditions::Atomic`). After the batch is accepted the client polls the change
/// until it is `INSYNC`.
///
/// Zones are public hosted zones found by exact name; hosted zone IDs are cached for the life
/// of the client, and a stale one is detected and resolved again.
pub struct Route53 {
    config: Route53Config,
    /// The API.
    pub(super) api: Api,
    /// Zone name to hosted zone ID.
    pub(super) zones: ZoneCache,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
    /// The configured hosted zone, without the prefix.
    hosted_zone_id: Option<String>,
}

impl fmt::Debug for Route53 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret; the access key ID is sent in every request.
        f.debug_struct("Route53")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Route53 {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: Route53Config,
        credentials: Route53Credentials,
        ctx: &Context,
    ) -> Result<Route53, Error> {
        let settings = config.validate(ctx)?;
        let session_token = credentials.validate()?.is_some();
        let Route53Credentials {
            secret_access_key,
            session_token: token,
            ..
        } = credentials;
        let token = token.filter(|_| session_token);
        let mut http = Http::builder(ctx, ProviderId::Route53)
            .endpoint(&settings.api)
            .secret(secret_access_key.expose_secret())
            .message(api::error_message)
            .rate_limit(api::throttled);
        if let Some(token) = &token {
            http = http.secret(token.expose_secret());
        }
        let api = Api::new(
            http.build()?,
            settings.api,
            config.access_key_id.clone(),
            secret_access_key,
            token,
            Duration::from_millis(settings.change_poll_ms),
        )?;
        Ok(Route53 {
            api,
            zones: ZoneCache::new(),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            hosted_zone_id: settings.hosted_zone_id,
            config,
        })
    }

    /// The zone's hosted zone ID, looked up afresh. A missing zone is `Error::ZoneNotFound`;
    /// an ambiguous name or an unusable `hosted_zone_id` is `Error::Config`.
    pub(super) async fn resolve_zone(&self, zone: &DomainName) -> Result<String, Error> {
        match self.find_zone(zone).await? {
            Lookup::Found(id) => Ok(id),
            Lookup::Missing => Err(Error::zone_not_found(zone.clone())),
            Lookup::Unusable(why) => Err(config_error(why)),
        }
    }

    /// Drops the cached ID of `zone`.
    pub(super) fn forget_zone(&self, zone: &DomainName) {
        if let Some(id) = self.zones.get(zone) {
            self.zones.evict(zone, &id);
        }
    }

    /// Looks the zone up: the configured hosted zone if it has this name, otherwise the public
    /// hosted zones with exactly this name. Several of them are `Error::Config` (design section
    /// 11.3).
    // Source: API reference, `ListHostedZonesByName`: the listing starts at `dnsname` in sort
    // order, so the zones with that name come first; `HostedZone.Config.PrivateZone`. lego
    // providers/dns/route53/route53.go at commit c40c0a2a458a2dc77daaced6cb94a86e253dc8c1,
    // `getHostedZoneID` (lines 301-337): a configured hosted zone ID takes precedence; otherwise
    // the name is compared exactly and private zones are skipped (`PrivateZone` defaults to
    // false).
    ///
    /// What the answers say about the zone is the [`Lookup`]; an `Err` is a failure to obtain
    /// them (transport, authentication, an unreadable answer) and is never a zone finding.
    async fn find_zone(&self, zone: &DomainName) -> Result<Lookup, Error> {
        if let Some(id) = &self.hosted_zone_id {
            match self.api.hosted_zone(id).await? {
                None => return Ok(Lookup::Unusable(OVERRIDE_MISSING)),
                Some(hz) if hz.name.as_ref() == Some(zone) => {
                    if hz.private {
                        return Ok(Lookup::Unusable(OVERRIDE_PRIVATE));
                    }
                    return Ok(Lookup::Found(hz.id));
                }
                // The configured zone has another name; this one is looked up by name.
                Some(_) => {}
            }
        }
        let start = zone.without_dot();
        let mut found: Vec<String> = Vec::new();
        let mut cursor: Option<(String, String)> = None;
        for _ in 0..crate::http::pager::MAX_PAGES {
            let page = match &cursor {
                None => self.api.zones_page(Some(start), None).await?,
                Some((name, id)) => self.api.zones_page(Some(name), Some(id)).await?,
            };
            let mut past = false;
            for hz in page.zones {
                if hz.name.as_ref() != Some(zone) {
                    // Sorted by name: the zones with the name are behind us.
                    past = true;
                    break;
                }
                if !hz.private && !found.contains(&hz.id) {
                    found.push(hz.id);
                }
            }
            match page.next {
                Some(next) if !past => {
                    if cursor.as_ref() == Some(&next) {
                        return Err(Error::Protocol {
                            detail: Detail::constant("the provider's pagination did not advance"),
                        });
                    }
                    cursor = Some(next);
                }
                _ => {
                    return Ok(match found.pop() {
                        None => Lookup::Missing,
                        Some(id) if found.is_empty() => Lookup::Found(id),
                        Some(_) => Lookup::Unusable(AMBIGUOUS),
                    });
                }
            }
        }
        Err(Error::Protocol {
            detail: Detail::constant(
                "the listing has more than 1000 pages, the limit of the client",
            ),
        })
    }

    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        self.forget_zone(zone);
        // Only what the provider answered becomes a zone finding; any error, a `Config` one
        // from the transport (a refused certificate, the URL policy) included, fails the
        // check, so that `credentials_verified` is never reported without an answer.
        Ok(match self.find_zone(zone).await? {
            Lookup::Found(id) => {
                self.zones.insert(zone, &id);
                ZoneCheck::new(zone.clone(), true, None)
            }
            Lookup::Missing => ZoneCheck::new(zone.clone(), false, None),
            Lookup::Unusable(why) => {
                ZoneCheck::new(zone.clone(), false, Some(Detail::constant(why)))
            }
        })
    }
}

/// What a zone lookup found in the provider's answers.
enum Lookup {
    /// Exactly one usable hosted zone.
    Found(String),
    /// No public hosted zone with the name.
    Missing,
    /// The name cannot be resolved to one usable zone: the reason (ambiguous name, a
    /// `hosted_zone_id` that names a private zone or no zone).
    Unusable(&'static str),
}

impl Provider for Route53 {
    fn id(&self) -> ProviderId {
        ProviderId::Route53
    }

    /// Makes a signed request on every call, which verifies the keys: one lookup per zone, or
    /// the first hosted zone when no zone is given. Every zone is looked up afresh.
    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        if zones.is_empty() {
            self.api.probe().await?;
        }
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            checks.push(self.check_zone(zone).await?);
        }
        Ok(CheckReport::new(true, checks))
    }

    /// The public hosted zones of the account, all pages; with `hosted_zone_id`, that zone
    /// only. A name held by several public zones is listed once and not cached.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        if let Some(id) = &self.hosted_zone_id {
            let hz = self
                .api
                .hosted_zone(id)
                .await?
                .ok_or_else(|| config_error(OVERRIDE_MISSING))?;
            if hz.private {
                return Err(config_error(OVERRIDE_PRIVATE));
            }
            return Ok(hz
                .name
                .map(|name| {
                    self.zones.insert(&name, &hz.id);
                    ZoneInfo::new(name)
                })
                .into_iter()
                .collect());
        }
        let mut names: BTreeMap<DomainName, Vec<String>> = BTreeMap::new();
        for hz in self.api.all_zones().await? {
            if hz.private {
                continue;
            }
            if let Some(name) = hz.name {
                names.entry(name).or_default().push(hz.id);
            }
        }
        Ok(names
            .into_iter()
            .map(|(name, ids)| {
                if let [id] = ids.as_slice() {
                    self.zones.insert(&name, id);
                }
                ZoneInfo::new(name)
            })
            .collect())
    }

    /// Every rrset of the zone, all pages. Alias and routing-policy sets are reported in
    /// `skipped` (see the record-level module).
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

fn config_error(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`Route53::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Route53, Error> {
    Route53::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
