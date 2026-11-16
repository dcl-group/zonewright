//! The Google Cloud DNS client: construction, `Debug`, zone resolution and the [`Provider`]
//! implementation. The layout of the module is that of `yandex_cloud` (see its `client.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::crypto::{KeyError, Rs256Key};
use crate::error::Error;
use crate::http::{Http, ZoneCache, poll_interval};
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

use super::api::{self, Api, ManagedZone, Parts};
use super::config::{self, DEFAULT_POLL_MS, GoogleCloudConfig, GoogleCloudCredentials};

/// Why a zone is not found when the project holds it as a private (or forwarding, peering)
/// zone only.
const ONLY_PRIVATE: &str =
    "the project holds this zone only as a private, forwarding or peering managed zone";

/// Why a zone is not usable when the project holds two public managed zones of its name.
const AMBIGUOUS: &str = "the project holds more than one public managed zone of this name; set \
                         the one to use in managed_zones";

/// Why a zone with a configured managed zone is not found.
const CONFIGURED_MISSING: &str =
    "the managed zone configured in managed_zones for this zone was not found";

/// Why a configured managed zone is not usable.
const CONFIGURED_PRIVATE: &str = "the managed zone configured in managed_zones for this zone is \
                                  a private, forwarding or peering zone";

/// The Google Cloud DNS client.
///
/// Authenticates with a service account key: an RS256-signed JWT is exchanged for an access
/// token, which is sent as a bearer token and renewed before it expires. The native unit is the
/// rrset, addressed by name and type and changed through `changes.create`, whose deletions must
/// match the stored rrset exactly: a TXT value operation never overwrites another writer's
/// change, inside this process or outside it (`ValueGuarantee::Conditional`), and a record-level
/// write is conditional on the rrset it read (`Preconditions::Atomic`). A change that is still
/// pending is polled until it is done.
///
/// Zones are the public managed zones of the configured project, or the managed zones
/// configured by name. Managed zone identifiers are cached for the life of the client; a stale
/// one is detected and resolved again.
pub struct GoogleCloud {
    config: GoogleCloudConfig,
    /// The APIs.
    pub(super) api: Api,
    /// Zone name to managed zone identifier.
    pub(super) zones: ZoneCache,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
    /// Configured managed zones.
    configured: BTreeMap<DomainName, String>,
}

impl fmt::Debug for GoogleCloud {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("GoogleCloud")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl GoogleCloud {
    /// Builds the client. Validates the settings and the credentials, and parses the private
    /// key; makes no request.
    pub fn new(
        config: GoogleCloudConfig,
        credentials: GoogleCloudCredentials,
        ctx: &Context,
    ) -> Result<GoogleCloud, Error> {
        let settings = config.validate(ctx)?;
        let key = credentials.service_account_key;
        if key.client_email.expose_secret().is_empty() {
            return Err(config::config(
                "service_account_key.client_email must not be empty",
            ));
        }
        // The key's errors carry no input; each maps to a fixed text.
        let signing_key =
            Rs256Key::from_pem(key.private_key.expose_secret()).map_err(|e| match e {
                KeyError::UnsupportedKey => config::config(
                    "service_account_key.private_key is not an RSA private key of 2048 to 8192 \
                     bits",
                ),
                _ => config::config(
                    "service_account_key.private_key is not a PEM document with a PRIVATE KEY \
                     or RSA PRIVATE KEY section",
                ),
            })?;
        // The private key is not registered with the scrubber: it is never sent (design section
        // 5.5). The two identifiers are, and every signed JWT and issued token at run time.
        let mut builder = Http::builder(ctx, ProviderId::GoogleCloud)
            .endpoint(&settings.dns)
            .endpoint(&settings.token)
            .secret(key.client_email.expose_secret())
            .message(api::error_message)
            .code(api::error_code)
            .rate_limit(api::rate_limited);
        if let Some(id) = &key.private_key_id {
            builder = builder.secret(id.expose_secret());
        }
        let api = Api::new(Parts {
            http: builder.build()?,
            dns: settings.dns,
            token: settings.token,
            project: settings.project,
            key: signing_key,
            client_email: key.client_email,
            key_id: key.private_key_id,
            poll_interval: poll_interval(Some(config.change_poll_ms), DEFAULT_POLL_MS),
        });
        Ok(GoogleCloud {
            api,
            zones: ZoneCache::new(),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            configured: settings.zones,
            config,
        })
    }

    /// The zone's managed zone identifier, looked up afresh. A missing zone is
    /// `Error::ZoneNotFound`; a name held by more than one public managed zone is
    /// `Error::Config`.
    pub(super) async fn resolve_zone(&self, zone: &DomainName) -> Result<String, Error> {
        match self.find_zone(zone).await? {
            Lookup::Found(id) => Ok(id),
            Lookup::Missing(_) => Err(Error::zone_not_found(zone.clone())),
            Lookup::Ambiguous => Err(config::config(AMBIGUOUS)),
        }
    }

    /// Drops the cached identifier of `zone`.
    pub(super) fn forget_zone(&self, zone: &DomainName) {
        if let Some(id) = self.zones.get(zone) {
            self.zones.evict(zone, &id);
        }
    }

    /// Looks the zone up: by its configured managed zone, verified against its DNS name and
    /// visibility; otherwise among the managed zones of the project with that DNS name, where
    /// only a public one is used.
    // Source: https://www.googleapis.com/discovery/v1/apis/dns/v1/rest (`managedZones.list`
    // `dnsName`; `managedZones.get`); lego googlecloud.go:338-398 (an explicit zone ID read with
    // `ManagedZones.Get`; otherwise `ManagedZones.List(...).DnsName(authZone)` and the first
    // public zone). Up to five public zones can share a DNS name
    // (https://docs.cloud.google.com/dns/quotas); lego takes the first, the client takes none
    // and asks for `managed_zones` instead.
    async fn find_zone(&self, zone: &DomainName) -> Result<Lookup, Error> {
        if let Some(configured) = self.configured.get(zone) {
            return match self.api.managed_zone(configured).await? {
                Some(found) if dns_name(&found).as_ref() != Some(zone) => Err(config::config(
                    "a managed zone configured in managed_zones has another DNS name",
                )),
                Some(found) if !found.usable() => Ok(Lookup::Missing(Some(CONFIGURED_PRIVATE))),
                Some(found) => Ok(Lookup::Found(found.address()?)),
                None => Ok(Lookup::Missing(Some(CONFIGURED_MISSING))),
            };
        }
        let named = self.api.managed_zones(Some(zone.as_str())).await?;
        // The request asked for this DNS name: a zone of another name is an answer the client
        // cannot interpret.
        if named.iter().any(|z| dns_name(z).as_ref() != Some(zone)) {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered a managed zone lookup with a zone of another name",
                ),
            });
        }
        let usable: Vec<&ManagedZone> = named.iter().filter(|z| z.usable()).collect();
        match usable.as_slice() {
            [] if named.is_empty() => Ok(Lookup::Missing(None)),
            [] => Ok(Lookup::Missing(Some(ONLY_PRIVATE))),
            [only] => Ok(Lookup::Found(only.address()?)),
            _ => Ok(Lookup::Ambiguous),
        }
    }

    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        self.forget_zone(zone);
        Ok(match self.find_zone(zone).await? {
            Lookup::Found(id) => {
                self.zones.insert(zone, &id);
                ZoneCheck::new(zone.clone(), true, None)
            }
            Lookup::Missing(detail) => {
                ZoneCheck::new(zone.clone(), false, detail.map(Detail::constant))
            }
            Lookup::Ambiguous => {
                ZoneCheck::new(zone.clone(), false, Some(Detail::constant(AMBIGUOUS)))
            }
        })
    }
}

/// The DNS name of a managed zone, or `None` when it has none or it is not a valid name.
fn dns_name(zone: &ManagedZone) -> Option<DomainName> {
    zone.dns_name
        .as_deref()
        .and_then(|name| DomainName::parse(name).ok())
}

/// What a lookup by name found.
enum Lookup {
    Found(String),
    Missing(Option<&'static str>),
    Ambiguous,
}

impl Provider for GoogleCloud {
    fn id(&self) -> ProviderId {
        ProviderId::GoogleCloud
    }

    /// Exchanges a newly signed JWT for a new token (which verifies the key) and looks every
    /// zone up afresh.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        Call::check(zones.len())
            .observe(self, async {
                let zones = zones.as_slice();
                self.api.authenticate().await?;
                let mut checks = Vec::with_capacity(zones.len());
                for zone in zones {
                    checks.push(self.check_zone(zone).await?);
                }
                Ok(CheckReport::new(true, checks))
            })
            .await
    }

    /// The public managed zones of the project, all pages, and the zones of `managed_zones`
    /// whose managed zone matches their name. A name held by more than one public managed zone
    /// is listed once and not cached. The identifiers are cached.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones()
            .observe(self, async {
                let mut found: BTreeMap<DomainName, Vec<String>> = BTreeMap::new();
                for zone in self.api.managed_zones(None).await? {
                    if !zone.usable() {
                        continue;
                    }
                    let (Some(name), Ok(id)) = (dns_name(&zone), zone.address()) else {
                        continue;
                    };
                    found.entry(name).or_default().push(id);
                }
                for (name, configured) in &self.configured {
                    if let Some(zone) = self.api.managed_zone(configured).await?
                        && zone.usable()
                        && dns_name(&zone).as_ref() == Some(name)
                    {
                        // A configured managed zone is the one used, whatever else the project
                        // holds.
                        found.insert(name.clone(), vec![zone.address()?]);
                    }
                }
                let mut names = BTreeSet::new();
                for (name, ids) in found {
                    if let [id] = ids.as_slice() {
                        self.zones.insert(&name, id);
                    }
                    names.insert(name);
                }
                Ok(names.into_iter().map(ZoneInfo::new).collect())
            })
            .await
    }

    /// Every rrset of the zone, all pages. Rrsets of types outside the record-level type list
    /// are listed too; what the model cannot hold is in `skipped`.
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
            .observe(self, rrsets::get_whole_set(self, zone, name, rtype))
            .await
    }

    async fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> Result<SetOutcome, Error> {
        Call::set_rrset(zone, rrset)
            .observe(self, rrsets::set_whole_set(self, zone, rrset, expect))
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
                rrsets::delete_whole_set(self, zone, name, rtype, expect),
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
            .observe(self, values::add_whole_set(self, zone, name, value, ttl))
            .await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        Call::remove_txt_value(zone, name)
            .observe(self, values::remove_whole_set(self, zone, name, value))
            .await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`GoogleCloud::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<GoogleCloud, Error> {
    GoogleCloud::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
