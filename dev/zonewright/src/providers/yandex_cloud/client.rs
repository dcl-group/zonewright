//! The Yandex Cloud client: construction, `Debug`, zone resolution and the [`Provider`]
//! implementation. The layout of the module is that of `selectel_v2` (see its `client.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::crypto::{KeyError, Ps256Key};
use crate::error::Error;
use crate::http::{Http, ZoneCache, path_id, poll_interval};
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

use super::api::{self, Api, Endpoints};
use super::config::{self, DEFAULT_POLL_MS, YandexCloudConfig, YandexCloudCredentials};

/// Why a zone is not found when the folder holds it as a private zone only.
const ONLY_PRIVATE: &str = "the folder holds this zone as a private zone only";

/// Why a zone is not usable when the folder holds two public zones of its name.
const AMBIGUOUS: &str =
    "the folder holds more than one public zone of this name; set its ID in zone_ids";

/// Why a zone with a configured ID is not found.
const CONFIGURED_MISSING: &str = "the zone ID configured in zone_ids for this zone was not found";

/// Why a zone is not found without a folder.
const NOT_CONFIGURED: &str = "the zone is not in zone_ids, and no folder_id is configured";

/// The Yandex Cloud DNS client.
///
/// Authenticates with a service account's authorized key: a PS256-signed JWT is exchanged for an
/// IAM token, which is sent as a bearer token and renewed every 50 minutes at the latest. The
/// native unit is the record set, addressed by name and type and changed with the provider's
/// strict call, which refuses a write when the set changed after the client read it: a TXT
/// value operation never overwrites another writer's change, inside this process or outside it
/// (`ValueGuarantee::Conditional`), and a record-level write is conditional on the set it read
/// (`Preconditions::Atomic`). Writes complete through a provider-side operation that the client
/// polls.
///
/// Zones are the public zones of the configured folder, or the zones whose IDs are configured.
/// Zone identifiers are cached for the life of the client; a stale one is detected and resolved
/// again.
pub struct YandexCloud {
    config: YandexCloudConfig,
    /// The APIs.
    pub(super) api: Api,
    /// Zone name to zone identifier.
    pub(super) zones: ZoneCache,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
    /// The folder whose public zones are looked up.
    folder: Option<String>,
    /// Configured zone IDs.
    configured: BTreeMap<DomainName, String>,
}

impl fmt::Debug for YandexCloud {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("YandexCloud")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl YandexCloud {
    /// Builds the client. Validates the settings and the credentials, and parses the private
    /// key; makes no request.
    pub fn new(
        config: YandexCloudConfig,
        credentials: YandexCloudCredentials,
        ctx: &Context,
    ) -> Result<YandexCloud, Error> {
        let settings = config.validate(ctx)?;
        let key = credentials.authorized_key;
        if key.id.expose_secret().is_empty() {
            return Err(config::config("authorized_key.id must not be empty"));
        }
        if key.service_account_id.expose_secret().is_empty() {
            return Err(config::config(
                "authorized_key.service_account_id must not be empty",
            ));
        }
        // The key's errors carry no input; each maps to a fixed text.
        let signing_key =
            Ps256Key::from_pem(key.private_key.expose_secret()).map_err(|e| match e {
                KeyError::UnsupportedKey => config::config(
                    "authorized_key.private_key is not an RSA private key of 2048 to 8192 bits",
                ),
                _ => config::config(
                    "authorized_key.private_key is not a PEM document with a PRIVATE KEY or RSA \
                     PRIVATE KEY section",
                ),
            })?;
        // The private key is not registered with the scrubber: it is never sent (design section
        // 5.5). The two identifiers are, and every signed JWT and issued token at run time.
        let http = Http::builder(ctx, ProviderId::YandexCloud)
            .endpoint(&settings.dns)
            .endpoint(&settings.iam)
            .endpoint(&settings.operation)
            .secret(key.id.expose_secret())
            .secret(key.service_account_id.expose_secret())
            .message(api::error_message)
            .code(api::error_code)
            .build()?;
        let api = Api::new(
            http,
            Endpoints {
                dns: settings.dns,
                iam: settings.iam,
                operation: settings.operation,
            },
            signing_key,
            key.id,
            key.service_account_id,
            poll_interval(Some(config.operation_poll_ms), DEFAULT_POLL_MS),
        );
        Ok(YandexCloud {
            api,
            zones: ZoneCache::new(),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            folder: settings.folder,
            configured: settings.zones,
            config,
        })
    }

    /// The zone's identifier, looked up afresh. A missing zone is `Error::ZoneNotFound`; a name
    /// held by more than one public zone of the folder is `Error::Config`.
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

    /// Looks the zone up (design section 11.3): by its configured ID, verified against its name;
    /// otherwise among the zones of the folder, where only a public zone of that name is used.
    // Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/list (`zone`, the DNS suffix;
    // `publicVisibility` and `privateVisibility`); lego yandexcloud.go:126-130 compares
    // `zone.GetZone()` with the absolute zone name.
    async fn find_zone(&self, zone: &DomainName) -> Result<Lookup, Error> {
        if let Some(id) = self.configured.get(zone) {
            return match self.api.zone(id).await? {
                Some(found) if found.zone_name().as_ref() == Some(zone) => {
                    Ok(Lookup::Found(id.clone()))
                }
                Some(_) => Err(config::config(
                    "a zone ID configured in zone_ids belongs to a zone of another name",
                )),
                None => Ok(Lookup::Missing(Some(CONFIGURED_MISSING))),
            };
        }
        let Some(folder) = &self.folder else {
            return Ok(Lookup::Missing(Some(NOT_CONFIGURED)));
        };
        let named: Vec<api::Zone> = self
            .api
            .zones(folder)
            .await?
            .into_iter()
            .filter(|z| z.zone_name().as_ref() == Some(zone))
            .collect();
        let public: Vec<&api::Zone> = named.iter().filter(|z| z.is_public()).collect();
        match public.as_slice() {
            [] if named.is_empty() => Ok(Lookup::Missing(None)),
            [] => Ok(Lookup::Missing(Some(ONLY_PRIVATE))),
            [only] => Ok(Lookup::Found(path_id(&only.id)?.to_owned())),
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

/// What a lookup by name found.
enum Lookup {
    Found(String),
    Missing(Option<&'static str>),
    Ambiguous,
}

impl Provider for YandexCloud {
    fn id(&self) -> ProviderId {
        ProviderId::YandexCloud
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

    /// The public zones of the folder, all pages, and the zones of `zone_ids` whose ID matches
    /// their name. A name held by more than one public zone of the folder is listed once and not
    /// cached. The identifiers are cached.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones()
            .observe(self, async {
                let mut found: BTreeMap<DomainName, Vec<String>> = BTreeMap::new();
                if let Some(folder) = &self.folder {
                    for zone in self.api.zones(folder).await? {
                        if !zone.is_public() {
                            continue;
                        }
                        let (Some(name), Ok(id)) = (zone.zone_name(), path_id(&zone.id)) else {
                            continue;
                        };
                        found.entry(name).or_default().push(id.to_owned());
                    }
                }
                for (name, id) in &self.configured {
                    if let Some(zone) = self.api.zone(id).await?
                        && zone.zone_name().as_ref() == Some(name)
                    {
                        // A configured ID is the one used, whatever the folder holds.
                        found.insert(name.clone(), vec![id.clone()]);
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

    /// Every record set of the zone, all pages. Record sets of types outside the record-level
    /// type list are listed too; what the model cannot hold is in `skipped`.
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
/// [`YandexCloud::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<YandexCloud, Error> {
    YandexCloud::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
