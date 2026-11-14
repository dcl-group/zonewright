//! The Hetzner client: construction, `Debug`, zone resolution and the [`Provider`]
//! implementation. The layout of a provider module is described in the Selectel v2 client.
//!
//! Zone identifiers are cached for the life of the client; a stale one is detected and resolved
//! again (design section 3.8). Only zones in primary mode can be read or changed.

use std::collections::BTreeSet;
use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::error::Error;
use crate::http::{Http, Poller, ZoneCache};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::name::DomainName;
use crate::provider::{AddOutcome, CheckReport, Provider, RemoveOutcome, ZoneCheck, ZoneInfo};
use crate::record::{Ttl, Txt};
use crate::redact::Detail;
use crate::values;

use super::api::{self, Api, PRIMARY};
use super::config::{self, ACTION_POLLS, HetznerConfig, HetznerCredentials};

/// Why a zone that exists cannot be used.
const NOT_PRIMARY: &str = "the zone is not in primary mode; only primary zones can be read or \
                           changed through the API (incorrect_zone_mode)";

/// The Hetzner DNS client (Hetzner Cloud API, zones and RRSets).
///
/// Authenticates with a project API token in `Authorization: Bearer`. The native unit is the
/// rrset with value-level actions: TXT value operations ask the API to add one value to an
/// rrset or to remove the values that equal ours, spelled as the API returned them. Values of
/// other writers are never part of a request (`ValueGuarantee::PerValue`); a writer outside this
/// process can at worst cause a duplicate of our own value. Writes are actions the API completes
/// asynchronously: the operation returns after the action has finished.
///
/// Zone identifiers are cached for the life of the client; a stale one is detected and
/// resolved again.
pub struct Hetzner {
    config: HetznerConfig,
    /// The API.
    pub(super) api: Api,
    /// Zone name to zone identifier.
    pub(super) zones: ZoneCache,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
    /// How a running action is waited for.
    pub(super) poller: Poller,
}

impl fmt::Debug for Hetzner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("Hetzner")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// What a lookup of a zone by name found.
enum Lookup {
    Found(String),
    Missing,
    Secondary,
}

impl Hetzner {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: HetznerConfig,
        credentials: HetznerCredentials,
        ctx: &Context,
    ) -> Result<Hetzner, Error> {
        let settings = config.validate(ctx)?;
        let raw = credentials.api_token.expose_secret();
        let token = raw.trim();
        if token.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("api_token must not be empty"),
            });
        }
        let http = Http::builder(ctx, ProviderId::Hetzner)
            .endpoint(&settings.api)
            // The token as given is registered too, whether or not it was trimmed.
            .secret(raw)
            .bearer("api_token", token)
            .message(api::error_message)
            .build()?;
        Ok(Hetzner {
            api: Api::new(http, settings.api),
            zones: ZoneCache::new(),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            poller: Poller::new(settings.poll, ACTION_POLLS),
            config,
        })
    }

    /// Looks the zone up by name. The answer must be about the zone asked for.
    async fn lookup_zone(&self, zone: &DomainName) -> Result<Lookup, Error> {
        let Some(found) = self.api.zone(zone).await? else {
            return Ok(Lookup::Missing);
        };
        if DomainName::parse(&found.name).as_ref() != Ok(zone) {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered with a zone other than the one asked for",
                ),
            });
        }
        if found.mode != PRIMARY {
            return Ok(Lookup::Secondary);
        }
        Ok(Lookup::Found(found.id.to_string()))
    }

    /// The zone's identifier, looked up afresh. A missing zone is `Error::ZoneNotFound`, one in
    /// secondary mode `Error::Rejected` with the status the API uses for it.
    pub(super) async fn resolve_zone(&self, zone: &DomainName) -> Result<String, Error> {
        match self.lookup_zone(zone).await? {
            Lookup::Found(id) => Ok(id),
            Lookup::Missing => Err(Error::zone_not_found(zone.clone())),
            // Source: the reference, Zone RRSets, "Operation specific errors": `422`
            // `incorrect_zone_mode`.
            Lookup::Secondary => Err(Error::Rejected {
                status: Some(422),
                detail: Detail::constant(NOT_PRIMARY),
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

    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        self.forget_zone(zone);
        Ok(match self.lookup_zone(zone).await? {
            Lookup::Found(id) => {
                self.zones.insert(zone, &id);
                ZoneCheck::new(zone.clone(), true, None)
            }
            Lookup::Missing => ZoneCheck::new(zone.clone(), false, None),
            Lookup::Secondary => {
                ZoneCheck::new(zone.clone(), false, Some(Detail::constant(NOT_PRIMARY)))
            }
        })
    }
}

impl Provider for Hetzner {
    fn id(&self) -> ProviderId {
        ProviderId::Hetzner
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

    /// Every zone in primary mode, all pages. The identifiers are cached.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let mut names = BTreeSet::new();
        for zone in self.api.primary_zones().await? {
            if zone.mode != PRIMARY {
                continue;
            }
            let Ok(name) = DomainName::parse(&zone.name) else {
                continue;
            };
            self.zones.insert(&name, &zone.id.to_string());
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
        values::add_value_calls(self, zone, name, value, ttl).await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        values::remove_value_calls(self, zone, name, value).await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`Hetzner::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Hetzner, Error> {
    Hetzner::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use zonewright_mock::hetzner::{HetznerMock, Seed};

    use super::*;
    use crate::context::ContextOptions;
    use crate::error::ErrorKind;
    use crate::record::Txt;

    /// The number of looks at a running action is bounded: an action that never finishes ends
    /// the operation with `Transient` after the last look, and the write is not repeated. The
    /// bound of the client is [`ACTION_POLLS`]; the test lowers it so that it does not wait
    /// minutes.
    #[tokio::test]
    async fn an_action_that_keeps_running_is_transient_after_the_last_look() {
        let mock = HetznerMock::start(Seed::standard()).await;
        mock.control().set_action_looks(u32::MAX);
        let ctx = Context::new(ContextOptions {
            loopback_only: true,
            ..ContextOptions::default()
        })
        .unwrap();
        let config = HetznerConfig {
            base_url: mock.base_url(),
            ..HetznerConfig::default()
        };
        let credentials = HetznerCredentials::new(SecretString::from("test-only-token".to_owned()));
        let mut client = Hetzner::new(config, credentials, &ctx).unwrap();
        assert_eq!(ACTION_POLLS, 120);
        client.poller = Poller::new(Duration::from_millis(250), 3);
        let zone = DomainName::parse("example.org").unwrap();
        let name = DomainName::parse("_acme-challenge.example.org").unwrap();
        let value = Txt::new("v1").unwrap();
        let e = client
            .add_txt_value(&zone, &name, &value, None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
        assert_eq!(mock.log().count(Some("GET"), "/v1/actions/*"), 3);
        assert_eq!(
            mock.log()
                .count(Some("POST"), "/v1/zones/*/rrsets/*/TXT/actions/add_records"),
            1
        );
    }
}
