//! The nic.ru client: construction, `Debug`, zone resolution, the staged-change marks and the
//! commit, and the [`Provider`] implementation. The layout of a provider module is described in
//! the Selectel v2 client.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::PoisonError;
use std::time::Duration;

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

use super::State;
use super::api::{self, Api, Zone};
use super::config::{self, NicruConfig, NicruCredentials};
use super::txt::{FOREIGN_CHANGES, Op};

/// How many times a commit is tried before the operation gives up (design section 11.3).
const COMMIT_ATTEMPTS: u32 = 3;

/// Pause before commit attempt `n + 1`: `n` times this. The design fixes the number of
/// attempts, not their spacing; the pause is the client's own, shorter than the transport's
/// back-off because the commit is repeated by the operation, not by the transport.
const COMMIT_BACKOFF: Duration = Duration::from_millis(200);

/// Why a zone of a Secondary service cannot be used.
// Source: "API of DNS hosting" section 3.2.2 (`has-primary="false"` – Secondary service) and
// section 4, whose record calls are described "for DNS master services".
const ZONE_SECONDARY: &str =
    "the zone is placed under a Secondary service, whose records this client cannot change";

/// Why a zone listed under several DNS-master services cannot be used.
const ZONE_AMBIGUOUS: &str = "the zone is listed under more than one DNS-master service";

/// A warning about a usable zone with staged changes of this process.
const OWN_CHANGES: &str = "the zone has staged changes of this process that are not committed \
     yet; the next operation in the zone commits them";

/// The nic.ru (RU-CENTER) DNS hosting client.
///
/// Authenticates with the OAuth 2 password grant (the contract number and the account's
/// password, with the OAuth application's ID and secret) and sends the token as
/// `Authorization: Bearer`. The native unit is the individual record: TXT value operations
/// stage one record per value, or the deletion of the records that hold the value, by
/// identifier, so a request never names a foreign value (`ValueGuarantee::PerValue`).
///
/// Changes are staged until a commit, and a commit publishes every staged change of the zone,
/// including changes staged by anyone else. The client therefore refuses a zone that has staged
/// changes it did not make (`Error::Rejected`), holds a lock per zone in the [`Context`] for
/// the whole read, edit and commit, and remembers in the context which zones hold its own
/// staged changes, so that an operation interrupted before its commit is finished by the next
/// one. That memory lives in the process: after a restart, a zone left with this process's
/// staged changes has to be committed by hand, in the provider's control panel or with its
/// API.
///
/// The zone listing and the record listing each arrive in one answer, bounded by the
/// transport's 4 MiB limit. Zones are looked up afresh on every operation.
pub struct Nicru {
    config: NicruConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// The context, for the client's process-local state.
    ctx: Context,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
}

impl fmt::Debug for Nicru {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("Nicru")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Nicru {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: NicruConfig,
        credentials: NicruCredentials,
        ctx: &Context,
    ) -> Result<Nicru, Error> {
        let settings = config.validate(ctx)?;
        credentials.validate()?;
        let mut http = Http::builder(ctx, ProviderId::Nicru)
            .endpoint(&settings.api)
            .endpoint(&settings.token)
            .secret(credentials.password.expose_secret())
            .secret(credentials.client_id.expose_secret())
            .secret(credentials.client_secret.expose_secret())
            // Not a secret, but it travels in the token request with the others, and an echo
            // of it is withheld as well.
            .secret(&config.username)
            .message(api::error_message);
        if !settings.interval.is_zero() {
            http = http.pacing(settings.interval);
        }
        let grant = api::grant(
            &config.username,
            &config.scope,
            &credentials.password,
            &credentials.client_id,
            &credentials.client_secret,
        );
        Ok(Nicru {
            api: Api::new(http.build()?, settings.api, &settings.token, grant),
            locks: ctx.locks().clone(),
            ctx: ctx.clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// The process-local state of the nic.ru clients of the context.
    pub(super) fn state(&self) -> &State {
        self.ctx.nicru()
    }

    /// True when this process has marked `zone` as holding its staged changes.
    pub(super) fn is_marked(&self, zone: &DomainName) -> bool {
        self.state()
            .staged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(zone)
    }

    /// Marks `zone` as holding staged changes of this process.
    pub(super) fn mark(&self, zone: &DomainName) {
        self.state()
            .staged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(zone.clone());
    }

    /// Clears the mark of `zone`.
    pub(super) fn unmark(&self, zone: &DomainName) {
        self.state()
            .staged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(zone);
    }

    /// Commits `zone`, up to [`COMMIT_ATTEMPTS`] times, and clears its mark after a successful
    /// commit. When every attempt fails, the mark stays and the result is `Error::Transient`:
    /// the next operation in the zone commits the staged changes.
    pub(super) async fn commit_own(&self, zone: &DomainName, service: &str) -> Result<(), Error> {
        let mut last = None;
        for attempt in 0..COMMIT_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(COMMIT_BACKOFF * attempt).await;
            }
            match self.api.commit(service, zone).await {
                Ok(()) => {
                    self.unmark(zone);
                    return Ok(());
                }
                Err(e) => last = Some(e),
            }
        }
        let cause = last.map(|e| e.to_string()).unwrap_or_default();
        Err(Error::Transient {
            detail: self.api.detail(&format!(
                "the staged changes are not committed after three attempts; the next operation \
                 in the zone commits them ({cause})"
            )),
        })
    }

    /// After an edit failed, still under the zone lock: makes sure the mark of `zone` stays only
    /// while the zone holds staged changes of this process (design section 11.3, points b and
    /// c). Returns `Ok(true)` when the edit turned out to be staged and is now committed.
    ///
    /// - An edit that was certainly not applied stages nothing: the mark is cleared at once,
    ///   without looking at the zone, so that a foreign edit staged meanwhile is not committed.
    /// - Otherwise the zone is listed again. Without staged changes, nothing of ours is
    ///   pending and the mark is cleared. With staged changes, they are taken to be this edit
    ///   and committed: when this operation read the zone under the zone lock it had no staged
    ///   changes (or only ours, which it committed first), every edit of this process in the
    ///   zone happens under that lock, and earlier edits of this operation were each committed
    ///   before the next one. A writer outside the process that stages an edit between this
    ///   operation's read and this commit is not detected; that window is the same as the one
    ///   between a successful edit and its commit, which no API call can close.
    /// - If the zone cannot be listed again, the mark stays: the next operation then commits a
    ///   staged edit of ours, or clears the mark on a clean zone.
    pub(super) async fn settle_failed_edit(
        &self,
        zone: &DomainName,
        service: &str,
        refused: bool,
    ) -> Result<bool, Error> {
        if refused {
            self.unmark(zone);
            return Ok(false);
        }
        let zones = self.api.zones().await?;
        let Lookup::Found(found) = lookup(zones, zone) else {
            return Ok(false);
        };
        if !found.has_changes {
            self.unmark(zone);
            return Ok(false);
        }
        self.commit_own(zone, service).await?;
        Ok(true)
    }

    /// The zone to write to, looked up afresh. A missing zone is `Error::ZoneNotFound`; a zone
    /// of a Secondary service, or one listed under several DNS-master services, is
    /// `Error::Rejected`.
    pub(super) async fn resolve_zone(&self, zone: &DomainName) -> Result<Zone, Error> {
        let zones = self.api.zones().await?;
        match lookup(zones, zone) {
            Lookup::Found(found) => Ok(found),
            Lookup::Missing => Err(Error::zone_not_found(zone.clone())),
            Lookup::Secondary => Err(rejected(ZONE_SECONDARY)),
            Lookup::Ambiguous => Err(rejected(ZONE_AMBIGUOUS)),
        }
    }

    fn check_zone(&self, zones: &[Zone], zone: &DomainName) -> ZoneCheck {
        match lookup(zones.to_vec(), zone) {
            Lookup::Found(found) if found.has_changes => {
                let detail = if self.is_marked(zone) {
                    OWN_CHANGES
                } else {
                    FOREIGN_CHANGES
                };
                ZoneCheck::new(zone.clone(), true, Some(Detail::constant(detail)))
            }
            Lookup::Found(_) => ZoneCheck::new(zone.clone(), true, None),
            Lookup::Missing => ZoneCheck::new(zone.clone(), false, None),
            Lookup::Secondary => {
                ZoneCheck::new(zone.clone(), false, Some(Detail::constant(ZONE_SECONDARY)))
            }
            Lookup::Ambiguous => {
                ZoneCheck::new(zone.clone(), false, Some(Detail::constant(ZONE_AMBIGUOUS)))
            }
        }
    }
}

/// What a lookup by name found.
enum Lookup {
    Found(Zone),
    Missing,
    Secondary,
    Ambiguous,
}

/// The zone named `zone` among `zones`: the one of a DNS-master service. The listing covers
/// every service of the contract, so a name can appear more than once.
fn lookup(zones: Vec<Zone>, zone: &DomainName) -> Lookup {
    let named: Vec<Zone> = zones
        .into_iter()
        .filter(|z| z.name.as_ref() == Some(zone))
        .collect();
    let any = !named.is_empty();
    let mut primary = named.into_iter().filter(|z| z.primary);
    match (primary.next(), primary.next()) {
        (Some(found), None) => Lookup::Found(found),
        (Some(_), Some(_)) => Lookup::Ambiguous,
        (None, _) if any => Lookup::Secondary,
        (None, _) => Lookup::Missing,
    }
}

fn rejected(text: &'static str) -> Error {
    Error::Rejected {
        status: None,
        detail: Detail::constant(text),
    }
}

impl Provider for Nicru {
    fn id(&self) -> ProviderId {
        ProviderId::Nicru
    }

    /// Exchanges the credentials for a new token, even when one is cached, and lists the zones
    /// once. A zone with staged changes is reported as found, with a detail that says whose
    /// they are as far as this process knows.
    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        self.api.authenticate().await?;
        let listed = self.api.zones().await?;
        let checks = zones
            .iter()
            .map(|zone| self.check_zone(&listed, zone))
            .collect();
        Ok(CheckReport::new(true, checks))
    }

    /// Every zone of a DNS-master service of the contract, each name once.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let names: BTreeSet<DomainName> = self
            .api
            .zones()
            .await?
            .into_iter()
            .filter(|z| z.primary)
            .filter_map(|z| z.name)
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
        values::add_per_record(&Op::new(self), zone, name, value, ttl).await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        values::remove_per_record(&Op::new(self), zone, name, value).await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`Nicru::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Nicru, Error> {
    Nicru::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
