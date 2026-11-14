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
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneCheck,
    ZoneInfo, ZoneListing,
};
use crate::record::{RecordType, RrSet, Ttl, Txt};
use crate::redact::Detail;
use crate::{rrsets, values};

use super::api::{self, Api, Zone};
use super::config::{self, NicruConfig, NicruCredentials};
use super::records::RecordOp;
use super::txt::{FOREIGN_CHANGES, Op};
use super::{Pending, State};

/// How many times a commit is tried before the operation gives up (design section 11.3). A
/// rollback is tried as often.
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
     yet; the next operation in the zone commits them or, if they belong to a record-level \
     operation that did not finish, rolls them back";

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
/// staged changes has to be committed or rolled back by hand, in the provider's control panel
/// or with its API.
///
/// The record-level operations stage every edit of one operation (records to create, the
/// deletions of records to remove) and publish them with one commit, so the published rrset
/// changes in one step; an operation that fails before its commit has its staged edits rolled
/// back, and a zone with staged changes is not read, since its record listing could show them
/// as published. The API has no edit call: a TTL change stages each record again.
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

    /// What this process has marked `zone` for: `None` when it holds no staged changes of
    /// this process.
    pub(super) fn pending(&self, zone: &DomainName) -> Option<Pending> {
        self.state()
            .staged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(zone)
            .copied()
    }

    /// True when this process has marked `zone` as holding its staged changes.
    pub(super) fn is_marked(&self, zone: &DomainName) -> bool {
        self.pending(zone).is_some()
    }

    /// Marks `zone` as holding staged changes of this process that make up a complete change,
    /// to be committed by the next operation if this one does not.
    pub(super) fn mark(&self, zone: &DomainName) {
        self.mark_for(zone, Pending::Commit);
    }

    /// Marks `zone` as holding staged changes of this process, to be treated as `pending`.
    pub(super) fn mark_for(&self, zone: &DomainName, pending: Pending) {
        self.state()
            .staged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(zone.clone(), pending);
    }

    /// Clears the mark of `zone`.
    pub(super) fn unmark(&self, zone: &DomainName) {
        self.state()
            .staged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(zone);
    }

    /// Before an operation edits `zone`, under the zone lock: a zone without staged changes has
    /// its mark cleared (nothing of ours can be pending there, and a stale mark must not later
    /// make a foreign edit look like ours); staged changes this process did not make are
    /// `Error::Rejected`; staged changes of this process left by an earlier operation are
    /// committed or rolled back, as their mark says (design section 11.3, points b and c).
    pub(super) async fn settle_leftovers(
        &self,
        zone: &DomainName,
        target: &Zone,
    ) -> Result<(), Error> {
        if !target.has_changes {
            self.unmark(zone);
            return Ok(());
        }
        match self.pending(zone) {
            None => Err(rejected(FOREIGN_CHANGES)),
            Some(Pending::Commit) => self.commit_own(zone, &target.service).await,
            Some(Pending::Rollback) => self.rollback_own(zone, &target.service).await,
        }
    }

    /// Commits `zone`, up to [`COMMIT_ATTEMPTS`] times, and clears its mark after a successful
    /// commit. When every attempt fails, the result is `Error::Transient`, and the zone is
    /// listed once more: an attempt may have been applied with its answer lost, so a zone
    /// without staged changes has its mark cleared (nothing of ours is pending, and a foreign
    /// edit staged later must not be committed as ours). With staged changes, or when the
    /// listing fails, the mark stays and the next operation in the zone commits them.
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
        if let Ok(zones) = self.api.zones().await
            && let Lookup::Found(found) = lookup(zones, zone)
            && !found.has_changes
        {
            self.unmark(zone);
        }
        let cause = last.map(|e| e.to_string()).unwrap_or_default();
        Err(Error::Transient {
            detail: self.api.detail(&format!(
                "the staged changes are not committed after three attempts; the next operation \
                 in the zone commits them ({cause})"
            )),
        })
    }

    /// Rolls `zone` back, up to [`COMMIT_ATTEMPTS`] times, and clears its mark after a
    /// successful rollback. When every attempt fails, the zone is marked for a rollback and the
    /// result is `Error::Transient`: the next operation in the zone rolls the staged changes
    /// back before it does anything else.
    pub(super) async fn rollback_own(&self, zone: &DomainName, service: &str) -> Result<(), Error> {
        let mut last = None;
        for attempt in 0..COMMIT_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(COMMIT_BACKOFF * attempt).await;
            }
            match self.api.rollback(service, zone).await {
                Ok(()) => {
                    self.unmark(zone);
                    return Ok(());
                }
                Err(e) => last = Some(e),
            }
        }
        self.mark_for(zone, Pending::Rollback);
        let cause = last.map(|e| e.to_string()).unwrap_or_default();
        Err(Error::Transient {
            detail: self.api.detail(&format!(
                "the staged changes of an unfinished operation are not rolled back after three \
                 attempts; the next operation in the zone rolls them back ({cause})"
            )),
        })
    }

    /// After a record-level operation failed with some of its edits possibly staged, still
    /// under the zone lock: its edits are discarded, never published (a commit would publish
    /// a half-applied replacement). The zone is listed again; without staged changes nothing
    /// was staged and the mark is cleared, with staged changes the zone is rolled back. A
    /// rollback discards every staged change of the zone: when this operation read the zone it
    /// had none but ours, which it settled first, and every edit of this process in the zone
    /// happens under the zone lock; a writer outside the process that stages an edit between
    /// this operation's read and the rollback loses that edit, the same window as the one
    /// before a commit. If the zone cannot be listed again the mark stays, and the next
    /// operation rolls back.
    pub(super) async fn discard_own(&self, zone: &DomainName, service: &str) -> Result<(), Error> {
        let zones = self.api.zones().await?;
        let Lookup::Found(found) = lookup(zones, zone) else {
            return Ok(());
        };
        if !found.has_changes {
            self.unmark(zone);
            return Ok(());
        }
        self.rollback_own(zone, service).await
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

pub(super) fn rejected(text: &'static str) -> Error {
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

    /// Every record of the zone. Staged changes this process left behind are committed or
    /// rolled back first, as their mark says; refused (`Error::Rejected`) while the zone has
    /// other staged changes: the listing would show them as if they were published.
    async fn list_rrsets(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        self.list_zone(zone).await
    }

    /// Settles this process's own staged changes first and refuses (`Error::Rejected`) a zone
    /// with other staged changes, as `list_rrsets`.
    async fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Option<RrSet>, Error> {
        rrsets::get_per_record(&RecordOp::reading(self), zone, name, rtype).await
    }

    /// Stages every edit of the replacement, then publishes them with one commit; an operation
    /// that fails before its commit has its staged edits rolled back.
    async fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> Result<SetOutcome, Error> {
        let op = RecordOp::writing(self);
        let result = rrsets::set_per_record(&op, zone, rrset, expect).await;
        op.finish(zone, result).await
    }

    /// Stages the deletion of every record of the rrset, then publishes them with one commit; an
    /// operation that fails before its commit has its staged edits rolled back.
    async fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        expect: Expect<'_>,
    ) -> Result<DeleteOutcome, Error> {
        let op = RecordOp::writing(self);
        let result = rrsets::delete_per_record(&op, zone, name, rtype, expect).await;
        op.finish(zone, result).await
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
