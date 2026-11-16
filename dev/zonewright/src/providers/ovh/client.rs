//! The OVHcloud client: construction, `Debug`, the publication of staged changes and the
//! [`Provider`] implementation.
//!
//! The module follows the layout of every provider module: `meta.rs` (static metadata),
//! `config.rs` (settings and credentials), `api.rs` (the HTTP API, the signature and the server
//! clock), `txt.rs` (the TXT value operations over one shape of the value layer), `records.rs`
//! (the record-level operations over one shape of the record layer, and the mapping of each
//! record type) and this file.
//!
//! The zone's name is the key of every path, so there are no zone identifiers to cache and none
//! to go stale.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::Future;
use std::sync::{Mutex, PoisonError};

use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::error::Error;
use crate::http::Http;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::name::DomainName;
use crate::operation::Call;
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneCheck,
    ZoneInfo, ZoneListing,
};
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};
use crate::{rrsets, values};

use super::api::{self, Api};
use super::config::{self, OvhConfig, OvhCredentials};
use super::records::Unstated;

/// The OVHcloud DNS client (the `/domain/zone` API, version 1.0).
///
/// Authenticates with an application key, an application secret and a consumer key: every
/// request carries the application key and the consumer key in headers and a signature over the
/// method, the full URL, the body and a timestamp, made with the application secret, which is
/// never sent. The timestamp follows the provider's clock: `/auth/time`, unauthenticated, is read
/// before the first signed request and again after an hour, and the time elapsed since a reading
/// is counted with a monotonic clock.
///
/// A `403` answer is [`Error::Forbidden`](crate::Error::Forbidden). At this provider it means a
/// missing permission or a consumer key that expired or was revoked (go-ovh README: "your
/// application should be prepared to receive 403 HTTP errors and prompt the user to
/// re-authenticate"); no error class documented by the sources tells the two apart. A consumer
/// key for unattended use should be created with unlimited validity.
///
/// The native unit is the individual record with an identifier: TXT value operations create one
/// record for the value being added and delete only the records that hold the value being
/// removed, under the per-name lock of the [`Context`] (`ValueGuarantee::PerValue`). Record-level
/// writes create the missing values first and delete the surplus records last; that is several
/// requests and not atomic, and a writer outside this process that changes the rrset between
/// the read and the writes is not detected (`Preconditions::ReadThenWrite`).
///
/// # Staged changes and the refresh
///
/// The API stages every record change; a change is served only after a refresh of the zone,
/// `POST /domain/zone/{zone}/refresh`, which publishes every staged change of the zone at once,
/// including changes staged by anyone else, and has no counterpart that discards them.
/// Everything below rests on two assumptions, neither documented nor observed against the live
/// API: that the record endpoints read the staged state, so that a change that is stored but
/// not published reads as present (the schema says only that a change "applies after the zone
/// is refreshed"); and that a refresh sent after the answer to a record write was received
/// publishes that write. The second is also what lego and the Terraform provider rely on: they
/// send the write, wait for its answer, then send the refresh. The rules:
///
/// - Every write operation that reaches the provider (sends at least one request about the
///   zone) ends with a refresh of the zone, whatever its outcome: also when it found nothing to
///   change (`AlreadyPresent`, `NotPresent`, `Unchanged`) and when it fails after its read
///   (`PreconditionFailed` included). What it read may be a change of an earlier operation, in
///   this or another process, whose refresh failed or never happened; the refresh publishes it,
///   so an operation that succeeds reports a published state, and a `PreconditionFailed` describes
///   one too once its refresh succeeded. A refresh is idempotent and is retried by the transport
///   like a read. It runs after the operation's name lock is released.
/// - When the refresh of an operation that succeeded fails, the operation fails with the
///   refresh's error, its text saying that the changes are stored but not published (where the
///   kind has a text: `RateLimited` has none). Nothing is undone. When the operation itself
///   failed, its own error is returned and the refresh's result is dropped.
/// - The client keeps, per zone and in this client only, the record writes it started that no
///   successful refresh has covered yet ("a refresh is owed"). While one is owed, every operation
///   in the zone refreshes: a write operation at its end on every exit, also one that fails before
///   any request; `get_rrset` and `list_rrsets` before they read, so that what they report is what
///   is served (a read that publishes is surprising; a read that reports as present a change no
///   name server serves is worse). If that refresh fails, the read fails with the refresh's error.
///   A write whose future was dropped after it was sent thus is published by the client's next
///   operation in the zone. A refresh sent while another record write of this client is in
///   flight does not cover that write: it stays owed until a refresh sent after it ended
///   succeeds. While writes of this client in the zone overlap without a gap, a refresh therefore
///   stays owed and every read in the zone refreshes first.
/// - A record write that ended without a certain outcome (no answer: a timeout or a connection
///   broken after it was established; a `5xx`; an answer that cannot be read; or its future
///   dropped while it was in flight) may still be applied by the provider later, also after the
///   refresh its own operation sends on its way out. Such a write stays owed until a second
///   refresh succeeds, sent after the first one succeeded: the client's next operation in the
///   zone refreshes once more. A write the provider refused, or one the transport is certain it
///   never sent, costs nothing extra.
///
/// What is not guaranteed: the mark lives in the client and is lost with it or with the process.
/// A change staged by a dropped future or a failed refresh and then forgotten that way is published
/// only by the next write operation in the zone that reaches the provider, in any process, or by
/// anyone else's refresh (the control panel's included); a read in another client does not
/// publish it and reports it as present. Publication of a refreshed zone by the name servers
/// takes a time the documentation does not state; the default propagation timeout is lego's. A
/// record write that ended without an answer (a timeout, a broken connection) or whose future was
/// dropped may still be applied by the provider later. If that happens after the second refresh
/// described above succeeded, no refresh of this client published it and the client owes
/// nothing: the client cannot see it. The next write operation in the zone publishes it.
///
/// # Reads
///
/// The record listing answers identifiers only, filtered by type and name with pattern matches;
/// every record is then read on its own. A read of a name with N records of the type costs
/// N + 1 requests; at the apex, and for a name with a backslash escape, the listing is filtered
/// by type only, so the read costs every record of that type in the zone plus one. A zone
/// listing costs the zone's records plus one. A read of more than 1000 records fails with
/// `Error::Protocol` instead of returning part of them. The type and name of every record are
/// compared exactly on the client's side. Reads report the staged state (see above).
pub struct Ovh {
    config: OvhConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new record.
    pub(super) ttl: u32,
    /// For a TXT rrset whose records state no TTL: the form they have, from the read of the
    /// operation that holds the name's lock, for the create that follows it.
    txt_unstated: Mutex<HashMap<(DomainName, DomainName), Unstated>>,
}

impl fmt::Debug for Ovh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret; the application key is sent in every request.
        f.debug_struct("Ovh")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Ovh {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: OvhConfig,
        credentials: OvhCredentials,
        ctx: &Context,
    ) -> Result<Ovh, Error> {
        let settings = config.validate(ctx)?;
        credentials.validate()?;
        let OvhCredentials {
            application_secret,
            consumer_key,
        } = credentials;
        let http = Http::builder(ctx, ProviderId::Ovh)
            .endpoint(&settings.api)
            // The consumer key goes in a header of its own with every signed request and is
            // registered with the scrubber; the application secret is never sent, and is
            // registered as well.
            .auth_header(
                "consumer_key",
                api::X_OVH_CONSUMER,
                "",
                consumer_key.expose_secret(),
            )
            .secret(application_secret.expose_secret())
            .message(api::error_message)
            .code(api::error_class)
            .build()?;
        Ok(Ovh {
            api: Api::new(
                http,
                settings.api,
                &settings.application_key,
                application_secret,
                consumer_key,
                settings.read_pause,
            )?,
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            txt_unstated: Mutex::new(HashMap::new()),
            config,
        })
    }

    /// Remembers how the TXT rrset at `name` states no TTL (`None`: it states one, or there is
    /// none). Called by the TXT read under the name's lock.
    pub(super) fn remember_unstated(
        &self,
        zone: &DomainName,
        name: &DomainName,
        unstated: Option<Unstated>,
    ) {
        let mut map = self
            .txt_unstated
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let key = (zone.clone(), name.clone());
        match unstated {
            Some(form) => {
                map.insert(key, form);
            }
            None => {
                map.remove(&key);
            }
        }
    }

    /// The form the last TXT read at `name` found.
    pub(super) fn unstated(&self, zone: &DomainName, name: &DomainName) -> Unstated {
        self.txt_unstated
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(zone.clone(), name.clone()))
            .copied()
            .unwrap_or_default()
    }

    /// Runs the write operation `work` in `zone` and publishes what is staged (see the type's
    /// documentation, "Staged changes and the refresh"): a refresh after success, after a
    /// failure once the operation reached the provider, and on every exit while a refresh is
    /// owed.
    async fn published<T>(
        &self,
        zone: &DomainName,
        work: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let before = self.api.contacts(zone);
        match work.await {
            Ok(outcome) => match self.api.refresh(zone).await {
                Ok(()) => Ok(outcome),
                Err(e) => Err(self.api.unpublished(e)),
            },
            Err(e) => {
                if self.api.contacts(zone) != before || self.api.owed(zone) {
                    // The operation's error is the result; a failed refresh leaves the mark,
                    // and the next operation in the zone refreshes again.
                    let _ = self.api.refresh(zone).await;
                }
                Err(e)
            }
        }
    }

    /// Runs the read `work` in `zone`, after a refresh when one is owed.
    async fn settled<T>(
        &self,
        zone: &DomainName,
        work: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        if self.api.owed(zone) {
            self.api
                .refresh(zone)
                .await
                .map_err(|e| self.api.unpublished(e))?;
        }
        work.await
    }
}

impl Provider for Ovh {
    fn id(&self) -> ProviderId {
        ProviderId::Ovh
    }

    /// Lists the account's zones, which exercises the credentials, and reports each zone as
    /// found when the listing holds it.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        Call::check(zones.len())
            .observe(self, async {
                let listed: BTreeSet<DomainName> = self
                    .api
                    .zones()
                    .await?
                    .iter()
                    .filter_map(|name| DomainName::parse(name).ok())
                    .collect();
                let checks = zones
                    .iter()
                    .map(|zone| ZoneCheck::new(zone.clone(), listed.contains(zone), None))
                    .collect();
                Ok(CheckReport::new(true, checks))
            })
            .await
    }

    /// Every zone of the account, in one answer.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones()
            .observe(self, async {
                let names: BTreeSet<DomainName> = self
                    .api
                    .zones()
                    .await?
                    .iter()
                    .filter_map(|name| DomainName::parse(name).ok())
                    .collect();
                Ok(names.into_iter().map(ZoneInfo::new).collect())
            })
            .await
    }

    /// Every record of the zone, read one by one, grouped into rrsets. Records of types outside
    /// the record-level type list are listed too. The listing reports the staged state; a
    /// refresh this client owes the zone is sent first.
    async fn list_rrsets(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        Call::list_rrsets(zone)
            .observe(self, self.settled(zone, self.list_zone(zone)))
            .await
    }

    /// The rrset as the record endpoints report it (the staged state); a refresh this client
    /// owes the zone is sent first.
    async fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Option<RrSet>, Error> {
        Call::get_rrset(zone, name, rtype)
            .observe(
                self,
                self.settled(zone, rrsets::get_per_record(self, zone, name, rtype)),
            )
            .await
    }

    async fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> Result<SetOutcome, Error> {
        Call::set_rrset(zone, rrset)
            .observe(
                self,
                self.published(zone, rrsets::set_per_record(self, zone, rrset, expect)),
            )
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
                self.published(
                    zone,
                    rrsets::delete_per_record(self, zone, name, rtype, expect),
                ),
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
            .observe(
                self,
                self.published(zone, values::add_per_record(self, zone, name, value, ttl)),
            )
            .await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        Call::remove_txt_value(zone, name)
            .observe(
                self,
                self.published(zone, values::remove_per_record(self, zone, name, value)),
            )
            .await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`Ovh::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Ovh, Error> {
    Ovh::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
