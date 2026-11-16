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

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;

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

/// The OVHcloud DNS client (the `/domain/zone` API, version 1.0).
///
/// Authenticates with an application key, an application secret and a consumer key: every
/// request carries the application key and the consumer key in headers and a signature over the
/// method, the full URL, the body and a timestamp, made with the application secret, which is
/// never sent. The timestamp follows the provider's clock: the difference to the local clock is
/// read once per client from `/auth/time`, unauthenticated, before the first signed request.
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
/// including changes staged by anyone else, and has no counterpart that discards them. The
/// record listing shows the staged state. The client therefore:
///
/// - ends every write operation that succeeds with a refresh of the zone, also when the
///   operation found nothing to change (`AlreadyPresent`, `NotPresent`, `Unchanged`): the value
///   it found may be a change of an earlier operation whose refresh did not happen, in this or
///   another process, and the operation's success means that the state it reports is published.
///   A refresh is idempotent and is retried by the transport like a read;
/// - when the refresh fails, returns its error, stating that the record changes are stored but
///   not published. Nothing is undone: the staged changes stay and are published by the next
///   refresh of the zone, which the repeat of the operation sends;
/// - when a write operation fails after it sent a record write (a replacement that failed
///   part-way, a write whose outcome is unknown), refreshes the zone too, so that what the record
///   listing shows and what is published do not drift apart, and returns the operation's error.
///   An operation that fails before any record write sends no refresh.
///
/// Publication of a refreshed zone by the name servers takes a time the documentation does not
/// state; the default propagation timeout is lego's.
///
/// # Reads
///
/// The record listing answers identifiers only, filtered by type and name with pattern matches;
/// every record is then read on its own, so a read of a name with N records costs N + 1 requests
/// and a zone listing as many as the zone has records plus one. A read of more than 1000 records
/// fails with `Error::Protocol` instead of returning part of them. The type and name of every
/// record are compared exactly on the client's side.
pub struct Ovh {
    config: OvhConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new record.
    pub(super) ttl: u32,
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
            )?,
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// Runs the write operation `work` in `zone` and publishes its changes: a refresh after
    /// success, and after a failure that came after a record write (see the type's
    /// documentation, "Staged changes and the refresh").
    async fn published<T>(
        &self,
        zone: &DomainName,
        work: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let before = self.api.writes(zone);
        match work.await {
            Ok(outcome) => match self.api.refresh(zone).await {
                Ok(()) => Ok(outcome),
                Err(e) => Err(self.api.unpublished(e)),
            },
            Err(e) => {
                if self.api.writes(zone) != before {
                    // The operation's error is the result; a failed refresh changes nothing
                    // about it, and the next operation's refresh publishes what is staged.
                    let _ = self.api.refresh(zone).await;
                }
                Err(e)
            }
        }
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
    /// the record-level type list are listed too. The listing shows staged changes that no
    /// refresh has published yet.
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
            .observe(self, rrsets::get_per_record(self, zone, name, rtype))
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
