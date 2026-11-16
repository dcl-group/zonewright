//! The DNSimple client: construction, `Debug` and the [`Provider`] implementation.
//!
//! The module follows the layout of every provider module: `meta.rs` (static metadata),
//! `config.rs` (settings and credentials), `api.rs` (the HTTP API and the account identifier),
//! `txt.rs` (the TXT value operations over one shape of the value layer), `records.rs` (the
//! record-level operations over one shape of the record layer, and the mapping of each record
//! type) and this file.
//!
//! Every path starts with the account identifier. It comes from the settings, or for an account
//! token from `GET /whoami` on the first call that needs it; it is kept for the client's life,
//! since the account of a token does not change. The zone's name is the key of every path
//! below it, so there are no zone identifiers to cache and none to go stale.

use std::collections::BTreeSet;
use std::fmt;

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
use crate::redact::Detail;
use crate::{rrsets, values};

use super::api::{self, Api};
use super::config::{self, DnsimpleConfig, DnsimpleCredentials};

/// The DNSimple DNS client (API v2).
///
/// Authenticates with an API access token sent as `Authorization: Bearer`. An account token is
/// enough on its own; a user token, which can reach several accounts, needs `account_id` in the
/// settings. The native unit is the individual record with an identifier: TXT value operations
/// create one record for the value being added and delete only the records that hold the value
/// being removed, under the per-name lock of the [`Context`]. Values of other writers are never
/// part of a request (`ValueGuarantee::PerValue`); a writer outside this process can at worst
/// cause a duplicate of our own value.
///
/// Record-level writes work on the same records: a replacement creates the missing values first
/// and deletes the surplus records last, so the name never loses all its values; it is several
/// requests and not atomic (`atomic_rrset_write` is false), and a writer outside this process
/// that changes the rrset between the read and the writes is not detected
/// (`Preconditions::ReadThenWrite`). Records the provider marks as system records are never
/// changed or deleted, and a name whose records are limited to some regions is refused.
///
/// A listing of records is read in full, page by page, before anything is written; a listing
/// whose pages do not add up to the totals it states is `Error::Protocol`.
pub struct Dnsimple {
    config: DnsimpleConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new record.
    pub(super) ttl: u32,
}

impl fmt::Debug for Dnsimple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("Dnsimple")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Dnsimple {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: DnsimpleConfig,
        credentials: DnsimpleCredentials,
        ctx: &Context,
    ) -> Result<Dnsimple, Error> {
        let settings = config.validate(ctx)?;
        let raw = credentials.api_token.expose_secret();
        let token = raw.trim();
        if token.is_empty() {
            return Err(config::config("api_token must not be empty"));
        }
        let http = Http::builder(ctx, ProviderId::Dnsimple)
            .endpoint(&settings.api)
            .bearer("api_token", token)
            // The token as given is registered too, whether or not it was trimmed.
            .secret(raw)
            .message(api::error_message)
            // Source: Overview, "Rate limiting": an exceeded hourly quota is answered 429
            // `{"message":"quota exceeded"}` with `X-RateLimit-Reset`, "The time at which the
            // current rate limit window in Unix time format", and no `Retry-After`; the block
            // after failed authentications sends `Retry-After`, which the transport reads first.
            .rate_reset_unix("x-ratelimit-reset")
            .build()?;
        Ok(Dnsimple {
            api: Api::new(http, settings.api, settings.account_id),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        let Some(found) = self.api.zone(zone).await? else {
            return Ok(ZoneCheck::new(zone.clone(), false, None));
        };
        // The answer must be about the zone asked for; a missing name is accepted, the path
        // named the zone.
        if let Some(stated) = &found.name
            && DomainName::parse(stated).as_ref() != Ok(zone)
        {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered with a zone other than the one asked for",
                ),
            });
        }
        // Source: OpenAPI `Zone`: `active`, "If false, DNS services are disabled and DNS records
        // will not be resolved"; `secondary`, "Returns true for a secondary zone". Whether the
        // records of a secondary zone can be changed through the API is not documented; the
        // zone is reported as found, with the warning.
        let detail = if found.active == Some(false) {
            Some(Detail::constant(
                "DNS services are disabled for the zone: its records are not resolved",
            ))
        } else if found.secondary == Some(true) {
            Some(Detail::constant(
                "a secondary zone: its records come from the primary name servers",
            ))
        } else {
            None
        };
        Ok(ZoneCheck::new(zone.clone(), true, detail))
    }
}

impl Provider for Dnsimple {
    fn id(&self) -> ProviderId {
        ProviderId::Dnsimple
    }

    /// Reads the token's identity, which exercises the token on every call, checks the account
    /// against it, and looks every zone up afresh.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        Call::check(zones.len())
            .observe(self, async {
                let zones = zones.as_slice();
                let identity = self.api.whoami().await?;
                self.api.adopt(identity)?;
                let mut checks = Vec::with_capacity(zones.len());
                for zone in zones {
                    checks.push(self.check_zone(zone).await?);
                }
                Ok(CheckReport::new(true, checks))
            })
            .await
    }

    /// Every zone of the account, all pages.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones()
            .observe(self, async {
                let names: BTreeSet<DomainName> = self
                    .api
                    .zones()
                    .await?
                    .iter()
                    .filter_map(|zone| zone.name.as_deref())
                    .filter_map(|name| DomainName::parse(name).ok())
                    .collect();
                Ok(names.into_iter().map(ZoneInfo::new).collect())
            })
            .await
    }

    /// Every record of the zone, all pages, grouped into rrsets. Records of types outside the
    /// record-level type list are listed too.
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
            .observe(self, rrsets::set_per_record(self, zone, rrset, expect))
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
                rrsets::delete_per_record(self, zone, name, rtype, expect),
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
            .observe(self, values::add_per_record(self, zone, name, value, ttl))
            .await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        Call::remove_txt_value(zone, name)
            .observe(self, values::remove_per_record(self, zone, name, value))
            .await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`Dnsimple::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Dnsimple, Error> {
    Dnsimple::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
