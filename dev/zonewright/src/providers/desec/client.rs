//! The deSEC client: construction, `Debug`, the zone checks and the [`Provider`] implementation.
//! The layout follows the provider modules described in the Selectel v2 client: `api.rs` (the
//! HTTP API), `rrset.rs` (the rrset primitives), `records.rs` (record content, the record layer
//! and the listing), `txt.rs` (the value layer) and this file.

use std::collections::BTreeSet;
use std::fmt;

use reqwest::header::AUTHORIZATION;
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
use super::config::{self, DesecConfig, DesecCredentials};

/// The deSEC DNS API client.
///
/// Authenticates with an API token in `Authorization: Token <token>`. The native unit is the
/// rrset, addressed by domain, subname and type, and replaced whole: record-level writes and TXT
/// value operations read the rrset and write it back, under the per-name lock of the
/// [`Context`]. A writer outside this process that changes the same rrset between that read and
/// that write can lose its change (`Preconditions::ReadThenWrite`,
/// `ValueGuarantee::ReadThenWrite`).
///
/// The provider limits writes to 2 per second and 15 per minute per domain, and reads to 10 per
/// second and 50 per minute per account; a throttled request is answered `429` with
/// `Retry-After`. A read is repeated after a short wait; a write is not, and the operation ends
/// with `Error::RateLimited` carrying the wait.
///
/// The zone name is the key of every path, so there are no zone identifiers to cache.
pub struct Desec {
    config: DesecConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
}

impl fmt::Debug for Desec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("Desec")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Desec {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: DesecConfig,
        credentials: DesecCredentials,
        ctx: &Context,
    ) -> Result<Desec, Error> {
        let settings = config.validate(ctx)?;
        let raw = credentials.api_token.expose_secret();
        let token = raw.trim();
        if token.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("api_token must not be empty"),
            });
        }
        // Source: https://desec.readthedocs.io/en/latest/auth/tokens.html (`--header
        // "Authorization: Token mu4W4MHuSc0Hy-GD1h_dnKuZBond"`); nrdcg `desec.go`
        // (`fmt.Sprintf("Token %s", …)`).
        let http = Http::builder(ctx, ProviderId::Desec)
            .endpoint(&settings.api)
            .auth_header("api_token", AUTHORIZATION, "Token ", token)
            // The token as given is registered too, whether or not it was trimmed.
            .secret(raw)
            .message(api::error_message)
            .build()?;
        Ok(Desec {
            api: Api::new(http, settings.api),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// `check`: reads the first page of the domain listing, which verifies the token on every
    /// call, then looks every zone up afresh.
    async fn check_zones(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        self.api.probe().await?;
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            let found = self.api.zone(zone).await?.is_some();
            checks.push(ZoneCheck::new(zone.clone(), found, None));
        }
        Ok(CheckReport::new(true, checks))
    }

    /// `list_zones`: every domain of the account, all pages. A name the crate cannot hold is
    /// left out.
    async fn all_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let names: BTreeSet<DomainName> = self
            .api
            .zones()
            .await?
            .iter()
            .filter_map(|zone| DomainName::parse(&zone.name).ok())
            .collect();
        Ok(names.into_iter().map(ZoneInfo::new).collect())
    }
}

impl Provider for Desec {
    fn id(&self) -> ProviderId {
        ProviderId::Desec
    }

    /// Reads the first page of the domain listing, which verifies the token, and looks every
    /// zone up afresh. A token restricted by policies passes as long as it may read; whether it
    /// may write is known only at the first write.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        Call::check(zones.len())
            .observe(self, self.check_zones(&zones))
            .await
    }

    /// Every domain of the account, all pages.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones().observe(self, self.all_zones()).await
    }

    /// Every rrset of the zone, all pages, the apex NS included. The SOA rrset is not part of
    /// it: the API does not show it. Rrsets of types outside the record-level type list are
    /// listed too; what the model cannot hold is in `skipped`.
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
/// [`Desec::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Desec, Error> {
    Desec::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
