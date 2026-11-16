//! The Azure DNS client: construction, `Debug`, the zone checks and the [`Provider`]
//! implementation. The layout follows the provider modules described in the Selectel v2 client:
//! `api.rs` (the HTTP API and the token exchange), `content.rs` (record objects), `rrset.rs`
//! (the record set primitives), `records.rs` (the record layer and the listing), `txt.rs` (the
//! value layer) and this file.

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
use crate::{rrsets, values};

use super::api::{self, Api};
use super::config::{self, AzureDnsConfig, AzureDnsCredentials};

/// The Azure DNS client: public zones through Azure Resource Manager.
///
/// Authenticates as a service principal with a client secret: the OAuth 2.0 client credentials
/// grant at the Microsoft identity platform (`{login_url}/{tenant}/oauth2/v2.0/token`), and the
/// token as `Authorization: Bearer`. The token is cached and renewed before it expires.
/// Managed identity, workload identity federation and certificate credentials are not
/// supported.
///
/// The client sees the zones of one resource group of one subscription. The native unit is the
/// record set, addressed by zone, type and relative name, replaced whole by `PUT` and removed by
/// `DELETE`. Every write is conditional on what the client read: `If-Match` with the record
/// set's etag, or `If-None-Match: *` when there was none. A writer outside this process that
/// changes the record set in between makes the write fail; the operation reads again once, and
/// a second failure is `Error::Conflict` (`Preconditions::Atomic`,
/// `ValueGuarantee::Conditional`).
///
/// Azure Resource Manager throttles with `429` and `Retry-After`; it also answers `429` when
/// another operation holds the resource (`RetryableErrorDueToAnotherOperation`). A read is
/// repeated after a short wait; a write is not, and the operation ends with
/// `Error::RateLimited` carrying the wait.
pub struct AzureDns {
    config: AzureDnsConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
}

impl fmt::Debug for AzureDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("AzureDns")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl AzureDns {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: AzureDnsConfig,
        credentials: AzureDnsCredentials,
        ctx: &Context,
    ) -> Result<AzureDns, Error> {
        let settings = config.validate(ctx)?;
        let secret = credentials.client_secret.expose_secret();
        if secret.is_empty() {
            return Err(config::config("client_secret must not be empty"));
        }
        // Source: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
        // ("POST /{tenant}/oauth2/v2.0/token", on the host `login_url`).
        let token_url = settings
            .login
            .url()
            .segment(&config.tenant_id)
            .path("/oauth2/v2.0/token")
            .build()?;
        let http = Http::builder(ctx, ProviderId::AzureDns)
            .endpoint(&settings.management)
            .endpoint(&settings.login)
            // The secret travels in the form body of the token request only; an identity
            // platform or Resource Manager answer that repeats it is scrubbed.
            .secret(secret)
            .code(api::error_code)
            .build()?;
        let grant = api::grant(&config.client_id, &config.scope, &credentials.client_secret);
        Ok(AzureDns {
            api: Api::new(
                http,
                settings.management,
                config.subscription_id.clone(),
                config.resource_group.clone(),
                token_url,
                grant,
            ),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// `check`: a new token, which proves the credentials now, then the zone listing of the
    /// resource group, which proves the access to it.
    async fn check_zones(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        self.api.authenticate().await?;
        let held: BTreeSet<DomainName> = self.zone_names().await?;
        let checks = zones
            .iter()
            .map(|zone| ZoneCheck::new(zone.clone(), held.contains(zone), None))
            .collect();
        Ok(CheckReport::new(true, checks))
    }

    /// The public zones of the resource group. A name the crate cannot hold is left out.
    async fn zone_names(&self) -> Result<BTreeSet<DomainName>, Error> {
        Ok(self
            .api
            .zones()
            .await?
            .iter()
            .filter_map(|zone| DomainName::parse(&zone.name).ok())
            .collect())
    }

    async fn all_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Ok(self
            .zone_names()
            .await?
            .into_iter()
            .map(ZoneInfo::new)
            .collect())
    }
}

impl Provider for AzureDns {
    fn id(&self) -> ProviderId {
        ProviderId::AzureDns
    }

    /// Obtains a new token and lists the zones of the resource group. A principal that may
    /// read the zones passes; whether it may write is known only at the first write.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        Call::check(zones.len())
            .observe(self, self.check_zones(&zones))
            .await
    }

    /// Every public zone of the resource group, all pages.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones().observe(self, self.all_zones()).await
    }

    /// Every record set of the zone, all pages, the apex SOA and NS included. Alias record sets
    /// are in `skipped`.
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
/// [`AzureDns::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<AzureDns, Error> {
    AzureDns::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
