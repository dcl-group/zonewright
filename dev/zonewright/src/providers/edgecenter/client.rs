//! The EdgeCenter client: construction, `Debug` and the [`Provider`] implementation. The API,
//! the record content, the record layer and the value layer are shared with the Gcore client:
//! EdgeCenter's API is a fork of Gcore's (`providers::gcore_shared`). This module holds what is
//! EdgeCenter's own: the metadata, the configuration, the request spacing and the provider's
//! answers where the two specifications differ.

use std::fmt;

use reqwest::header::AUTHORIZATION;
use secrecy::{ExposeSecret as _, SecretString};

use crate::context::Context;
use crate::error::Error;
use crate::http::Http;
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::operation::Call;
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneInfo,
    ZoneListing,
};
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::{rrsets, values};

use super::super::gcore_shared::{Core, Flavor, error_message};
use super::config::{self, EdgeCenterConfig, EdgeCenterCredentials};

/// EdgeCenter's identity for the shared code.
static FLAVOR: Flavor = Flavor {
    provider: ProviderId::EdgeCenter,
    capabilities: &super::meta::META.capabilities,
};

/// The EdgeCenter DNS client (DNS API v2).
///
/// Authenticates with a permanent API token in `Authorization: APIKey <token>`, and spaces its
/// requests by `min_request_interval_ms` (the API allows 4 per second). The native unit
/// is the rrset, addressed by zone name, owner name and type, and replaced whole: record-level
/// writes and TXT value operations read the rrset and write it back, under the per-name lock of
/// the [`Context`]. A writer outside this process that changes the same rrset between that read
/// and that write can lose its change (`Preconditions::ReadThenWrite`,
/// `ValueGuarantee::ReadThenWrite`). An rrset that selects its answers per query (filters,
/// rrset metadata) is never written; disabled records and per-record metadata are kept.
///
/// The zone name is the key of every path, so there are no zone identifiers to cache.
pub struct EdgeCenter {
    config: EdgeCenterConfig,
    core: Core,
}

impl fmt::Debug for EdgeCenter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("EdgeCenter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl EdgeCenter {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: EdgeCenterConfig,
        credentials: EdgeCenterCredentials,
        ctx: &Context,
    ) -> Result<EdgeCenter, Error> {
        let settings = config.validate(ctx)?;
        let raw = credentials.api_token.expose_secret();
        let token = raw.trim();
        if token.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("api_token must not be empty"),
            });
        }
        // Source: the Swagger document, `securityDefinitions.APIKey` (`in: header`, `name:
        // Authorization`, "Authorization: APIKey eyJ0eXAiOiJKV"); the SDK client.go:23,53; lego
        // providers/dns/internal/gcore/internal/client.go (`tokenTypeHeader = "APIKey"`).
        let http = Http::builder(ctx, ProviderId::EdgeCenter)
            .endpoint(&settings.api)
            .auth_header("api_token", AUTHORIZATION, "APIKey ", token)
            // The token as given is registered too, whether or not it was trimmed.
            .secret(raw)
            .message(error_message)
            .pacing(settings.interval)
            .build()?;
        Ok(EdgeCenter {
            core: Core::new(
                &FLAVOR,
                http,
                settings.api,
                ctx.locks().clone(),
                settings.ttl,
            ),
            config,
        })
    }
}

impl Provider for EdgeCenter {
    fn id(&self) -> ProviderId {
        ProviderId::EdgeCenter
    }

    /// Reads one page of the zone listing, which exercises the token on every call, and looks
    /// every zone up afresh. A disabled zone is reported as found, with a remark.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        Call::check(zones.len())
            .observe(self, self.core.check(&zones))
            .await
    }

    /// Every zone of the account, all pages.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones()
            .observe(self, self.core.list_zones())
            .await
    }

    /// Every rrset of the zone, all pages, the provider's NS and SOA included. Rrsets of types
    /// outside the record-level type list are listed too; dynamic rrsets and what the model
    /// cannot hold are in `skipped`.
    async fn list_rrsets(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        Call::list_rrsets(zone)
            .observe(self, self.core.list_zone(zone))
            .await
    }

    async fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Option<RrSet>, Error> {
        Call::get_rrset(zone, name, rtype)
            .observe(self, rrsets::get_whole_set(&self.core, zone, name, rtype))
            .await
    }

    async fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> Result<SetOutcome, Error> {
        Call::set_rrset(zone, rrset)
            .observe(self, rrsets::set_whole_set(&self.core, zone, rrset, expect))
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
                rrsets::delete_whole_set(&self.core, zone, name, rtype, expect),
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
                values::add_whole_set(&self.core, zone, name, value, ttl),
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
                values::remove_whole_set(&self.core, zone, name, value),
            )
            .await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`EdgeCenter::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<EdgeCenter, Error> {
    EdgeCenter::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
