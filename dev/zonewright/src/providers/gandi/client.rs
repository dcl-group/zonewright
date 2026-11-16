//! The Gandi client: construction, `Debug`, `check`, `list_zones` and the [`Provider`]
//! implementation. The API is in `api.rs`, the rrset primitives in `rrset.rs`, the value forms in
//! `content.rs`, the record layer in `records.rs` and the value layer in `txt.rs`.

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
use super::config::{self, GandiConfig, GandiCredentials};

/// The Gandi LiveDNS client (API v5).
///
/// Authenticates with a personal access token in `Authorization: Bearer <token>`. The native
/// unit is the rrset, addressed by domain, owner name and type. The TXT value operations add and
/// remove single values with the API's value-level `PATCH`, so they never write a foreign value
/// (`ValueGuarantee::PerValue`). Record-level writes read the rrset and create it or replace it
/// whole in one request, under the per-name lock of the [`Context`]; the API checks no condition,
/// so a writer outside this process that changes the same rrset between that read and that write
/// can lose its change (`Preconditions::ReadThenWrite`).
///
/// The zone name is the key of every path, so there are no zone identifiers to cache.
pub struct Gandi {
    config: GandiConfig,
    pub(super) api: Api,
    pub(super) locks: NameLocks,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
    sharing_id: Option<String>,
}

impl fmt::Debug for Gandi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("Gandi")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Gandi {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: GandiConfig,
        credentials: GandiCredentials,
        ctx: &Context,
    ) -> Result<Gandi, Error> {
        let settings = config.validate(ctx)?;
        let raw = credentials.personal_access_token.expose_secret();
        let token = raw.trim();
        if token.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("personal_access_token must not be empty"),
            });
        }
        // Source: the LiveDNS API reference, header `Authorization`: "must start with Bearer for
        // access token" ("Example: Bearer pat_abc-123"); the authentication page
        // <https://api.gandi.net/docs/authentication/> ("Authorization: Bearer abc"); lego
        // internal/client.go:137 (`"Bearer "+c.pat`).
        let http = Http::builder(ctx, ProviderId::Gandi)
            .endpoint(&settings.api)
            .bearer("personal_access_token", token)
            // The token as given is registered too, whether or not it was trimmed.
            .secret(raw)
            .message(api::error_message)
            .code(api::error_code)
            .build()?;
        Ok(Gandi {
            api: Api::new(http, settings.api),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            sharing_id: settings.sharing_id,
            config,
        })
    }

    /// `check`: one page of the domain listing, which exercises the token on every call, then
    /// every zone looked up afresh.
    async fn check_zones(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        self.api.probe(self.sharing_id.as_deref()).await?;
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            let found = self.api.domain(zone).await?.is_some();
            checks.push(ZoneCheck::new(zone.clone(), found, None));
        }
        Ok(CheckReport::new(true, checks))
    }

    /// `list_zones`: every domain of the listing, all pages. A name the crate cannot hold is
    /// left out.
    async fn zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let names: BTreeSet<DomainName> = self
            .api
            .domains(self.sharing_id.as_deref())
            .await?
            .iter()
            .filter_map(|domain| domain.fqdn.as_deref())
            .filter_map(|fqdn| DomainName::parse(fqdn).ok())
            .collect();
        Ok(names.into_iter().map(ZoneInfo::new).collect())
    }
}

impl Provider for Gandi {
    fn id(&self) -> ProviderId {
        ProviderId::Gandi
    }

    /// Reads one page of the domain listing, which exercises the token on every call, and looks
    /// every zone up afresh.
    ///
    /// A token that is wrong, expired or without the needed permission is `Error::Forbidden`, not
    /// `Error::Auth`: the reference answers a bearer token that "has expired, does not have
    /// enought permission or does not exists" with `403` (its `401` is "a wrong API Key", the
    /// deprecated scheme), and the two cases cannot be told apart.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        Call::check(zones.len())
            .observe(self, self.check_zones(&zones))
            .await
    }

    /// Every domain of the listing, all pages: the personal organization's, or with the
    /// `sharing_id` setting that organization's.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones().observe(self, self.zones()).await
    }

    /// Every rrset of the zone, all pages. Rrsets of types outside the record-level type list
    /// are listed too; what the model cannot hold is in `skipped`.
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
            .observe(self, values::add_value_calls(self, zone, name, value, ttl))
            .await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        Call::remove_txt_value(zone, name)
            .observe(self, values::remove_value_calls(self, zone, name, value))
            .await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`Gandi::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Gandi, Error> {
    Gandi::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
