//! The Yandex 360 client: construction, `Debug` and the [`Provider`] implementation.
//!
//! The module follows the layout of every provider module: `meta.rs` (static metadata),
//! `config.rs` (settings and credentials), `api.rs` (the HTTP API), `txt.rs` (the TXT value
//! operations over one shape of the value layer), `records.rs` (the record-level operations over
//! one shape of the record layer) and this file.
//!
//! The domain's name is the key of every path, so there are no zone identifiers to cache and
//! none to go stale.

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
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneCheck,
    ZoneInfo, ZoneListing,
};
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::{rrsets, values};

use super::api::{self, Api, Domain};
use super::config::{self, Yandex360Config, Yandex360Credentials};

/// The Yandex 360 DNS client (`DomainDNSService` of API 360).
///
/// Authenticates with the OAuth token of an application, sent as `Authorization: OAuth`. The
/// native unit is the individual record with an identifier: TXT value operations create one
/// record for the value being added and delete only the records that hold the value being
/// removed, under the per-name lock of the [`Context`]. Values of other writers are never part
/// of a request (`ValueGuarantee::PerValue`); a writer outside this process can at worst cause
/// a duplicate of our own value.
///
/// The record-level operations work on the same records: replacing an rrset creates the missing
/// records before it deletes the surplus ones, after a read and without a condition the provider
/// checks. They cover A, AAAA, CAA, CNAME, MX, SRV and TXT.
///
/// Only domains delegated to Yandex name servers can be managed through the API: `list_zones`
/// leaves the others out, and `check` reports them as not found, with a detail saying why.
///
/// A listing is read in full, page by page, before anything is written; the answer of a
/// listing that ends before the total it states is `Error::Protocol`.
pub struct Yandex360 {
    config: Yandex360Config,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new record.
    pub(super) ttl: u32,
}

impl fmt::Debug for Yandex360 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("Yandex360")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Yandex360 {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: Yandex360Config,
        credentials: Yandex360Credentials,
        ctx: &Context,
    ) -> Result<Yandex360, Error> {
        let settings = config.validate(ctx)?;
        let raw = credentials.oauth_token.expose_secret();
        let token = raw.trim();
        if token.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("oauth_token must not be empty"),
            });
        }
        let http = Http::builder(ctx, ProviderId::Yandex360)
            .endpoint(&settings.api)
            // Source: https://yandex.ru/dev/api360/doc/ru/access.md: the token type "OAuth"
            // precedes the token in `Authorization`; Bearer is not documented.
            .auth_header("oauth_token", AUTHORIZATION, "OAuth ", token)
            // The token as given is registered too, whether or not it was trimmed.
            .secret(raw)
            .message(api::error_message)
            .code(api::error_code)
            .build()?;
        Ok(Yandex360 {
            api: Api::new(http, settings.api, settings.org_id),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// What `check` says about one zone, given the organization's domains.
    async fn check_zone(&self, zone: &DomainName, domains: &[Domain]) -> Result<ZoneCheck, Error> {
        let stated = domains
            .iter()
            .find(|domain| DomainName::parse(&domain.name).as_ref() == Ok(zone));
        Ok(match stated {
            None => ZoneCheck::new(zone.clone(), false, None),
            Some(domain) if !domain.delegated => ZoneCheck::new(
                zone.clone(),
                false,
                Some(Detail::constant(
                    "the domain is not delegated to Yandex name servers, so its DNS records \
                     cannot be managed through the API",
                )),
            ),
            // The records are read too: the scope of the domain list says nothing about the
            // scope that manages DNS.
            Some(_) => ZoneCheck::new(zone.clone(), self.api.probe(zone).await?, None),
        })
    }
}

impl Provider for Yandex360 {
    fn id(&self) -> ProviderId {
        ProviderId::Yandex360
    }

    /// Reads the organization's domains, which exercises the token on every call, then reads
    /// the records of every given zone that is delegated.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        let zones = zones.as_slice();
        let domains = self.api.domains().await?;
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            checks.push(self.check_zone(zone, &domains).await?);
        }
        Ok(CheckReport::new(true, checks))
    }

    /// The domains of the organization that are delegated to Yandex, all pages.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let names: BTreeSet<DomainName> = self
            .api
            .domains()
            .await?
            .iter()
            .filter(|domain| domain.delegated)
            .filter_map(|domain| DomainName::parse(&domain.name).ok())
            .collect();
        Ok(names.into_iter().map(ZoneInfo::new).collect())
    }

    /// Every record of the domain, all pages, grouped into rrsets. Records of types outside the
    /// record-level type list are reported too (NS among them, as skipped sets).
    async fn list_rrsets(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        self.list_zone(zone).await
    }

    async fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Option<RrSet>, Error> {
        rrsets::get_per_record(self, zone, name, rtype).await
    }

    async fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> Result<SetOutcome, Error> {
        rrsets::set_per_record(self, zone, rrset, expect).await
    }

    async fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        expect: Expect<'_>,
    ) -> Result<DeleteOutcome, Error> {
        rrsets::delete_per_record(self, zone, name, rtype, expect).await
    }

    async fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<RrsetTtl>,
    ) -> Result<AddOutcome, Error> {
        // The apex is not written (see `txt.rs`). A request that does not fit the provider is
        // refused before any request (design section 3.1, check 4); the root and wildcard zones
        // are left to the value layer's own check 2.
        if name == zone && !zone.is_root() && !zone.is_wildcard() {
            return Err(super::txt::apex_not_written());
        }
        values::add_per_record(self, zone, name, value, ttl).await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        values::remove_per_record(self, zone, name, value).await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`Yandex360::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Yandex360, Error> {
    Yandex360::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
