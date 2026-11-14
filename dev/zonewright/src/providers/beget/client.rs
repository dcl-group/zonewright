//! The Beget client: construction, `Debug` and the [`Provider`] implementation.
//!
//! The module follows the layout of every provider module: `meta.rs` (static metadata),
//! `config.rs` (settings and credentials), `api.rs` (the HTTP API), `txt.rs` (the TXT value
//! operations over one shape of the value layer) and this file.
//!
//! A domain's name is the key of every call, so there are no zone identifiers to cache and none
//! to go stale.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;

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

use super::api::{self, Api};
use super::config::{self, BegetConfig, BegetCredentials};

/// The Beget DNS client (Beget.API).
///
/// Every call is a `POST` whose form body carries the login and the API password; neither is
/// ever put in a URL. The native unit is the TXT set of one name, replaced whole: TXT value
/// operations read the name, then write it back with the value added or removed, under the
/// per-name lock of the [`Context`]. A writer outside this process that changes the same name
/// between that read and that write can lose its change (`ValueGuarantee::ReadThenWrite`).
///
/// The write replaces the A, MX and TXT records of the name together, so a name that holds
/// any record besides TXT records (or a TXT record that cannot be written back as it is) is
/// refused with `Error::Rejected` for add and remove alike.
///
/// The API allows 60 requests a minute per user; the client spaces its requests by
/// `min_request_interval_ms`.
pub struct Beget {
    config: BegetConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new TXT value.
    pub(super) ttl: u32,
}

impl fmt::Debug for Beget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret, but the login is half of the credentials and is not shown.
        f.debug_struct("Beget")
            .field("base_url", &self.config.base_url)
            .field("ttl", &self.config.ttl)
            .finish_non_exhaustive()
    }
}

impl Beget {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: BegetConfig,
        credentials: BegetCredentials,
        ctx: &Context,
    ) -> Result<Beget, Error> {
        let settings = config.validate(ctx)?;
        let password = credentials.password.expose_secret();
        if password.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant("password must not be empty"),
            });
        }
        let mut http = Http::builder(ctx, ProviderId::Beget)
            .endpoint(&settings.api)
            // Both halves of the credentials are secrets for the scrubber: an API that quotes
            // the request in an error must not hand either back.
            .secret(&config.login)
            .secret(password)
            .message(api::error_message);
        if settings.interval_ms > 0 {
            http = http.pacing(Duration::from_millis(settings.interval_ms));
        }
        Ok(Beget {
            api: Api::new(
                http.build()?,
                settings.api,
                config.login.clone(),
                SecretString::from(password.to_owned()),
            ),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// One zone of a check: listed among the domains of the account, and served by Beget's name
    /// servers, which is what makes a change visible.
    async fn check_zone(
        &self,
        zone: &DomainName,
        domains: &BTreeSet<DomainName>,
    ) -> Result<ZoneCheck, Error> {
        if !domains.contains(zone) {
            return Ok(ZoneCheck::new(zone.clone(), false, None));
        }
        let result = match self.api.get_data(zone).await {
            Ok(result) => result,
            // The provider refuses to describe the domain: its reason is the detail.
            Err(Error::Rejected { detail, .. }) => {
                return Ok(ZoneCheck::new(zone.clone(), false, Some(detail)));
            }
            Err(e) => return Err(e),
        };
        // Source: the DNS page, `getData`: `is_beget_dns` ("домен на DNS-серверах BeGet",
        // 0 or 1).
        let served = match result.get("is_beget_dns") {
            Some(Value::Bool(flag)) => *flag,
            Some(Value::Number(n)) => n.as_i64() != Some(0),
            Some(Value::String(s)) => !matches!(s.trim(), "" | "0"),
            _ => {
                return Err(Error::Protocol {
                    detail: Detail::constant(
                        "the provider's domain answer does not say whether it serves the domain",
                    ),
                });
            }
        };
        let detail = (!served)
            .then(|| Detail::constant("the domain does not use the provider's name servers"));
        Ok(ZoneCheck::new(zone.clone(), served, detail))
    }
}

impl Provider for Beget {
    fn id(&self) -> ProviderId {
        ProviderId::Beget
    }

    /// Lists the account's domains, which exercises the credentials on every call even with no
    /// zone given, and reads every zone afresh.
    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let domains: BTreeSet<DomainName> = self.api.domains().await?.into_iter().collect();
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            checks.push(self.check_zone(zone, &domains).await?);
        }
        Ok(CheckReport::new(true, checks))
    }

    /// The domains of the account.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let names: BTreeSet<DomainName> = self.api.domains().await?.into_iter().collect();
        Ok(names.into_iter().map(ZoneInfo::new).collect())
    }

    async fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<Ttl>,
    ) -> Result<AddOutcome, Error> {
        values::add_whole_set(self, zone, name, value, ttl).await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        values::remove_whole_set(self, zone, name, value).await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`Beget::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Beget, Error> {
    Beget::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
