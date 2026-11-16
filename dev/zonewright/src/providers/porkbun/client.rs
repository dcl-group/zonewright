//! The Porkbun client: construction, `Debug` and the [`Provider`] implementation.
//!
//! The module follows the layout of every provider module: `meta.rs` (static metadata),
//! `config.rs` (settings and credentials), `api.rs` (the HTTP API), `txt.rs` (the TXT value
//! operations over one shape of the value layer), `records.rs` (the record-level operations over
//! one shape of the record layer, and the mapping of each record type) and this file.
//!
//! The domain's name is the key of every path, so there are no zone identifiers to cache and
//! none to go stale.

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
use super::config::{self, PorkbunConfig, PorkbunCredentials};

/// The Porkbun DNS client (API v3).
///
/// Authenticates with the API key and the secret API key: as the headers `X-API-Key` and
/// `X-Secret-API-Key` on the reads (`GET`), as `apikey` and `secretapikey` in the JSON body of
/// the writes (`POST`), as the provider documents each. The native unit is the
/// individual record with an identifier: TXT value operations create one record for the value
/// being added and delete only the records that hold the value being removed, under the
/// per-name lock of the [`Context`]. Values of other writers are never part of a request
/// (`ValueGuarantee::PerValue`); a writer outside this process can at worst cause a duplicate of
/// our own value, which the provider refuses.
///
/// Record-level writes work on the same records: a replacement creates the missing values first
/// and deletes the surplus records last, so the name never loses all its values; it is several
/// requests and not atomic (`atomic_rrset_write` is false), and a writer outside this process
/// that changes the rrset between the read and the writes is not detected
/// (`Preconditions::ReadThenWrite`).
///
/// Every domain must be opted in to API access by the account holder; a domain that is not is
/// reported by `check` as not usable, and every operation on it fails with `Error::Forbidden`.
pub struct Porkbun {
    config: PorkbunConfig,
    /// The API.
    pub(super) api: Api,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of a new record.
    pub(super) ttl: u32,
}

impl fmt::Debug for Porkbun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("Porkbun")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Porkbun {
    /// Builds the client. Validates the settings and the credentials; makes no request.
    pub fn new(
        config: PorkbunConfig,
        credentials: PorkbunCredentials,
        ctx: &Context,
    ) -> Result<Porkbun, Error> {
        let settings = config.validate(ctx)?;
        let raw_key = credentials.api_key.expose_secret();
        let raw_secret = credentials.secret_api_key.expose_secret();
        let (key, secret) = (raw_key.trim(), raw_secret.trim());
        if key.is_empty() {
            return Err(config::config("api_key must not be empty"));
        }
        if secret.is_empty() {
            return Err(config::config("secret_api_key must not be empty"));
        }
        let http = Http::builder(ctx, ProviderId::Porkbun)
            .endpoint(&settings.api)
            .auth_header("secret_api_key", api::SECRET_KEY_HEADER, "", secret)
            // Both keys are secrets of the scrubber, as given and as sent: an answer that
            // quotes the request must not hand either back.
            .secret(raw_secret)
            .secret(key)
            .secret(raw_key)
            .message(api::error_message)
            .code(api::error_code)
            .rate_limit(api::throttled)
            .build()?;
        let api = Api::new(http, settings.api, key, secret).ok_or_else(|| {
            config::config("api_key contains a character that cannot be sent in an HTTP header")
        })?;
        Ok(Porkbun {
            api,
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// One zone of `check`: found when the account has the domain and it is opted in to API
    /// access.
    // Source: the spec (`api.rs`), `DomainListAllResponse.domains[].apiAccess` and `notLocal`;
    // "Error codes", `API_ACCESS_DISABLED`; the description of the DNS operations: a write to a
    // domain "delegated to any other DNS provider" succeeds but "do[es] not change what
    // resolves".
    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        let Some(domain) = self.api.domain(zone).await? else {
            return Ok(ZoneCheck::new(zone.clone(), false, None));
        };
        if domain.api_access() == Some(false) {
            return Ok(ZoneCheck::new(
                zone.clone(),
                false,
                Some(Detail::constant(
                    "the domain is not opted in to API access; the account holder turns it on \
                     at the provider",
                )),
            ));
        }
        let detail = (domain.not_local() == Some(true)).then(|| {
            Detail::constant(
                "the domain is delegated to name servers the provider does not operate: changes \
                 are stored but not published",
            )
        });
        Ok(ZoneCheck::new(zone.clone(), true, detail))
    }
}

impl Provider for Porkbun {
    fn id(&self) -> ProviderId {
        ProviderId::Porkbun
    }

    /// Pings with the keys, which exercises them on every call, and looks every zone up afresh.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        Call::check(zones.len())
            .observe(self, async {
                let zones = zones.as_slice();
                self.api.ping().await?;
                let mut checks = Vec::with_capacity(zones.len());
                for zone in zones {
                    checks.push(self.check_zone(zone).await?);
                }
                Ok(CheckReport::new(true, checks))
            })
            .await
    }

    /// Every domain of the account, all pages, whether or not it is opted in to API access.
    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones()
            .observe(self, async {
                let names: BTreeSet<DomainName> = self
                    .api
                    .domains()
                    .await?
                    .iter()
                    .filter_map(|domain| DomainName::parse(&domain.domain).ok())
                    .collect();
                Ok(names.into_iter().map(ZoneInfo::new).collect())
            })
            .await
    }

    /// Every record of the domain, grouped into rrsets. Records of types outside the
    /// record-level type list are listed too; SOA and the provider's default NS records are not
    /// part of the API's listing.
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
/// [`Porkbun::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Porkbun, Error> {
    Porkbun::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
