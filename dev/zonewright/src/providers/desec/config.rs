//! Settings and credentials of the deSEC client (design section 2.8).
//!
//! The keys are a compatibility surface: applications persist them.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::record::{RrsetTtl, Ttl};
use crate::redact::Detail;

/// Default API endpoint.
// Source: https://desec.readthedocs.io/en/latest/dns/rrsets.html ("The relevant endpoints all
// reside under `/api/v1/domains/{name}/rrsets/`", with `https://desec.io/api/v1/...` in every
// example); the Go client lego uses, github.com/nrdcg/desec `desec.go` (`defaultBaseURL =
// "https://desec.io/api/v1/"`).
pub(super) const DEFAULT_BASE_URL: &str = "https://desec.io/api/v1";

/// TTL of a new rrset when the caller gives none.
// Source: https://desec.readthedocs.io/en/latest/dns/rrsets.html, field `ttl`: "This field is
// mandatory when creating an RRset. If you have no specific TTL in mind, 3600 seconds is a
// common choice." lego providers/dns/desec/desec.go (`defaultTTL int = 3600`).
pub(super) const DEFAULT_TTL: u32 = 3600;

/// TTL range the client accepts, in seconds. The upper bound is documented; the lower bound is
/// the zone's `minimum_ttl`, set by the server per domain ("Smallest TTL that can be used in an
/// RRset. The value is set automatically by the server",
/// https://desec.readthedocs.io/en/latest/dns/domains.html), so the client takes 1 and leaves the
/// zone's floor to the API, which refuses a lower TTL with `400`.
// Source for the maximum: rrsets.html, field `ttl`: "The maximum value is 86400 (one day)."
pub(super) const TTL_MIN: u32 = 1;
pub(super) const TTL_MAX: u32 = 86_400;

/// Settings of the deSEC client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct DesecConfig {
    /// TTL of a new rrset: 1 to 86400 seconds, default 3600. The zone's minimum TTL, which the
    /// provider sets per domain, also applies. An existing rrset keeps its own TTL.
    pub ttl: RrsetTtl,
    /// API endpoint; default `https://desec.io/api/v1`.
    pub base_url: String,
}

impl Default for DesecConfig {
    fn default() -> DesecConfig {
        DesecConfig {
            ttl: RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL)),
            base_url: DEFAULT_BASE_URL.to_owned(),
        }
    }
}

impl DesecConfig {
    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        let ttl = match self.ttl {
            RrsetTtl::Explicit(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl.as_secs()) => {
                ttl.as_secs()
            }
            RrsetTtl::Explicit(_) => return Err(config("ttl must be between 1 and 86400")),
            RrsetTtl::ProviderDefault => {
                return Err(config(
                    "ttl cannot be provider_default: the provider requires a TTL on every rrset",
                ));
            }
        };
        Ok(Settings {
            api: Endpoint::parse("base_url", &self.base_url, ctx)?,
            ttl,
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The API.
    pub(super) api: Endpoint,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
}

/// Credentials of the deSEC client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the token.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct DesecCredentials {
    /// An API token of the deSEC account. It may be scoped by token policies; it needs write
    /// permission for the rrsets the client changes.
    pub api_token: SecretString,
}

impl DesecCredentials {
    /// Credentials with the API token.
    #[must_use]
    pub fn new(api_token: SecretString) -> DesecCredentials {
        DesecCredentials { api_token }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<DesecConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<DesecCredentials, Error> {
    serde_json::from_str(text.expose_secret())
        .map_err(|_| config("the credentials must be a JSON object with the string key api_token"))
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
