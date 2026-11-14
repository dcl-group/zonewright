//! Settings and credentials of the Cloudflare client (design sections 2.8 and 11.3).
//!
//! The keys are those of the earlier TXT-only implementation, minus its propagation timeout
//! (an application setting now). They are a compatibility surface: applications persist them.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::redact::Detail;

/// Default API endpoint.
// Source: https://developers.cloudflare.com/api/ (the API's base is
// `https://api.cloudflare.com/client/v4`, as in the documentation's curl examples) and lego
// providers/dns/cloudflare/internal/client.go (`defaultBaseURL`, line 25).
pub(super) const DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4";

/// TTL of a new rrset when the caller gives none: lego's minimum and default
/// (providers/dns/cloudflare/cloudflare.go, `minTTL = 120`).
pub(super) const DEFAULT_TTL: u32 = 120;

/// The TTL value the API defines as "automatic".
// Source: the API schema of a record's `ttl` (https://developers.cloudflare.com/api/resources/
// dns/subresources/records/methods/create/): "Setting to 1 means 'automatic'. Value must be
// between 60 and 86400, with the minimum reduced to 30 for Enterprise zones."
pub(super) const TTL_AUTOMATIC: u32 = 1;

/// Range of an explicit TTL, in seconds. The Enterprise minimum of 30 is not offered: the
/// client cannot tell the plan of a zone.
pub(super) const TTL_MIN: u32 = 60;
pub(super) const TTL_MAX: u32 = 86_400;

/// Settings of the Cloudflare client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct CloudflareConfig {
    /// API endpoint; default `https://api.cloudflare.com/client/v4`.
    pub base_url: String,
    /// TTL of a new record, in seconds: `1` (automatic) or 60 to 86400, default 120.
    pub ttl: u32,
}

impl Default for CloudflareConfig {
    fn default() -> CloudflareConfig {
        CloudflareConfig {
            base_url: DEFAULT_BASE_URL.to_owned(),
            ttl: DEFAULT_TTL,
        }
    }
}

impl CloudflareConfig {
    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        if self.ttl != TTL_AUTOMATIC && !(TTL_MIN..=TTL_MAX).contains(&self.ttl) {
            return Err(config("ttl must be 1 (automatic) or between 60 and 86400"));
        }
        Ok(Settings {
            api: Endpoint::parse("base_url", &self.base_url, ctx)?,
            ttl: self.ttl,
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The API.
    pub(super) api: Endpoint,
    /// TTL of a new record.
    pub(super) ttl: u32,
}

/// Credentials of the Cloudflare client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the token.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct CloudflareCredentials {
    /// An API token (not the Global API Key).
    pub api_token: SecretString,
}

impl CloudflareCredentials {
    /// Credentials with an API token.
    #[must_use]
    pub fn new(api_token: SecretString) -> CloudflareCredentials {
        CloudflareCredentials { api_token }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem.
pub(super) fn parse_settings(text: &str) -> Result<CloudflareConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<CloudflareCredentials, Error> {
    serde_json::from_str(text.expose_secret())
        .map_err(|_| config("the credentials must be a JSON object with the string key api_token"))
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
