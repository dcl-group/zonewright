//! Settings and credentials of the DigitalOcean client (design sections 2.8 and 11.3).
//!
//! The keys are those of the earlier TXT-only implementation, minus its propagation timeout (an
//! application setting now). They are a compatibility surface: applications persist them.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::redact::Detail;

/// Default API endpoint.
// Source: https://docs.digitalocean.com/reference/api/reference/domain-records/ (paths start
// with `/v2/domains/...`); lego providers/dns/digitalocean/internal/client.go:40 builds
// `BaseURL/v2/domains/{zone}/records` with the base `https://api.digitalocean.com`.
pub(super) const DEFAULT_BASE_URL: &str = "https://api.digitalocean.com/v2";

/// TTL of a new record when the caller gives none.
// Source: lego providers/dns/digitalocean/digitalocean.go:49 (`DO_TTL`, default 30).
pub(super) const DEFAULT_TTL: u32 = 30;

/// TTL range the client accepts, in seconds.
// Source for the minimum: https://docs.digitalocean.com/products/networking/dns/details/limits/
// ("All DNS records require a minimum TTL value of 30 seconds"). Assumption (not documented):
// the maximum; neither the API reference nor the limits page states one, and 86400 is the
// usual one-day ceiling. Being wrong only refuses a TTL the API would accept; a value the API
// refuses comes back as `Error::Rejected` and writes nothing.
pub(super) const TTL_MIN: u32 = 30;
pub(super) const TTL_MAX: u32 = 86_400;

/// Settings of the DigitalOcean client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct DigitalOceanConfig {
    /// API endpoint; default `https://api.digitalocean.com/v2`.
    pub base_url: String,
    /// TTL of a new record, in seconds: 30 to 86400, default 30.
    pub ttl: u32,
}

impl Default for DigitalOceanConfig {
    fn default() -> DigitalOceanConfig {
        DigitalOceanConfig {
            base_url: DEFAULT_BASE_URL.to_owned(),
            ttl: DEFAULT_TTL,
        }
    }
}

impl DigitalOceanConfig {
    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        if !(TTL_MIN..=TTL_MAX).contains(&self.ttl) {
            return Err(config("ttl must be between 30 and 86400"));
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

/// Credentials of the DigitalOcean client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the token.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct DigitalOceanCredentials {
    /// A personal access token. A custom-scoped token needs domain read, create, update and
    /// delete, and account read.
    pub api_token: SecretString,
}

impl DigitalOceanCredentials {
    /// Credentials with the personal access token.
    #[must_use]
    pub fn new(api_token: SecretString) -> DigitalOceanCredentials {
        DigitalOceanCredentials { api_token }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<DigitalOceanConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<DigitalOceanCredentials, Error> {
    serde_json::from_str(text.expose_secret())
        .map_err(|_| config("the credentials must be a JSON object with the string key api_token"))
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
