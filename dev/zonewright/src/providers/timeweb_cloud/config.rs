//! Settings and credentials of the Timeweb Cloud client (design sections 2.8 and 11.3).
//!
//! The keys are those of the earlier TXT-only implementation, minus its propagation timeout (an
//! application setting now). They are a compatibility surface: applications persist them.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::record::RrsetTtl;
use crate::redact::Detail;

/// Default API endpoint.
// Source: the public API description, https://timeweb.cloud/api-docs (OpenAPI `servers`:
// `https://api.timeweb.cloud`, every path below `/api/`); lego
// providers/dns/timewebcloud/internal/client.go:19 at commit `012a2c1e01` (`defaultBaseURL`
// with the `/api` part) and line 44 (`v2/domains/{fqdn}/dns-records` below it).
pub(super) const DEFAULT_BASE_URL: &str = "https://api.timeweb.cloud/api";

/// TTL range the client accepts for a setting or a request, in seconds.
// Assumption (not documented): the public API description types `ttl` as a number without a
// range. The range is the one the settings form has always offered. Being wrong only refuses a
// TTL the API would accept, or passes one it refuses, which comes back as `Error::Rejected` and
// writes nothing.
pub(super) const TTL_MIN: u32 = 60;
pub(super) const TTL_MAX: u32 = 86_400;

/// Settings of the Timeweb Cloud client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct TimewebCloudConfig {
    /// API endpoint; default `https://api.timeweb.cloud/api`.
    pub base_url: String,
    /// TTL of a new record: 60 to 86400 seconds, or `"provider_default"` (the default): no TTL
    /// is sent and the provider chooses. A missing key and `null` mean the provider's default,
    /// as they always have.
    #[serde(deserialize_with = "ttl_or_provider_default")]
    pub ttl: RrsetTtl,
}

impl Default for TimewebCloudConfig {
    fn default() -> TimewebCloudConfig {
        TimewebCloudConfig {
            base_url: DEFAULT_BASE_URL.to_owned(),
            ttl: RrsetTtl::ProviderDefault,
        }
    }
}

/// `ttl`, with `null` read as the provider's default.
fn ttl_or_provider_default<'de, D: serde::Deserializer<'de>>(d: D) -> Result<RrsetTtl, D::Error> {
    Ok(Option::<RrsetTtl>::deserialize(d)?.unwrap_or(RrsetTtl::ProviderDefault))
}

impl TimewebCloudConfig {
    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        if let RrsetTtl::Explicit(ttl) = self.ttl
            && !(TTL_MIN..=TTL_MAX).contains(&ttl.as_secs())
        {
            return Err(config(
                "ttl must be between 60 and 86400, or provider_default",
            ));
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
    /// TTL of a new record: a number, or the provider's choice.
    pub(super) ttl: RrsetTtl,
}

/// Credentials of the Timeweb Cloud client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the token.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct TimewebCloudCredentials {
    /// An API token from the API and Terraform section of the Timeweb Cloud panel.
    pub token: SecretString,
}

impl TimewebCloudCredentials {
    /// Credentials with the API token.
    #[must_use]
    pub fn new(token: SecretString) -> TimewebCloudCredentials {
        TimewebCloudCredentials { token }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<TimewebCloudConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<TimewebCloudCredentials, Error> {
    serde_json::from_str(text.expose_secret())
        .map_err(|_| config("the credentials must be a JSON object with the string key token"))
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
