//! Settings and credentials of the EdgeCenter client (design section 2.8).
//!
//! The keys are a compatibility surface: applications persist them.

use std::time::Duration;

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::record::{RrsetTtl, Ttl};
use crate::redact::Detail;

/// Default API endpoint.
// Source: the provider's Go SDK github.com/Edge-Center/edgecenter-dns-sdk-go, client.go:22
// (`defaultBaseURL`); lego providers/dns/edgecenter/edgecenter.go:28 (`defaultBaseURL =
// "https://api.edgecenter.ru/dns"`); the Swagger document
// https://api.edgecenter.ru/dns/docs/swagger-en.yaml (`basePath: /dns`).
pub(super) const DEFAULT_BASE_URL: &str = "https://api.edgecenter.ru/dns";

/// TTL of a new rrset when the caller gives none: the API's own default for an rrset written
/// without `ttl`.
// Source: the Swagger document, `InputRRSet.ttl` (`default: 300`). lego sends its own default,
// 120 (`dns01.DefaultTTL`, `EDGECENTER_TTL`); the value is a choice, not an API requirement.
pub(super) const DEFAULT_TTL: u32 = 300;

/// TTL range the client accepts, in seconds: the plan's minimum is checked by the API
/// (`min_ttl` of `GET /v2/tarifflimits`), no maximum is documented (`ttl` is a `uint32`), so
/// RFC 2181's range is taken without zero.
pub(super) const TTL_MIN: u32 = 1;
pub(super) const TTL_MAX: u32 = 2_147_483_647;

/// Default minimum time between two requests, in milliseconds.
// Source: the Swagger document, `info.description`: "There is a general limit of 4 requests per
// second. If you go over the rate limit, you will receive a response status of 429." The same
// document says 5 per second in `securityDefinitions.APIKey`; the stricter figure is taken.
pub(super) const DEFAULT_INTERVAL_MS: u64 = 250;

/// Largest interval the setting accepts, in milliseconds.
pub(super) const MAX_INTERVAL_MS: u64 = 60_000;

/// Settings of the EdgeCenter client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct EdgeCenterConfig {
    /// TTL of a new rrset: 1 to 2147483647 seconds, default 300. An existing rrset keeps its own
    /// TTL.
    pub ttl: RrsetTtl,
    /// Minimum time between two requests, in milliseconds: 0 to 60000, default 250 (the API
    /// allows 4 requests per second).
    pub min_request_interval_ms: u64,
    /// API endpoint; default `https://api.edgecenter.ru/dns`.
    pub base_url: String,
}

impl Default for EdgeCenterConfig {
    fn default() -> EdgeCenterConfig {
        EdgeCenterConfig {
            ttl: RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL)),
            min_request_interval_ms: DEFAULT_INTERVAL_MS,
            base_url: DEFAULT_BASE_URL.to_owned(),
        }
    }
}

impl EdgeCenterConfig {
    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        let ttl = match self.ttl {
            RrsetTtl::Explicit(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl.as_secs()) => {
                ttl.as_secs()
            }
            RrsetTtl::Explicit(_) => return Err(config("ttl must be between 1 and 2147483647")),
            RrsetTtl::ProviderDefault => {
                return Err(config(
                    "ttl cannot be provider_default: an rrset at the provider always reads with \
                     a TTL of its own",
                ));
            }
        };
        if self.min_request_interval_ms > MAX_INTERVAL_MS {
            return Err(config(
                "min_request_interval_ms must be between 0 and 60000",
            ));
        }
        Ok(Settings {
            api: Endpoint::parse("base_url", &self.base_url, ctx)?,
            ttl,
            interval: Duration::from_millis(self.min_request_interval_ms),
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
    /// Minimum time between two requests.
    pub(super) interval: Duration,
}

/// Credentials of the EdgeCenter client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the token.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct EdgeCenterCredentials {
    /// A permanent API token of the account, with a role that may change DNS records.
    pub api_token: SecretString,
}

impl EdgeCenterCredentials {
    /// Credentials with the permanent API token.
    #[must_use]
    pub fn new(api_token: SecretString) -> EdgeCenterCredentials {
        EdgeCenterCredentials { api_token }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<EdgeCenterConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<EdgeCenterCredentials, Error> {
    serde_json::from_str(text.expose_secret())
        .map_err(|_| config("the credentials must be a JSON object with the string key api_token"))
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
