//! Settings and credentials of the Porkbun client (design sections 2.8 and 11.3).
//!
//! The keys are a compatibility surface: applications persist them. The credential keys follow
//! the names lego reads (`PORKBUN_API_KEY`, `PORKBUN_SECRET_API_KEY`, lego
//! providers/dns/porkbun/porkbun.go lines 24 and 25).

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::record::{RrsetTtl, Ttl};
use crate::redact::Detail;

/// Default API endpoint.
// Source: the OpenAPI description, <https://porkbun.com/api/json/v3/spec> (`servers`, version
// 3.79, read 2026-11-16): `https://api.porkbun.com/api/json/v3`; nrdcg/porkbun client.go
// (`defaultBaseURL`, commit `b8c9c69`), the client lego uses, has the same.
pub(super) const DEFAULT_BASE_URL: &str = "https://api.porkbun.com/api/json/v3";

/// TTL of a new record when the caller gives none: the documented minimum.
// Source: the OpenAPI description, `CreateDnsRequest.ttl`: "Minimum is determined by account
// settings (typically 600)"; the knowledge base, <https://kb.porkbun.com/article/33> ("Porkbun
// DNS allows a minimum TTL of 600 seconds"). lego sends 300 by default (porkbun.go line 33,
// `minTTL = 300`), which the documentation does not allow; the documentation is followed.
pub(super) const DEFAULT_TTL: u32 = 600;

/// TTL range the client accepts, in seconds.
// Source for the minimum: as for `DEFAULT_TTL`. An account whose minimum is lower than the
// documented "typical" 600 cannot use the lower values through this client. No maximum is
// documented (`ttl` is an integer), so RFC 2181's is taken and a lower limit of the provider is
// left to the API: a value it refuses comes back as an error and writes nothing.
pub(super) const TTL_MIN: u32 = 600;
pub(super) const TTL_MAX: u32 = 2_147_483_647;

/// Settings of the Porkbun client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct PorkbunConfig {
    /// API endpoint; default `https://api.porkbun.com/api/json/v3`.
    pub base_url: String,
    /// TTL of a new record, in seconds: 600 to 2147483647, default 600.
    pub ttl: RrsetTtl,
}

impl Default for PorkbunConfig {
    fn default() -> PorkbunConfig {
        PorkbunConfig {
            base_url: DEFAULT_BASE_URL.to_owned(),
            ttl: RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL)),
        }
    }
}

impl PorkbunConfig {
    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        let ttl = match self.ttl {
            RrsetTtl::Explicit(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl.as_secs()) => {
                ttl.as_secs()
            }
            RrsetTtl::Explicit(_) => return Err(config("ttl must be between 600 and 2147483647")),
            RrsetTtl::ProviderDefault => {
                return Err(config(
                    "ttl cannot be provider_default: every record at the provider has a TTL of \
                     its own",
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
    /// TTL of a new record.
    pub(super) ttl: u32,
}

/// Credentials of the Porkbun client: the secret part of its configuration.
///
/// Both keys are held as secrets: the API key is an identifier rather than a secret, but it
/// arrives in the credentials object and travels with the secret one. Unknown keys are ignored.
/// Nothing prints or serializes either key.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct PorkbunCredentials {
    /// The API key (`pk1_...`).
    pub api_key: SecretString,
    /// The secret API key (`sk1_...`).
    pub secret_api_key: SecretString,
}

impl PorkbunCredentials {
    /// Credentials with the API key and its secret API key.
    #[must_use]
    pub fn new(api_key: SecretString, secret_api_key: SecretString) -> PorkbunCredentials {
        PorkbunCredentials {
            api_key,
            secret_api_key,
        }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<PorkbunConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected keys.
pub(super) fn parse_credentials(text: &SecretString) -> Result<PorkbunCredentials, Error> {
    serde_json::from_str(text.expose_secret()).map_err(|_| {
        config(
            "the credentials must be a JSON object with the string keys api_key and \
             secret_api_key",
        )
    })
}

pub(super) fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
