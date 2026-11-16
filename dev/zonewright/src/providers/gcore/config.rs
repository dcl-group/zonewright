//! Settings and credentials of the Gcore client (design section 2.8).
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
// Source: https://docs.gcore.com/api-reference/overview (the table of products: Managed DNS,
// `https://api.gcore.com/dns`); lego providers/dns/internal/gcore/internal/client.go
// (`defaultBaseURL = "https://api.gcore.com/dns"`).
pub(super) const DEFAULT_BASE_URL: &str = "https://api.gcore.com/dns";

/// TTL of a new rrset when the caller gives none: the API's own default for an rrset written
/// without `ttl`.
// Source: the provider's Swagger document https://api.gcore.com/dns/docs/swagger.yaml,
// `InputRRSet.ttl` (`default: 300`). lego sends its own default, 120 (`dns01.DefaultTTL`,
// `GCORE_TTL`); the value is a choice, not an API requirement.
pub(super) const DEFAULT_TTL: u32 = 300;

/// TTL range the client accepts, in seconds: no range is documented (`ttl` is a `uint32`), so
/// RFC 2181's is taken without zero, and a plan's minimum is left to the API.
pub(super) const TTL_MIN: u32 = 1;
pub(super) const TTL_MAX: u32 = 2_147_483_647;

/// Settings of the Gcore client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct GcoreConfig {
    /// TTL of a new rrset: 1 to 2147483647 seconds, default 300. An existing rrset keeps its own
    /// TTL.
    pub ttl: RrsetTtl,
    /// API endpoint; default `https://api.gcore.com/dns`.
    pub base_url: String,
}

impl Default for GcoreConfig {
    fn default() -> GcoreConfig {
        GcoreConfig {
            ttl: RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL)),
            base_url: DEFAULT_BASE_URL.to_owned(),
        }
    }
}

impl GcoreConfig {
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

/// Credentials of the Gcore client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the token.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct GcoreCredentials {
    /// A permanent API token of the account, with a Managed DNS role that may change records.
    pub api_token: SecretString,
}

impl GcoreCredentials {
    /// Credentials with the permanent API token.
    #[must_use]
    pub fn new(api_token: SecretString) -> GcoreCredentials {
        GcoreCredentials { api_token }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<GcoreConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<GcoreCredentials, Error> {
    serde_json::from_str(text.expose_secret())
        .map_err(|_| config("the credentials must be a JSON object with the string key api_token"))
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
