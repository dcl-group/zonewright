//! Settings and credentials of the DNSimple client (design sections 2.8 and 11.3).
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
// Source: https://developer.dnsimple.com/v2/ ("URL": "https://api.dnsimple.com/v2/"; every
// request names the version in the path) and the OpenAPI description
// https://developer.dnsimple.com/v2/openapi.json (`servers[0]`). The Sandbox,
// `https://api.sandbox.dnsimple.com/v2` (`servers[1]`; "Sandbox API calls must use the
// api.sandbox.dnsimple.com domain"), is reached by setting `base_url`.
pub(super) const DEFAULT_BASE_URL: &str = "https://api.dnsimple.com/v2";

/// TTL of a new record when the caller gives none.
// Source: lego providers/dns/dnsimple/dnsimple.go (`DNSIMPLE_TTL`, default
// `dns01.DefaultTTL`, 120 seconds; challenge/dns01/dns_challenge.go).
pub(super) const DEFAULT_TTL: u32 = 120;

/// TTL range the client accepts, in seconds.
// Source: https://support.dnsimple.com/articles/what-minimum-time-to-live/ ("the record editor
// lets you choose a TTL from 1 minute to 3 days"; "Through the web interface, you can select a
// TTL as low as 1 minute (60 seconds)"). Assumption (not documented for the API): that the API
// accepts the same range. The OpenAPI description states only `minimum: 0` for `TTL`; the
// editor's range is the narrower reading. Being wrong only refuses a TTL the API would accept; a
// value the API refuses comes back as `Error::Rejected` and writes nothing.
pub(super) const TTL_MIN: u32 = 60;
pub(super) const TTL_MAX: u32 = 259_200;

/// Largest account identifier the settings accept: the metadata states the range as `i64`.
const ACCOUNT_ID_MAX: u64 = i64::MAX as u64;

/// Settings of the DNSimple client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct DnsimpleConfig {
    /// API endpoint; default `https://api.dnsimple.com/v2`. The Sandbox is
    /// `https://api.sandbox.dnsimple.com/v2`.
    pub base_url: String,
    /// The numeric identifier of the account whose zones the client manages. Required with a
    /// user token; with an account token, `None` reads it from the token's identity (`whoami`)
    /// once per client, and a value given must be the token's account.
    pub account_id: Option<u64>,
    /// TTL of a new record, in seconds: 60 to 259200, default 120.
    pub ttl: RrsetTtl,
}

impl Default for DnsimpleConfig {
    fn default() -> DnsimpleConfig {
        DnsimpleConfig {
            base_url: DEFAULT_BASE_URL.to_owned(),
            account_id: None,
            ttl: RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL)),
        }
    }
}

impl DnsimpleConfig {
    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        let ttl = match self.ttl {
            RrsetTtl::Explicit(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl.as_secs()) => {
                ttl.as_secs()
            }
            RrsetTtl::Explicit(_) => return Err(config("ttl must be between 60 and 259200")),
            RrsetTtl::ProviderDefault => {
                return Err(config(
                    "ttl cannot be provider_default: every record has a TTL of its own",
                ));
            }
        };
        let account_id = match self.account_id {
            Some(id) if (1..=ACCOUNT_ID_MAX).contains(&id) => Some(id),
            Some(_) => return Err(config("account_id must be a positive integer")),
            None => None,
        };
        Ok(Settings {
            api: Endpoint::parse("base_url", &self.base_url, ctx)?,
            account_id,
            ttl,
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The API.
    pub(super) api: Endpoint,
    /// The configured account, if any.
    pub(super) account_id: Option<u64>,
    /// TTL of a new record.
    pub(super) ttl: u32,
}

/// Credentials of the DNSimple client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the token.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct DnsimpleCredentials {
    /// An API access token, sent as `Authorization: Bearer`. An account token (recommended by
    /// the provider) or a user token; a user token needs `account_id` in the settings.
    pub api_token: SecretString,
}

impl DnsimpleCredentials {
    /// Credentials with the API access token.
    #[must_use]
    pub fn new(api_token: SecretString) -> DnsimpleCredentials {
        DnsimpleCredentials { api_token }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<DnsimpleConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<DnsimpleCredentials, Error> {
    serde_json::from_str(text.expose_secret())
        .map_err(|_| config("the credentials must be a JSON object with the string key api_token"))
}

pub(super) fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
