//! Settings and credentials of the Yandex 360 client (design sections 2.8 and 11.3).
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
// Source: https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Create (the
// URL `https://api360.yandex.net/directory/v1/org/{orgId}/domains/{domain}/dns`); lego
// providers/dns/yandex360/internal/client.go line 18 (`defaultBaseURL`).
pub(super) const DEFAULT_BASE_URL: &str = "https://api360.yandex.net";

/// TTL of a new record when the caller gives none.
// Assumption (not documented): 300. The create page requires `ttl` and states no default and no
// range; lego uses 21600 (providers/dns/yandex360/yandex360.go line 49). A short TTL helps an
// ACME challenge. Being wrong changes only how long a resolver may cache the challenge value.
pub(super) const DEFAULT_TTL: u32 = 300;

/// TTL range the client accepts, in seconds.
// Assumption (not documented): the create page says only "TTL in seconds" and states no range.
// 60 to 86400 is a conservative range: one minute to one day. Being wrong refuses a TTL the API
// would accept, or sends one the API refuses, which comes back as `Error::Rejected` with
// nothing written.
pub(super) const TTL_MIN: u32 = 60;
pub(super) const TTL_MAX: u32 = 86_400;

/// Most digits of the organization ID. The API states an integer (`orgId`, `integer`); lego holds
/// it as an `int64`, which has at most 19 digits.
const ORG_ID_MAX_DIGITS: usize = 19;

/// Settings of the Yandex 360 client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct Yandex360Config {
    /// API endpoint; default `https://api360.yandex.net`.
    pub base_url: String,
    /// The numeric ID of the Yandex 360 organization. Required.
    pub org_id: String,
    /// TTL of a new record, in seconds: 60 to 86400, default 300.
    pub ttl: u32,
}

impl Default for Yandex360Config {
    fn default() -> Yandex360Config {
        Yandex360Config {
            base_url: DEFAULT_BASE_URL.to_owned(),
            org_id: String::new(),
            ttl: DEFAULT_TTL,
        }
    }
}

impl Yandex360Config {
    /// Settings for the organization `org_id`, with the defaults of everything else.
    #[must_use]
    pub fn new(org_id: impl Into<String>) -> Yandex360Config {
        Yandex360Config {
            org_id: org_id.into(),
            ..Yandex360Config::default()
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        let digits = self.org_id.len();
        if digits == 0
            || digits > ORG_ID_MAX_DIGITS
            || !self.org_id.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(config("org_id must be a decimal number"));
        }
        if !(TTL_MIN..=TTL_MAX).contains(&self.ttl) {
            return Err(config("ttl must be between 60 and 86400"));
        }
        Ok(Settings {
            api: Endpoint::parse("base_url", &self.base_url, ctx)?,
            org_id: self.org_id.clone(),
            ttl: self.ttl,
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The API.
    pub(super) api: Endpoint,
    /// The organization, decimal digits only.
    pub(super) org_id: String,
    /// TTL of a new record.
    pub(super) ttl: u32,
}

/// Credentials of the Yandex 360 client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the token.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct Yandex360Credentials {
    /// The OAuth token of an application, sent as `Authorization: OAuth <token>`. The
    /// application needs the scopes `directory:read_domains` and `directory:manage_dns`.
    pub oauth_token: SecretString,
}

impl Yandex360Credentials {
    /// Credentials with the OAuth token.
    #[must_use]
    pub fn new(oauth_token: SecretString) -> Yandex360Credentials {
        Yandex360Credentials { oauth_token }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<Yandex360Config, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<Yandex360Credentials, Error> {
    serde_json::from_str(text.expose_secret()).map_err(|_| {
        config("the credentials must be a JSON object with the string key oauth_token")
    })
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
