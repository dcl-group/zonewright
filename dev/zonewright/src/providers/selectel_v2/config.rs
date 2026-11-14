//! Settings and credentials of the Selectel v2 client (design sections 2.8 and 11.3).
//!
//! The keys are those of the earlier TXT-only implementation, minus its propagation timeout
//! (an application setting now) and plus `project_name` (design section 11.3). They are a
//! compatibility surface: applications persist them.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::record::{RrsetTtl, Ttl};
use crate::redact::Detail;

/// Default DNS API endpoint.
// Source: https://docs.selectel.ru/api/docs/cloud-services/dns_api/dns_api_actual/ and lego
// providers/dns/selectelv2/selectelv2.go (`defaultBaseURL`).
pub(super) const DEFAULT_BASE_URL: &str = "https://api.selectel.ru/domains/v2";

/// Default identity (Keystone v3) endpoint; one URL for every region.
// Source: https://docs.selectel.ru/api/authorization/ ("POST
// https://cloud.api.selcloud.ru/identity/v3/auth/tokens").
pub(super) const DEFAULT_AUTH_URL: &str = "https://cloud.api.selcloud.ru/identity/v3";

/// TTL of a new rrset when the caller gives none: the documented minimum, which is also lego's
/// default (`SELECTELV2_TTL`, providers/dns/selectelv2/selectelv2.go).
pub(super) const DEFAULT_TTL: u32 = 60;

/// TTL range the API accepts, in seconds.
// Source: https://docs.selectel.ru/api/docs/cloud-services/dns_api/dns_api_actual/ (rrset
// `ttl`: 60 to 604800).
pub(super) const TTL_MIN: u32 = 60;
pub(super) const TTL_MAX: u32 = 604_800;

/// Longest user name the client accepts: a bound of the client's own, not of the API.
const USERNAME_MAX: usize = 255;

/// Settings of the Selectel v2 client: the non-secret part of its configuration.
///
/// The project that holds the zones is given by exactly one of `project_id` and
/// `project_name`; a name is looked up within the account's Keystone domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SelectelV2Config {
    /// The account number (digits), not the login. It is also the user's Keystone domain
    /// unless `user_domain_name` is given.
    pub account_id: String,
    /// The ID of the project that holds the zones.
    #[serde(default)]
    pub project_id: Option<String>,
    /// The name of the project that holds the zones, within the account's domain.
    #[serde(default)]
    pub project_name: Option<String>,
    /// The service user's name.
    pub username: String,
    /// The service user's Keystone domain; the account number when `None`.
    #[serde(default)]
    pub user_domain_name: Option<String>,
    /// TTL of a new rrset, in seconds: 60 to 604800, default 60.
    #[serde(default = "default_ttl")]
    pub ttl: RrsetTtl,
    /// DNS API endpoint; default `https://api.selectel.ru/domains/v2`.
    #[serde(default = "default_base_url")]
    pub base_url: String,
    /// Identity endpoint; default `https://cloud.api.selcloud.ru/identity/v3`.
    #[serde(default = "default_auth_url")]
    pub auth_url: String,
}

fn default_ttl() -> RrsetTtl {
    RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL))
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_owned()
}

fn default_auth_url() -> String {
    DEFAULT_AUTH_URL.to_owned()
}

impl SelectelV2Config {
    /// Settings with the two required keys; every other field starts at its default, and the
    /// project still has to be set (`project_id` or `project_name`).
    #[must_use]
    pub fn new(account_id: String, username: String) -> SelectelV2Config {
        SelectelV2Config {
            account_id,
            project_id: None,
            project_name: None,
            username,
            user_domain_name: None,
            ttl: default_ttl(),
            base_url: default_base_url(),
            auth_url: default_auth_url(),
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        if self.account_id.is_empty() || !self.account_id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(config(
                "account_id must be the account number (digits only)",
            ));
        }
        let project = match (&self.project_id, &self.project_name) {
            (Some(id), None) => {
                let usable = |b: u8| b.is_ascii_alphanumeric() || b == b'-';
                if id.is_empty() || !id.bytes().all(usable) {
                    return Err(config(
                        "project_id must consist of letters, digits and hyphens",
                    ));
                }
                Project::Id(id.clone())
            }
            (None, Some(name)) => {
                if name.is_empty() || name.chars().any(char::is_control) {
                    return Err(config(
                        "project_name must be a non-empty name without control characters",
                    ));
                }
                Project::Name(name.clone())
            }
            (Some(_), Some(_)) => {
                return Err(config("give exactly one of project_id and project_name"));
            }
            (None, None) => {
                return Err(config("one of project_id and project_name is required"));
            }
        };
        if self.username.is_empty() || self.username.chars().count() > USERNAME_MAX {
            return Err(config("username must be 1 to 255 characters long"));
        }
        let user_domain = match &self.user_domain_name {
            Some(domain) if domain.is_empty() => {
                return Err(config("user_domain_name must not be empty when given"));
            }
            Some(domain) => domain.clone(),
            None => self.account_id.clone(),
        };
        let ttl = match self.ttl {
            RrsetTtl::Explicit(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl.as_secs()) => {
                ttl.as_secs()
            }
            RrsetTtl::Explicit(_) => return Err(config("ttl must be between 60 and 604800")),
            RrsetTtl::ProviderDefault => {
                return Err(config(
                    "ttl cannot be provider_default: the provider has no default TTL of its own",
                ));
            }
        };
        Ok(Settings {
            api: Endpoint::parse("base_url", &self.base_url, ctx)?,
            identity: Endpoint::parse("auth_url", &self.auth_url, ctx)?,
            project,
            user_domain,
            ttl,
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The DNS API.
    pub(super) api: Endpoint,
    /// The identity service.
    pub(super) identity: Endpoint,
    /// The project the token is scoped to.
    pub(super) project: Project,
    /// The user's Keystone domain.
    pub(super) user_domain: String,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
}

/// The project the token is scoped to (design section 11.3).
#[derive(Debug)]
pub(super) enum Project {
    /// By ID.
    Id(String),
    /// By name, within the account's Keystone domain.
    Name(String),
}

/// Credentials of the Selectel v2 client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the password.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct SelectelV2Credentials {
    /// The service user's password.
    pub password: SecretString,
}

impl SelectelV2Credentials {
    /// Credentials with the service user's password.
    #[must_use]
    pub fn new(password: SecretString) -> SelectelV2Credentials {
        SelectelV2Credentials { password }
    }
}

/// The settings keys that a settings object must contain.
const REQUIRED_KEYS: [(&str, &str); 2] = [
    (
        "account_id",
        "the settings lack the required key account_id",
    ),
    ("username", "the settings lack the required key username"),
];

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem and, for a missing key, its name.
pub(super) fn parse_settings(text: &str) -> Result<SelectelV2Config, Error> {
    serde_json::from_str(text).map_err(|e| {
        let message = e.to_string();
        let missing = REQUIRED_KEYS
            .iter()
            .find(|(key, _)| message.starts_with(&format!("missing field `{key}`")));
        match missing {
            Some((_, text)) => config(text),
            None => Error::settings_syntax(e.line(), e.column()),
        }
    })
}

/// Parses the credentials object. Any failure is one fixed text naming the expected keys.
pub(super) fn parse_credentials(text: &SecretString) -> Result<SelectelV2Credentials, Error> {
    let credentials: SelectelV2Credentials =
        serde_json::from_str(text.expose_secret()).map_err(|_| {
            config("the credentials must be a JSON object with the string key password")
        })?;
    Ok(credentials)
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
