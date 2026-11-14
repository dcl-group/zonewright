//! Settings and credentials of the VK Cloud client (design sections 2.8 and 11.3).
//!
//! The keys are those of the earlier TXT-only implementation, minus its propagation timeout
//! (an application setting now). They are a compatibility surface: applications persist them.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::redact::Detail;

/// Default public DNS API endpoint.
// Source: lego providers/dns/vkcloud/vkcloud.go:36 (`defaultDNSEndpoint`); the provider's API
// page (https://cloud.vk.ru/docs/ru/tools-for-using-services/api/api-spec/network-api/api-dns)
// shows the same base in its example, `curl --location "https://mcs.mail.ru/public-dns/v2/dns/"`.
pub(super) const DEFAULT_DNS_URL: &str = "https://mcs.mail.ru/public-dns/v2/dns";

/// Default identity (Keystone v3) endpoint.
// Source: lego providers/dns/vkcloud/vkcloud.go:35 (`defaultIdentityEndpoint`, with a trailing
// slash that the endpoint policy removes). The provider's token documentation
// (https://cloud.vk.ru/docs/ru/tools-for-using-services/api/rest-api/case-keystone-token) shows
// `https://infra.mail.ru/infra/identity/v3/auth/tokens` in its examples; the earlier
// implementation's default is kept, and the setting can point at either.
pub(super) const DEFAULT_IDENTITY_URL: &str = "https://infra.mail.ru/identity/v3";

/// Default Keystone domain of the user.
// Source: lego providers/dns/vkcloud/vkcloud.go:39 (`defaultDomainName = "users"`).
pub(super) const DEFAULT_USER_DOMAIN: &str = "users";

/// TTL of a new record when the caller gives none: lego's default
/// (providers/dns/vkcloud/vkcloud.go:62, `VK_CLOUD_TTL` default 60), the documented minimum.
pub(super) const DEFAULT_TTL: u32 = 60;

/// TTL range the client accepts, in seconds. The minimum is the documented one; the documented
/// maximum (2147483648) is wider than the earlier implementation's bound, which is kept.
// Source: the OpenAPI of the public DNS API (`ttl`: minimum 60, maximum 2147483648).
pub(super) const TTL_MIN: u32 = 60;
pub(super) const TTL_MAX: u32 = 86_400;

/// Longest user name the client accepts: a bound of the client's own, not of the API.
const USERNAME_MAX: usize = 255;

/// Settings of the VK Cloud client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct VkCloudConfig {
    /// The ID of the project that holds the zones; the token is scoped to it.
    pub project_id: String,
    /// The user's name (the login, an e-mail address).
    pub username: String,
    /// The user's Keystone domain; default `users`.
    #[serde(default = "default_user_domain")]
    pub user_domain: String,
    /// TTL of a new record set, in seconds: 60 to 86400, default 60.
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// Identity endpoint; default `https://infra.mail.ru/identity/v3`.
    #[serde(default = "default_identity_url")]
    pub identity_url: String,
    /// Public DNS API endpoint; default `https://mcs.mail.ru/public-dns/v2/dns`.
    #[serde(default = "default_dns_url")]
    pub dns_url: String,
}

fn default_user_domain() -> String {
    DEFAULT_USER_DOMAIN.to_owned()
}

fn default_ttl() -> u32 {
    DEFAULT_TTL
}

fn default_identity_url() -> String {
    DEFAULT_IDENTITY_URL.to_owned()
}

fn default_dns_url() -> String {
    DEFAULT_DNS_URL.to_owned()
}

impl VkCloudConfig {
    /// Settings with the two required keys; every other field starts at its default.
    #[must_use]
    pub fn new(project_id: String, username: String) -> VkCloudConfig {
        VkCloudConfig {
            project_id,
            username,
            user_domain: default_user_domain(),
            ttl: DEFAULT_TTL,
            identity_url: default_identity_url(),
            dns_url: default_dns_url(),
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        let usable = |b: u8| b.is_ascii_alphanumeric() || b == b'-';
        if self.project_id.is_empty() || !self.project_id.bytes().all(usable) {
            return Err(config(
                "project_id must consist of letters, digits and hyphens",
            ));
        }
        if self.username.is_empty() || self.username.chars().count() > USERNAME_MAX {
            return Err(config("username must be 1 to 255 characters long"));
        }
        if self.user_domain.is_empty() {
            return Err(config("user_domain must not be empty"));
        }
        if !(TTL_MIN..=TTL_MAX).contains(&self.ttl) {
            return Err(config("ttl must be between 60 and 86400"));
        }
        Ok(Settings {
            dns: Endpoint::parse("dns_url", &self.dns_url, ctx)?,
            identity: Endpoint::parse("identity_url", &self.identity_url, ctx)?,
            ttl: self.ttl,
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The public DNS API.
    pub(super) dns: Endpoint,
    /// The identity service.
    pub(super) identity: Endpoint,
    /// TTL of a new record set.
    pub(super) ttl: u32,
}

/// Credentials of the VK Cloud client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the password.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct VkCloudCredentials {
    /// The user's password.
    pub password: SecretString,
}

impl VkCloudCredentials {
    /// Credentials with the user's password.
    #[must_use]
    pub fn new(password: SecretString) -> VkCloudCredentials {
        VkCloudCredentials { password }
    }
}

/// The settings keys that a settings object must contain.
const REQUIRED_KEYS: [(&str, &str); 2] = [
    (
        "project_id",
        "the settings lack the required key project_id",
    ),
    ("username", "the settings lack the required key username"),
];

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem and, for a missing key, its name.
pub(super) fn parse_settings(text: &str) -> Result<VkCloudConfig, Error> {
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
pub(super) fn parse_credentials(text: &SecretString) -> Result<VkCloudCredentials, Error> {
    let credentials: VkCloudCredentials =
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
