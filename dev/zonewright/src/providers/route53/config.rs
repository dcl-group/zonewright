//! Settings and credentials of the Route 53 client (design sections 2.8 and 11.3).
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
// Source: AWS General Reference, "Amazon Route 53 endpoints and quotas"
// (https://docs.aws.amazon.com/general/latest/gr/r53.html): the IPv4 service endpoint is
// route53.amazonaws.com, HTTPS, for every commercial Region.
pub(super) const DEFAULT_BASE_URL: &str = "https://route53.amazonaws.com";

/// TTL of a new rrset when the caller gives none.
pub(super) const DEFAULT_TTL: u32 = 60;

/// TTL range the client accepts for a new rrset, in seconds: the range of the setting in the
/// metadata. The API itself accepts 0 to 2147483647 (API reference, `ResourceRecordSet.TTL`).
pub(super) const TTL_MIN: u32 = 1;
pub(super) const TTL_MAX: u32 = 86_400;

/// Default interval between two polls of a change, in milliseconds (design section 3.7).
pub(super) const DEFAULT_CHANGE_POLL_MS: u64 = 2000;

/// Range of `change_poll_ms`: the floor of design section 3.7 and the bound of the metadata.
const CHANGE_POLL_MIN_MS: u64 = 250;
const CHANGE_POLL_MAX_MS: u64 = 60_000;

/// Longest hosted zone ID.
// Source: API reference, `GetHostedZone` and `ListResourceRecordSets`: `Id`, "Maximum length of
// 32".
const ZONE_ID_MAX: usize = 32;

/// Longest access key ID.
// Source: IAM API reference, `AccessKey.AccessKeyId`: length 16 to 128, pattern `[\w]+`
// (https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html).
const ACCESS_KEY_ID_MAX: usize = 128;

/// The prefix the API puts before a hosted zone ID in `HostedZone.Id`.
// Source: API reference, `GetHostedZone` example response (`<Id>/hostedzone/Z1PA6795UKMFR9</Id>`);
// lego providers/dns/route53/route53.go (line 335 at commit c40c0a2) trims the same prefix.
pub(super) const HOSTED_ZONE_PREFIX: &str = "/hostedzone/";

/// Settings of the Route 53 client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Route53Config {
    /// The ID of the IAM access key. Not a secret: it is sent in every request.
    pub access_key_id: String,
    /// The hosted zone to use for the zone with the same name, when several public hosted zones
    /// share that name; with or without the `/hostedzone/` prefix.
    #[serde(default)]
    pub hosted_zone_id: Option<String>,
    /// TTL of a new rrset, in seconds: 1 to 86400, default 60.
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// Interval between two polls of a submitted change, in milliseconds: 250 to 60000, default
    /// 2000.
    #[serde(default = "default_change_poll_ms")]
    pub change_poll_ms: u64,
    /// API endpoint: scheme and host only; default `https://route53.amazonaws.com`.
    #[serde(default = "default_base_url")]
    pub base_url: String,
}

fn default_ttl() -> u32 {
    DEFAULT_TTL
}

fn default_change_poll_ms() -> u64 {
    DEFAULT_CHANGE_POLL_MS
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_owned()
}

impl Route53Config {
    /// Settings with the required access key ID; every other field starts at its default.
    #[must_use]
    pub fn new(access_key_id: String) -> Route53Config {
        Route53Config {
            access_key_id,
            hosted_zone_id: None,
            ttl: DEFAULT_TTL,
            change_poll_ms: DEFAULT_CHANGE_POLL_MS,
            base_url: default_base_url(),
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        let key_ok = !self.access_key_id.is_empty()
            && self.access_key_id.len() <= ACCESS_KEY_ID_MAX
            && self
                .access_key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !key_ok {
            return Err(config(
                "access_key_id must be 1 to 128 letters, digits or underscores",
            ));
        }
        let hosted_zone_id = match &self.hosted_zone_id {
            None => None,
            Some(raw) => Some(zone_id(raw).ok_or_else(|| {
                config("hosted_zone_id must be a hosted zone ID of up to 32 letters and digits")
            })?),
        };
        if !(TTL_MIN..=TTL_MAX).contains(&self.ttl) {
            return Err(config("ttl must be between 1 and 86400"));
        }
        if !(CHANGE_POLL_MIN_MS..=CHANGE_POLL_MAX_MS).contains(&self.change_poll_ms) {
            return Err(config("change_poll_ms must be between 250 and 60000"));
        }
        let api = Endpoint::parse("base_url", &self.base_url, ctx)?;
        // Requests are signed over their path; the API's paths start at the host
        // (`/2013-04-01/...`), so the endpoint carries no path of its own.
        if api.as_url().path() != "/" && !api.as_url().path().is_empty() {
            return Err(config(
                "base_url must consist of the scheme and the host only",
            ));
        }
        Ok(Settings {
            api,
            hosted_zone_id,
            ttl: self.ttl,
            change_poll_ms: self.change_poll_ms,
        })
    }
}

/// The hosted zone ID in `raw`, without the `/hostedzone/` prefix, if it has the documented
/// form: 1 to 32 ASCII letters and digits.
pub(super) fn zone_id(raw: &str) -> Option<String> {
    let id = raw.strip_prefix(HOSTED_ZONE_PREFIX).unwrap_or(raw);
    let ok =
        !id.is_empty() && id.len() <= ZONE_ID_MAX && id.bytes().all(|b| b.is_ascii_alphanumeric());
    ok.then(|| id.to_owned())
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The API.
    pub(super) api: Endpoint,
    /// The configured hosted zone, without the prefix.
    pub(super) hosted_zone_id: Option<String>,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
    /// Polling interval of a change, in milliseconds.
    pub(super) change_poll_ms: u64,
}

/// Credentials of the Route 53 client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the secrets.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct Route53Credentials {
    /// The secret access key.
    pub secret_access_key: SecretString,
    /// The session token of temporary security credentials; `None` (or empty) for long-term
    /// access keys.
    #[serde(default)]
    pub session_token: Option<SecretString>,
}

impl Route53Credentials {
    /// Credentials of a long-term access key.
    #[must_use]
    pub fn new(secret_access_key: SecretString) -> Route53Credentials {
        Route53Credentials {
            secret_access_key,
            session_token: None,
        }
    }

    /// Credentials of temporary security credentials, with their session token.
    #[must_use]
    pub fn with_session_token(
        secret_access_key: SecretString,
        session_token: SecretString,
    ) -> Route53Credentials {
        Route53Credentials {
            secret_access_key,
            session_token: Some(session_token),
        }
    }

    /// Checks the credentials; returns the session token if one is given and not empty.
    pub(super) fn validate(&self) -> Result<Option<&SecretString>, Error> {
        if self.secret_access_key.expose_secret().is_empty() {
            return Err(config("secret_access_key must not be empty"));
        }
        let token = self
            .session_token
            .as_ref()
            .filter(|t| !t.expose_secret().is_empty());
        if let Some(token) = token
            && !token
                .expose_secret()
                .bytes()
                .all(|b| b == b' ' || b.is_ascii_graphic())
        {
            return Err(config(
                "session_token contains a character that cannot be sent in an HTTP header",
            ));
        }
        Ok(token)
    }
}

/// The settings keys that a settings object must contain.
const REQUIRED_KEYS: [(&str, &str); 1] = [(
    "access_key_id",
    "the settings lack the required key access_key_id",
)];

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem and, for a missing key, its name.
pub(super) fn parse_settings(text: &str) -> Result<Route53Config, Error> {
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
pub(super) fn parse_credentials(text: &SecretString) -> Result<Route53Credentials, Error> {
    serde_json::from_str(text.expose_secret()).map_err(|_| {
        config(
            "the credentials must be a JSON object with the string key secret_access_key and \
             optionally session_token",
        )
    })
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
