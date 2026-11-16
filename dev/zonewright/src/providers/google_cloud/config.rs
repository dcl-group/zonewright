//! Settings and credentials of the Google Cloud DNS client (design sections 2.8 and 11.3).
//!
//! The settings name the project and, optionally, managed zones by their resource name or ID;
//! the credentials hold a service account key file. The token endpoint is a setting, used both
//! as the URL of the token request and as the `aud` claim of the signed JWT; the key file's own
//! `token_uri` is not read (see [`DEFAULT_TOKEN_URL`]).

use std::collections::BTreeMap;
use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::name::DomainName;
use crate::record::{RrsetTtl, Ttl};
use crate::redact::Detail;

/// Default Cloud DNS API endpoint: the root URL of the API with the version path.
// Source: https://www.googleapis.com/discovery/v1/apis/dns/v1/rest (`rootUrl`
// "https://dns.googleapis.com/", method paths "dns/v1/projects/{project}/...").
pub(super) const DEFAULT_DNS_URL: &str = "https://dns.googleapis.com/dns/v1";

/// Default token endpoint; also the `aud` claim of the JWT.
// Source: https://developers.google.com/identity/protocols/oauth2/service-account ("Making the
// access token request": `POST https://oauth2.googleapis.com/token`; the claim set's `aud`: "the
// value is always https://oauth2.googleapis.com/token"). The key file's `token_uri` differs
// between the documentation's own examples (https://docs.cloud.google.com/iam/docs/
// keys-create-delete: `https://accounts.google.com/o/oauth2/token` and
// `https://oauth2.googleapis.com/token`), so the client follows the service-account flow's page
// and takes the endpoint from this setting, not from the key file.
pub(super) const DEFAULT_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// TTL of a new rrset when the caller gives none: lego's default (`GCE_TTL`,
/// `dns01.DefaultTTL`, 120; providers/dns/gcloud/googlecloud.go:75, gcloud.toml).
pub(super) const DEFAULT_TTL: u32 = 120;

/// TTL range, in seconds, of the setting and of a TTL a caller passes. The API carries `ttl` as
/// an int32 ("Number of seconds that this `ResourceRecordSet` can be cached by resolvers",
/// https://www.googleapis.com/discovery/v1/apis/dns/v1/rest, `ResourceRecordSet.ttl`); the
/// console documentation asks for "a positive integer". No other bound is documented.
// Assumption (not observed against the live API): the API accepts every positive int32. A TTL it
// refuses is answered with `invalidValue` ("bad TTL",
// https://docs.cloud.google.com/dns/docs/error-messages), which the client returns as
// `Error::Rejected` with nothing written.
pub(super) const TTL_MIN: u32 = 1;
pub(super) const TTL_MAX: u32 = 2_147_483_647;

/// Default and bounds of the interval between two looks at a pending change (design section
/// 3.7).
pub(super) const DEFAULT_POLL_MS: u64 = 1000;
const POLL_MS_MIN: u64 = 250;
const POLL_MS_MAX: u64 = 60_000;

/// Longest project ID the client accepts. The documentation of the API gives no form; the
/// project goes into the path percent-encoded, so this bounds the text only.
const PROJECT_ID_MAX: usize = 128;

/// Settings of the Google Cloud DNS client: the non-secret part of its configuration.
///
/// Zones listed in `managed_zones` are used by their configured managed zone, which is verified
/// against the zone's name before first use; every other zone is looked up among the public
/// managed zones of the project.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GoogleCloudConfig {
    /// The project whose managed zones are used.
    pub project_id: String,
    /// Zone names mapped to managed zone names or IDs, for a service account whose role is
    /// granted on managed zones rather than on the project, or for a zone name that more than
    /// one public managed zone of the project holds. Accepted as a JSON object or as a string
    /// holding one.
    ///
    /// A configured zone is read with `managedZones.get` (permission `dns.managedZones.get` on
    /// the managed zone). Every other zone, and `list_zones` always, uses `managedZones.list` on
    /// the project (permission `dns.managedZones.list`): a service account whose role is granted
    /// on managed zones only gets `Error::Forbidden` from `list_zones` and from `check` of a zone
    /// that is not configured here.
    #[serde(default, deserialize_with = "managed_zones")]
    pub managed_zones: Option<BTreeMap<String, String>>,
    /// TTL of a new rrset, in seconds: 1 to 2147483647, default 120.
    #[serde(default = "default_ttl")]
    pub ttl: RrsetTtl,
    /// Interval between two looks at a pending change, in milliseconds: 250 to 60000, default
    /// 1000.
    #[serde(default = "default_poll_ms")]
    pub change_poll_ms: u64,
    /// Cloud DNS API endpoint; default `https://dns.googleapis.com/dns/v1`. Every request to it
    /// carries the access token, which can read and change the project's DNS records for an
    /// hour: the value needs the same trust as the credentials and must not come from untrusted
    /// input.
    #[serde(default = "default_dns_url")]
    pub dns_url: String,
    /// OAuth 2.0 token endpoint; default `https://oauth2.googleapis.com/token`. It is also the
    /// audience of the signed JWT. It receives the signed JWT and answers with the access token,
    /// so the value needs the same trust as the credentials and must not come from untrusted
    /// input.
    #[serde(default = "default_token_url")]
    pub token_url: String,
}

fn default_ttl() -> RrsetTtl {
    RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL))
}

fn default_poll_ms() -> u64 {
    DEFAULT_POLL_MS
}

fn default_dns_url() -> String {
    DEFAULT_DNS_URL.to_owned()
}

fn default_token_url() -> String {
    DEFAULT_TOKEN_URL.to_owned()
}

/// `managed_zones`: an object, a string holding one (a multi-line form field), or `null`.
fn managed_zones<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<BTreeMap<String, String>>, D::Error> {
    struct ManagedZones;
    impl<'de> Visitor<'de> for ManagedZones {
        type Value = Option<BTreeMap<String, String>>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object mapping zone names to managed zones, or its JSON text")
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
            serde_json::from_str(s)
                .map(Some)
                .map_err(|_| E::custom("managed_zones is not a JSON object of strings"))
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            BTreeMap::deserialize(de::value::MapAccessDeserializer::new(map)).map(Some)
        }
    }
    d.deserialize_any(ManagedZones)
}

impl GoogleCloudConfig {
    /// Settings for the public managed zones of project `project_id`; every other field starts
    /// at its default.
    #[must_use]
    pub fn new(project_id: String) -> GoogleCloudConfig {
        GoogleCloudConfig {
            project_id,
            managed_zones: None,
            ttl: default_ttl(),
            change_poll_ms: DEFAULT_POLL_MS,
            dns_url: default_dns_url(),
            token_url: default_token_url(),
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        let project = &self.project_id;
        if project.is_empty()
            || project.len() > PROJECT_ID_MAX
            || !project.bytes().all(|b| b.is_ascii_graphic() && b != b'/')
        {
            return Err(config(
                "project_id must be 1 to 128 visible ASCII characters without a slash",
            ));
        }
        let mut zones = BTreeMap::new();
        for (name, managed) in self.managed_zones.iter().flatten() {
            let Ok(name) = DomainName::parse(name) else {
                return Err(config(
                    "managed_zones holds a key that is not a domain name",
                ));
            };
            if crate::http::path_id(managed).is_err() {
                return Err(config(
                    "managed_zones holds a managed zone that is not 1 to 128 letters, digits, \
                     hyphens or underscores",
                ));
            }
            zones.insert(name, managed.clone());
        }
        let ttl = match self.ttl {
            RrsetTtl::Explicit(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl.as_secs()) => {
                ttl.as_secs()
            }
            RrsetTtl::Explicit(_) => return Err(config("ttl must be between 1 and 2147483647")),
            RrsetTtl::ProviderDefault => {
                return Err(config(
                    "ttl cannot be provider_default: the provider has no default TTL of its own",
                ));
            }
        };
        if !(POLL_MS_MIN..=POLL_MS_MAX).contains(&self.change_poll_ms) {
            return Err(config("change_poll_ms must be between 250 and 60000"));
        }
        Ok(Settings {
            dns: Endpoint::parse("dns_url", &self.dns_url, ctx)?,
            token: Endpoint::parse("token_url", &self.token_url, ctx)?,
            project: project.clone(),
            zones,
            ttl,
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The Cloud DNS API.
    pub(super) dns: Endpoint,
    /// The token endpoint.
    pub(super) token: Endpoint,
    /// The project.
    pub(super) project: String,
    /// Configured managed zones.
    pub(super) zones: BTreeMap<DomainName, String>,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
}

/// A service account key, as the provider's console and `gcloud` write it to a JSON file.
///
/// Only `client_email`, `private_key_id` and `private_key` are read, and `type`, which must be
/// `service_account` when present; other keys of the file (`project_id`, `client_id`,
/// `auth_uri`, `token_uri`, the certificate URLs, `universe_domain`) are ignored. All three are
/// held as secrets, the two identifiers included, since they arrive in the credentials object.
// Source: https://docs.cloud.google.com/iam/docs/keys-create-delete (the key file's members).
#[derive(Debug)]
#[non_exhaustive]
pub struct ServiceAccountKey {
    /// The service account's e-mail address: the `iss` of the signed JWT.
    pub client_email: SecretString,
    /// The key's ID: the `kid` of the signed JWT; the JWT carries no `kid` without it.
    pub private_key_id: Option<SecretString>,
    /// The RSA private key in PEM ("PRIVATE KEY" or "RSA PRIVATE KEY").
    pub private_key: SecretString,
}

impl ServiceAccountKey {
    /// A service account key from its parts.
    #[must_use]
    pub fn new(
        client_email: SecretString,
        private_key_id: Option<SecretString>,
        private_key: SecretString,
    ) -> ServiceAccountKey {
        ServiceAccountKey {
            client_email,
            private_key_id,
            private_key,
        }
    }
}

/// The members of a key file this client reads.
#[derive(Deserialize)]
struct KeyFields {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    client_email: SecretString,
    #[serde(default)]
    private_key_id: Option<SecretString>,
    private_key: SecretString,
}

/// The `type` of a service account key file.
// Source: https://docs.cloud.google.com/iam/docs/keys-create-delete (`"type":
// "service_account"`).
const SERVICE_ACCOUNT: &str = "service_account";

impl KeyFields {
    fn into_key<E: de::Error>(self) -> Result<ServiceAccountKey, E> {
        if self
            .kind
            .as_deref()
            .is_some_and(|kind| kind != SERVICE_ACCOUNT)
        {
            return Err(E::custom(
                "the key file is not a service account key (its type is not service_account)",
            ));
        }
        Ok(ServiceAccountKey::new(
            self.client_email,
            self.private_key_id,
            self.private_key,
        ))
    }
}

impl<'de> Deserialize<'de> for ServiceAccountKey {
    /// Accepts the key file's JSON object, or a string holding that JSON (a form field).
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<ServiceAccountKey, D::Error> {
        struct Key;
        impl<'de> Visitor<'de> for Key {
            type Value = ServiceAccountKey;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a service account key object or its JSON text")
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<ServiceAccountKey, E> {
                serde_json::from_str::<KeyFields>(s)
                    .map_err(|_| E::custom("the service account key is not valid"))?
                    .into_key()
            }

            fn visit_string<E: de::Error>(self, s: String) -> Result<ServiceAccountKey, E> {
                let s = zeroize::Zeroizing::new(s);
                self.visit_str(&s)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<ServiceAccountKey, A::Error> {
                KeyFields::deserialize(de::value::MapAccessDeserializer::new(map))?.into_key()
            }
        }
        d.deserialize_any(Key)
    }
}

/// Credentials of the Google Cloud DNS client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the key.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct GoogleCloudCredentials {
    /// The service account key.
    pub service_account_key: ServiceAccountKey,
}

impl GoogleCloudCredentials {
    /// Credentials with a service account key.
    #[must_use]
    pub fn new(service_account_key: ServiceAccountKey) -> GoogleCloudCredentials {
        GoogleCloudCredentials {
            service_account_key,
        }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem.
pub(super) fn parse_settings(text: &str) -> Result<GoogleCloudConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected keys.
pub(super) fn parse_credentials(text: &SecretString) -> Result<GoogleCloudCredentials, Error> {
    serde_json::from_str(text.expose_secret()).map_err(|_| {
        config(
            "the credentials must be a JSON object with the key service_account_key: a service \
             account key file (an object or its JSON text) with the string keys client_email and \
             private_key, and private_key_id",
        )
    })
}

pub(super) fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
