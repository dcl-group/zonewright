//! Settings and credentials of the Yandex Cloud client (design sections 2.8 and 11.3).
//!
//! The keys are those of the earlier TXT-only implementation, minus its propagation timeout (an
//! application setting now), with `folder_id` optional and `zone_ids` added (design section
//! 11.3). They are a compatibility surface: applications persist them.

use std::collections::BTreeMap;
use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::name::DomainName;
use crate::redact::Detail;

/// Default DNS API endpoint.
// Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/list ("GET
// https://dns.api.cloud.yandex.net/dns/v1/zones").
pub(super) const DEFAULT_DNS_URL: &str = "https://dns.api.cloud.yandex.net/dns/v1";

/// Default IAM token endpoint; also the `aud` claim of the JWT.
// Source: https://yandex.cloud/en/docs/iam/api-ref/IamToken/create ("POST
// https://iam.api.cloud.yandex.net/iam/v1/tokens") and
// https://yandex.cloud/en/docs/iam/operations/iam-token/create-for-sa (`aud`).
pub(super) const DEFAULT_IAM_URL: &str = "https://iam.api.cloud.yandex.net/iam/v1/tokens";

/// Default Operation API endpoint.
// Source: https://yandex.cloud/en/docs/api-design-guide/concepts/operation ("GET
// https://operation.api.cloud.yandex.net/operations/{operationId}").
pub(super) const DEFAULT_OPERATION_URL: &str = "https://operation.api.cloud.yandex.net/operations";

/// TTL of a new rrset when the caller gives none: lego's default (`YANDEX_CLOUD_TTL`, 60,
/// providers/dns/yandexcloud/yandexcloud.go:52).
pub(super) const DEFAULT_TTL: u32 = 60;

/// TTL range of the `ttl` setting, in seconds. The API accepts 0 to 2147483647
/// (https://yandex.cloud/en/docs/dns/api-ref/DnsZone/updateRecordSets, `ttl`); the setting keeps
/// a narrower range, which the metadata states: a TTL below one minute or above a week is not
/// useful for the records this client writes.
pub(super) const TTL_MIN: u32 = 60;
pub(super) const TTL_MAX: u32 = 604_800;

/// Default and bounds of the polling interval of a provider-side operation (design section 3.7).
pub(super) const DEFAULT_POLL_MS: u64 = 1000;
const POLL_MS_MIN: u64 = 250;
const POLL_MS_MAX: u64 = 60_000;

/// Longest folder ID the API accepts.
// Source: https://yandex.cloud/en/docs/dns/api-ref/DnsZone/list (`folderId`: "The maximum string
// length in characters is 50").
const FOLDER_ID_MAX: usize = 50;

/// Settings of the Yandex Cloud client: the non-secret part of its configuration.
///
/// At least one of `folder_id` and `zone_ids` is required. Zones listed in `zone_ids` are used
/// by their configured ID, which is verified against the zone's name before first use; every
/// other zone is looked up among the public zones of the folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct YandexCloudConfig {
    /// The folder whose public zones are used.
    #[serde(default)]
    pub folder_id: Option<String>,
    /// Zone names mapped to zone IDs, for accounts whose role is granted on zones rather than
    /// on the folder. Accepted as a JSON object or as a string holding one.
    #[serde(default, deserialize_with = "zone_ids")]
    pub zone_ids: Option<BTreeMap<String, String>>,
    /// TTL of a new rrset, in seconds: 60 to 604800, default 60.
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// Interval between two polls of a provider-side operation, in milliseconds: 250 to 60000,
    /// default 1000.
    #[serde(default = "default_poll_ms")]
    pub operation_poll_ms: u64,
    /// DNS API endpoint; default `https://dns.api.cloud.yandex.net/dns/v1`.
    #[serde(default = "default_dns_url")]
    pub dns_url: String,
    /// IAM token endpoint; default `https://iam.api.cloud.yandex.net/iam/v1/tokens`. It is also
    /// the audience of the signed JWT.
    #[serde(default = "default_iam_url")]
    pub iam_url: String,
    /// Operation API endpoint; default `https://operation.api.cloud.yandex.net/operations`.
    #[serde(default = "default_operation_url")]
    pub operation_url: String,
}

fn default_ttl() -> u32 {
    DEFAULT_TTL
}

fn default_poll_ms() -> u64 {
    DEFAULT_POLL_MS
}

fn default_dns_url() -> String {
    DEFAULT_DNS_URL.to_owned()
}

fn default_iam_url() -> String {
    DEFAULT_IAM_URL.to_owned()
}

fn default_operation_url() -> String {
    DEFAULT_OPERATION_URL.to_owned()
}

/// `zone_ids`: an object, a string holding one (a multi-line form field), or `null`.
fn zone_ids<'de, D: Deserializer<'de>>(d: D) -> Result<Option<BTreeMap<String, String>>, D::Error> {
    struct ZoneIds;
    impl<'de> Visitor<'de> for ZoneIds {
        type Value = Option<BTreeMap<String, String>>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object mapping zone names to zone IDs, or its JSON text")
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
                .map_err(|_| E::custom("zone_ids is not a JSON object of strings"))
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            BTreeMap::deserialize(de::value::MapAccessDeserializer::new(map)).map(Some)
        }
    }
    d.deserialize_any(ZoneIds)
}

impl Default for YandexCloudConfig {
    /// Every field at its default; `folder_id` or `zone_ids` still has to be set.
    fn default() -> YandexCloudConfig {
        YandexCloudConfig {
            folder_id: None,
            zone_ids: None,
            ttl: DEFAULT_TTL,
            operation_poll_ms: DEFAULT_POLL_MS,
            dns_url: default_dns_url(),
            iam_url: default_iam_url(),
            operation_url: default_operation_url(),
        }
    }
}

impl YandexCloudConfig {
    /// Settings for the public zones of folder `folder_id`; every other field starts at its
    /// default.
    #[must_use]
    pub fn new(folder_id: String) -> YandexCloudConfig {
        YandexCloudConfig {
            folder_id: Some(folder_id),
            ..YandexCloudConfig::default()
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        let folder = match &self.folder_id {
            Some(id) if id.is_empty() || id.len() > FOLDER_ID_MAX || !id.bytes().all(id_byte) => {
                return Err(config(
                    "folder_id must be 1 to 50 letters, digits, hyphens or underscores",
                ));
            }
            other => other.clone(),
        };
        let mut zones = BTreeMap::new();
        for (name, id) in self.zone_ids.iter().flatten() {
            let Ok(name) = DomainName::parse(name) else {
                return Err(config("zone_ids holds a key that is not a domain name"));
            };
            if crate::http::path_id(id).is_err() {
                return Err(config(
                    "zone_ids holds a zone ID that is not 1 to 128 letters, digits, hyphens or underscores",
                ));
            }
            zones.insert(name, id.clone());
        }
        if folder.is_none() && zones.is_empty() {
            return Err(config("one of folder_id and zone_ids is required"));
        }
        if !(TTL_MIN..=TTL_MAX).contains(&self.ttl) {
            return Err(config("ttl must be between 60 and 604800"));
        }
        if !(POLL_MS_MIN..=POLL_MS_MAX).contains(&self.operation_poll_ms) {
            return Err(config("operation_poll_ms must be between 250 and 60000"));
        }
        Ok(Settings {
            dns: Endpoint::parse("dns_url", &self.dns_url, ctx)?,
            iam: Endpoint::parse("iam_url", &self.iam_url, ctx)?,
            operation: Endpoint::parse("operation_url", &self.operation_url, ctx)?,
            folder,
            zones,
            ttl: self.ttl,
        })
    }
}

fn id_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The DNS API.
    pub(super) dns: Endpoint,
    /// The IAM token endpoint.
    pub(super) iam: Endpoint,
    /// The Operation API.
    pub(super) operation: Endpoint,
    /// The folder whose public zones are looked up.
    pub(super) folder: Option<String>,
    /// Configured zone IDs.
    pub(super) zones: BTreeMap<DomainName, String>,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
}

/// A service account's authorized key, as the provider's CLI writes it to a file.
///
/// Only `id`, `service_account_id` and `private_key` are read; other keys of the file
/// (`created_at`, `key_algorithm`, `public_key`) are ignored. All three are held as secrets,
/// the two identifiers included, since they arrive in the credentials object.
#[derive(Debug)]
#[non_exhaustive]
pub struct AuthorizedKey {
    /// The key's ID: the `kid` of the signed JWT.
    pub id: SecretString,
    /// The service account the key belongs to: the `iss` of the signed JWT.
    pub service_account_id: SecretString,
    /// The RSA private key in PEM ("PRIVATE KEY" or "RSA PRIVATE KEY"); a line of text before
    /// the PEM section, as the provider writes it, is ignored.
    pub private_key: SecretString,
}

impl AuthorizedKey {
    /// An authorized key from its three parts.
    #[must_use]
    pub fn new(
        id: SecretString,
        service_account_id: SecretString,
        private_key: SecretString,
    ) -> AuthorizedKey {
        AuthorizedKey {
            id,
            service_account_id,
            private_key,
        }
    }
}

/// The fields of an authorized key file this client reads.
#[derive(Deserialize)]
struct KeyFields {
    id: SecretString,
    service_account_id: SecretString,
    private_key: SecretString,
}

impl From<KeyFields> for AuthorizedKey {
    fn from(fields: KeyFields) -> AuthorizedKey {
        AuthorizedKey::new(fields.id, fields.service_account_id, fields.private_key)
    }
}

impl<'de> Deserialize<'de> for AuthorizedKey {
    /// Accepts the key file's JSON object, or a string holding that JSON (a form field).
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<AuthorizedKey, D::Error> {
        struct Key;
        impl<'de> Visitor<'de> for Key {
            type Value = AuthorizedKey;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an authorized key object or its JSON text")
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<AuthorizedKey, E> {
                serde_json::from_str::<KeyFields>(s)
                    .map(AuthorizedKey::from)
                    .map_err(|_| E::custom("the authorized key is not valid"))
            }

            fn visit_string<E: de::Error>(self, s: String) -> Result<AuthorizedKey, E> {
                let s = zeroize::Zeroizing::new(s);
                self.visit_str(&s)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<AuthorizedKey, A::Error> {
                KeyFields::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(AuthorizedKey::from)
            }
        }
        d.deserialize_any(Key)
    }
}

/// Credentials of the Yandex Cloud client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the key.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct YandexCloudCredentials {
    /// The service account's authorized key.
    pub authorized_key: AuthorizedKey,
}

impl YandexCloudCredentials {
    /// Credentials with a service account's authorized key.
    #[must_use]
    pub fn new(authorized_key: AuthorizedKey) -> YandexCloudCredentials {
        YandexCloudCredentials { authorized_key }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem. The settings have no required key.
pub(super) fn parse_settings(text: &str) -> Result<YandexCloudConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected keys.
pub(super) fn parse_credentials(text: &SecretString) -> Result<YandexCloudCredentials, Error> {
    serde_json::from_str(text.expose_secret()).map_err(|_| {
        config(
            "the credentials must be a JSON object with the key authorized_key: an object (or its \
             JSON text) with the string keys id, service_account_id and private_key",
        )
    })
}

pub(super) fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
