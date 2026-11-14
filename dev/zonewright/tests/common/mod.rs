//! Helpers shared by the integration tests: context and client builders.

// Each test crate includes this module and uses a different part of it.
#![allow(dead_code)]

pub mod echo;

use secrecy::SecretString;
use zonewright::{AnyProvider, Context, ContextOptions, DomainName, Error, ProviderId};

/// A context for tests: connections to anything but loopback addresses are refused, so a test
/// that forgets to point a client at a mock fails instead of contacting a provider.
pub fn context() -> Context {
    let mut options = ContextOptions::default();
    options.loopback_only = true;
    Context::new(options).unwrap()
}

/// A domain name from text that is known to be valid.
pub fn dn(s: &str) -> DomainName {
    DomainName::parse(s).unwrap()
}

/// Settings and credentials JSON with which `AnyProvider::from_json` builds a client of `id`
/// without any request. Synthetic values only.
///
/// A placeholder client accepts any two JSON objects. When a client is ported, its developer
/// asks the lead to replace its entry with the smallest valid configuration, pointed at a
/// loopback address.
pub fn sample_config(id: ProviderId) -> (&'static str, &'static str) {
    match id {
        ProviderId::SelectelV2 => (
            r#"{"account_id":"123456","project_id":"project-a","username":"zw-test-user","base_url":"http://127.0.0.1:9/domains/v2","auth_url":"http://127.0.0.1:9/identity/v3"}"#,
            r#"{"password":"test-only-password"}"#,
        ),
        ProviderId::Cloudflare => (
            r#"{"base_url":"http://127.0.0.1:9/client/v4"}"#,
            r#"{"api_token":"test-only-token"}"#,
        ),
        ProviderId::YandexCloud => {
            // A valid configuration needs an RSA key that parses. No key is stored in the
            // repository: the mock generates one per test process.
            static CONFIG: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
            let (settings, credentials) = CONFIG.get_or_init(|| {
                let seed = zonewright_mock::yandex_cloud::Seed::standard();
                let key =
                    seed.authorized_key(&zonewright_mock::yandex_cloud::test_key().private_pem);
                (
                    r#"{"folder_id":"b1gtestfolder000001","dns_url":"http://127.0.0.1:9/dns/v1","iam_url":"http://127.0.0.1:9/iam/v1/tokens","operation_url":"http://127.0.0.1:9/operations"}"#.to_owned(),
                    serde_json::json!({ "authorized_key": key }).to_string(),
                )
            });
            (settings.as_str(), credentials.as_str())
        }
        ProviderId::Route53 => (
            r#"{"access_key_id":"AKIAZWTEST0000000001","base_url":"http://127.0.0.1:9"}"#,
            r#"{"secret_access_key":"test-only-secret"}"#,
        ),
        ProviderId::DigitalOcean => (
            r#"{"base_url":"http://127.0.0.1:9/v2"}"#,
            r#"{"api_token":"test-only-token"}"#,
        ),
        ProviderId::AcmeDns
        | ProviderId::Beget
        | ProviderId::CloudRu
        | ProviderId::Hetzner
        | ProviderId::Nicru
        | ProviderId::Regru
        | ProviderId::Rfc2136
        | ProviderId::TimewebCloud
        | ProviderId::VkCloud
        | ProviderId::Yandex360 => ("{}", "{}"),
        _ => panic!("no sample configuration for {id}"),
    }
}

/// Builds a client of `id` from [`sample_config`].
pub fn sample_client(id: ProviderId, ctx: &Context) -> Result<AnyProvider, Error> {
    let (settings, credentials) = sample_config(id);
    AnyProvider::from_json(
        id,
        settings,
        &SecretString::from(credentials.to_owned()),
        ctx,
    )
}
