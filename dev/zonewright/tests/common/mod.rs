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
        ProviderId::VkCloud => (
            r#"{"project_id":"b5b7ffd4ef0547e5b222f44555df0000","username":"dns@example.test","identity_url":"http://127.0.0.1:9/identity/v3","dns_url":"http://127.0.0.1:9/public-dns/v2/dns"}"#,
            r#"{"password":"test-only-password"}"#,
        ),
        ProviderId::Yandex360 => (
            r#"{"org_id":"7654321","base_url":"http://127.0.0.1:9"}"#,
            r#"{"oauth_token":"test-only-token"}"#,
        ),
        ProviderId::Rfc2136 => (
            r#"{"server":"127.0.0.1:9","key_name":"zw-test-key"}"#,
            r#"{"secret":"em9uZXdyaWdodC1zYW1wbGUtdHNpZy1zZWNyZXQtMzI="}"#,
        ),
        ProviderId::TimewebCloud => (
            r#"{"base_url":"http://127.0.0.1:9/api"}"#,
            r#"{"token":"test-only-token"}"#,
        ),
        ProviderId::Hetzner => (
            r#"{"base_url":"http://127.0.0.1:9/v1"}"#,
            r#"{"api_token":"test-only-token"}"#,
        ),
        ProviderId::Regru => (
            r#"{"username":"zw-test-user","base_url":"http://127.0.0.1:9/api/regru2"}"#,
            r#"{"password":"test-only-password"}"#,
        ),
        ProviderId::CloudRu => (
            r#"{"project_id":"0f1e2d3c-0000-4000-8000-000000000001","key_id":"zw-test-key-id","dns_url":"http://127.0.0.1:9","iam_url":"http://127.0.0.1:9/api/v1/auth/token"}"#,
            r#"{"secret":"test-only-secret"}"#,
        ),
        ProviderId::AcmeDns => (
            r#"{"server_url":"http://127.0.0.1:9"}"#,
            r#"{"registrations":"{\"username\":\"c36f50e8-4632-4000-8000-000000000001\",\"password\":\"htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KWtest\",\"subdomain\":\"8e5700ea-a4bf-4000-8000-000000000001\",\"fulldomain\":\"8e5700ea-a4bf-4000-8000-000000000001.auth.example.org\"}"}"#,
        ),
        ProviderId::Beget => (
            r#"{"login":"zw-test-login","base_url":"http://127.0.0.1:9/api"}"#,
            r#"{"password":"test-only-password"}"#,
        ),
        ProviderId::Nicru => (
            r#"{"username":"123/NIC-REG","base_url":"http://127.0.0.1:9/dns-master","token_url":"http://127.0.0.1:9/oauth/token"}"#,
            r#"{"password":"test-only-password","client_id":"test-only-client-id","client_secret":"test-only-secret"}"#,
        ),
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
