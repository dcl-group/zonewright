// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Tests of the HTTP transport through the public API: building a `Context`, its options (the
//! proxy setting included, and a provider client that reaches its API through a proxy), and source
//! scans. The transport itself is private to the crate; its behavior against loopback servers
//! (TLS, redirects, proxies, timeouts, the size cap, retries, rate limits, tokens, secrets in
//! errors and logs) is tested by the unit tests in `src/http/tests.rs` and
//! `src/http/proxy_tests.rs`.

mod common;

use std::path::{Path, PathBuf};

use common::echo::{CANARIES, assert_clean, find_secret, spellings};

/// Every `.rs` file under `dir`.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// `RequestBuilder::bearer_auth` and `basic_auth` mark the header sensitive but build its value
/// with an ordinary `format!`, leaving an unwiped copy of the secret (design section 5.2). The
/// crate builds secret header values itself.
#[test]
fn no_source_file_uses_bearer_auth_or_basic_auth() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(files.len() > 20, "the scan found the sources");
    // Built at run time, so that this file does not match itself if it is ever scanned.
    let needles = [
        [".bearer", "_auth("].concat(),
        [".basic", "_auth("].concat(),
    ];
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap();
        for needle in &needles {
            assert!(
                !text.contains(needle.as_str()),
                "{} calls {needle}",
                path.display()
            );
        }
    }
}

#[test]
fn the_secret_test_support_spells_canaries_as_apis_echo_them() {
    let all = spellings("a b/c+@é");
    for expected in [
        "a b/c+@é",
        "a+b%2Fc%2B%40%C3%A9",
        "a%20b%2Fc%2B%40%C3%A9",
        "a b\\/c+@\\u00e9",
    ] {
        assert!(all.iter().any(|s| s == expected), "missing {expected}");
    }
    assert!(find_secret("x a+b%2Fc%2B%40%C3%A9 y", &["a b/c+@é"]).is_some());
    assert!(find_secret("x [redacted] y", &CANARIES).is_none());
    assert_clean("clean text", "nothing to see", &CANARIES);
}

#[cfg(feature = "__http")]
mod http {
    use std::time::{Duration, SystemTime};

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    use zonewright::{Context, ContextOptions, ErrorKind};

    /// A DER-encoded root CA certificate, valid around now.
    fn root_ca() -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "zonewright test root");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let epoch = rcgen::date_time_ymd(1970, 1, 1);
        params.not_before = epoch + (now - Duration::from_secs(86_400));
        params.not_after = epoch + (now + Duration::from_secs(7 * 86_400));
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    /// The context builds its own TLS configuration with an explicit provider: nothing is
    /// installed process-wide, and nothing installed is needed. This test binary installs no
    /// provider anywhere.
    #[test]
    fn a_context_needs_and_installs_no_process_wide_crypto_provider() {
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        let ctx = Context::new(ContextOptions::default()).unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        let mut options = ContextOptions::default();
        options.extra_root_certificates = vec![root_ca(), root_ca()];
        options.loopback_only = true;
        let with_roots = Context::new(options).unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        drop((ctx, with_roots));
    }

    #[test]
    fn an_invalid_extra_root_is_a_config_error_naming_its_position() {
        let mut options = ContextOptions::default();
        options.extra_root_certificates = vec![root_ca(), b"-----BEGIN CERT canary".to_vec()];
        let e = Context::new(options).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config);
        let text = format!("{e} {e:?}");
        assert!(text.contains("extra_root_certificates[1]"), "{text}");
        assert!(!text.contains("canary"), "{text}");
        let mut options = ContextOptions::default();
        options.extra_root_certificates = vec![Vec::new()];
        assert_eq!(Context::new(options).unwrap_err().kind(), ErrorKind::Config);
    }

    /// The proxy setting through the public API: refusals without echo, and `Debug` without
    /// credentials.
    #[test]
    fn a_proxy_setting_is_checked_and_printed_without_credentials() {
        use secrecy::SecretString;
        use zonewright::HttpProxy;

        let with = |url: &str, loopback_only: bool| {
            let mut options = ContextOptions::default();
            options.loopback_only = loopback_only;
            options.proxy = Some(HttpProxy::new(url.to_owned()).with_credentials(
                "proxy-user".to_owned(),
                SecretString::from("pr0xy-pa55-canary".to_owned()),
            ));
            options
        };
        for (url, loopback_only) in [
            ("http://u:url-canary@127.0.0.1:3128", false),
            ("socks4://127.0.0.1:1080", false),
            ("http://127.0.0.1:3128/url-canary", false),
            ("http://proxy.example.test:3128", true),
        ] {
            let e = Context::new(with(url, loopback_only)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Config, "{url}");
            let text = format!("{e} {e:?}");
            assert!(text.contains("proxy.url"), "{text}");
            assert!(
                !text.contains("canary") && !text.contains("example"),
                "{text}"
            );
        }
        for url in [
            "http://127.0.0.1:3128",
            "https://[::1]:8443",
            "socks5://127.0.0.1:1080",
            "socks5h://[::1]:1080",
        ] {
            let options = with(url, true);
            let ctx = Context::new(options.clone()).unwrap();
            let text = format!("{options:?} {ctx:?}");
            assert!(!text.contains("pr0xy-pa55-canary"), "{text}");
            assert!(text.contains(url), "{text}");
        }
        // Exclusions are checked; a refusal names the position, not the entry.
        let mut options = with("http://127.0.0.1:3128", true);
        options.proxy = options
            .proxy
            .map(|p| p.with_exclusions(vec!["api.example.test".to_owned(), "*".to_owned()]));
        let e = Context::new(options).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config);
        assert!(e.to_string().contains("proxy.exclusions[1]"), "{e}");
        assert!(!e.to_string().contains("example"), "{e}");
        let mut options = with("socks5h://127.0.0.1:1080", true);
        options.proxy = options.proxy.map(|p| {
            p.with_exclusions(vec![
                "api.example.test".to_owned(),
                "*.example.test".to_owned(),
                "10.0.0.0/8".to_owned(),
                "::1".to_owned(),
            ])
        });
        assert!(Context::new(options).is_ok());
        // A URL with user info is not printed, even before `Context::new` refuses it.
        let options = with("http://u:url-canary@127.0.0.1:3128", false);
        assert!(!format!("{options:?}").contains("canary"));
        // Without the setting the default is no proxy.
        assert!(ContextOptions::default().proxy.is_none());
    }

    /// A provider client built through the public API reaches its API through the proxy: the
    /// proxy gets the request with the proxy credentials, the API gets it with the provider
    /// credential and without the proxy's.
    #[cfg(feature = "cloudflare")]
    #[tokio::test]
    async fn a_provider_client_reaches_its_api_through_the_proxy() {
        use secrecy::SecretString;
        use zonewright::providers::cloudflare::{
            Cloudflare, CloudflareConfig, CloudflareCredentials,
        };
        use zonewright::{HttpProxy, Provider};
        use zonewright_mock::cloudflare::{CloudflareMock, Seed};
        use zonewright_mock::proxy::ProxyServer;

        let mock = CloudflareMock::start(Seed::standard()).await;
        let proxy = ProxyServer::start().await;
        proxy.require_basic("proxy-user", "proxy-password");
        let mut options = ContextOptions::default();
        options.loopback_only = true;
        options.proxy = Some(HttpProxy::new(proxy.url()).with_credentials(
            "proxy-user".to_owned(),
            SecretString::from("proxy-password".to_owned()),
        ));
        let ctx = Context::new(options).unwrap();
        let mut config = CloudflareConfig::default();
        config.base_url = mock.base_url();
        let credentials =
            CloudflareCredentials::new(SecretString::from("cf-test-token".to_owned()));
        let client = Cloudflare::new(config, credentials, &ctx).unwrap();
        let zones = client.list_zones().await.unwrap();
        let expected = zonewright::DomainName::parse("example.org").unwrap();
        assert!(zones.iter().any(|z| z.name == expected), "{zones:?}");
        let log = proxy.log();
        assert!(!log.is_empty());
        for entry in &log {
            assert!(entry.target.starts_with(&mock.base_url()), "{entry:?}");
            assert!(entry.header("proxy-authorization").is_some());
        }
        let api = mock.log().entries();
        assert_eq!(api.len(), log.len());
        for entry in &api {
            assert_eq!(entry.header("authorization"), Some("Bearer cf-test-token"));
            assert!(entry.header("proxy-authorization").is_none());
        }

        // Wrong proxy credentials: `ProxyAuth`, not the provider's `Auth`.
        proxy.require_basic("proxy-user", "another-password");
        let e = client.list_zones().await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ProxyAuth, "{e:?}");
        assert_eq!(e.kind().as_str(), "proxy_auth");
        assert!(!e.is_retryable());
        assert_eq!(mock.log().entries().len(), api.len());
    }

    #[test]
    fn a_context_is_built_outside_a_runtime() {
        // No `tokio` runtime on this thread: building the HTTP client must not need one.
        let mut options = ContextOptions::default();
        options.user_agent_suffix = Some("app/1.0".to_owned());
        assert!(Context::new(options).is_ok());
    }
}
