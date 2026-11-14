// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Tests of the HTTP transport through the public API: building a `Context`, its options, and
//! source scans. The transport itself is private to the crate; its behavior against loopback
//! servers (TLS, redirects, proxies, timeouts, the size cap, retries, rate limits, tokens,
//! secrets in errors and logs) is tested by the unit tests in `src/http/tests.rs`.

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

    #[test]
    fn a_context_is_built_outside_a_runtime() {
        // No `tokio` runtime on this thread: building the HTTP client must not need one.
        let mut options = ContextOptions::default();
        options.user_agent_suffix = Some("app/1.0".to_owned());
        assert!(Context::new(options).is_ok());
    }
}
