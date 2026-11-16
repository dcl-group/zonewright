//! The TLS configuration of the transport (design section 5.1).
//!
//! The crate builds its own `rustls::ClientConfig`: the `aws-lc-rs` provider passed explicitly,
//! safe default protocol versions, the certificate verifier of [`Trust`], and ALPN `http/1.1`.
//! Nothing is installed process-wide and no process-wide default is consulted (decision 3).
//! `reqwest` sets ALPN and applies a client identity only to configurations it builds itself, so
//! the crate sets ALPN here and builds a second configuration with the client certificate when a
//! client needs one.
//!
//! The trust anchors are those `ContextOptions` selects:
//!
//! - `TrustRoots::Mozilla` and `TrustRoots::None`: `rustls`'s WebPKI verifier, built with
//!   `WebPkiServerVerifier::builder_with_provider` and the crate's provider, over a root store of
//!   Mozilla's roots (or none), the Russian Trusted Root CA when
//!   `ContextOptions::russian_trusted_root` is set, and `ContextOptions::extra_root_certificates`
//!   ([`super::roots`]). No file of the operating system is read and no platform API is called.
//!   Revocation is not checked (the builder's default).
//! - `TrustRoots::Platform`, with the `platform-verifier` feature: the platform verifier of
//!   `rustls-platform-verifier`, with the Russian root and the extra roots as its additional
//!   roots. Without the feature it is `Error::Config`.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
#[cfg(feature = "platform-verifier")]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore};
#[cfg(feature = "platform-verifier")]
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(feature = "platform-verifier")]
use rustls_pki_types::{ServerName, UnixTime};

use zeroize::Zeroize as _;

use crate::context::{ContextOptions, TrustRoots};
use crate::error::Error;
use crate::redact::Detail;

use super::roots;

/// Text of the `Error::Config` an HTTPS request gets when the platform has no CA certificates
/// (`TrustRoots::Platform` only).
pub(crate) const NO_CA_CERTIFICATES: &str = "no CA certificates are available to verify the provider's HTTPS certificate; \
     install the system CA certificates, pass extra_root_certificates, or use trust_roots Mozilla";

/// Text of the `Error::Config` of `TrustRoots::None` without any root certificate.
const NO_ROOTS: &str = "trust_roots is None and no root certificate was given";

/// Text of the `Error::Config` of `TrustRoots::Platform` in a build without the feature.
#[cfg(not(feature = "platform-verifier"))]
const PLATFORM_NEEDS_FEATURE: &str =
    "trust_roots is Platform, which needs the `platform-verifier` feature of this crate";

/// The crypto provider of every TLS configuration of the crate: `aws-lc-rs`, passed explicitly.
pub(crate) fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Checks and converts `ContextOptions::extra_root_certificates`. An entry that is not a DER
/// certificate usable as a trust anchor is `Error::Config`, named by its position.
pub(crate) fn extra_roots(certs: &[Vec<u8>]) -> Result<Vec<CertificateDer<'static>>, Error> {
    let mut out = Vec::with_capacity(certs.len());
    for (i, der) in certs.iter().enumerate() {
        let cert = CertificateDer::from(der.clone());
        if RootCertStore::empty().add(cert.clone()).is_err() {
            return Err(Error::Config {
                detail: Detail::new(&format!(
                    "extra_root_certificates[{i}] is not a DER-encoded certificate usable as a trust anchor"
                )),
            });
        }
        out.push(cert);
    }
    Ok(out)
}

/// The roots the options add to the set of `trust_roots`: the Russian Trusted Root CA when
/// `russian_trusted_root` is set, then `extra_root_certificates`, checked.
fn added_roots(options: &ContextOptions) -> Result<Vec<CertificateDer<'static>>, Error> {
    let mut extra = extra_roots(&options.extra_root_certificates)?;
    if options.russian_trusted_root {
        extra.insert(0, roots::russian_trusted_root()?);
    }
    Ok(extra)
}

/// The root store of the WebPKI verifier: Mozilla's roots for `TrustRoots::Mozilla`, none
/// otherwise, then `added`.
fn webpki_store(
    trust_roots: TrustRoots,
    added: &[CertificateDer<'static>],
) -> Result<RootCertStore, Error> {
    roots::store(trust_roots == TrustRoots::Mozilla, added)
}

/// The server certificate verifier of a context.
#[derive(Clone, Debug)]
pub(crate) struct Trust {
    verifier: Arc<dyn ServerCertVerifier>,
    /// True when the platform has no CA certificates and every certificate is rejected.
    no_ca_certificates: bool,
}

impl Trust {
    /// The verifier `options` select (see the module documentation). Checks
    /// `extra_root_certificates` first.
    pub(crate) fn from_options(
        options: &ContextOptions,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Trust, Error> {
        let extra = added_roots(options)?;
        match options.trust_roots {
            TrustRoots::Mozilla | TrustRoots::None => {
                Trust::webpki(webpki_store(options.trust_roots, &extra)?, provider)
            }
            #[cfg(feature = "platform-verifier")]
            TrustRoots::Platform => Trust::platform(extra, provider),
            #[cfg(not(feature = "platform-verifier"))]
            TrustRoots::Platform => Err(Error::Config {
                detail: Detail::constant(PLATFORM_NEEDS_FEATURE),
            }),
        }
    }

    /// `rustls`'s WebPKI verifier over `store`, with the crate's provider. An empty store is
    /// `Error::Config`: nothing could ever be verified.
    fn webpki(store: RootCertStore, provider: &Arc<CryptoProvider>) -> Result<Trust, Error> {
        if store.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant(NO_ROOTS),
            });
        }
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider.clone())
                .build()
                .map_err(|_| Error::Config {
                    detail: Detail::constant("the certificate verifier could not be built"),
                })?;
        Ok(Trust {
            verifier,
            no_ca_certificates: false,
        })
    }

    /// The platform verifier with `extra` roots. When the platform verifier cannot be built
    /// because no CA certificate is available (Unix-like systems without system CA
    /// certificates), logs one warning and returns a verifier that rejects every certificate
    /// instead of failing.
    #[cfg(feature = "platform-verifier")]
    pub(crate) fn platform(
        extra: Vec<CertificateDer<'static>>,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Trust, Error> {
        let extra_given = !extra.is_empty();
        let result =
            rustls_platform_verifier::Verifier::new_with_extra_roots(extra, provider.clone());
        Trust::from_result(
            result.map(|v| Arc::new(v) as Arc<dyn ServerCertVerifier>),
            extra_given,
            PLATFORM_READS_CA_FILES,
            provider,
        )
    }

    /// Decides what a failure to build the platform verifier means.
    ///
    /// `rustls-platform-verifier` 0.7.1 fails on Unix-like systems other than Apple's and
    /// Android when no CA certificate could be loaded and no extra root was given
    /// (`verification/others.rs`). The extra roots were checked before, so on those systems a
    /// failure without extra roots is that condition. Any other failure is `Error::Config`.
    #[cfg(feature = "platform-verifier")]
    fn from_result(
        result: Result<Arc<dyn ServerCertVerifier>, rustls::Error>,
        extra_given: bool,
        platform_reads_ca_files: bool,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Trust, Error> {
        match result {
            Ok(verifier) => Ok(Trust {
                verifier,
                no_ca_certificates: false,
            }),
            Err(_) if platform_reads_ca_files && !extra_given => {
                tracing::warn!(
                    target: "zonewright::http",
                    "no system CA certificates are available; HTTPS requests to providers will fail"
                );
                Ok(Trust::reject_all(provider))
            }
            Err(_) => Err(Error::Config {
                detail: Detail::constant("the platform certificate verifier could not be built"),
            }),
        }
    }

    /// A verifier that rejects every certificate, for a platform without CA certificates.
    #[cfg(feature = "platform-verifier")]
    pub(crate) fn reject_all(provider: &Arc<CryptoProvider>) -> Trust {
        Trust {
            verifier: Arc::new(NoCaCertificates {
                schemes: provider
                    .signature_verification_algorithms
                    .supported_schemes(),
            }),
            no_ca_certificates: true,
        }
    }

    /// True when every certificate is rejected because no CA certificate is available.
    pub(crate) fn no_ca_certificates(&self) -> bool {
        self.no_ca_certificates
    }
}

/// Whether `rustls-platform-verifier` reads CA files on this target, and so can fail for want
/// of them: Unix-like systems other than Apple's and Android.
#[cfg(feature = "platform-verifier")]
const PLATFORM_READS_CA_FILES: bool = cfg!(all(
    unix,
    not(target_os = "android"),
    not(target_vendor = "apple"),
    not(target_arch = "wasm32"),
));

/// Rejects every certificate: there is nothing to verify it against.
#[cfg(feature = "platform-verifier")]
#[derive(Debug)]
struct NoCaCertificates {
    schemes: Vec<SignatureScheme>,
}

#[cfg(feature = "platform-verifier")]
impl NoCaCertificates {
    fn error() -> rustls::Error {
        rustls::Error::General(NO_CA_CERTIFICATES.to_owned())
    }
}

#[cfg(feature = "platform-verifier")]
impl ServerCertVerifier for NoCaCertificates {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Err(NoCaCertificates::error())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(NoCaCertificates::error())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(NoCaCertificates::error())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// A TLS client certificate chain and its private key.
pub(crate) struct ClientIdentity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Drop for ClientIdentity {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("certificates", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl ClientIdentity {
    /// Reads the certificate chain (one or more `CERTIFICATE` sections, leaf first) and the
    /// private key (PKCS#8, PKCS#1 or SEC1) from PEM. Text outside the sections is ignored.
    /// Failures name the setting and quote nothing.
    pub(crate) fn from_pem(cert_pem: &str, key_pem: &str) -> Result<ClientIdentity, Error> {
        let chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .ok()
            .filter(|chain| !chain.is_empty())
            .ok_or(Error::Config {
                detail: Detail::constant(
                    "the client certificate is not a PEM document with a CERTIFICATE section",
                ),
            })?;
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|_| Error::Config {
            detail: Detail::constant(
                "the client certificate key is not a PEM document with a private key section",
            ),
        })?;
        Ok(ClientIdentity { chain, key })
    }
}

/// The `rustls` configuration of one HTTP client: explicit provider, safe default protocol
/// versions, `trust`'s verifier, ALPN `http/1.1`, and the client certificate if one is given.
pub(crate) fn client_config(
    provider: &Arc<CryptoProvider>,
    trust: &Trust,
    identity: Option<ClientIdentity>,
) -> Result<ClientConfig, Error> {
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Config {
            detail: Detail::constant("the TLS configuration could not be built"),
        })?
        .dangerous()
        .with_custom_certificate_verifier(trust.verifier.clone());
    let mut config = match identity {
        None => builder.with_no_client_auth(),
        // rustls takes the key by value, parses it with aws-lc-rs and drops the DER without
        // wiping it; `PrivateKeyDer` has no wiping `Drop`. It gets a copy, and the copy this
        // crate holds is wiped when `identity` drops at the end of this function. The parsed
        // key then lives in aws-lc-rs memory for the life of the client.
        Some(identity) => builder
            .with_client_auth_cert(identity.chain.clone(), identity.key.clone_key())
            .map_err(|_| Error::Config {
                detail: Detail::constant(
                    "the client certificate and its key cannot be used together for TLS",
                ),
            })?,
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn extra_roots_are_checked_by_position() {
        let (ca, _) = crate::http::testing::ca();
        assert_eq!(extra_roots(&[ca.der().to_vec()]).unwrap().len(), 1);
        let e = extra_roots(&[ca.der().to_vec(), b"not a certificate".to_vec()]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config);
        assert!(e.to_string().contains("extra_root_certificates[1]"), "{e}");
        assert!(extra_roots(&[]).unwrap().is_empty());
    }

    /// The default verifier: Mozilla's roots, compiled in.
    fn default_trust(provider: &Arc<CryptoProvider>) -> Trust {
        Trust::from_options(&ContextOptions::default(), provider).unwrap()
    }

    #[test]
    fn trust_roots_select_the_anchors() {
        let provider = crypto_provider();
        let (ca, _) = crate::http::testing::ca();
        let options = |trust_roots, russian_trusted_root, extra_root_certificates| ContextOptions {
            trust_roots,
            russian_trusted_root,
            extra_root_certificates,
            ..ContextOptions::default()
        };
        for (trust_roots, russian, extra) in [
            (TrustRoots::Mozilla, false, Vec::new()),
            (TrustRoots::Mozilla, true, vec![ca.der().to_vec()]),
            (TrustRoots::None, true, Vec::new()),
            (TrustRoots::None, false, vec![ca.der().to_vec()]),
        ] {
            let trust =
                Trust::from_options(&options(trust_roots, russian, extra), &provider).unwrap();
            assert!(!trust.no_ca_certificates());
        }
        // The stores behind the WebPKI verifier.
        let mozilla = webpki_roots::TLS_SERVER_ROOTS.len();
        for (trust_roots, russian, extra, len) in [
            (TrustRoots::None, true, Vec::new(), 1),
            (TrustRoots::None, true, vec![ca.der().to_vec()], 2),
            (TrustRoots::None, false, Vec::new(), 0),
            (TrustRoots::Mozilla, false, Vec::new(), mozilla),
            (TrustRoots::Mozilla, true, Vec::new(), mozilla + 1),
            (
                TrustRoots::Mozilla,
                true,
                vec![ca.der().to_vec()],
                mozilla + 2,
            ),
        ] {
            let options = options(trust_roots, russian, extra);
            let store = webpki_store(trust_roots, &added_roots(&options).unwrap()).unwrap();
            assert_eq!(store.len(), len, "{trust_roots:?} {russian}");
        }
        // Nothing to verify against.
        let e = Trust::from_options(&options(TrustRoots::None, false, Vec::new()), &provider)
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config);
        assert_eq!(
            e.to_string(),
            "invalid provider configuration: trust_roots is None and no root certificate was given"
        );
        // The extra roots are checked first, whatever the set.
        for trust_roots in [TrustRoots::Mozilla, TrustRoots::None, TrustRoots::Platform] {
            let e = Trust::from_options(
                &options(trust_roots, true, vec![b"not a certificate".to_vec()]),
                &provider,
            )
            .unwrap_err();
            assert!(e.to_string().contains("extra_root_certificates[0]"), "{e}");
        }
    }

    #[cfg(not(feature = "platform-verifier"))]
    #[test]
    fn the_platform_set_needs_the_feature() {
        let options = ContextOptions {
            trust_roots: TrustRoots::Platform,
            ..ContextOptions::default()
        };
        let e = Trust::from_options(&options, &crypto_provider()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config);
        assert!(
            e.to_string()
                .contains("trust_roots is Platform, which needs the `platform-verifier` feature"),
            "{e}"
        );
    }

    #[cfg(feature = "platform-verifier")]
    #[test]
    fn the_platform_set_builds_with_the_feature() {
        let (ca, _) = crate::http::testing::ca();
        let options = ContextOptions {
            trust_roots: TrustRoots::Platform,
            russian_trusted_root: true,
            extra_root_certificates: vec![ca.der().to_vec()],
            ..ContextOptions::default()
        };
        assert!(Trust::from_options(&options, &crypto_provider()).is_ok());
    }

    #[cfg(feature = "platform-verifier")]
    #[test]
    fn missing_ca_certificates_give_a_rejecting_verifier() {
        let provider = crypto_provider();
        let failed = || Err(rustls::Error::General("No CA certificates".to_owned()));
        let trust = Trust::from_result(failed(), false, true, &provider).unwrap();
        assert!(trust.no_ca_certificates());
        // With extra roots, or on a platform that does not read CA files, it is a hard error.
        for (extra, reads) in [(true, true), (false, false)] {
            let e = Trust::from_result(failed(), extra, reads, &provider).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Config);
        }
        let ok = Trust::platform(Vec::new(), &provider);
        // Builds on every platform: with system CA certificates, or as the rejecting verifier.
        assert!(ok.is_ok());
    }

    #[test]
    fn config_has_alpn_http1_and_the_explicit_provider() {
        let provider = crypto_provider();
        let trust = default_trust(&provider);
        let config = client_config(&provider, &trust, None).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(Arc::ptr_eq(config.crypto_provider(), &provider));
        assert!(!config.client_auth_cert_resolver.has_certs());
        assert!(CryptoProvider::get_default().is_none());
    }

    #[test]
    fn client_identity_from_pem() {
        let (_, _, cert_pem, key_pem) = crate::http::testing::client_cert();
        let provider = crypto_provider();
        let trust = default_trust(&provider);
        let identity = ClientIdentity::from_pem(&cert_pem, &key_pem).unwrap();
        assert!(!format!("{identity:?}").contains("BEGIN"));
        let config = client_config(&provider, &trust, Some(identity)).unwrap();
        assert!(config.client_auth_cert_resolver.has_certs());
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
        for (cert, key) in [
            ("", key_pem.as_str()),
            ("garbage", key_pem.as_str()),
            (cert_pem.as_str(), ""),
            (
                cert_pem.as_str(),
                "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            ),
        ] {
            let e = ClientIdentity::from_pem(cert, key)
                .and_then(|id| client_config(&provider, &trust, Some(id)))
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Config);
            assert!(!e.to_string().contains("BEGIN"), "{e}");
        }
    }
}
