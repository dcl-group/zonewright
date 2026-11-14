//! The TLS configuration of the transport (design section 5.1).
//!
//! The crate builds its own `rustls::ClientConfig`: the `aws-lc-rs` provider passed explicitly,
//! safe default protocol versions, the platform certificate verifier with the extra roots of
//! `ContextOptions`, and ALPN `http/1.1`. Nothing is installed process-wide and no process-wide
//! default is consulted (decision 3). `reqwest` sets ALPN and applies a client identity only to
//! configurations it builds itself, so the crate sets ALPN here and builds a second configuration
//! with the client certificate when a client needs one.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::error::Error;
use crate::redact::Detail;

/// Text of the `Error::Config` an HTTPS request gets when the platform has no CA certificates.
pub(crate) const NO_CA_CERTIFICATES: &str = "no CA certificates are available to verify the provider's HTTPS certificate; \
     install the system CA certificates or pass extra_root_certificates";

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

/// The server certificate verifier of a context.
#[derive(Clone, Debug)]
pub(crate) struct Trust {
    verifier: Arc<dyn ServerCertVerifier>,
    /// True when the platform has no CA certificates and every certificate is rejected.
    no_ca_certificates: bool,
}

impl Trust {
    /// The platform verifier with `extra` roots. When the platform verifier cannot be built
    /// because no CA certificate is available (Unix-like systems without system CA
    /// certificates), logs one warning and returns a verifier that rejects every certificate
    /// instead of failing.
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
const PLATFORM_READS_CA_FILES: bool = cfg!(all(
    unix,
    not(target_os = "android"),
    not(target_vendor = "apple"),
    not(target_arch = "wasm32"),
));

/// Rejects every certificate: there is nothing to verify it against.
#[derive(Debug)]
struct NoCaCertificates {
    schemes: Vec<SignatureScheme>,
}

impl NoCaCertificates {
    fn error() -> rustls::Error {
        rustls::Error::General(NO_CA_CERTIFICATES.to_owned())
    }
}

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
    let mut config =
        match identity {
            None => builder.with_no_client_auth(),
            Some(ClientIdentity { chain, key }) => builder
                .with_client_auth_cert(chain, key)
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
        let trust = Trust::platform(Vec::new(), &provider).unwrap();
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
        let trust = Trust::platform(Vec::new(), &provider).unwrap();
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
