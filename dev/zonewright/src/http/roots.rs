//! Root certificates compiled into the crate (design section 5.1).
//!
//! - Mozilla's root certificates, from the crate `webpki-roots` as ready trust anchors: the set of
//!   `TrustRoots::Mozilla`.
//! - The Russian Trusted Root CA of the Ministry of Digital Development and Communications of the
//!   Russian Federation, `roots/russian_trusted_root_ca.pem` in the crate directory, trusted only
//!   when `ContextOptions::russian_trusted_root` is set. Neither Mozilla's list nor a typical
//!   operating system's store has it. Subject `C=RU, O=The Ministry of Digital Development and
//!   Communications, CN=Russian Trusted Root CA`, serial number `0x1000`, valid from 2022-03-01 to
//!   2032-02-27, SHA-256 fingerprint of the DER certificate
//!   `D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31`.
//!   `roots/README.md` records where it comes from and how to replace it. The expiry is not
//!   enforced: `rustls` keeps a trust anchor as subject, public key and name constraints, without
//!   its validity dates, and checks `notBefore` and `notAfter` only for the certificates a server
//!   sends. A build that carries this file therefore keeps trusting the root after 2032-02-27. The
//!   file must be replaced by the authority's next root, or removed, in a release before that date.
//!
//! Only the root certificate is compiled in, no intermediate certificate: `rustls` turns every
//! certificate added to a root store into a trust anchor of its own, so an intermediate there
//! would be trusted without its root, and a server sends its intermediates itself.

use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, TrustAnchor};

use crate::error::Error;
use crate::redact::Detail;

/// The PEM file of the Russian Trusted Root CA, as downloaded from the official address (see
/// `roots/README.md`).
const RUSSIAN_TRUSTED_ROOT_CA_PEM: &[u8] =
    include_bytes!("../../roots/russian_trusted_root_ca.pem");

/// The Russian Trusted Root CA as a DER certificate.
pub(crate) fn russian_trusted_root() -> Result<CertificateDer<'static>, Error> {
    // The file is part of the crate and is checked by the tests below; a failure here means a
    // damaged package.
    CertificateDer::from_pem_slice(RUSSIAN_TRUSTED_ROOT_CA_PEM).map_err(|_| Error::Config {
        detail: Detail::constant("the compiled-in Russian Trusted Root CA could not be read"),
    })
}

/// Mozilla's root certificates as trust anchors.
pub(crate) fn mozilla() -> impl Iterator<Item = TrustAnchor<'static>> {
    webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
}

/// A root store with Mozilla's anchors when `mozilla` is true, followed by `extra`, each added as
/// a trust anchor of its own. `extra` was checked before (`tls::extra_roots`); a certificate that
/// is still refused here is `Error::Config`.
pub(crate) fn store(
    mozilla_roots: bool,
    extra: &[CertificateDer<'static>],
) -> Result<RootCertStore, Error> {
    let mut store = RootCertStore::empty();
    if mozilla_roots {
        store.extend(mozilla());
    }
    for cert in extra {
        store.add(cert.clone()).map_err(|_| Error::Config {
            detail: Detail::constant("a root certificate is not usable as a trust anchor"),
        })?;
    }
    Ok(store)
}

#[cfg(test)]
mod tests {
    use rustls::SupportedCipherSuite;
    use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;

    use super::*;

    /// SHA-256 of the DER certificate, published with it (see `roots/README.md`).
    const SHA256: &str = "D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31";

    /// SHA-256 with the hash of the crate's own crypto provider (`aws-lc-rs` through `rustls`),
    /// in the colon-separated form certificate tools print.
    fn sha256(data: &[u8]) -> String {
        let SupportedCipherSuite::Tls13(suite) = TLS13_AES_128_GCM_SHA256 else {
            panic!("a TLS 1.3 suite");
        };
        let digest = suite.common.hash_provider.hash(data);
        digest
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    #[test]
    fn the_file_is_exactly_one_root_certificate() {
        let all = CertificateDer::pem_slice_iter(RUSSIAN_TRUSTED_ROOT_CA_PEM)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(all.len(), 1);
        let cert = russian_trusted_root().unwrap();
        assert_eq!(all[0], cert);
        assert_eq!(sha256(&cert), SHA256);
        let mut store = RootCertStore::empty();
        store.add(cert).unwrap();
        assert_eq!(store.len(), 1);
        let subject = store.roots[0].subject.as_ref();
        assert!(
            subject
                .windows(b"Russian Trusted Root CA".len())
                .any(|w| w == b"Russian Trusted Root CA"),
            "{subject:?}"
        );
    }

    /// When this test fails, Mozilla's list has taken the root in, and the compiled-in file and
    /// the option can go.
    #[test]
    fn the_russian_root_is_not_among_mozillas() {
        let russian = store(false, &[russian_trusted_root().unwrap()]).unwrap();
        let subject = russian.roots[0].subject.as_ref();
        assert!(mozilla().count() > 100);
        assert!(mozilla().all(|anchor| anchor.subject.as_ref() != subject));
    }

    #[test]
    fn stores_add_to_mozillas_set_without_displacing_a_root() {
        let russian = russian_trusted_root().unwrap();
        let count = webpki_roots::TLS_SERVER_ROOTS.len();
        assert_eq!(store(true, &[]).unwrap().len(), count);
        let both = store(true, std::slice::from_ref(&russian)).unwrap();
        assert_eq!(both.len(), count + 1);
        assert!(both.roots[..count] == *webpki_roots::TLS_SERVER_ROOTS);
        let alone = store(false, std::slice::from_ref(&russian)).unwrap();
        assert_eq!(alone.len(), 1);
        assert!(both.roots[count] == alone.roots[0]);
        assert!(store(false, &[]).unwrap().is_empty());
    }
}
