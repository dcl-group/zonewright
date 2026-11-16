//! Reading an RSA private key from PEM, shared by the signers that use a service-account key:
//! [`Ps256Key`](super::Ps256Key) (Yandex Cloud) and [`Rs256Key`](super::Rs256Key) (Google Cloud
//! DNS).

use aws_lc_rs::signature::RsaKeyPair;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use zeroize::Zeroize;

use super::KeyError;

/// The RSA key of the first private-key section of a PEM document: "PRIVATE KEY" (PKCS#8) or
/// "RSA PRIVATE KEY" (PKCS#1); text before the section is ignored. Errors never contain key
/// material.
///
/// An "EC PRIVATE KEY" section, a PKCS#8 key of another algorithm and an RSA key outside 2048 to
/// 8192 bits are [`KeyError::UnsupportedKey`]; text without a decodable private-key section is
/// [`KeyError::Pem`].
pub(super) fn rsa_key_pair(pem: &str) -> Result<RsaKeyPair, KeyError> {
    let mut der = PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|_| KeyError::Pem)?;
    let parsed = match &der {
        PrivateKeyDer::Pkcs8(key) => {
            RsaKeyPair::from_pkcs8(key.secret_pkcs8_der()).map_err(|_| KeyError::UnsupportedKey)
        }
        PrivateKeyDer::Pkcs1(key) => {
            RsaKeyPair::from_der(key.secret_pkcs1_der()).map_err(|_| KeyError::UnsupportedKey)
        }
        _ => Err(KeyError::UnsupportedKey),
    };
    // The decoded DER is owned by `der`; wipe it now that the backend has its own copy.
    der.zeroize();
    parsed
}
