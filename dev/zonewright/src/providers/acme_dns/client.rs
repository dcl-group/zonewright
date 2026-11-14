// PLACEHOLDER: replaced when the acme_dns client is ported.
//! The acme-dns client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `acme_dns` feature. The ported client replaces this file with
//! `AcmeDnsConfig`, `AcmeDnsCredentials` and the real `AcmeDns`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The acme-dns client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct AcmeDns {
    _private: (),
}

impl fmt::Debug for AcmeDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeDns").finish_non_exhaustive()
    }
}

impl Provider for AcmeDns {
    fn id(&self) -> ProviderId {
        ProviderId::AcmeDns
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::AcmeDns, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<AcmeDns, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(AcmeDns { _private: () })
}
