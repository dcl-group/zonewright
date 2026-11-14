// PLACEHOLDER: replaced when the regru client is ported.
//! The reg.ru client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `regru` feature. The ported client replaces this file with
//! `RegruConfig`, `RegruCredentials` and the real `Regru`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The reg.ru client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct Regru {
    _private: (),
}

impl fmt::Debug for Regru {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Regru").finish_non_exhaustive()
    }
}

impl Provider for Regru {
    fn id(&self) -> ProviderId {
        ProviderId::Regru
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::Regru, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Regru, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(Regru { _private: () })
}
