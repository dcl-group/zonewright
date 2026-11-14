// PLACEHOLDER: replaced when the nicru client is ported.
//! The nic.ru client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `nicru` feature. The ported client replaces this file with
//! `NicruConfig`, `NicruCredentials` and the real `Nicru`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The nic.ru client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct Nicru {
    _private: (),
}

impl fmt::Debug for Nicru {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nicru").finish_non_exhaustive()
    }
}

impl Provider for Nicru {
    fn id(&self) -> ProviderId {
        ProviderId::Nicru
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::Nicru, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Nicru, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(Nicru { _private: () })
}
