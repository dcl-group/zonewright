// PLACEHOLDER: replaced when the beget client is ported.
//! The Beget client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `beget` feature. The ported client replaces this file with
//! `BegetConfig`, `BegetCredentials` and the real `Beget`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The Beget client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct Beget {
    _private: (),
}

impl fmt::Debug for Beget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Beget").finish_non_exhaustive()
    }
}

impl Provider for Beget {
    fn id(&self) -> ProviderId {
        ProviderId::Beget
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::Beget, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Beget, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(Beget { _private: () })
}
