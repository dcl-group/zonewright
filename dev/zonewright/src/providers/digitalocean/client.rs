// PLACEHOLDER: replaced when the digitalocean client is ported.
//! The DigitalOcean client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `digitalocean` feature. The ported client replaces this file with
//! `DigitalOceanConfig`, `DigitalOceanCredentials` and the real `DigitalOcean`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The DigitalOcean client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct DigitalOcean {
    _private: (),
}

impl fmt::Debug for DigitalOcean {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigitalOcean").finish_non_exhaustive()
    }
}

impl Provider for DigitalOcean {
    fn id(&self) -> ProviderId {
        ProviderId::DigitalOcean
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(
            ProviderId::DigitalOcean,
            Operation::Check,
        ))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<DigitalOcean, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(DigitalOcean { _private: () })
}
