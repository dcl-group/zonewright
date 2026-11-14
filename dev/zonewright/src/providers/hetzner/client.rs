// PLACEHOLDER: replaced when the hetzner client is ported.
//! The Hetzner client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `hetzner` feature. The ported client replaces this file with
//! `HetznerConfig`, `HetznerCredentials` and the real `Hetzner`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The Hetzner client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct Hetzner {
    _private: (),
}

impl fmt::Debug for Hetzner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hetzner").finish_non_exhaustive()
    }
}

impl Provider for Hetzner {
    fn id(&self) -> ProviderId {
        ProviderId::Hetzner
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::Hetzner, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Hetzner, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(Hetzner { _private: () })
}
