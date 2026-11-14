// PLACEHOLDER: replaced when the cloudflare client is ported.
//! The Cloudflare client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `cloudflare` feature. The ported client replaces this file with
//! `CloudflareConfig`, `CloudflareCredentials` and the real `Cloudflare`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The Cloudflare client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct Cloudflare {
    _private: (),
}

impl fmt::Debug for Cloudflare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cloudflare").finish_non_exhaustive()
    }
}

impl Provider for Cloudflare {
    fn id(&self) -> ProviderId {
        ProviderId::Cloudflare
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::Cloudflare, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Cloudflare, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(Cloudflare { _private: () })
}
