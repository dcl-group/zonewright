// PLACEHOLDER: replaced when the route53 client is ported.
//! The Route 53 client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `route53` feature. The ported client replaces this file with
//! `Route53Config`, `Route53Credentials` and the real `Route53`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The Route 53 client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct Route53 {
    _private: (),
}

impl fmt::Debug for Route53 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Route53").finish_non_exhaustive()
    }
}

impl Provider for Route53 {
    fn id(&self) -> ProviderId {
        ProviderId::Route53
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::Route53, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Route53, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(Route53 { _private: () })
}
