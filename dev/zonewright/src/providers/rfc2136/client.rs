// PLACEHOLDER: replaced when the rfc2136 client is ported.
//! The RFC 2136 client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `rfc2136` feature. The ported client replaces this file with
//! `Rfc2136Config`, `Rfc2136Credentials` and the real `Rfc2136`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The RFC 2136 client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct Rfc2136 {
    _private: (),
}

impl fmt::Debug for Rfc2136 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rfc2136").finish_non_exhaustive()
    }
}

impl Provider for Rfc2136 {
    fn id(&self) -> ProviderId {
        ProviderId::Rfc2136
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::Rfc2136, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Rfc2136, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(Rfc2136 { _private: () })
}
