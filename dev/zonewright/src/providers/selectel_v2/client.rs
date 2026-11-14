// PLACEHOLDER: replaced when the selectel_v2 client is ported.
//! The Selectel v2 client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `selectel_v2` feature. The ported client replaces this file with
//! `SelectelV2Config`, `SelectelV2Credentials` and the real `SelectelV2`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The Selectel v2 client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct SelectelV2 {
    _private: (),
}

impl fmt::Debug for SelectelV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectelV2").finish_non_exhaustive()
    }
}

impl Provider for SelectelV2 {
    fn id(&self) -> ProviderId {
        ProviderId::SelectelV2
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::SelectelV2, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<SelectelV2, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(SelectelV2 { _private: () })
}
