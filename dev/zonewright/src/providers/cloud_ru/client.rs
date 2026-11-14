// PLACEHOLDER: replaced when the cloud_ru client is ported.
//! The Cloud.ru client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `cloud_ru` feature. The ported client replaces this file with
//! `CloudRuConfig`, `CloudRuCredentials` and the real `CloudRu`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The Cloud.ru client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct CloudRu {
    _private: (),
}

impl fmt::Debug for CloudRu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudRu").finish_non_exhaustive()
    }
}

impl Provider for CloudRu {
    fn id(&self) -> ProviderId {
        ProviderId::CloudRu
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::CloudRu, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<CloudRu, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(CloudRu { _private: () })
}
