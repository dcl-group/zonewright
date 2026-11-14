// PLACEHOLDER: replaced when the timeweb_cloud client is ported.
//! The Timeweb Cloud client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `timeweb_cloud` feature. The ported client replaces this file with
//! `TimewebCloudConfig`, `TimewebCloudCredentials` and the real `TimewebCloud`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The Timeweb Cloud client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct TimewebCloud {
    _private: (),
}

impl fmt::Debug for TimewebCloud {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimewebCloud").finish_non_exhaustive()
    }
}

impl Provider for TimewebCloud {
    fn id(&self) -> ProviderId {
        ProviderId::TimewebCloud
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(
            ProviderId::TimewebCloud,
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
) -> Result<TimewebCloud, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(TimewebCloud { _private: () })
}
