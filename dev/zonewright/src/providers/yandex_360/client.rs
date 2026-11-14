// PLACEHOLDER: replaced when the yandex_360 client is ported.
//! The Yandex 360 client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `yandex_360` feature. The ported client replaces this file with
//! `Yandex360Config`, `Yandex360Credentials` and the real `Yandex360`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The Yandex 360 client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct Yandex360 {
    _private: (),
}

impl fmt::Debug for Yandex360 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Yandex360").finish_non_exhaustive()
    }
}

impl Provider for Yandex360 {
    fn id(&self) -> ProviderId {
        ProviderId::Yandex360
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::Yandex360, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Yandex360, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(Yandex360 { _private: () })
}
