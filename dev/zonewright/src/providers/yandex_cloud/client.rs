// PLACEHOLDER: replaced when the yandex_cloud client is ported.
//! The Yandex Cloud client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `yandex_cloud` feature. The ported client replaces this file with
//! `YandexCloudConfig`, `YandexCloudCredentials` and the real `YandexCloud`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The Yandex Cloud client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct YandexCloud {
    _private: (),
}

impl fmt::Debug for YandexCloud {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("YandexCloud").finish_non_exhaustive()
    }
}

impl Provider for YandexCloud {
    fn id(&self) -> ProviderId {
        ProviderId::YandexCloud
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(
            ProviderId::YandexCloud,
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
) -> Result<YandexCloud, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(YandexCloud { _private: () })
}
