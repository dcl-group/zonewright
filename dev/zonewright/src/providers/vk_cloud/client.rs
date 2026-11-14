// PLACEHOLDER: replaced when the vk_cloud client is ported.
//! The VK Cloud client.
//!
//! Placeholder: it lets `AnyProvider`, its forwarding and `AnyProvider::from_json` be built and
//! exercised with the `vk_cloud` feature. The ported client replaces this file with
//! `VkCloudConfig`, `VkCloudCredentials` and the real `VkCloud`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::{Error, Operation};
use crate::id::ProviderId;
use crate::name::DomainName;
use crate::provider::{CheckReport, Provider};

/// The VK Cloud client.
///
/// Not ported yet: it cannot be configured, and every operation, `check` included, returns
/// [`Error::Unsupported`].
pub struct VkCloud {
    _private: (),
}

impl fmt::Debug for VkCloud {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VkCloud").finish_non_exhaustive()
    }
}

impl Provider for VkCloud {
    fn id(&self) -> ProviderId {
        ProviderId::VkCloud
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        let _ = zones;
        Err(Error::unsupported(ProviderId::VkCloud, Operation::Check))
    }
}

/// Builds the client from stored configuration. Accepts any two JSON objects and keeps nothing
/// of them.
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<VkCloud, Error> {
    let _ = ctx;
    super::super::placeholder_json(settings, credentials)?;
    Ok(VkCloud { _private: () })
}
