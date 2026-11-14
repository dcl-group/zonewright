//! Helpers shared by the integration tests: context and client builders.

// Each test crate includes this module and uses a different part of it.
#![allow(dead_code)]

pub mod echo;

use secrecy::SecretString;
use zonewright::{AnyProvider, Context, ContextOptions, DomainName, Error, ProviderId};

/// A context for tests: connections to anything but loopback addresses are refused, so a test
/// that forgets to point a client at a mock fails instead of contacting a provider.
pub fn context() -> Context {
    let mut options = ContextOptions::default();
    options.loopback_only = true;
    Context::new(options).unwrap()
}

/// A domain name from text that is known to be valid.
pub fn dn(s: &str) -> DomainName {
    DomainName::parse(s).unwrap()
}

/// Settings and credentials JSON with which `AnyProvider::from_json` builds a client of `id`
/// without any request. Synthetic values only.
///
/// A placeholder client accepts any two JSON objects. When a client is ported, its developer
/// asks the lead to replace its entry with the smallest valid configuration, pointed at a
/// loopback address.
pub fn sample_config(id: ProviderId) -> (&'static str, &'static str) {
    match id {
        ProviderId::AcmeDns
        | ProviderId::Beget
        | ProviderId::CloudRu
        | ProviderId::Cloudflare
        | ProviderId::DigitalOcean
        | ProviderId::Hetzner
        | ProviderId::Nicru
        | ProviderId::Regru
        | ProviderId::Rfc2136
        | ProviderId::Route53
        | ProviderId::SelectelV2
        | ProviderId::TimewebCloud
        | ProviderId::VkCloud
        | ProviderId::Yandex360
        | ProviderId::YandexCloud => ("{}", "{}"),
        _ => panic!("no sample configuration for {id}"),
    }
}

/// Builds a client of `id` from [`sample_config`].
pub fn sample_client(id: ProviderId, ctx: &Context) -> Result<AnyProvider, Error> {
    let (settings, credentials) = sample_config(id);
    AnyProvider::from_json(
        id,
        settings,
        &SecretString::from(credentials.to_owned()),
        ctx,
    )
}
