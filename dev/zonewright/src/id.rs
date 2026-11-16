//! Provider identifiers (design section 2.4).

use std::fmt;
use std::str::FromStr;

use crate::meta::ProviderMeta;

/// The identifier of a DNS hosting provider: what an application stores to remember which
/// provider an account belongs to.
///
/// The list is complete in every build, whatever features are enabled; only the client code is
/// feature-gated ([`ProviderId::available`]). The strings are listed in `PROVIDERS.md`; an
/// existing one is never renamed or reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ProviderId {
    /// acme-dns (`acme_dns`).
    AcmeDns,
    /// Beget (`beget`).
    Beget,
    /// Cloud.ru (`cloud_ru`).
    CloudRu,
    /// Cloudflare (`cloudflare`).
    Cloudflare,
    /// DigitalOcean (`digitalocean`).
    DigitalOcean,
    /// Hetzner (`hetzner`).
    Hetzner,
    /// nic.ru (`nicru`).
    Nicru,
    /// reg.ru (`regru`).
    Regru,
    /// RFC 2136 dynamic update (`rfc2136`).
    Rfc2136,
    /// Route 53 (`route53`).
    Route53,
    /// Selectel v2 (`selectel_v2`).
    SelectelV2,
    /// Timeweb Cloud (`timeweb_cloud`).
    TimewebCloud,
    /// VK Cloud (`vk_cloud`).
    VkCloud,
    /// Yandex 360 (`yandex_360`).
    Yandex360,
    /// Yandex Cloud (`yandex_cloud`).
    YandexCloud,
}

impl ProviderId {
    /// Every identifier, in alphabetical order of the persisted strings. Complete in every build.
    pub const ALL: &'static [ProviderId] = &[
        ProviderId::AcmeDns,
        ProviderId::Beget,
        ProviderId::CloudRu,
        ProviderId::Cloudflare,
        ProviderId::DigitalOcean,
        ProviderId::Hetzner,
        ProviderId::Nicru,
        ProviderId::Regru,
        ProviderId::Rfc2136,
        ProviderId::Route53,
        ProviderId::SelectelV2,
        ProviderId::TimewebCloud,
        ProviderId::VkCloud,
        ProviderId::Yandex360,
        ProviderId::YandexCloud,
    ];

    /// The persisted string. Never changes for an existing variant.
    ///
    /// This `match` and the one in [`ProviderId::parse`] are the only tables that map a variant to
    /// its string and back.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ProviderId::AcmeDns => "acme_dns",
            ProviderId::Beget => "beget",
            ProviderId::CloudRu => "cloud_ru",
            ProviderId::Cloudflare => "cloudflare",
            ProviderId::DigitalOcean => "digitalocean",
            ProviderId::Hetzner => "hetzner",
            ProviderId::Nicru => "nicru",
            ProviderId::Regru => "regru",
            ProviderId::Rfc2136 => "rfc2136",
            ProviderId::Route53 => "route53",
            ProviderId::SelectelV2 => "selectel_v2",
            ProviderId::TimewebCloud => "timeweb_cloud",
            ProviderId::VkCloud => "vk_cloud",
            ProviderId::Yandex360 => "yandex_360",
            ProviderId::YandexCloud => "yandex_cloud",
        }
    }

    /// Exact, case-sensitive match of [`ProviderId::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<ProviderId> {
        let id = match s {
            "acme_dns" => ProviderId::AcmeDns,
            "beget" => ProviderId::Beget,
            "cloud_ru" => ProviderId::CloudRu,
            "cloudflare" => ProviderId::Cloudflare,
            "digitalocean" => ProviderId::DigitalOcean,
            "hetzner" => ProviderId::Hetzner,
            "nicru" => ProviderId::Nicru,
            "regru" => ProviderId::Regru,
            "rfc2136" => ProviderId::Rfc2136,
            "route53" => ProviderId::Route53,
            "selectel_v2" => ProviderId::SelectelV2,
            "timeweb_cloud" => ProviderId::TimewebCloud,
            "vk_cloud" => ProviderId::VkCloud,
            "yandex_360" => ProviderId::Yandex360,
            "yandex_cloud" => ProviderId::YandexCloud,
            _ => return None,
        };
        Some(id)
    }

    /// The client for this provider is compiled into this build: its cargo feature, named like
    /// the identifier, is enabled.
    #[must_use]
    pub const fn available(self) -> bool {
        match self {
            ProviderId::AcmeDns => cfg!(feature = "acme_dns"),
            ProviderId::Beget => cfg!(feature = "beget"),
            ProviderId::CloudRu => cfg!(feature = "cloud_ru"),
            ProviderId::Cloudflare => cfg!(feature = "cloudflare"),
            ProviderId::DigitalOcean => cfg!(feature = "digitalocean"),
            ProviderId::Hetzner => cfg!(feature = "hetzner"),
            ProviderId::Nicru => cfg!(feature = "nicru"),
            ProviderId::Regru => cfg!(feature = "regru"),
            ProviderId::Rfc2136 => cfg!(feature = "rfc2136"),
            ProviderId::Route53 => cfg!(feature = "route53"),
            ProviderId::SelectelV2 => cfg!(feature = "selectel_v2"),
            ProviderId::TimewebCloud => cfg!(feature = "timeweb_cloud"),
            ProviderId::VkCloud => cfg!(feature = "vk_cloud"),
            ProviderId::Yandex360 => cfg!(feature = "yandex_360"),
            ProviderId::YandexCloud => cfg!(feature = "yandex_cloud"),
        }
    }

    /// The provider's metadata. Present for every provider in every build.
    #[must_use]
    pub fn meta(self) -> &'static ProviderMeta {
        crate::providers::meta_of(self)
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProviderId {
    type Err = UnknownProviderId;

    fn from_str(s: &str) -> Result<ProviderId, UnknownProviderId> {
        ProviderId::parse(s).ok_or_else(|| UnknownProviderId::new(s))
    }
}

impl serde::Serialize for ProviderId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ProviderId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = ProviderId;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a provider ID string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<ProviderId, E> {
                v.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

/// Most bytes of the rejected input an [`UnknownProviderId`] keeps.
const ECHO_MAX_BYTES: usize = 64;

/// A string that is not a provider ID.
///
/// It keeps at most 64 bytes of the input, cut on a character boundary, and prints them escaped,
/// so a long or hostile string cannot flood or break a log line.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown provider ID {0:?}")]
pub struct UnknownProviderId(String);

impl UnknownProviderId {
    fn new(input: &str) -> UnknownProviderId {
        let mut end = input.len().min(ECHO_MAX_BYTES);
        while !input.is_char_boundary(end) {
            end -= 1;
        }
        UnknownProviderId(input.get(..end).unwrap_or_default().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{ProviderId, UnknownProviderId};

    #[test]
    fn unknown_id_echo_is_bounded() {
        let err: UnknownProviderId = "ж".repeat(100).parse::<ProviderId>().unwrap_err();
        assert!(err.0.len() <= 64);
        let shown = err.to_string();
        assert!(shown.starts_with("unknown provider ID "));
        let err = "a\nb".parse::<ProviderId>().unwrap_err();
        assert!(!err.to_string().contains('\n'));
    }
}
