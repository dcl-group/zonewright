//! Provider clients: one module per provider, and [`AnyProvider`], which dispatches to the
//! clients compiled into this build.
//!
//! Each provider module holds the provider's metadata in every build; its client, with the
//! `…Config` and `…Credentials` types, is compiled with the provider's cargo feature. The
//! modules and their cargo features are named like the provider IDs.

use secrecy::SecretString;

use crate::context::Context;
use crate::error::Error;
use crate::id::ProviderId;
use crate::meta::ProviderMeta;
use crate::name::DomainName;
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneInfo,
    ZoneListing,
};
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};

pub mod acme_dns;
pub mod beget;
pub mod cloud_ru;
pub mod cloudflare;
pub mod digitalocean;
pub mod hetzner;
pub mod nicru;
pub mod regru;
pub mod rfc2136;
pub mod route53;
pub mod selectel_v2;
pub mod timeweb_cloud;
pub mod vk_cloud;
pub mod yandex_360;
pub mod yandex_cloud;

/// The metadata of a provider. Present for every provider in every build.
pub(crate) fn meta_of(id: ProviderId) -> &'static ProviderMeta {
    match id {
        ProviderId::AcmeDns => &acme_dns::meta::META,
        ProviderId::Beget => &beget::meta::META,
        ProviderId::CloudRu => &cloud_ru::meta::META,
        ProviderId::Cloudflare => &cloudflare::meta::META,
        ProviderId::DigitalOcean => &digitalocean::meta::META,
        ProviderId::Hetzner => &hetzner::meta::META,
        ProviderId::Nicru => &nicru::meta::META,
        ProviderId::Regru => &regru::meta::META,
        ProviderId::Rfc2136 => &rfc2136::meta::META,
        ProviderId::Route53 => &route53::meta::META,
        ProviderId::SelectelV2 => &selectel_v2::meta::META,
        ProviderId::TimewebCloud => &timeweb_cloud::meta::META,
        ProviderId::VkCloud => &vk_cloud::meta::META,
        ProviderId::Yandex360 => &yandex_360::meta::META,
        ProviderId::YandexCloud => &yandex_cloud::meta::META,
    }
}

/// One client of any provider compiled into this build.
///
/// With no provider feature enabled the enum has no variants; it still compiles, and
/// [`AnyProvider::from_json`] returns [`Error::NotCompiled`] for every ID.
#[derive(Debug)]
#[non_exhaustive]
// A client is built once and lives as long as the application uses the account; boxing the larger
// clients would add an indirection to every call to save bytes that are allocated once.
#[allow(clippy::large_enum_variant)]
pub enum AnyProvider {
    /// The acme-dns client (`acme_dns`).
    #[cfg(feature = "acme_dns")]
    AcmeDns(acme_dns::AcmeDns),
    /// The Beget client (`beget`).
    #[cfg(feature = "beget")]
    Beget(beget::Beget),
    /// The Cloud.ru client (`cloud_ru`).
    #[cfg(feature = "cloud_ru")]
    CloudRu(cloud_ru::CloudRu),
    /// The Cloudflare client (`cloudflare`).
    #[cfg(feature = "cloudflare")]
    Cloudflare(cloudflare::Cloudflare),
    /// The DigitalOcean client (`digitalocean`).
    #[cfg(feature = "digitalocean")]
    DigitalOcean(digitalocean::DigitalOcean),
    /// The Hetzner client (`hetzner`).
    #[cfg(feature = "hetzner")]
    Hetzner(hetzner::Hetzner),
    /// The nic.ru client (`nicru`).
    #[cfg(feature = "nicru")]
    Nicru(nicru::Nicru),
    /// The reg.ru client (`regru`).
    #[cfg(feature = "regru")]
    Regru(regru::Regru),
    /// The RFC 2136 client (`rfc2136`).
    #[cfg(feature = "rfc2136")]
    Rfc2136(rfc2136::Rfc2136),
    /// The Route 53 client (`route53`).
    #[cfg(feature = "route53")]
    Route53(route53::Route53),
    /// The Selectel v2 client (`selectel_v2`).
    #[cfg(feature = "selectel_v2")]
    SelectelV2(selectel_v2::SelectelV2),
    /// The Timeweb Cloud client (`timeweb_cloud`).
    #[cfg(feature = "timeweb_cloud")]
    TimewebCloud(timeweb_cloud::TimewebCloud),
    /// The VK Cloud client (`vk_cloud`).
    #[cfg(feature = "vk_cloud")]
    VkCloud(vk_cloud::VkCloud),
    /// The Yandex 360 client (`yandex_360`).
    #[cfg(feature = "yandex_360")]
    Yandex360(yandex_360::Yandex360),
    /// The Yandex Cloud client (`yandex_cloud`).
    #[cfg(feature = "yandex_cloud")]
    YandexCloud(yandex_cloud::YandexCloud),
}

/// Forwards to the client inside an [`AnyProvider`]: a `match` with one arm per provider, each
/// behind the provider's feature. With no provider compiled in the `match` has no arms.
macro_rules! forward {
    ($any:expr, $client:ident => $body:expr) => {
        match *$any {
            #[cfg(feature = "acme_dns")]
            AnyProvider::AcmeDns(ref $client) => $body,
            #[cfg(feature = "beget")]
            AnyProvider::Beget(ref $client) => $body,
            #[cfg(feature = "cloud_ru")]
            AnyProvider::CloudRu(ref $client) => $body,
            #[cfg(feature = "cloudflare")]
            AnyProvider::Cloudflare(ref $client) => $body,
            #[cfg(feature = "digitalocean")]
            AnyProvider::DigitalOcean(ref $client) => $body,
            #[cfg(feature = "hetzner")]
            AnyProvider::Hetzner(ref $client) => $body,
            #[cfg(feature = "nicru")]
            AnyProvider::Nicru(ref $client) => $body,
            #[cfg(feature = "regru")]
            AnyProvider::Regru(ref $client) => $body,
            #[cfg(feature = "rfc2136")]
            AnyProvider::Rfc2136(ref $client) => $body,
            #[cfg(feature = "route53")]
            AnyProvider::Route53(ref $client) => $body,
            #[cfg(feature = "selectel_v2")]
            AnyProvider::SelectelV2(ref $client) => $body,
            #[cfg(feature = "timeweb_cloud")]
            AnyProvider::TimewebCloud(ref $client) => $body,
            #[cfg(feature = "vk_cloud")]
            AnyProvider::VkCloud(ref $client) => $body,
            #[cfg(feature = "yandex_360")]
            AnyProvider::Yandex360(ref $client) => $body,
            #[cfg(feature = "yandex_cloud")]
            AnyProvider::YandexCloud(ref $client) => $body,
        }
    };
}

impl AnyProvider {
    /// Builds the client for `id` from stored configuration: `settings` is the text of a JSON
    /// object with the non-secret fields, `credentials` the text of a JSON object with the
    /// secret fields (see [`ProviderMeta::fields`]).
    ///
    /// This is exactly: deserialize both objects, call the client's `new`. An ID whose feature is
    /// off is [`Error::NotCompiled`]. No error quotes a configured value.
    // With no provider compiled in, every arm returns `NotCompiled` and the arguments are unused.
    // With every provider compiled in, no arm falls through and the final `NotCompiled` is
    // unreachable.
    #[cfg_attr(
        all(
            feature = "acme_dns",
            feature = "beget",
            feature = "cloud_ru",
            feature = "cloudflare",
            feature = "digitalocean",
            feature = "hetzner",
            feature = "nicru",
            feature = "regru",
            feature = "rfc2136",
            feature = "route53",
            feature = "selectel_v2",
            feature = "timeweb_cloud",
            feature = "vk_cloud",
            feature = "yandex_360",
            feature = "yandex_cloud"
        ),
        allow(unreachable_code)
    )]
    #[cfg_attr(
        not(any(
            feature = "acme_dns",
            feature = "beget",
            feature = "cloud_ru",
            feature = "cloudflare",
            feature = "digitalocean",
            feature = "hetzner",
            feature = "nicru",
            feature = "regru",
            feature = "rfc2136",
            feature = "route53",
            feature = "selectel_v2",
            feature = "timeweb_cloud",
            feature = "vk_cloud",
            feature = "yandex_360",
            feature = "yandex_cloud"
        )),
        allow(unused_variables)
    )]
    pub fn from_json(
        id: ProviderId,
        settings: &str,
        credentials: &SecretString,
        ctx: &Context,
    ) -> Result<AnyProvider, Error> {
        // An arm returns the client when its feature is on and falls through to `NotCompiled`
        // when it is off.
        match id {
            ProviderId::AcmeDns => {
                #[cfg(feature = "acme_dns")]
                return acme_dns::from_json(settings, credentials, ctx).map(AnyProvider::AcmeDns);
            }
            ProviderId::Beget => {
                #[cfg(feature = "beget")]
                return beget::from_json(settings, credentials, ctx).map(AnyProvider::Beget);
            }
            ProviderId::CloudRu => {
                #[cfg(feature = "cloud_ru")]
                return cloud_ru::from_json(settings, credentials, ctx).map(AnyProvider::CloudRu);
            }
            ProviderId::Cloudflare => {
                #[cfg(feature = "cloudflare")]
                return cloudflare::from_json(settings, credentials, ctx)
                    .map(AnyProvider::Cloudflare);
            }
            ProviderId::DigitalOcean => {
                #[cfg(feature = "digitalocean")]
                return digitalocean::from_json(settings, credentials, ctx)
                    .map(AnyProvider::DigitalOcean);
            }
            ProviderId::Hetzner => {
                #[cfg(feature = "hetzner")]
                return hetzner::from_json(settings, credentials, ctx).map(AnyProvider::Hetzner);
            }
            ProviderId::Nicru => {
                #[cfg(feature = "nicru")]
                return nicru::from_json(settings, credentials, ctx).map(AnyProvider::Nicru);
            }
            ProviderId::Regru => {
                #[cfg(feature = "regru")]
                return regru::from_json(settings, credentials, ctx).map(AnyProvider::Regru);
            }
            ProviderId::Rfc2136 => {
                #[cfg(feature = "rfc2136")]
                return rfc2136::from_json(settings, credentials, ctx).map(AnyProvider::Rfc2136);
            }
            ProviderId::Route53 => {
                #[cfg(feature = "route53")]
                return route53::from_json(settings, credentials, ctx).map(AnyProvider::Route53);
            }
            ProviderId::SelectelV2 => {
                #[cfg(feature = "selectel_v2")]
                return selectel_v2::from_json(settings, credentials, ctx)
                    .map(AnyProvider::SelectelV2);
            }
            ProviderId::TimewebCloud => {
                #[cfg(feature = "timeweb_cloud")]
                return timeweb_cloud::from_json(settings, credentials, ctx)
                    .map(AnyProvider::TimewebCloud);
            }
            ProviderId::VkCloud => {
                #[cfg(feature = "vk_cloud")]
                return vk_cloud::from_json(settings, credentials, ctx).map(AnyProvider::VkCloud);
            }
            ProviderId::Yandex360 => {
                #[cfg(feature = "yandex_360")]
                return yandex_360::from_json(settings, credentials, ctx)
                    .map(AnyProvider::Yandex360);
            }
            ProviderId::YandexCloud => {
                #[cfg(feature = "yandex_cloud")]
                return yandex_cloud::from_json(settings, credentials, ctx)
                    .map(AnyProvider::YandexCloud);
            }
        }
        Err(Error::not_compiled(id))
    }
}

// With no provider compiled in, every method is an empty `match` and its arguments are unused.
#[cfg_attr(
    not(any(
        feature = "acme_dns",
        feature = "beget",
        feature = "cloud_ru",
        feature = "cloudflare",
        feature = "digitalocean",
        feature = "hetzner",
        feature = "nicru",
        feature = "regru",
        feature = "rfc2136",
        feature = "route53",
        feature = "selectel_v2",
        feature = "timeweb_cloud",
        feature = "vk_cloud",
        feature = "yandex_360",
        feature = "yandex_cloud"
    )),
    allow(unused_variables)
)]
impl Provider for AnyProvider {
    fn id(&self) -> ProviderId {
        forward!(self, client => client.id())
    }

    async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        forward!(self, client => client.check(zones).await)
    }

    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        forward!(self, client => client.list_zones().await)
    }

    async fn list_rrsets(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        forward!(self, client => client.list_rrsets(zone).await)
    }

    async fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Option<RrSet>, Error> {
        forward!(self, client => client.get_rrset(zone, name, rtype).await)
    }

    async fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> Result<SetOutcome, Error> {
        forward!(self, client => client.set_rrset(zone, rrset, expect).await)
    }

    async fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        expect: Expect<'_>,
    ) -> Result<DeleteOutcome, Error> {
        forward!(self, client => client.delete_rrset(zone, name, rtype, expect).await)
    }

    async fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<RrsetTtl>,
    ) -> Result<AddOutcome, Error> {
        forward!(self, client => client.add_txt_value(zone, name, value, ttl).await)
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        forward!(self, client => client.remove_txt_value(zone, name, value).await)
    }
}

#[cfg(feature = "acme_dns")]
impl From<acme_dns::AcmeDns> for AnyProvider {
    fn from(client: acme_dns::AcmeDns) -> AnyProvider {
        AnyProvider::AcmeDns(client)
    }
}

#[cfg(feature = "beget")]
impl From<beget::Beget> for AnyProvider {
    fn from(client: beget::Beget) -> AnyProvider {
        AnyProvider::Beget(client)
    }
}

#[cfg(feature = "cloud_ru")]
impl From<cloud_ru::CloudRu> for AnyProvider {
    fn from(client: cloud_ru::CloudRu) -> AnyProvider {
        AnyProvider::CloudRu(client)
    }
}

#[cfg(feature = "cloudflare")]
impl From<cloudflare::Cloudflare> for AnyProvider {
    fn from(client: cloudflare::Cloudflare) -> AnyProvider {
        AnyProvider::Cloudflare(client)
    }
}

#[cfg(feature = "digitalocean")]
impl From<digitalocean::DigitalOcean> for AnyProvider {
    fn from(client: digitalocean::DigitalOcean) -> AnyProvider {
        AnyProvider::DigitalOcean(client)
    }
}

#[cfg(feature = "hetzner")]
impl From<hetzner::Hetzner> for AnyProvider {
    fn from(client: hetzner::Hetzner) -> AnyProvider {
        AnyProvider::Hetzner(client)
    }
}

#[cfg(feature = "nicru")]
impl From<nicru::Nicru> for AnyProvider {
    fn from(client: nicru::Nicru) -> AnyProvider {
        AnyProvider::Nicru(client)
    }
}

#[cfg(feature = "regru")]
impl From<regru::Regru> for AnyProvider {
    fn from(client: regru::Regru) -> AnyProvider {
        AnyProvider::Regru(client)
    }
}

#[cfg(feature = "rfc2136")]
impl From<rfc2136::Rfc2136> for AnyProvider {
    fn from(client: rfc2136::Rfc2136) -> AnyProvider {
        AnyProvider::Rfc2136(client)
    }
}

#[cfg(feature = "route53")]
impl From<route53::Route53> for AnyProvider {
    fn from(client: route53::Route53) -> AnyProvider {
        AnyProvider::Route53(client)
    }
}

#[cfg(feature = "selectel_v2")]
impl From<selectel_v2::SelectelV2> for AnyProvider {
    fn from(client: selectel_v2::SelectelV2) -> AnyProvider {
        AnyProvider::SelectelV2(client)
    }
}

#[cfg(feature = "timeweb_cloud")]
impl From<timeweb_cloud::TimewebCloud> for AnyProvider {
    fn from(client: timeweb_cloud::TimewebCloud) -> AnyProvider {
        AnyProvider::TimewebCloud(client)
    }
}

#[cfg(feature = "vk_cloud")]
impl From<vk_cloud::VkCloud> for AnyProvider {
    fn from(client: vk_cloud::VkCloud) -> AnyProvider {
        AnyProvider::VkCloud(client)
    }
}

#[cfg(feature = "yandex_360")]
impl From<yandex_360::Yandex360> for AnyProvider {
    fn from(client: yandex_360::Yandex360) -> AnyProvider {
        AnyProvider::Yandex360(client)
    }
}

#[cfg(feature = "yandex_cloud")]
impl From<yandex_cloud::YandexCloud> for AnyProvider {
    fn from(client: yandex_cloud::YandexCloud) -> AnyProvider {
        AnyProvider::YandexCloud(client)
    }
}
