//! Time to live: the number ([`Ttl`]) and the TTL of an rrset ([`RrsetTtl`]), which is a number
//! or the provider's default.

use std::fmt;
use std::time::Duration;

use super::RecordError;

/// Time to live in seconds, 0 ..= 2^31 - 1 (RFC 2181 section 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ttl(u32);

impl Ttl {
    /// The largest TTL, 2^31 - 1 seconds.
    pub const MAX: Ttl = Ttl(0x7fff_ffff);

    /// Fails with `OutOfRange` above [`Ttl::MAX`].
    pub fn from_secs(secs: u32) -> Result<Ttl, RecordError> {
        if secs > Ttl::MAX.0 {
            return Err(RecordError::OutOfRange { field: "ttl" });
        }
        Ok(Ttl(secs))
    }

    /// The TTL in seconds.
    pub const fn as_secs(self) -> u32 {
        self.0
    }

    /// `secs` seconds, or [`Ttl::MAX`] above it. For the defaults of the `ttl` settings, which
    /// are constants within range.
    #[cfg_attr(
        not(any(
            feature = "beget",
            feature = "cloud_ru",
            feature = "cloudflare",
            feature = "digitalocean",
            feature = "edgecenter",
            feature = "gcore",
            feature = "hetzner",
            feature = "nicru",
            feature = "rfc2136",
            feature = "route53",
            feature = "selectel_v2",
            feature = "vk_cloud",
            feature = "yandex_360",
            feature = "yandex_cloud"
        )),
        allow(dead_code)
    )]
    pub(crate) const fn clamped(secs: u32) -> Ttl {
        if secs > Ttl::MAX.0 {
            Ttl::MAX
        } else {
            Ttl(secs)
        }
    }
}

impl From<Ttl> for Duration {
    fn from(ttl: Ttl) -> Duration {
        Duration::from_secs(u64::from(ttl.0))
    }
}

impl TryFrom<Duration> for Ttl {
    type Error = RecordError;

    /// Whole seconds only; a sub-second part or a value above [`Ttl::MAX`] is `OutOfRange`.
    fn try_from(duration: Duration) -> Result<Ttl, RecordError> {
        if duration.subsec_nanos() != 0 {
            return Err(RecordError::OutOfRange { field: "ttl" });
        }
        let secs = u32::try_from(duration.as_secs())
            .map_err(|_| RecordError::OutOfRange { field: "ttl" })?;
        Ttl::from_secs(secs)
    }
}

impl serde::Serialize for Ttl {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Ttl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let secs = u32::deserialize(deserializer)?;
        Ttl::from_secs(secs).map_err(serde::de::Error::custom)
    }
}

/// The TTL of an rrset: an explicit number of seconds, or the provider's default.
///
/// Some providers let an rrset or a record have no TTL of its own (an "automatic" TTL, or a
/// zone default that applies while none is stored); [`Capabilities::provider_default_ttl`]
/// says where. Such an rrset reads as `Some(RrsetTtl::ProviderDefault)`, and a write can ask
/// for it the same way. Where a TTL is stated at all, it is one of these two; an rrset whose
/// TTL is not stated (a read that cannot tell, a write that leaves the TTL alone) has
/// `RrSet::ttl() == None`.
///
/// Serialized as the number of seconds, or as the string `"provider_default"`: the same
/// spelling in an rrset and in the `ttl` setting of every provider's configuration.
///
/// [`Capabilities::provider_default_ttl`]: crate::Capabilities::provider_default_ttl
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RrsetTtl {
    /// This TTL.
    Explicit(Ttl),
    /// No TTL of the caller's: the provider's default applies (Cloudflare's "automatic", the
    /// zone default of Hetzner, nic.ru and Timeweb Cloud, the TTL a provider that sets every
    /// TTL itself chooses).
    ProviderDefault,
}

/// The serialized spelling of [`RrsetTtl::ProviderDefault`].
const PROVIDER_DEFAULT: &str = "provider_default";

impl RrsetTtl {
    /// An explicit TTL of `secs` seconds. Fails with `OutOfRange` above [`Ttl::MAX`].
    pub fn from_secs(secs: u32) -> Result<RrsetTtl, RecordError> {
        Ttl::from_secs(secs).map(RrsetTtl::Explicit)
    }

    /// The explicit TTL; `None` for the provider's default.
    #[must_use]
    pub const fn explicit(self) -> Option<Ttl> {
        match self {
            RrsetTtl::Explicit(ttl) => Some(ttl),
            RrsetTtl::ProviderDefault => None,
        }
    }

    /// The TTL an rrset whose records state their own reads with (design section 3.6): the
    /// smallest explicit TTL among them; when none states a number but one states the
    /// provider's default, the provider's default; `None` when no record states a TTL.
    #[cfg_attr(
        not(any(
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
        allow(dead_code)
    )]
    pub(crate) fn of_records(ttls: impl IntoIterator<Item = Option<RrsetTtl>>) -> Option<RrsetTtl> {
        let mut smallest: Option<Ttl> = None;
        let mut provider_default = false;
        for ttl in ttls.into_iter().flatten() {
            match ttl {
                RrsetTtl::Explicit(ttl) => {
                    smallest = Some(smallest.map_or(ttl, |s| s.min(ttl)));
                }
                RrsetTtl::ProviderDefault => provider_default = true,
            }
        }
        match smallest {
            Some(ttl) => Some(RrsetTtl::Explicit(ttl)),
            None if provider_default => Some(RrsetTtl::ProviderDefault),
            None => None,
        }
    }
}

impl From<Ttl> for RrsetTtl {
    fn from(ttl: Ttl) -> RrsetTtl {
        RrsetTtl::Explicit(ttl)
    }
}

impl serde::Serialize for RrsetTtl {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            RrsetTtl::Explicit(ttl) => ttl.serialize(serializer),
            RrsetTtl::ProviderDefault => serializer.serialize_str(PROVIDER_DEFAULT),
        }
    }
}

impl<'de> serde::Deserialize<'de> for RrsetTtl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(RrsetTtlVisitor)
    }
}

/// Accepts an integer number of seconds or the string `"provider_default"`. Error texts are
/// fixed: they never quote the input.
struct RrsetTtlVisitor;

impl RrsetTtlVisitor {
    fn secs<E: serde::de::Error>(secs: u64) -> Result<RrsetTtl, E> {
        u32::try_from(secs)
            .ok()
            .and_then(|secs| RrsetTtl::from_secs(secs).ok())
            .ok_or_else(|| E::custom("a TTL is at most 2147483647 seconds"))
    }
}

impl serde::de::Visitor<'_> for RrsetTtlVisitor {
    type Value = RrsetTtl;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a TTL in seconds or \"provider_default\"")
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<RrsetTtl, E> {
        RrsetTtlVisitor::secs(v)
    }

    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<RrsetTtl, E> {
        u64::try_from(v)
            .map_err(|_| E::custom("a TTL is not negative"))
            .and_then(RrsetTtlVisitor::secs)
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<RrsetTtl, E> {
        if v == PROVIDER_DEFAULT {
            Ok(RrsetTtl::ProviderDefault)
        } else {
            Err(E::custom(
                "a TTL is a number of seconds or \"provider_default\"",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RrsetTtl, Ttl};

    fn explicit(secs: u32) -> Option<RrsetTtl> {
        Some(RrsetTtl::from_secs(secs).unwrap())
    }

    #[test]
    fn serde_spelling() {
        let json = |t: RrsetTtl| serde_json::to_string(&t).unwrap();
        assert_eq!(json(RrsetTtl::from_secs(300).unwrap()), "300");
        assert_eq!(json(RrsetTtl::ProviderDefault), "\"provider_default\"");
        let parse = |s: &str| serde_json::from_str::<RrsetTtl>(s);
        assert_eq!(parse("0").unwrap(), RrsetTtl::from_secs(0).unwrap());
        assert_eq!(
            parse("\"provider_default\"").unwrap(),
            RrsetTtl::ProviderDefault
        );
        for bad in [
            "-1",
            "2147483648",
            "1.5",
            "null",
            "\"Provider_Default\"",
            "\"300\"",
            "true",
        ] {
            let err = parse(bad).unwrap_err().to_string();
            assert!(!err.contains("Provider_Default"), "{bad}: {err}");
        }
    }

    #[test]
    fn records_read_with_the_smallest_number_else_the_default() {
        let d = Some(RrsetTtl::ProviderDefault);
        assert_eq!(
            RrsetTtl::of_records([None, explicit(600), d, explicit(300)]),
            explicit(300)
        );
        assert_eq!(RrsetTtl::of_records([d, None]), d);
        assert_eq!(RrsetTtl::of_records([d, d]), d);
        assert_eq!(RrsetTtl::of_records([None, None]), None);
        assert_eq!(RrsetTtl::of_records([]), None);
    }

    #[test]
    fn explicit_and_conversions() {
        let ttl = Ttl::from_secs(60).unwrap();
        assert_eq!(RrsetTtl::from(ttl).explicit(), Some(ttl));
        assert_eq!(RrsetTtl::ProviderDefault.explicit(), None);
        assert!(RrsetTtl::from_secs(Ttl::MAX.as_secs() + 1).is_err());
    }
}
