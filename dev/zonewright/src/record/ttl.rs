//! Time to live.

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
