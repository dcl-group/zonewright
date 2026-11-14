//! Configuration of the inspector (design section 8.2).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use super::InspectorError;
use crate::name::TargetName;

/// Cloudflare (1.1.1.1), Google (8.8.8.8) and Quad9 (9.9.9.9), port 53.
pub const PUBLIC_RESOLVERS: &[SocketAddr] = &[
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53)),
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 53)),
];

/// Upper bound on the resolvers of one configuration. Every resolver may be asked during one
/// discovery and one CNAME lookup, so the list is kept short.
pub(crate) const MAX_RESOLVERS: usize = 16;

/// How the inspector finds the authoritative name servers of a zone.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum NsDiscovery {
    /// Ask the resolvers for the zone's NS rrset and the servers' addresses (design section
    /// 8.3).
    Recursive,
    /// Use exactly these servers for every zone. The list is used as given: no address filter
    /// and no cache apply, because the application chose the addresses.
    Static(Vec<NameServer>),
}

/// Address families of discovered name servers to query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpFamilies {
    /// IPv4 only (`A` records of the NS names).
    V4,
    /// IPv6 only (`AAAA` records of the NS names).
    V6,
    /// Both. Every address is a server that has to agree, so a host without working IPv6 egress
    /// should not choose this.
    Both,
}

impl IpFamilies {
    pub(crate) fn wants_v4(self) -> bool {
        matches!(self, IpFamilies::V4 | IpFamilies::Both)
    }

    pub(crate) fn wants_v6(self) -> bool {
        matches!(self, IpFamilies::V6 | IpFamilies::Both)
    }
}

/// One authoritative name server: an address, and the NS name it was found under when known.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NameServer {
    /// The NS name, when known.
    pub name: Option<TargetName>,
    /// The address queries are sent to.
    pub addr: SocketAddr,
}

impl NameServer {
    /// A server at `addr`, optionally with its NS name.
    #[must_use]
    pub fn new(name: Option<TargetName>, addr: SocketAddr) -> NameServer {
        NameServer { name, addr }
    }
}

/// Configuration of an [`Inspector`](super::Inspector).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct InspectorConfig {
    /// Recursive resolvers, tried in order. Default: [`PUBLIC_RESOLVERS`]. At most 16, each
    /// address once.
    pub resolvers: Vec<SocketAddr>,
    /// How name servers are found. Default: [`NsDiscovery::Recursive`].
    pub discovery: NsDiscovery,
    /// Address families of discovered name servers to query. Default: [`IpFamilies::V4`].
    pub ip_families: IpFamilies,
    /// Limit for one question to one server, including a TCP retry. Default 3 s.
    pub query_timeout: Duration,
    /// How long a discovered server list is reused. Default 300 s. Zero disables the cache.
    pub ns_cache_ttl: Duration,
    /// Upper bound on the name servers (addresses) of one zone. Default 32.
    pub max_servers: usize,
    /// Limit for the whole discovery of one zone's servers. Default 10 s.
    pub discovery_timeout: Duration,
    /// Accept discovered name-server addresses in private ranges (RFC 1918, RFC 6598, RFC 4193
    /// and the deprecated site-local `fec0::/10`), also when embedded in an IPv6 address.
    /// Default false. Loopback, link-local, unspecified, multicast, broadcast, reserved,
    /// benchmarking and IETF protocol-assignment addresses are refused regardless (design
    /// section 8.3).
    pub allow_private_addresses: bool,
}

impl Default for InspectorConfig {
    fn default() -> InspectorConfig {
        InspectorConfig {
            resolvers: PUBLIC_RESOLVERS.to_vec(),
            discovery: NsDiscovery::Recursive,
            ip_families: IpFamilies::V4,
            query_timeout: Duration::from_secs(3),
            ns_cache_ttl: Duration::from_secs(300),
            max_servers: 32,
            discovery_timeout: Duration::from_secs(10),
            allow_private_addresses: false,
        }
    }
}

impl InspectorConfig {
    /// Checks the configuration; the reasons are the `Config` errors of [`Inspector::new`].
    ///
    /// [`Inspector::new`]: super::Inspector::new
    pub(crate) fn validate(&self) -> Result<(), InspectorError> {
        let fail = |detail: &str| Err(InspectorError::config(detail));
        if self.query_timeout.is_zero() {
            return fail("query_timeout must be greater than zero");
        }
        if self.discovery_timeout.is_zero() {
            return fail("discovery_timeout must be greater than zero");
        }
        if self.max_servers == 0 {
            return fail("max_servers must be at least 1");
        }
        if self.resolvers.len() > MAX_RESOLVERS {
            return fail("more than 16 resolvers");
        }
        // A resolver listed twice would count twice toward the CNAME quorum (design 8.7).
        for (at, resolver) in self.resolvers.iter().enumerate() {
            if self
                .resolvers
                .iter()
                .skip(at + 1)
                .any(|other| other == resolver)
            {
                return fail("a resolver is listed more than once");
            }
        }
        match &self.discovery {
            NsDiscovery::Recursive => {
                if self.resolvers.is_empty() {
                    return fail("recursive discovery needs at least one resolver");
                }
            }
            NsDiscovery::Static(servers) => {
                if servers.is_empty() {
                    return fail("the static name-server list is empty");
                }
                if servers.len() > self.max_servers {
                    return fail("the static name-server list is longer than max_servers");
                }
            }
        }
        Ok(())
    }
}
