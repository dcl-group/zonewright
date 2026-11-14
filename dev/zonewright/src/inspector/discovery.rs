//! Name-server discovery (design section 8.3).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream;
use tokio::time::Instant;

use super::answer::Mode;
use super::exchange::{Ask, Transport};
use super::{
    AddressRefusal, Answer, Engine, InspectorError, NameServer, NotAsked, NsDiscovery, TARGET,
};
use crate::name::{DomainName, TargetName};
use crate::record::RecordType;

/// Most distinct NS names of one zone.
pub(crate) const MAX_NS_NAMES: usize = 16;
/// Most addresses of one NS name and family.
pub(crate) const MAX_ADDRESSES_PER_NAME: usize = 8;
/// Address lookups running at the same time during one discovery.
pub(crate) const ADDRESS_LOOKUPS_AT_ONCE: usize = 8;
/// Most zones in the cache.
pub(crate) const MAX_CACHED_ZONES: usize = 256;

/// The port discovered servers are queried on.
const DNS_PORT: u16 = 53;

/// Discovered server lists by zone, with the time they were stored. Failures are not cached.
#[derive(Debug, Default)]
pub(crate) struct NsCache {
    entries: Mutex<HashMap<DomainName, (Instant, Vec<NameServer>)>>,
}

impl NsCache {
    /// The list stored for `zone` if it is younger than `ttl`.
    fn get(&self, zone: &DomainName, ttl: Duration) -> Option<Vec<NameServer>> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        match entries.get(zone) {
            Some((stored, servers)) if stored.elapsed() < ttl => Some(servers.clone()),
            Some(_) => {
                entries.remove(zone);
                None
            }
            None => None,
        }
    }

    /// Stores the list for `zone`, evicting the oldest entry when the cache is full.
    fn put(&self, zone: &DomainName, servers: Vec<NameServer>) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if !entries.contains_key(zone) && entries.len() >= MAX_CACHED_ZONES {
            let oldest = entries
                .iter()
                .min_by_key(|(_, (stored, _))| *stored)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
        entries.insert(zone.clone(), (Instant::now(), servers));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Why an address is refused, or `None` when it is usable.
///
/// The policy follows the IANA special-purpose address registries
/// (<https://www.iana.org/assignments/iana-ipv4-special-registry/>,
/// <https://www.iana.org/assignments/iana-ipv6-special-registry/>, both as updated 2025-10-09)
/// and the IPv6 address space registry
/// (<https://www.iana.org/assignments/ipv6-address-space/>):
///
/// - Always refused: blocks that are not globally reachable and are not private use, and blocks
///   that cannot hold a name server — unspecified, loopback, link-local, multicast, `240.0.0.0/4`
///   with the limited broadcast address, `192.0.0.0/24` (IETF protocol assignments) except the
///   two entries the registry marks globally reachable (`192.0.0.9`, PCP anycast, RFC 7723;
///   `192.0.0.10`, TURN anycast, RFC 8155), `192.88.99.0/24` (deprecated 6to4 relay anycast,
///   RFC 7526), `198.18.0.0/15` (benchmarking, RFC 2544), IPv4-mapped `::ffff:0:0/96` (the
///   registry marks it neither a destination nor globally reachable) and IPv4-compatible `::/96`
///   (deprecated, RFC 4291 section 2.5.5.1), whatever IPv4 address they carry, every other IPv6
///   address outside the global unicast space `2000::/3` except the two translation prefixes
///   below (this covers `100::/64`, `100:0:0:1::/64` and `5f00::/16`), and the parts of
///   `2001::/23` that the registry does not mark globally reachable (`2001:2::/48`
///   benchmarking, `2001:10::/28` deprecated ORCHID, and the unassigned rest).
/// - Refused unless private addresses are allowed: `10.0.0.0/8`, `172.16.0.0/12`,
///   `192.168.0.0/16` (RFC 1918), `100.64.0.0/10` (RFC 6598), `fc00::/7` (RFC 4193), the
///   deprecated site-local `fec0::/10` (RFC 3879) and the local-use translation prefix
///   `64:ff9b:1::/48` (RFC 8215; the registry marks it forwardable but not globally reachable).
/// - IPv6 forms that route to an embedded IPv4 address get the IPv4 rules for that address: the
///   NAT64 well-known prefix `64:ff9b::/96` (RFC 6052), 6to4 `2002::/16` (RFC 3056), Teredo
///   `2001::/32` (RFC 4380: both the server address and the de-obfuscated client address), and
///   an ISATAP interface identifier `0:5efe:a.b.c.d` or `200:5efe:a.b.c.d` under any global
///   prefix (RFC 5214 section 6.1).
/// - The documentation blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
///   `2001:db8::/32`, `3fff::/20`) are accepted on purpose, although the registries mark them
///   not globally reachable: they are routed nowhere, so a query to them times out and
///   satisfies nothing, they cannot point the process at a host of its own network, and test
///   fixtures use them.
pub(crate) fn refusal(ip: IpAddr, allow_private: bool) -> Option<AddressRefusal> {
    match ip {
        IpAddr::V4(v4) => refusal_v4(v4, allow_private),
        IpAddr::V6(v6) => refusal_v6(v6, allow_private),
    }
}

fn refusal_v4(ip: Ipv4Addr, allow_private: bool) -> Option<AddressRefusal> {
    let [a, b, c, d] = ip.octets();
    if a == 0 {
        Some(AddressRefusal::Unspecified)
    } else if ip.is_loopback() {
        Some(AddressRefusal::Loopback)
    } else if ip.is_link_local() {
        Some(AddressRefusal::LinkLocal)
    } else if ip.is_multicast() {
        Some(AddressRefusal::Multicast)
    } else if a >= 240 {
        // 240.0.0.0/4 is reserved and holds the limited broadcast address.
        Some(AddressRefusal::Reserved)
    } else if (a, b, c) == (192, 0, 0) {
        // PCP anycast 192.0.0.9 and TURN anycast 192.0.0.10 are globally reachable.
        if d == 9 || d == 10 {
            None
        } else {
            Some(AddressRefusal::ProtocolAssignment)
        }
    } else if (a, b, c) == (192, 88, 99) {
        Some(AddressRefusal::Relay6to4)
    } else if a == 198 && (b & 0xfe) == 18 {
        Some(AddressRefusal::Benchmarking)
    } else if allow_private {
        None
    } else if ip.is_private() {
        Some(AddressRefusal::Private)
    } else if a == 100 && (64..128).contains(&b) {
        Some(AddressRefusal::SharedAddressSpace)
    } else {
        None
    }
}

/// The IPv4 address in the 32 bits that start at segment `at`.
fn v4_at(segments: &[u16; 8], at: usize) -> Ipv4Addr {
    let high = segments.get(at).copied().unwrap_or(0);
    let low = segments.get(at + 1).copied().unwrap_or(0);
    Ipv4Addr::from((u32::from(high) << 16) | u32::from(low))
}

fn refusal_v6(ip: Ipv6Addr, allow_private: bool) -> Option<AddressRefusal> {
    let s = ip.segments();
    let [s0, s1, s2, s3, s4, s5, _, _] = s;
    if ip.is_unspecified() {
        return Some(AddressRefusal::Unspecified);
    }
    if ip.is_loopback() {
        return Some(AddressRefusal::Loopback);
    }
    if (s0, s1, s2, s3, s4) == (0, 0, 0, 0, 0) {
        return Some(if s5 == 0xffff {
            AddressRefusal::Ipv4Mapped
        } else if s5 == 0 {
            AddressRefusal::Ipv4Compatible
        } else {
            AddressRefusal::NotGlobalUnicast
        });
    }
    // NAT64 well-known prefix 64:ff9b::/96.
    if (s0, s1, s2, s3, s4, s5) == (0x64, 0xff9b, 0, 0, 0, 0) {
        return refusal_v4(v4_at(&s, 6), allow_private);
    }
    // Local-use IPv4/IPv6 translation prefix 64:ff9b:1::/48.
    if (s0, s1, s2) == (0x64, 0xff9b, 1) {
        return private(AddressRefusal::LocalTranslation, allow_private);
    }
    if s0 & 0xffc0 == 0xfe80 {
        return Some(AddressRefusal::LinkLocal);
    }
    if ip.is_multicast() {
        return Some(AddressRefusal::Multicast);
    }
    if s0 & 0xfe00 == 0xfc00 {
        return private(AddressRefusal::UniqueLocal, allow_private);
    }
    if s0 & 0xffc0 == 0xfec0 {
        return private(AddressRefusal::SiteLocal, allow_private);
    }
    if s0 & 0xe000 != 0x2000 {
        return Some(AddressRefusal::NotGlobalUnicast);
    }
    let prefix = if s0 == 0x2002 {
        // 6to4: the IPv4 address follows the 16-bit prefix.
        refusal_v4(v4_at(&s, 1), allow_private)
    } else if s0 == 0x2001 && s1 < 0x0200 {
        // 2001::/23, IETF protocol assignments: only the entries marked globally reachable.
        refusal_2001(&s, allow_private)
    } else {
        None
    };
    prefix.or_else(|| isatap(&s, allow_private))
}

/// `reason` unless private addresses are allowed.
fn private(reason: AddressRefusal, allow_private: bool) -> Option<AddressRefusal> {
    if allow_private { None } else { Some(reason) }
}

/// The IPv4 rules for the address in an ISATAP interface identifier (RFC 5214 section 6.1:
/// `00-00-5E-FE` followed by the IPv4 address, with the universal/local and group bits of the
/// first octet free).
fn isatap(s: &[u16; 8], allow_private: bool) -> Option<AddressRefusal> {
    let [_, _, _, _, s4, s5, _, _] = *s;
    if s4 & 0xfcff == 0 && s5 == 0x5efe {
        refusal_v4(v4_at(s, 6), allow_private)
    } else {
        None
    }
}

/// An address in `2001::/23`.
fn refusal_2001(s: &[u16; 8], allow_private: bool) -> Option<AddressRefusal> {
    let [_, s1, s2, s3, s4, s5, s6, s7] = *s;
    match s1 {
        // Teredo: server IPv4 in bits 32..64, the client IPv4 inverted in the last 32 bits.
        0x0000 => {
            let client = Ipv4Addr::from(!u32::from(v4_at(s, 6)));
            refusal_v4(v4_at(s, 2), allow_private).or_else(|| refusal_v4(client, allow_private))
        }
        // PCP, TURN and DNS-SD SRP anycast: 2001:1::1, ::2, ::3.
        0x0001 if (s2, s3, s4, s5, s6) == (0, 0, 0, 0, 0) && (1..=3).contains(&s7) => None,
        // Benchmarking 2001:2::/48.
        0x0002 if s2 == 0 => Some(AddressRefusal::Benchmarking),
        // AMT 2001:3::/32.
        0x0003 => None,
        // AS112-v6 2001:4:112::/48.
        0x0004 if s2 == 0x0112 => None,
        // ORCHIDv2 2001:20::/28 and DETs 2001:30::/28.
        0x0020..=0x003f => None,
        // Documentation 2001:db8::/32 lies outside 2001::/23; see the policy above.
        _ => Some(AddressRefusal::ProtocolAssignment),
    }
}

impl<T: Transport> Engine<T> {
    /// The authoritative servers of `zone`, by the configured discovery.
    pub(crate) async fn name_servers(
        &self,
        zone: &DomainName,
    ) -> Result<Vec<NameServer>, InspectorError> {
        let NsDiscovery::Static(servers) = &self.config.discovery else {
            return self.discover_cached(zone).await;
        };
        Ok(servers.clone())
    }

    async fn discover_cached(&self, zone: &DomainName) -> Result<Vec<NameServer>, InspectorError> {
        let ttl = self.config.ns_cache_ttl;
        if !ttl.is_zero()
            && let Some(servers) = self.cache.get(zone, ttl)
        {
            return Ok(servers);
        }
        let servers = tokio::time::timeout(self.config.discovery_timeout, self.discover(zone))
            .await
            .unwrap_or_else(|_| {
                Err(InspectorError::no_servers(
                    zone,
                    "discovery did not finish within the discovery timeout",
                ))
            })?;
        if !ttl.is_zero() {
            self.cache.put(zone, servers.clone());
        }
        Ok(servers)
    }

    /// Steps 1 to 5 of design section 8.3.
    async fn discover(&self, zone: &DomainName) -> Result<Vec<NameServer>, InspectorError> {
        let names = self.ns_names(zone).await?;
        if names.len() > MAX_NS_NAMES {
            return Err(InspectorError::TooManyNameServers {
                zone: zone.clone(),
                count: names.len(),
            });
        }
        let mut lookups = stream::iter(names.into_iter().map(|name| async move {
            let addresses = self.addresses_of(zone, &name).await;
            (name, addresses)
        }))
        .buffered(ADDRESS_LOOKUPS_AT_ONCE);

        let allow_private = self.config.allow_private_addresses;
        let mut servers: Vec<NameServer> = Vec::new();
        let mut seen: HashSet<IpAddr> = HashSet::new();
        while let Some((name, addresses)) = lookups.next().await {
            let addresses = addresses?;
            // A server that cannot be asked is reported, never left out: leaving it out would
            // make success mean "some servers" (design section 8.3, step 5). Delegation data
            // is public and not secret (design section 8.10).
            if addresses.is_empty() {
                tracing::warn!(
                    target: TARGET,
                    zone = %zone,
                    ns = %name,
                    reason = NotAsked::NoAddress.as_str(),
                    "name server not asked"
                );
                servers.push(NameServer::unasked(Some(name), None, NotAsked::NoAddress));
                continue;
            }
            for ip in addresses {
                if !seen.insert(ip) {
                    continue;
                }
                let addr = SocketAddr::new(ip, DNS_PORT);
                match refusal(ip, allow_private) {
                    Some(reason) => {
                        tracing::warn!(
                            target: TARGET,
                            zone = %zone,
                            ns = %name,
                            address = %ip,
                            reason = reason.as_str(),
                            "name-server address refused"
                        );
                        servers.push(NameServer::unasked(
                            Some(name.clone()),
                            Some(addr),
                            NotAsked::AddressRefused(reason),
                        ));
                    }
                    None => servers.push(NameServer::new(Some(name.clone()), addr)),
                }
            }
        }
        if servers.len() > self.config.max_servers {
            return Err(InspectorError::TooManyNameServers {
                zone: zone.clone(),
                count: servers.len(),
            });
        }
        Ok(servers)
    }

    /// Step 1: the NS names of the first resolver whose answer holds an NS rrset owned by the
    /// zone itself. Resolvers are asked one at a time.
    async fn ns_names(&self, zone: &DomainName) -> Result<Vec<TargetName>, InspectorError> {
        let ask = Ask {
            name: TargetName::from(zone).wire().to_vec(),
            rtype: RecordType::NS.code().unwrap_or(2),
            recursion: true,
        };
        let mut outcomes: Vec<String> = Vec::new();
        for resolver in &self.config.resolvers {
            // Not following CNAMEs: only NS records owned by the zone itself count.
            let answer = self
                .ask(*resolver, &ask, Mode::Resolver { follow: false })
                .await;
            if let Answer::Records { records, .. } = &answer {
                // Every NS value must be readable: dropping one would shorten the list. An
                // answer with an unreadable value is unusable, like a failure.
                let names: Result<Vec<TargetName>, _> = records
                    .iter()
                    .map(|data| TargetName::parse(data.as_str()))
                    .collect();
                match names {
                    Ok(names) if !names.is_empty() => return Ok(names),
                    Ok(_) => {}
                    Err(_) => {
                        outcomes.push(format!("{resolver}: unreadable NS value"));
                        continue;
                    }
                }
            }
            outcomes.push(format!("{resolver}: {}", answer.kind()));
        }
        Err(InspectorError::no_servers(
            zone,
            &format!(
                "no resolver returned an NS set for the zone ({})",
                outcomes.join(", ")
            ),
        ))
    }

    /// Step 3 for one NS name: its addresses per configured family, each family from the first
    /// resolver that answers (a negative answer counts as an answer). When no resolver answers
    /// for a family, or an answer holds an unreadable address, the addresses of the name are
    /// not established and the result is an error, never a shorter list.
    async fn addresses_of(
        &self,
        zone: &DomainName,
        name: &TargetName,
    ) -> Result<Vec<IpAddr>, InspectorError> {
        let families = self.config.ip_families;
        let mut types: Vec<RecordType> = Vec::with_capacity(2);
        if families.wants_v4() {
            types.push(RecordType::A);
        }
        if families.wants_v6() {
            types.push(RecordType::AAAA);
        }
        let mut out: Vec<IpAddr> = Vec::new();
        for rtype in types {
            let ask = Ask {
                name: name.wire().to_vec(),
                rtype: rtype.code().unwrap_or(1),
                recursion: true,
            };
            let mut answered = false;
            let mut outcomes: Vec<String> = Vec::new();
            for resolver in &self.config.resolvers {
                match self
                    .ask(*resolver, &ask, Mode::Resolver { follow: true })
                    .await
                {
                    Answer::Records { records, .. } => {
                        if records.len() > MAX_ADDRESSES_PER_NAME {
                            return Err(InspectorError::TooManyNameServers {
                                zone: zone.clone(),
                                count: records.len(),
                            });
                        }
                        for data in &records {
                            let ip = data.as_str().parse::<IpAddr>().map_err(|_| {
                                InspectorError::no_servers(
                                    zone,
                                    &format!(
                                        "{resolver} returned an unreadable {rtype} value for {name}"
                                    ),
                                )
                            })?;
                            out.push(ip);
                        }
                        answered = true;
                        break;
                    }
                    Answer::NoData | Answer::NxDomain => {
                        answered = true;
                        break;
                    }
                    other => outcomes.push(format!("{resolver}: {}", other.kind())),
                }
            }
            if !answered {
                return Err(InspectorError::no_servers(
                    zone,
                    &format!(
                        "no resolver answered the {rtype} question for name server {name} ({})",
                        outcomes.join(", ")
                    ),
                ));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::inspector::IpFamilies;
    use crate::inspector::exchange::Failure;
    use crate::inspector::testing::{
        Behavior, Fake, addr, config_with, nodata, nxdomain, ok, rec, reply,
    };

    fn zone() -> DomainName {
        DomainName::parse("example.org").unwrap()
    }

    fn engine(config: InspectorConfig) -> Engine<Fake> {
        Engine::new(config, Fake::default()).unwrap()
    }

    use crate::inspector::InspectorConfig;

    fn ns_set(fake: &Fake, resolver: SocketAddr, names: &[&str]) {
        let records = names
            .iter()
            .map(|name| rec("example.org", RecordType::NS, 300, name))
            .collect();
        fake.reply(resolver, "example.org", RecordType::NS, ok(records));
    }

    fn a(fake: &Fake, resolver: SocketAddr, name: &str, addresses: &[&str]) {
        let records = addresses
            .iter()
            .map(|ip| rec(name, RecordType::A, 300, ip))
            .collect();
        fake.reply(resolver, name, RecordType::A, ok(records));
    }

    #[test]
    fn the_address_filter_follows_the_design() {
        let refused = |text: &str, allow: bool| {
            refusal(text.parse().unwrap(), allow).map(AddressRefusal::as_str)
        };
        for (ip, reason) in [
            ("0.0.0.0", "unspecified"),
            ("0.1.2.3", "unspecified"),
            ("127.0.0.1", "loopback"),
            ("169.254.1.1", "link-local"),
            ("224.0.0.1", "multicast"),
            ("255.255.255.255", "broadcast or reserved"),
            ("::", "unspecified"),
            ("::1", "loopback"),
            ("fe80::1", "link-local"),
            ("ff02::1", "multicast"),
            ("::ffff:127.0.0.1", "IPv4-mapped"),
            ("::ffff:169.254.0.1", "IPv4-mapped"),
            ("::ffff:10.0.0.1", "IPv4-mapped"),
        ] {
            assert_eq!(refused(ip, false), Some(reason), "{ip}");
            assert_eq!(refused(ip, true), Some(reason), "{ip} with private allowed");
        }
        for (ip, reason) in [
            ("10.1.2.3", "private"),
            ("172.16.0.1", "private"),
            ("192.168.1.1", "private"),
            ("100.64.0.1", "shared address space"),
            ("100.127.255.255", "shared address space"),
            ("fd00::1", "unique-local"),
        ] {
            assert_eq!(refused(ip, false), Some(reason), "{ip}");
            assert_eq!(refused(ip, true), None, "{ip} with private allowed");
        }
        for ip in ["192.0.2.1", "100.128.0.1", "8.8.8.8", "2001:db8::1"] {
            assert_eq!(refused(ip, false), None, "{ip}");
        }
    }

    #[test]
    fn the_address_filter_covers_the_special_purpose_registries() {
        let refused = |text: &str, allow: bool| {
            refusal(text.parse().unwrap(), allow).map(AddressRefusal::as_str)
        };
        // Refused whatever the option says.
        for (ip, reason) in [
            ("192.0.0.1", "IETF protocol assignment"),
            ("192.0.0.8", "IETF protocol assignment"),
            ("192.0.0.11", "IETF protocol assignment"),
            ("192.0.0.170", "IETF protocol assignment"),
            ("192.88.99.1", "deprecated 6to4 relay anycast"),
            ("198.18.0.1", "benchmarking"),
            ("198.19.255.255", "benchmarking"),
            ("100::1", "not global unicast"),
            ("100:0:0:1::1", "not global unicast"),
            ("5f00::1", "not global unicast"),
            ("4000::1", "not global unicast"),
            ("::ffff:0:808:808", "not global unicast"),
            ("2001:2::1", "benchmarking"),
            ("2001:10::1", "IETF protocol assignment"),
            ("2001:100::1", "IETF protocol assignment"),
            // IPv4 embedded in IPv6: the IPv4 rules apply to the embedded address.
            ("::127.0.0.1", "IPv4-compatible"),
            ("::169.254.0.1", "IPv4-compatible"),
            ("::2", "IPv4-compatible"),
            ("::10.0.0.1", "IPv4-compatible"),
            ("64:ff9b::127.0.0.1", "loopback"),
            ("64:ff9b::224.0.0.1", "multicast"),
            ("64:ff9b::198.18.0.1", "benchmarking"),
            ("2002:7f00:1::", "loopback"),
            ("2002:a9fe:101::1", "link-local"),
            ("2002:c000:1::", "IETF protocol assignment"),
            ("::ffff:198.18.0.1", "IPv4-mapped"),
            ("::ffff:192.0.0.8", "IPv4-mapped"),
            // Teredo: server 127.0.0.1, or client 127.0.0.1 (stored inverted).
            ("2001:0:7f00:1::808:808", "loopback"),
            ("2001:0:808:808::80ff:fffe", "loopback"),
        ] {
            assert_eq!(refused(ip, false), Some(reason), "{ip}");
            assert_eq!(refused(ip, true), Some(reason), "{ip} with private allowed");
        }
        // Refused unless private addresses are allowed, embedded forms included.
        for (ip, reason) in [
            ("fec0::1", "site-local"),
            ("fc00::1", "unique-local"),
            ("64:ff9b:1::1", "local-use translation"),
            ("64:ff9b::10.0.0.1", "private"),
            ("64:ff9b::100.64.0.1", "shared address space"),
            ("2002:c0a8:101::1", "private"),
            ("2001:0:808:808::f5ff:fffe", "private"),
        ] {
            assert_eq!(refused(ip, false), Some(reason), "{ip}");
            assert_eq!(refused(ip, true), None, "{ip} with private allowed");
        }
        // Globally reachable, or documentation (routed nowhere).
        for ip in [
            "64:ff9b::8.8.8.8",
            "2002:808:808::1",
            "2001:0:808:808::f7f7:f7f7",
            "2001:1::1",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
            "2620:4f:8000::1",
            "2a00:1450::1",
            "3fff::1",
            "198.51.100.1",
            "203.0.113.1",
            "198.20.0.1",
            "192.0.1.1",
            "192.0.0.9",
            "192.0.0.10",
        ] {
            assert_eq!(refused(ip, false), None, "{ip}");
        }
    }

    /// The cases of the sixth review: the IANA entries read wrongly before, the boundaries of
    /// `240.0.0.0/4` and of the `2001::/23` entries, the IPv4-mapped and IPv4-compatible forms
    /// of a global address, ISATAP, and the documentation blocks.
    #[test]
    fn the_address_filter_follows_the_registries_at_their_boundaries() {
        let refused = |text: &str, allow: bool| {
            refusal(text.parse().unwrap(), allow).map(AddressRefusal::as_str)
        };
        for (ip, reason) in [
            // 240.0.0.0/4 whole, not only its top.
            ("240.0.0.0", "broadcast or reserved"),
            ("240.0.0.1", "broadcast or reserved"),
            ("250.1.2.3", "broadcast or reserved"),
            ("255.255.255.254", "broadcast or reserved"),
            ("239.255.255.255", "multicast"),
            // A global IPv4 address written as IPv6 is not an IPv6 destination.
            ("::ffff:8.8.8.8", "IPv4-mapped"),
            ("::8.8.8.8", "IPv4-compatible"),
            // 2001::/23 around its entries.
            ("2001:1::", "IETF protocol assignment"),
            ("2001:1::4", "IETF protocol assignment"),
            ("2001:1::1:1", "IETF protocol assignment"),
            ("2001:1:1::1", "IETF protocol assignment"),
            ("2001:2::ffff", "benchmarking"),
            ("2001:2:0:ffff::1", "benchmarking"),
            ("2001:2:1::1", "IETF protocol assignment"),
            ("2001:4::1", "IETF protocol assignment"),
            ("2001:4:113::1", "IETF protocol assignment"),
            ("2001:5::1", "IETF protocol assignment"),
            ("2001:10::1", "IETF protocol assignment"),
            ("2001:1f:ffff::1", "IETF protocol assignment"),
            ("2001:40::1", "IETF protocol assignment"),
            ("2001:1ff:ffff::1", "IETF protocol assignment"),
            // Next to the translation prefixes.
            ("64:ff9b:2::1", "not global unicast"),
            ("64:ff9b::1:0:808:808", "not global unicast"),
            // ISATAP: the embedded IPv4 address decides, both forms of the identifier.
            ("2a00:1450::5efe:7f00:1", "loopback"),
            ("2a00:1450::200:5efe:a9fe:101", "link-local"),
            ("2002:808:808::5efe:7f00:1", "loopback"),
        ] {
            assert_eq!(refused(ip, false), Some(reason), "{ip}");
            assert_eq!(refused(ip, true), Some(reason), "{ip} with private allowed");
        }
        for (ip, reason) in [
            ("64:ff9b:1::1", "local-use translation"),
            ("64:ff9b:1:ffff::1", "local-use translation"),
            ("2a00:1450::5efe:a00:1", "private"),
        ] {
            assert_eq!(refused(ip, false), Some(reason), "{ip}");
            assert_eq!(refused(ip, true), None, "{ip} with private allowed");
        }
        for ip in [
            // Globally reachable per the registries.
            "192.0.0.9",
            "192.0.0.10",
            "2001:1::2",
            "2001:3:ffff::1",
            "2001:4:112:ffff::1",
            "2001:20::1",
            "2001:2f:ffff::1",
            "2001:3f:ffff::1",
            "2001:200::1",
            "2a00:1450::5efe:808:808",
            "2a00:1450::200:5efe:808:808",
            "2a00:1450::1:5efe:7f00:1",
            // Documentation, accepted on purpose.
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "3fff::1",
            "3fff:fff::1",
        ] {
            assert_eq!(refused(ip, false), None, "{ip}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_resolver_with_an_ns_set_owned_by_the_zone_wins() {
        let (r1, r2, r3) = (addr(1), addr(2), addr(3));
        let e = engine(config_with(vec![r1, r2, r3]));
        e.transport
            .on(r1, "example.org", RecordType::NS, Behavior::Hang);
        // An NS set owned by another name does not count.
        e.transport.reply(
            r2,
            "example.org",
            RecordType::NS,
            ok(vec![rec(
                "evil.example",
                RecordType::NS,
                300,
                "ns.evil.example.",
            )]),
        );
        ns_set(&e.transport, r3, &["ns1.example.net.", "ns2.example.net."]);
        for resolver in [r1, r2, r3] {
            a(&e.transport, resolver, "ns1.example.net", &["192.0.2.53"]);
            a(
                &e.transport,
                resolver,
                "ns2.example.net",
                &["198.51.100.53"],
            );
        }
        let servers = e.name_servers(&zone()).await.unwrap();
        assert_eq!(
            servers,
            vec![
                NameServer::new(
                    Some(TargetName::parse("ns1.example.net.").unwrap()),
                    "192.0.2.53:53".parse().unwrap()
                ),
                NameServer::new(
                    Some(TargetName::parse("ns2.example.net.").unwrap()),
                    "198.51.100.53:53".parse().unwrap()
                ),
            ]
        );
        // Resolvers are asked one at a time for NS; address lookups use the first resolver
        // that answers.
        assert_eq!(e.transport.calls_of(RecordType::NS), 3);
        assert_eq!(e.transport.calls_of(RecordType::A), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn no_ns_set_from_any_resolver_is_no_name_servers() {
        let (r1, r2) = (addr(1), addr(2));
        let e = engine(config_with(vec![r1, r2]));
        e.transport
            .reply(r1, "example.org", RecordType::NS, nxdomain());
        e.transport
            .reply(r2, "example.org", RecordType::NS, nodata());
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert!(
            matches!(&err, InspectorError::NoNameServers { detail, .. } if detail.contains("nxdomain") && detail.contains("nodata")),
            "{err:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn more_than_sixteen_ns_names_fail_before_any_address_lookup() {
        let r1 = addr(1);
        let e = engine(config_with(vec![r1]));
        let names: Vec<String> = (0..17).map(|i| format!("ns{i}.example.net.")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        ns_set(&e.transport, r1, &refs);
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert!(matches!(
            err,
            InspectorError::TooManyNameServers { count: 17, .. }
        ));
        assert_eq!(e.transport.calls_of(RecordType::A), 0);
        // Exactly sixteen is accepted.
        let e = engine(config_with(vec![r1]));
        ns_set(&e.transport, r1, &refs[..16]);
        for name in &refs[..16] {
            a(&e.transport, r1, name, &["192.0.2.1"]);
        }
        // All sixteen names share one address: one server.
        assert_eq!(e.name_servers(&zone()).await.unwrap().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn more_than_eight_addresses_per_name_is_too_many() {
        let r1 = addr(1);
        let e = engine(config_with(vec![r1]));
        ns_set(&e.transport, r1, &["ns.example.net."]);
        let ips: Vec<String> = (1..=9).map(|i| format!("192.0.2.{i}")).collect();
        let refs: Vec<&str> = ips.iter().map(String::as_str).collect();
        a(&e.transport, r1, "ns.example.net", &refs);
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert!(matches!(
            err,
            InspectorError::TooManyNameServers { count: 9, .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn more_servers_than_max_servers_is_an_error_not_a_truncated_list() {
        let r1 = addr(1);
        let mut config = config_with(vec![r1]);
        config.max_servers = 3;
        let e = engine(config);
        ns_set(&e.transport, r1, &["a.example.net.", "b.example.net."]);
        a(
            &e.transport,
            r1,
            "a.example.net",
            &["192.0.2.1", "192.0.2.2"],
        );
        a(
            &e.transport,
            r1,
            "b.example.net",
            &["192.0.2.3", "192.0.2.4"],
        );
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert!(matches!(
            err,
            InspectorError::TooManyNameServers { count: 4, .. }
        ));
    }

    fn ns(name: &str) -> Option<TargetName> {
        Some(TargetName::parse(name).unwrap())
    }

    fn sock(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn refused_row(name: &str, ip: &str, reason: AddressRefusal) -> NameServer {
        NameServer::unasked(ns(name), Some(sock(ip)), NotAsked::AddressRefused(reason))
    }

    #[tokio::test(start_paused = true)]
    async fn refused_addresses_are_reported_as_rows_and_private_ones_need_the_option() {
        let r1 = addr(1);
        let setup = |allow: bool| {
            let mut config = config_with(vec![r1]);
            config.allow_private_addresses = allow;
            let e = engine(config);
            ns_set(&e.transport, r1, &["a.example.net.", "b.example.net."]);
            a(
                &e.transport,
                r1,
                "a.example.net",
                &["127.0.0.1", "10.0.0.1"],
            );
            a(
                &e.transport,
                r1,
                "b.example.net",
                &["169.254.0.1", "192.0.2.7"],
            );
            e
        };
        // Without the option no address of a.example.net can be asked, and b.example.net keeps
        // one: every refused address is a row with its reason, nothing is left out, and the
        // complete list is cached.
        let e = setup(false);
        let servers = e.name_servers(&zone()).await.unwrap();
        assert_eq!(
            servers,
            vec![
                refused_row("a.example.net.", "10.0.0.1:53", AddressRefusal::Private),
                refused_row("a.example.net.", "127.0.0.1:53", AddressRefusal::Loopback),
                refused_row(
                    "b.example.net.",
                    "169.254.0.1:53",
                    AddressRefusal::LinkLocal
                ),
                NameServer::new(ns("b.example.net."), sock("192.0.2.7:53")),
            ]
        );
        assert_eq!(e.cache.len(), 1);
        let asked: Vec<SocketAddr> = servers.iter().filter_map(NameServer::query_addr).collect();
        assert_eq!(asked, vec![sock("192.0.2.7:53")]);

        // With the option the private address is asked; loopback and link-local stay refused.
        let servers = setup(true).name_servers(&zone()).await.unwrap();
        let asked: Vec<SocketAddr> = servers.iter().filter_map(NameServer::query_addr).collect();
        assert_eq!(asked, vec![sock("10.0.0.1:53"), sock("192.0.2.7:53")]);
        assert_eq!(servers.len(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn an_ns_name_no_resolver_answers_for_fails_the_discovery_and_is_not_cached() {
        let (r1, r2) = (addr(1), addr(2));
        let e = engine(config_with(vec![r1, r2]));
        ns_set(&e.transport, r1, &["ns1.example.net.", "ns2.example.net."]);
        a(&e.transport, r1, "ns1.example.net", &["192.0.2.1"]);
        // Every resolver fails for ns2's address, once.
        for (resolver, failure) in [(r1, Err(Failure::Timeout)), (r2, servfail())] {
            e.transport.on(
                resolver,
                "ns2.example.net",
                RecordType::A,
                Behavior::Seq(vec![
                    failure,
                    ok(vec![rec(
                        "ns2.example.net",
                        RecordType::A,
                        300,
                        "198.51.100.2",
                    )]),
                ]),
            );
        }
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert!(
            matches!(&err, InspectorError::NoNameServers { detail, .. }
                if detail.contains("ns2.example.net.") && detail.contains("no resolver answered")),
            "{err:?}"
        );
        assert_eq!(e.cache.len(), 0, "nothing partial is cached");
        // The next call discovers again and gets the whole list.
        let servers = e.name_servers(&zone()).await.unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(e.transport.calls_of(RecordType::NS), 2);
    }

    fn servfail() -> Result<crate::inspector::exchange::Reply, Failure> {
        Ok(reply(2, false, Vec::new()))
    }

    #[tokio::test(start_paused = true)]
    async fn an_ns_name_without_an_address_in_the_families_is_a_row_not_asked() {
        let r1 = addr(1);
        let e = engine(config_with(vec![r1]));
        ns_set(
            &e.transport,
            r1,
            &[
                "dangling.example.net.",
                "ns1.example.net.",
                "v6only.example.net.",
            ],
        );
        a(&e.transport, r1, "ns1.example.net", &["192.0.2.1"]);
        e.transport
            .reply(r1, "v6only.example.net", RecordType::A, nodata());
        // NXDOMAIN is an answer too: the name has no address, the lookup did not fail.
        e.transport
            .reply(r1, "dangling.example.net", RecordType::A, nxdomain());
        let servers = e.name_servers(&zone()).await.unwrap();
        assert_eq!(
            servers,
            vec![
                NameServer::unasked(ns("dangling.example.net."), None, NotAsked::NoAddress),
                NameServer::new(ns("ns1.example.net."), sock("192.0.2.1:53")),
                NameServer::unasked(ns("v6only.example.net."), None, NotAsked::NoAddress),
            ]
        );
        // A complete answer: cached.
        assert_eq!(e.cache.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_zone_whose_servers_all_cannot_be_asked_is_still_a_list() {
        let r1 = addr(1);
        let e = engine(config_with(vec![r1]));
        ns_set(&e.transport, r1, &["a.example.net.", "b.example.net."]);
        a(&e.transport, r1, "a.example.net", &["127.0.0.1"]);
        e.transport
            .reply(r1, "b.example.net", RecordType::A, nodata());
        let servers = e.name_servers(&zone()).await.unwrap();
        assert_eq!(
            servers,
            vec![
                refused_row("a.example.net.", "127.0.0.1:53", AddressRefusal::Loopback),
                NameServer::unasked(ns("b.example.net."), None, NotAsked::NoAddress),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rows_not_asked_count_toward_max_servers() {
        let r1 = addr(1);
        let mut config = config_with(vec![r1]);
        config.max_servers = 2;
        let e = engine(config);
        ns_set(
            &e.transport,
            r1,
            &["a.example.net.", "b.example.net.", "c.example.net."],
        );
        a(&e.transport, r1, "a.example.net", &["192.0.2.1"]);
        a(&e.transport, r1, "b.example.net", &["127.0.0.1"]);
        e.transport
            .reply(r1, "c.example.net", RecordType::A, nodata());
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert!(
            matches!(err, InspectorError::TooManyNameServers { count: 3, .. }),
            "{err:?}"
        );
        assert_eq!(e.cache.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn unreadable_values_never_shorten_the_list() {
        use crate::record::RecordData;
        let (r1, r2) = (addr(1), addr(2));
        let e = engine(config_with(vec![r1, r2]));
        // r1's NS set holds one unreadable value: the whole answer is unusable.
        let mut bad = rec("example.org", RecordType::NS, 300, "ns1.example.net.");
        bad.data = Ok(RecordData::non_canonical("not a..name"));
        e.transport.reply(
            r1,
            "example.org",
            RecordType::NS,
            ok(vec![
                rec("example.org", RecordType::NS, 300, "ns1.example.net."),
                bad,
            ]),
        );
        ns_set(&e.transport, r2, &["ns1.example.net.", "ns2.example.net."]);
        a(&e.transport, r1, "ns1.example.net", &["192.0.2.1"]);
        a(&e.transport, r1, "ns2.example.net", &["192.0.2.2"]);
        assert_eq!(e.name_servers(&zone()).await.unwrap().len(), 2);

        // An unreadable address is an error, not a dropped address.
        let e = engine(config_with(vec![r1]));
        ns_set(&e.transport, r1, &["ns1.example.net."]);
        let mut bad = rec("ns1.example.net", RecordType::A, 300, "192.0.2.1");
        bad.data = Ok(RecordData::non_canonical("not-an-address"));
        e.transport.reply(
            r1,
            "ns1.example.net",
            RecordType::A,
            ok(vec![
                rec("ns1.example.net", RecordType::A, 300, "192.0.2.1"),
                bad,
            ]),
        );
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert!(
            matches!(&err, InspectorError::NoNameServers { detail, .. } if detail.contains("unreadable")),
            "{err:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn address_families_follow_the_configuration() {
        let r1 = addr(1);
        let mut config = config_with(vec![r1]);
        config.ip_families = IpFamilies::Both;
        let e = engine(config);
        ns_set(&e.transport, r1, &["ns.example.net."]);
        a(&e.transport, r1, "ns.example.net", &["192.0.2.1"]);
        e.transport.reply(
            r1,
            "ns.example.net",
            RecordType::AAAA,
            ok(vec![rec(
                "ns.example.net",
                RecordType::AAAA,
                60,
                "2001:db8::1",
            )]),
        );
        let servers = e.name_servers(&zone()).await.unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[1].addr, Some("[2001:db8::1]:53".parse().unwrap()));

        let mut config = config_with(vec![r1]);
        config.ip_families = IpFamilies::V6;
        let e = engine(config);
        ns_set(&e.transport, r1, &["ns.example.net."]);
        e.transport.reply(
            r1,
            "ns.example.net",
            RecordType::AAAA,
            ok(vec![rec(
                "ns.example.net",
                RecordType::AAAA,
                60,
                "2001:db8::1",
            )]),
        );
        assert_eq!(e.name_servers(&zone()).await.unwrap().len(), 1);
        assert_eq!(e.transport.calls_of(RecordType::A), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn at_most_eight_address_lookups_run_at_once() {
        let r1 = addr(1);
        let e = engine(config_with(vec![r1]));
        let names: Vec<String> = (0..16).map(|i| format!("ns{i}.example.net.")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        ns_set(&e.transport, r1, &refs);
        for (i, name) in refs.iter().enumerate() {
            a(&e.transport, r1, name, &[&format!("192.0.2.{}", i + 1)]);
        }
        *e.transport.delay.lock().unwrap() = Duration::from_millis(500);
        let servers = e.name_servers(&zone()).await.unwrap();
        assert_eq!(servers.len(), 16);
        assert_eq!(
            e.transport.peak.load(Ordering::SeqCst),
            ADDRESS_LOOKUPS_AT_ONCE
        );
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_is_bounded_by_the_discovery_timeout() {
        // Four resolvers, so that one name's lookups (4 x 3 s) outlast the 10 s deadline: a
        // name whose resolvers all fail is an error of its own (design 8.3).
        let resolvers = vec![addr(1), addr(2), addr(3), addr(4)];
        let e = engine(config_with(resolvers.clone()));
        let names: Vec<String> = (0..16).map(|i| format!("ns{i}.example.net.")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        ns_set(&e.transport, addr(1), &refs);
        for resolver in &resolvers {
            for name in &refs {
                e.transport
                    .on(*resolver, name, RecordType::A, Behavior::Hang);
            }
        }
        let started = Instant::now();
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        assert!(
            matches!(&err, InspectorError::NoNameServers { detail, .. } if detail.contains("timeout")),
            "{err:?}"
        );
        // Every hanging lookup is cut at the 3 s query timeout: the first eight names are at
        // their fourth resolver (started at 9 s) when the deadline passes; the second eight
        // have not started.
        assert_eq!(e.transport.calls_of(RecordType::A), 8 * 4);
    }

    #[tokio::test(start_paused = true)]
    async fn results_are_cached_failures_are_not() {
        let r1 = addr(1);
        let e = engine(config_with(vec![r1]));
        e.transport.on(
            r1,
            "example.org",
            RecordType::NS,
            Behavior::Seq(vec![
                Err(Failure::Timeout),
                ok(vec![rec(
                    "example.org",
                    RecordType::NS,
                    300,
                    "ns.example.net.",
                )]),
            ]),
        );
        a(&e.transport, r1, "ns.example.net", &["192.0.2.1"]);
        assert!(e.name_servers(&zone()).await.is_err());
        assert_eq!(e.cache.len(), 0);
        assert!(e.name_servers(&zone()).await.is_ok());
        let calls = e.transport.total_calls();
        assert!(e.name_servers(&zone()).await.is_ok());
        assert_eq!(e.transport.total_calls(), calls, "served from the cache");
        tokio::time::advance(Duration::from_secs(301)).await;
        assert!(e.name_servers(&zone()).await.is_ok());
        assert_eq!(
            e.transport.total_calls(),
            calls + 2,
            "expired after the TTL"
        );

        let mut config = config_with(vec![r1]);
        config.ns_cache_ttl = Duration::ZERO;
        let e = engine(config);
        ns_set(&e.transport, r1, &["ns.example.net."]);
        a(&e.transport, r1, "ns.example.net", &["192.0.2.1"]);
        e.name_servers(&zone()).await.unwrap();
        e.name_servers(&zone()).await.unwrap();
        assert_eq!(e.transport.total_calls(), 4);
        assert_eq!(e.cache.len(), 0);
    }

    #[test]
    fn the_cache_holds_at_most_256_zones_and_evicts_the_oldest() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cache = NsCache::default();
            let ttl = Duration::from_secs(3600);
            for i in 0..=MAX_CACHED_ZONES {
                let zone = DomainName::parse(&format!("z{i}.example")).unwrap();
                cache.put(&zone, Vec::new());
                tokio::time::advance(Duration::from_millis(1)).await;
            }
            assert_eq!(cache.len(), MAX_CACHED_ZONES);
            let first = DomainName::parse("z0.example").unwrap();
            assert!(cache.get(&first, ttl).is_none());
            let last = DomainName::parse(&format!("z{MAX_CACHED_ZONES}.example")).unwrap();
            assert!(cache.get(&last, ttl).is_some());
        });
    }

    #[tokio::test(start_paused = true)]
    async fn a_static_list_is_used_as_given() {
        let server = NameServer::new(None, "127.0.0.1:5353".parse().unwrap());
        let mut config = config_with(Vec::new());
        config.discovery = NsDiscovery::Static(vec![server.clone()]);
        let e = engine(config);
        assert_eq!(e.name_servers(&zone()).await.unwrap(), vec![server]);
        assert_eq!(e.transport.total_calls(), 0);
        let _ = reply(0, true, Vec::new());
    }
}
