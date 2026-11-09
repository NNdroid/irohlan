//! Virtual addressing for the dual-stack LAN.
//!
//! A network has one optional IPv4 subnet and one optional IPv6 prefix. Both
//! families share a single *host index* (`offset`): offset 1 is the creator,
//! offsets 2.. are handed out by the lease allocator. A single index therefore
//! maps to one IPv4 address and/or one IPv6 address, which keeps the lease
//! table, the membership table and the wire protocol family-agnostic.
//!
//! IPv6 prefixes default to a ULA /64 derived from the network id, so every
//! network gets a unique, stable, non-routed prefix without any configuration.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use serde::{Deserialize, Serialize};

/// IPv6 requires every link to carry at least 1280-byte packets (RFC 8200).
/// A TAP MTU below this makes ICMPv6 "packet too big" handling mandatory and
/// breaks Neighbor Discovery on most stacks, so we reject it up front.
pub const IPV6_MIN_MTU: u16 = 1280;

/// Default IPv4 subnet, kept for backwards compatibility with v1 networks.
pub const DEFAULT_V4_CIDR: &str = "10.13.37.0/24";

/// An IPv4 subnet. `base` is the masked network address as u32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V4Net {
    pub base: u32,
    pub prefix: u8,
}

/// An IPv6 prefix. `base` is the masked network address in network byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V6Net {
    pub base: [u8; 16],
    pub prefix: u8,
}

/// The address plan of one virtual network. At least one family is enabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddrPlan {
    pub v4: Option<V4Net>,
    pub v6: Option<V6Net>,
}

/// The addresses of one member (absent when that family is disabled).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualAddrs {
    pub v4: Option<u32>,
    pub v6: Option<[u8; 16]>,
}

impl V4Net {
    pub fn parse_cidr(s: &str) -> anyhow::Result<Self> {
        let (addr, prefix) = split_cidr(s, "10.13.37.0/24")?;
        let ip: Ipv4Addr = addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid IPv4 subnet address: {e}"))?;
        anyhow::ensure!(
            (8..=30).contains(&prefix),
            "IPv4 prefix must be between /8 and /30 (got /{prefix})"
        );
        let mask = u32::MAX << (32 - prefix as u32);
        Ok(Self {
            base: u32::from(ip) & mask,
            prefix,
        })
    }

    pub fn base_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base)
    }

    pub fn addr(&self, offset: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.base.wrapping_add(offset))
    }

    /// Host index of `ip`, or `None` when it is outside this subnet.
    pub fn offset_of(&self, ip: Ipv4Addr) -> Option<u32> {
        let size = 1u64 << (32 - self.prefix as u32);
        let base = self.base as u64;
        let n = u32::from(ip) as u64;
        (n >= base && n < base + size).then_some((n - base) as u32)
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", self.base_addr(), self.prefix)
    }
}

impl V6Net {
    pub fn parse_cidr(s: &str) -> anyhow::Result<Self> {
        let (addr, prefix) = split_cidr(s, "fd00:1234:5678:9abc::/64")?;
        let ip: Ipv6Addr = addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid IPv6 prefix address: {e}"))?;
        // At least 32 host bits are needed so a u32 host index always fits.
        anyhow::ensure!(
            (32..=96).contains(&prefix),
            "IPv6 prefix must be between /32 and /96 (got /{prefix})"
        );
        anyhow::ensure!(
            !ip.is_unspecified(),
            "the unspecified prefix :: cannot be used as a virtual subnet"
        );
        let mask = Self::net_mask(prefix);
        let base = u128::from(ip) & mask;
        Ok(Self {
            base: base.to_be_bytes(),
            prefix,
        })
    }

    fn net_mask(prefix: u8) -> u128 {
        let host_bits = 128 - prefix as u32;
        !((1u128 << host_bits) - 1)
    }

    fn base_u128(&self) -> u128 {
        u128::from_be_bytes(self.base)
    }

    pub fn base_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.base)
    }

    pub fn addr(&self, offset: u32) -> Ipv6Addr {
        Ipv6Addr::from(self.base_u128() | offset as u128)
    }

    /// Host index of `ip`, or `None` when it is outside this prefix or has
    /// more than 32 host bits set.
    pub fn offset_of(&self, ip: Ipv6Addr) -> Option<u32> {
        let mask = Self::net_mask(self.prefix);
        let n = u128::from(ip);
        if n & mask != self.base_u128() {
            return None;
        }
        let host = n & !mask;
        (host <= u32::MAX as u128).then_some(host as u32)
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", self.base_addr(), self.prefix)
    }
}

fn split_cidr<'a>(s: &'a str, example: &str) -> anyhow::Result<(&'a str, u8)> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("subnet must use CIDR notation, e.g. {example}"))?;
    let prefix: u8 = prefix
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid prefix length: {e}"))?;
    Ok((addr.trim(), prefix))
}

/// Derive a unique ULA /64 prefix from the network id: `fd` + 40-bit global
/// id + a zero 16-bit subnet id. Two networks with different net ids (or
/// secrets) never collide, and the prefix never needs to travel in the state
/// file because it can be recomputed from `net_id`.
pub fn ula_prefix(net_id: &[u8; 32]) -> V6Net {
    let h = blake3::hash(net_id);
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfd; // ULA, locally assigned
    bytes[1..6].copy_from_slice(&h.as_bytes()[..5]); // 40-bit global id
    V6Net {
        base: bytes,
        prefix: 64,
    }
}

impl AddrPlan {
    pub fn new(v4: Option<V4Net>, v6: Option<V6Net>) -> Self {
        Self { v4, v6 }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.v4.is_some() || self.v6.is_some(),
            "at least one address family (IPv4 or IPv6) must be enabled"
        );
        if let Some(v4) = self.v4 {
            anyhow::ensure!(
                (8..=30).contains(&v4.prefix),
                "IPv4 prefix must be between /8 and /30"
            );
            let mask = u32::MAX << (32 - v4.prefix as u32);
            anyhow::ensure!(v4.base & mask == v4.base, "IPv4 subnet is not aligned");
        }
        if let Some(v6) = self.v6 {
            anyhow::ensure!(
                (32..=96).contains(&v6.prefix),
                "IPv6 prefix must be between /32 and /96"
            );
            anyhow::ensure!(
                v6.base_u128() & V6Net::net_mask(v6.prefix) == v6.base_u128(),
                "IPv6 prefix is not aligned"
            );
        }
        anyhow::ensure!(
            !self.usable_offsets().is_empty(),
            "the virtual subnet has no assignable host addresses"
        );
        Ok(())
    }

    /// Host indexes available to joiners. Offset 0 is the subnet-router
    /// anycast address, offset 1 belongs to the creator, and the last IPv4
    /// address of the subnet is its broadcast address.
    pub fn usable_offsets(&self) -> Range<u32> {
        let mut end = u32::MAX;
        if let Some(v4) = self.v4 {
            let size = 1u64 << (32 - v4.prefix as u32);
            end = end.min((size - 1) as u32);
        }
        if let Some(v6) = self.v6 {
            let host_bits = 128 - v6.prefix as u32;
            let cap = if host_bits >= 32 {
                u64::from(u32::MAX)
            } else {
                (1u64 << host_bits) - 1
            };
            end = end.min(cap as u32);
        }
        2..end
    }

    pub fn addrs(&self, offset: u32) -> VirtualAddrs {
        VirtualAddrs {
            v4: self.v4.map(|n| u32::from(n.addr(offset))),
            v6: self.v6.map(|n| n.addr(offset).octets()),
        }
    }

    pub fn creator_addrs(&self) -> VirtualAddrs {
        self.addrs(1)
    }

    /// Resolve requested `ip` / `ip6` values to a single host index.
    /// When both are given they must describe the same host.
    pub fn offset_of(&self, desired: &VirtualAddrs) -> Result<Option<u32>, String> {
        let mut offset: Option<u32> = None;
        if let Some(raw) = desired.v4 {
            let net = self
                .v4
                .ok_or_else(|| "IPv4 is disabled in this network".to_string())?;
            let ip = Ipv4Addr::from(raw);
            let off = net
                .offset_of(ip)
                .ok_or_else(|| format!("{ip} is outside the virtual subnet {}", net.cidr()))?;
            offset = Some(off);
        }
        if let Some(raw) = desired.v6 {
            let net = self
                .v6
                .ok_or_else(|| "IPv6 is disabled in this network".to_string())?;
            let ip = Ipv6Addr::from(raw);
            let off = net
                .offset_of(ip)
                .ok_or_else(|| format!("{ip} is outside the virtual subnet {}", net.cidr()))?;
            if let Some(prev) = offset {
                if prev != off {
                    return Err(format!(
                        "requested IPv4 and IPv6 addresses map to different host indexes ({prev} vs {off}); \
                         use addresses with the same trailing host part"
                    ));
                }
            }
            offset = Some(off);
        }
        if let Some(off) = offset {
            if !self.usable_offsets().contains(&off) {
                return Err(format!(
                    "host index {off} is reserved or outside the virtual subnet"
                ));
            }
        }
        Ok(offset)
    }

    /// Reject link MTUs that IPv6 cannot work with. IPv4-only networks may
    /// use smaller MTUs (e.g. over a low-MTU tunnel).
    pub fn validate_mtu(&self, mtu: u16) -> anyhow::Result<()> {
        if self.v6.is_some() {
            anyhow::ensure!(
                mtu >= IPV6_MIN_MTU,
                "IPv6 requires a link MTU of at least {IPV6_MIN_MTU} bytes (got {mtu}); \
                 raise \"mtu\" or set \"no-ipv6\" in the config file"
            );
        }
        Ok(())
    }

    pub fn describe(&self) -> String {
        match (self.v4, self.v6) {
            (Some(a), Some(b)) => format!("{}, {}", a.cidr(), b.cidr()),
            (Some(a), None) => a.cidr(),
            (None, Some(b)) => b.cidr(),
            (None, None) => "no address family configured".to_string(),
        }
    }
}

impl VirtualAddrs {
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.v4.map(Ipv4Addr::from)
    }

    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.v6.map(Ipv6Addr::from)
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_none() && self.v6.is_none()
    }

    /// Human readable form used in logs and `status` output.
    pub fn display(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ip) = self.ipv4() {
            parts.push(ip.to_string());
        }
        if let Some(ip) = self.ipv6() {
            parts.push(ip.to_string());
        }
        if parts.is_empty() {
            "-".to_string()
        } else {
            parts.join(", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_v4_cidr() {
        let n = V4Net::parse_cidr("10.13.37.9/24").unwrap();
        assert_eq!(n.cidr(), "10.13.37.0/24");
        assert_eq!(n.offset_of(Ipv4Addr::new(10, 13, 37, 42)), Some(42));
        assert_eq!(n.offset_of(Ipv4Addr::new(10, 13, 38, 42)), None);
        assert!(V4Net::parse_cidr("10.13.37.0/31").is_err());
        assert!(V4Net::parse_cidr("10.13.37.0").is_err());
    }

    #[test]
    fn parses_and_normalizes_v6_cidr() {
        let n = V6Net::parse_cidr("fd12:3456:789a::abcd/64").unwrap();
        assert_eq!(n.cidr(), "fd12:3456:789a::/64");
        assert_eq!(n.addr(2).to_string(), "fd12:3456:789a::2");
        assert_eq!(n.offset_of("fd12:3456:789a::2".parse().unwrap()), Some(2));
        assert_eq!(n.offset_of("fd12:3456:789b::2".parse().unwrap()), None);
        assert!(V6Net::parse_cidr("::/64").is_err());
        assert!(V6Net::parse_cidr("fd00::/120").is_err());
    }

    #[test]
    fn ula_prefix_is_stable_and_unique() {
        let a = ula_prefix(&[1; 32]);
        let b = ula_prefix(&[2; 32]);
        assert_eq!(a, ula_prefix(&[1; 32]));
        assert_ne!(a, b);
        assert_eq!(a.base[0], 0xfd);
        assert_eq!(a.prefix, 64);
        assert_eq!(a.base[6..], [0u8; 10]);
    }

    #[test]
    fn dual_stack_offsets_map_to_both_families() {
        let plan = AddrPlan::new(
            Some(V4Net::parse_cidr(DEFAULT_V4_CIDR).unwrap()),
            Some(V6Net::parse_cidr("fd00:1234:5678:9abc::/64").unwrap()),
        );
        plan.validate().unwrap();
        let addrs = plan.addrs(7);
        assert_eq!(addrs.ipv4().unwrap(), Ipv4Addr::new(10, 13, 37, 7));
        assert_eq!(
            addrs.ipv6().unwrap(),
            "fd00:1234:5678:9abc::7".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(plan.offset_of(&addrs).unwrap(), Some(7));
        assert_eq!(
            plan.creator_addrs().ipv4().unwrap(),
            Ipv4Addr::new(10, 13, 37, 1)
        );
    }

    #[test]
    fn single_stack_plans_are_valid() {
        let v6_only = AddrPlan::new(None, Some(ula_prefix(&[9; 32])));
        v6_only.validate().unwrap();
        assert!(v6_only.addrs(3).ipv4().is_none());
        assert!(v6_only.addrs(3).ipv6().is_some());

        let v4_only = AddrPlan::new(Some(V4Net::parse_cidr(DEFAULT_V4_CIDR).unwrap()), None);
        v4_only.validate().unwrap();
        assert!(v4_only.addrs(3).ipv6().is_none());

        assert!(AddrPlan::default().validate().is_err());
    }

    #[test]
    fn usable_offsets_exclude_reserved_addresses() {
        let plan = AddrPlan::new(Some(V4Net::parse_cidr("10.0.0.0/30").unwrap()), None);
        // /30: .0 network, .1 creator, .2 usable, .3 broadcast
        assert_eq!(plan.usable_offsets(), 2..3);
        assert_eq!(plan.usable_offsets().count(), 1);
    }

    #[test]
    fn mismatched_desired_addresses_are_rejected() {
        let plan = AddrPlan::new(
            Some(V4Net::parse_cidr(DEFAULT_V4_CIDR).unwrap()),
            Some(V6Net::parse_cidr("fd00::/64").unwrap()),
        );
        let bad = VirtualAddrs {
            v4: Some(u32::from(Ipv4Addr::new(10, 13, 37, 5))),
            v6: Some("fd00::6".parse::<Ipv6Addr>().unwrap().octets()),
        };
        assert!(plan
            .offset_of(&bad)
            .unwrap_err()
            .contains("different host indexes"));
        assert_eq!(plan.offset_of(&VirtualAddrs::default()).unwrap(), None);
    }

    #[test]
    fn mtu_lower_bound_only_applies_with_ipv6() {
        let dual = AddrPlan::new(
            Some(V4Net::parse_cidr(DEFAULT_V4_CIDR).unwrap()),
            Some(ula_prefix(&[5; 32])),
        );
        let v4_only = AddrPlan::new(Some(V4Net::parse_cidr(DEFAULT_V4_CIDR).unwrap()), None);
        assert!(dual.validate_mtu(1279).is_err());
        assert!(dual.validate_mtu(IPV6_MIN_MTU).is_ok());
        assert!(dual.validate_mtu(1500).is_ok());
        assert!(v4_only.validate_mtu(576).is_ok());
    }

    #[test]
    fn display_lists_both_families() {
        let a = VirtualAddrs {
            v4: Some(u32::from(Ipv4Addr::new(10, 13, 37, 2))),
            v6: Some("fd00::2".parse::<Ipv6Addr>().unwrap().octets()),
        };
        assert_eq!(a.display(), "10.13.37.2, fd00::2");
        assert_eq!(VirtualAddrs::default().display(), "-");
    }
}
