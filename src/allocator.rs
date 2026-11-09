//! Creator-side virtual address allocation (a tiny DHCP for both families).
//!
//! The creator keeps a lease table persisted to the node's state directory.
//! A lease is keyed by a *host index*: offset 1 is reserved for the creator,
//! joiners get offsets from 2 up. The index derives the IPv4 address, the IPv6
//! address, or both, depending on the network's [`AddrPlan`].
//!
//! For IPv4 networks the persisted key is `v4_base + offset`, which is exactly
//! the IPv4 address used as key by v1 lease files — old `leases.json` files
//! therefore stay valid after an upgrade. IPv6-only networks key by the raw
//! offset.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::netaddr::{AddrPlan, VirtualAddrs};
use crate::proto::IdBytes;

/// One granted lease.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lease {
    pub endpoint_id: IdBytes,
    pub hostname: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct LeaseFile {
    /// Key: IPv4 address (dual-stack / IPv4-only) or raw offset (IPv6-only).
    leases: BTreeMap<u32, Lease>,
}

#[derive(Debug)]
pub struct Allocator {
    plan: AddrPlan,
    state: LeaseFile,
    path: Option<PathBuf>,
}

#[allow(dead_code)] // ops-facing helpers kept for future tooling
impl Allocator {
    /// Create an allocator for `plan`, optionally persisting leases.
    pub fn new(plan: AddrPlan, path: Option<PathBuf>) -> anyhow::Result<Self> {
        plan.validate()?;
        let state = match &path {
            Some(p) if p.exists() => {
                let raw = std::fs::read(p)?;
                serde_json::from_slice(&raw)
                    .map_err(|e| anyhow::anyhow!("corrupt lease file {}: {e}", p.display()))?
            }
            _ => LeaseFile::default(),
        };
        Ok(Self { plan, state, path })
    }

    /// The addresses the creator assigns to itself.
    pub fn creator_addrs(&self) -> VirtualAddrs {
        self.plan.creator_addrs()
    }

    /// Total number of assignable host indexes.
    pub fn capacity(&self) -> usize {
        self.plan.usable_offsets().count()
    }

    /// Persisted key for a host index.
    fn key(&self, offset: u32) -> u32 {
        match self.plan.v4 {
            Some(v4) => v4.base.wrapping_add(offset),
            None => offset,
        }
    }

    /// Inverse of [`Self::key`]; `None` for keys outside the current subnet
    /// (e.g. stale entries from a previously configured prefix).
    fn offset_of_key(&self, key: u32) -> Option<u32> {
        match self.plan.v4 {
            Some(v4) => {
                let offset = key.wrapping_sub(v4.base);
                let size = 1u64 << (32 - v4.prefix as u32);
                (u64::from(offset) < size).then_some(offset)
            }
            None => Some(key),
        }
    }

    /// Grant (or confirm) a lease for `endpoint_id`.
    ///
    /// * `desired` — honored when free or already leased by the same endpoint.
    ///   `ip` and `ip6` must resolve to the same host index.
    /// * Otherwise the lowest free index is granted.
    /// * If the endpoint already holds a lease, that lease is returned
    ///   unchanged (stable addressing across rejoin).
    pub fn assign(
        &mut self,
        endpoint_id: IdBytes,
        hostname: &str,
        desired: VirtualAddrs,
    ) -> Result<VirtualAddrs, String> {
        // Existing lease for this endpoint wins (stable address).
        let existing = self
            .state
            .leases
            .iter()
            .find(|(key, l)| l.endpoint_id == endpoint_id && self.offset_of_key(**key).is_some())
            .map(|(key, l)| (*key, l.hostname.clone()));
        if let Some((key, old_hostname)) = existing {
            if old_hostname != hostname {
                if let Some(lease) = self.state.leases.get_mut(&key) {
                    lease.hostname = hostname.to_string();
                }
                self.save().ok();
            }
            let offset = self.offset_of_key(key).expect("checked above");
            return Ok(self.plan.addrs(offset));
        }

        let requested = self.plan.offset_of(&desired)?;
        if let Some(offset) = requested {
            if self.state.leases.contains_key(&self.key(offset)) {
                return Err(format!("{} is already in use", desired.display()));
            }
            self.grant(offset, endpoint_id, hostname)?;
            return Ok(self.plan.addrs(offset));
        }

        for offset in self.plan.usable_offsets() {
            if !self.state.leases.contains_key(&self.key(offset)) {
                self.grant(offset, endpoint_id, hostname)?;
                return Ok(self.plan.addrs(offset));
            }
        }
        Err("no free addresses left in the virtual subnet".into())
    }

    fn grant(&mut self, offset: u32, endpoint_id: IdBytes, hostname: &str) -> Result<(), String> {
        self.state.leases.insert(
            self.key(offset),
            Lease {
                endpoint_id,
                hostname: hostname.to_string(),
            },
        );
        self.save()
            .map_err(|e| format!("failed to persist lease: {e}"))
    }

    /// Release the lease of an endpoint (e.g. explicitly leaving).
    pub fn release(&mut self, endpoint_id: &IdBytes) {
        self.state
            .leases
            .retain(|_, lease| lease.endpoint_id != *endpoint_id);
        self.save().ok();
    }

    fn save(&self) -> anyhow::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(&self.state)?)?;
        Ok(())
    }

    /// Snapshot of current leases.
    pub fn leases(&self) -> &BTreeMap<u32, Lease> {
        &self.state.leases
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netaddr::{ula_prefix, V4Net, V6Net};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn id(seed: u8) -> IdBytes {
        IdBytes([seed; 32])
    }

    fn v4_plan() -> AddrPlan {
        AddrPlan::new(Some(V4Net::parse_cidr("10.13.37.0/24").unwrap()), None)
    }

    fn dual_plan() -> AddrPlan {
        AddrPlan::new(
            Some(V4Net::parse_cidr("10.13.37.0/24").unwrap()),
            Some(V6Net::parse_cidr("fd00:1234:5678:9abc::/64").unwrap()),
        )
    }

    fn tmp_path(name: &str) -> Option<PathBuf> {
        let dir = std::env::temp_dir().join(format!("irohlan-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join(name))
    }

    #[test]
    fn assigns_sequential_addresses_after_creator() {
        let mut a = Allocator::new(v4_plan(), None).unwrap();
        assert_eq!(a.creator_addrs().ipv4(), Some(Ipv4Addr::new(10, 13, 37, 1)));
        assert_eq!(
            a.assign(id(1), "a", VirtualAddrs::default())
                .unwrap()
                .ipv4(),
            Some(Ipv4Addr::new(10, 13, 37, 2))
        );
        assert_eq!(
            a.assign(id(2), "b", VirtualAddrs::default())
                .unwrap()
                .ipv4(),
            Some(Ipv4Addr::new(10, 13, 37, 3))
        );
    }

    #[test]
    fn rejoining_endpoint_keeps_its_lease() {
        let mut a = Allocator::new(v4_plan(), None).unwrap();
        let first = a.assign(id(1), "a", VirtualAddrs::default()).unwrap();
        let again = a.assign(id(1), "a", VirtualAddrs::default()).unwrap();
        assert_eq!(first, again);
    }

    #[test]
    fn desired_ip_honored_and_conflicts_rejected() {
        let mut a = Allocator::new(v4_plan(), None).unwrap();
        let want = VirtualAddrs {
            v4: Some(u32::from(Ipv4Addr::new(10, 13, 37, 42))),
            v6: None,
        };
        assert_eq!(a.assign(id(1), "a", want).unwrap(), a.plan.addrs(42));
        assert_eq!(
            a.assign(id(2), "b", want).unwrap_err(),
            "10.13.37.42 is already in use"
        );
        // re-request by owner succeeds
        assert_eq!(a.assign(id(1), "a", want).unwrap(), a.plan.addrs(42));
        // desired outside subnet rejected
        let outside = VirtualAddrs {
            v4: Some(u32::from(Ipv4Addr::new(192, 168, 5, 5))),
            v6: None,
        };
        assert!(a.assign(id(3), "c", outside).is_err());
    }

    #[test]
    fn subnet_bounds_respected() {
        let plan = AddrPlan::new(Some(V4Net::parse_cidr("10.0.0.0/30").unwrap()), None);
        let mut a = Allocator::new(plan, None).unwrap();
        // /30: network .0, creator .1, usable .2, broadcast .3
        assert_eq!(a.capacity(), 1);
        assert_eq!(
            a.assign(id(1), "a", VirtualAddrs::default())
                .unwrap()
                .ipv4(),
            Some(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert!(
            a.assign(id(2), "b", VirtualAddrs::default()).is_err(),
            "no space left"
        );
    }

    #[test]
    fn dual_stack_lease_grants_both_addresses() {
        let mut a = Allocator::new(dual_plan(), None).unwrap();
        let addrs = a.assign(id(1), "a", VirtualAddrs::default()).unwrap();
        assert_eq!(addrs.ipv4(), Some(Ipv4Addr::new(10, 13, 37, 2)));
        assert_eq!(
            addrs.ipv6(),
            Some("fd00:1234:5678:9abc::2".parse::<Ipv6Addr>().unwrap())
        );
        // A v6-only request resolves to the same host index.
        let want6 = VirtualAddrs {
            v4: None,
            v6: Some(
                "fd00:1234:5678:9abc::7"
                    .parse::<Ipv6Addr>()
                    .unwrap()
                    .octets(),
            ),
        };
        let got = a.assign(id(2), "b", want6).unwrap();
        assert_eq!(got.ipv4(), Some(Ipv4Addr::new(10, 13, 37, 7)));
    }

    #[test]
    fn ipv6_only_network_allocates_offsets() {
        let plan = AddrPlan::new(None, Some(ula_prefix(&[3; 32])));
        let mut a = Allocator::new(plan, None).unwrap();
        let addrs = a.assign(id(1), "a", VirtualAddrs::default()).unwrap();
        assert!(addrs.ipv4().is_none());
        assert_eq!(addrs.ipv6(), Some(plan.addrs(2).ipv6().unwrap()));
        assert_eq!(a.leases().keys().next(), Some(&2));
    }

    #[test]
    fn v1_lease_keys_stay_valid() {
        // v1 stored IPv4 addresses as keys; the offset must be recovered.
        let path = tmp_path("legacy.json").unwrap();
        let key = u32::from(Ipv4Addr::new(10, 13, 37, 42));
        let ids = vec!["9"; 32].join(",");
        let raw =
            format!(r#"{{"leases":{{"{key}":{{"endpoint_id":[{ids}],"hostname":"persisted"}}}}}}"#);
        std::fs::write(&path, raw).unwrap();
        let mut a = Allocator::new(v4_plan(), Some(path)).unwrap();
        assert_eq!(
            a.assign(id(9), "persisted", VirtualAddrs::default())
                .unwrap()
                .ipv4(),
            Some(Ipv4Addr::new(10, 13, 37, 42))
        );
    }

    #[test]
    fn leases_persist_and_reload() {
        let path = tmp_path("leases.json").unwrap();
        std::fs::remove_file(&path).ok();
        {
            let mut a = Allocator::new(v4_plan(), Some(path.clone())).unwrap();
            a.assign(id(9), "persisted", VirtualAddrs::default())
                .unwrap();
        }
        let a = Allocator::new(v4_plan(), Some(path)).unwrap();
        let lease = a.leases().values().next().unwrap();
        assert_eq!(lease.endpoint_id, id(9));
        assert_eq!(lease.hostname, "persisted");
    }
}
