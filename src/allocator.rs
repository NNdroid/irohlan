//! Creator-side virtual IP allocation (a tiny DHCP).
//!
//! The creator keeps a lease table persisted to the node's state directory.
//! The first address of the subnet is reserved for the creator itself,
//! joiners get addresses from `.2` up to the last usable address.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::proto::IdBytes;

/// One granted lease.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lease {
    pub endpoint_id: IdBytes,
    pub hostname: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct LeaseFile {
    /// Key: IPv4 address as u32.
    leases: BTreeMap<u32, Lease>,
}

#[derive(Debug)]
pub struct Allocator {
    base: Ipv4Addr,
    prefix: u8,
    state: LeaseFile,
    path: Option<PathBuf>,
}

#[allow(dead_code)] // ops-facing helpers kept for future tooling
impl Allocator {
    /// Create an allocator for `base/prefix`, optionally persisting leases.
    pub fn new(base: Ipv4Addr, prefix: u8, path: Option<PathBuf>) -> anyhow::Result<Self> {
        anyhow::ensure!((8..=30).contains(&prefix), "unsupported prefix /{prefix}");
        let state = match &path {
            Some(p) if p.exists() => {
                let raw = std::fs::read(p)?;
                serde_json::from_slice(&raw)
                    .map_err(|e| anyhow::anyhow!("corrupt lease file {}: {e}", p.display()))?
            }
            _ => LeaseFile::default(),
        };
        Ok(Self {
            base,
            prefix,
            state,
            path,
        })
    }

    /// The address the creator assigns to itself.
    pub fn creator_ip(&self) -> Ipv4Addr {
        self.offset_addr(1)
    }

    /// Total number of assignable addresses (excluding network, creator and
    /// broadcast addresses).
    pub fn capacity(&self) -> usize {
        self.usable_range().count()
    }

    fn usable_range(&self) -> std::ops::Range<u32> {
        let base_u32 = u32::from(self.base);
        let size: u32 = 1u32
            .checked_shl(32 - self.prefix as u32)
            .unwrap_or(u32::MAX);
        let last = base_u32.wrapping_add(size).wrapping_sub(1); // broadcast
        (base_u32 + 2)..last // (base+2) ..= (last-1) via exclusive range
    }

    fn offset_addr(&self, offset: u32) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.base).wrapping_add(offset))
    }

    /// Grant (or confirm) a lease for `endpoint_id`.
    ///
    /// * `desired` — honored when free or already leased by the same endpoint.
    /// * Otherwise the lowest free address is granted.
    /// * If the endpoint already holds a lease, that lease is returned
    ///   unchanged (stable addressing across rejoin).
    pub fn assign(
        &mut self,
        endpoint_id: IdBytes,
        hostname: &str,
        desired: Option<Ipv4Addr>,
    ) -> Result<Ipv4Addr, String> {
        // Existing lease for this endpoint wins (stable address).
        if let Some((ip, lease)) = self
            .state
            .leases
            .iter()
            .find(|(_, l)| l.endpoint_id == endpoint_id)
        {
            let ip = Ipv4Addr::from(*ip);
            if lease.hostname != hostname {
                self.save().ok();
            }
            return Ok(ip);
        }

        if let Some(want) = desired {
            if self.state.leases.contains_key(&u32::from(want)) {
                return Err(format!("{want} is already in use"));
            }
            let in_range = self.usable_range().contains(&u32::from(want));
            if !in_range {
                return Err(format!("{want} is outside the virtual subnet"));
            }
            self.grant(want, endpoint_id, hostname)?;
            return Ok(want);
        }

        for candidate in self.usable_range() {
            if !self.state.leases.contains_key(&candidate) {
                let ip = Ipv4Addr::from(candidate);
                self.grant(ip, endpoint_id, hostname)?;
                return Ok(ip);
            }
        }
        Err("no free addresses left in the virtual subnet".into())
    }

    fn grant(&mut self, ip: Ipv4Addr, endpoint_id: IdBytes, hostname: &str) -> Result<(), String> {
        self.state.leases.insert(
            u32::from(ip),
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

    fn id(seed: u8) -> IdBytes {
        IdBytes([seed; 32])
    }

    fn tmp_path() -> Option<PathBuf> {
        let dir = std::env::temp_dir().join(format!(
            "irohlan-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join("leases.json"))
    }

    #[test]
    fn assigns_sequential_addresses_after_creator() {
        let mut a =
            Allocator::new(Ipv4Addr::new(10, 13, 37, 0), 24, None).unwrap();
        assert_eq!(a.creator_ip(), Ipv4Addr::new(10, 13, 37, 1));
        assert_eq!(
            a.assign(id(1), "a", None).unwrap(),
            Ipv4Addr::new(10, 13, 37, 2)
        );
        assert_eq!(
            a.assign(id(2), "b", None).unwrap(),
            Ipv4Addr::new(10, 13, 37, 3)
        );
    }

    #[test]
    fn rejoining_endpoint_keeps_its_lease() {
        let mut a =
            Allocator::new(Ipv4Addr::new(10, 13, 37, 0), 24, None).unwrap();
        let first = a.assign(id(1), "a", None).unwrap();
        let again = a.assign(id(1), "a", None).unwrap();
        assert_eq!(first, again);
    }

    #[test]
    fn desired_ip_honored_and_conflicts_rejected() {
        let mut a =
            Allocator::new(Ipv4Addr::new(10, 13, 37, 0), 24, None).unwrap();
        let want = Ipv4Addr::new(10, 13, 37, 42);
        assert_eq!(a.assign(id(1), "a", Some(want)).unwrap(), want);
        assert_eq!(
            a.assign(id(2), "b", Some(want)).unwrap_err(),
            format!("{want} is already in use")
        );
        // re-request by owner succeeds
        assert_eq!(a.assign(id(1), "a", Some(want)).unwrap(), want);
        // desired outside subnet rejected
        assert!(a
            .assign(id(3), "c", Some(Ipv4Addr::new(192, 168, 5, 5)))
            .is_err());
    }

    #[test]
    fn subnet_bounds_respected() {
        let mut a = Allocator::new(Ipv4Addr::new(10, 0, 0, 0), 30, None).unwrap();
        // /30: network .0, creator .1, usable .2, broadcast .3
        assert_eq!(a.capacity(), 1);
        assert_eq!(
            a.assign(id(1), "a", None).unwrap(),
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert!(a.assign(id(2), "b", None).is_err(), "no space left");
    }

    #[test]
    fn leases_persist_and_reload() {
        let path = tmp_path().unwrap();
        std::fs::remove_file(&path).ok();
        {
            let mut a =
                Allocator::new(Ipv4Addr::new(10, 13, 37, 0), 24, Some(path.clone()))
                    .unwrap();
            a.assign(id(9), "persisted", None).unwrap();
        }
        let a = Allocator::new(Ipv4Addr::new(10, 13, 37, 0), 24, Some(path)).unwrap();
        let lease = a.leases().values().next().unwrap();
        assert_eq!(lease.endpoint_id, id(9));
        assert_eq!(lease.hostname, "persisted");
    }
}
