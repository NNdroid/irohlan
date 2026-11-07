//! Membership table: who is in the virtual LAN.
//!
//! Serves three purposes:
//! * MAC routing table — the virtual MAC is derived from the endpoint id, so
//!   `mac -> EndpointId` lookups drive all unicast forwarding.
//! * Announcement state — entries expire unless refreshed periodically.
//! * The `ip -> hostname` view shown by `irohlan status`.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::proto::{IdBytes, MemberRecord};

/// How long a member stays in the table without an announcement.
pub const MEMBER_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct MemberInfo {
    pub record: MemberRecord,
    pub last_seen: Instant,
}

#[derive(Debug, Default)]
pub struct Membership {
    peers: RwLock<HashMap<IdBytes, MemberInfo>>,
}

impl Membership {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or refresh a member. Returns `true` if this introduced a
    /// previously unknown endpoint id or changed its address.
    pub fn upsert(&self, record: MemberRecord) -> bool {
        let mut peers = self.peers.write().expect("membership lock poisoned");
        match peers.get_mut(&record.id) {
            Some(info) => {
                info.last_seen = Instant::now();
                if info.record != record {
                    *info = MemberInfo {
                        record,
                        last_seen: Instant::now(),
                    };
                    true
                } else {
                    false
                }
            }
            None => {
                peers.insert(
                    record.id,
                    MemberInfo {
                        record,
                        last_seen: Instant::now(),
                    },
                );
                true
            }
        }
    }

    /// Remove members that have not announced themselves within [`MEMBER_TTL`].
    /// Returns the records that were dropped.
    pub fn expire(&self) -> Vec<MemberRecord> {
        let mut peers = self.peers.write().expect("membership lock poisoned");
        let stale: Vec<IdBytes> = peers
            .iter()
            .filter(|(_, info)| info.last_seen.elapsed() > MEMBER_TTL)
            .map(|(id, _)| *id)
            .collect();
        stale
            .into_iter()
            .filter_map(|id| peers.remove(&id).map(|i| i.record))
            .collect()
    }

    pub fn get(&self, id: &IdBytes) -> Option<MemberInfo> {
        self.peers.read().expect("membership lock poisoned").get(id).cloned()
    }

    /// Resolve a destination MAC to a member record. `None` means the frame
    /// targets a MAC that is not (or no longer) a member of this LAN.
    pub fn by_mac(&self, mac: &[u8; 6]) -> Option<MemberInfo> {
        let peers = self.peers.read().expect("membership lock poisoned");
        peers
            .values()
            .find(|info| crate::crypto::mac_from_id(info.record.id.as_bytes()) == *mac)
            .cloned()
    }

    /// Resolve a virtual IP to a member record (self excluded).
    /// Used by tests; kept as part of the lookup surface.
    #[allow(dead_code)]
    pub fn by_ip(&self, ip: Ipv4Addr) -> Option<MemberInfo> {
        let peers = self.peers.read().expect("membership lock poisoned");
        peers
            .values()
            .find(|info| info.record.ip() == ip)
            .cloned()
    }

    pub fn all(&self) -> Vec<MemberInfo> {
        self.peers.read().expect("membership lock poisoned").values().cloned().collect()
    }

    #[allow(dead_code)] // used by tests and future status output
    pub fn len(&self) -> usize {
        self.peers.read().expect("membership lock poisoned").len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(seed: u8, ip: u32) -> MemberRecord {
        MemberRecord {
            id: IdBytes([seed; 32]),
            ip,
            hostname: format!("host-{seed}"),
        }
    }

    #[test]
    fn upsert_and_lookup_by_mac_and_ip() {
        let m = Membership::new();
        let r = rec(1, u32::from(Ipv4Addr::new(10, 13, 37, 2)));
        assert!(m.upsert(r.clone()), "first insert reports new");
        assert!(!m.upsert(r.clone()), "refresh reports unchanged");

        let mac = crate::crypto::mac_from_id(r.id.as_bytes());
        assert_eq!(m.by_mac(&mac).unwrap().record, r);
        assert_eq!(m.by_ip(Ipv4Addr::new(10, 13, 37, 2)).unwrap().record, r);
        assert!(m.by_mac(&[0xaa; 6]).is_none());
        assert!(m.by_ip(Ipv4Addr::new(10, 13, 37, 99)).is_none());
    }

    #[test]
    fn ip_change_is_reported_and_updated() {
        let m = Membership::new();
        m.upsert(rec(1, u32::from(Ipv4Addr::new(10, 13, 37, 2))));
        assert!(m.upsert(rec(1, u32::from(Ipv4Addr::new(10, 13, 37, 3)))));
        assert!(m.by_ip(Ipv4Addr::new(10, 13, 37, 3)).is_some());
        assert!(m.by_ip(Ipv4Addr::new(10, 13, 37, 2)).is_none());
    }

    #[test]
    fn expire_drops_only_stale_entries() {
        let m = Membership::new();
        m.upsert(rec(1, 1));
        m.upsert(rec(2, 2));
        assert_eq!(m.expire().len(), 0, "fresh entries survive");

        // age all entries beyond the TTL
        let mut peers = m.peers.write().unwrap();
        for info in peers.values_mut() {
            info.last_seen -= MEMBER_TTL + Duration::from_secs(1);
        }
        drop(peers);

        let dropped = m.expire();
        assert_eq!(dropped.len(), 2);
        assert!(m.is_empty());
    }
}
