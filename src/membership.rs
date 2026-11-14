//! Membership table: who is in the virtual LAN.
//!
//! Serves three purposes:
//! * MAC routing table — the virtual MAC is derived from the endpoint id, so
//!   `mac -> EndpointId` lookups drive all unicast forwarding.
//! * Announcement state — entries expire unless refreshed periodically.
//! * The `address -> hostname` view shown by `irohlan status`.

use std::collections::HashMap;
use std::net::IpAddr;
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
    /// MAC → endpoint id index. The virtual MAC is a pure function of the
    /// endpoint id, so the index only changes on insert/remove. `by_mac`
    /// runs for every forwarded unicast frame (twice on a relaying node)
    /// and must be O(1) — a scan would pay one blake3 hash per member for
    /// every frame.
    macs: RwLock<HashMap<[u8; 6], IdBytes>>,
}

impl Membership {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or refresh a member. Returns `true` if this introduced a
    /// previously unknown endpoint id or changed its address.
    pub fn upsert(&self, record: MemberRecord) -> bool {
        let id = record.id;
        let mac = crate::crypto::mac_from_id(id.as_bytes());
        let mut peers = self.peers.write().expect("membership lock poisoned");
        let changed = match peers.get_mut(&id) {
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
                    id,
                    MemberInfo {
                        record,
                        last_seen: Instant::now(),
                    },
                );
                true
            }
        };
        drop(peers);
        if changed {
            // The MAC is derived from the id, so this can only ever (re)write
            // the same entry — an address refresh changes no key here.
            self.macs
                .write()
                .expect("membership lock poisoned")
                .insert(mac, id);
        }
        changed
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
        let mut dropped = Vec::with_capacity(stale.len());
        for id in &stale {
            if let Some(info) = peers.remove(id) {
                dropped.push(info.record);
            }
        }
        drop(peers);
        if !dropped.is_empty() {
            let mut macs = self.macs.write().expect("membership lock poisoned");
            for info in &dropped {
                macs.remove(&crate::crypto::mac_from_id(info.id.as_bytes()));
            }
        }
        dropped
    }

    pub fn get(&self, id: &IdBytes) -> Option<MemberInfo> {
        self.peers
            .read()
            .expect("membership lock poisoned")
            .get(id)
            .cloned()
    }

    /// Resolve a destination MAC to a member record. `None` means the frame
    /// targets a MAC that is not (or no longer) a member of this LAN.
    ///
    /// O(1) through the MAC index: the index maps MAC → id, and the member
    /// table holds the record. The two locks are always taken one after the
    /// other, never nested.
    pub fn by_mac(&self, mac: &[u8; 6]) -> Option<MemberInfo> {
        let id = *self.macs.read().expect("membership lock poisoned").get(mac)?;
        self.peers
            .read()
            .expect("membership lock poisoned")
            .get(&id)
            .cloned()
    }

    /// Resolve a virtual IPv4 or IPv6 address to a member record (self
    /// excluded). Used by tests; kept as part of the lookup surface.
    #[allow(dead_code)]
    pub fn by_ip(&self, ip: IpAddr) -> Option<MemberInfo> {
        let peers = self.peers.read().expect("membership lock poisoned");
        peers
            .values()
            .find(|info| match ip {
                IpAddr::V4(v4) => info.record.ipv4() == Some(v4),
                IpAddr::V6(v6) => info.record.ipv6() == Some(v6),
            })
            .cloned()
    }

    pub fn all(&self) -> Vec<MemberInfo> {
        self.peers
            .read()
            .expect("membership lock poisoned")
            .values()
            .cloned()
            .collect()
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
    use crate::netaddr::VirtualAddrs;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn rec(seed: u8, addrs: VirtualAddrs) -> MemberRecord {
        MemberRecord {
            id: IdBytes([seed; 32]),
            addrs,
            hostname: format!("host-{seed}"),
        }
    }

    fn dual(offset: u8) -> VirtualAddrs {
        VirtualAddrs {
            v4: Some(u32::from(Ipv4Addr::new(10, 13, 37, offset))),
            v6: Some(
                format!("fd00::{offset:x}")
                    .parse::<Ipv6Addr>()
                    .unwrap()
                    .octets(),
            ),
        }
    }

    #[test]
    fn upsert_and_lookup_by_mac_and_ip() {
        let m = Membership::new();
        let r = rec(1, dual(2));
        assert!(m.upsert(r.clone()), "first insert reports new");
        assert!(!m.upsert(r.clone()), "refresh reports unchanged");

        let mac = crate::crypto::mac_from_id(r.id.as_bytes());
        assert_eq!(m.by_mac(&mac).unwrap().record, r);
        assert_eq!(
            m.by_ip(IpAddr::V4(Ipv4Addr::new(10, 13, 37, 2)))
                .unwrap()
                .record,
            r
        );
        assert_eq!(
            m.by_ip(IpAddr::V6("fd00::2".parse().unwrap()))
                .unwrap()
                .record,
            r
        );
        assert!(m.by_mac(&[0xaa; 6]).is_none());
        assert!(m.by_ip(IpAddr::V4(Ipv4Addr::new(10, 13, 37, 99))).is_none());
    }

    #[test]
    fn ip_change_is_reported_and_updated() {
        let m = Membership::new();
        m.upsert(rec(1, dual(2)));
        assert!(m.upsert(rec(1, dual(3))));
        assert!(m.by_ip(IpAddr::V4(Ipv4Addr::new(10, 13, 37, 3))).is_some());
        assert!(m.by_ip(IpAddr::V6("fd00::3".parse().unwrap())).is_some());
        assert!(m.by_ip(IpAddr::V4(Ipv4Addr::new(10, 13, 37, 2))).is_none());
        assert!(m.by_ip(IpAddr::V6("fd00::2".parse().unwrap())).is_none());
    }

    #[test]
    fn mac_index_tracks_insert_refresh_and_expiry() {
        let m = Membership::new();
        let r = rec(4, dual(5));
        let mac = crate::crypto::mac_from_id(r.id.as_bytes());
        assert!(m.by_mac(&mac).is_none(), "nothing indexed before insert");

        m.upsert(r.clone());
        assert_eq!(m.by_mac(&mac).unwrap().record, r);
        // A refresh with unchanged record must not disturb the index.
        assert!(!m.upsert(r.clone()));
        assert!(m.by_mac(&mac).is_some());
        // An address change re-indexes the same MAC.
        assert!(m.upsert(rec(4, dual(6))));
        assert!(m.by_mac(&mac).is_some());

        // Expiry removes the member and its index entry.
        {
            let mut peers = m.peers.write().unwrap();
            for info in peers.values_mut() {
                info.last_seen -= MEMBER_TTL + Duration::from_secs(1);
            }
        }
        assert_eq!(m.expire().len(), 1);
        assert!(m.by_mac(&mac).is_none(), "expired member leaves the index");
    }

    #[test]
    fn expire_drops_only_stale_entries() {
        let m = Membership::new();
        m.upsert(rec(1, dual(2)));
        m.upsert(rec(2, dual(3)));
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
