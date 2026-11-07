//! Link-state routing for the partial-mesh topology.
//!
//! Every node advertises its current mesh neighbors in a
//! [`LinkStateMsg`](crate::proto::LinkStateMsg) on the broadcast bus. Each
//! node assembles these advertisements into a link-state database (LSDB) and
//! derives its own next-hop table with a BFS over the resulting graph, so
//! unicast frames can be relayed across multiple hops without any central
//! controller.
//!
//! The graph is treated as undirected: an edge A—B exists when *either* side
//! lists the other. This keeps routing working while advertisements are still
//! converging, at the cost of possibly routing toward a stale edge until it
//! expires (TCP retransmits cover the gap).
//!
//! Loop safety: shortest-path forwarding is loop-free in the steady state.
//! While the topology is converging, transient loops are possible, so relayed
//! frames carry a hop counter ([`MAX_HOPS`]) that every forwarder decrements.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::proto::IdBytes;

/// Maximum number of relays a unicast frame may traverse.
pub const MAX_HOPS: u8 = 32;
/// How often a node refreshes its own link-state advertisement.
pub const LSA_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// How long an unrefreshed advertisement stays in the database.
pub const LSA_EXPIRE_AFTER: Duration = Duration::from_secs(90);

#[derive(Clone, Debug)]
struct LsaEntry {
    seq: u64,
    neighbors: Vec<IdBytes>,
    received_at: Instant,
}

/// Link-state database plus the next-hop table derived from it.
#[derive(Debug)]
pub struct RoutingTable {
    my_id: IdBytes,
    my_neighbors: HashSet<IdBytes>,
    lsdb: HashMap<IdBytes, LsaEntry>,
    /// destination → first hop on the shortest path.
    next_hop: HashMap<IdBytes, IdBytes>,
}

impl RoutingTable {
    pub fn new(my_id: IdBytes) -> Self {
        Self {
            my_id,
            my_neighbors: HashSet::new(),
            lsdb: HashMap::new(),
            next_hop: HashMap::new(),
        }
    }

    /// Apply a link-state advertisement. Returns `true` if the database
    /// changed (newer sequence number than what we had).
    pub fn apply(&mut self, origin: IdBytes, seq: u64, neighbors: Vec<IdBytes>) -> bool {
        if origin == self.my_id {
            return false;
        }
        if let Some(entry) = self.lsdb.get(&origin) {
            if entry.seq >= seq {
                return false;
            }
        }
        self.lsdb.insert(
            origin,
            LsaEntry {
                seq,
                neighbors,
                received_at: Instant::now(),
            },
        );
        self.recompute();
        true
    }

    /// Update our own live neighbor set. Returns `true` if it changed.
    pub fn set_my_neighbors(&mut self, neighbors: HashSet<IdBytes>) -> bool {
        if neighbors == self.my_neighbors {
            return false;
        }
        self.my_neighbors = neighbors;
        self.recompute();
        true
    }

    /// Drop advertisements that have not been refreshed within
    /// [`LSA_EXPIRE_AFTER`]. Returns `true` if the database changed.
    pub fn expire(&mut self) -> bool {
        let before = self.lsdb.len();
        self.lsdb
            .retain(|_, entry| entry.received_at.elapsed() < LSA_EXPIRE_AFTER);
        if self.lsdb.len() != before {
            self.recompute();
            true
        } else {
            false
        }
    }

    /// Next hop toward `dest`, or `None` if no route is known. Direct
    /// neighbors route to themselves.
    pub fn next_hop(&self, dest: &IdBytes) -> Option<IdBytes> {
        if *dest == self.my_id {
            return None;
        }
        self.next_hop.get(dest).copied()
    }

    /// Number of destinations we currently know a route to.
    pub fn known_destinations(&self) -> usize {
        self.next_hop.len()
    }

    /// Number of advertisements currently in the database.
    pub fn lsdb_size(&self) -> usize {
        self.lsdb.len()
    }

    /// Recompute the next-hop table: BFS over the undirected graph built from
    /// the LSDB plus our own live connections (unit link costs).
    fn recompute(&mut self) {
        let mut adj: HashMap<IdBytes, HashSet<IdBytes>> = HashMap::new();
        let add_edge = |a: &IdBytes, b: &IdBytes, adj: &mut HashMap<IdBytes, HashSet<IdBytes>>| {
            if a == b {
                return;
            }
            adj.entry(*a).or_default().insert(*b);
            adj.entry(*b).or_default().insert(*a);
        };
        for (origin, entry) in &self.lsdb {
            for neighbor in &entry.neighbors {
                add_edge(origin, neighbor, &mut adj);
            }
        }
        for neighbor in &self.my_neighbors {
            add_edge(&self.my_id, neighbor, &mut adj);
        }

        // BFS from self; `first` tracks the first hop on the discovered path.
        let mut dist: HashMap<IdBytes, u32> = HashMap::new();
        let mut first: HashMap<IdBytes, IdBytes> = HashMap::new();
        let mut queue: VecDeque<(IdBytes, IdBytes)> = VecDeque::new(); // (node, first_hop)
        dist.insert(self.my_id, 0);
        if let Some(neighbors) = adj.get(&self.my_id) {
            for n in neighbors {
                dist.insert(*n, 1);
                first.insert(*n, *n);
                queue.push_back((*n, *n));
            }
        }
        while let Some((node, hop)) = queue.pop_front() {
            let d = dist[&node];
            if let Some(neighbors) = adj.get(&node) {
                for n in neighbors {
                    if !dist.contains_key(n) {
                        dist.insert(*n, d + 1);
                        first.insert(*n, hop);
                        queue.push_back((*n, hop));
                    }
                }
            }
        }
        self.next_hop = first;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> IdBytes {
        IdBytes([seed; 32])
    }

    fn set(items: &[u8]) -> HashSet<IdBytes> {
        items.iter().map(|s| id(*s)).collect()
    }

    #[test]
    fn direct_neighbors_route_to_themselves() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_neighbors(set(&[2, 3]));
        assert_eq!(rt.next_hop(&id(2)), Some(id(2)));
        assert_eq!(rt.next_hop(&id(3)), Some(id(3)));
        assert_eq!(rt.next_hop(&id(9)), None);
        assert_eq!(rt.next_hop(&id(1)), None, "self is never a destination");
    }

    #[test]
    fn two_hop_chain_routes_via_middle() {
        // 1 — 2 — 3: node 1 knows 2 directly and hears 2's LSA about 3.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_neighbors(set(&[2]));
        rt.apply(id(2), 1, vec![id(1), id(3)]);
        assert_eq!(rt.next_hop(&id(3)), Some(id(2)));
        assert_eq!(rt.known_destinations(), 2);
    }

    #[test]
    fn multi_hop_chain_first_hop_stays_stable() {
        // 1 — 2 — 3 — 4: node 1 should route to 4 via 2.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_neighbors(set(&[2]));
        rt.apply(id(2), 1, vec![id(1), id(3)]);
        rt.apply(id(3), 1, vec![id(2), id(4)]);
        rt.apply(id(4), 1, vec![id(3)]);
        assert_eq!(rt.next_hop(&id(4)), Some(id(2)));
        assert_eq!(rt.next_hop(&id(3)), Some(id(2)));
    }

    #[test]
    fn partitioned_graph_has_no_route() {
        // 1—2 and 3—4 are separate components.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_neighbors(set(&[2]));
        rt.apply(id(2), 1, vec![id(1)]);
        rt.apply(id(3), 1, vec![id(4)]);
        rt.apply(id(4), 1, vec![id(3)]);
        assert_eq!(rt.next_hop(&id(2)), Some(id(2)));
        assert_eq!(rt.next_hop(&id(3)), None);
        assert_eq!(rt.next_hop(&id(4)), None);
    }

    #[test]
    fn edges_are_undirected_from_either_side() {
        // Only node 2's LSA has arrived; the 1—2 edge still exists because
        // node 1 lists 2 among its own neighbors.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_neighbors(set(&[2]));
        rt.apply(id(2), 5, vec![id(3)]);
        rt.apply(id(3), 5, vec![id(2)]);
        assert_eq!(rt.next_hop(&id(3)), Some(id(2)));
    }

    #[test]
    fn stale_sequence_numbers_are_ignored() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_neighbors(set(&[2]));
        assert!(rt.apply(id(2), 7, vec![id(1), id(3)]));
        assert!(!rt.apply(id(2), 6, vec![id(1)]), "older seq rejected");
        assert!(!rt.apply(id(2), 7, vec![id(1)]), "same seq rejected");
        assert_eq!(rt.next_hop(&id(3)), Some(id(2)), "newer topology survives");

        assert!(rt.apply(id(2), 8, vec![id(1)]), "newer seq accepted");
        assert_eq!(rt.next_hop(&id(3)), None);
    }

    #[test]
    fn own_lsas_are_not_applied() {
        let mut rt = RoutingTable::new(id(1));
        assert!(!rt.apply(id(1), 99, vec![id(2), id(3)]));
    }

    #[test]
    fn expire_removes_stale_advertisements() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_neighbors(set(&[2]));
        rt.apply(id(2), 1, vec![id(1), id(3)]);
        assert_eq!(rt.next_hop(&id(3)), Some(id(2)));

        // Age the entry beyond the expiry window.
        {
            let entry = rt.lsdb.get_mut(&id(2)).unwrap();
            entry.received_at -= LSA_EXPIRE_AFTER + Duration::from_secs(1);
        }
        assert!(rt.expire());
        assert_eq!(rt.lsdb_size(), 0);
        assert_eq!(rt.next_hop(&id(3)), None);
        assert_eq!(rt.next_hop(&id(2)), Some(id(2)), "direct neighbor survives");

        assert!(!rt.expire(), "second expire is a no-op");
    }

    #[test]
    fn shortest_path_preferred_over_longer_alternative() {
        // 1—2, 2—4, 1—3, 3—4: route to 4 should prefer either 2 or 3 (both
        // length 2); assert it is one of them and never 2 via a longer path.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_neighbors(set(&[2, 3]));
        rt.apply(id(2), 1, vec![id(1), id(4)]);
        rt.apply(id(3), 1, vec![id(1), id(4)]);
        rt.apply(id(4), 1, vec![id(2), id(3)]);
        let hop = rt.next_hop(&id(4)).unwrap();
        assert!(hop == id(2) || hop == id(3));
    }

    #[test]
    fn self_loops_and_duplicate_edges_are_harmless() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_neighbors(set(&[2]));
        rt.apply(id(2), 1, vec![id(2), id(1), id(1)]);
        assert_eq!(rt.next_hop(&id(2)), Some(id(2)));
    }
}
