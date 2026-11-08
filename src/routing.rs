//! Link-quality-weighted link-state routing for the partial-mesh topology.
//!
//! Every node advertises its current mesh neighbors together with the
//! measured quality of each QUIC link
//! ([`LinkStateMsg`](crate::proto::LinkStateMsg)): smoothed RTT, windowed
//! packet loss, observed send throughput and the congestion controller's
//! bandwidth estimate. Each node assembles these advertisements into a
//! link-state database (LSDB) and derives its own next-hop table with
//! Dijkstra over the resulting weighted graph.
//!
//! Link cost is `RTT_ms + PER_HOP_PENALTY_MS + quality penalties`. The fixed
//! per-hop component keeps a many-hop path from beating a reasonably direct
//! one; the quality components penalise loss, low estimated bandwidth and
//! saturation. A healthy link with no loss/bandwidth data has zero penalty,
//! so the model degenerates to the v4 RTT-only cost when QUIC exposes no
//! extra measurements.
//!
//! Anti-flapping: all four measurements are EWMA-smoothed before they are
//! advertised, and a new path only replaces the current one when it is better
//! by at least `HYSTERESIS_MIN_MS` (or 10% of the current path cost). Without
//! this, a 30 s LSA refresh with slightly different samples would make first
//! hops oscillate and TCP connections would keep changing paths.
//!
//! The graph is treated as undirected: an edge A—B exists when *either* side
//! lists the other. LSDB edges take the minimum advertised cost (measurements
//! are roughly symmetric; min avoids amplifying jitter), while our own
//! measured links override them because the local measurement is the most
//! trustworthy.
//!
//! Loop safety: shortest-path forwarding is loop-free in the steady state.
//! While the topology is converging, transient loops are possible, so relayed
//! frames carry a hop counter ([`MAX_HOPS`]) that every forwarder decrements.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::proto::{IdBytes, LinkMetric};

/// Maximum number of relays a unicast frame may traverse.
pub const MAX_HOPS: u8 = 32;
/// How often a node refreshes its own link-state advertisement.
pub const LSA_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// How long an unrefreshed advertisement stays in the database.
pub const LSA_EXPIRE_AFTER: Duration = Duration::from_secs(90);

/// RTT assumed when a QUIC connection has no selected path yet.
pub const UNKNOWN_RTT_MS: u32 = 10;
/// Upper bound for an advertised RTT, so a pathological sample cannot make a
/// link effectively unusable for arithmetic purposes.
pub const MAX_RTT_MS: u32 = 60_000;
/// Fixed cost added to every link on top of its RTT (milliseconds).
pub const PER_HOP_PENALTY_MS: u32 = 5;
/// A candidate path must beat the current one by at least this many ms.
pub const HYSTERESIS_MIN_MS: u64 = 10;
/// ...or by this fraction of the current path cost (10%).
pub const HYSTERESIS_PERCENT_DIV: u64 = 10;

/// Loss cripples TCP goodput, so each permille of packet loss is charged as
/// two milliseconds of path cost (5% loss => +100 ms).
pub const LOSS_PENALTY_MS_PER_MILLE: u64 = 2;
pub const MAX_LOSS_PERMILLE: u32 = 1000;
/// Estimated bandwidth at or above this value is not penalised (10 Mbit/s).
pub const BW_REFERENCE_KBPS: u32 = 10_000;
pub const MAX_BW_PENALTY_MS: u64 = 120;
/// Only a link using at least this share of its estimated bandwidth is
/// considered saturated. Idle links are never penalised for being idle.
pub const SATURATION_THRESHOLD_PCT: u64 = 80;
pub const MAX_SATURATION_PENALTY_MS: u64 = 60;

/// Integer EWMA with alpha = 1/4, shared by the mesh sampler and the LSA
/// smoother so both dimensions use the same time constant.
pub fn ewma(prev: u32, sample: u32) -> u32 {
    ((u64::from(prev) * 3 + u64::from(sample)) / 4) as u32
}

fn loss_penalty(loss_permille: u32) -> u64 {
    u64::from(loss_permille.min(MAX_LOSS_PERMILLE)) * LOSS_PENALTY_MS_PER_MILLE
}

/// Only slow links are charged. A missing estimate (`0`) is neutral rather
/// than "infinitely slow", so a node that cannot measure bandwidth does not
/// suddenly look like the worst relay in the mesh.
fn bandwidth_penalty(bw_kbps: u32) -> u64 {
    if bw_kbps == 0 || bw_kbps >= BW_REFERENCE_KBPS {
        return 0;
    }
    MAX_BW_PENALTY_MS * u64::from(BW_REFERENCE_KBPS - bw_kbps) / u64::from(BW_REFERENCE_KBPS)
}

/// A high send rate only matters when it approaches the estimated capacity.
/// Without a capacity estimate we cannot tell "busy" from "idle", so we do
/// not guess.
fn saturation_penalty(tx_kbps: u32, bw_kbps: u32) -> u64 {
    if bw_kbps == 0 || tx_kbps == 0 {
        return 0;
    }
    let ratio = (u64::from(tx_kbps) * 100 / u64::from(bw_kbps)).min(100);
    if ratio < SATURATION_THRESHOLD_PCT {
        return 0;
    }
    MAX_SATURATION_PENALTY_MS * (ratio - SATURATION_THRESHOLD_PCT)
        / (100 - SATURATION_THRESHOLD_PCT)
}

/// Cost of one link in "equivalent milliseconds".
pub fn link_cost(m: &LinkMetric) -> u64 {
    u64::from(m.rtt_ms.clamp(1, MAX_RTT_MS))
        + u64::from(PER_HOP_PENALTY_MS)
        + loss_penalty(m.loss_permille)
        + bandwidth_penalty(m.bw_kbps)
        + saturation_penalty(m.tx_kbps, m.bw_kbps)
}

/// EWMA smoother for all dimensions of our own link measurements.
#[derive(Debug, Default)]
pub struct LinkSmoother {
    values: HashMap<IdBytes, LinkMetric>,
}

impl LinkSmoother {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold a fresh sample set into the smoothed values and forget peers that
    /// are no longer connected.
    pub fn update(&mut self, samples: &[LinkMetric]) {
        let live: HashSet<IdBytes> = samples.iter().map(|m| m.neighbor).collect();
        self.values.retain(|id, _| live.contains(id));
        for m in samples {
            self.values
                .entry(m.neighbor)
                .and_modify(|v| {
                    v.rtt_ms = ewma(v.rtt_ms, m.rtt_ms);
                    v.loss_permille = ewma(v.loss_permille, m.loss_permille);
                    v.tx_kbps = ewma(v.tx_kbps, m.tx_kbps);
                    v.bw_kbps = ewma(v.bw_kbps, m.bw_kbps);
                })
                .or_insert(*m);
        }
    }

    /// Stable ordering matters: peers compare LSA contents to decide whether
    /// a recompute is needed, so a HashMap iteration order would make every
    /// periodic refresh look like a topology change.
    pub fn snapshot(&self) -> Vec<LinkMetric> {
        let mut out: Vec<LinkMetric> = self.values.values().copied().collect();
        out.sort_by_key(|m| m.neighbor.0);
        out
    }

    #[cfg(test)]
    pub fn get(&self, id: &IdBytes) -> Option<LinkMetric> {
        self.values.get(id).copied()
    }
}

#[derive(Clone, Debug)]
struct LsaEntry {
    seq: u64,
    links: Vec<LinkMetric>,
    received_at: Instant,
}

/// Link-state database plus the next-hop table derived from it.
#[derive(Debug)]
pub struct RoutingTable {
    my_id: IdBytes,
    /// Our own direct links with their smoothed quality measurements.
    my_links: HashMap<IdBytes, LinkMetric>,
    lsdb: HashMap<IdBytes, LsaEntry>,
    /// destination → first hop on the chosen path.
    next_hop: HashMap<IdBytes, IdBytes>,
    /// destination → cost of the chosen path, used by the hysteresis check.
    path_cost: HashMap<IdBytes, u64>,
}

impl RoutingTable {
    pub fn new(my_id: IdBytes) -> Self {
        Self {
            my_id,
            my_links: HashMap::new(),
            lsdb: HashMap::new(),
            next_hop: HashMap::new(),
            path_cost: HashMap::new(),
        }
    }

    /// Apply a link-state advertisement. Returns `true` if the database
    /// changed enough to require a recompute. An unchanged advertisement
    /// still refreshes the expiry timer (nodes publish every 30 s).
    pub fn apply(&mut self, origin: IdBytes, seq: u64, links: Vec<LinkMetric>) -> bool {
        if origin == self.my_id {
            return false;
        }
        if let Some(entry) = self.lsdb.get_mut(&origin) {
            if entry.seq >= seq {
                return false;
            }
            let changed = entry.links != links;
            entry.seq = seq;
            entry.received_at = Instant::now();
            if !changed {
                return false;
            }
            entry.links = links;
        } else {
            self.lsdb.insert(
                origin,
                LsaEntry {
                    seq,
                    links,
                    received_at: Instant::now(),
                },
            );
        }
        self.recompute();
        true
    }

    /// Update our own live links. Returns `true` if they changed.
    pub fn set_my_links(&mut self, links: &[LinkMetric]) -> bool {
        let new: HashMap<IdBytes, LinkMetric> = links.iter().map(|m| (m.neighbor, *m)).collect();
        if new == self.my_links {
            return false;
        }
        self.my_links = new;
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

    /// Cost of the path currently chosen for `dest` (for diagnostics/tests).
    pub fn path_cost(&self, dest: &IdBytes) -> Option<u64> {
        self.path_cost.get(dest).copied()
    }

    /// Number of destinations we currently know a route to.
    pub fn known_destinations(&self) -> usize {
        self.next_hop.len()
    }

    /// Number of advertisements currently in the database.
    pub fn lsdb_size(&self) -> usize {
        self.lsdb.len()
    }

    /// Smoothed quality of our direct links, sorted by peer id (status output).
    pub fn my_link_metrics(&self) -> Vec<LinkMetric> {
        let mut out: Vec<LinkMetric> = self.my_links.values().copied().collect();
        out.sort_by_key(|m| m.neighbor.0);
        out
    }

    /// The chosen paths as `(destination, first hop, weighted cost)`, sorted
    /// by destination. Exposed so `irohlan status` can show which path the
    /// weighted computation actually picked.
    pub fn routes(&self) -> Vec<(IdBytes, IdBytes, u64)> {
        let mut out: Vec<(IdBytes, IdBytes, u64)> = self
            .next_hop
            .iter()
            .filter_map(|(dest, hop)| self.path_cost(dest).map(|cost| (*dest, *hop, cost)))
            .collect();
        out.sort_by_key(|(dest, _, _)| dest.0);
        out
    }

    /// Rebuild the weighted graph and recompute the next-hop table.
    fn recompute(&mut self) {
        // Undirected weighted edges, stored in both directions.
        let mut edges: HashMap<(IdBytes, IdBytes), u64> = HashMap::new();
        for (origin, entry) in &self.lsdb {
            for m in &entry.links {
                if origin == &m.neighbor {
                    continue;
                }
                let cost = link_cost(m);
                for key in [(*origin, m.neighbor), (m.neighbor, *origin)] {
                    edges
                        .entry(key)
                        .and_modify(|c| *c = (*c).min(cost))
                        .or_insert(cost);
                }
            }
        }
        // Our own measurements take precedence over what peers advertise.
        for (neighbor, m) in &self.my_links {
            if *neighbor == self.my_id {
                continue;
            }
            let cost = link_cost(m);
            edges.insert((self.my_id, *neighbor), cost);
            edges.insert((*neighbor, self.my_id), cost);
        }

        let mut adj: HashMap<IdBytes, Vec<(IdBytes, u64)>> = HashMap::new();
        for ((a, b), cost) in edges {
            adj.entry(a).or_default().push((b, cost));
        }

        // For every direct neighbor h, run Dijkstra from h. The cost of going
        // via h to dest is cost(self, h) + dist_h(dest). Keeping the per-hop
        // costs lets the hysteresis check compare "the path we are on now"
        // against the new best path under the *new* topology.
        let self_edges = adj.get(&self.my_id).cloned().unwrap_or_default();
        let mut via: HashMap<(IdBytes, IdBytes), u64> = HashMap::new();
        let mut best: HashMap<IdBytes, (u64, IdBytes)> = HashMap::new();
        for (h, hop_cost) in &self_edges {
            for (dest, d) in dijkstra(&adj, h, &self.my_id) {
                if dest == self.my_id {
                    continue;
                }
                let total = hop_cost.saturating_add(d);
                via.insert((*h, dest), total);
                match best.get(&dest) {
                    Some((c, _)) if *c <= total => {}
                    _ => {
                        best.insert(dest, (total, *h));
                    }
                }
            }
        }

        let mut next_hop = HashMap::new();
        let mut path_cost = HashMap::new();
        for (dest, (cost, hop)) in best {
            let chosen = match self.next_hop.get(&dest).copied() {
                Some(old_hop) if old_hop != hop => match via.get(&(old_hop, dest)).copied() {
                    // Old first hop is still usable; only switch when the new
                    // path is clearly better.
                    Some(old_total) => {
                        let hysteresis = HYSTERESIS_MIN_MS.max(old_total / HYSTERESIS_PERCENT_DIV);
                        if cost.saturating_add(hysteresis) >= old_total {
                            (old_hop, old_total)
                        } else {
                            (hop, cost)
                        }
                    }
                    None => (hop, cost),
                },
                _ => (hop, cost),
            };
            next_hop.insert(dest, chosen.0);
            path_cost.insert(dest, chosen.1);
        }
        self.next_hop = next_hop;
        self.path_cost = path_cost;
    }
}

/// Dijkstra from `src` over the weighted adjacency list. `IdBytes` has no
/// `Ord`, so the priority queue keys on the raw 32-byte id instead.
///
/// `blocked` is never expanded as an intermediate node: when computing the
/// cost of paths via a first hop, a frame that left this node must not be
/// routed back through it (that would be a forwarding loop).
fn dijkstra(
    adj: &HashMap<IdBytes, Vec<(IdBytes, u64)>>,
    src: &IdBytes,
    blocked: &IdBytes,
) -> HashMap<IdBytes, u64> {
    let mut dist: HashMap<IdBytes, u64> = HashMap::new();
    let mut heap: BinaryHeap<Reverse<(u64, [u8; 32])>> = BinaryHeap::new();
    dist.insert(*src, 0);
    heap.push(Reverse((0, src.0)));
    while let Some(Reverse((d, raw))) = heap.pop() {
        let node = IdBytes(raw);
        if node == *blocked {
            continue;
        }
        if dist.get(&node).is_some_and(|&known| d > known) {
            continue;
        }
        if let Some(neighbors) = adj.get(&node) {
            for (next, cost) in neighbors {
                let nd = d.saturating_add(*cost);
                if dist.get(next).is_none_or(|&known| nd < known) {
                    dist.insert(*next, nd);
                    heap.push(Reverse((nd, next.0)));
                }
            }
        }
    }
    dist
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> IdBytes {
        IdBytes([seed; 32])
    }

    fn metric(seed: u8, rtt_ms: u32) -> LinkMetric {
        LinkMetric::unknown(id(seed), rtt_ms)
    }

    fn quality(seed: u8, rtt_ms: u32, loss: u32, tx: u32, bw: u32) -> LinkMetric {
        LinkMetric {
            neighbor: id(seed),
            rtt_ms,
            loss_permille: loss,
            tx_kbps: tx,
            bw_kbps: bw,
        }
    }

    /// Equal-cost links: weighted routing degenerates to plain hop count.
    fn n(items: &[u8]) -> Vec<LinkMetric> {
        items.iter().map(|s| metric(*s, UNKNOWN_RTT_MS)).collect()
    }

    fn l(pairs: &[(u8, u32)]) -> Vec<LinkMetric> {
        pairs.iter().map(|(s, rtt)| metric(*s, *rtt)).collect()
    }

    #[test]
    fn link_cost_formula() {
        assert_eq!(link_cost(&metric(2, 0)), 1 + PER_HOP_PENALTY_MS as u64);
        assert_eq!(link_cost(&metric(2, 200)), 200 + PER_HOP_PENALTY_MS as u64);
        assert_eq!(
            link_cost(&metric(2, u32::MAX)),
            MAX_RTT_MS as u64 + PER_HOP_PENALTY_MS as u64
        );
    }

    #[test]
    fn loss_adds_a_strong_penalty() {
        let healthy = link_cost(&metric(2, 20));
        let lossy = link_cost(&quality(2, 20, 50, 0, 0)); // 5% loss
        assert_eq!(lossy - healthy, 50 * LOSS_PENALTY_MS_PER_MILLE);
        assert_eq!(
            link_cost(&quality(2, 20, u32::MAX, 0, 0)) - healthy,
            u64::from(MAX_LOSS_PERMILLE) * LOSS_PENALTY_MS_PER_MILLE
        );
    }

    #[test]
    fn only_slow_or_saturated_links_are_penalised() {
        let baseline = link_cost(&metric(2, 20));
        assert_eq!(link_cost(&quality(2, 20, 0, 0, 0)), baseline, "unknown bw");
        assert_eq!(
            link_cost(&quality(2, 20, 0, 0, 50_000)),
            baseline,
            "fast link"
        );
        assert!(
            link_cost(&quality(2, 20, 0, 0, 1_000)) > baseline,
            "slow link"
        );
        assert_eq!(
            link_cost(&quality(2, 20, 0, 1_000, 10_000)),
            baseline,
            "10% utilisation"
        );
        assert!(
            link_cost(&quality(2, 20, 0, 9_000, 10_000)) > baseline,
            "90% utilisation"
        );
        assert_eq!(
            link_cost(&quality(2, 20, 0, 9_000, 0)),
            baseline,
            "no capacity estimate => cannot judge saturation"
        );
    }

    #[test]
    fn quality_penalties_are_bounded() {
        let worst = link_cost(&quality(2, u32::MAX, u32::MAX, u32::MAX, 1));
        assert!(worst < 70_000);
        assert_eq!(
            worst,
            link_cost(&quality(2, u32::MAX, u32::MAX, u32::MAX, 1))
        );
    }

    #[test]
    fn a_lossy_direct_link_loses_to_a_clean_relay() {
        // 1 — 2 — 4 is clean but two hops; 1 — 3 — 4 is also two hops but
        // the link from 3 is deliberately awful. Dijkstra must avoid 3.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&[metric(2, 2), metric(3, 2)]);
        rt.apply(id(2), 1, vec![metric(1, 2), metric(4, 2)]);
        rt.apply(id(3), 1, vec![metric(1, 2), quality(4, 2, 100, 0, 0)]);
        rt.apply(id(4), 1, n(&[2, 3]));
        assert_eq!(rt.next_hop(&id(4)), Some(id(2)));
    }

    #[test]
    fn direct_neighbors_route_to_themselves() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&n(&[2, 3]));
        assert_eq!(rt.next_hop(&id(2)), Some(id(2)));
        assert_eq!(rt.next_hop(&id(3)), Some(id(3)));
        assert_eq!(rt.next_hop(&id(9)), None);
        assert_eq!(rt.next_hop(&id(1)), None, "self is never a destination");
    }

    #[test]
    fn two_hop_chain_routes_via_middle() {
        // 1 — 2 — 3: node 1 knows 2 directly and hears 2's LSA about 3.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&n(&[2]));
        rt.apply(id(2), 1, n(&[1, 3]));
        assert_eq!(rt.next_hop(&id(3)), Some(id(2)));
        assert_eq!(rt.known_destinations(), 2);
    }

    #[test]
    fn multi_hop_chain_first_hop_stays_stable() {
        // 1 — 2 — 3 — 4: node 1 should route to 4 via 2.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&n(&[2]));
        rt.apply(id(2), 1, n(&[1, 3]));
        rt.apply(id(3), 1, n(&[2, 4]));
        rt.apply(id(4), 1, n(&[3]));
        assert_eq!(rt.next_hop(&id(4)), Some(id(2)));
        assert_eq!(rt.next_hop(&id(3)), Some(id(2)));
    }

    #[test]
    fn partitioned_graph_has_no_route() {
        // 1—2 and 3—4 are separate components.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&n(&[2]));
        rt.apply(id(2), 1, n(&[1]));
        rt.apply(id(3), 1, n(&[4]));
        rt.apply(id(4), 1, n(&[3]));
        assert_eq!(rt.next_hop(&id(2)), Some(id(2)));
        assert_eq!(rt.next_hop(&id(3)), None);
        assert_eq!(rt.next_hop(&id(4)), None);
    }

    #[test]
    fn edges_are_undirected_from_either_side() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&n(&[2]));
        rt.apply(id(2), 5, n(&[3]));
        rt.apply(id(3), 5, n(&[2]));
        assert_eq!(rt.next_hop(&id(3)), Some(id(2)));
    }

    #[test]
    fn stale_sequence_numbers_are_ignored() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&n(&[2]));
        assert!(rt.apply(id(2), 7, n(&[1, 3])));
        assert!(!rt.apply(id(2), 6, n(&[1])), "older seq rejected");
        assert!(!rt.apply(id(2), 7, n(&[1])), "same seq rejected");
        assert_eq!(rt.next_hop(&id(3)), Some(id(2)), "newer topology survives");

        assert!(rt.apply(id(2), 8, n(&[1])), "newer seq accepted");
        assert_eq!(rt.next_hop(&id(3)), None);
    }

    #[test]
    fn own_lsas_are_not_applied() {
        let mut rt = RoutingTable::new(id(1));
        assert!(!rt.apply(id(1), 99, n(&[2, 3])));
    }

    #[test]
    fn expire_removes_stale_advertisements() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&n(&[2]));
        rt.apply(id(2), 1, n(&[1, 3]));
        assert_eq!(rt.next_hop(&id(3)), Some(id(2)));

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
        // 1—2, 2—4, 1—3, 3—4: route to 4 should prefer either 2 or 3.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&n(&[2, 3]));
        rt.apply(id(2), 1, n(&[1, 4]));
        rt.apply(id(3), 1, n(&[1, 4]));
        rt.apply(id(4), 1, n(&[2, 3]));
        let hop = rt.next_hop(&id(4)).unwrap();
        assert!(hop == id(2) || hop == id(3));
    }

    #[test]
    fn self_loops_and_duplicate_edges_are_harmless() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&n(&[2]));
        let mut links = n(&[1, 1]);
        links.push(metric(2, UNKNOWN_RTT_MS));
        rt.apply(id(2), 1, links);
        assert_eq!(rt.next_hop(&id(2)), Some(id(2)));
    }

    #[test]
    fn prefers_low_rtt_neighbor_over_high_rtt_neighbor() {
        // 1→2 is 200 ms, 1→3 is 2 ms; both can reach 4.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&[metric(2, 200), metric(3, 2)]);
        rt.apply(id(2), 1, l(&[(1, 200), (4, 2)]));
        rt.apply(id(3), 1, l(&[(1, 2), (4, 2)]));
        assert_eq!(rt.next_hop(&id(4)), Some(id(3)));
        let via_3 = link_cost(&metric(3, 2)) + link_cost(&metric(4, 2));
        assert_eq!(rt.path_cost(&id(4)), Some(via_3));
    }

    #[test]
    fn hop_penalty_keeps_a_direct_link_over_many_tiny_hops() {
        // Without a per-hop penalty, 1→2→3→4 (3 × 1 ms) would look cheaper
        // than the direct 1→4 (5 ms). It isn't: each relay costs work.
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&[metric(2, 1), metric(4, 5)]);
        rt.apply(id(2), 1, l(&[(1, 1), (3, 1)]));
        rt.apply(id(3), 1, l(&[(2, 1), (4, 1)]));
        assert_eq!(rt.next_hop(&id(4)), Some(id(4)));
        assert_eq!(rt.path_cost(&id(4)), Some(link_cost(&metric(4, 5))));
    }

    #[test]
    fn hysteresis_keeps_current_path_until_gain_is_significant() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&[metric(2, 2), metric(3, 20)]);
        rt.apply(id(2), 1, l(&[(1, 2), (4, 1)]));
        rt.apply(id(3), 1, l(&[(1, 20), (4, 1)]));
        assert_eq!(rt.next_hop(&id(4)), Some(id(2)));

        // Small change: switching would save only 5 ms, below the 10 ms
        // hysteresis — keep the path we are on.
        rt.set_my_links(&[metric(2, 20), metric(3, 15)]);
        assert_eq!(rt.next_hop(&id(4)), Some(id(2)));

        // Large degradation: the old path is now much worse, switch.
        rt.set_my_links(&[metric(2, 100), metric(3, 15)]);
        assert_eq!(rt.next_hop(&id(4)), Some(id(3)));
    }

    #[test]
    fn smoother_applies_ewma_and_prunes_disconnected_peers() {
        let mut s = LinkSmoother::new();
        s.update(&[metric(2, 10)]);
        assert_eq!(s.get(&id(2)).unwrap().rtt_ms, 10);
        s.update(&[metric(2, 20)]);
        assert_eq!(s.get(&id(2)).unwrap().rtt_ms, (10 * 3 + 20) / 4);
        s.update(&[metric(3, 5)]);
        assert!(s.get(&id(2)).is_none(), "gone peers are dropped");
        assert_eq!(s.get(&id(3)).unwrap().rtt_ms, 5);
        assert_eq!(s.snapshot().len(), 1);
    }

    #[test]
    fn smoother_tracks_every_quality_dimension() {
        let mut s = LinkSmoother::new();
        s.update(&[quality(2, 20, 100, 4_000, 8_000)]);
        s.update(&[quality(2, 40, 0, 0, 12_000)]);
        let m = s.get(&id(2)).unwrap();
        assert_eq!(m.rtt_ms, (20 * 3 + 40) / 4);
        assert_eq!(m.loss_permille, (100 * 3) / 4);
        assert_eq!(m.tx_kbps, (4_000 * 3) / 4);
        assert_eq!(m.bw_kbps, (8_000 * 3 + 12_000) / 4);
    }

    #[test]
    fn unchanged_lsa_refreshes_expiry_without_recomputing() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&n(&[2]));
        assert!(rt.apply(id(2), 1, n(&[1, 3])));
        // Age the entry almost to expiry, then receive the periodic refresh.
        {
            let entry = rt.lsdb.get_mut(&id(2)).unwrap();
            entry.received_at -= LSA_EXPIRE_AFTER - Duration::from_secs(1);
        }
        assert!(!rt.apply(id(2), 2, n(&[1, 3])), "same links: no recompute");
        assert!(!rt.expire(), "refresh kept the entry alive");
        assert_eq!(rt.lsdb_size(), 1);
        assert_eq!(rt.next_hop(&id(3)), Some(id(2)));
    }

    #[test]
    fn smoother_snapshot_is_deterministically_sorted() {
        let mut s = LinkSmoother::new();
        s.update(&[metric(3, 30), metric(2, 20), metric(4, 40)]);
        let a = s.snapshot();
        let b = s.snapshot();
        assert_eq!(a, b);
        assert_eq!(
            a.iter().map(|m| m.neighbor).collect::<Vec<_>>(),
            vec![id(2), id(3), id(4)]
        );
    }

    #[test]
    fn dijkstra_never_expands_the_blocked_node() {
        // From 2, the only way to reach 4 is 2→1→3→4, i.e. routing back
        // through ourselves. That path must not be considered.
        let mut adj: HashMap<IdBytes, Vec<(IdBytes, u64)>> = HashMap::new();
        adj.insert(id(2), vec![(id(1), 1)]);
        adj.insert(id(1), vec![(id(2), 1), (id(3), 1)]);
        adj.insert(id(3), vec![(id(1), 1), (id(4), 1)]);
        adj.insert(id(4), vec![(id(3), 1)]);
        let dist = dijkstra(&adj, &id(2), &id(1));
        assert!(!dist.contains_key(&id(4)));
        assert_eq!(
            dist.get(&id(1)),
            Some(&1),
            "blocked node is reachable but not expanded"
        );
    }

    #[test]
    fn link_metrics_are_sorted_for_status_output() {
        let mut rt = RoutingTable::new(id(1));
        rt.set_my_links(&[metric(3, 20), metric(2, 10)]);
        let links = rt.my_link_metrics();
        assert_eq!(links, vec![metric(2, 10), metric(3, 20)]);
    }
}
