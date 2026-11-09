//! Relay accounting, per-peer fair quotas, per-flow FIFOs and CoDel AQM.
//!
//! Only frames that this node *forwards for somebody else* pass through here:
//! a unicast frame received from a peer whose destination is another member.
//! Frames the local host originated, frames delivered to the local TAP and
//! broadcast/multicast frames on the bus never touch the relay path.
//!
//! The `relay-limit-kib` setting stays a cap on this node's **total** forwarding rate,
//! divided evenly between the currently active *source* peers (idle peers
//! give their share back). Within each peer, frames are split into flows by
//! the ordered five tuple (see [`crate::flow`]); each flow has its own FIFO,
//! its own DRR deficit and its own CoDel state. A bulk transfer therefore
//! cannot starve a sparse flow (ACKs, DNS, ARP, NDP) from the same peer, and
//! a standing queue is actively trimmed by CoDel instead of growing until
//! tail-drop. Flow classification is used *only* to pick a queue — forwarding
//! remains EtherType agnostic, and unparseable frames share one safe flow.
//!
//! Queues are bounded per flow and per peer, and frames older than
//! [`QUEUE_TTL`] are dropped instead of delivered stale. Accounting is always
//! on; with the default limit of 0 every frame takes an immediate fast path
//! and nothing is ever queued or dropped.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::config::{RelayLedger, RelayPeerLedger};
use crate::flow::flow_id;
use crate::proto::IdBytes;

/// Tokens are counted in units of 1/SCALE bytes. A refill over `us`
/// microseconds at `rate` bytes/s adds exactly `rate * us` units, so no
/// fractional token is lost between closely spaced frames (integer-only).
const SCALE: u128 = 1_000_000;

/// Never make a bucket smaller than one maximum-sized frame.
const MIN_CAPACITY_BYTES: u64 = crate::proto::MAX_STREAM_MSG_LEN as u64;

/// How long a source peer keeps its share after its last frame.
const ACTIVE_WINDOW: Duration = Duration::from_secs(5);
/// Queued frames older than this are dropped instead of delivered stale.
const QUEUE_TTL: Duration = Duration::from_secs(2);
/// Per-flow backlog bounds. Keeping these per flow is what stops one bulk
/// transfer from consuming a peer's entire queue allowance.
const MAX_FLOW_FRAMES: usize = 64;
const MAX_FLOW_BYTES: u64 = 128 * 1024;
/// Peer-wide backstop so many concurrent flows cannot grow without bound.
const MAX_PEER_FRAMES: u64 = 512;
const MAX_PEER_BYTES: u64 = 512 * 1024;
/// Minimum DRR quantum per drain tick: one typical ethernet frame.
const MIN_QUANTUM_BYTES: u64 = 1500;

/// CoDel target standing delay. Below this, a queue is not bufferbloat.
const CODEL_TARGET: Duration = Duration::from_millis(5);
/// How long the standing delay must persist before dropping starts.
const CODEL_INTERVAL: Duration = Duration::from_millis(100);
/// A queue with a single packet cannot be diagnosed as persistent.
const CODEL_MAXPACKET: u64 = 1500;

/// Integer square root (Newton) on u128, used by the CoDel control law.
/// Integer-only keeps the drop schedule deterministic.
fn isqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x / 2 + 1;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// `SCALE / sqrt(count)` in fixed point. A plain integer `isqrt(count)`
/// would quantise 2, 3 and 4 all to 1 and flatten the CoDel control law for
/// the first few drops; fixed point keeps `interval / sqrt(count)` smooth.
fn codel_inv_sqrt(count: u32) -> u128 {
    let n = u128::from(count.max(1));
    let root = isqrt(n * SCALE * SCALE).max(1);
    SCALE * SCALE / root
}

/// A frame ready to be handed back to the mesh for transmission.
#[derive(Debug)]
pub struct RelayFrame {
    pub to: IdBytes,
    pub hop: u8,
    pub frame: Bytes,
}

/// Outcome of submitting one candidate relay frame.
#[derive(Debug)]
pub enum RelayDecision {
    /// Send immediately: an idle peer with tokens available, or no limit set.
    Forward { hop: u8, frame: Bytes },
    /// Parked in this flow's FIFO; a drain tick will deliver it.
    Queued,
    /// Dropped because its flow (or the peer) is full.
    Dropped,
}

/// Traffic counters for one peer, in both directions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerStats {
    /// Frames received from this peer that we were asked to relay.
    pub in_frames: u64,
    pub in_bytes: u64,
    /// Frames we actually forwarded to this peer.
    pub out_frames: u64,
    pub out_bytes: u64,
    /// Frames dropped by a full queue or by queue expiry.
    pub limited_frames: u64,
    pub limited_bytes: u64,
    /// Frames dropped proactively by CoDel to control standing delay.
    pub codel_frames: u64,
    pub codel_bytes: u64,
    /// Current backlog at snapshot time (not cumulative).
    pub queued_frames: u64,
    pub queued_bytes: u64,
}

#[derive(Debug)]
struct QueuedFrame {
    to: IdBytes,
    hop: u8,
    frame: Bytes,
    enqueued_at: Instant,
}

impl QueuedFrame {
    fn len(&self) -> u64 {
        self.frame.len() as u64
    }
}

/// Per-flow CoDel state machine, evaluated when a frame is about to leave the
/// queue. Sparse queues never reach the dropping state.
#[derive(Clone, Copy, Debug, Default)]
struct Codel {
    first_above: Option<Instant>,
    drop_next: Option<Instant>,
    count: u32,
    dropping: bool,
}

impl Codel {
    fn reset(&mut self) {
        self.first_above = None;
        self.drop_next = None;
        self.count = 0;
        self.dropping = false;
    }

    /// `sojourn` is the time this frame spent queued, `queue_bytes` the flow's
    /// current backlog. Returns true when the frame should be dropped.
    fn should_drop(&mut self, now: Instant, sojourn: Duration, queue_bytes: u64) -> bool {
        if queue_bytes <= CODEL_MAXPACKET || sojourn < CODEL_TARGET {
            self.reset();
            return false;
        }
        match self.first_above {
            None => self.first_above = Some(now + CODEL_INTERVAL),
            Some(threshold) if now >= threshold => self.dropping = true,
            Some(_) => {}
        }
        if !self.dropping {
            return false;
        }
        if self.drop_next.is_none() {
            self.count = 1;
            self.drop_next = Some(now); // drop the first overdue frame at once
        }
        let next = self.drop_next.expect("drop_next is set");
        if now < next {
            return false;
        }
        self.count = self.count.saturating_add(1);
        let gap_us = (CODEL_INTERVAL.as_micros() * codel_inv_sqrt(self.count) / SCALE) as u64;
        self.drop_next = Some(now + Duration::from_micros(gap_us));
        true
    }
}

#[derive(Debug, Default)]
struct FlowQueue {
    frames: VecDeque<QueuedFrame>,
    bytes: u64,
    deficit: u64,
    codel: Codel,
}

#[derive(Debug)]
struct PeerState {
    /// Current share of the total rate, bytes/s. Zero for inactive peers.
    rate: u64,
    /// Token count scaled by [`SCALE`].
    tokens: u128,
    last_refill: Instant,
    /// Last time this peer was the *source* of a frame. `None` for peers that
    /// only ever appear as a next hop — they must not consume a quota share.
    source_seen: Option<Instant>,
    flows: HashMap<u32, FlowQueue>,
    /// Rotating start offset across this peer's flows.
    flow_cursor: usize,
    queue_frames: u64,
    queue_bytes: u64,
    stats: PeerStats,
}

impl PeerState {
    fn new(now: Instant, rate: u64) -> Self {
        Self {
            rate,
            tokens: Self::capacity(rate),
            last_refill: now,
            source_seen: None,
            flows: HashMap::new(),
            flow_cursor: 0,
            queue_frames: 0,
            queue_bytes: 0,
            stats: PeerStats::default(),
        }
    }

    fn capacity(rate: u64) -> u128 {
        u128::from(rate.max(MIN_CAPACITY_BYTES)) * SCALE
    }

    fn refill(&mut self, now: Instant) {
        let elapsed_us = now.saturating_duration_since(self.last_refill).as_micros();
        self.last_refill = now;
        self.tokens = self
            .tokens
            .saturating_add(elapsed_us.saturating_mul(u128::from(self.rate)))
            .min(Self::capacity(self.rate));
    }

    fn clamp_tokens(&mut self) {
        self.tokens = self.tokens.min(Self::capacity(self.rate));
    }
}

#[derive(Debug)]
struct State {
    total_rate: u64,
    per_peer_rate: u64,
    /// Sorted ids of the active source peers; DRR rotates over this list.
    active: Vec<IdBytes>,
    rr_cursor: usize,
    last_drain: Instant,
    peers: HashMap<IdBytes, PeerState>,
    relayed_frames: u64,
    relayed_bytes: u64,
    limited_frames: u64,
    limited_bytes: u64,
    codel_frames: u64,
    codel_bytes: u64,
}

impl State {
    fn new(total_rate: u64, now: Instant) -> Self {
        Self {
            total_rate,
            per_peer_rate: 0,
            active: Vec::new(),
            rr_cursor: 0,
            last_drain: now,
            peers: HashMap::new(),
            relayed_frames: 0,
            relayed_bytes: 0,
            limited_frames: 0,
            limited_bytes: 0,
            codel_frames: 0,
            codel_bytes: 0,
        }
    }

    fn peer_mut(&mut self, id: IdBytes, now: Instant) -> &mut PeerState {
        let rate = self.per_peer_rate;
        self.peers
            .entry(id)
            .or_insert_with(|| PeerState::new(now, rate))
    }

    fn account_in(&mut self, from: IdBytes, bytes: u64, now: Instant) {
        let peer = self.peer_mut(from, now);
        peer.stats.in_frames += 1;
        peer.stats.in_bytes += bytes;
    }

    fn account_forward(&mut self, to: IdBytes, bytes: u64, now: Instant) {
        self.relayed_frames += 1;
        self.relayed_bytes += bytes;
        let peer = self.peer_mut(to, now);
        peer.stats.out_frames += 1;
        peer.stats.out_bytes += bytes;
    }

    fn account_limited(&mut self, from: IdBytes, bytes: u64, now: Instant) {
        self.limited_frames += 1;
        self.limited_bytes += bytes;
        let peer = self.peer_mut(from, now);
        peer.stats.limited_frames += 1;
        peer.stats.limited_bytes += bytes;
    }

    fn account_codel(&mut self, from: IdBytes, bytes: u64, now: Instant) {
        self.codel_frames += 1;
        self.codel_bytes += bytes;
        let peer = self.peer_mut(from, now);
        peer.stats.codel_frames += 1;
        peer.stats.codel_bytes += bytes;
    }

    /// Refill every bucket up to `now`, then recompute the active set and the
    /// per-peer share. Refilling first is essential: a rate change must not
    /// throw away time already accrued at the previous rate.
    fn rebalance(&mut self, now: Instant) {
        for peer in self.peers.values_mut() {
            peer.refill(now);
        }
        let mut active: Vec<IdBytes> = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                peer.queue_frames > 0
                    || peer
                        .source_seen
                        .is_some_and(|t| now.saturating_duration_since(t) <= ACTIVE_WINDOW)
            })
            .map(|(id, _)| *id)
            .collect();
        active.sort_by_key(|id| id.0);

        if active != self.active {
            self.per_peer_rate = if active.is_empty() {
                0
            } else {
                (self.total_rate / active.len() as u64).max(1)
            };
            for (id, peer) in self.peers.iter_mut() {
                peer.rate = if active.contains(id) {
                    self.per_peer_rate
                } else {
                    0
                };
                peer.clamp_tokens();
            }
            self.active = active;
            self.rr_cursor = 0;
        }
    }
}

/// A stable, sorted snapshot of the relay ledger for `irohlan status`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelaySnapshot {
    /// Total cap in KiB/s; 0 means accounting only, no queueing or dropping.
    pub limit_kib_per_sec: u32,
    /// Source peers currently sharing the cap.
    pub active_peers: usize,
    /// Non-empty flow queues across all peers.
    pub active_flows: usize,
    /// Derived per-peer share, KiB/s.
    pub per_peer_kib_per_sec: u32,
    pub relayed_frames: u64,
    pub relayed_bytes: u64,
    /// Frames dropped by a full queue or by queue expiry.
    pub limited_frames: u64,
    pub limited_bytes: u64,
    /// Frames dropped proactively by CoDel.
    pub codel_frames: u64,
    pub codel_bytes: u64,
    /// Frames currently waiting in all queues.
    pub queued_frames: u64,
    pub queued_bytes: u64,
    /// Sorted by endpoint id so status output never shuffles.
    pub peers: Vec<(IdBytes, PeerStats)>,
}

/// Shared relay accounting + limiter used by the switch.
#[derive(Debug)]
pub struct RelayControl {
    limit_kib_per_sec: u32,
    state: Mutex<State>,
}

impl RelayControl {
    /// Build with a total limit in KiB/s; `0` disables queueing and dropping.
    pub fn new(limit_kib_per_sec: u32) -> Self {
        Self::new_at(limit_kib_per_sec, Instant::now())
    }

    fn new_at(limit_kib_per_sec: u32, now: Instant) -> Self {
        Self {
            limit_kib_per_sec,
            state: Mutex::new(State::new(u64::from(limit_kib_per_sec) * 1024, now)),
        }
    }

    pub fn limit_kib_per_sec(&self) -> u32 {
        self.limit_kib_per_sec
    }

    /// Account one candidate relay frame and decide what to do with it.
    ///
    /// `from` is the peer the frame arrived on, `to` the next hop, `hop` the
    /// budget to carry on the wire (already decremented by the switch).
    pub fn submit(&self, from: IdBytes, to: IdBytes, hop: u8, frame: Bytes) -> RelayDecision {
        self.submit_at(from, to, hop, frame, Instant::now())
    }

    fn submit_at(
        &self,
        from: IdBytes,
        to: IdBytes,
        hop: u8,
        frame: Bytes,
        now: Instant,
    ) -> RelayDecision {
        let bytes = frame.len() as u64;
        let fid = flow_id(&frame);
        let mut state = self.state.lock().expect("relay lock");
        state.account_in(from, bytes, now);

        if self.limit_kib_per_sec == 0 {
            state.account_forward(to, bytes, now);
            return RelayDecision::Forward { hop, frame };
        }

        state.peer_mut(from, now).source_seen = Some(now);
        state.rebalance(now);

        let peer = state.peers.get_mut(&from).expect("relay peer entry");
        let need = u128::from(bytes) * SCALE;
        // Fast path: no backlog and enough tokens. Low-load traffic never
        // pays the drain-tick latency.
        if peer.queue_frames == 0 && peer.tokens >= need {
            peer.tokens -= need;
            state.account_forward(to, bytes, now);
            return RelayDecision::Forward { hop, frame };
        }
        if peer.queue_frames >= MAX_PEER_FRAMES
            || peer.queue_bytes.saturating_add(bytes) > MAX_PEER_BYTES
        {
            state.account_limited(from, bytes, now);
            return RelayDecision::Dropped;
        }
        let flow = peer.flows.entry(fid).or_default();
        if flow.frames.len() >= MAX_FLOW_FRAMES || flow.bytes.saturating_add(bytes) > MAX_FLOW_BYTES
        {
            state.account_limited(from, bytes, now);
            return RelayDecision::Dropped;
        }
        flow.bytes += bytes;
        flow.frames.push_back(QueuedFrame {
            to,
            hop,
            frame,
            enqueued_at: now,
        });
        peer.queue_frames += 1;
        peer.queue_bytes += bytes;
        RelayDecision::Queued
    }

    /// Take every frame that this tick's flow-level DRR schedule can afford
    /// to send. Pure data: the node-level pump is responsible for the mesh.
    pub fn drain(&self) -> Vec<RelayFrame> {
        self.drain_at(Instant::now())
    }

    fn drain_at(&self, now: Instant) -> Vec<RelayFrame> {
        let mut state = self.state.lock().expect("relay lock");
        if self.limit_kib_per_sec == 0 {
            return Vec::new();
        }
        state.rebalance(now);

        let elapsed_us = now.saturating_duration_since(state.last_drain).as_micros();
        state.last_drain = now;
        let fair = (u128::from(state.per_peer_rate) * elapsed_us / SCALE) as u64;
        let quantum = fair.max(MIN_QUANTUM_BYTES);

        let count = state.active.len();
        if count == 0 {
            return Vec::new();
        }
        let start = state.rr_cursor % count;
        let mut out = Vec::new();
        let mut forwarded: Vec<(IdBytes, u64)> = Vec::new();
        let mut expired: Vec<(IdBytes, u64)> = Vec::new();
        let mut codel_drops: Vec<(IdBytes, u64)> = Vec::new();

        for offset in 0..count {
            let id = state.active[(start + offset) % count];
            let Some(peer) = state.peers.get_mut(&id) else {
                continue;
            };
            if peer.queue_frames == 0 {
                continue;
            }
            // Copy the peer-wide counters out so the inner loop can borrow a
            // single flow queue mutably without aliasing the peer.
            let mut tokens = peer.tokens;
            let mut queue_frames = peer.queue_frames;
            let mut queue_bytes = peer.queue_bytes;

            let mut fids: Vec<u32> = peer.flows.keys().copied().collect();
            fids.sort_unstable();
            let flow_count = fids.len();
            let flow_start = peer.flow_cursor % flow_count.max(1);

            for i in 0..flow_count {
                let fid = fids[(flow_start + i) % flow_count];
                let Some(flow) = peer.flows.get_mut(&fid) else {
                    continue;
                };
                flow.deficit = flow.deficit.saturating_add(quantum);
                // Copy head metadata first so the borrow ends before mutation.
                while let Some((len, enqueued_at)) = flow
                    .frames
                    .front()
                    .map(|front| (front.len(), front.enqueued_at))
                {
                    if now.saturating_duration_since(enqueued_at) > QUEUE_TTL {
                        let _ = flow.frames.pop_front();
                        flow.bytes = flow.bytes.saturating_sub(len);
                        queue_frames = queue_frames.saturating_sub(1);
                        queue_bytes = queue_bytes.saturating_sub(len);
                        expired.push((id, len));
                        continue;
                    }
                    if len > flow.deficit || tokens < u128::from(len) * SCALE {
                        break;
                    }
                    let sojourn = now.saturating_duration_since(enqueued_at);
                    if flow.codel.should_drop(now, sojourn, flow.bytes) {
                        // Head drop: no tokens or deficit are consumed, and
                        // we immediately reconsider the next frame.
                        let _ = flow.frames.pop_front();
                        flow.bytes = flow.bytes.saturating_sub(len);
                        queue_frames = queue_frames.saturating_sub(1);
                        queue_bytes = queue_bytes.saturating_sub(len);
                        codel_drops.push((id, len));
                        continue;
                    }
                    let queued = flow.frames.pop_front().expect("front exists");
                    flow.bytes = flow.bytes.saturating_sub(len);
                    flow.deficit -= len;
                    tokens -= u128::from(len) * SCALE;
                    queue_frames = queue_frames.saturating_sub(1);
                    queue_bytes = queue_bytes.saturating_sub(len);
                    forwarded.push((queued.to, len));
                    out.push(RelayFrame {
                        to: queued.to,
                        hop: queued.hop,
                        frame: queued.frame,
                    });
                }
            }
            peer.flow_cursor = (flow_start + 1) % flow_count.max(1);
            peer.tokens = tokens;
            peer.queue_frames = queue_frames;
            peer.queue_bytes = queue_bytes;
            peer.flows.retain(|_, flow| !flow.frames.is_empty());
        }
        state.rr_cursor = (start + 1) % count;
        for (to, len) in forwarded {
            state.account_forward(to, len, now);
        }
        for (from, len) in expired {
            state.account_limited(from, len, now);
        }
        for (from, len) in codel_drops {
            state.account_codel(from, len, now);
        }
        out
    }

    pub fn snapshot(&self) -> RelaySnapshot {
        let state = self.state.lock().expect("relay lock");
        let mut peers: Vec<(IdBytes, PeerStats)> = state
            .peers
            .iter()
            .map(|(id, peer)| {
                let mut stats = peer.stats;
                stats.queued_frames = peer.queue_frames;
                stats.queued_bytes = peer.queue_bytes;
                (*id, stats)
            })
            .collect();
        peers.sort_by_key(|(id, _)| id.0);
        RelaySnapshot {
            limit_kib_per_sec: self.limit_kib_per_sec,
            active_peers: state.active.len(),
            active_flows: state
                .peers
                .values()
                .map(|p| p.flows.values().filter(|f| !f.frames.is_empty()).count())
                .sum(),
            per_peer_kib_per_sec: (state.per_peer_rate / 1024) as u32,
            relayed_frames: state.relayed_frames,
            relayed_bytes: state.relayed_bytes,
            limited_frames: state.limited_frames,
            limited_bytes: state.limited_bytes,
            codel_frames: state.codel_frames,
            codel_bytes: state.codel_bytes,
            queued_frames: state.peers.values().map(|p| p.queue_frames).sum(),
            queued_bytes: state.peers.values().map(|p| p.queue_bytes).sum(),
            peers,
        }
    }

    /// Cumulative counters suitable for persistence. Instantaneous queue and
    /// active-peer state is deliberately excluded.
    pub fn ledger(&self) -> RelayLedger {
        let state = self.state.lock().expect("relay lock");
        let mut peers: Vec<RelayPeerLedger> = state
            .peers
            .iter()
            .map(|(id, peer)| RelayPeerLedger {
                peer: id.hex(),
                in_frames: peer.stats.in_frames,
                in_bytes: peer.stats.in_bytes,
                out_frames: peer.stats.out_frames,
                out_bytes: peer.stats.out_bytes,
                limited_frames: peer.stats.limited_frames,
                limited_bytes: peer.stats.limited_bytes,
                codel_frames: peer.stats.codel_frames,
                codel_bytes: peer.stats.codel_bytes,
            })
            .collect();
        peers.sort_by(|a, b| a.peer.cmp(&b.peer));
        RelayLedger {
            relayed_frames: state.relayed_frames,
            relayed_bytes: state.relayed_bytes,
            limited_frames: state.limited_frames,
            limited_bytes: state.limited_bytes,
            codel_frames: state.codel_frames,
            codel_bytes: state.codel_bytes,
            peers,
        }
    }

    /// Fold a previously persisted ledger into the running totals. Additive
    /// rather than overwriting: counters keep growing across restarts.
    /// Malformed peer ids are skipped so a damaged file cannot abort startup.
    pub fn restore(&self, saved: &RelayLedger) {
        let mut state = self.state.lock().expect("relay lock");
        let now = Instant::now();
        state.relayed_frames = state.relayed_frames.saturating_add(saved.relayed_frames);
        state.relayed_bytes = state.relayed_bytes.saturating_add(saved.relayed_bytes);
        state.limited_frames = state.limited_frames.saturating_add(saved.limited_frames);
        state.limited_bytes = state.limited_bytes.saturating_add(saved.limited_bytes);
        state.codel_frames = state.codel_frames.saturating_add(saved.codel_frames);
        state.codel_bytes = state.codel_bytes.saturating_add(saved.codel_bytes);
        for entry in &saved.peers {
            let Some(id) = IdBytes::from_hex(&entry.peer) else {
                continue;
            };
            let stats = &mut state.peer_mut(id, now).stats;
            stats.in_frames = stats.in_frames.saturating_add(entry.in_frames);
            stats.in_bytes = stats.in_bytes.saturating_add(entry.in_bytes);
            stats.out_frames = stats.out_frames.saturating_add(entry.out_frames);
            stats.out_bytes = stats.out_bytes.saturating_add(entry.out_bytes);
            stats.limited_frames = stats.limited_frames.saturating_add(entry.limited_frames);
            stats.limited_bytes = stats.limited_bytes.saturating_add(entry.limited_bytes);
            stats.codel_frames = stats.codel_frames.saturating_add(entry.codel_frames);
            stats.codel_bytes = stats.codel_bytes.saturating_add(entry.codel_bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn id(n: u8) -> IdBytes {
        IdBytes([n; 32])
    }

    /// An all-zero frame: always lands in the same (L2-keyed) flow.
    fn frame(len: usize) -> Bytes {
        Bytes::from(vec![0u8; len])
    }

    /// A minimal IPv4/TCP frame whose source port selects the flow.
    fn tcp_frame(src_port: u16, len: usize) -> Bytes {
        let size = len.max(54);
        let mut f = vec![0u8; size];
        f[0..6].copy_from_slice(&[0x02, 1, 2, 3, 4, 5]);
        f[6..12].copy_from_slice(&[0x02, 6, 7, 8, 9, 10]);
        f[12..14].copy_from_slice(&[0x08, 0x00]);
        f[14] = 0x45;
        f[16..18].copy_from_slice(&((size - 14) as u16).to_be_bytes());
        f[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
        f[23] = 6;
        f[26..30].copy_from_slice(&[10, 0, 0, 1]);
        f[30..34].copy_from_slice(&[10, 0, 0, 2]);
        f[34..36].copy_from_slice(&src_port.to_be_bytes());
        f[36..38].copy_from_slice(&80u16.to_be_bytes());
        Bytes::from(f)
    }

    fn src_port(frame: &Bytes) -> u16 {
        u16::from_be_bytes([frame[34], frame[35]])
    }

    fn forwarded(d: RelayDecision) -> bool {
        matches!(d, RelayDecision::Forward { .. })
    }

    /// Drain a source peer's initial token bucket with one maximum frame.
    fn drain_bucket(ctl: &RelayControl, from: IdBytes, now: Instant) {
        assert!(forwarded(ctl.submit_at(
            from,
            id(99),
            5,
            frame(MIN_CAPACITY_BYTES as usize),
            now
        )));
    }

    #[test]
    fn isqrt_is_exact() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(3), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(15), 3);
        assert_eq!(isqrt(1_000_000), 1000);
        assert_eq!(codel_inv_sqrt(1), SCALE);
        assert!(codel_inv_sqrt(4) < codel_inv_sqrt(2));
        assert!(codel_inv_sqrt(9) < codel_inv_sqrt(4));
    }

    #[test]
    fn codel_ignores_short_or_low_delay_queues() {
        let t0 = Instant::now();
        let mut c = Codel::default();
        assert!(!c.should_drop(t0, Duration::from_millis(50), CODEL_MAXPACKET));
        assert!(!c.should_drop(t0, Duration::from_millis(1), 30_000));
        assert!(!c.dropping);
    }

    #[test]
    fn codel_starts_dropping_only_after_a_full_interval() {
        let t0 = Instant::now();
        let mut c = Codel::default();
        assert!(!c.should_drop(t0, Duration::from_millis(50), 30_000));
        assert!(!c.should_drop(
            t0 + Duration::from_millis(50),
            Duration::from_millis(50),
            30_000
        ));
        assert!(c.should_drop(
            t0 + Duration::from_millis(100),
            Duration::from_millis(50),
            30_000
        ));
        assert!(c.dropping);
    }

    #[test]
    fn codel_drop_interval_shrinks_as_the_count_grows() {
        let t0 = Instant::now();
        let mut c = Codel::default();
        c.should_drop(t0, Duration::from_millis(50), 30_000);
        let first = t0 + Duration::from_millis(100);
        assert!(c.should_drop(first, Duration::from_millis(50), 30_000));
        let second = c.drop_next.expect("drop_next set");
        assert!(c.should_drop(second, Duration::from_millis(50), 30_000));
        let third = c.drop_next.expect("drop_next set");
        assert!(third - second < second - first);
    }

    #[test]
    fn codel_resets_when_delay_recovers() {
        let t0 = Instant::now();
        let mut c = Codel::default();
        c.should_drop(t0, Duration::from_millis(50), 30_000);
        assert!(c.should_drop(
            t0 + Duration::from_millis(100),
            Duration::from_millis(50),
            30_000
        ));
        assert!(!c.should_drop(
            t0 + Duration::from_millis(110),
            Duration::from_millis(1),
            30_000
        ));
        assert!(!c.dropping);
        assert_eq!(c.count, 0);
    }

    #[test]
    fn unlimited_mode_forwards_immediately_and_never_queues() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(0, t0);
        for _ in 0..3 {
            assert!(forwarded(ctl.submit_at(id(1), id(9), 5, frame(1500), t0)));
        }
        assert!(ctl.drain_at(t0).is_empty());
        let snap = ctl.snapshot();
        assert_eq!(snap.limit_kib_per_sec, 0);
        assert_eq!(snap.relayed_frames, 3);
        assert_eq!(snap.queued_frames, 0);
        assert_eq!(snap.limited_frames, 0);
        assert_eq!(snap.active_flows, 0);
        assert_eq!(snap.peers.len(), 2);
    }

    #[test]
    fn total_cap_is_split_evenly_and_idle_peers_give_it_back() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(3000, t0);
        for n in [1u8, 2, 3] {
            assert!(forwarded(ctl.submit_at(id(n), id(9), 5, frame(1500), t0)));
        }
        let snap = ctl.snapshot();
        assert_eq!(snap.active_peers, 3);
        assert_eq!(snap.per_peer_kib_per_sec, 1000);

        ctl.drain_at(t0 + Duration::from_secs(6));
        let snap = ctl.snapshot();
        assert_eq!(snap.active_peers, 0);
        assert_eq!(snap.per_peer_kib_per_sec, 0);
    }

    #[test]
    fn fast_path_bypasses_the_queue_when_tokens_are_available() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(2048, t0);
        assert!(forwarded(ctl.submit_at(id(1), id(9), 5, frame(1500), t0)));
        assert_eq!(ctl.snapshot().queued_frames, 0);
    }

    #[test]
    fn drr_keeps_a_small_peer_from_starving_behind_a_big_frame() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(8, t0);
        drain_bucket(&ctl, id(1), t0);
        drain_bucket(&ctl, id(2), t0);
        for _ in 0..3 {
            assert!(matches!(
                ctl.submit_at(id(1), id(11), 5, frame(1500), t0),
                RelayDecision::Queued
            ));
        }
        assert!(matches!(
            ctl.submit_at(id(2), id(12), 5, frame(60), t0),
            RelayDecision::Queued
        ));
        let out = ctl.drain_at(t0 + Duration::from_millis(100));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, id(12));
        let out = ctl.drain_at(t0 + Duration::from_millis(600));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, id(11));
    }

    #[test]
    fn a_sparse_flow_escapes_a_bulk_flow_from_the_same_peer() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(8, t0);
        drain_bucket(&ctl, id(1), t0);
        // Bulk flow: three full-size frames, all with the same five tuple.
        for _ in 0..3 {
            assert!(matches!(
                ctl.submit_at(id(1), id(9), 5, tcp_frame(5000, 1500), t0),
                RelayDecision::Queued
            ));
        }
        // Sparse flow: one small frame with a different source port.
        assert!(matches!(
            ctl.submit_at(id(1), id(9), 5, tcp_frame(6000, 60), t0),
            RelayDecision::Queued
        ));
        assert_eq!(ctl.snapshot().active_flows, 2);

        // 100 ms of tokens (819 bytes) cannot move a 1500-byte bulk frame,
        // but the sparse flow is served in the very same drain tick.
        let out = ctl.drain_at(t0 + Duration::from_millis(100));
        assert_eq!(out.len(), 1);
        assert_eq!(src_port(&out[0].frame), 6000);
    }

    #[test]
    fn a_flow_never_reorders_its_own_frames() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(8, t0);
        drain_bucket(&ctl, id(1), t0);
        // Identical frame shape => one flow; the next hop carries the order.
        for to in [21u8, 22, 23] {
            assert!(matches!(
                ctl.submit_at(id(1), id(to), 5, frame(1500), t0),
                RelayDecision::Queued
            ));
        }
        let out = ctl.drain_at(t0 + Duration::from_millis(1500));
        let order: Vec<u8> = out.iter().map(|f| f.to.0[0]).collect();
        assert_eq!(order, vec![21, 22, 23]);
    }

    #[test]
    fn one_full_flow_does_not_block_another_flow() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(8, t0);
        drain_bucket(&ctl, id(1), t0);
        for _ in 0..MAX_FLOW_FRAMES + 5 {
            let _ = ctl.submit_at(id(1), id(9), 5, tcp_frame(5000, 1500), t0);
        }
        // The bulk flow is full, but a different flow still has room.
        assert!(matches!(
            ctl.submit_at(id(1), id(9), 5, tcp_frame(6000, 60), t0),
            RelayDecision::Queued
        ));
        assert_eq!(ctl.snapshot().active_flows, 2);
    }

    #[test]
    fn bounded_queue_drops_and_accounts() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(8, t0);
        drain_bucket(&ctl, id(1), t0);
        let mut dropped = 0u64;
        for _ in 0..600 {
            if matches!(
                ctl.submit_at(id(1), id(9), 5, frame(1500), t0),
                RelayDecision::Dropped
            ) {
                dropped += 1;
            }
        }
        assert!(dropped > 0);
        let snap = ctl.snapshot();
        assert_eq!(snap.limited_frames, dropped);
        assert!(snap.queued_frames <= MAX_PEER_FRAMES);
        assert!(snap.queued_bytes <= MAX_PEER_BYTES);
    }

    #[test]
    fn stale_frames_expire_instead_of_being_delivered() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(8, t0);
        drain_bucket(&ctl, id(1), t0);
        assert!(matches!(
            ctl.submit_at(id(1), id(9), 5, frame(1500), t0),
            RelayDecision::Queued
        ));
        let out = ctl.drain_at(t0 + Duration::from_secs(3));
        assert!(out.is_empty());
        let snap = ctl.snapshot();
        assert_eq!(snap.limited_frames, 1);
        assert_eq!(snap.queued_frames, 0);
        assert_eq!(snap.relayed_frames, 1);
    }

    #[test]
    fn codel_drops_are_accounted_end_to_end() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(64, t0);
        drain_bucket(&ctl, id(1), t0);
        for _ in 0..20 {
            assert!(matches!(
                ctl.submit_at(id(1), id(9), 5, frame(1500), t0),
                RelayDecision::Queued
            ));
        }
        // Simulate pump ticks. Standing delay crosses one CoDel interval and
        // the AQM starts dropping before the frames expire.
        for ms in [50, 100, 150, 200, 250, 300, 350, 400] {
            let _ = ctl.drain_at(t0 + Duration::from_millis(ms));
        }
        let snap = ctl.snapshot();
        assert!(snap.codel_frames > 0, "CoDel should have trimmed the queue");
        assert!(snap.codel_bytes >= snap.codel_frames * 1500);
        assert_eq!(
            snap.peers
                .iter()
                .find(|(p, _)| *p == id(1))
                .unwrap()
                .1
                .codel_frames,
            snap.codel_frames
        );
    }

    #[test]
    fn snapshot_is_sorted_and_reports_backlog() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(8, t0);
        for n in [9u8, 3, 7] {
            drain_bucket(&ctl, id(n), t0);
        }
        let ids: Vec<u8> = ctl.snapshot().peers.iter().map(|(p, _)| p.0[0]).collect();
        let mut expected = ids.clone();
        expected.sort_unstable();
        assert_eq!(ids, expected);
        assert_eq!(ctl.snapshot().relayed_frames, 3);
        assert_eq!(ctl.limit_kib_per_sec(), 8);
    }

    #[test]
    fn ledger_roundtrip_restores_cumulative_counters() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(0, t0);
        assert!(forwarded(ctl.submit_at(id(1), id(9), 5, frame(1500), t0)));
        let saved = ctl.ledger();
        assert_eq!(saved.relayed_frames, 1);
        assert_eq!(saved.relayed_bytes, 1500);
        assert_eq!(saved.peers.len(), 2); // source and next hop

        let fresh = RelayControl::new_at(0, t0);
        fresh.restore(&saved);
        assert_eq!(fresh.snapshot().relayed_frames, 1);
        assert_eq!(fresh.snapshot().peers.len(), 2);
        // New traffic keeps accumulating on top of the restored totals.
        assert!(forwarded(fresh.submit_at(id(1), id(9), 5, frame(1500), t0)));
        assert_eq!(fresh.snapshot().relayed_frames, 2);
        assert_eq!(fresh.ledger().relayed_frames, 2);
    }

    #[test]
    fn ledger_never_restores_instantaneous_backlog() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(8, t0);
        drain_bucket(&ctl, id(1), t0);
        assert!(matches!(
            ctl.submit_at(id(1), id(9), 5, frame(1500), t0),
            RelayDecision::Queued
        ));
        assert_eq!(ctl.snapshot().queued_frames, 1);

        let fresh = RelayControl::new_at(8, t0);
        fresh.restore(&ctl.ledger());
        let snap = fresh.snapshot();
        assert_eq!(snap.queued_frames, 0);
        assert_eq!(snap.relayed_frames, 1);
        assert_eq!(
            snap.peers
                .iter()
                .find(|(p, _)| *p == id(1))
                .unwrap()
                .1
                .in_frames,
            2
        );
    }

    #[test]
    fn restore_skips_malformed_peer_ids() {
        let t0 = Instant::now();
        let ctl = RelayControl::new_at(0, t0);
        let mut saved = RelayLedger {
            relayed_frames: 7,
            ..Default::default()
        };
        saved.peers.push(RelayPeerLedger {
            peer: "not-a-hex-id".into(),
            in_frames: 99,
            ..Default::default()
        });
        ctl.restore(&saved);
        assert_eq!(ctl.snapshot().relayed_frames, 7);
        assert!(ctl.snapshot().peers.is_empty());
    }
}
