//! The L2 switch: forwards ethernet frames between the TAP device, the mesh
//! and the broadcast bus.
//!
//! Forwarding rules (no MAC learning needed — the virtual MAC is derived
//! from the endpoint id, so the membership table maps MACs to endpoints and
//! the link-state routing table maps endpoints to next hops):
//!
//! | frame                          | path                                            |
//! |--------------------------------|-------------------------------------------------|
//! | broadcast / multicast (local)  | broadcast bus (gossip tree or flood)            |
//! | broadcast / multicast (in)     | delivered to the TAP                            |
//! | unicast for us                 | delivered to the TAP                            |
//! | unicast for another member     | relayed to the routing table's next hop         |
//! | unicast, unknown MAC / no path | dropped (stale ARP entry; ARP will refresh)     |

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use iroh::EndpointId;
use tokio::sync::{broadcast, mpsc};

use crate::bus::{BusEvent, BroadcastBus};
use crate::crypto;
use crate::membership::Membership;
use crate::mesh::{InboundFrame, Mesh};
use crate::proto::{classify_frame, BusMsg, FrameClass};
use crate::routing::{RoutingTable, MAX_HOPS};

/// Packet counters, exposed through `irohlan status`.
#[derive(Debug, Default)]
pub struct Counters {
    pub frames_from_tap: AtomicU64,
    pub frames_to_tap: AtomicU64,
    pub frames_dropped: AtomicU64,
    pub frames_relayed: AtomicU64,
}

impl Counters {
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.frames_from_tap.load(Ordering::Relaxed),
            self.frames_to_tap.load(Ordering::Relaxed),
            self.frames_dropped.load(Ordering::Relaxed),
            self.frames_relayed.load(Ordering::Relaxed),
        )
    }
}

/// The switch task input and wiring.
pub struct Switch {
    my_mac: [u8; 6],
    membership: Arc<Membership>,
    routing: Arc<RwLock<RoutingTable>>,
    mesh: Arc<Mesh>,
    bus: Arc<BroadcastBus>,
    to_tap: mpsc::Sender<Bytes>,
    counters: Arc<Counters>,
}

impl Switch {
    pub fn new(
        my_mac: [u8; 6],
        membership: Arc<Membership>,
        routing: Arc<RwLock<RoutingTable>>,
        mesh: Arc<Mesh>,
        bus: Arc<BroadcastBus>,
        to_tap: mpsc::Sender<Bytes>,
        counters: Arc<Counters>,
    ) -> Arc<Self> {
        Arc::new(Self {
            my_mac,
            membership,
            routing,
            mesh,
            bus,
            to_tap,
            counters,
        })
    }

    /// Run the forwarding loop until one of the inputs closes.
    pub async fn run(
        self: Arc<Self>,
        mut from_tap: mpsc::Receiver<Bytes>,
        mut mesh_frames: mpsc::Receiver<InboundFrame>,
        mut bus_events: broadcast::Receiver<BusEvent>,
    ) {
        loop {
            tokio::select! {
                frame = from_tap.recv() => {
                    match frame {
                        Some(frame) => self.handle_from_tap(frame).await,
                        None => break,
                    }
                }
                inbound = mesh_frames.recv() => {
                    match inbound {
                        Some(inbound) => self.handle_from_mesh(inbound).await,
                        None => break,
                    }
                }
                event = bus_events.recv() => {
                    match event {
                        Ok(BusEvent::Frame(frame)) => self.deliver(frame).await,
                        Ok(_) => {} // announcements & LSAs are consumed by the node
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("switch fell behind the bus by {n} events");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
        tracing::info!("switch loop stopped");
    }

    /// A frame that the local host sent into the TAP device.
    async fn handle_from_tap(&self, frame: Bytes) {
        self.counters.frames_from_tap.fetch_add(1, Ordering::Relaxed);
        match classify_frame(&frame) {
            Some(FrameClass::Broadcast) | Some(FrameClass::Multicast) => {
                self.bus.publish(BusMsg::Frame(frame.to_vec())).await;
            }
            Some(FrameClass::Unicast(mac)) => {
                let Some(member) = self.membership.by_mac(&mac) else {
                    // Not a member (anymore). Dropping is correct: the
                    // remote's MAC is derived from its endpoint id, so an
                    // unknown MAC cannot be reached by flooding either.
                    self.counters.frames_dropped.fetch_add(1, Ordering::Relaxed);
                    tracing::trace!(mac = %crypto::format_mac(&mac), "unicast to unknown member, dropped");
                    return;
                };
                // The routing table returns the destination itself for direct
                // neighbors, so both cases share one send path.
                let next_hop = self
                    .routing
                    .read()
                    .expect("routing lock")
                    .next_hop(&member.record.id);
                match next_hop.and_then(|nh| EndpointId::try_from(nh).ok()) {
                    Some(next_id) => self.mesh.send_unicast(&next_id, MAX_HOPS, frame),
                    None => {
                        self.counters.frames_dropped.fetch_add(1, Ordering::Relaxed);
                        tracing::trace!(mac = %crypto::format_mac(&mac), "no route to member, dropped");
                    }
                }
            }
            None => {
                self.counters.frames_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// A unicast frame received from a peer: deliver it if it is ours,
    /// otherwise relay it one hop further along the routing table.
    async fn handle_from_mesh(&self, inbound: InboundFrame) {
        let InboundFrame { hop, frame } = inbound;
        match classify_frame(&frame) {
            Some(FrameClass::Unicast(mac)) if mac == self.my_mac => self.deliver(frame).await,
            Some(FrameClass::Unicast(mac)) => {
                if hop == 0 {
                    self.counters.frames_dropped.fetch_add(1, Ordering::Relaxed);
                    tracing::trace!(mac = %crypto::format_mac(&mac), "hop budget exhausted, dropped");
                    return;
                }
                let Some(member) = self.membership.by_mac(&mac) else {
                    self.counters.frames_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                let next_hop = self
                    .routing
                    .read()
                    .expect("routing lock")
                    .next_hop(&member.record.id);
                match next_hop.and_then(|nh| EndpointId::try_from(nh).ok()) {
                    Some(next_id) => {
                        self.counters.frames_relayed.fetch_add(1, Ordering::Relaxed);
                        self.mesh.send_unicast(&next_id, hop - 1, frame);
                    }
                    None => {
                        self.counters.frames_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            // Broadcast/multicast frames only travel on the bus; a peer sent
            // one over the mesh channel. Deliver it instead of dropping.
            Some(_) => self.deliver(frame).await,
            None => {
                self.counters.frames_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// A broadcast frame received from the bus, destined for the local TAP.
    async fn deliver(&self, frame: Bytes) {
        self.counters.frames_to_tap.fetch_add(1, Ordering::Relaxed);
        if let Err(err) = self.to_tap.send(frame).await {
            tracing::debug!("tap writer gone: {err}");
        }
    }
}
