//! Wire protocol definitions: ethernet frame classification, control
//! messages and the framing used on mesh connections.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::netaddr::VirtualAddrs;

/// ALPN of the irohlan mesh protocol.
///
/// v4 made link-state advertisements carry a per-link RTT; v5 extends each
/// link with measured loss and throughput/bandwidth so routes are chosen by
/// overall link quality instead of pure latency. v5 peers cannot talk to
/// v4/v3/v2 peers; join tickets (v2) are unchanged and still decodable.
pub const ALPN: &[u8] = b"irohlan/v5";

/// Hard upper bound for anything we read from a stream (frames or messages).
pub const MAX_STREAM_MSG_LEN: usize = 65_535;
/// Upper bound for control messages on bi-directional streams.
pub const MAX_CTRL_MSG_LEN: usize = 4_096;

/// Tag byte prefixing every datagram and uni-directional stream payload.
pub mod tag {
    /// Unicast ethernet frame plus hop counter: `[hop: u8][frame…]`.
    pub const FRAME: u8 = 0x00;
    /// postcard-encoded [`FloodEnvelope`] (flooded broadcast / multicast
    /// frames and member announcements on the flood bus).
    pub const FLOOD: u8 = 0x01;
}

/// Length-prefix framing (u16 little endian) used on bi-directional streams.
pub mod lenframe {
    /// Maximum length accepted by the framing.
    pub const MAX: usize = crate::proto::MAX_CTRL_MSG_LEN;

    /// Encode `payload` with a u16 LE length prefix.
    pub fn encode(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            payload.len() <= MAX,
            "control message too large: {} bytes",
            payload.len()
        );
        let mut out = Vec::with_capacity(2 + payload.len());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Read one framed message from `recv` (length prefix + payload).
    pub async fn read(
        recv: &mut (impl tokio::io::AsyncReadExt + Unpin),
    ) -> anyhow::Result<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        recv.read_exact(&mut len_buf).await?;
        let len = u16::from_le_bytes(len_buf) as usize;
        anyhow::ensure!(len <= MAX, "peer sent oversized control message: {len}");
        let mut buf = vec![0u8; len];
        if len > 0 {
            recv.read_exact(&mut buf).await?;
        }
        Ok(buf)
    }

    /// Write one framed message to `send`.
    pub async fn write(
        send: &mut (impl tokio::io::AsyncWriteExt + Unpin),
        payload: &[u8],
    ) -> anyhow::Result<()> {
        send.write_all(&encode(payload)?).await?;
        Ok(())
    }
}

/// A 32-byte endpoint identifier (an iroh `EndpointId` / Ed25519 public key).
///
/// Owned plain-copy type so that protocol messages stay `serde` friendly and
/// platform independent.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdBytes(pub [u8; 32]);

impl IdBytes {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse a full 64-character hex string. Returns `None` on malformed
    /// input, so a damaged ledger file can be skipped rather than aborting
    /// node startup.
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            out[i] = (hi * 16 + lo) as u8;
        }
        Some(IdBytes(out))
    }
}

impl std::fmt::Debug for IdBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

impl From<iroh::EndpointId> for IdBytes {
    fn from(id: iroh::EndpointId) -> Self {
        IdBytes(*id.as_bytes())
    }
}

impl TryFrom<IdBytes> for iroh::EndpointId {
    type Error = iroh::KeyParsingError;
    fn try_from(id: IdBytes) -> Result<Self, Self::Error> {
        iroh::EndpointId::from_bytes(&id.0)
    }
}

impl std::fmt::Display for IdBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

/// A member of the virtual LAN as announced over the control plane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecord {
    /// Endpoint id; the virtual MAC is derived from it.
    pub id: IdBytes,
    /// Virtual IPv4 and/or IPv6 addresses.
    /// `default` only matters for JSON: it lets an old status.json (which
    /// stored a bare IPv4 `ip`) deserialize without errors.
    #[serde(default)]
    pub addrs: VirtualAddrs,
    /// Human readable hostname.
    pub hostname: String,
}

impl MemberRecord {
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.addrs.ipv4()
    }

    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.addrs.ipv6()
    }

    /// Human readable address list for logs and `status` output.
    pub fn display_addrs(&self) -> String {
        self.addrs.display()
    }

    pub fn empty_addrs(id: IdBytes) -> Self {
        Self {
            id,
            addrs: VirtualAddrs::default(),
            hostname: String::new(),
        }
    }
}

/// Control-plane messages exchanged on bi-directional streams.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CtrlMsg {
    /// First message of a connection, sent by the dialing side.
    AuthHello {
        nonce: [u8; 16],
        proof: [u8; 32],
        /// Only honored by the network creator: requested virtual addresses.
        desired: VirtualAddrs,
        /// The dialer's current virtual addresses, if it has any.
        my_addrs: VirtualAddrs,
        hostname: String,
    },
    /// Successful auth reply, sent by the accepting side.
    AuthAccept {
        nonce: [u8; 16],
        proof: [u8; 32],
        /// Only set by the network creator: assigned virtual addresses.
        assigned: VirtualAddrs,
        /// The accepting side's own member record.
        record: MemberRecord,
    },
    /// Auth failed; connection will be closed.
    AuthReject { reason: String },
    /// Joiner asks the creator for virtual addresses (e.g. after a conflict).
    RequestIp { desired: VirtualAddrs },
    /// Creator grants virtual addresses.
    AssignIp { addrs: VirtualAddrs },
    /// Creator refuses to grant virtual addresses.
    RejectIp { reason: String },
}

/// Messages distributed through the broadcast bus (gossip tree or flood bus).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BusMsg {
    /// An ethernet frame addressed to a broadcast or multicast MAC.
    Frame(Vec<u8>),
    /// Membership announcement.
    Announce(MemberRecord),
    /// Link-state advertisement for the partial-mesh routing table.
    LinkState(LinkStateMsg),
}

/// One link in a link-state advertisement: a neighbor plus the measured
/// quality of the QUIC connection to it.
///
/// All four measurements are EWMA-smoothed before publication. `bw_kbps` is
/// `0` when the congestion controller has no bandwidth estimate; `tx_kbps`
/// is the observed QUIC send rate, used to detect a saturated link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkMetric {
    pub neighbor: IdBytes,
    /// Smoothed round-trip time in milliseconds.
    pub rtt_ms: u32,
    /// Windowed packet loss in permille (0..=1000).
    pub loss_permille: u32,
    /// Observed QUIC send throughput in kbit/s.
    pub tx_kbps: u32,
    /// Estimated sustainable bandwidth in kbit/s; 0 means unknown.
    pub bw_kbps: u32,
}

impl LinkMetric {
    /// A healthy link with no loss/throughput data yet. Used as the default
    /// for tests and for peers whose selected path has no statistics.
    pub fn unknown(neighbor: IdBytes, rtt_ms: u32) -> Self {
        Self {
            neighbor,
            rtt_ms,
            loss_permille: 0,
            tx_kbps: 0,
            bw_kbps: 0,
        }
    }
}

/// Link-state advertisement distributed on the broadcast bus.
///
/// Each node announces its current mesh neighbors *and* the measured quality
/// of each link. Every node assembles these into a link-state database and
/// derives its own next-hop table with a weighted shortest-path computation
/// (see [`crate::routing`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkStateMsg {
    /// Endpoint that originated this advertisement.
    pub origin: IdBytes,
    /// Monotonically increasing per-origin sequence number; stale (older)
    /// advertisements are ignored.
    pub seq: u64,
    /// The origin's current mesh links with their measured quality.
    pub links: Vec<LinkMetric>,
}

/// Envelope for messages distributed on the flood bus.
///
/// `(origin, seq)` identifies a message so every peer can drop duplicates it
/// has already seen — the flood bus is a naive epidemic broadcast and relies
/// on this for loop prevention.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FloodEnvelope {
    /// Endpoint that originally published the message.
    pub origin: IdBytes,
    /// Monotonically increasing per-origin sequence number.
    pub seq: u64,
    /// The message being flooded.
    pub msg: BusMsg,
}

/// Classification of an ethernet frame by destination MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameClass {
    /// ff:ff:ff:ff:ff:ff
    Broadcast,
    /// destination MAC has the multicast bit set (includes broadcast).
    Multicast,
    /// directed at a single station
    Unicast([u8; 6]),
}

/// Minimum size of an ethernet II frame (dst + src + ethertype).
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Ethernet II ether types used by diagnostics and the forwarding tests.
#[allow(dead_code)]
pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const IPV6: u16 = 0x86dd;
}

/// Parse the destination MAC of a raw ethernet frame.
pub fn dst_mac(frame: &[u8]) -> Option<[u8; 6]> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&frame[..6]);
    Some(mac)
}

/// EtherType field of an ethernet II frame. Forwarding itself is EtherType
/// agnostic — this is used by diagnostics and tests to prove IPv6 (0x86dd)
/// frames, including NDP/MLD, take exactly the same paths as IPv4/ARP.
#[allow(dead_code)]
pub fn frame_ethertype(frame: &[u8]) -> Option<u16> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    Some(u16::from_be_bytes([frame[12], frame[13]]))
}

/// Classify a raw ethernet frame for forwarding decisions.
pub fn classify_frame(frame: &[u8]) -> Option<FrameClass> {
    let mac = dst_mac(frame)?;
    if mac == [0xff; 6] {
        return Some(FrameClass::Broadcast);
    }
    if mac[0] & 0x01 != 0 {
        return Some(FrameClass::Multicast);
    }
    Some(FrameClass::Unicast(mac))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp_request_frame() -> Vec<u8> {
        let mut f = vec![0xffu8; 6];
        f.extend_from_slice(&[0x02, 1, 2, 3, 4, 5]);
        f.extend_from_slice(&[0x08, 0x06]); // ARP
        f.extend_from_slice(&[0u8; 28]);
        f
    }

    /// IPv6 Neighbor Solicitation: solicited-node multicast MAC 33:33:ff:xx.
    fn ndp_solicit_frame() -> Vec<u8> {
        let mut f = vec![0x33, 0x33, 0xff, 0, 0, 0x01];
        f.extend_from_slice(&[0x02, 1, 2, 3, 4, 5]);
        f.extend_from_slice(&[0x86, 0xdd]); // IPv6
        f.extend_from_slice(&[0u8; 40]);
        f
    }

    #[test]
    fn classifies_broadcast() {
        let f = arp_request_frame();
        assert_eq!(classify_frame(&f), Some(FrameClass::Broadcast));
        assert_eq!(frame_ethertype(&f), Some(ethertype::ARP));
    }

    #[test]
    fn classifies_unicast_and_multicast() {
        let mut f = vec![0x02, 1, 2, 3, 4, 5];
        f.extend_from_slice(&[0x02, 6, 7, 8, 9, 10]);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&[0u8; 20]);
        assert_eq!(
            classify_frame(&f),
            Some(FrameClass::Unicast([0x02, 1, 2, 3, 4, 5]))
        );
        assert_eq!(frame_ethertype(&f), Some(ethertype::IPV4));

        // IPv4 multicast MAC 01:00:5e:...
        let mut m = vec![0x01, 0x00, 0x5e, 0, 0, 1];
        m.extend_from_slice(&[0x02, 6, 7, 8, 9, 10]);
        m.extend_from_slice(&[0x08, 0x00]);
        m.extend_from_slice(&[0u8; 20]);
        assert_eq!(classify_frame(&m), Some(FrameClass::Multicast));

        // IPv6 multicast MAC 33:33:...
        let mut m6 = vec![0x33, 0x33, 0, 0, 0, 1];
        m6.extend_from_slice(&[0x02, 6, 7, 8, 9, 10]);
        m6.extend_from_slice(&[0x86, 0xdd]);
        m6.extend_from_slice(&[0u8; 20]);
        assert_eq!(classify_frame(&m6), Some(FrameClass::Multicast));
    }

    #[test]
    fn ipv6_frames_are_forwarded_like_ipv4() {
        // NDP multicast takes the broadcast-bus path.
        let ndp = ndp_solicit_frame();
        assert_eq!(frame_ethertype(&ndp), Some(ethertype::IPV6));
        assert_eq!(classify_frame(&ndp), Some(FrameClass::Multicast));

        // Unicast IPv6 (e.g. ICMPv6 echo / TCP over v6) takes the mesh path.
        let mut unicast = vec![0x02, 6, 7, 8, 9, 10];
        unicast.extend_from_slice(&[0x02, 1, 2, 3, 4, 5]);
        unicast.extend_from_slice(&[0x86, 0xdd]);
        unicast.extend_from_slice(&[0u8; 40]);
        assert_eq!(frame_ethertype(&unicast), Some(ethertype::IPV6));
        assert_eq!(
            classify_frame(&unicast),
            Some(FrameClass::Unicast([0x02, 6, 7, 8, 9, 10]))
        );
    }

    #[test]
    fn rejects_runt_frames() {
        assert_eq!(classify_frame(&[0u8; 13]), None);
        assert_eq!(dst_mac(&[0u8; 10]), None);
        assert_eq!(frame_ethertype(&[0u8; 13]), None);
    }

    #[test]
    fn length_prefix_roundtrip() {
        let payload = b"hello world".to_vec();
        let framed = lenframe::encode(&payload).unwrap();
        assert_eq!(framed.len(), payload.len() + 2);

        // decode via the async read helper
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut cursor = std::io::Cursor::new(framed);
            let decoded = lenframe::read(&mut cursor).await.unwrap();
            assert_eq!(decoded, payload);
        });
    }

    #[test]
    fn length_prefix_rejects_oversize() {
        let too_big = vec![0xffu8; 3];
        // craft a length field larger than MAX
        let mut framed = (u16::MAX).to_le_bytes().to_vec();
        framed.extend_from_slice(&too_big);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut cursor = std::io::Cursor::new(framed);
            assert!(lenframe::read(&mut cursor).await.is_err());
        });
    }

    #[test]
    fn ctrl_msg_postcard_roundtrip() {
        let desired = VirtualAddrs {
            v4: Some(u32::from(Ipv4Addr::new(10, 13, 37, 42))),
            v6: Some("fd00::2a".parse::<Ipv6Addr>().unwrap().octets()),
        };
        let msg = CtrlMsg::AuthHello {
            nonce: [1; 16],
            proof: [2; 32],
            desired,
            my_addrs: VirtualAddrs::default(),
            hostname: "testhost".into(),
        };
        let bytes = postcard::to_allocvec(&msg).unwrap();
        let back: CtrlMsg = postcard::from_bytes(&bytes).unwrap();
        match back {
            CtrlMsg::AuthHello {
                nonce,
                desired: got,
                hostname,
                ..
            } => {
                assert_eq!(nonce, [1; 16]);
                assert_eq!(got, desired);
                assert_eq!(hostname, "testhost");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn id_hex_roundtrip_and_malformed_input() {
        let id = IdBytes([0xab; 32]);
        assert_eq!(IdBytes::from_hex(&id.hex()), Some(id));
        assert_eq!(IdBytes::from_hex(""), None);
        assert_eq!(IdBytes::from_hex(&"00".repeat(31)), None);
        assert_eq!(IdBytes::from_hex(&"zz".repeat(32)), None);
    }

    #[test]
    fn v5_link_metric_postcard_roundtrip() {
        let m = LinkMetric {
            neighbor: IdBytes([3; 32]),
            rtt_ms: 25,
            loss_permille: 12,
            tx_kbps: 4_000,
            bw_kbps: 10_000,
        };
        let bytes = postcard::to_allocvec(&m).unwrap();
        assert_eq!(postcard::from_bytes::<LinkMetric>(&bytes).unwrap(), m);
        // 32-byte id + four varints: still small enough for a gossip LSA.
        assert!(bytes.len() < 64);
    }
}
