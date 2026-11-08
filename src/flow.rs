//! Flow classification for relay queueing.
//!
//! This module is the **only** place in the data plane that looks at
//! EtherType / IP / L4 headers, and its output is used exclusively to pick a
//! queue. Forwarding decisions (destination MAC classification, membership
//! lookup, next-hop routing) remain completely EtherType agnostic, as before.
//! Nothing here can drop or reroute a frame: anything we cannot parse gets a
//! single stable [`UNCLASSIFIED_FLOW`] id.
//!
//! The hash is over the *ordered* five tuple (src/dst address, protocol,
//! src/dst port). Keeping direction significant means TCP ACKs form a sparse
//! flow of their own and are not stuck behind a bulk transfer — that is the
//! main point of flow queueing. IPv6 extension headers are walked until the
//! upper-layer header is reached, so a connection behind Hop-by-Hop /
//! Destination Options / AH still gets its own flow instead of sharing a
//! coarse L3 bucket.
//!
//! The one rule that overrides fine granularity: **one connection must never
//! be split across queues**, because that reorders it. IPv4/IPv6 fragments
//! are therefore always keyed by the datagram identification (including the
//! first fragment, which does carry ports), and ESP by its SPI. Anything we
//! cannot fully dissect degrades to a stable coarser key rather than being
//! split.

use crate::proto::ETHERNET_HEADER_LEN;

const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_VLAN: u16 = 0x8100;
const ETH_P_QINQ: u16 = 0x88a8;

const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_DCCP: u8 = 33;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_ESP: u8 = 50;
const IPPROTO_AH: u8 = 51;
const IPPROTO_DSTOPTS: u8 = 60;
const IPPROTO_SCTP: u8 = 132;
const IPPROTO_MOBILITY: u8 = 135;
const IPPROTO_HIP: u8 = 139;
const IPPROTO_SHIM6: u8 = 140;

/// Guard against a crafted, cyclic or excessively deep extension header chain.
const MAX_EXTENSION_HEADERS: usize = 8;

/// Stable bucket for frames that cannot be classified. Such frames are still
/// forwarded normally; they just share one queue.
pub const UNCLASSIFIED_FLOW: u32 = 0;

/// Compute the flow id of a raw ethernet frame.
pub fn flow_id(frame: &[u8]) -> u32 {
    let mut hasher = blake3::Hasher::new();
    if !classify(frame, &mut hasher) {
        return UNCLASSIFIED_FLOW;
    }
    let digest = hasher.finalize();
    let mut id = [0u8; 4];
    id.copy_from_slice(&digest.as_bytes()[..4]);
    u32::from_le_bytes(id)
}

/// Feed a stable flow key into `hasher`. Returns `false` for runt/malformed
/// frames, which the caller maps to [`UNCLASSIFIED_FLOW`].
fn classify(frame: &[u8], hasher: &mut blake3::Hasher) -> bool {
    if frame.len() < ETHERNET_HEADER_LEN {
        return false;
    }
    let mut offset = ETHERNET_HEADER_LEN;
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    // Skip up to two VLAN tags (802.1Q / QinQ).
    for _ in 0..2 {
        if ether_type != ETH_P_VLAN && ether_type != ETH_P_QINQ {
            break;
        }
        if frame.len() < offset + 4 {
            return false;
        }
        ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    match ether_type {
        ETH_P_IPV4 => classify_v4(frame, offset, hasher),
        ETH_P_IPV6 => classify_v6(frame, offset, hasher),
        _ => {
            // ARP, RARP, MLD control frames, unknown protocols: key by the
            // L2 addresses so separate neighbours stay separate flows.
            hasher.update(b"l2");
            hasher.update(&ether_type.to_be_bytes());
            hasher.update(&frame[6..12]);
            hasher.update(&frame[0..6]);
            true
        }
    }
}

fn classify_v4(frame: &[u8], offset: usize, hasher: &mut blake3::Hasher) -> bool {
    const IPV4_MIN_HEADER: usize = 20;
    if frame.len() < offset + IPV4_MIN_HEADER || frame[offset] >> 4 != 4 {
        return false;
    }
    let header_len = usize::from(frame[offset] & 0x0f) * 4;
    if header_len < IPV4_MIN_HEADER || frame.len() < offset + header_len {
        return false;
    }
    let protocol = frame[offset + 9];
    let frag = u16::from_be_bytes([frame[offset + 6], frame[offset + 7]]);
    // 0x3fff covers MF and the fragment offset, but not DF.
    let fragmented = frag & 0x3fff != 0;

    hasher.update(b"v4");
    hasher.update(&frame[offset + 12..offset + 16]); // src
    hasher.update(&frame[offset + 16..offset + 20]); // dst
    hasher.update(&[protocol]);
    if fragmented {
        // Non-first fragments have no L4 header. Key on the IP identification
        // so every fragment of one datagram lands in the same queue.
        hasher.update(&frame[offset + 4..offset + 6]);
        return true;
    }
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
        && frame.len() >= offset + header_len + 4
    {
        hasher.update(&frame[offset + header_len..offset + header_len + 4]);
    }
    true
}

/// Walk the IPv6 extension header chain until we reach the upper-layer
/// protocol. The key is built from the *final* five tuple only: extension
/// headers are deliberately not hashed, so the same connection stays in one
/// queue whether or not it carries a Hop-by-Hop / Destination Options header.
fn classify_v6(frame: &[u8], offset: usize, hasher: &mut blake3::Hasher) -> bool {
    const IPV6_HEADER: usize = 40;
    if frame.len() < offset + IPV6_HEADER || frame[offset] >> 4 != 6 {
        return false;
    }
    let first_next = frame[offset + 6];
    let payload_len = u16::from_be_bytes([frame[offset + 4], frame[offset + 5]]) as usize;
    // Cap parsing at the declared IPv6 payload: ethernet padding after a
    // short IP packet must never be mistaken for L4 ports.
    let end = frame.len().min(offset + IPV6_HEADER + payload_len);

    hasher.update(b"v6");
    hasher.update(&frame[offset + 8..offset + 24]); // src
    hasher.update(&frame[offset + 24..offset + 40]); // dst

    let mut next = first_next;
    let mut cursor = offset + IPV6_HEADER;
    for _ in 0..MAX_EXTENSION_HEADERS {
        match next {
            IPPROTO_TCP | IPPROTO_UDP | IPPROTO_DCCP | IPPROTO_SCTP => {
                hasher.update(&[next]);
                if cursor + 4 <= end {
                    hasher.update(&frame[cursor..cursor + 4]); // src + dst port
                }
                return true;
            }
            IPPROTO_FRAGMENT => {
                // The first fragment carries L4 ports, later ones do not.
                // Key *all* fragments of a datagram by its identification so
                // they cannot be split into two FIFOs and reordered.
                hasher.update(b"frag");
                if cursor + 8 <= end {
                    hasher.update(&frame[cursor + 4..cursor + 8]);
                }
                return true;
            }
            IPPROTO_ESP => {
                // Ports are encrypted; the SPI is the only stable per-SA key.
                hasher.update(b"esp");
                if cursor + 4 <= end {
                    hasher.update(&frame[cursor..cursor + 4]);
                }
                return true;
            }
            IPPROTO_AH => {
                // AH's length field is in 32-bit words minus 2, unlike every
                // other extension header's 8-byte units minus 1.
                if cursor + 2 > end {
                    return degrade_v6(hasher, first_next);
                }
                let following = frame[cursor];
                let len = (usize::from(frame[cursor + 1]) + 2) * 4;
                next = following;
                match cursor.checked_add(len) {
                    Some(c) if c <= end => cursor = c,
                    _ => return degrade_v6(hasher, first_next),
                }
            }
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS | IPPROTO_MOBILITY
            | IPPROTO_HIP | IPPROTO_SHIM6 => {
                if cursor + 2 > end {
                    return degrade_v6(hasher, first_next);
                }
                let following = frame[cursor];
                let len = (usize::from(frame[cursor + 1]) + 1) * 8;
                next = following;
                match cursor.checked_add(len) {
                    Some(c) if c <= end => cursor = c,
                    _ => return degrade_v6(hasher, first_next),
                }
            }
            _ => {
                // ICMPv6, No Next Header, or an unknown protocol: an L3 key
                // based on the *original* next header is stable for every
                // packet of that protocol.
                hasher.update(&[first_next]);
                return true;
            }
        }
    }
    degrade_v6(hasher, first_next)
}

/// A stable coarse key for anything the extension header walk cannot fully
/// dissect. Never returns `false`: unparseable frames are still forwarded.
fn degrade_v6(hasher: &mut blake3::Hasher, first_next: u8) -> bool {
    hasher.update(b"degraded");
    hasher.update(&[first_next]);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const V6_SRC: [u8; 16] = [0xfd, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
    const V6_DST: [u8; 16] = [0xfd, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4];

    fn eth(ether_type: u16, payload_len: usize) -> Vec<u8> {
        let mut f = vec![0u8; ETHERNET_HEADER_LEN + payload_len];
        f[0..6].copy_from_slice(&[0x02, 1, 2, 3, 4, 5]);
        f[6..12].copy_from_slice(&[0x02, 6, 7, 8, 9, 10]);
        f[12..14].copy_from_slice(&ether_type.to_be_bytes());
        f
    }

    /// Fill in the common IPv6 fixed header. Returns the frame.
    fn v6_base(payload_len: usize, next: u8) -> Vec<u8> {
        let mut f = eth(ETH_P_IPV6, 40 + payload_len);
        f[14] = 0x60;
        f[18..20].copy_from_slice(&(payload_len as u16).to_be_bytes());
        f[20] = next;
        f[22..38].copy_from_slice(&V6_SRC);
        f[38..54].copy_from_slice(&V6_DST);
        f
    }

    fn ports(f: &mut [u8], at: usize, src_port: u16) {
        f[at..at + 2].copy_from_slice(&src_port.to_be_bytes());
        f[at + 2..at + 4].copy_from_slice(&53u16.to_be_bytes());
    }

    fn v4_tcp(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut f = eth(ETH_P_IPV4, 40);
        f[14] = 0x45; // IPv4, IHL = 5
        f[16..18].copy_from_slice(&40u16.to_be_bytes());
        f[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // DF, no fragmentation
        f[23] = IPPROTO_TCP;
        f[26..30].copy_from_slice(&[10, 0, 0, 1]);
        f[30..34].copy_from_slice(&[10, 0, 0, 2]);
        f[34..36].copy_from_slice(&src_port.to_be_bytes());
        f[36..38].copy_from_slice(&dst_port.to_be_bytes());
        f
    }

    /// IPv6 + direct UDP header (no extension headers).
    fn v6_udp(src_port: u16) -> Vec<u8> {
        let mut f = v6_base(8, IPPROTO_UDP);
        ports(&mut f, 54, src_port);
        f
    }

    /// IPv6 + one 8-byte generic extension header + UDP header.
    fn v6_one_ext_udp(src_port: u16, ext: u8) -> Vec<u8> {
        let mut f = v6_base(16, ext);
        f[54] = IPPROTO_UDP; // next header inside the extension header
        f[55] = 0; // hdr ext len 0 => 8 bytes
        ports(&mut f, 62, src_port);
        f
    }

    /// IPv6 + two chained 8-byte extension headers + UDP header.
    fn v6_two_ext_udp(src_port: u16) -> Vec<u8> {
        let mut f = v6_base(24, IPPROTO_HOPOPTS);
        f[54] = IPPROTO_DSTOPTS;
        f[55] = 0;
        f[62] = IPPROTO_UDP;
        f[63] = 0;
        ports(&mut f, 70, src_port);
        f
    }

    /// IPv6 + AH (12 bytes) + UDP header.
    fn v6_ah_udp(src_port: u16) -> Vec<u8> {
        let mut f = v6_base(20, IPPROTO_AH);
        f[54] = IPPROTO_UDP; // AH next header
        f[55] = 1; // (1 + 2) * 4 = 12 bytes
        ports(&mut f, 66, src_port);
        f
    }

    /// IPv6 + fragment header (+ trailing bytes standing in for L4 ports).
    fn v6_frag(identification: u32, frag_field: u16, src_port: u16) -> Vec<u8> {
        let mut f = v6_base(16, IPPROTO_FRAGMENT);
        f[54] = IPPROTO_UDP; // next header inside the fragment header
        f[56..58].copy_from_slice(&frag_field.to_be_bytes());
        f[58..62].copy_from_slice(&identification.to_be_bytes());
        ports(&mut f, 62, src_port);
        f
    }

    /// IPv6 + ESP header with a given SPI.
    fn v6_esp(spi: u32) -> Vec<u8> {
        let mut f = v6_base(8, IPPROTO_ESP);
        f[54..58].copy_from_slice(&spi.to_be_bytes());
        f
    }

    #[test]
    fn same_five_tuple_shares_a_flow() {
        assert_eq!(flow_id(&v4_tcp(1234, 80)), flow_id(&v4_tcp(1234, 80)));
    }

    #[test]
    fn ports_and_direction_are_significant() {
        let base = flow_id(&v4_tcp(1234, 80));
        assert_ne!(base, flow_id(&v4_tcp(1235, 80)));
        assert_ne!(base, flow_id(&v4_tcp(1234, 443)));
        // The tuple is ordered: the reverse direction is a separate (sparse)
        // flow, which is what lets pure ACKs escape a bulk transfer's queue.
        assert_ne!(base, flow_id(&v4_tcp(80, 1234)));
    }

    #[test]
    fn ipv4_fragments_are_keyed_by_identification() {
        let mut a = v4_tcp(1234, 80);
        a[20..22].copy_from_slice(&0x2000u16.to_be_bytes()); // MF
        a[18..20].copy_from_slice(&0x0042u16.to_be_bytes()); // identification
        let mut b = a.clone();
        assert_eq!(flow_id(&a), flow_id(&b));

        b[18..20].copy_from_slice(&0x0043u16.to_be_bytes());
        assert_ne!(flow_id(&a), flow_id(&b));
        // And a fragment is not mixed into the unfragmented flow.
        assert_ne!(flow_id(&a), flow_id(&v4_tcp(1234, 80)));
    }

    #[test]
    fn ipv6_direct_udp_uses_ports() {
        assert_eq!(flow_id(&v6_udp(5000)), flow_id(&v6_udp(5000)));
        assert_ne!(flow_id(&v6_udp(5000)), flow_id(&v6_udp(5001)));
    }

    #[test]
    fn ipv6_extension_headers_still_reach_the_ports() {
        // Hop-by-Hop, Routing and Destination Options all use the generic
        // 8-byte-unit length. The five tuple must be recovered behind them.
        for ext in [
            IPPROTO_HOPOPTS,
            IPPROTO_ROUTING,
            IPPROTO_DSTOPTS,
            IPPROTO_MOBILITY,
            IPPROTO_HIP,
            IPPROTO_SHIM6,
        ] {
            let f = v6_one_ext_udp(5000, ext);
            // Same five tuple as a bare UDP packet: one connection, one queue.
            assert_eq!(flow_id(&f), flow_id(&v6_udp(5000)), "ext {ext}");
            assert_ne!(
                flow_id(&f),
                flow_id(&v6_one_ext_udp(5001, ext)),
                "ext {ext}"
            );
        }
        assert_eq!(flow_id(&v6_two_ext_udp(5000)), flow_id(&v6_udp(5000)));
        assert_ne!(
            flow_id(&v6_two_ext_udp(5000)),
            flow_id(&v6_two_ext_udp(5001))
        );
    }

    #[test]
    fn ipv6_ah_uses_its_own_length_units() {
        let f = v6_ah_udp(5000);
        assert_eq!(flow_id(&f), flow_id(&v6_udp(5000)));
        assert_ne!(flow_id(&f), flow_id(&v6_ah_udp(5001)));
    }

    #[test]
    fn ipv6_fragments_never_split_a_datagram() {
        // First fragment (M=1, offset 0) carries ports; a later fragment
        // (offset 1) does not. Both must land in the same FIFO.
        let first = v6_frag(0x42, 0x0001, 5000);
        let later = v6_frag(0x42, 0x0008, 9999);
        assert_eq!(flow_id(&first), flow_id(&later));
        assert_ne!(flow_id(&first), flow_id(&v6_frag(0x43, 0x0001, 5000)));
        assert_ne!(flow_id(&first), flow_id(&v6_udp(5000)));
    }

    #[test]
    fn esp_is_keyed_by_spi() {
        assert_eq!(flow_id(&v6_esp(7)), flow_id(&v6_esp(7)));
        assert_ne!(flow_id(&v6_esp(7)), flow_id(&v6_esp(8)));
    }

    #[test]
    fn malformed_extension_headers_degrade_safely() {
        let mut f = v6_one_ext_udp(5000, IPPROTO_HOPOPTS);
        f[55] = 200; // hdr ext len claims far more bytes than the payload
        let a = flow_id(&f);
        assert_eq!(a, flow_id(&f));
        assert_ne!(a, UNCLASSIFIED_FLOW);
        assert_ne!(a, flow_id(&v6_udp(5000)));

        // A frame whose declared payload is missing is still a valid L3 key,
        // not an error.
        let short = v6_base(8, IPPROTO_HOPOPTS)[..54].to_vec();
        assert_eq!(flow_id(&short), flow_id(&short));
        assert_ne!(flow_id(&short), UNCLASSIFIED_FLOW);
    }

    #[test]
    fn ethernet_padding_is_not_mistaken_for_ports() {
        // Two frames with the same declared payload but different trailing
        // padding must hash identically.
        let mut a = v6_base(8, IPPROTO_UDP);
        ports(&mut a, 54, 5000);
        let mut b = a.clone();
        b.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(flow_id(&a), flow_id(&b));
    }

    #[test]
    fn non_ip_frames_are_keyed_by_mac_pair() {
        let arp = eth(crate::proto::ethertype::ARP, 28);
        assert_eq!(flow_id(&arp), flow_id(&arp));
        let mut other = arp.clone();
        other[5] = 0x99;
        assert_ne!(flow_id(&arp), flow_id(&other));
        assert_ne!(flow_id(&arp), UNCLASSIFIED_FLOW);
    }

    #[test]
    fn vlan_tag_is_skipped() {
        let plain = v4_tcp(1234, 80);
        let mut tagged = Vec::with_capacity(plain.len() + 4);
        tagged.extend_from_slice(&plain[..12]); // dst + src MAC
        tagged.extend_from_slice(&ETH_P_VLAN.to_be_bytes());
        tagged.extend_from_slice(&[0, 1]); // TCI
        tagged.extend_from_slice(&ETH_P_IPV4.to_be_bytes());
        tagged.extend_from_slice(&plain[ETHERNET_HEADER_LEN..]);
        assert_eq!(flow_id(&tagged), flow_id(&plain));
    }

    #[test]
    fn malformed_frames_degrade_to_one_safe_flow() {
        assert_eq!(flow_id(&[]), UNCLASSIFIED_FLOW);
        assert_eq!(flow_id(&[0u8; 13]), UNCLASSIFIED_FLOW);
        let mut short_ip = eth(ETH_P_IPV4, 8);
        short_ip[14] = 0x45;
        assert_eq!(flow_id(&short_ip), UNCLASSIFIED_FLOW);
        // A 14-byte all-zero frame is a valid (if odd) L2 header: classified,
        // not dropped, and stable.
        let zeros = [0u8; 14];
        assert_eq!(flow_id(&zeros), flow_id(&zeros));
        assert_ne!(flow_id(&zeros), UNCLASSIFIED_FLOW);
    }
}
