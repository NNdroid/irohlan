//! Linux TAP device handling (layer-2 virtual ethernet interface).
//!
//! The TAP device is created via tun-rs (`/dev/net/tun`, `IFF_TAP`). Frames
//! read from it are full ethernet frames, exactly what we tunnel through the
//! iroh mesh. Creating and configuring the device requires `CAP_NET_ADMIN`
//! (run as root or use `setcap cap_net_admin+ep`).
//!
//! Forwarding is EtherType agnostic: IPv4, ARP, IPv6, NDP and MLD frames all
//! traverse the same switch. The device is configured with both address
//! families so the host stack can use either one (or both).

use crate::netaddr::{AddrPlan, VirtualAddrs};

/// Default MTU for the virtual ethernet device.
///
/// 1500 matches a regular Ethernet network and is above the 1280-byte minimum
/// IPv6 link MTU, so the host protocol stack never fragments and path-MTU
/// blackholes are avoided.
///
/// Note what this costs on the wire. A QUIC datagram budget is
/// `current_mtu - 38` bytes (QUIC header plus AEAD tag plus the datagram frame
/// header), i.e. 1414 bytes once PMTU discovery has settled at its 1452-byte
/// upper bound. A 1500-byte MTU produces ethernet frames of up to 1514 bytes,
/// so with the two-byte mesh header (`tag`, `hop`) **every full-size frame
/// takes the uni-stream overflow path** — one stream per frame, and a stream
/// slot is only returned a round trip later. Small frames (ARP, NDP, TCP ACKs)
/// still use the datagram fast path.
///
/// That is a deliberate trade (no host-side fragmentation) but it is the first
/// thing to look at when throughput sits far below the link capacity: see
/// `irohlan_mesh_frames_total{path="stream"}`. Lowering `mtu` to 1280 moves
/// full-size frames back onto datagrams.
pub const DEFAULT_MTU: u16 = 1500;

/// Async handle to a TAP device.
#[cfg(target_os = "linux")]
pub struct TapDevice {
    dev: tun_rs::AsyncDevice,
    name: String,
}

#[cfg(target_os = "linux")]
impl TapDevice {
    /// Create a layer-2 device with the given name, MTU and MAC.
    ///
    /// `name` may be a fixed name (e.g. `irohlan0`) or a template containing
    /// `%d` (e.g. `irohlan%d`); `None` lets the kernel pick a name.
    pub async fn create(
        name: Option<String>,
        mtu: u16,
        mac: [u8; 6],
    ) -> std::io::Result<TapDevice> {
        let mut builder = tun_rs::DeviceBuilder::new()
            .layer(tun_rs::Layer::L2)
            .mtu(mtu)
            .mac_addr(mac)
            // Bring the interface up explicitly: IPv6 addresses need an UP
            // device for DAD (duplicate address detection) to complete.
            .enable(true);
        if let Some(name) = name {
            builder = builder.name(name);
        }
        let dev = builder.build_async()?;
        let name = dev.name()?;
        tracing::info!(device = %name, mtu, mac = %crate::crypto::format_mac(&mac), "TAP device created");
        Ok(TapDevice { dev, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Assign our virtual addresses (IPv4 and/or IPv6) with their prefixes.
    pub fn configure(&self, addrs: &VirtualAddrs, plan: &AddrPlan) -> std::io::Result<()> {
        if let (Some(ip), Some(net)) = (addrs.ipv4(), plan.v4) {
            tracing::info!(ip = %ip, prefix = net.prefix, "configuring IPv4 address");
            self.dev.add_address_v4(ip, net.prefix)?;
        }
        if let (Some(ip), Some(net)) = (addrs.ipv6(), plan.v6) {
            tracing::info!(ip = %ip, prefix = net.prefix, "configuring IPv6 address");
            self.dev.add_address_v6(ip, net.prefix)?;
        }
        Ok(())
    }

    /// Read one ethernet frame into `buf`, returning its length.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.dev.recv(buf).await
    }

    /// Write one ethernet frame.
    pub async fn send(&self, frame: &[u8]) -> std::io::Result<()> {
        self.dev.send(frame).await?;
        Ok(())
    }
}

/// Stub for non-Linux hosts (e.g. the Windows dev machine): the rest of the
/// crate compiles, but creating a device always fails at runtime.
#[cfg(not(target_os = "linux"))]
pub struct TapDevice;

#[cfg(not(target_os = "linux"))]
impl TapDevice {
    pub async fn create(
        _name: Option<String>,
        _mtu: u16,
        _mac: [u8; 6],
    ) -> std::io::Result<TapDevice> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "irohlan currently requires Linux for TAP devices",
        ))
    }

    pub fn name(&self) -> &str {
        "n/a"
    }

    pub fn configure(&self, _addrs: &VirtualAddrs, _plan: &AddrPlan) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "not supported on this platform",
        ))
    }

    pub async fn recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
        unreachable!("device cannot be created on this platform")
    }

    pub async fn send(&self, _frame: &[u8]) -> std::io::Result<()> {
        unreachable!("device cannot be created on this platform")
    }
}
