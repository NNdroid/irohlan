# irohlan

**P2P Layer-2 VPN for Linux, built on [iroh](https://iroh.computer).**

irohlan 把多台 Linux 机器接入同一个**虚拟以太网**(TAP 设备,二层):ARP、mDNS、
网络邻居发现、局域网游戏等原生二层流量直接工作。底层用 iroh 的 QUIC 连接传输:
自动 NAT 打洞、中继回退、TLS 加密(身份即 Ed25519 公钥),无需配置任何 IP/端口。

```text
 machine A                     machine B
┌──────────────┐              ┌──────────────┐
│ tap0 10.13.37.1             │ tap0 10.13.37.2
│   ▲  irohlan │   QUIC mesh  │  irohlan  ▲  │
│   └──(TAP)───┼◄────────────►┼───(TAP)──►┘  │
└──────────────┘  NAT 打洞/中继 └──────────────┘
        ▲        加密传输            ▲
        └──────── 广播走 gossip 树 ──┘
```

## 特性

- **二层虚拟局域网** —— TAP 设备承载以太网帧,内核协议栈无感知
- **iroh 数据面** —— QUIC datagram 直传(低延迟),超长帧自动走流兜底;
  公网经 n0 中继,局域网走 mDNS 直连
- **免学习转发** —— 虚拟 MAC 从节点公钥确定性派生(`02:xx:xx:...`),
  MAC ↔ 节点身份天然互查,成员表即寻址表
- **Partial mesh(默认)** —— 每节点维持约 8 个邻居(`--mesh-links`),
  连接数 O(N·k) 而非 O(N²);单播帧经链路状态路由(迷你 OSPF)多跳中继
- **广播树** —— 广播/组播帧经 [iroh-gossip] 蔓延(可切换 flood 泛洪兜底)
- **创建者分配 IP** —— 类 DHCP:创建者维护租约表,重入网保持地址稳定
- **口令准入** —— 握手时做网络口令知识证明;传输层另有 iroh TLS 加密
- **零配置发现** —— 入网凭证是一个自包含的 join ticket(base32 字符串)

[iroh-gossip]: https://crates.io/crates/iroh-gossip

## 快速开始

需要 Linux(内核 TUN/TAP 支持)与 root 或 `CAP_NET_ADMIN`。

```bash
# 机器 A(创建者)
sudo ./irohlan create
# 输出:
#   network secret: ABCD2345...
#   join ticket   : irohlan1_BBBB...

# 机器 B(加入者)
sudo ./irohlan join irohlan1_BBBB... --secret ABCD2345...

# 回到机器 A / B,验证
ping 10.13.37.2     # 互 ping 对方虚拟 IP
arp -i tap0         # 能看到对端的 ARP 表项
```

两台机器在同一个局域网时,发现走 mDNS,完全离线可用;跨公网时经 n0 中继
自动打洞(可用 `--no-relay` 关闭,配合自建 relay 使用)。

## 命令

| 命令 | 说明 |
|---|---|
| `irohlan create [--subnet 10.13.37.0/24] [--secret ...] [--dev irohlan0] [--mtu 1500] [--bus gossip\|flood] [--topology partial\|full] [--mesh-links 8] [--no-relay] [--no-mdns]` | 创建网络并常驻运行;打印 join ticket |
| `irohlan join <ticket> [--secret ...] [--ip 10.13.37.5] [同上选项]` | 加入网络并常驻运行 |
| `irohlan run [--dev/--mtu/--bus/--topology/--mesh-links/...]` | 从本地已保存的状态恢复运行(开机自启用) |
| `irohlan show` | 重新打印本机保存的 join ticket |
| `irohlan status` | 查看最近一次运行的运行时状态(成员表/路由表/计数器) |

常用选项:`--no-relay` 纯离线组网;`--no-mdns` 关闭局域网发现;
`--bus flood` 用泛洪代替 gossip(小网络排障用);`-v/-vv` 提升日志级别。

## 权限与部署

创建/配置 TAP 设备需要 `CAP_NET_ADMIN`,推荐用 setcap 免 root 运行:

```bash
sudo setcap cap_net_admin+ep "$(readlink -f "$(which irohlan)")"
```

systemd 单元见 [`deploy/irohlan.service`](deploy/irohlan.service):
先手动执行一次 `irohlan create` / `irohlan join`(状态写入
`~/.local/state/irohlan/`),然后:

```bash
sudo systemctl enable --now irohlan@$USER
```

## 状态与数据

| 路径 | 内容 |
|---|---|
| `~/.local/state/irohlan/identity.key` | 节点身份(32 字节 ed25519 种子,0600) |
| `~/.local/state/irohlan/network.json` | 当前网络参数 |
| `~/.local/state/irohlan/secret.txt` | 网络口令(0600) |
| `~/.local/state/irohlan/ticket.txt` | join ticket |
| `~/.local/state/irohlan/leases.json` | (创建者)IP 租约表 |
| `~/.local/state/irohlan/status.json` | 运行中周期写入的状态 |

## 工作原理

1. **身份与寻址**:每个节点持有一个 ed25519 密钥对,公钥即 iroh 的
   `EndpointId`。虚拟 MAC = `[0x02, blake3(EndpointId)[0..5]]`,因此任何
   成员都能把目的 MAC 直接映射到对端身份,无需地址学习。
2. **单播数据面**:节点与约 `k` 个邻居建立 QUIC 连接(partial mesh)。TAP 读出
   以太网帧 → 查目的 MAC 得到目标节点 → 查链路状态路由表得到下一跳 → 作为
   QUIC datagram(或超限时的单向流)发给下一跳;中间节点同理继续转发,
   帧头带 hop 上限(32)防环。直接邻居之间零跳直达。默认 MTU 1500(与常规
   以太网一致,主机侧不分片):不超过 QUIC datagram 上限的小帧(ARP、ACK、
   小包)走 datagram 快路径,更大的帧自动改走独立单向流(每帧一条流,
   帧间无队头阻塞)。
3. **链路状态路由**:每个节点把自己的**当前邻居集合**作为 LSA(链路状态通告)
   经广播总线分发(连接变化即发布,30s 周期刷新,90s 过期)。每个节点在本地
   对"自己的邻居 + LSDB"做 BFS,算出全网下一跳表——无中心控制器。
4. **广播数据面**:广播/组播帧发布到 iroh-gossip 主题(epidemic broadcast
   tree,天然去重防环),或用 flood 模式沿现有连接泛洪(`(origin, seq)` 去重)。
5. **控制面**:连接建立后先做口令证明(双方各出 nonce + blake3 proof,重放/反射
   均被绑定字段阻止);创建者在握手中完成 IP 分配;成员表经广播总线周期同步
   (20s 公告,60s 过期)。
6. **连接管理**:partial 模式下每节点自主拨号约 `k/2` 个邻居、接受约 `k/2` 个
   入连接(期望总度数 ≈ k);创建者作为锚点始终保留直连。掉线由拨号循环自动
   补位(随机重选邻居),断链后路由随 LSA 刷新自动收敛。`--topology full` 可
   退回全互联(每对节点直连,小网络下两者等价)。

## 开发

```bash
cargo check                 # Windows/macOS 也能编译(设备层被 cfg 隔离)
cargo test                  # 纯逻辑单元测试(协议/票据/分配器/去重)
cargo clippy --all-targets
cargo zigbuild --target x86_64-unknown-linux-gnu   # 交叉编译 Linux 二进制
```

CI(GitHub Actions,ubuntu)运行 check + clippy + test,见
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)。

### 真机测试清单(WSL2 / 两台 Linux)

```bash
# 1. 双节点互通:互 ping 对方虚拟 IP,ping 通即二层转发正常
# 2. 吞吐基线:任一节点 iperf3 -s,另一节点 iperf3 -c <对端IP>
# 3. 组播/mDNS:两侧安装 avahi-daemon,avahi-browse -a 应看到对方
# 4. 广播:arping -I tap0 <对方IP>;观察 status 中 frames_from_tap 增长
# 5. 重连:断开对端网络 30s 再恢复,观察 "mesh connected" 日志
# 6. 冲突:两个节点用相同 --ip 加入,后者应被创建者拒绝
# 7. 多跳中继(partial mesh):3+ 节点组网,在 status 中确认
#    peers 数约等于 --mesh-links;两台互不相邻的机器互 ping,
#    中间节点的 frames_relayed 计数应增长
# 8. 拓扑对比:--topology full 重跑小规模场景,比较延迟/吞吐
```

### 已知限制(v1)

- 加入网络时创建者必须在线(它是地址分配器,partial 模式下还作为锚点邻居)
- partial mesh 的单播可能经过 1~2 跳中继,中继节点承担少量转发负载;
  链路状态收敛期间(秒级)个别帧可能被丢弃,由上层协议重试
- 广播走 gossip 时消息不保证送达(ARP/TCP 自带重试,可容忍)
- 目前仅支持 Linux;Windows(需 tap-windows6 驱动)在路线图上
- 一个主机同时只属于一个虚拟网络
- 路由代价统一按跳数(BFS),未按 RTT/带宽加权

## License

MIT OR Apache-2.0
