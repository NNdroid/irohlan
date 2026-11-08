# irohlan

**P2P Layer-2 VPN for Linux, built on [iroh](https://iroh.computer).**

irohlan 把多台 Linux 机器接入同一个**虚拟以太网**(TAP 设备,二层):ARP、NDP、
mDNS、网络邻居发现、局域网游戏等原生二层流量直接工作。虚拟网络默认同时是
**IPv4 + IPv6 双栈**,也可单独关闭任一地址族。底层用 iroh 的 QUIC 连接传输:
自动 NAT 打洞、中继回退、TLS 加密(身份即 Ed25519 公钥),无需配置任何 IP/端口。

```text
 machine A                     machine B
┌──────────────┐              ┌──────────────┐
│ tap0 10.13.37.1             │ tap0 10.13.37.2
│      fdXX:…::1              │      fdXX:…::2
│   ▲  irohlan │   QUIC mesh  │  irohlan  ▲  │
│   └──(TAP)───┼◄────────────►┼───(TAP)──►┘  │
└──────────────┘  NAT 打洞/中继 └──────────────┘
        ▲        加密传输            ▲
        └──────── 广播走 gossip 树 ──┘
```

## 特性

- **二层虚拟局域网** —— TAP 设备承载以太网帧,内核协议栈无感知;转发按目的 MAC
  分类,与 EtherType 无关,`0x0800`(IPv4)、`0x0806`(ARP)、`0x86dd`(IPv6)
  走完全相同的路径,NDP / MLD / DAD 的组播帧也照常经广播总线送达
- **IPv4 / IPv6 双栈** —— 创建者按同一个 host index 分配两族地址并写入租约表;
  TAP 同时配置 v4/v6,默认 IPv6 前缀是从网络 id 派生的唯一 ULA /64;
  `--no-ipv4` / `--no-ipv6` 可建纯单栈网络
- **iroh 数据面** —— QUIC datagram 直传(低延迟),超长帧自动走流兜底;
  公网经 n0 中继,局域网走 mDNS 直连(底层端点同时绑定 `0.0.0.0` 与 `[::]`,
  ticket 直连地址支持 IPv6)
- **免学习转发** —— 虚拟 MAC 从节点公钥确定性派生(`02:xx:xx:...`),
  MAC ↔ 节点身份天然互查,成员表即寻址表
- **Partial mesh(默认)** —— 每节点维持约 8 个邻居(`--mesh-links`),
  连接数 O(N·k) 而非 O(N²);单播帧按**链路质量加权**的链路状态路由(迷你 OSPF)
  多跳中继:代价综合 QUIC RTT、窗口丢包率、拥塞控制器估计带宽与链路饱和度,
  全部 EWMA 平滑并带切换迟滞防震荡
- **按对端配额 + 按流公平 + CoDel** —— 总中继带宽按活跃来源 peer 均分,
  peer 内再按有序五元组哈希分流(FQ),每条流独立 FIFO / DRR / CoDel:大象流
  挤不掉 ACK、DNS、ARP,持续排队时延被主动丢包压住,而不是等队列爆了才
  tail-drop。IPv6 扩展头逐层解析到端口,分片/ESP 按 identification/SPI 归流;
  分类只用于选队列,**转发决策仍与 EtherType 无关**;默认只记账不排队
- **累计账本与 Prometheus 指标** —— 中继累计计数落盘、重启后接着累加;
  同一份状态同时写成 `metrics.prom`(textfile collector 用)并可选开启
  **仅监听回环**的 `/metrics` HTTP 端点,含逐链路质量与选中路径代价
- **广播树** —— 广播/组播帧经 [iroh-gossip] 蔓延(可切换 flood 泛洪兜底)
- **创建者分配地址** —— 类 DHCP:创建者维护租约表,重入网保持地址稳定
- **口令准入** —— 握手时做网络口令知识证明;传输层另有 iroh TLS 加密
- **零配置发现** —— 入网凭证是一个自包含的 join ticket(base32 字符串)

[iroh-gossip]: https://crates.io/crates/iroh-gossip

## 快速开始

需要 Linux(内核 TUN/TAP 支持,且启用 IPv6)与 root 或 `CAP_NET_ADMIN`。

```bash
# 机器 A(创建者)
sudo ./irohlan create
# 输出:
#   addresses : 10.13.37.1, fdXX:XXXX:XXXX::1
#   subnets   : 10.13.37.0/24, fdXX:XXXX:XXXX::/64
#   network secret: ABCD2345...
#   join ticket   : irohlan1_BBBB...

# 机器 B(加入者)
sudo ./irohlan join irohlan1_BBBB... --secret ABCD2345...

# 回到机器 A / B,验证
ping 10.13.37.2              # IPv4 互 ping
ping6 fdXX:XXXX:XXXX::2      # IPv6 互 ping(用创建者输出的实际前缀)
ip -6 neigh show dev tap0    # NDP 学到的对端
arp -i tap0                  # IPv4 ARP 表项
```

两台机器在同一个局域网时,发现走 mDNS,完全离线可用;跨公网时经 n0 中继
自动打洞(可用 `--no-relay` 关闭,配合自建 relay 使用)。

## 命令

| 命令 | 说明 |
|---|---|
| `irohlan create [--subnet 10.13.37.0/24] [--subnet6 fd00:1234::/64] [--no-ipv4] [--no-ipv6] [--secret ...] [--dev irohlan0] [--mtu 1500] [--bus gossip\|flood] [--topology partial\|full] [--mesh-links 8] [--relay-limit-kib 2048] [--metrics-addr 127.0.0.1:9090] [--no-relay] [--no-mdns]` | 创建网络并常驻运行;打印 join ticket。默认 IPv4 /24 + 由 net_id 派生的 ULA /64 |
| `irohlan join <ticket> [--secret ...] [--ip 10.13.37.5] [--ip6 fd00::5] [--relay-limit-kib 2048] [--metrics-addr 127.0.0.1:9090] [--dev/--mtu/--bus/--topology/...]` | 加入网络并常驻运行;地址族由 ticket 决定,`--ip`/`--ip6` 必须对应同一个 host index(地址尾部一致) |
| `irohlan run [--dev/--mtu/--bus/--topology/--mesh-links/--relay-limit-kib/--metrics-addr/--no-metrics/...]` | 从本地已保存的状态恢复运行(开机自启用) |
| `irohlan show` | 重新打印本机保存的 join ticket |
| `irohlan status` | 查看运行时状态(成员表/路由表/计数器),含 ipv4 / ipv6 / subnets、逐链路 RTT/丢包/吞吐/带宽、选中路径代价、中继配额、活跃流数与 CoDel 计数 |

常用选项:`--no-ipv4` / `--no-ipv6` 切换单栈;`--subnet6` 自定义 IPv6 前缀
(支持 /32~/96,主机位至少 32 位);`--no-relay` 禁用公共 relay(但 iroh 的
`N0DisableRelay` 预设**仍会尝试 DNS/pkarr 地址发现**);完全无外网时,gossip
总线仍需可用的 mDNS 才能按 EndpointId 拨号,而 `--bus flood` 只沿已建立的 mesh
连接泛洪,可彻底不依赖地址发现(离线/隔离网络推荐);`--no-mdns` 关闭局域网
mDNS 发现;`-v/-vv` 提升日志级别。
启用 IPv6 时 MTU 必须 ≥ 1280(RFC 8200 的链路 MTU 下限),否则启动报错;
默认 1500。纯 IPv4 网络可以用更小的 MTU。

`--relay-limit-kib N` 把本机**转发**的中继总流量限制为 N KiB/s(按字节计,
0 = 默认,只记账、不排队也不丢帧)。这个 N 是**总量**,由当前活跃的来源 peer
均分(空闲 5 秒后释放份额),不会随邻居数线性放大。超限帧按五元组排进各自的
flow 队列:每条流上限 64 帧 / 128 KiB(一个 peer 合计 512 帧 / 512 KiB 兜底),
排队超过 2 秒丢弃;持续积压超过 5ms 且满 100ms 时,该流的 CoDel 会主动丢帧
压低时延,让对端 TCP 提前降速。配置写入 `network.json`,`irohlan run` 重启后
仍生效,也可用 `run --relay-limit-kib 0` 临时覆盖。它只作用于「从邻居收到、
再转给下一跳」的单播帧:本机自己发出或发给本机自己的流量、广播/组播帧都不受限。

`--metrics-addr 127.0.0.1:9090` 在本机回环开一个极简 HTTP 端点,
`curl http://127.0.0.1:9090/metrics` 即可抓 Prometheus 文本格式指标:
relay 全局/逐 peer 累计计数、队列积压、逐链路 RTT / 丢包率 / 吞吐 / 带宽估计,
以及每条选中路径的加权代价。**只接受回环地址**(非 loopback 会直接报错、拒绝绑定),
端口本身也不做认证,不要用端口转发把它暴露到公网。无论是否开 HTTP,每 5 秒
都会把同一份指标写到状态目录的 `metrics.prom`,可直接交给 node_exporter 的
textfile collector。中继的**累计**帧数/字节数同时写入 `relay-ledger.json`
(临时文件 + rename 原子替换),启动时读回并累加,重启不再归零;瞬时状态
(队列积压、活跃 peer/flow)不持久化。`--metrics-addr` 会写进 `network.json`,
`irohlan run` 默认继承,本次临时关闭用 `run --no-metrics`,临时换端口用
`run --metrics-addr 127.0.0.1:9101`。

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
| `~/.local/state/irohlan/network.json` | 当前网络参数(IPv4 子网 + IPv6 前缀、拓扑、邻居数、中继限速、metrics 地址) |
| `~/.local/state/irohlan/secret.txt` | 网络口令(0600) |
| `~/.local/state/irohlan/ticket.txt` | join ticket |
| `~/.local/state/irohlan/leases.json` | (创建者)按 host index 记录的租约 |
| `~/.local/state/irohlan/status.json` | 运行中周期写入的状态(含 ipv4/ipv6/subnets、link_metrics、routes、relay 账本/队列积压/CoDel 计数) |
| `~/.local/state/irohlan/relay-ledger.json` | 中继**累计**计数,每 5 秒及退出时原子写入,启动时读回累加 |
| `~/.local/state/irohlan/metrics.prom` | Prometheus 文本指标快照(textfile collector / 人工查看) |

## 工作原理

1. **身份与寻址**:每个节点持有一个 ed25519 密钥对,公钥即 iroh 的
   `EndpointId`。虚拟 MAC = `[0x02, blake3(EndpointId)[0..5]]`,因此任何
   成员都能把目的 MAC 直接映射到对端身份,无需地址学习。
2. **单播数据面**:节点与约 `k` 个邻居建立 QUIC 连接(partial mesh)。TAP 读出
   以太网帧 → 查目的 MAC 得到目标节点 → 查链路状态路由表得到下一跳 → 作为
   QUIC datagram(或超限时的单向流)发给下一跳;中间节点同理继续转发,
   帧头带 hop 上限(32)防环。直接邻居之间零跳直达。默认 MTU 1500(与常规
   以太网一致,主机侧不分片):不超过 QUIC datagram 上限的小帧(ARP、NDP、ACK、
   小包)走 datagram 快路径,更大的帧自动改走独立单向流(每帧一条流,
   帧间无队头阻塞)。
3. **链路质量加权链路状态路由**:每个节点把自己的**当前邻居 + 每条链路的 QUIC
   实测质量**作为 LSA(链路状态通告)经广播总线分发(连接变化即发布,30s 周期
   刷新,90s 过期)。四个维度全部取自 iroh 选中路径的 `PathStats`,不需要主动探测包:
   - `rtt_ms`:QUIC 平滑 RTT 估计
   - `loss_permille`:`sent_packets` / `lost_packets` 累计计数器**差分**出的窗口丢包率(‰)
   - `tx_kbps`:`sent_bytes` 差分出的实际 QUIC 发送吞吐(kbit/s)
   - `bw_kbps`:拥塞控制器给出的可持续带宽估计(kbit/s),没有估计时为 0

   差分结果先做一次 EWMA,发布前 LSA smoother 再做一次 EWMA(alpha=1/4)。
   链路代价(等价 ms)= `RTT_ms + 5ms`(每跳固定开销,避免"多跳但每跳都快"压过
   直连)+ `丢包‰ × 2` + 低带宽惩罚 + 饱和惩罚。**只罚差链路**:无损、带宽未知
   或 ≥ 10 Mbit/s、利用率 < 80% 的链路惩罚为 0,代价退化回 v4 的 `RTT + 5ms`;
   低带宽最高 +120ms,利用率 ≥80% 最高 +60ms,5% 丢包即 +100ms。注意"吞吐低"
   本身不是坏事,只有吞吐相对估计带宽**接近饱和**才罚,空闲链路不会被误判为
   差链路。每个节点把 LSDB 组装成带权无向图,用 Dijkstra 按 first hop 算出全网
   下一跳表——无中心控制器。为防止采样抖动造成路径震荡,新路径必须比当前路径
   好至少 **10ms 或 10%** 才会切换;内容未变的 LSA 只刷新过期时间、不触发重算。
   `irohlan status` 与 `/metrics` 都会列出逐链路质量和选中路径代价。每条链路的
   LSA 约 48 字节,默认 8 邻居远低于 gossip 4096 字节上限。
4. **广播数据面**:广播/组播帧发布到 iroh-gossip 主题(epidemic broadcast
   tree,天然去重防环),或用 flood 模式沿现有连接泛洪(`(origin, seq)` 去重)。
   IPv4 广播、ARP 与 IPv6 的 `33:33:xx` 组播(NDP/MLD/DAD)走同一条路径。
5. **控制面**:连接建立后先做口令证明(双方各出 nonce + blake3 proof,重放/反射
   均被绑定字段阻止);创建者在握手中完成双栈地址分配;成员表经广播总线周期同步
   (20s 公告,60s 过期)。
6. **连接管理**:partial 模式下每节点自主拨号约 `k/2` 个邻居、接受约 `k/2` 个
   入连接(期望总度数 ≈ k);创建者作为锚点始终保留直连。掉线由拨号循环自动
   补位(随机重选邻居),断链后路由随 LSA 刷新自动收敛。`--topology full` 可
   退回全互联(每对节点直连,小网络下两者等价)。
7. **双栈地址计划**:网络由一个可选 IPv4 子网 + 一个可选 IPv6 前缀组成,地址族
   可独立开关。默认 IPv6 前缀 = `fd00::/8` + `blake3(net_id)` 的前 40 位 + 16 位
   零子网号,即一个全局唯一、稳定的 ULA /64,无需 RA/DHCPv6 即可确定;
   自定义前缀与地址族开关都会写进 join ticket。创建者按 **host index** 分配:
   IPv4 = `base + index`,IPv6 = `prefix | index`,两族一一对应(租约表只存一个
   index,创建者固定占用 1)。TAP 上同时调用 `add_address_v4` /
   `add_address_v6`,内核自动生成 link-local 并完成 DAD;邻居解析靠原生 NDP,
   不需要任何 IPv6 专属控制协议。
8. **中继记账、按对端配额、按流公平与 CoDel**:partial mesh 的中继帧在转发前
   先过 `relay.rs`。账本按对端记录 `in`(从该邻居收到、待中继)、`out`(我转发
   给该邻居)、`queued`(当前积压)、`limited`(队列满/超时丢弃)与 `codel`(AQM
   主动丢弃)的帧数与字节数——注意 `in` 的归属是**上一跳**而不是原始发送者,
   因为二层帧里没有源节点身份。账本始终开启(默认就只记账),限速是可选的
   总量控制,分几层:
   - **均分配额**:`--relay-limit-kib N` 定义本机总转发速率,由「活跃来源 peer」
     (有积压或 5 秒内有帧)均分为 `N/k`;每个 peer 一个独立令牌桶(整数定点,
     不丢小数令牌,容量至少容纳一个最大帧)。重算份额前先把所有桶 refill 到
     当前时刻,避免切速率时丢掉已累积的时间;空闲 peer 退出后份额自动回吐,
     因此总带宽恒定,不会因为邻居多而被放大。
   - **按流分类(FQ)**:`flow.rs` 从以太网帧解析**有序**五元组(源/目的 IP、
     协议、源/目的端口)并哈希成 flow id。方向敏感是故意的:纯 ACK 属于稀疏流,
     不会被同一连接的批量数据堵住;ARP/NDP 按 MAC 对分流;IPv6 逐层跳过
     Hop-by-Hop / Routing / Destination Options / AH / Mobility / HIP / Shim6
     扩展头(长度单位不同:AH 是 32-bit words−2,其余是 8 字节×n)直到取出
     TCP/UDP 端口,且哈希里**不含扩展头链**,同一条连接无论带不带扩展头都在一个
     队列。反过来,只要有一条规则会拆散连接就绝不细分:IPv4/IPv6 分片(含首片)
     一律按 identification 归流、ESP 按 SPI、无法解析的统一进一个安全 flow。
     **分类结果只用于选队列**,转发路径(目的 MAC → 成员表 → 下一跳)完全不碰
     EtherType,原本"转发与 EtherType 无关"的原则仍然成立。
   - **每流 FIFO + DRR**:每个 peer 下按 flow id 惰性建队列,队列内严格 FIFO
     不重排。后台每 5ms 调一次 `drain()`,先在活跃 peer 间轮转,再在 peer 内的
     flow 队列间按字节赤字轮询,每轮给一条队列一个 quantum、轮转起点逐次后移;
     队首帧太长或令牌不足只影响自己那条流,小帧天然先走、大帧也不会饿死。
   - **CoDel AQM**:每条 flow 各自维护 CoDel 状态。帧出队时算 sojourn time,
     队列积压 ≤ 1 帧或时延 < 5ms 就复位;持续超过 100ms 进入 dropping,按
     `interval / sqrt(count)` 的间隔主动 head-drop(定点整数平方根,控制律平滑),
     时延回落后立即退出。稀疏流和刚入队的帧永远不会被误伤。
   - **有界 + 过期 + 低负载零延迟**:每 flow 64 帧 / 128 KiB(每个 peer 合计
     512 帧 / 512 KiB 兜底),排队超 2 秒丢弃;队列满/超时计入 `limited`,CoDel
     丢弃计入 `codel`。其中只有「队列满」是在 switch 当场丢弃、会同时计入
     `frames_dropped`,超时与 CoDel 都发生在 `drain()` 内部。队列为空且令牌够时
     `submit()` 走 fast path 立即发送,不经过 drain tick;
     `--relay-limit-kib 0` 时所有帧都走这条路径。

  `drain()` 只返回待发帧,由 node 的 pump 负责真正调用 mesh,因此调度逻辑
  是纯数据、可确定性单测。账本的**累计**部分每 5 秒以及 Ctrl-C 退出时写入
  `relay-ledger.json`,启动时读回累加;`metrics.prom` 与可选的回环 `/metrics`
  共用同一个 renderer,输出全局/逐 peer 计数、链路质量与路径代价。这些都是
  节点本地行为,不进 LSA、不改 ticket、不改 ALPN,同为 v5 的节点可以逐台
  滚动开启。

## 开发

```bash
cargo fmt --check              # 格式检查
cargo check                    # Windows/macOS 也能编译(设备层被 cfg 隔离)
cargo test                     # 纯逻辑单元测试(协议/票据/分配器/双栈地址/链路质量路由/flow 分类/队列与 CoDel/账本/指标渲染)
cargo clippy --all-targets -- -D warnings
cargo zigbuild --target x86_64-unknown-linux-gnu   # 交叉编译 Linux 二进制(验证 TAP 分支)
```

CI(GitHub Actions,ubuntu)运行 check + clippy + test,见
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)。

### Benchmark 与弱网测试

[`bench/`](bench/) 在**一台 Linux 主机**上用 network namespace + veth 搭出真实
QUIC underlay,用 `tc netem` 注入弱网,再用 `iperf3` / `ping` 测 TAP 里的虚拟以太网:

```text
direct:  ns-a (tap-a) ── veth ── ns-b (tap-b)                 # 创建者 = a
relay:   ns-a (tap-a) ── veth ── ns-b (tap-b) ── veth ── ns-c (tap-c)
                                    └─ 创建者/中继,固定 10.13.37.1
```

relay 模式里 a 与 c **没有 IP 路由直连**,且所有节点带 `--no-relay`,所以 a→c 的帧
必然经 b 转发,能真正压到按对端配额、flow 队列、DRR 与 CoDel。netem 施加在每个
veth endpoint 的 egress qdisc 上,劣化的是 QUIC underlay 而不是 TAP 帧本身。

⚠ **harness 固定用 `--bus flood`,不要用默认的 gossip**:join ticket 只携带
创建者的直接地址,而 gossip 要按裸 `EndpointId` 拨号,必须依赖地址发现。隔离
netns 里没有 DNS、没有默认路由,mDNS 也因为「找不到默认接口」无法加入多播组
(`could not join multicast group ... No such device`),所以 `gossip dial failed:
timed out` 会反复出现。后果不是 QUIC 断链 —— `connected_peers`、`link_metrics`
和 `routes` 都正常 —— 而是 ARP/NDP 广播帧与 20 秒一次的成员公告送不出去;
成员 TTL(60 秒)一到就被清掉,`by_mac()` 找不到对端,`ping` 变成
`Destination Host Unreachable`、`iperf3` 变成 `No route to host`。flood 把广播
封装成 `(origin, seq)` 信封沿**已建立的 mesh 连接**泛洪,不需要地址发现;relay
拓扑另外用 `--mesh-links 1`,让 partial-mesh dialer 不再尝试拨没有地址的 c。
mDNS 保持开启但不在关键路径上,它和 pkarr/DNS 超时只是预期日志噪声。

第三次 CI 复验又暴露出更底层的 **mesh 单向传输问题**:flood 已经能把创建者的
帧送到加入者(加入者 `frames_to_tap` 持续增长),但反方向只通最初几个包就停,
创建者 `members: []` / `lsdb_entries: 0`,成员 75 秒后过期。据此加固了
[`src/mesh.rs`](src/mesh.rs):`max_datagram_size()` 改为每条消息重算(该值随
路径 MTU 变化,只在 pump 启动时取一次会把连接永久钉死在 0)、datagram 发送
失败自动回落 uni-stream、**单次发送失败不再让 outbound pump 退出**(原本
`break` 后 handle 仍在 `peers` 里,后续帧全被静默吞掉)、uni-stream 读取拆到
独立任务避免饿死 `read_datagram()`。同时把总线订阅提前到发布者启动之前,
并为「零订阅者」「入站通道拒绝」「发送失败」加上可见日志,harness 运行时
`RUST_LOG=info,irohlan=debug` 会把它们收进节点日志。

> 排障顺序(CI 三次报红):第一次误判 `--no-mdns`;打开 mDNS 后第二次仍失败,
> 由 `frames_to_tap` 停滞 + `member expired` + `gossip dial failed` 定位到总线;
> 换成 flood 后第三次发现「创建者能发不能收」,才下沉到 mesh 传输层。

harness 还要求 overlay **连续 3 次 ping 成功**才算就绪(单次成功可能是刚建链时
的偶然回包),并在每个弱网档位开始前先清掉上一档的 qdisc、再探一次活;overlay
中途挂掉会立刻判该 mode 失败并落诊断,而不是把一堆空测量结果记成「弱网表现」。

前置条件:root、`/dev/net/tun`、`iproute2`(`ip` + `tc`)、`iperf3`、
`iputils-ping`、`python3`、`coreutils`。

```bash
cargo build --release
sudo bash ./bench/run.sh --binary ./target/release/irohlan
# 只跑中继 + 弱网档位,并打开限速以观察 FQ/CoDel
sudo bash ./bench/run.sh --binary ./target/release/irohlan --mode relay \
    --profiles clean,loss,congested,mobile --relay-limit-kib 2048 \
    --ipv6 --out ./bench-results
bash ./bench/run.sh --list-profiles
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--mode` | `both` | `direct` / `relay` / `both` |
| `--profiles` | `clean,latency,loss,congested,mobile` | 逗号分隔,或 `all` |
| `--duration` / `--parallel` | `10` / `4` | 每档 iperf3 秒数 / TCP 流数 |
| `--udp-rate` | `50M` | UDP 目标发送速率(弱网下故意过载) |
| `--relay-limit-kib` | `0` | 中继总带宽上限;`0` 只记账不排队,`>0` 才产生 queued/CoDel |
| `--settle` | `6` | 采集前等待秒数,`status.json` 每 5 秒写一次 |
| `--ipv6` | 关 | 保留双栈地址计划并额外做 `ping -6`(ULA 前缀运行时派生) |

弱网档位(`tc netem`,链路双向生效):

| 档位 | netem |
| --- | --- |
| `clean` | 无 |
| `latency` | `delay 60ms` |
| `jitter` | `delay 40ms 20ms distribution normal` |
| `loss` / `heavy-loss` | `loss 2%` / `loss 8%` |
| `slow` | `rate 10mbit` |
| `congested` | `delay 30ms 10ms loss 1% rate 20mbit` |
| `reorder` | `delay 20ms reorder 5% 50%` |
| `mobile` | `delay 80ms 30ms loss 3% rate 8mbit duplicate 0.5%` |

每档采集 TCP/UDP goodput、TCP 重传、UDP 丢包/抖动、空闲与负载下 RTT(可选
IPv6)、v5 链路质量与路径代价、relay 累计差值、active flows / queued,并从每个
节点的回环 `/metrics` 拉一次指标。输出 `summary.md` / `summary.json` 与逐档原始
文件。`ΔTCP` 是相对同拓扑 `clean` 的**吞吐下降百分比**,越大越差;`relay` /
`limited` / `CoDel` 是该档内所有节点累计差值之和。报告会自动给出告警(例如
relay 模式完全没有中继帧、开了限速却没有 CoDel 丢帧、IPv6 ping 全失败),
`report.py --fail-on-error` 可在测量出错或拓扑没就绪时返回非零。

[`benchmark.yml`](.github/workflows/benchmark.yml) 只提供 `workflow_dispatch`
手动触发(可改档位/时长/限速),**没有定时任务**,需要时在 Actions 里点
"Run workflow";产物是 `irohlan-benchmark-results` artifact,同时写进 job
summary。它也**不作为 PR 门槛**,因为共享 runner 的绝对吞吐不可跨次比较,
只看同一次运行内各档位之间的相对变化。若拓扑未就绪或中途掉线,harness 会把
各节点的完整日志、`status.json` / `network.json`,以及接口状态、TAP 收发计数、
ARP/NDP 邻居表、多播组、最后一次 ping 输出写到 `_diagnostics/<mode>/` 并一并上传;
`Assert measurements completed` 会打印 `summary.json`,失败时另一步会把
`errors.txt` / `*.err`、节点日志关键行和报告告警直接打进 CI 日志。

> 这是单机仿真:netem 劣化的是 veth 上的 QUIC underlay,不模拟公网 NAT、公共
> relay 或 CDN 路径;`--ipv6` 目前只加 IPv6 ping 探针,iperf3 仍走 IPv4。

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
# 9. IPv6:`ip -6 addr show dev tap0` 看到 ULA 地址;`ping6 <对端 v6>` 通;
#    `ip -6 neigh show dev tap0` 能看到对端(NDP 走广播总线)
# 10. IPv6 吞吐:`iperf3 -s -6` / `iperf3 -6 -c <对端 v6>`
# 11. 纯单栈:`create --no-ipv4` 后确认 tap0 只有 v6 地址且 ping6 通;
#     `create --no-ipv6` 后确认只有 v4 地址
# 12. MTU 保护:带 IPv6 时 `--mtu 1200` 应被拒绝;`--no-ipv6 --mtu 1200` 可启动
# 13. 自定义前缀:`create --subnet6 fd00:1234:5678::/64` 后 join,
#     两端地址都应落在该前缀内
# 14. 链路质量观测:status 的 "links" 应列出直连邻居的 RTT(ms)、loss(‰)、
#     tx/bw(kbps);"routes" 应列出到各目的地的 first hop 与加权代价;
#     直连链路经中继/打洞切换时,RTT 与带宽估计应随之变化
# 15. 加权选路:3+ 节点组网,给某条链路人为加延迟(tc qdisc netem delay),
#     观察 status 中该目的地的 first hop 是否切到低延迟路径;
#     延迟回到原值后路径不应来回抖动(迟滞 10ms / 10%)
# 16. LSA 容量:--mesh-links 保持默认 8;若调得极大,LSA 需保持在
#     iroh-gossip 单条消息 4096 字节上限内(v5 约 80 条链路),
#     flood 模式超限会自动改走 uni-stream
# 17. 中继记账:3+ 节点 partial mesh,让两台非直连机器互 ping / iperf3,
#     在中间节点 status 的 "relay peer" 里看到 in/out 帧数与字节数增长
#     (归属是上一跳,不是原始发送者)
# 18. 总量与均分:中间节点加 --relay-limit-kib 256,从**两个不同来源 peer**
#     同时跑 iperf3;status 应显示 2 active peers、每 peer 128 KiB/s,
#     两条流合计吞吐仍约 256 KiB/s(不是各 256),queued 计数随压测增长
# 19. 公平性/防饿死:一边跑大包持续灌,另一边只发 ping/小包;小包流不应被
#     饿死(DRR 轮转),同一来源的 TCP 流不应出现乱序重传告警;
#     队列满或排队超时后 limited 增长,本机直连流量不受影响
# 20. 持久化:限速节点改用 irohlan run 重启,status 的 limit 值应保持不变;
#     run --relay-limit-kib 0 可临时关闭
# 21. 按流公平:同一个来源 peer 上同时跑 1 条 iperf3 大象流和持续的
#     ping / DNS 小包;status 的 active flows 应 >= 2,小包 RTT 不应随大象流
#     灌入而飙升(有序五元组让 ACK/小包单独成流,DRR 单独服务)
# 22. CoDel:把 --relay-limit-kib 调到明显低于发送速率并持续压测;
#     status 的 codel 计数应增长,排队时延被压在 5ms~100ms 量级而不是
#     一直涨到 2 秒 TTL;停止压测后 codel 计数应停止增长
# 23. 链路质量:tc qdisc netem loss 5% 给某条链路注入丢包,status 的 links
#     里 loss 应上升、routes 的 first hop 应切到无损路径;iperf3 压到接近
#     链路容量时 tx/bw 上升,高利用率链路的代价被抬高
# 24. 账本持久化:压一段中继流量后 Ctrl-C 停止,查看 relay-ledger.json 的
#     累计值;irohlan run 重启后 status / metrics 的 relayed 总数应继续累加
#     (不归零),queued 与 active_flows 则应从 0 开始
# 25. Prometheus:create --metrics-addr 127.0.0.1:9090,
#     curl http://127.0.0.1:9090/metrics 应看到 irohlan_relay_* /
#     irohlan_link_* / irohlan_route_cost;其它路径返回 404;
#     --metrics-addr 0.0.0.0:9090 应被拒绝;metrics.prom 与 HTTP 内容一致
# 26. IPv6 扩展头:用 scapy 构造带 HBH / Destination Options 的 v6 流量,
#     与同五元组的普通 v6 流对比,status 的 active flows 不应因扩展头翻倍;
#     v6 分片下同一 datagram 的首片与后续片不应出现乱序重传
```

### 升级与兼容性

- wire 协议当前是 **`irohlan/v5`**:v3 起成员记录/握手消息带双栈地址,v4 起
  LSA 从「邻居 ID 列表」改为「邻居 + RTT」的加权链路列表,v5 起每条链路再带上
  窗口丢包率、实际吞吐与带宽估计,代价从纯 RTT 改为综合链路质量。**v5 节点
  不能与 v4/v3/v2 节点互通**(mesh ALPN 不同,且 LSA 的 postcard 编码不兼容);
  join ticket 仍是 v2,v1 ticket 也仍可解码。升级时请整网一起换版本。
- v1 ticket 仍可解码,会升级为「仅 IPv4」的网络计划;要用双栈,请用新版
  `irohlan show` 重新取 ticket 再加入。
- 旧 `network.json` / `leases.json` 自动兼容:旧 IPv4 网络升级后会自动获得派生
  的 ULA /64;创建者重启会重写 `ticket.txt`。旧租约按 IPv4 地址反推 host index,
  地址保持稳定。
- 中继记账/配额/flow 队列/CoDel、IPv6 扩展头解析、账本持久化与 metrics 导出
  都是**纯本地行为**,不改 wire 协议:`irohlan/v5`、join ticket v2、LSA 格式
  都不变。这里说的"逐台滚动开启、新旧节点可混跑"仅指 **同为 v5 的节点**
  (旧节点只是没有账本/队列),与上一条 v2/v3/v4 → v5 必须整网同升不冲突。
  限速值存在 `network.json` 的 `relay_limit_kib`,metrics 地址存在
  `metrics_addr`,旧文件缺省分别视为 0(只记账)与关闭。`status.json` 的
  `link_metrics` 兼容读取 v4 的 `link_rtts` 字段(缺失的质量维度按 0 处理);
  `relay-ledger.json` 允许字段缺失,损坏时只告警并从零重新计数。

### 已知限制

- 加入网络时创建者必须在线(它是地址分配器,partial 模式下还作为锚点邻居)
- partial mesh 的单播可能经过 1~2 跳中继,中继节点承担少量转发负载;
  链路状态收敛期间(秒级)个别帧可能被丢弃,由上层协议重试
- 广播走 gossip 时消息不保证送达(ARP/NDP/TCP 自带重试,可容忍);在完全没有
  地址发现的隔离网络里 gossip 拨号会持续超时,成员公告随之丢失,60 秒 TTL
  过期后即使 QUIC 连接仍在,`by_mac()` 也会查不到对端、单播被丢弃。这种环境
  请显式用 `--bus flood`(见 Benchmark 章节)
- 目前仅支持 Linux;Windows(需 tap-windows6 驱动)在路线图上
- 一个主机同时只属于一个虚拟网络
- 链路质量全部来自 QUIC 选中路径的统计,不是主动探测:RTT 是 QUIC 的平滑估计,
  带宽估计可能返回 `None`(此时低带宽/饱和惩罚都不生效),丢包率与吞吐是两次
  LSA 采样之间的窗口值(默认 30s),短突发拥塞会被 EWMA 抹平。代价模型不含
  抖动、主动可用带宽探测或应用级体验指标;迟滞按总代价的 10% 计算,代价基数
  被质量惩罚抬高后,切换也会相应更保守
- 按流公平的粒度受解析能力限制:IPv6 分片按 identification、ESP 按 SPI、
  无法解析的帧共用一个 flow(同一对主机上的多条连接可能落到同一队列);
  IPv6 扩展头链最多解析 8 层,越界/畸形会退化为稳定粗粒度 key;哈希碰撞也会
  让不同流共享队列。CoDel 对 UDP / 非拥塞控制流量只是丢帧而非降速,队列满仍是
  tail-drop(没有按流的丢弃优先级),且 CoDel 只在帧**能被调度出队**时才评估,
  速率极低、帧根本发不出去时由 2 秒 TTL 兜底。账本只认「上一跳」而非原始
  发送者(二层帧里没有源节点身份);累计计数落盘,但瞬时队列/活跃流状态不持久化
- `/metrics` 只监听回环、无认证,同一主机上的其它用户可读到拓扑与逐 peer
  流量;`metrics.prom` 是快照而非时间序列,长期趋势需要外部采集器

## License

GPL-3.0(与仓库 LICENSE 一致;依赖均为 MIT/Apache-2.0,兼容)
