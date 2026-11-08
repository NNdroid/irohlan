#!/usr/bin/env bash
# Shared helpers for the irohlan benchmark harness.
#
# Topology (network namespaces, one veth pair per physical hop):
#
#   direct:  ns-a (tap-a) --- veth --- ns-b (tap-b)
#   relay:   ns-a (tap-a) --- veth --- ns-b (tap-b) --- veth --- ns-c (tap-c)
#
# The veth links are the *only* path between the namespaces, so `tc netem`
# on them degrades exactly the QUIC underlay (not the emulated LAN frames).
# In relay mode ns-a and ns-c have no IP route to each other: any iroh
# direct connection between them fails, which forces A -> B -> C forwarding
# and therefore exercises relay accounting, FQ and CoDel.
#
# All nodes share the host filesystem but get separate XDG_STATE_HOME dirs,
# so `irohlan show` can read the creator ticket from the host namespace.

set -euo pipefail

BENCH_BINARY="${BENCH_BINARY:-}"
BENCH_ROOT="${BENCH_ROOT:-/tmp/irohlan-bench}"
BENCH_OUT="${BENCH_OUT:-$BENCH_ROOT/results}"
BENCH_STATE_ROOT="$BENCH_ROOT/state"
BENCH_LOG_ROOT="$BENCH_ROOT/logs"

BENCH_V4_NET="10.13.37.0/24"
BENCH_MTU="${BENCH_MTU:-1400}"
BENCH_SECRET="irohlan-benchmark-only-secret"
BENCH_METRICS_PORT=9090
BENCH_READY_TIMEOUT="${BENCH_READY_TIMEOUT:-90}"
BENCH_PING_COUNT="${BENCH_PING_COUNT:-20}"
# status.json is written every 5s; wait for one more tick before collecting
# so the "after" snapshot includes the whole measurement window.
BENCH_SETTLE_SECS="${BENCH_SETTLE_SECS:-6}"

BENCH_NODES=()
BENCH_VETH_DEVS=()
BENCH_PIDS=()
BENCH_TICKET=""
BENCH_MODE="direct"
BENCH_IPV6=0
BENCH_SERVER_IP6=""

bench_log() { printf '[bench] %s\n' "$*" >&2; }
bench_die() { printf '[bench] ERROR: %s\n' "$*" >&2; exit 1; }

# StateDir::open() resolves to $XDG_STATE_HOME/irohlan/, not $XDG_STATE_HOME/.
# Every direct file read in this harness must go through this helper.
state_of() { echo "$BENCH_STATE_ROOT/$1/irohlan"; }

# In relay mode the creator must sit in the middle: every joiner has to dial
# the creator once to get its address, and only node b is reachable from both
# ends of the linear veth chain. The creator always owns host index 1.
vip_of() {
    if [[ "$BENCH_MODE" == relay ]]; then
        case "$1" in
            a) echo "10.13.37.2" ;;
            b) echo "10.13.37.1" ;;
            c) echo "10.13.37.3" ;;
            *) return 1 ;;
        esac
    else
        case "$1" in
            a) echo "10.13.37.1" ;;
            b) echo "10.13.37.2" ;;
            *) return 1 ;;
        esac
    fi
}

ns_of() { echo "irohlan-$1"; }

bench_creator_node() {
    if [[ "$BENCH_MODE" == relay ]]; then
        echo b
    else
        echo a
    fi
}

bench_server_node() {
    if [[ "$BENCH_MODE" == relay ]]; then
        echo c
    else
        echo b
    fi
}

bench_require_env() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || bench_die "run as root (ip netns / tc / TAP need CAP_NET_ADMIN)"
    [[ -n "$BENCH_BINARY" && -x "$BENCH_BINARY" ]] || bench_die "BENCH_BINARY is not an executable: $BENCH_BINARY"
    local missing=()
    local cmd
    for cmd in ip tc iperf3 ping python3 timeout; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        bench_die "missing tools: ${missing[*]} (apt install iproute2 iperf3 iputils-ping python3 coreutils)"
    fi
    [[ -e /dev/net/tun ]] || bench_die "/dev/net/tun is missing; load it with: sudo modprobe tun"
    if ! ip netns list >/dev/null 2>&1; then
        bench_die "ip netns is unavailable (needs CAP_NET_ADMIN and a writable /var/run/netns)"
    fi
}

# ---------------------------------------------------------------------------
# Weak-network profiles. Every value is injected on the egress qdisc of every
# veth endpoint, so both directions of every hop are affected.
# ---------------------------------------------------------------------------
bench_netem_spec() {
    case "$1" in
        clean) echo "" ;;
        latency) echo "delay 60ms" ;;
        jitter) echo "delay 40ms 20ms distribution normal" ;;
        loss) echo "loss 2%" ;;
        heavy-loss) echo "loss 8%" ;;
        slow) echo "rate 10mbit" ;;
        congested) echo "delay 30ms 10ms loss 1% rate 20mbit" ;;
        reorder) echo "delay 20ms reorder 5% 50%" ;;
        mobile) echo "delay 80ms 30ms loss 3% rate 8mbit duplicate 0.5%" ;;
        *) bench_die "unknown weak-network profile: $1" ;;
    esac
}

bench_list_profiles() {
    echo "clean latency jitter loss heavy-loss slow congested reorder mobile"
}

bench_apply_netem() {
    local spec entry ns dev
    spec=$(bench_netem_spec "$1")
    for entry in "${BENCH_VETH_DEVS[@]}"; do
        ns=${entry%%:*}
        dev=${entry##*:}
        ip netns exec "$ns" tc qdisc del dev "$dev" root 2>/dev/null || true
        if [[ -n "$spec" ]]; then
            # shellcheck disable=SC2086
            ip netns exec "$ns" tc qdisc add dev "$dev" root netem $spec
        fi
    done
    bench_log "netem[$1]: ${spec:-<none>} on ${#BENCH_VETH_DEVS[@]} veth endpoints"
}

# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------
bench_setup_topology() {
    BENCH_MODE=$1
    case "$BENCH_MODE" in
        direct) BENCH_NODES=(a b) ;;
        relay) BENCH_NODES=(a b c) ;;
        *) bench_die "unknown mode: $BENCH_MODE" ;;
    esac
    BENCH_VETH_DEVS=()
    BENCH_PIDS=()
    BENCH_TICKET=""
    BENCH_SERVER_IP6=""

    # Only clear per-run state; results live under $BENCH_OUT and must
    # survive when the harness restarts the topology for the next mode.
    rm -rf "$BENCH_STATE_ROOT" "$BENCH_LOG_ROOT"
    mkdir -p "$BENCH_STATE_ROOT" "$BENCH_LOG_ROOT" "$BENCH_OUT"

    local node
    for node in "${BENCH_NODES[@]}"; do
        local ns
        ns=$(ns_of "$node")
        ip netns del "$ns" 2>/dev/null || true
        ip netns add "$ns"
        ip netns exec "$ns" ip link set lo up
        mkdir -p "$BENCH_STATE_ROOT/$node"
    done

    # Linear chain: a--b (direct and relay), b--c (relay only).
    local pairs=("a:b")
    if [[ "$BENCH_MODE" == relay ]]; then
        pairs+=("b:c")
    fi

    local idx=0 pair left right vl vr ip_l ip_r
    for pair in "${pairs[@]}"; do
        idx=$((idx + 1))
        left=${pair%%:*}
        right=${pair##*:}
        vl="veth${idx}l"
        vr="veth${idx}r"
        ip_l="172.20.${idx}.1"
        ip_r="172.20.${idx}.2"

        ip link add "$vl" type veth peer name "$vr"
        ip link set "$vl" netns "$(ns_of "$left")"
        ip link set "$vr" netns "$(ns_of "$right")"
        ip netns exec "$(ns_of "$left")" ip link set "$vl" mtu "$BENCH_MTU" up
        ip netns exec "$(ns_of "$right")" ip link set "$vr" mtu "$BENCH_MTU" up
        ip netns exec "$(ns_of "$left")" ip addr add "$ip_l/30" dev "$vl"
        ip netns exec "$(ns_of "$right")" ip addr add "$ip_r/30" dev "$vr"

        BENCH_VETH_DEVS+=("$(ns_of "$left"):$vl" "$(ns_of "$right"):$vr")
    done
    bench_log "topology[$BENCH_MODE]: ${BENCH_NODES[*]} over ${#pairs[@]} veth hop(s)"
}

bench_cleanup() {
    local pid
    for pid in "${BENCH_PIDS[@]:-}"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    # `ip netns exec` forks, so the recorded PID belongs to `ip`, not to the
    # node process. Enumerate the namespace itself to reap every leftover.
    local node ns p
    for node in a b c; do
        ns=$(ns_of "$node")
        for p in $(ip netns pids "$ns" 2>/dev/null || true); do
            kill "$p" 2>/dev/null || true
        done
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap bench_cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------
bench_start_nodes() {
    local relay_limit=$1 ipv6=$2
    BENCH_IPV6=$ipv6
    local creator
    creator=$(bench_creator_node)

    # --no-relay is mandatory for the linear topology: a public relay would
    # let a and c connect directly and bypass the middle node entirely.
    #
    # mDNS MUST stay enabled. The join ticket only carries the creator's
    # direct addresses, so every other peer connection (mesh reconnects and
    # gossip dials) has to resolve a bare EndpointId via address lookup.
    # presets::N0DisableRelay still installs pkarr/DNS lookups, but those
    # cannot reach dns.iroh.link from an isolated netns (no DNS, no default
    # route). mDNS over the veth link is the ONLY usable lookup here.
    # iroh merges lookup services concurrently (AddressLookupStream), so the
    # timing-out DNS lookups do not block successful mDNS results.
    local common=(--no-relay --mtu "$BENCH_MTU" --secret "$BENCH_SECRET"
        --relay-limit-kib "$relay_limit"
        --metrics-addr "127.0.0.1:$BENCH_METRICS_PORT")
    if [[ "$BENCH_MODE" == relay ]]; then
        common+=(--topology partial --mesh-links 2)
    else
        common+=(--topology full)
    fi

    local creator_args=("${common[@]}" --subnet "$BENCH_V4_NET")
    if [[ "$ipv6" != "1" ]]; then
        creator_args+=(--no-ipv6)
    fi

    ip netns exec "$(ns_of "$creator")" \
        env XDG_STATE_HOME="$BENCH_STATE_ROOT/$creator" RUST_LOG=info \
        "$BENCH_BINARY" create --dev "tap-$creator" "${creator_args[@]}" \
        >"$BENCH_LOG_ROOT/$creator.log" 2>&1 &
    BENCH_PIDS+=("$!")

    # The creator writes ticket.txt right after its banner; polling `show`
    # is cleaner than scraping stdout of a long-running process.
    local ticket="" i
    for ((i = 0; i < 60; i++)); do
        ticket=$(env XDG_STATE_HOME="$BENCH_STATE_ROOT/$creator" "$BENCH_BINARY" show 2>/dev/null || true)
        if [[ "$ticket" == irohlan1_* ]]; then
            break
        fi
        ticket=""
        sleep 1
    done
    [[ -n "$ticket" ]] || bench_die "creator ($creator) did not publish a join ticket; see $BENCH_LOG_ROOT/$creator.log"
    BENCH_TICKET=$ticket

    local node
    for node in "${BENCH_NODES[@]}"; do
        if [[ "$node" == "$creator" ]]; then
            continue
        fi
        # Pin the virtual IPv4 so the harness knows every address up front.
        # The creator derives the matching IPv6 from the same host index.
        ip netns exec "$(ns_of "$node")" \
            env XDG_STATE_HOME="$BENCH_STATE_ROOT/$node" RUST_LOG=info \
            "$BENCH_BINARY" join "$BENCH_TICKET" --ip "$(vip_of "$node")" \
            --dev "tap-$node" "${common[@]}" \
            >"$BENCH_LOG_ROOT/$node.log" 2>&1 &
        BENCH_PIDS+=("$!")
    done
    bench_log "nodes started (creator=$creator, ticket ${#BENCH_TICKET} chars, relay cap ${relay_limit} KiB/s, ipv6=$ipv6)"
}

# Read the assigned IPv6 address from a node's status.json. The ULA prefix is
# derived from net_id at runtime, so it cannot be hardcoded like the v4 plan.
bench_resolve_ip6() {
    local node=$1 path i val
    path="$(state_of "$node")/status.json"
    for ((i = 0; i < 15; i++)); do
        val=$(python3 - "$path" <<'PY' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        print((json.load(f).get("ip6") or "").strip())
except Exception:
    print("")
PY
        )
        if [[ -n "$val" ]]; then
            echo "$val"
            return 0
        fi
        sleep 1
    done
    return 1
}

# Dump enough state to explain WHY the overlay never came up. The full node
# logs only live in $BENCH_LOG_ROOT, which the runner deletes on exit, so the
# harness also copies them into the results tree (see bench_collect_failure).
bench_dump_diagnostics() {
    local server=$1 ip=$2 status=$3 node ns
    bench_log "status file: $status ($([[ -f "$status" ]] && echo present || echo MISSING))"
    for node in "${BENCH_NODES[@]}"; do
        ns=$(ns_of "$node")
        bench_log "--- $node: interfaces / addresses ---"
        ip netns exec "$ns" ip -brief addr show 2>&1 | sed 's/^/[bench]   /' >&2 || true
        bench_log "--- $node: multicast groups ---"
        ip netns exec "$ns" ip maddr show 2>&1 | sed 's/^/[bench]   /' >&2 || true
        bench_log "--- $node: node log tail ---"
        tail -n 40 "$BENCH_LOG_ROOT/$node.log" >&2 || true
    done
    bench_log "--- final ping attempt (a -> $ip) ---"
    ip netns exec "$(ns_of a)" ping -c 3 -W 2 "$ip" 2>&1 | tail -n 10 >&2 || true
}

bench_collect_failure() {
    local out=$1 node
    mkdir -p "$out"
    for node in "${BENCH_NODES[@]}"; do
        cp "$BENCH_LOG_ROOT/$node.log" "$out/log-$node.txt" 2>/dev/null || true
        cp "$(state_of "$node")/status.json" "$out/status-$node.json" 2>/dev/null || true
        cp "$(state_of "$node")/network.json" "$out/network-$node.json" 2>/dev/null || true
    done
}

bench_wait_ready() {
    local server ip status i
    server=$(bench_server_node)
    ip=$(vip_of "$server")
    status="$(state_of "$server")/status.json"
    for ((i = 0; i < BENCH_READY_TIMEOUT; i++)); do
        # Readiness is a data-plane property: one successful ping is enough.
        # Do NOT gate it on status.json existing -- a wrong state path would
        # otherwise look exactly like a broken overlay for the whole timeout.
        if ip netns exec "$(ns_of a)" ping -c 1 -W 2 "$ip" >/dev/null 2>&1; then
            bench_log "overlay ready after ${i}s (a -> $server @ $ip)"
            break
        fi
        if ((i == BENCH_READY_TIMEOUT - 1)); then
            bench_log "overlay did NOT become ready after ${BENCH_READY_TIMEOUT} polls"
            bench_dump_diagnostics "$server" "$ip" "$status"
            return 1
        fi
        sleep 1
    done

    if [[ "$BENCH_IPV6" == "1" ]]; then
        BENCH_SERVER_IP6=$(bench_resolve_ip6 "$server") || true
        if [[ -n "$BENCH_SERVER_IP6" ]]; then
            bench_log "server IPv6: $BENCH_SERVER_IP6"
        else
            echo "ipv6 address not published in status.json" >>"$BENCH_LOG_ROOT/ipv6.err"
            bench_log "WARNING: no IPv6 address in $status; v6 probes will be skipped"
        fi
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------
bench_run_iperf_server() {
    local pidfile=$1 ip
    ip=$(vip_of "$(bench_server_node)")
    ip netns exec "$(ns_of "$(bench_server_node)")" iperf3 -s -B "$ip" -J --one-off \
        >"$pidfile.json" 2>"$pidfile.err" &
    echo "$!" >"$pidfile.pid"
    sleep 1
}

bench_stop_iperf_server() {
    local pidfile=$1 pid
    [[ -f "$pidfile.pid" ]] || return 0
    pid=$(cat "$pidfile.pid")
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$pidfile.pid"
}

bench_measure() {
    local out=$1 duration=$2 parallel=$3 udp_rate=$4 relay_limit=$5
    local server ip_a ip_s
    server=$(bench_server_node)
    ip_s=$(vip_of "$server")
    ip_a=$(vip_of a)
    local ns_a
    ns_a=$(ns_of a)
    mkdir -p "$out"

    # TCP goodput + retransmits.
    bench_run_iperf_server "$out/tcp-server"
    if ! ip netns exec "$ns_a" timeout "$((duration + 30))" iperf3 \
        -c "$ip_s" -B "$ip_a" -t "$duration" -P "$parallel" -J \
        >"$out/tcp.json" 2>"$out/tcp.err"; then
        echo "tcp iperf3 failed" >>"$out/errors.txt"
    fi
    bench_stop_iperf_server "$out/tcp-server"

    # UDP goodput, loss and jitter.
    bench_run_iperf_server "$out/udp-server"
    if ! ip netns exec "$ns_a" timeout "$((duration + 30))" iperf3 \
        -c "$ip_s" -B "$ip_a" -u -b "$udp_rate" -t "$duration" -J \
        >"$out/udp.json" 2>"$out/udp.err"; then
        echo "udp iperf3 failed" >>"$out/errors.txt"
    fi
    bench_stop_iperf_server "$out/udp-server"

    # Idle overlay RTT (through the real TAP path).
    if ! ip netns exec "$ns_a" ping -c "$BENCH_PING_COUNT" -i 0.2 -W 2 "$ip_s" \
        >"$out/ping.txt" 2>&1; then
        echo "ping failed" >>"$out/errors.txt"
    fi

    # Dual-stack data plane: NDP + IPv6 forwarding across the same QUIC
    # underlay, so netem affects it exactly like the IPv4 probes.
    if [[ "$BENCH_IPV6" == "1" && -n "$BENCH_SERVER_IP6" ]]; then
        if ! ip netns exec "$ns_a" ping -6 -c "$BENCH_PING_COUNT" -i 0.2 -W 2 \
            "$BENCH_SERVER_IP6" >"$out/ping6.txt" 2>&1; then
            echo "ping -6 failed" >>"$out/errors.txt"
        fi
    fi

    # Flow-queueing fairness: a bulk elephant flow plus a sparse ping stream,
    # only meaningful when a relay node is actually rate-limiting forwarding.
    if [[ "$BENCH_MODE" == relay && "$relay_limit" -gt 0 ]]; then
        bench_run_iperf_server "$out/elephant-server"
        ip netns exec "$ns_a" timeout "$((duration + 20))" iperf3 \
            -c "$ip_s" -B "$ip_a" -t "$duration" -P 4 -J \
            >"$out/elephant.json" 2>"$out/elephant.err" &
        local elephant=$!
        sleep 2
        if ! ip netns exec "$ns_a" ping -c "$BENCH_PING_COUNT" -i 0.2 -W 2 "$ip_s" \
            >"$out/ping-under-load.txt" 2>&1; then
            echo "ping-under-load failed" >>"$out/errors.txt"
        fi
        wait "$elephant" 2>/dev/null || true
        bench_stop_iperf_server "$out/elephant-server"
    fi
}

bench_snapshot_before() {
    local out=$1 node s
    for node in "${BENCH_NODES[@]}"; do
        s=$(state_of "$node")
        cp "$s/status.json" "$out/before-$node.json" 2>/dev/null || true
    done
}

bench_settle() {
    bench_log "waiting ${BENCH_SETTLE_SECS}s for the status writer to flush"
    sleep "$BENCH_SETTLE_SECS"
}

bench_collect() {
    local out=$1 node s ns
    for node in "${BENCH_NODES[@]}"; do
        s=$(state_of "$node")
        ns=$(ns_of "$node")
        cp "$s/status.json" "$out/status-$node.json" 2>/dev/null || true
        cp "$s/metrics.prom" "$out/metrics-$node.prom" 2>/dev/null || true
        cp "$s/relay-ledger.json" "$out/ledger-$node.json" 2>/dev/null || true
        cp "$BENCH_LOG_ROOT/$node.log" "$out/log-$node.txt" 2>/dev/null || true

        # Exercise the optional loopback HTTP endpoint, not just metrics.prom.
        # `ip netns exec` gives each node its own loopback, so port 9090 does
        # not collide across nodes even though every node binds the same port.
        if ! ip netns exec "$ns" python3 -c '
import sys, urllib.request
url = "http://127.0.0.1:" + sys.argv[1] + "/metrics"
with urllib.request.urlopen(url, timeout=3) as r:
    sys.stdout.write(r.read().decode("utf-8", "replace"))
' "$BENCH_METRICS_PORT" >"$out/http-metrics-$node.prom" 2>"$out/http-metrics-$node.err"; then
            echo "metrics endpoint of node $node did not respond" >>"$out/metrics-errors.txt"
        fi
    done
}

bench_write_meta() {
    local out=$1 mode=$2 profile=$3 duration=$4 parallel=$5 udp_rate=$6 relay_limit=$7
    python3 - "$out/meta.json" "$mode" "$profile" "$duration" "$parallel" \
        "$udp_rate" "$relay_limit" "$(bench_netem_spec "$profile")" \
        "$BENCH_IPV6" "$BENCH_MTU" <<'PY'
import json, sys
(path, mode, profile, duration, parallel, udp_rate, relay_limit,
 netem, ipv6, mtu) = sys.argv[1:]
with open(path, "w", encoding="utf-8") as f:
    json.dump({
        "mode": mode,
        "profile": profile,
        "duration_s": int(duration),
        "parallel": int(parallel),
        "udp_rate": udp_rate,
        "relay_limit_kib": int(relay_limit),
        "netem": netem,
        "ipv6": ipv6 == "1",
        "mtu": int(mtu),
    }, f, indent=2)
PY
}
