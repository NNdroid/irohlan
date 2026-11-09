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
#
# The nodes MUST use the flood bus, not gossip. Gossip dials bare EndpointIds,
# which needs a working address lookup; an isolated netns has no DNS, no
# default route and no usable mDNS, so gossip broadcasts (ARP/NDP frames and
# membership announcements) go missing and the member table expires. Flood
# reuses the mesh connections that were already established from the ticket's
# direct addresses, so it needs no address lookup at all.

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
# A single lucky echo reply is not enough: the first CI run had a working
# overlay for one ping and then lost it. Require consecutive successes.
BENCH_READY_STREAK="${BENCH_READY_STREAK:-3}"
# Per-profile liveness check. A relay link that dropped under the previous
# profile is redialed by the node itself, but a silently blackholed QUIC path
# is only detected when the 30s idle timeout fires, and a two-hop topology can
# lose both hops in sequence. Measured worst case: ~90s from the first drop
# until the overlay answers again (30s detect + redial, twice, plus re-ARP).
# 40 attempts x (<=2s ping + 2s sleep) ~= 160s covers that with margin.
BENCH_OVERLAY_RETRIES="${BENCH_OVERLAY_RETRIES:-40}"
BENCH_OVERLAY_RETRY_INTERVAL="${BENCH_OVERLAY_RETRY_INTERVAL:-2}"
BENCH_PING_COUNT="${BENCH_PING_COUNT:-20}"
# status.json is written every 5s; wait for one more tick before collecting
# so the "after" snapshot includes the whole measurement window.
BENCH_SETTLE_SECS="${BENCH_SETTLE_SECS:-6}"
# Hard lifetime for every iperf3 server. An overloaded relay can drop the
# final control-channel exchange, leaving `--one-off` blocked in recv() with
# no server-side timeout at all. Without this ceiling the harness would hang
# in `wait` until the CI job timeout.
BENCH_IPERF_SERVER_SECS="${BENCH_IPERF_SERVER_SECS:-90}"
# Grace period on top of `-t duration` for the iperf3 client. On a heavily
# impaired underlay (e.g. `mobile`: 80ms+/-30ms delay, 3% loss, 8mbit on
# every veth endpoint) the test-start/stop control exchange can take many
# seconds; too small a value makes `timeout` kill a test that was working.
BENCH_IPERF_CLIENT_EXTRA="${BENCH_IPERF_CLIENT_EXTRA:-45}"

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

# Remove any netem left over from the previous profile. Callers use this
# before probing the overlay, otherwise a loss/reorder profile still in
# place could make a healthy overlay look broken.
bench_clear_netem() {
    local entry ns dev
    for entry in "${BENCH_VETH_DEVS[@]:-}"; do
        ns=${entry%%:*}
        dev=${entry##*:}
        ip netns exec "$ns" tc qdisc del dev "$dev" root 2>/dev/null || true
    done
}

bench_apply_netem() {
    local spec entry ns dev
    spec=$(bench_netem_spec "$1")
    bench_clear_netem
    for entry in "${BENCH_VETH_DEVS[@]}"; do
        ns=${entry%%:*}
        dev=${entry##*:}
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
# Node settings
# ---------------------------------------------------------------------------
# The CLI accepts nothing but `--config`, so every knob the harness needs
# travels in a per-node JSON file: device name, secret, MTU, relay cap,
# topology/bus, the pinned address and (creator only) the subnet.
bench_write_config() {
    local path=$1 role=$2 node=$3 relay_limit=$4 ipv6=$5
    mkdir -p "$(dirname "$path")"
    {
        printf '{\n'
        printf '  "dev": "tap-%s",\n' "$node"
        printf '  "secret": "%s",\n' "$BENCH_SECRET"
        printf '  "mtu": %s,\n' "$BENCH_MTU"
        # "no-relay" is mandatory for the linear topology: a public relay would
        # let a and c connect directly and bypass the middle node entirely.
        printf '  "no-relay": true,\n'
        # "bus": "flood" is equally mandatory. The join ticket only carries the
        # creator's direct addresses; iroh-gossip would have to dial every other
        # peer by bare EndpointId, which needs an address lookup. An isolated
        # netns has no DNS/default route and mDNS cannot join a multicast group
        # on a nonexistent default interface, so those dials time out. Gossip
        # then drops ARP/NDP broadcasts and the 20s membership announcements,
        # the 60s member TTL expires, and the L2 overlay goes dark even though
        # the QUIC mesh is still connected. Flood sends envelopes over the
        # already-established mesh links (with (origin, seq) dedup) and needs
        # no lookup service at all.
        #
        # mDNS is left enabled but is NOT on the critical path: its send errors
        # and the pkarr/DNS timeouts are expected noise in this topology.
        # Our own crate logs at debug level so mesh send failures, dropped frames
        # and bus delivery problems land in the collected node logs.
        printf '  "bus": "flood",\n'
        if [[ "$BENCH_MODE" == relay ]]; then
            # One link per node keeps the partial-mesh dialer idle: a and c each
            # already have the creator, so no bare-EndpointId dial is attempted.
            # Higher values would make a try (and fail) to dial c.
            printf '  "topology": "partial",\n'
            printf '  "mesh-links": 1,\n'
        else
            # Direct mode is a two-node network that the ticket already wires
            # up; full topology keeps the dialer out of the way.
            printf '  "topology": "full",\n'
        fi
        printf '  "relay-limit-kib": %s,\n' "$relay_limit"
        if [[ "$role" == create ]]; then
            printf '  "subnet": "%s",\n' "$BENCH_V4_NET"
            if [[ "$ipv6" != "1" ]]; then
                printf '  "no-ipv6": true,\n'
            fi
        else
            # Pin the virtual IPv4 so the harness knows every address up front.
            # The creator derives the matching IPv6 from the same host index.
            printf '  "ip": "%s",\n' "$(vip_of "$node")"
        fi
        printf '  "metrics-addr": "127.0.0.1:%s"\n' "$BENCH_METRICS_PORT"
        printf '}\n'
    } >"$path"
}

# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------
bench_start_nodes() {
    local relay_limit=$1 ipv6=$2
    BENCH_IPV6=$ipv6
    local creator
    creator=$(bench_creator_node)
    local cfgdir="$BENCH_STATE_ROOT/config"

    bench_write_config "$cfgdir/$creator.json" create "$creator" "$relay_limit" "$ipv6"

    ip netns exec "$(ns_of "$creator")" \
        env XDG_STATE_HOME="$BENCH_STATE_ROOT/$creator" RUST_LOG="info,irohlan=debug" \
        "$BENCH_BINARY" create --config "$cfgdir/$creator.json" \
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
        bench_write_config "$cfgdir/$node.json" join "$node" "$relay_limit" "$ipv6"
        ip netns exec "$(ns_of "$node")" \
            env XDG_STATE_HOME="$BENCH_STATE_ROOT/$node" RUST_LOG="info,irohlan=debug" \
            "$BENCH_BINARY" join "$BENCH_TICKET" --config "$cfgdir/$node.json" \
            >"$BENCH_LOG_ROOT/$node.log" 2>&1 &
        BENCH_PIDS+=("$!")
    done
    bench_log "nodes started (creator=$creator, ticket ${#BENCH_TICKET} chars, relay cap ${relay_limit} KiB/s, ipv6=$ipv6, config=$cfgdir)"
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
        bench_log "--- $node: link flags (is the TAP UP?) ---"
        ip netns exec "$ns" ip -brief link show 2>&1 | sed 's/^/[bench]   /' >&2 || true
        bench_log "--- $node: TAP counters (TX/RX frames) ---"
        ip netns exec "$ns" ip -s link show "tap-$node" 2>&1 \
            | sed 's/^/[bench]   /' >&2 || true
        bench_log "--- $node: neighbours (ARP/NDP state) ---"
        ip netns exec "$ns" ip neigh show 2>&1 | sed 's/^/[bench]   /' >&2 || true
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

# One data-plane probe from a to the server's virtual address.
bench_ping_once() {
    ip netns exec "$(ns_of a)" ping -c 1 -W 2 "$1" >/dev/null 2>&1
}

bench_wait_ready() {
    local server ip status i streak=0
    server=$(bench_server_node)
    ip=$(vip_of "$server")
    status="$(state_of "$server")/status.json"
    for ((i = 0; i < BENCH_READY_TIMEOUT; i++)); do
        # Readiness is a data-plane property. Do NOT gate it on status.json
        # existing -- a wrong state path would otherwise look exactly like a
        # broken overlay for the whole timeout. A single echo reply is too
        # weak (we have seen the overlay die right after one), so require a
        # streak of consecutive replies.
        if bench_ping_once "$ip"; then
            streak=$((streak + 1))
            if ((streak >= BENCH_READY_STREAK)); then
                bench_log "overlay ready after ${i}s (a -> $server @ $ip, ${streak} consecutive pings)"
                break
            fi
        else
            streak=0
        fi
        if ((i == BENCH_READY_TIMEOUT - 1)); then
            bench_log "overlay did NOT become ready after ${BENCH_READY_TIMEOUT} polls (streak=$streak/${BENCH_READY_STREAK})"
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

# Per-profile liveness check, run after the previous profile's qdisc has been
# cleared. A dropped QUIC link is redialed by the node that initiated it, and
# the retry schedule backs off up to 30s, so a single failed ping proves
# nothing. Retry for BENCH_OVERLAY_RETRIES attempts before giving up; the
# semantics stay the same -- a mode is only failed when the overlay is still
# unreachable after every attempt.
bench_check_overlay() {
    local ip attempt
    ip=$(vip_of "$(bench_server_node)")
    for ((attempt = 1; attempt <= BENCH_OVERLAY_RETRIES; attempt++)); do
        if bench_ping_once "$ip"; then
            if ((attempt > 1)); then
                bench_log "overlay recovered after $((attempt - 1)) failed probe(s) (~$(((attempt - 1) * BENCH_OVERLAY_RETRY_INTERVAL))s)"
            fi
            return 0
        fi
        if ((attempt < BENCH_OVERLAY_RETRIES)); then
            bench_log "overlay probe $attempt/$BENCH_OVERLAY_RETRIES failed; waiting ${BENCH_OVERLAY_RETRY_INTERVAL}s for the mesh to redial"
            sleep "$BENCH_OVERLAY_RETRY_INTERVAL"
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------
# Kill every iperf3 left inside a namespace. `ip netns exec` forks, so a PID
# recorded with $! may belong to the `ip` parent while iperf3 is a grandchild
# that keeps port 5201 occupied after the parent is gone. The cmdline match
# also catches the `timeout ... iperf3` wrapper.
bench_kill_iperf_in_ns() {
    local ns=$1 p cmd="" comm=""
    for p in $(ip netns pids "$ns" 2>/dev/null || true); do
        cmd=""
        comm=""
        # Guard the redirect itself: a missing /proc entry would otherwise
        # print a shell error (2>/dev/null on `tr` does not cover it).
        if [[ -r "/proc/$p/cmdline" ]]; then
            cmd=$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null || true)
        elif [[ -r "/proc/$p/comm" ]]; then
            read -r comm <"/proc/$p/comm" || comm=""
        fi
        if [[ "$cmd" == *iperf3* || "$comm" == *iperf3* ]]; then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
}

# Wait for a background PID but never forever. iperf3 servers can hang when
# the relay queue drops their control stream, and a bare `wait` then stalls
# the whole benchmark until the job timeout. A zombie still answers `kill -0`,
# so /proc state is checked too and the child is always reaped.
bench_wait_bounded() {
    local pid=$1 secs=${2:-5} i state=""
    for ((i = 0; i < secs * 5; i++)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        state=""
        if [[ -r "/proc/$pid/stat" ]]; then
            read -r _ _ state _ <"/proc/$pid/stat" || true
        fi
        if [[ "$state" == Z* ]]; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        sleep 0.2
    done
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
}

bench_run_iperf_server() {
    local pidfile=$1 ip ns
    ns=$(ns_of "$(bench_server_node)")
    ip=$(vip_of "$(bench_server_node)")
    # A previous test may have left a server behind; make sure the port is
    # free before binding it again.
    bench_kill_iperf_in_ns "$ns"
    # `timeout` is the last line of defence: `--one-off` has no server-side
    # deadline, and a stalled control connection must not outlive the test.
    ip netns exec "$ns" timeout -k 5 "$BENCH_IPERF_SERVER_SECS" \
        iperf3 -s -B "$ip" -J --one-off \
        >"$pidfile.json" 2>"$pidfile.err" &
    echo "$!" >"$pidfile.pid"
    sleep 1
}

bench_stop_iperf_server() {
    local pidfile=$1 pid ns
    [[ -f "$pidfile.pid" ]] || return 0
    pid=$(cat "$pidfile.pid")
    ns=$(ns_of "$(bench_server_node)")
    # Kill the real iperf3 FIRST. If we only signal the recorded `ip` wrapper,
    # its child can stay alive and keep the wrapper (and `wait`) blocked.
    bench_kill_iperf_in_ns "$ns"
    kill "$pid" 2>/dev/null || true
    bench_wait_bounded "$pid" 5 || true
    # Second pass for grandchildren that were forked after the first scan.
    bench_kill_iperf_in_ns "$ns"
    rm -f "$pidfile.pid"
}

# One iperf3 measurement against a fresh `--one-off` server. An impaired
# underlay can kill the control channel before the test even starts, so a
# single transient failure is retried once with a brand-new server.
# $1 = output prefix, $2 = client netns, $3 = timeout seconds, $4.. = args
bench_iperf_probe() {
    local prefix=$1 ns=$2 limit=$3
    shift 3
    local attempt rc
    for attempt in 1 2; do
        bench_run_iperf_server "$prefix-server"
        rc=0
        ip netns exec "$ns" timeout -k 5 "$limit" iperf3 "$@" \
            >"$prefix.json" 2>"$prefix.err" || rc=$?
        bench_stop_iperf_server "$prefix-server"
        if ((rc == 0)); then
            return 0
        fi
        # 124/137 means `timeout` fired. Retrying would only double the
        # deadline on an already-unresponsive link; report the loss instead.
        if ((rc == 124 || rc == 137)); then
            bench_log "$(basename "$prefix") iperf3 hit its ${limit}s deadline; not retrying"
            return 1
        fi
        if ((attempt == 1)); then
            bench_log "$(basename "$prefix") iperf3 failed once, retrying with a fresh server"
            sleep 1
        fi
    done
    return 1
}

bench_measure() {
    local out=$1 duration=$2 parallel=$3 udp_rate=$4 relay_limit=$5
    local server ip_a ip_s ns_a client_timeout
    server=$(bench_server_node)
    ip_s=$(vip_of "$server")
    ip_a=$(vip_of a)
    ns_a=$(ns_of a)
    client_timeout=$((duration + BENCH_IPERF_CLIENT_EXTRA))
    mkdir -p "$out"

    # TCP goodput + retransmits.
    if ! bench_iperf_probe "$out/tcp" "$ns_a" "$client_timeout" \
        -c "$ip_s" -B "$ip_a" -t "$duration" -P "$parallel" -J; then
        echo "tcp iperf3 failed" >>"$out/errors.txt"
    fi

    # UDP goodput, loss and jitter.
    if ! bench_iperf_probe "$out/udp" "$ns_a" "$client_timeout" \
        -c "$ip_s" -B "$ip_a" -u -b "$udp_rate" -t "$duration" -J; then
        echo "udp iperf3 failed" >>"$out/errors.txt"
    fi

    # Idle overlay RTT (through the real TAP path).
    if ! ip netns exec "$ns_a" ping -c "$BENCH_PING_COUNT" -i 0.2 -W 2 "$ip_s" \
        >"$out/ping.txt" 2>&1; then
        echo "ping failed" >>"$out/errors.txt"
    fi

    # Dual-stack data plane: NDP + IPv6 forwarding across the same QUIC
    # underlay, so netem affects it exactly like the IPv4 probes. NDP needs a
    # longer reply window on impaired links; retry once so a slow neighbour
    # discovery is not recorded as a broken IPv6 data plane.
    if [[ "$BENCH_IPV6" == "1" && -n "$BENCH_SERVER_IP6" ]]; then
        if ! ip netns exec "$ns_a" ping -6 -c "$BENCH_PING_COUNT" -i 0.2 -W 5 \
            "$BENCH_SERVER_IP6" >"$out/ping6.txt" 2>&1; then
            sleep 1
            if ! ip netns exec "$ns_a" ping -6 -c "$BENCH_PING_COUNT" -i 0.2 -W 5 \
                "$BENCH_SERVER_IP6" >"$out/ping6.txt" 2>&1; then
                echo "ping -6 failed" >>"$out/errors.txt"
            fi
        fi
    fi

    # Flow-queueing fairness: a bulk elephant flow plus a sparse ping stream,
    # only meaningful when a relay node is actually rate-limiting forwarding.
    if [[ "$BENCH_MODE" == relay && "$relay_limit" -gt 0 ]]; then
        bench_run_iperf_server "$out/elephant-server"
        ip netns exec "$ns_a" timeout -k 5 "$client_timeout" iperf3 \
            -c "$ip_s" -B "$ip_a" -t "$duration" -P 4 -J \
            >"$out/elephant.json" 2>"$out/elephant.err" &
        local elephant=$!
        sleep 2
        if ! ip netns exec "$ns_a" ping -c "$BENCH_PING_COUNT" -i 0.2 -W 2 "$ip_s" \
            >"$out/ping-under-load.txt" 2>&1; then
            echo "ping-under-load failed" >>"$out/errors.txt"
        fi
        bench_wait_bounded "$elephant" "$client_timeout" || true
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
