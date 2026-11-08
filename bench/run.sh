#!/usr/bin/env bash
# irohlan benchmark harness: baseline + weak-network profiles.
#
#   sudo ./bench/run.sh --binary ./target/release/irohlan
#   sudo ./bench/run.sh --binary ./target/release/irohlan --mode relay \
#       --profiles clean,loss,congested,mobile --relay-limit-kib 256 \
#       --out ./bench-results
#
# Requires: root, /dev/net/tun, iproute2 (ip + tc), iperf3, iputils-ping,
# python3, coreutils. Runs entirely on one Linux host using network
# namespaces; no public relay or second machine is needed.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

MODE_ARG="both"
PROFILES_ARG="clean,latency,loss,congested,mobile"
DURATION=10
PARALLEL=4
UDP_RATE="50M"
RELAY_LIMIT=0
IPV6=0
OUTPUT=""

usage() {
    cat <<'EOF'
Usage: sudo ./bench/run.sh --binary PATH [options]

  --binary PATH          path to the irohlan binary (required)
  --mode MODE            direct | relay | both            (default: both)
  --profiles LIST        comma separated, or "all"       (default: 5 profiles)
  --duration N           seconds per iperf3 run          (default: 10)
  --parallel N           TCP streams                     (default: 4)
  --udp-rate RATE        iperf3 UDP target rate          (default: 50M)
  --relay-limit-kib N    relay cap; >0 enables FQ/CoDel  (default: 0 = off)
  --settle N             seconds to wait before collecting status (default: 6)
  --out DIR              report directory                (default: /tmp/irohlan-bench/results)
  --ipv6                 keep dual-stack and add IPv6 ping probes
  --list-profiles        print the available weak-network profiles
  -h, --help             show this help

Profiles are applied with `tc netem` on every veth hop, i.e. on the QUIC
underlay, not on the emulated TAP frames. Environment overrides:
BENCH_ROOT, BENCH_MTU, BENCH_READY_TIMEOUT, BENCH_PING_COUNT.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BENCH_BINARY=$2; shift 2 ;;
        --mode) MODE_ARG=$2; shift 2 ;;
        --profiles) PROFILES_ARG=$2; shift 2 ;;
        --duration) DURATION=$2; shift 2 ;;
        --parallel) PARALLEL=$2; shift 2 ;;
        --udp-rate) UDP_RATE=$2; shift 2 ;;
        --relay-limit-kib) RELAY_LIMIT=$2; shift 2 ;;
        --settle) BENCH_SETTLE_SECS=$2; shift 2 ;;
        --out) OUTPUT=$2; shift 2 ;;
        --ipv6) IPV6=1; shift ;;
        --list-profiles) bench_list_profiles; exit 0 ;;
        -h | --help) usage; exit 0 ;;
        *) bench_die "unknown argument: $1 (try --help)" ;;
    esac
done

[[ "$MODE_ARG" == direct || "$MODE_ARG" == relay || "$MODE_ARG" == both ]] \
    || bench_die "--mode must be direct, relay or both"
[[ "$DURATION" =~ ^[0-9]+$ && "$DURATION" -gt 0 ]] || bench_die "--duration must be a positive integer"
[[ "$PARALLEL" =~ ^[0-9]+$ && "$PARALLEL" -gt 0 ]] || bench_die "--parallel must be a positive integer"
[[ "$RELAY_LIMIT" =~ ^[0-9]+$ ]] || bench_die "--relay-limit-kib must be a non-negative integer"
[[ "$BENCH_SETTLE_SECS" =~ ^[0-9]+$ ]] || bench_die "--settle must be a non-negative integer"

if [[ -n "$OUTPUT" ]]; then
    export BENCH_OUT=$OUTPUT
fi
mkdir -p "$BENCH_OUT"
bench_require_env

if [[ "$PROFILES_ARG" == all ]]; then
    read -r -a PROFILES <<<"$(bench_list_profiles)"
else
    IFS=',' read -r -a PROFILES <<<"$PROFILES_ARG"
fi
[[ ${#PROFILES[@]} -gt 0 ]] || bench_die "no profiles selected"
for p in "${PROFILES[@]}"; do
    bench_netem_spec "$p" >/dev/null # validates the name
done

if [[ "$MODE_ARG" == both ]]; then
    MODES=(direct relay)
else
    MODES=("$MODE_ARG")
fi

bench_log "binary=$BENCH_BINARY modes=${MODES[*]} profiles=${PROFILES[*]}"
bench_log "duration=${DURATION}s parallel=$PARALLEL udp=$UDP_RATE relay_limit=${RELAY_LIMIT}KiB/s ipv6=$IPV6"
bench_log "mtu=$BENCH_MTU settle=${BENCH_SETTLE_SECS}s output=$BENCH_OUT"

FAILED_MODES=()
for mode in "${MODES[@]}"; do
    bench_cleanup
    sleep 1
    bench_setup_topology "$mode"
    bench_start_nodes "$RELAY_LIMIT" "$IPV6"
    if ! bench_wait_ready; then
        bench_log "SKIPPING mode '$mode': overlay never became ready"
        FAILED_MODES+=("$mode")
        continue
    fi

    for profile in "${PROFILES[@]}"; do
        local_out="$BENCH_OUT/$mode/$profile"
        mkdir -p "$local_out"
        bench_log "--- $mode / $profile ---"
        bench_apply_netem "$profile"
        # Give QUIC's RTT estimator, the congestion controller and the LSA
        # smoother a moment to react to the new netem profile.
        sleep 2
        bench_snapshot_before "$local_out"
        bench_measure "$local_out" "$DURATION" "$PARALLEL" "$UDP_RATE" "$RELAY_LIMIT"
        bench_settle
        bench_collect "$local_out"
        bench_write_meta "$local_out" "$mode" "$profile" "$DURATION" \
            "$PARALLEL" "$UDP_RATE" "$RELAY_LIMIT"
    done
done

python3 - "$BENCH_OUT/failed-modes.json" "${FAILED_MODES[@]:-}" <<'PY'
import json, sys
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump([m for m in sys.argv[2:] if m], f, indent=2)
PY

bench_log "generating report"
python3 "$SCRIPT_DIR/report.py" --root "$BENCH_OUT" >"$BENCH_OUT/summary.json"
python3 "$SCRIPT_DIR/report.py" --root "$BENCH_OUT" --markdown >"$BENCH_OUT/summary.md"

if [[ ${#FAILED_MODES[@]} -gt 0 ]]; then
    bench_log "modes without a working overlay: ${FAILED_MODES[*]} (see $BENCH_ROOT/logs)"
fi
bench_log "done: $BENCH_OUT/summary.md"
