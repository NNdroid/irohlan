#!/usr/bin/env python3
"""Summarize one irohlan benchmark run into JSON or a Markdown table.

Reads the per-profile directories produced by run.sh and derives:
  * TCP/UDP goodput, UDP loss/jitter, TCP retransmits (iperf3 JSON)
  * idle and under-load RTT, plus IPv6 RTT in dual-stack runs (ping)
  * v5 link quality (rtt/loss/tx/bw) from status.json
  * cumulative relay deltas (frames relayed, limited, CoDel-dropped) from
    the before/after status snapshots
  * throughput degradation relative to the `clean` profile of the same mode
  * whether the optional loopback /metrics endpoint answered on each node
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path

PROFILE_ORDER = [
    "clean",
    "latency",
    "jitter",
    "loss",
    "heavy-loss",
    "slow",
    "congested",
    "reorder",
    "mobile",
]
MODE_ORDER = ["direct", "relay"]
# `clean` injects no impairment, so a failed iperf3/ping there is a harness or
# product regression. Under netem, lost measurements ARE the result we are
# trying to measure (an 8% loss + 8mbit mobile link is allowed to starve the
# iperf3 control channel or NDP); those go into warnings, not the CI gate.
BASELINE_PROFILES = frozenset({"clean"})

RTT_RE = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms")
LOSS_RE = re.compile(r"([\d.]+)%\s*packet loss")


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def iperf_sum(obj, kind):
    """Return (bits_per_second, retransmits, lost_percent, jitter_ms)."""
    if not obj:
        return (None, None, None, None)
    end = obj.get("end") or {}
    received = end.get("sum_received") or {}
    sent = end.get("sum_sent") or {}
    total = end.get("sum") or {}
    bits = received.get("bits_per_second")
    if bits is None:
        bits = total.get("bits_per_second")
    retrans = sent.get("retransmits")
    lost = total.get("lost_percent")
    jitter = total.get("jitter_ms")
    if kind == "tcp" and lost is None:
        lost = 0.0
    return (bits, retrans, lost, jitter)


def parse_ping(path):
    text = read_text(path)
    avg = None
    loss = None
    m = RTT_RE.search(text)
    if m:
        avg = float(m.group(2))
    m = LOSS_RE.search(text)
    if m:
        loss = float(m.group(1))
    return avg, loss


def relay_of(status):
    if not status:
        return {}
    return status.get("relay") or {}


CUMULATIVE = (
    "relayed_frames",
    "limited_frames",
    "codel_frames",
)


def delta(before, after, key):
    return max(0, (after.get(key, 0) or 0) - (before.get(key, 0) or 0))


def collect_dir(meta_path):
    d = meta_path.parent
    mode = d.parent.name
    profile = d.name
    meta = load_json(meta_path) or {}

    tcp, retrans, _, _ = iperf_sum(load_json(d / "tcp.json"), "tcp")
    udp, _, udp_loss, jitter = iperf_sum(load_json(d / "udp.json"), "udp")
    ping_avg, ping_loss = parse_ping(d / "ping.txt")
    ping_load_avg, ping_load_loss = parse_ping(d / "ping-under-load.txt")
    ping6_avg, ping6_loss = parse_ping(d / "ping6.txt")

    relayed = limited = codel = 0
    queued = active_flows = active_peers = 0
    link_rtts = []
    link_loss = []
    link_tx = []
    link_bw = []
    routes = 0
    for status_path in sorted(d.glob("status-*.json")):
        node = status_path.stem.replace("status-", "")
        after = load_json(status_path) or {}
        before = load_json(d / f"before-{node}.json") or {}
        rb, ra = relay_of(before), relay_of(after)
        relayed += delta(rb, ra, "relayed_frames")
        limited += delta(rb, ra, "limited_frames")
        codel += delta(rb, ra, "codel_frames")
        queued += ra.get("queued_frames", 0) or 0
        active_flows += ra.get("active_flows", 0) or 0
        active_peers += ra.get("active_peers", 0) or 0
        routes += len(after.get("routes") or [])
        for link in after.get("link_metrics") or []:
            link_rtts.append(link.get("rtt_ms", 0) or 0)
            link_loss.append(link.get("loss_permille", 0) or 0)
            link_tx.append(link.get("tx_kbps", 0) or 0)
            link_bw.append(link.get("bw_kbps", 0) or 0)

    metrics_ok = sum(
        1
        for p in sorted(d.glob("http-metrics-*.prom"))
        if "irohlan_up 1" in read_text(p)
    )
    errors = [e for e in read_text(d / "errors.txt").strip().splitlines() if e]
    return {
        "mode": mode,
        "profile": profile,
        "netem": meta.get("netem", "") or "(none)",
        "relay_limit_kib": meta.get("relay_limit_kib", 0),
        "ipv6": bool(meta.get("ipv6", False)),
        "mtu": meta.get("mtu"),
        "tcp_mbps": round(tcp / 1e6, 2) if tcp else None,
        "tcp_retransmits": retrans,
        "udp_mbps": round(udp / 1e6, 2) if udp else None,
        "udp_loss_pct": udp_loss,
        "udp_jitter_ms": jitter,
        "ping_avg_ms": ping_avg,
        "ping_loss_pct": ping_loss,
        "ping_under_load_ms": ping_load_avg,
        "ping_under_load_loss_pct": ping_load_loss,
        "ping6_ms": ping6_avg,
        "ping6_loss_pct": ping6_loss,
        "link_rtt_ms_avg": round(sum(link_rtts) / len(link_rtts), 1) if link_rtts else None,
        "link_loss_permille_max": max(link_loss) if link_loss else None,
        "link_tx_kbps_avg": round(sum(link_tx) / len(link_tx), 1) if link_tx else None,
        "link_bw_kbps_avg": round(sum(link_bw) / len(link_bw), 1) if link_bw else None,
        "routes": routes,
        "relay_frames_delta": relayed,
        "limited_frames_delta": limited,
        "codel_frames_delta": codel,
        "queued_frames": queued,
        "active_flows": active_flows,
        "active_peers": active_peers,
        "metrics_endpoints_ok": metrics_ok,
        "errors": errors,
    }


def analyze(root):
    metas = sorted(root.rglob("meta.json"))
    rows = [collect_dir(m) for m in metas]
    rows.sort(key=lambda r: (
        MODE_ORDER.index(r["mode"]) if r["mode"] in MODE_ORDER else 99,
        PROFILE_ORDER.index(r["profile"]) if r["profile"] in PROFILE_ORDER else 99,
    ))

    baselines = {}
    for r in rows:
        if r["profile"] == "clean" and r["tcp_mbps"]:
            baselines[r["mode"]] = r["tcp_mbps"]
    for r in rows:
        base = baselines.get(r["mode"])
        r["tcp_drop_pct"] = (
            round((base - r["tcp_mbps"]) / base * 100, 1)
            if base and r["tcp_mbps"] is not None
            else None
        )

    failed_modes = load_json(root / "failed-modes.json") or []
    warnings = []
    if not rows:
        warnings.append("No results found. Did any mode reach a ready overlay?")
    for m in failed_modes:
        warnings.append(
            f"mode '{m}' never produced a ready overlay; its profiles are "
            "missing (see the node logs in the results artifact)."
        )
    for mode in MODE_ORDER:
        mode_rows = [r for r in rows if r["mode"] == mode]
        if not mode_rows:
            continue
        if mode == "relay":
            total_relayed = sum(r["relay_frames_delta"] for r in mode_rows)
            if total_relayed == 0:
                warnings.append(
                    "relay mode produced no relayed frames: A and C may have "
                    "connected directly (check that \"no-relay\" is set in every node's config and "
                    "that the veth topology has no A-C route). FQ/CoDel "
                    "numbers for this mode are not meaningful."
                )
            total_codel = sum(r["codel_frames_delta"] for r in mode_rows)
            if any(r["relay_limit_kib"] > 0 for r in mode_rows) and total_codel == 0:
                warnings.append(
                    "A relay cap was configured but CoDel dropped nothing: "
                    "the cap may be above the achievable throughput, so the "
                    "queue never became standing."
                )
    for r in rows:
        for err in r["errors"]:
            if r["profile"] in BASELINE_PROFILES:
                warnings.append(f"[FATAL] {r['mode']}/{r['profile']}: {err}")
            else:
                warnings.append(
                    f"{r['mode']}/{r['profile']} (impaired profile, "
                    f"measurement lost): {err}"
                )

    metrics_failures = 0
    for p in root.rglob("metrics-errors.txt"):
        metrics_failures += len(
            [line for line in read_text(p).splitlines() if line.strip()]
        )
    if metrics_failures:
        warnings.append(
            f"{metrics_failures} loopback /metrics HTTP probe(s) failed; "
            "check the node logs and the metrics-addr setting."
        )
    if rows and all(r["metrics_endpoints_ok"] == 0 for r in rows):
        warnings.append(
            "No /metrics endpoint answered on any node (irohlan_up 1 was "
            "never observed)."
        )
    ipv6_rows = [r for r in rows if r["ipv6"]]
    if ipv6_rows and all(r["ping6_ms"] is None for r in ipv6_rows):
        warnings.append(
            "Dual-stack was requested but no IPv6 ping succeeded; verify "
            "NDP over the TAP and the derived ULA prefix."
        )

    return {
        "generated_at_unix": int(time.time()),
        "rows": rows,
        "failed_modes": failed_modes,
        "warnings": warnings,
    }


def fmt(value, suffix=""):
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:g}{suffix}"
    return f"{value}{suffix}"


def markdown(data):
    lines = []
    lines.append("# irohlan benchmark")
    lines.append("")
    lines.append(
        "Weak-network profiles are applied with `tc netem` on every veth hop "
        "(the QUIC underlay). `ΔTCP` is the **throughput drop** in percent "
        "relative to the `clean` profile of the same mode; higher is worse."
    )
    lines.append("")
    header = (
        "| mode | profile | netem | TCP Mbps | ΔTCP | UDP Mbps | "
        "UDP loss | ping ms | ping(load) | v6 ping ms | link RTT/loss‰ | "
        "relayed | limited | CoDel | flows |"
    )
    lines.append(header)
    lines.append("|" + "---|" * (header.count("|") - 1))
    for r in data["rows"]:
        link = (
            f"{fmt(r['link_rtt_ms_avg'])}/{fmt(r['link_loss_permille_max'])}"
            if r["link_rtt_ms_avg"] is not None
            else "-"
        )
        drop = fmt(r["tcp_drop_pct"], "%")
        lines.append(
            "| {mode} | {profile} | `{netem}` | {tcp} | {drop} | {udp} | {uloss} | "
            "{ping} | {pingload} | {ping6} | {link} | {relayed} | {limited} | "
            "{codel} | {flows} |".format(
                mode=r["mode"],
                profile=r["profile"],
                netem=r["netem"],
                tcp=fmt(r["tcp_mbps"]),
                drop=drop,
                udp=fmt(r["udp_mbps"]),
                uloss=fmt(r["udp_loss_pct"], "%"),
                ping=fmt(r["ping_avg_ms"]),
                pingload=fmt(r["ping_under_load_ms"]),
                ping6=fmt(r["ping6_ms"]),
                link=link,
                relayed=r["relay_frames_delta"],
                limited=r["limited_frames_delta"],
                codel=r["codel_frames_delta"],
                flows=r["active_flows"],
            )
        )
    lines.append("")
    lines.append("## Checks")
    lines.append("")
    if data["warnings"]:
        for w in data["warnings"]:
            lines.append(f"- ⚠ {w}")
    else:
        lines.append("- All measured profiles completed without errors.")
    lines.append("")
    lines.append(
        "> Only the `clean` baseline must complete without errors. Failures on "
        "`netem` profiles are measured degradation (warnings), not CI failures; "
        "a missing mode is always fatal."
    )
    lines.append("")
    lines.append(
        "> `relayed`, `limited` and `CoDel` are per-profile deltas summed over "
        "all nodes. In `direct` mode there is no relay hop, so they stay at 0 "
        "by design. `flows` is the instantaneous active-flow count at the end "
        "of the profile. `v6 ping ms` is empty unless `--ipv6` was used."
    )
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", required=True, help="directory containing <mode>/<profile>/ results")
    ap.add_argument("--markdown", action="store_true", help="emit Markdown instead of JSON")
    ap.add_argument(
        "--fail-on-error",
        action="store_true",
        help=(
            "exit 1 when a mode never became ready, no rows exist, or a "
            "clean (unimpaired) baseline measurement errored"
        ),
    )
    args = ap.parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print(f"no results directory: {root}", file=sys.stderr)
        return 1
    data = analyze(root)
    if args.markdown:
        sys.stdout.write(markdown(data))
    else:
        json.dump(data, sys.stdout, indent=2, sort_keys=False)
        sys.stdout.write("\n")
    baseline_errors = [
        r for r in data["rows"] if r["errors"] and r["profile"] in BASELINE_PROFILES
    ]
    fatal = bool(data["failed_modes"]) or not data["rows"] or baseline_errors
    if args.fail_on_error and fatal:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
