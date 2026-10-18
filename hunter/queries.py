"""Hypothesis query library.

Each hunt is a hypothesis an analyst states in words, encoded as a function
over the data. Every hunt returns a list of finding dicts:
    hunt        hypothesis name
    explanation why this matters
    evidence    concrete rows/counts backing the finding
    severity    informational | suspicious | likely-malicious
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime


def hunt_beaconing(netflow: list[dict], cv_threshold: float = 0.1,
                   min_flows: int = 20) -> list[dict]:
    """Hypothesis: something on the network talks to one destination at a
    mechanical, humanly-impossible regularity (C2 beacon).

    Beacon signal = many flows to one dst with low inter-arrival CV.
    """
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in netflow:
        groups[(r["src_ip"], r["dst_ip"], r["dst_port"])].append(r)

    findings = []
    import statistics
    for (src, dst, port), rows in groups.items():
        if len(rows) < min_flows:
            continue
        rows.sort(key=lambda r: r["ts"])
        gaps = [(b["ts"] - a["ts"]).total_seconds() for a, b in zip(rows, rows[1:])]
        mean_gap = statistics.fmean(gaps) if gaps else 0
        if mean_gap <= 0:
            continue
        cv = statistics.pstdev(gaps) / mean_gap
        if cv < cv_threshold:
            findings.append({
                "hunt": "beaconing",
                "explanation": (
                    f"{src} -> {dst}:{port} with {len(rows)} flows at "
                    f"{mean_gap:.0f}s average interval (CV {cv:.3f}). Organic "
                    "traffic has irregular timing; this rhythm suggests automation."
                ),
                "evidence": {
                    "src_ip": src, "dst_ip": dst, "dst_port": port,
                    "flows": len(rows), "mean_interval_s": round(mean_gap, 1),
                    "cv": round(cv, 4),
                },
                "severity": "likely-malicious",
            })
    return findings


def hunt_rare_ports(netflow: list[dict], max_flows: int = 25,
                    max_share: float = 0.02) -> list[dict]:
    """Hypothesis: C2 hiding on ports almost nobody else uses.

    A (src, dst, port) conversation is rare when its flow count is both
    absolutely small (< max_flows) and a tiny share of all traffic.
    """
    port_counts: dict[int, int] = defaultdict(int)
    conv_counts: dict[tuple, int] = defaultdict(int)
    total = len(netflow)
    for r in netflow:
        port_counts[r["dst_port"]] += 1
        conv_counts[(r["src_ip"], r["dst_ip"], r["dst_port"])] += 1
    findings = []
    for (src, dst, port), count in sorted(conv_counts.items()):
        share = port_counts[port] / total
        if port_counts[port] < max_flows and share < max_share:
            findings.append({
                "hunt": "rare-outbound-port",
                "explanation": (
                    f"{src} -> {dst}:{port} carries only {count} flow(s) "
                    f"({share:.3%} of all traffic). Rare ports on egress are "
                    "worth an allow-list review."
                ),
                "evidence": {
                    "src_ip": src, "dst_ip": dst, "dst_port": port,
                    "conversation_flows": count,
                    "port_flow_count": port_counts[port],
                },
                "severity": "suspicious",
            })
    return findings


def hunt_offhours_logons(auth: list[dict], start_hour: int = 0,
                         end_hour: int = 5) -> list[dict]:
    """Hypothesis: successful logons outside working hours."""
    findings = []
    for r in auth:
        if r["success"] and not start_hour <= r["ts"].hour < end_hour:
            continue
        if r["success"]:
            findings.append({
                "hunt": "offhours-logon",
                "explanation": (
                    f"{r['user']} logged in successfully at "
                    f"{r['ts'].isoformat()} from {r['src_ip']}."
                ),
                "evidence": {k: (v.isoformat() if isinstance(v, datetime) else v)
                             for k, v in r.items()},
                "severity": "suspicious",
            })
    return findings


def hunt_password_spray(auth: list[dict], window_minutes: int = 10,
                        min_users: int = 3) -> list[dict]:
    """Hypothesis: one source tries many users quickly (password spray)."""
    by_src: dict[str, list[dict]] = defaultdict(list)
    for r in auth:
        if not r["success"]:
            by_src[r["src_ip"]].append(r)
    findings = []
    from datetime import timedelta as _td
    for src, rows in by_src.items():
        rows.sort(key=lambda r: r["ts"])
        for i, pivot in enumerate(rows):
            window = [
                r for r in rows[i:]
                if r["ts"] - pivot["ts"] <= _td(minutes=window_minutes)
            ]
            users = {r["user"] for r in window}
            if len(users) >= min_users:
                findings.append({
                    "hunt": "password-spray",
                    "explanation": (
                        f"{src} attempted {len(window)} failed logons across "
                        f"{len(users)} accounts within {window_minutes} min."
                    ),
                    "evidence": {"src_ip": src, "users": sorted(users),
                                 "attempts": len(window)},
                    "severity": "likely-malicious",
                })
                break  # one finding per source
    return findings


ALL_HUNTS = [
    hunt_beaconing,
    hunt_rare_ports,
    hunt_offhours_logons,
    hunt_password_spray,
]
