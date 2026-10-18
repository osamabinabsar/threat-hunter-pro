"""Feature extraction: netflow rows -> per-conversation features.

One feature vector per (src_ip, dst_ip, dst_port) conversation:
    flows            number of flows
    total_bytes      bytes_out + bytes_in summed
    distinct_hours   how many distinct hours flows landed in (activity spread)
    interarrival_cv  coefficient of variation of gaps between flows
                    (low CV = mechanical regularity = beacon candidate)
    offhours_ratio   fraction of flows outside 08:00-18:00 local-ish time
    mean_bytes_out   average outbound payload per flow
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import datetime

FEATURE_NAMES = [
    "flows", "total_bytes", "distinct_hours", "interarrival_cv",
    "offhours_ratio", "mean_bytes_out",
]


def conversation_features(netflow: list[dict]) -> list[dict]:
    """Aggregate netflow rows into per-conversation feature dicts."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in netflow:
        groups[(r["src_ip"], r["dst_ip"], r["dst_port"])].append(r)

    out = []
    for (src, dst, port), rows in groups.items():
        rows.sort(key=lambda r: r["ts"])
        gaps = [
            (b["ts"] - a["ts"]).total_seconds()
            for a, b in zip(rows, rows[1:])
        ]
        mean_gap = statistics.fmean(gaps) if gaps else 0.0
        cv = (statistics.pstdev(gaps) / mean_gap) if len(gaps) > 1 and mean_gap > 0 else 1.0
        offhours = sum(1 for r in rows if not 8 <= r["ts"].hour < 18)
        out.append({
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": port,
            "flows": len(rows),
            "total_bytes": sum(r["bytes_out"] + r["bytes_in"] for r in rows),
            "distinct_hours": len({r["ts"].replace(minute=0, second=0) for r in rows}),
            "interarrival_cv": round(cv, 4),
            "offhours_ratio": round(offhours / len(rows), 4),
            "mean_bytes_out": round(statistics.fmean(r["bytes_out"] for r in rows), 2),
            "first_seen": rows[0]["ts"].isoformat(),
            "last_seen": rows[-1]["ts"].isoformat(),
        })
    out.sort(key=lambda f: f["flows"], reverse=True)
    return out


def feature_vector(conv: dict) -> list[float]:
    """Numeric vector for ML scoring (features in FEATURE_NAMES order)."""
    return [float(conv[name]) for name in FEATURE_NAMES]

