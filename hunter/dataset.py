"""Dataset loading and (seeded) synthetic data generation.

Netflow CSV columns:
    ts,duration_s,src_ip,dst_ip,dst_port,proto,bytes_out,bytes_in
Auth JSONL fields:
    ts,user,src_ip,success(bool),method
"""

from __future__ import annotations

import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

NETFLOW_COLUMNS = ["ts", "duration_s", "src_ip", "dst_ip", "dst_port", "proto", "bytes_out", "bytes_in"]


def load_netflow(path: str | Path) -> list[dict]:
    rows = []
    with Path(path).open(newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            r["ts"] = datetime.fromisoformat(r["ts"])
            for k in ("duration_s", "dst_port", "bytes_out", "bytes_in"):
                r[k] = int(r[k])
            rows.append(r)
    return rows


def load_auth(path: str | Path) -> list[dict]:
    rows = []
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            o = json.loads(line)
            o["ts"] = datetime.fromisoformat(o["ts"])
            rows.append(o)
    return rows


def generate_synthetic(seed: int = 42) -> tuple[list[dict], list[dict]]:
    """Deterministic synthetic telemetry with three planted incidents.

    Incident 1: 10.0.4.25 beacons to 203.0.113.66:443 every 60s (low jitter).
    Incident 2: same host's operator logs in off-hours (02:00-04:00).
    Incident 3: 10.0.4.25 talks to 198.51.100.99 on rare port 54321.
    """
    rng = random.Random(seed)
    base = datetime(2026, 9, 20, 0, 0, 0)
    netflow: list[dict] = []
    auth: list[dict] = []

    def add_flow(t, src, dst, port, out_b, in_b, dur=1):
        netflow.append({
            "ts": t, "duration_s": dur, "src_ip": src, "dst_ip": dst,
            "dst_port": port, "proto": "tcp", "bytes_out": out_b, "bytes_in": in_b,
        })

    # Background chatter: random workstation traffic over 48h.
    workstations = [f"10.0.4.{i}" for i in range(10, 20)]
    servers = ["93.184.216.34", "151.101.1.69", "142.250.72.14", "104.16.132.229"]
    for hour in range(48):
        for ws in workstations:
            for _ in range(rng.randint(2, 6)):
                t = base + timedelta(hours=hour, seconds=rng.randint(0, 3599))
                add_flow(t, ws, rng.choice(servers), rng.choice([80, 443, 53]),
                         rng.randint(200, 4000), rng.randint(500, 20000))

    # Incident 1: beacon, 60s +/- 1s jitter, 12 hours.
    t = base + timedelta(hours=6)
    for _ in range(720):
        add_flow(t, "10.0.4.25", "203.0.113.66", 443, rng.randint(180, 260), rng.randint(120, 200))
        t += timedelta(seconds=60 + rng.randint(-1, 1))

    # Incident 3: rare-port C2, 30 min apart.
    t = base + timedelta(hours=7, minutes=10)
    for _ in range(20):
        add_flow(t, "10.0.4.25", "198.51.100.99", 54321, rng.randint(900, 1400), rng.randint(300, 600), dur=2)
        t += timedelta(minutes=30)

    # Incident 2: off-hours logons from the implant operator.
    users = ["osama", "jpark", "svc_backup", "admin"]
    for day in range(2):
        night = base + timedelta(days=day, hours=2, minutes=rng.randint(0, 40))
        auth.append({"ts": night, "user": "jpark", "src_ip": "10.0.4.25",
                     "success": True, "method": "password"})
    # Benign daytime auth.
    for day in range(2):
        for u in users:
            auth.append({"ts": base + timedelta(days=day, hours=9, minutes=rng.randint(0, 59)),
                         "user": u, "src_ip": rng.choice(workstations),
                         "success": True, "method": "password"})

    netflow.sort(key=lambda r: r["ts"])
    auth.sort(key=lambda r: r["ts"])
    return netflow, auth


def write_dataset(netflow: list[dict], auth: list[dict], out_dir: str | Path) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "sample_netflow.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=NETFLOW_COLUMNS)
        w.writeheader()
        for r in netflow:
            w.writerow({**r, "ts": r["ts"].isoformat()})
    with (out / "sample_auth.jsonl").open("w", encoding="utf-8") as fh:
        for r in auth:
            fh.write(json.dumps({**r, "ts": r["ts"].isoformat()}) + "\n")
