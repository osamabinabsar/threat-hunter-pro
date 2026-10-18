"""CLI: python -m hunter.cli [--netflow ... --auth ... --out hunt-report.md]"""

from __future__ import annotations

import argparse
from pathlib import Path

from .dataset import load_auth, load_netflow
from .detect import score_conversations
from .features import conversation_features
from .queries import ALL_HUNTS, hunt_offhours_logons, hunt_password_spray
from .report import write_json, write_markdown

AUTH_HUNTS = {hunt_offhours_logons, hunt_password_spray}

DATA = Path(__file__).resolve().parent.parent / "data"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hunter", description="Threat hunting engine")
    ap.add_argument("--netflow", default=str(DATA / "sample_netflow.csv"))
    ap.add_argument("--auth", default=str(DATA / "sample_auth.jsonl"))
    ap.add_argument("--out", default="hunt-report.md")
    ap.add_argument("--top", type=int, default=10, help="top N ML outliers in report")
    args = ap.parse_args(argv)

    netflow = load_netflow(args.netflow)
    auth = load_auth(args.auth)
    print(f"Loaded {len(netflow)} netflow rows, {len(auth)} auth events.")

    findings = []
    for hunt in ALL_HUNTS:
        got = hunt(auth) if hunt in AUTH_HUNTS else hunt(netflow)
        print(f"{hunt.__name__}: {len(got)} finding(s)")
        findings.extend(got)

    convs = conversation_features(netflow)
    scored = score_conversations(convs)
    top = [c for c in scored if c["is_outlier"]][: args.top]
    print(f"Conversations: {len(convs)} - ML outliers: {sum(c['is_outlier'] for c in scored)}")

    write_markdown(findings, top, args.out)
    write_json(findings, Path(args.out).with_suffix(".json"))
    print(f"Wrote {args.out} and {Path(args.out).with_suffix('.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
