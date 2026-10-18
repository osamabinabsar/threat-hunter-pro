"""Report generation: findings + ML scores -> hunt-report.md and JSON."""

from __future__ import annotations

import json
from pathlib import Path

_SEV_ORDER = {"likely-malicious": 0, "suspicious": 1, "informational": 2}


def write_json(findings: list[dict], out_path: str | Path) -> None:
    Path(out_path).write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")


def write_markdown(findings: list[dict], top_outliers: list[dict],
                   out_path: str | Path) -> None:
    lines = ["# Threat Hunt Report", ""]
    lines.append(f"Findings: **{len(findings)}** · ML outliers reviewed: **{len(top_outliers)}**")
    lines.append("")
    ordered = sorted(findings, key=lambda f: _SEV_ORDER.get(f["severity"], 9))
    if ordered:
        lines += ["## Hunt findings", ""]
    for f in ordered:
        lines.append(f"### [{f['severity'].upper()}] {f['hunt']}")
        lines.append("")
        lines.append(f["explanation"])
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(f["evidence"], indent=2, default=str))
        lines.append("```")
        lines.append("")
    if top_outliers:
        lines += ["## Top ML outliers (Isolation Forest)", "",
                  "Ranked anomaly scores — investigate from the top.", "",
                  "| src | dst | port | flows | CV | offhours | score |",
                  "|---|---|---|---|---|---|---|"]
        for c in top_outliers:
            lines.append(
                f"| {c['src_ip']} | {c['dst_ip']} | {c['dst_port']} | {c['flows']} "
                f"| {c['interarrival_cv']} | {c['offhours_ratio']} | {c['anomaly_score']} |"
            )
        lines.append("")
    Path(out_path).write_text("\n".join(lines), encoding="utf-8")
