"""Regenerate the committed sample data (deterministic, seed=42).

Run from repo root:  python -m data.generate
"""

from hunter.dataset import generate_synthetic, write_dataset
from pathlib import Path

if __name__ == "__main__":
    nf, au = generate_synthetic(seed=42)
    out = Path(__file__).resolve().parent
    write_dataset(nf, au, out)
    print(f"Wrote {len(nf)} netflow rows, {len(au)} auth events to {out}")
