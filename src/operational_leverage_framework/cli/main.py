from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..core import compute_confidence
from ..io import dump_result_file, load_evidence_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trust-surface",
        description="Compute deterministic evidence-first confidence for a small evidence dataset.",
    )
    parser.add_argument("input", help="JSON file containing a list of evidence objects")
    parser.add_argument(
        "--out",
        default="examples/output/result.json",
        help="Output JSON file path (default: examples/output/result.json)",
    )
    parser.add_argument("--base-avg", type=int, default=60, help="Base confidence baseline (default: 60)")
    parser.add_argument("--sector", default="", help="Optional sector hint")
    parser.add_argument("--risk-type", default="impersonation", help="Risk type hint")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    input_path = Path(args.input).resolve()
    output_path = Path(args.out).resolve()

    if not input_path.exists() or not input_path.is_file():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 2

    try:
        evidence = load_evidence_file(input_path)
    except Exception as exc:
        print(f"error: invalid input: {exc}", file=sys.stderr)
        return 2

    confidence, meta = compute_confidence(
        evidence,
        base_avg=args.base_avg,
        sector=args.sector,
        risk_type=args.risk_type,
    )
    payload = {"confidence": confidence, "meta": meta}

    output_path.parent.mkdir(parents=True, exist_ok=True)
    dump_result_file(output_path, payload)

    print(f"confidence={confidence}")
    print(f"wrote={output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
