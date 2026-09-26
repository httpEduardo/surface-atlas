"""Command-line interface for attack-surface-prioritizer."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Sequence, TextIO

from . import __version__
from .scoring import LEVELS, Asset, ScoredAsset, build_rules, score_inventory

EXIT_OK = 0
EXIT_RISK = 1
EXIT_ERROR = 2

LEVEL_ORDER = {name: i for i, (_, name) in enumerate(reversed(LEVELS))}


def load_inventory(path: str) -> list[Asset]:
    """Load assets from a JSON file shaped as {"assets": [...]} or a bare list."""
    data: Any = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("assets")
    if not isinstance(data, list):
        raise ValueError('expected a list of assets or an object with an "assets" list')
    return [Asset.from_dict(item, i) for i, item in enumerate(data, start=1)]


def load_weights(path: str | None) -> dict[str, int] | None:
    if not path:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("weights file must contain a JSON object of rule -> weight")
    return data


def summarize(scored: list[ScoredAsset]) -> dict[str, Any]:
    owned = sum(1 for s in scored if s.asset.owner)
    drivers = Counter(r["rule"] for s in scored for r in s.reasons)
    return {
        "assets": len(scored),
        "public": sum(1 for s in scored if s.asset.public),
        "owner_coverage": round(100 * owned / len(scored)) if scored else 100,
        "by_level": dict(Counter(s.level for s in scored)),
        "by_env": dict(sorted(Counter(s.asset.env for s in scored).items())),
        "top_drivers": dict(drivers.most_common()),
    }


def write_text(out: TextIO, scored: list[ScoredAsset], top: int) -> None:
    summary = summarize(scored)
    out.write(f"Top {min(top, len(scored))} of {len(scored)} assets by exposure\n\n")
    for s in scored[:top]:
        host = f" ({s.asset.host})" if s.asset.host else ""
        out.write(f"  {s.score:>3}  {s.level.upper():<8} {s.asset.id}{host}\n")
        for r in s.reasons:
            out.write(f"                 +{r['weight']:<3} {r['detail']}\n")
        if not s.reasons:
            out.write("                 no risk factors\n")
        out.write("\n")

    out.write("Coverage\n")
    out.write(f"  public-facing assets: {summary['public']}/{summary['assets']}\n")
    out.write(f"  owner coverage:       {summary['owner_coverage']}%\n")
    envs = ", ".join(f"{env} {n}" for env, n in summary["by_env"].items())
    out.write(f"  environments:         {envs}\n")
    if summary["top_drivers"]:
        drivers = ", ".join(f"{rule} ({n})" for rule, n in summary["top_drivers"].items())
        out.write(f"  most common factors:  {drivers}\n")


def write_csv(out: TextIO, scored: list[ScoredAsset]) -> None:
    writer = csv.writer(out)
    writer.writerow(["id", "host", "env", "owner", "public", "score", "level", "reasons"])
    for s in scored:
        writer.writerow([
            s.asset.id, s.asset.host, s.asset.env, s.asset.owner, str(s.asset.public).lower(),
            s.score, s.level, "; ".join(r["detail"] for r in s.reasons),
        ])


def main(argv: Sequence[str] | None = None, out: TextIO = sys.stdout, err: TextIO = sys.stderr) -> int:
    parser = argparse.ArgumentParser(
        prog="attack-surface-prioritizer",
        description="Score an attack-surface inventory and rank assets by exposure risk.",
    )
    parser.add_argument("--input", "-i", required=True, help="asset inventory (JSON)")
    parser.add_argument("--top", "-n", type=int, default=10, help="number of assets to show in text mode (default: 10)")
    parser.add_argument("--format", "-f", choices=("text", "json", "csv"), default="text")
    parser.add_argument("--weights", "-w", help="JSON file overriding rule weights, e.g. {\"public\": 30}")
    parser.add_argument(
        "--fail-on",
        choices=[name for _, name in LEVELS],
        help="exit with code 1 if any asset reaches this risk level",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    if args.top < 1:
        parser.error("--top must be at least 1")

    try:
        rules = build_rules(load_weights(args.weights))
        assets = load_inventory(args.input)
    except (OSError, ValueError) as exc:  # json.JSONDecodeError is a ValueError
        err.write(f"error: {exc}\n")
        return EXIT_ERROR

    scored = score_inventory(assets, rules)

    if args.format == "json":
        json.dump({"summary": summarize(scored), "assets": [s.to_dict() for s in scored]}, out, indent=2)
        out.write("\n")
    elif args.format == "csv":
        write_csv(out, scored)
    elif not scored:
        out.write("No assets found.\n")
    else:
        write_text(out, scored, args.top)

    if args.fail_on and any(LEVEL_ORDER[s.level] >= LEVEL_ORDER[args.fail_on] for s in scored):
        return EXIT_RISK
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
