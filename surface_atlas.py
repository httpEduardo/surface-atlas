import argparse
import json
import sys
from collections import Counter, defaultdict

RULES = [
    ("public", 30, "public-facing"),
    ("no-owner", 25, "missing owner"),
    ("legacy-tech", 20, "legacy tech"),
    ("stale-assessment", 15, "assessment older than 90 days"),
    ("extra-ports", 10, "multiple open ports"),
    ("dev-env", 8, "dev environment"),
]

LEGACY_TECH = {"php", "iis", "tomcat", "apache"}


def score_asset(asset: dict) -> tuple[int, list[str]]:
    reasons = []
    score = 0

    if asset.get("public"):
        score += 30
        reasons.append("public-facing")
    if not asset.get("owner"):
        score += 25
        reasons.append("missing owner")

    tech = {item.lower() for item in asset.get("tech", [])}
    if tech & LEGACY_TECH:
        score += 20
        reasons.append("legacy tech")

    if asset.get("last_assessed_days", 0) > 90:
        score += 15
        reasons.append("assessment older than 90 days")

    if len(asset.get("ports", [])) > 1:
        score += 10
        reasons.append("multiple open ports")

    if asset.get("env", "").lower() == "dev" and asset.get("public"):
        score += 8
        reasons.append("dev environment")

    return score, reasons


def main() -> int:
    parser = argparse.ArgumentParser(description="Score attack-surface assets for risk.")
    parser.add_argument("--input", required=True, help="Asset inventory JSON")
    parser.add_argument("--top", type=int, default=5)
    args = parser.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Failed to read {args.input}: {exc}", file=sys.stderr)
        return 1

    assets = data.get("assets", [])
    if not assets:
        print("No assets found.")
        return 0

    scored = []
    env_counts = Counter()
    owner_missing = 0
    owner_counts = Counter()

    for asset in assets:
        score, reasons = score_asset(asset)
        scored.append({
            "id": asset.get("id", "unknown"),
            "host": asset.get("host", ""),
            "env": asset.get("env", "unknown"),
            "owner": asset.get("owner", ""),
            "score": score,
            "reasons": reasons,
        })
        env_counts[asset.get("env", "unknown")] += 1
        if not asset.get("owner"):
            owner_missing += 1
        else:
            owner_counts[asset.get("owner")] += 1

    scored.sort(key=lambda item: item["score"], reverse=True)

    print("Top risk assets:")
    for item in scored[: args.top]:
        reasons = ", ".join(item["reasons"]) or "no flags"
        print(f"- {item['id']} ({item['host']}) score {item['score']} -> {reasons}")

    print("\nEnvironment coverage:")
    for env, count in env_counts.items():
        print(f"- {env}: {count}")

    print("\nOwner coverage:")
    print(f"- missing owner: {owner_missing}")
    for owner, count in owner_counts.items():
        print(f"- {owner}: {count}")

    reasons_count = defaultdict(int)
    for item in scored:
        for reason in item["reasons"]:
            reasons_count[reason] += 1
    if reasons_count:
        print("\nTop drivers:")
        for reason, count in sorted(reasons_count.items(), key=lambda item: item[1], reverse=True):
            print(f"- {reason}: {count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
