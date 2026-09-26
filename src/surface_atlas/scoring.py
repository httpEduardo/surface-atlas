"""Rule-based exposure scoring for an attack-surface inventory."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

# Ports that should almost never be reachable from the internet.
SENSITIVE_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    2375: "Docker API",
    3000: "Grafana/dev server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    6379: "Redis",
    8500: "Consul",
    9200: "Elasticsearch",
    10250: "Kubelet",
    11211: "Memcached",
    27017: "MongoDB",
}

PLAINTEXT_PORTS = {80, 8000, 8080}

LEGACY_TECH = {"php", "iis", "tomcat", "apache", "jboss", "weblogic", "struts", "coldfusion"}

NON_PRODUCTION = {"dev", "development", "test", "testing", "qa", "staging", "stage", "sandbox"}

STALE_AFTER_DAYS = 90

LEVELS = ((70, "critical"), (45, "high"), (25, "medium"), (0, "low"))


@dataclass(frozen=True)
class Asset:
    id: str
    host: str = ""
    env: str = "unknown"
    owner: str = ""
    public: bool = False
    tech: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    last_assessed_days: int | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], index: int) -> "Asset":
        """Build an asset from raw JSON, raising ValueError on bad types."""
        if not isinstance(data, Mapping):
            raise ValueError(f"asset #{index} is not an object")

        def as_list(key: str) -> list:
            value = data.get(key) or []
            if not isinstance(value, list):
                raise ValueError(f"asset #{index}: '{key}' must be a list")
            return value

        ports = []
        for port in as_list("ports"):
            if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
                raise ValueError(f"asset #{index}: invalid port {port!r}")
            ports.append(port)

        assessed = data.get("last_assessed_days")
        if assessed is not None and (isinstance(assessed, bool) or not isinstance(assessed, int) or assessed < 0):
            raise ValueError(f"asset #{index}: 'last_assessed_days' must be a non-negative integer")

        return cls(
            id=str(data.get("id") or data.get("host") or f"asset-{index}"),
            host=str(data.get("host") or ""),
            env=str(data.get("env") or "unknown").lower(),
            owner=str(data.get("owner") or "").strip(),
            public=bool(data.get("public", False)),
            tech=tuple(str(t).lower() for t in as_list("tech")),
            ports=tuple(sorted(set(ports))),
            last_assessed_days=assessed,
        )


@dataclass(frozen=True)
class Rule:
    id: str
    weight: int
    check: Callable[[Asset], str | None]


def _public(a: Asset) -> str | None:
    return "reachable from the internet" if a.public else None


def _no_owner(a: Asset) -> str | None:
    return None if a.owner else "no owner assigned"


def _legacy(a: Asset) -> str | None:
    old = sorted(set(a.tech) & LEGACY_TECH)
    return f"legacy technology ({', '.join(old)})" if old else None


def _stale(a: Asset) -> str | None:
    if a.last_assessed_days is None:
        return "never assessed"
    if a.last_assessed_days > STALE_AFTER_DAYS:
        return f"last assessed {a.last_assessed_days} days ago"
    return None


def _sensitive_ports(a: Asset) -> str | None:
    if not a.public:
        return None
    exposed = [f"{p} ({SENSITIVE_PORTS[p]})" for p in a.ports if p in SENSITIVE_PORTS]
    return f"sensitive service exposed: {', '.join(exposed)}" if exposed else None


def _plaintext(a: Asset) -> str | None:
    plain = sorted(set(a.ports) & PLAINTEXT_PORTS)
    if a.public and plain:
        return f"serves plain HTTP on port {', '.join(map(str, plain))}"
    return None


def _non_production(a: Asset) -> str | None:
    return f"public {a.env} environment" if a.public and a.env in NON_PRODUCTION else None


def _many_ports(a: Asset) -> str | None:
    return f"{len(a.ports)} open ports" if len(a.ports) > 2 else None


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule("public", 25, _public),
    Rule("sensitive-port", 30, _sensitive_ports),
    Rule("no-owner", 20, _no_owner),
    Rule("non-production", 15, _non_production),
    Rule("legacy-tech", 15, _legacy),
    Rule("stale-assessment", 15, _stale),
    Rule("plaintext-http", 10, _plaintext),
    Rule("many-ports", 5, _many_ports),
)


def build_rules(weights: Mapping[str, int] | None = None) -> tuple[Rule, ...]:
    """Return the default rules with optional weight overrides.

    A weight of 0 disables a rule. Unknown rule IDs raise ValueError so a
    typo in a weights file doesn't go unnoticed.
    """
    if not weights:
        return DEFAULT_RULES
    known = {r.id for r in DEFAULT_RULES}
    unknown = set(weights) - known
    if unknown:
        raise ValueError(f"unknown rule(s) in weights: {', '.join(sorted(unknown))}; known: {', '.join(sorted(known))}")
    for rule_id, weight in weights.items():
        if isinstance(weight, bool) or not isinstance(weight, int) or weight < 0:
            raise ValueError(f"weight for {rule_id!r} must be a non-negative integer")
    return tuple(Rule(r.id, weights.get(r.id, r.weight), r.check) for r in DEFAULT_RULES)


@dataclass
class ScoredAsset:
    asset: Asset
    score: int
    level: str
    reasons: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.asset.id,
            "host": self.asset.host,
            "env": self.asset.env,
            "owner": self.asset.owner or None,
            "score": self.score,
            "level": self.level,
            "reasons": self.reasons,
        }


def level_for(score: int) -> str:
    return next(name for threshold, name in LEVELS if score >= threshold)


def score_asset(asset: Asset, rules: Iterable[Rule] = DEFAULT_RULES) -> ScoredAsset:
    """Score one asset. The score is the sum of matching weights, capped at 100."""
    reasons = []
    total = 0
    for rule in rules:
        if rule.weight == 0:
            continue
        detail = rule.check(asset)
        if detail:
            total += rule.weight
            reasons.append({"rule": rule.id, "weight": rule.weight, "detail": detail})
    score = min(total, 100)
    return ScoredAsset(asset, score, level_for(score), reasons)


def score_inventory(assets: Iterable[Asset], rules: Iterable[Rule] = DEFAULT_RULES) -> list[ScoredAsset]:
    """Score all assets, highest risk first (ties broken by id)."""
    rules = tuple(rules)
    scored = [score_asset(a, rules) for a in assets]
    return sorted(scored, key=lambda s: (-s.score, s.asset.id))
