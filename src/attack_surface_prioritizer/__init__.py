"""Attack-surface inventory and exposure scoring."""

from .scoring import Asset, ScoredAsset, build_rules, score_asset, score_inventory

__all__ = ["Asset", "ScoredAsset", "build_rules", "score_asset", "score_inventory"]
__version__ = "1.0.0"
