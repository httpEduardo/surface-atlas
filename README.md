# Surface Atlas

Surface Atlas builds an attack-surface inventory from asset metadata and scores exposure risk.

## Quick start

```bash
python surface_atlas.py --input assets.json --top 5
```

## Output

- Risk score per asset with reasons.
- Summary by environment and owner coverage.

## Notes

Scoring is heuristic. Adjust weights in the `RULES` table for your environment.
