# Attack Surface Prioritizer

**A lightweight way to decide which internet-facing assets deserve attention first.**

Attack Surface Prioritizer reads a JSON inventory of hosts and services, scores each asset, and explains the factors behind its score. It helps security and engineering teams turn a long asset list into a short, actionable review queue.

## What it looks at

- Publicly reachable services and sensitive ports
- Missing ownership and non-production systems exposed to the internet
- Older technologies, plain HTTP, and overdue security reviews

Each asset receives a score from 0 to 100, a risk level, and a short list of reasons. The score is a triage aid, not a vulnerability verdict.

## Quick start

Requires Python 3.9 or newer.

```bash
pip install git+https://github.com/httpEduardo/attack-surface-prioritizer.git
attack-surface-prioritizer --input inventory.json
```

To run directly from a clone:

```bash
git clone https://github.com/httpEduardo/attack-surface-prioritizer.git
cd attack-surface-prioritizer
PYTHONPATH=src python -m attack_surface_prioritizer -i examples/assets.json
```

## Inventory example

```json
{
  "assets": [
    {
      "id": "customer-api",
      "host": "api.example.com",
      "env": "production",
      "owner": "Platform",
      "public": true,
      "tech": ["nginx", "python"],
      "ports": [443],
      "last_assessed_days": 30
    }
  ]
}
```

The report ranks assets by score and shows the reasons for each result. Use `--format json` or `--format csv` to export the full inventory and scores.

## License

[MIT](LICENSE)
