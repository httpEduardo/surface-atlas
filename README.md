# surface-atlas

Turns an inventory of internet-facing assets into a ranked list of what to look at first. Each asset gets an exposure score from 0 to 100, a risk level, and the specific reasons behind the number.

Every security team has more hosts than time. The ones that end up in incident reports tend to share the same traits: nobody owns them, they run something old, they expose a database or admin panel to the internet, and nobody has looked at them in months. surface-atlas scores exactly those traits, so the conversation shifts from "we have 400 assets" to "these five need an owner and a review this week".

## How scoring works

Each rule adds its weight when it matches. The total is capped at 100.

| Rule | Weight | Matches when |
|------|-------:|--------------|
| `public` | 25 | The asset is reachable from the internet |
| `sensitive-port` | 30 | A public asset exposes SSH, RDP, databases, Redis, Elasticsearch, Docker, Kubelet… |
| `no-owner` | 20 | No team or person is accountable for it |
| `non-production` | 15 | A dev, test, QA or staging environment is public |
| `legacy-tech` | 15 | The stack includes PHP, IIS, Tomcat, Apache httpd, JBoss, WebLogic, Struts or ColdFusion |
| `stale-assessment` | 15 | Never assessed, or last assessed more than 90 days ago |
| `plaintext-http` | 10 | A public asset serves HTTP on 80, 8000 or 8080 |
| `many-ports` | 5 | More than two open ports |

| Score | Level |
|------:|-------|
| 70–100 | critical |
| 45–69 | high |
| 25–44 | medium |
| 0–24 | low |

The weights are a starting point, not gospel. See [Custom weights](#custom-weights) to tune them.

## Installation

Requires Python 3.9 or newer. No third-party dependencies.

```bash
pip install git+https://github.com/httpEduardo/surface-atlas.git
```

Or run from a clone:

```bash
git clone https://github.com/httpEduardo/surface-atlas.git
cd surface-atlas
PYTHONPATH=src python -m surface_atlas -i examples/assets.json
```

## Usage

```bash
surface-atlas -i examples/assets.json -n 3
```

```text
Top 3 of 5 assets by exposure

   85  CRITICAL dev-console (dev-console.example.com)
                 +25  reachable from the internet
                 +30  sensitive service exposed: 3000 (Grafana/dev server)
                 +15  public dev environment
                 +15  last assessed 120 days ago

   85  CRITICAL legacy-api (legacy-api.example.com)
                 +25  reachable from the internet
                 +20  no owner assigned
                 +15  legacy technology (apache, php)
                 +15  last assessed 210 days ago
                 +10  serves plain HTTP on port 80

   70  CRITICAL orders-db (db-orders.example.com)
                 +25  reachable from the internet
                 +30  sensitive service exposed: 22 (SSH), 5432 (PostgreSQL)
                 +15  never assessed

Coverage
  public-facing assets: 4/5
  owner coverage:       80%
  environments:         corp 1, dev 1, prod 3
  most common factors:  public (4), stale-assessment (3), sensitive-port (2), no-owner (1), legacy-tech (1), plaintext-http (1), non-production (1)
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `-i, --input FILE` | required | Asset inventory in JSON |
| `-n, --top N` | `10` | How many assets to list in the text report |
| `-f, --format {text,json,csv}` | `text` | CSV drops straight into a spreadsheet; JSON includes every asset and the summary |
| `-w, --weights FILE` | | Override rule weights |
| `--fail-on LEVEL` | | Exit with `1` if any asset reaches `low`, `medium`, `high` or `critical` |
| `--version` | | Print the version |

Exit code `2` means the inventory or weights file couldn't be read or failed validation.

## Inventory format

Either an object with an `assets` list or a bare list:

```json
{
  "assets": [
    {
      "id": "legacy-api",
      "host": "legacy-api.example.com",
      "env": "prod",
      "owner": "",
      "public": true,
      "tech": ["apache", "php"],
      "ports": [80, 443],
      "last_assessed_days": 210
    }
  ]
}
```

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Falls back to `host` when missing |
| `host` | string | Hostname or IP, for display |
| `env` | string | `prod`, `staging`, `dev`, … (case-insensitive) |
| `owner` | string | Team or person; empty means unowned |
| `public` | boolean | Reachable from the internet |
| `tech` | string[] | Detected technologies |
| `ports` | integer[] | Open ports, 1–65535 |
| `last_assessed_days` | integer | Days since the last review; omit if it has never been assessed |

Records with invalid types (a port of `70000`, `ports` given as a number) are rejected with a message pointing at the asset, rather than quietly scored as safe.

The format is intentionally simple so it can be generated from whatever you already have — a CMDB export, cloud inventory, or the output of `nmap`/`httpx` plus a spreadsheet of owners.

## Custom weights

Pass a JSON object mapping rule IDs to weights. A weight of `0` disables a rule, and unknown rule names are rejected so typos don't slip by.

```json
{
  "public": 30,
  "no-owner": 25,
  "many-ports": 0
}
```

```bash
surface-atlas -i inventory.json -w examples/weights.json
```

## Using it in CI or on a schedule

```bash
surface-atlas -i inventory.json --fail-on critical -f csv > exposure.csv
```

Run it nightly against a fresh inventory export and the build turns red the moment a critical asset appears.

## Development

```bash
python -m unittest discover -s tests -t .
```

`src/surface_atlas/scoring.py` holds the rules — each is a small function that returns a reason string or `None` — and `cli.py` handles loading and output. Adding a rule means writing the function, registering it in `DEFAULT_RULES` and adding a test.

## License

[MIT](LICENSE)
