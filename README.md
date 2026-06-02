# falcon-cloud-risk-rules

Fetch CrowdStrike Falcon **Cloud Risk rule definitions** from the CloudPolicies API and export them as JSON or CSV.

Cloud Risk rules are the system-managed policies that define compound security risks — combinations of misconfigurations, vulnerabilities, internet exposure, and identity issues that together create elevated risk. As of June 2026 there are 49 rules (8 Critical, 17 High, 21 Medium, 3 Low).

## Requirements

- Python 3.10+
- A Falcon API client with `cloud-security-policies:read` scope

## Installation

```bash
pip install -r requirements.txt
```

## Authentication

Credentials are resolved in this order:

1. **CLI flags** — `--client-id` / `--client-secret`
2. **Environment variables** — `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET`
3. **macOS Keychain** — profile-based lookup (CrowdStrike internal use)

## Usage

```bash
# Print a formatted table to the terminal
python fetch_rules.py

# Output JSON to stdout
python fetch_rules.py --json

# Save JSON to file
python fetch_rules.py --json -o rules

# Save CSV to file
python fetch_rules.py --csv -o rules

# Save both JSON and CSV
python fetch_rules.py --json --csv -o rules

# Filter by severity
python fetch_rules.py --json --severity critical

# Explicit credentials
python fetch_rules.py --client-id $ID --client-secret $SECRET --region us-1 --json -o rules
```

## Environment Variables

| Variable | Description |
|---|---|
| `FALCON_CLIENT_ID` | OAuth2 client ID |
| `FALCON_CLIENT_SECRET` | OAuth2 client secret |
| `FALCON_CLOUD_REGION` | Region: `us-1` (default), `us-2`, `eu-1`, `us-gov-1` |

## Output

### JSON

Array of rule objects. Key fields:

| Field | Type | Description |
|---|---|---|
| `uuid` | string | Rule UUID |
| `name` | string | Rule name |
| `severity` | integer | 0=Critical, 1=High, 2=Medium, 3=Low |
| `severity_label` | string | Human-readable severity |
| `description` | string | What the rule detects |
| `remediation_info` | string | How to fix it |
| `risk_factors` | string | Contributing risk factors |
| `enabled` | boolean | Whether the rule is active |

### CSV

Same fields as JSON, with list values (providers, risk_factors) serialised as comma-separated strings.

## Rule Taxonomy

Cloud Risk rules have `domain=CSPM` and `subdomain=CloudRisk`. They are distinct from:

- **IOM rules** (`subdomain=IOM`) — individual policy violations
- **Insight rules** (`subdomain=Insight`) — single-signal findings
- **IaC rules** (`subdomain=IAC`) — infrastructure-as-code scan results

## License

MIT
