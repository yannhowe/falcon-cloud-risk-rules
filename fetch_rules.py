#!/usr/bin/env python3
"""
fetch_rules.py — Fetch CrowdStrike Falcon Cloud Risk Rules

Retrieves the full list of cloud risk rule definitions from the
CloudPolicies API and outputs them as JSON or CSV.

Authentication (in order of precedence):
  1. CLI flags: --client-id / --client-secret
  2. Environment variables: FALCON_CLIENT_ID / FALCON_CLIENT_SECRET
  3. macOS Keychain (profile-based, for CrowdStrike internal use)

Usage:
  python fetch_rules.py --json                    # print JSON to stdout
  python fetch_rules.py --json -o rules.json      # save JSON to file
  python fetch_rules.py --csv  -o rules.csv       # save CSV to file
  python fetch_rules.py --json --csv -o output    # saves output.json + output.csv
  python fetch_rules.py --severity critical        # filter by severity
"""

import sys
import os
import json
import csv
import argparse
import subprocess
from typing import Optional

try:
    from falconpy import CloudPolicies
except ImportError:
    print("ERROR: falconpy not installed. Run: pip install crowdstrike-falconpy")
    sys.exit(1)


SEVERITY_MAP = {0: "Critical", 1: "High", 2: "Medium", 3: "Low"}
REGION_MAP = {
    "us-1":     "https://api.crowdstrike.com",
    "us-2":     "https://api.us-2.crowdstrike.com",
    "eu-1":     "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}
CSV_FIELDS = [
    "name", "severity", "severity_label", "uuid", "enabled",
    "domain", "subdomain", "description", "remediation_info",
    "cloud_providers", "resource_types", "risk_factors",
]


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _keychain(service: str, account: str) -> Optional[str]:
    """Retrieve a value from macOS Keychain (optional, skipped on non-Mac)."""
    try:
        r = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True, text=True, check=True,
        )
        return r.stdout.strip() or None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _active_profile() -> str:
    for path in [
        ".claude/memory/active-cid.txt",
        os.path.expanduser("~/.claude/projects/-Users-ykwan-Documents-code-knowledgebase/memory/active-cid.txt"),
    ]:
        try:
            with open(path) as f:
                for line in f:
                    if line.startswith("profile="):
                        return line.strip().split("=", 1)[1]
        except FileNotFoundError:
            continue
    return "default"


def resolve_credentials(args) -> tuple[str, str, str]:
    """Resolve client_id, client_secret, base_url from CLI > env > keychain."""
    client_id     = args.client_id     or os.getenv("FALCON_CLIENT_ID")
    client_secret = args.client_secret or os.getenv("FALCON_CLIENT_SECRET")
    region        = args.region        or os.getenv("FALCON_CLOUD_REGION", "")

    # Keychain fallback (macOS only)
    if not client_id or not client_secret:
        profile = _active_profile()
        client_id     = client_id     or _keychain("falcon-client-id",     profile)
        client_secret = client_secret or _keychain("falcon-client-secret", profile)
        region        = region        or _keychain("falcon-cloud-region",  profile) or "us-1"

    if not client_id or not client_secret:
        print(
            "ERROR: No credentials found.\n"
            "  Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables, or\n"
            "  pass --client-id / --client-secret on the command line."
        )
        sys.exit(1)

    base_url = REGION_MAP.get(region or "us-1", REGION_MAP["us-1"])
    return client_id, client_secret, base_url


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

def fetch_cloud_risk_rules(cp: CloudPolicies) -> tuple[list, int]:
    """Return (rules, total) for all cloud risk rule definitions."""
    resp = cp.query_rule(
        filter="rule_domain:'CSPM'+rule_subdomain:'CloudRisk'",
        limit=500,
    )
    if resp["status_code"] != 200:
        print(f"ERROR querying rule IDs: HTTP {resp['status_code']} — {resp['body'].get('errors')}")
        sys.exit(1)

    ids   = resp["body"].get("resources") or []
    total = resp["body"]["meta"]["pagination"]["total"]

    if not ids:
        return [], 0

    all_rules = []
    for i in range(0, len(ids), 100):
        batch = ids[i:i + 100]
        detail = cp.get_rule(ids=batch)
        if detail["status_code"] != 200:
            print(f"ERROR fetching rule details: HTTP {detail['status_code']} — {detail['body'].get('errors')}")
            sys.exit(1)
        all_rules.extend(detail["body"].get("resources") or [])

    return all_rules, total


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _enrich(rule: dict) -> dict:
    """Add human-readable severity_label and normalise list fields."""
    rule = dict(rule)
    rule["severity_label"] = SEVERITY_MAP.get(rule.get("severity"), "Unknown")
    # Normalise list fields to comma-separated strings for CSV
    for field in ("cloud_providers", "risk_factors"):
        val = rule.get(field)
        if isinstance(val, list):
            rule[field] = ", ".join(v if isinstance(v, str) else json.dumps(v) for v in val)
    # resource_types is a list of dicts — extract human-readable names to match GUI "Asset types"
    rt = rule.get("resource_types")
    if isinstance(rt, list):
        rule["resource_types"] = ", ".join(
            v.get("resource_type_name") or v.get("resource_type", "")
            if isinstance(v, dict) else str(v)
            for v in rt
        )
    return rule


def sort_rules(rules: list) -> list:
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return sorted(
        rules,
        key=lambda r: (sev_order.get(SEVERITY_MAP.get(r.get("severity"), ""), 99), r.get("name", ""))
    )


def write_json(rules: list, dest) -> None:
    enriched = [_enrich(r) for r in rules]
    data = json.dumps(enriched, indent=2)
    if hasattr(dest, "write"):
        dest.write(data + "\n")
    else:
        with open(dest, "w") as f:
            f.write(data + "\n")
        print(f"JSON saved to: {dest}")


def write_csv(rules: list, dest) -> None:
    enriched = [_enrich(r) for r in rules]
    # Collect all keys so extra fields aren't dropped
    all_keys = list(dict.fromkeys(CSV_FIELDS + [k for k in (enriched[0] if enriched else {}) if k not in CSV_FIELDS]))

    if hasattr(dest, "write"):
        writer = csv.DictWriter(dest, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(enriched)
    else:
        with open(dest, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(enriched)
        print(f"CSV saved to: {dest}")


def print_table(rules: list) -> None:
    counts = {}
    for r in rules:
        s = SEVERITY_MAP.get(r.get("severity"), "Unknown")
        counts[s] = counts.get(s, 0) + 1

    print(f"\n{'='*80}")
    print(f"  Cloud Risk Rules  ({len(rules)} total)")
    print(f"  Critical: {counts.get('Critical',0)}  High: {counts.get('High',0)}"
          f"  Medium: {counts.get('Medium',0)}  Low: {counts.get('Low',0)}")
    print(f"{'='*80}\n")

    for r in rules:
        sev  = SEVERITY_MAP.get(r.get("severity"), "?")
        name = r.get("name", "")
        uid  = r.get("uuid", r.get("id", ""))
        print(f"[{sev:8s}] {name}")
        print(f"           ID: {uid}")
        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Fetch CrowdStrike Falcon cloud risk rule definitions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # Auth
    auth = parser.add_argument_group("authentication")
    auth.add_argument("--client-id",     help="Falcon API client ID (or set FALCON_CLIENT_ID)")
    auth.add_argument("--client-secret", help="Falcon API client secret (or set FALCON_CLIENT_SECRET)")
    auth.add_argument("--region",        default="", help="Cloud region: us-1 (default), us-2, eu-1, us-gov-1")

    # Output
    out = parser.add_argument_group("output")
    out.add_argument("--json",     action="store_true", help="Output JSON")
    out.add_argument("--csv",      action="store_true", help="Output CSV")
    out.add_argument("-o", "--output", metavar="FILE",
                     help="Output file stem (omit extension). If both --json and --csv, "
                          "saves FILE.json and FILE.csv. If omitted, prints to stdout.")
    out.add_argument("--severity", choices=["critical", "high", "medium", "low"],
                     help="Filter by severity")

    args = parser.parse_args()

    # Default to table if no output format specified
    if not args.json and not args.csv:
        args.json = False
        args.csv  = False
        show_table = True
    else:
        show_table = False

    client_id, client_secret, base_url = resolve_credentials(args)

    print(f"Connecting to {base_url} ...", file=sys.stderr)
    cp = CloudPolicies(client_id=client_id, client_secret=client_secret, base_url=base_url)

    print("Fetching cloud risk rules ...", file=sys.stderr)
    rules, total = fetch_cloud_risk_rules(cp)
    print(f"Retrieved {len(rules)} of {total} rules.", file=sys.stderr)

    # Severity filter
    if args.severity:
        sev_int = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.severity]
        rules = [r for r in rules if r.get("severity") == sev_int]
        print(f"Filtered to {len(rules)} {args.severity} rules.", file=sys.stderr)

    rules = sort_rules(rules)

    if show_table:
        print_table(rules)
        return

    if args.json:
        dest = f"{args.output}.json" if args.output else sys.stdout
        write_json(rules, dest)

    if args.csv:
        dest = f"{args.output}.csv" if args.output else sys.stdout
        write_csv(rules, dest)


if __name__ == "__main__":
    main()
