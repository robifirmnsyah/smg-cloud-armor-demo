#!/usr/bin/env python3
"""
===============================================================================
PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner
SMG Cloud Armor Enterprise WAF + Layer 7 DDoS Mitigation & OWASP Top 10 Drill
File: scripts/verify_logs.py
===============================================================================
Real-time Google Cloud Armor Security Telemetry & Audit Log Inspector.
Queries Cloud Logging for HTTP Load Balancer entries enforced by Cloud Armor
and displays:
  - Timestamp
  - Client IP
  - Action (Configured Action + HTTP Status)
  - Matched Priority
  - Matched Rule ID (Preconfigured WAF Expression / Signature ID)
  - Target URL
===============================================================================
"""

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


PRIORITY_RULE_MAP = {
    "1000": "sqli-v33-stable (SQL Injection)",
    "1010": "xss-v33-stable (Cross-Site Scripting)",
    "1020": "lfi/rfi-v33-stable (File Inclusion)",
    "1030": "rce-v33-stable (Remote Code Execution)",
    "1040": "scannerdetection-v33-stable (Scanner)",
    "2000": "rate_based_ban (L7 DDoS Rate Limit)",
    "2147483647": "default-allow (Benign Traffic)",
}


def resolve_project_and_policy(
    cli_project: Optional[str], cli_policy: Optional[str]
) -> tuple[str, str]:
    project_id = cli_project or os.environ.get("PROJECT_ID") or "dev-robifirmansyah"
    policy_name = cli_policy or os.environ.get("SECURITY_POLICY_NAME")

    if not policy_name:
        try:
            proc = subprocess.run(
                ["terraform", "output", "-raw", "security_policy_name"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                policy_name = proc.stdout.strip()
        except Exception:
            pass

    if not policy_name:
        policy_name = "smg-armor-waf-policy"

    return project_id, policy_name


def fetch_cloud_armor_logs(
    project_id: str,
    policy_name: str,
    limit: int = 40,
    freshness: str = "30m",
    blocked_only: bool = False,
) -> List[Dict[str, Any]]:
    """Fetch Cloud Armor enforcedSecurityPolicy logs via gcloud logging read."""
    filter_parts = [
        'resource.type="http_load_balancer"',
        f'jsonPayload.enforcedSecurityPolicy.name="{policy_name}"',
    ]
    if blocked_only:
        filter_parts.append('jsonPayload.enforcedSecurityPolicy.outcome!="ALLOW"')

    log_filter = " AND ".join(filter_parts)

    cmd = [
        "gcloud",
        "logging",
        "read",
        log_filter,
        f"--project={project_id}",
        f"--limit={limit}",
        f"--freshness={freshness}",
        "--format=json",
    ]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, check=False
        )
        if proc.returncode != 0:
            print(
                f"{Color.RED}{Color.BOLD}[ERROR]{Color.RESET} gcloud logging read failed:\n{proc.stderr.strip()}"
            )
            sys.exit(1)
        raw_out = proc.stdout.strip()
        if not raw_out:
            return []
        return json.loads(raw_out)
    except json.JSONDecodeError as exc:
        print(f"{Color.RED}[ERROR]{Color.RESET} Failed to parse JSON output: {exc}")
        return []
    except Exception as exc:
        print(f"{Color.RED}[ERROR]{Color.RESET} Error invoking Cloud Logging: {exc}")
        sys.exit(1)


def parse_log_entry(entry: Dict[str, Any]) -> Dict[str, str]:
    timestamp_raw = entry.get("timestamp", "")
    try:
        dt = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
        timestamp_fmt = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        timestamp_fmt = timestamp_raw[:23]

    http_req = entry.get("httpRequest", {}) or {}
    client_ip = str(http_req.get("remoteIp", "N/A"))
    method = str(http_req.get("requestMethod", "GET"))
    target_url = str(http_req.get("requestUrl", "N/A"))
    status_code = str(http_req.get("status", "N/A"))

    json_payload = entry.get("jsonPayload", {}) or {}
    policy = json_payload.get("enforcedSecurityPolicy", {}) or {}

    priority = str(policy.get("priority", "N/A"))
    configured_action = str(policy.get("configuredAction", "N/A"))
    outcome = str(policy.get("outcome", configured_action))
    expr_ids = policy.get("preconfiguredExprIds", []) or []

    base_rule_name = PRIORITY_RULE_MAP.get(priority, policy.get("name", "custom-rule"))
    if expr_ids:
        matched_rule_id = f"{base_rule_name} [{', '.join(expr_ids)}]"
    else:
        matched_rule_id = base_rule_name

    action_display = f"{outcome} (HTTP {status_code})"
    if configured_action == "RATE_BASED_BAN" and outcome != "ALLOW":
        action_display = f"RATE_BAN (HTTP {status_code})"

    return {
        "timestamp": timestamp_fmt,
        "client_ip": client_ip,
        "action": action_display,
        "outcome": outcome,
        "status": status_code,
        "priority": priority,
        "rule_id": matched_rule_id,
        "method": method,
        "target_url": target_url,
    }


def print_audit_report(
    parsed_logs: List[Dict[str, str]], project_id: str, policy_name: str
) -> None:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"{Color.CYAN}{Color.BOLD}" + "=" * 120 + f"{Color.RESET}")
    print(
        f"{Color.CYAN}{Color.BOLD}  PT SMARTNET MAGNA GLOBAL (SMG) | GOOGLE CLOUD ARMOR REAL-TIME SECURITY AUDITOR{Color.RESET}"
    )
    print(f"{Color.CYAN}{Color.BOLD}" + "=" * 120 + f"{Color.RESET}")
    print(f"  {Color.BOLD}GCP Project ID  :{Color.RESET} {project_id}")
    print(f"  {Color.BOLD}Security Policy :{Color.RESET} {Color.GREEN}{policy_name}{Color.RESET}")
    print(f"  {Color.BOLD}Audit Time      :{Color.RESET} {now_str}")
    print(f"  {Color.BOLD}Entries Fetched :{Color.RESET} {len(parsed_logs)}")
    print(f"{Color.CYAN}" + "-" * 120 + f"{Color.RESET}\n")

    if not parsed_logs:
        print(
            f"  {Color.YELLOW}No Cloud Armor log entries found in the specified window.{Color.RESET}"
        )
        print(
            f"  {Color.DIM}Tip: Run `make attack-drill` first, wait ~10-15 seconds for log ingestion, then run `make verify-logs`.{Color.RESET}\n"
        )
        return

    header = (
        f" {'Timestamp (UTC)':<23} | {'Client IP':<15} | {'Priority':<10} | "
        f"{'Action':<19} | {'Matched Rule ID':<38} | {'Target URL'}"
    )
    print(f"{Color.BOLD}{header}{Color.RESET}")
    print("-" * 120)

    action_counter: Counter = Counter()
    rule_counter: Counter = Counter()

    for item in parsed_logs:
        action_raw = item["action"]
        if "DENY" in action_raw or "403" in action_raw:
            action_colored = f"{Color.RED}{Color.BOLD}{action_raw:<19}{Color.RESET}"
        elif "RATE_BAN" in action_raw or "429" in action_raw:
            action_colored = f"{Color.MAGENTA}{Color.BOLD}{action_raw:<19}{Color.RESET}"
        else:
            action_colored = f"{Color.GREEN}{action_raw:<19}{Color.RESET}"

        rule_short = (
            item["rule_id"][:36] + ".."
            if len(item["rule_id"]) > 38
            else item["rule_id"]
        )
        url_display = f"{item['method']} {item['target_url']}"
        if len(url_display) > 55:
            url_display = url_display[:52] + "..."

        print(
            f" {item['timestamp']:<23} | {item['client_ip']:<15} | "
            f"{item['priority']:<10} | {action_colored} | "
            f"{rule_short:<38} | {url_display}"
        )

        action_counter[item["action"]] += 1
        rule_counter[f"Priority {item['priority']} -> {PRIORITY_RULE_MAP.get(item['priority'], 'custom')}"] += 1

    print("-" * 120)
    print(f"\n{Color.BOLD}{Color.WHITE}  TELEMETRY BREAKDOWN BY MATCHED RULE PRIORITY:{Color.RESET}")
    for rule_desc, count in rule_counter.most_common():
        print(f"    • {rule_desc:<58} : {Color.BOLD}{count}{Color.RESET} event(s)")

    print(f"\n{Color.BOLD}{Color.WHITE}  TELEMETRY BREAKDOWN BY ENFORCEMENT ACTION:{Color.RESET}")
    for act, count in action_counter.most_common():
        color = Color.RED if ("DENY" in act or "RATE_BAN" in act) else Color.GREEN
        print(f"    • {color}{Color.BOLD}{act:<25}{Color.RESET} : {count} event(s)")

    print(f"{Color.CYAN}{Color.BOLD}" + "=" * 120 + f"{Color.RESET}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Google Cloud Armor Real-Time Audit Log Inspector (PT Smartnet Magna Global)"
    )
    parser.add_argument(
        "-p", "--project", default=None, help="GCP Project ID (default: dev-robifirmansyah)"
    )
    parser.add_argument(
        "-s",
        "--policy",
        default=None,
        help="Cloud Armor Security Policy Name (default: smg-armor-waf-policy)",
    )
    parser.add_argument(
        "-l",
        "--limit",
        type=int,
        default=40,
        help="Maximum number of log entries to retrieve (default: 40)",
    )
    parser.add_argument(
        "-f",
        "--freshness",
        default="30m",
        help="Log freshness window, e.g. 15m, 1h, 1d (default: 30m)",
    )
    parser.add_argument(
        "--blocked-only",
        action="store_true",
        help="Only show blocked/throttled security events (outcome != ALLOW)",
    )
    args = parser.parse_args()

    project_id, policy_name = resolve_project_and_policy(args.project, args.policy)
    entries = fetch_cloud_armor_logs(
        project_id=project_id,
        policy_name=policy_name,
        limit=args.limit,
        freshness=args.freshness,
        blocked_only=args.blocked_only,
    )
    parsed = [parse_log_entry(e) for e in entries]
    print_audit_report(parsed, project_id, policy_name)


if __name__ == "__main__":
    main()
