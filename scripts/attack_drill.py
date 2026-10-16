#!/usr/bin/env python3
"""
===============================================================================
PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner
SMG Cloud Armor Enterprise WAF + Layer 7 DDoS Mitigation & OWASP Top 10 Drill
File: scripts/attack_drill.py
===============================================================================
Interactive & Automated Live Attack Simulation CLI tool.
Executes 6 live scenarios against the Global External Application Load Balancer:
  1. Benign Enterprise Traffic       -> Expect HTTP 200 OK
  2. SQL Injection (SQLi) Attack     -> Expect HTTP 403 Forbidden (Priority 1000)
  3. Cross-Site Scripting (XSS)      -> Expect HTTP 403 Forbidden (Priority 1010)
  4. Path Traversal / LFI Attack     -> Expect HTTP 403 Forbidden (Priority 1020)
  5. Remote Code Execution (RCE)     -> Expect HTTP 403 Forbidden (Priority 1030)
  6. Layer 7 Rapid Flood / DDoS      -> Expect HTTP 429 Too Many Requests (Priority 2000)
===============================================================================
"""

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Terminal ANSI Color Formatting
# ---------------------------------------------------------------------------
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
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"


@dataclass
class DrillResult:
    stage_id: int
    name: str
    category: str
    payload_display: str
    endpoint: str
    expected_status: int
    actual_status: int
    passed: bool
    mitigated: bool
    latency_ms: float
    rule_priority: str
    notes: str


def print_banner(target_url: str) -> None:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"{Color.CYAN}{Color.BOLD}" + "=" * 88 + f"{Color.RESET}")
    print(
        f"{Color.CYAN}{Color.BOLD}  PT SMARTNET MAGNA GLOBAL (SMG) | GOOGLE CLOUD PREMIER PARTNER{Color.RESET}"
    )
    print(
        f"{Color.WHITE}{Color.BOLD}  CLOUD ARMOR ENTERPRISE WAF + LAYER 7 DDoS & OWASP TOP 10 LIVE DRILL{Color.RESET}"
    )
    print(f"{Color.CYAN}{Color.BOLD}" + "=" * 88 + f"{Color.RESET}")
    print(f"  {Color.BOLD}Target Load Balancer :{Color.RESET} {Color.YELLOW}{target_url}{Color.RESET}")
    print(f"  {Color.BOLD}Security Policy      :{Color.RESET} {Color.GREEN}smg-armor-waf-policy (CRS v3.3 + L7 Rate Ban){Color.RESET}")
    print(f"  {Color.BOLD}Timestamp            :{Color.RESET} {now_str}")
    print(f"{Color.CYAN}" + "-" * 88 + f"{Color.RESET}\n")


def resolve_target_url(cli_target: Optional[str]) -> str:
    """Resolve target Load Balancer URL from CLI arg, env var, or Terraform output."""
    target = cli_target or os.environ.get("TARGET_URL") or os.environ.get("LB_IP")
    if not target:
        try:
            proc = subprocess.run(
                ["terraform", "output", "-raw", "lb_external_ip"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                target = proc.stdout.strip()
        except Exception:
            pass

    if not target:
        print(
            f"{Color.RED}{Color.BOLD}[ERROR]{Color.RESET} Unable to auto-detect Load Balancer IP."
        )
        print(
            f"Please specify `--target http://<LB_IP>` or run `terraform apply` first."
        )
        sys.exit(1)

    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{target}"
    return target.rstrip("/")


def send_http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: float = 10.0,
) -> Tuple[int, float, str]:
    """Send an HTTP request and return (status_code, latency_ms, response_snippet)."""
    req_headers = {
        "User-Agent": "SMG-Security-Drill-Agent/2.0 (Enterprise-WAF-Validation)",
        "Accept": "application/json, text/html, */*",
    }
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = (time.perf_counter() - start) * 1000.0
            status = resp.getcode()
            raw = resp.read(256).decode("utf-8", errors="replace")
            return status, latency_ms, raw
    except urllib.error.HTTPError as http_err:
        latency_ms = (time.perf_counter() - start) * 1000.0
        raw = ""
        try:
            raw = http_err.read(256).decode("utf-8", errors="replace")
        except Exception:
            pass
        return http_err.code, latency_ms, raw
    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000.0
        return 0, latency_ms, str(exc)


def execute_single_scenario(
    stage_id: int,
    name: str,
    category: str,
    payload_display: str,
    endpoint_path: str,
    full_url: str,
    expected_status: int,
    rule_priority: str,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> DrillResult:
    print(
        f"{Color.BOLD}{Color.BLUE}[STAGE {stage_id}/6]{Color.RESET} "
        f"{Color.BOLD}{name}{Color.RESET} ({Color.CYAN}{category}{Color.RESET})"
    )
    print(f"  ├─ {Color.DIM}Endpoint :{Color.RESET} {method} {endpoint_path}")
    print(f"  ├─ {Color.DIM}Payload  :{Color.RESET} {Color.YELLOW}{payload_display}{Color.RESET}")
    print(f"  ├─ {Color.DIM}Rule Ref :{Color.RESET} Priority {rule_priority}")

    actual_status, latency_ms, snippet = send_http_request(
        full_url, method=method, headers=headers, body=body
    )

    passed = actual_status == expected_status
    # If testing Benign Traffic while IP is still under a 300s rate_based_ban (HTTP 429), explain clearly
    notes = ""
    if stage_id == 1 and actual_status == 200:
        notes = "Allowed to Backend MIG (HTTP 200 OK)"
        mitigated = False
    elif stage_id == 1 and actual_status == 429:
        notes = "Client IP currently in active 300s rate_based_ban window (HTTP 429)"
        mitigated = True
    elif actual_status == 403:
        notes = "Blocked at Google Edge by Cloud Armor WAF (HTTP 403 Forbidden)"
        mitigated = True
    elif actual_status == 429:
        notes = "Throttled/Banned by Cloud Armor Rate Limiting (HTTP 429)"
        mitigated = True
    else:
        notes = f"Unexpected HTTP {actual_status}: {snippet[:60].strip()}"
        mitigated = False

    status_badge = (
        f"{Color.GREEN}{Color.BOLD}PASS (HTTP {actual_status} == Expect {expected_status}){Color.RESET}"
        if passed
        else f"{Color.RED}{Color.BOLD}FAIL (HTTP {actual_status} != Expect {expected_status}){Color.RESET}"
    )

    print(f"  ├─ {Color.DIM}Latency  :{Color.RESET} {latency_ms:.1f} ms")
    print(f"  ├─ {Color.DIM}Action   :{Color.RESET} {notes}")
    print(f"  └─ {Color.DIM}Result   :{Color.RESET} {status_badge}\n")

    return DrillResult(
        stage_id=stage_id,
        name=name,
        category=category,
        payload_display=payload_display,
        endpoint=f"{method} {endpoint_path}",
        expected_status=expected_status,
        actual_status=actual_status,
        passed=passed,
        mitigated=mitigated,
        latency_ms=latency_ms,
        rule_priority=rule_priority,
        notes=notes,
    )


def execute_ddos_flood_scenario(
    base_url: str, flood_requests: int = 85, concurrency: int = 20
) -> DrillResult:
    stage_id = 6
    name = "L7 Rapid Flood / DDoS Attack"
    category = "Layer 7 Volumetric Flood"
    endpoint_path = "/api/search?q=flood_probe"
    rule_priority = "2000 (rate_based_ban: 50 req/min)"
    payload_display = f"{flood_requests} rapid burst requests ({concurrency} concurrent threads)"

    print(
        f"{Color.BOLD}{Color.BLUE}[STAGE {stage_id}/6]{Color.RESET} "
        f"{Color.BOLD}{name}{Color.RESET} ({Color.CYAN}{category}{Color.RESET})"
    )
    print(f"  ├─ {Color.DIM}Endpoint :{Color.RESET} GET {endpoint_path}")
    print(f"  ├─ {Color.DIM}Payload  :{Color.RESET} {Color.YELLOW}{payload_display}{Color.RESET}")
    print(f"  ├─ {Color.DIM}Rule Ref :{Color.RESET} Priority {rule_priority}")
    print(f"  ├─ {Color.DIM}Progress :{Color.RESET} ", end="", flush=True)

    status_counts: Dict[int, int] = {}
    latencies: List[float] = []
    start_flood = time.perf_counter()

    def _worker(idx: int) -> Tuple[int, float]:
        url = f"{base_url}/api/search?q=smg_flood_burst_{idx}"
        code, lat, _ = send_http_request(url, timeout=8.0)
        return code, lat

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_worker, i) for i in range(1, flood_requests + 1)]
        for idx, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            code, lat = fut.result()
            status_counts[code] = status_counts.get(code, 0) + 1
            latencies.append(lat)
            if idx % 5 == 0 or idx == flood_requests:
                char = (
                    f"{Color.RED}#{Color.RESET}"
                    if code == 429
                    else f"{Color.GREEN}.{Color.RESET}"
                )
                print(char, end="", flush=True)

    total_time_s = time.perf_counter() - start_flood
    print()

    count_200 = status_counts.get(200, 0)
    count_429 = status_counts.get(429, 0)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    # Verify ban enforcement with one final confirmation request
    final_code, _, _ = send_http_request(f"{base_url}/api/search?q=post_flood_verify")
    if final_code == 429:
        count_429 += 1

    triggered_429 = count_429 > 0 or final_code == 429
    actual_status = 429 if triggered_429 else (200 if count_200 > 0 else 0)
    passed = actual_status == 429

    notes = (
        f"Burst completed in {total_time_s:.1f}s | Allowed (200): {count_200}, "
        f"Rate-Banned (429): {count_429} (300s IP Ban Active)"
    )
    status_badge = (
        f"{Color.GREEN}{Color.BOLD}PASS (HTTP 429 Triggered - L7 DDoS Mitigated){Color.RESET}"
        if passed
        else f"{Color.RED}{Color.BOLD}FAIL (HTTP 429 Not Triggered){Color.RESET}"
    )

    print(f"  ├─ {Color.DIM}Summary  :{Color.RESET} {notes}")
    print(f"  ├─ {Color.DIM}Avg Lat  :{Color.RESET} {avg_latency:.1f} ms")
    print(f"  └─ {Color.DIM}Result   :{Color.RESET} {status_badge}\n")

    return DrillResult(
        stage_id=stage_id,
        name=name,
        category=category,
        payload_display=f"Burst {flood_requests} reqs ({concurrency} threads)",
        endpoint=f"GET {endpoint_path}",
        expected_status=429,
        actual_status=actual_status,
        passed=passed,
        mitigated=passed,
        latency_ms=avg_latency,
        rule_priority="2000",
        notes=notes,
    )


def print_summary_table(results: List[DrillResult]) -> None:
    print(f"{Color.CYAN}{Color.BOLD}" + "=" * 108 + f"{Color.RESET}")
    print(
        f"{Color.WHITE}{Color.BOLD}  SMG CLOUD ARMOR ENTERPRISE WAF & LAYER 7 DDoS DRILL - EXECUTIVE SUMMARY REPORT{Color.RESET}"
    )
    print(f"{Color.CYAN}{Color.BOLD}" + "=" * 108 + f"{Color.RESET}")

    header = (
        f" {'#':<2} | {'Scenario Name':<28} | {'Rule Pri':<10} | "
        f"{'Expect':<8} | {'Actual':<8} | {'Latency':<9} | {'Status':<10} | {'Enforcement Action'}"
    )
    print(f"{Color.BOLD}{header}{Color.RESET}")
    print("-" * 108)

    for r in results:
        status_str = (
            f"{Color.GREEN}{Color.BOLD}PASSED{Color.RESET}"
            if r.passed
            else f"{Color.RED}{Color.BOLD}FAILED{Color.RESET}"
        )
        # Keep alignment with ANSI codes
        status_padded = status_str + (" " * 4)
        print(
            f" {r.stage_id:<2} | {r.name:<28} | {r.rule_priority:<10} | "
            f"HTTP {r.expected_status:<3} | HTTP {r.actual_status:<3} | "
            f"{r.latency_ms:>6.1f} ms | {status_padded} | {r.notes[:34]}"
        )

    print("-" * 108)

    attack_scenarios = [r for r in results if r.expected_status in (403, 429)]
    mitigated_attacks = [r for r in attack_scenarios if r.passed and r.mitigated]
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r.passed)

    mitigation_rate = (
        (len(mitigated_attacks) / len(attack_scenarios)) * 100.0
        if attack_scenarios
        else 100.0
    )
    overall_accuracy = (passed_tests / total_tests) * 100.0 if total_tests else 0.0

    rate_color = Color.GREEN if mitigation_rate == 100.0 else Color.YELLOW
    print(
        f"\n  {Color.BOLD}Attack Mitigation Rate (OWASP + L7 DDoS) :{Color.RESET} "
        f"{rate_color}{Color.BOLD}{mitigation_rate:.1f}% ({len(mitigated_attacks)}/{len(attack_scenarios)} Attack Vectors Blocked at Google Edge){Color.RESET}"
    )
    print(
        f"  {Color.BOLD}Overall Drill Verification Score         :{Color.RESET} "
        f"{Color.CYAN}{Color.BOLD}{overall_accuracy:.1f}% ({passed_tests}/{total_tests} Scenarios Matched Expected Behavior){Color.RESET}"
    )
    print(f"{Color.CYAN}{Color.BOLD}" + "=" * 108 + f"{Color.RESET}\n")


def run_all_scenarios(base_url: str, flood_count: int) -> List[DrillResult]:
    results: List[DrillResult] = []

    # 1. Benign Traffic -> Expect HTTP 200 OK
    q_benign = urllib.parse.quote_plus("cloud armor enterprise security")
    results.append(
        execute_single_scenario(
            stage_id=1,
            name="Benign Traffic",
            category="Legitimate User Request",
            payload_display="GET /api/search?q=cloud+armor+enterprise+security",
            endpoint_path=f"/api/search?q={q_benign}",
            full_url=f"{base_url}/api/search?q={q_benign}",
            expected_status=200,
            rule_priority="2147483647",
        )
    )

    # 2. SQL Injection Attack (' OR 1=1 --) -> Expect HTTP 403 Forbidden
    sqli_raw = "' OR 1=1 --"
    sqli_encoded = urllib.parse.quote(sqli_raw)
    results.append(
        execute_single_scenario(
            stage_id=2,
            name="SQL Injection (SQLi) Attack",
            category="OWASP A03:2021 Injection",
            payload_display=sqli_raw,
            endpoint_path=f"/api/search?q={sqli_encoded}",
            full_url=f"{base_url}/api/search?q={sqli_encoded}",
            expected_status=403,
            rule_priority="1000",
        )
    )

    # 3. XSS Attack (<script>alert('pwned')</script>) -> Expect HTTP 403 Forbidden
    xss_raw = "<script>alert('pwned')</script>"
    xss_encoded = urllib.parse.quote(xss_raw)
    results.append(
        execute_single_scenario(
            stage_id=3,
            name="Cross-Site Scripting (XSS)",
            category="OWASP A03:2021 XSS",
            payload_display=xss_raw,
            endpoint_path=f"/api/search?q={xss_encoded}",
            full_url=f"{base_url}/api/search?q={xss_encoded}",
            expected_status=403,
            rule_priority="1010",
        )
    )

    # 4. Path Traversal / LFI Attack (../../../../etc/passwd) -> Expect HTTP 403 Forbidden
    lfi_raw = "../../../../etc/passwd"
    lfi_encoded = urllib.parse.quote(lfi_raw, safe="/")
    results.append(
        execute_single_scenario(
            stage_id=4,
            name="Path Traversal / LFI Attack",
            category="OWASP A01:2021 File Inclusion",
            payload_display=lfi_raw,
            endpoint_path=f"/api/view?file={lfi_encoded}",
            full_url=f"{base_url}/api/view?file={lfi_encoded}",
            expected_status=403,
            rule_priority="1020",
        )
    )

    # 5. RCE Attack (cat /etc/passwd; id) -> Expect HTTP 403 Forbidden
    rce_raw = "cat /etc/passwd; id"
    rce_encoded = urllib.parse.quote(rce_raw)
    results.append(
        execute_single_scenario(
            stage_id=5,
            name="Remote Code Execution (RCE)",
            category="OWASP A03:2021 OS Command Inj",
            payload_display=rce_raw,
            endpoint_path=f"/api/comment?cmd={rce_encoded}",
            full_url=f"{base_url}/api/comment?cmd={rce_encoded}",
            expected_status=403,
            rule_priority="1030",
            method="POST",
            body=f"comment={rce_encoded}".encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    )

    # 6. L7 Rapid Flood / DDoS Attack -> Expect HTTP 429 Too Many Requests
    results.append(
        execute_ddos_flood_scenario(base_url=base_url, flood_requests=flood_count)
    )

    return results


def interactive_menu(base_url: str, flood_count: int) -> None:
    while True:
        print(f"{Color.BOLD}{Color.CYAN}Select Live Attack Drill Mode:{Color.RESET}")
        print(f"  {Color.YELLOW}[1]{Color.RESET} Run Complete 6-Stage OWASP Top 10 & L7 DDoS Drill (Recommended)")
        print(f"  {Color.YELLOW}[2]{Color.RESET} Stage 1 Only: Benign Traffic Verification (Expect 200 OK)")
        print(f"  {Color.YELLOW}[3]{Color.RESET} Stage 2 Only: SQL Injection (' OR 1=1 --) (Expect 403)")
        print(f"  {Color.YELLOW}[4]{Color.RESET} Stage 3 Only: Cross-Site Scripting (<script>alert('pwned')</script>) (Expect 403)")
        print(f"  {Color.YELLOW}[5]{Color.RESET} Stage 4 Only: Path Traversal / LFI (../../../../etc/passwd) (Expect 403)")
        print(f"  {Color.YELLOW}[6]{Color.RESET} Stage 5 Only: Remote Code Execution (cat /etc/passwd; id) (Expect 403)")
        print(f"  {Color.YELLOW}[7]{Color.RESET} Stage 6 Only: Layer 7 Rapid Flood / DDoS Burst (Expect 429)")
        print(f"  {Color.YELLOW}[q]{Color.RESET} Quit")

        try:
            choice = input(f"\n{Color.BOLD}Enter choice [1-7, q] (default=1): {Color.RESET}").strip().lower()
        except EOFError:
            choice = "1"

        if not choice or choice == "1":
            print()
            results = run_all_scenarios(base_url, flood_count)
            print_summary_table(results)
            break
        elif choice == "q":
            print("Exiting drill.")
            break
        elif choice in ("2", "3", "4", "5", "6", "7"):
            print()
            all_res = run_all_scenarios(base_url, flood_count)
            idx = int(choice) - 2
            print_summary_table([all_res[idx]])
        else:
            print(f"{Color.RED}Invalid selection.{Color.RESET}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SMG Cloud Armor Enterprise WAF & Layer 7 DDoS Live Attack Drill CLI"
    )
    parser.add_argument(
        "-t",
        "--target",
        help="Target Load Balancer IP or URL (auto-detected from Terraform if omitted)",
        default=None,
    )
    parser.add_argument(
        "-n",
        "--flood-count",
        type=int,
        default=85,
        help="Number of rapid requests to send in Stage 6 DDoS simulation (default: 85)",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Launch interactive menu selection before running drill stages",
    )
    args = parser.parse_args()

    base_url = resolve_target_url(args.target)
    print_banner(base_url)

    if args.interactive and sys.stdin.isatty():
        interactive_menu(base_url, args.flood_count)
    else:
        results = run_all_scenarios(base_url, args.flood_count)
        print_summary_table(results)


if __name__ == "__main__":
    main()
