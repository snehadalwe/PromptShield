"""PromptShield Command Line Interface (CLI).

=============================================================================
CONCEPT: Ethical Pentesting & Safe Operations
=============================================================================
Penetration testing tools must enforce ethical boundaries:
1. Explicit Authorization Check: Prevents accidental or unauthorized scanning.
2. Configurable Rate-Limiting: Avoids Denial-of-Service (DoS) on target servers.
3. CI/CD Risk Gating: Exits with non-zero status code if risk exceeds a threshold.
"""

import sys
import os
import argparse
from pathlib import Path
from typing import Optional

# Ensure promptshield package is resolvable regardless of how CLI is invoked
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Fix Windows cp1252 terminal unicode encoding issues
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from promptshield.attacks.loader import AttackLoader
from promptshield.targets.demo_adapter import DemoTargetAdapter
from promptshield.targets.http_adapter import GenericRestAdapter
from promptshield.targets.openai_adapter import OpenAITargetAdapter
from promptshield.scanner import PromptShieldScanner
from promptshield.scoring.calculator import ScoreCalculator
from promptshield.scoring.models import ScanSummary
from promptshield.reports.json_reporter import JsonReporter
from promptshield.reports.markdown_reporter import MarkdownReporter
from promptshield.reports.html_reporter import HtmlReporter
from promptshield.detectors.base import DetectionStatus


def verify_authorization(agree_authorized: bool = False) -> None:
    """Enforces ethical confirmation prior to launching security probes."""
    if agree_authorized:
        return

    banner = """
==============================================================================
             🧬  PROMPTSHIELD LEGAL & ETHICAL NOTICE  🧬
==============================================================================
 PromptShield is an automated security audit framework intended STRICTLY
 for testing chatbots that you own or have explicit, documented authorization
 to assess. 

 Running security scans against systems without consent is illegal and 
 violates cybercrime laws.
==============================================================================
"""
    print(banner)
    try:
        response = input("Confirm you possess written authorization to test this target? (y/N): ").strip().lower()
        if response not in ["y", "yes"]:
            print("\n[!] Scan aborted by user. Exiting.")
            sys.exit(0)
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Aborted.")
        sys.exit(0)


def cmd_scan(args: argparse.Namespace) -> None:
    """Executes a security scan against a designated target."""
    verify_authorization(agree_authorized=args.agree_authorized)

    # 1. Resolve Target Adapter
    if args.target == "demo-weak":
        target = DemoTargetAdapter(mode="weak", use_mock=not args.live)
    elif args.target == "demo-hardened":
        target = DemoTargetAdapter(mode="hardened", use_mock=not args.live)
    elif args.target == "http":
        if not args.url:
            print("[!] Error: --url is required when using --target http")
            sys.exit(1)
        target = GenericRestAdapter(
            name="Custom-REST-Target",
            url=args.url,
            prompt_field=args.prompt_field,
            response_extractor=args.response_path,
        )
    elif args.target == "openai":
        target = OpenAITargetAdapter(
            name="OpenAI-Target",
            api_base=args.url or "https://api.openai.com/v1",
            api_key=os.getenv("OPENAI_API_KEY"),
            model=args.model or "gpt-3.5-turbo",
        )
    else:
        print(f"[!] Unknown target: {args.target}")
        sys.exit(1)

    # 2. Load Attacks
    loader = AttackLoader()
    attacks = loader.load_all(category=args.attacks)
    if not attacks:
        print(f"[!] No attack probes found matching criteria (category: {args.attacks})")
        sys.exit(1)

    print(f"\n[*] Target: {target.name}")
    print(f"[*] Loaded: {len(attacks)} audit test case(s)")
    print(f"[*] Threads: {args.threads} | Rate-limit delay: {args.delay}s\n")
    print("-" * 75)

    def on_progress(completed: int, total: int, res) -> None:
        if res.status == DetectionStatus.PASS:
            icon = "[PASS]"
            color_code = "\033[92m"
        elif res.status == DetectionStatus.FAIL:
            icon = "[FAIL]"
            color_code = "\033[91m"
        else:
            icon = "[UNCERTAIN]"
            color_code = "\033[93m"
        reset_code = "\033[0m"
        print(f"[{completed:02d}/{total:02d}] {color_code}{icon}{reset_code} [{res.severity.value.upper()}] {res.attack_id}: {res.attack_name}")

    # 3. Execute Scan
    scanner = PromptShieldScanner(
        target=target,
        delay_seconds=args.delay,
        max_workers=args.threads,
    )
    summary = scanner.run_scan(attacks, progress_callback=on_progress)

    print("-" * 75)
    print("\n" + "=" * 55)
    print(" 🧬 SCAN COMPLETED - EXECUTIVE SUMMARY")
    print("=" * 55)
    print(f" Target:                 {summary.target_name}")
    print(f" Security Grade:         {summary.letter_grade}")
    print(f" Vulnerability Risk:     {summary.risk_score} / 100")
    print(f" Attack Defense Rate:    {summary.attack_defense_rate_pct}% ({summary.adversarial_defended}/{summary.adversarial_probes} repelled)")
    print(f" Confirmed Vulns:        {summary.confirmed_vulnerabilities}")
    print(f" Control Benchmarks:     {summary.control_benchmarks_passed}/{summary.control_benchmarks_total} passed ({summary.control_pass_rate_pct}%)")
    print(f" Total Cases Evaluated:  {summary.total_cases}")
    print(f" Average Latency:        {summary.avg_latency_ms} ms")
    print("=" * 55 + "\n")

    # 4. Generate Reports
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target_clean_name = args.target.replace("-", "_")

    if args.report in ["json", "all"]:
        p = out_dir / f"{target_clean_name}_scan.json"
        JsonReporter.generate(summary, p)
        print(f"[+] JSON report saved:     {p}")

    if args.report in ["md", "markdown", "all"]:
        p = out_dir / f"{target_clean_name}_report.md"
        MarkdownReporter.generate(summary, p)
        print(f"[+] Markdown report saved: {p}")

    if args.report in ["html", "all"]:
        p = out_dir / f"{target_clean_name}_report.html"
        HtmlReporter.generate(summary, p)
        print(f"[+] HTML report saved:     {p}")

    # 5. CI/CD Risk Threshold Gate
    if args.fail_on_risk is not None:
        if summary.risk_score > args.fail_on_risk:
            print(f"\n[!] CI/CD Gate Failed: Risk Score ({summary.risk_score}) exceeded allowed threshold ({args.fail_on_risk})!")
            sys.exit(1)
        else:
            print(f"\n[+] CI/CD Gate Passed: Risk Score ({summary.risk_score}) <= threshold ({args.fail_on_risk}).")


def cmd_compare(args: argparse.Namespace) -> None:
    """Compares baseline vs candidate JSON scan reports to show security improvement."""
    import json
    baseline_path = Path(args.baseline)
    candidate_path = Path(args.candidate)

    if not baseline_path.exists() or not candidate_path.exists():
        print(f"[!] Error: Both files must exist: '{baseline_path}', '{candidate_path}'")
        sys.exit(1)

    with open(baseline_path, "r", encoding="utf-8") as f:
        base_summary = ScanSummary(**json.load(f))

    with open(candidate_path, "r", encoding="utf-8") as f:
        cand_summary = ScanSummary(**json.load(f))

    diff = ScoreCalculator.compare(base_summary, cand_summary)

    print("\n" + "=" * 65)
    print(" 🧬 PROMPTSHIELD COMPARATIVE BENCHMARK REPORT")
    print("=" * 65)
    print(f" Baseline Target:     {diff.baseline_target} (Grade: {diff.baseline_grade}, Risk: {diff.baseline_risk_score})")
    print(f" Candidate Target:    {diff.candidate_target} (Grade: {diff.candidate_grade}, Risk: {diff.candidate_risk_score})")
    print(f" Risk Reduction:      {diff.risk_reduction_pct}% improvement")
    print("-" * 65)
    print(f" 🧬 Vulnerabilities Remediated ({len(diff.vulnerabilities_remediated)}):")
    for item in diff.vulnerabilities_remediated:
        print(f"   ✓ {item}")
    if not diff.vulnerabilities_remediated:
        print("   (None)")

    if getattr(diff, "persisting_vulnerabilities", None):
        print(f"\n ⚠️  Persisting Vulnerabilities ({len(diff.persisting_vulnerabilities)}):")
        for item in diff.persisting_vulnerabilities:
            print(f"   ! {item}")

    if getattr(diff, "regressed_vulnerabilities", None):
        print(f"\n 🚨 Regressed Vulnerabilities ({len(diff.regressed_vulnerabilities)}):")
        for item in diff.regressed_vulnerabilities:
            print(f"   ✗ {item}")

    print(f"\n 🚨 Total Remaining Vulnerabilities ({len(diff.remaining_vulnerabilities)}):")
    for item in diff.remaining_vulnerabilities:
        print(f"   ✗ {item}")
    if not diff.remaining_vulnerabilities:
        print("   ✓ None! Target is completely hardened.")
    print("=" * 65 + "\n")


def cmd_server(args: argparse.Namespace) -> None:
    """Launches the Demo Target REST API server."""
    from promptshield.demo_target.server import run_server
    run_server(host=args.host, port=args.port)


def build_parser() -> argparse.ArgumentParser:
    """Builds the argument parser for PromptShield."""
    parser = argparse.ArgumentParser(
        prog="promptshield",
        description="PromptShield: Automated Prompt Injection Security Assessment Framework for AI Chatbots.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: scan
    scan_parser = subparsers.add_parser("scan", help="Run an automated security audit scan against a chatbot.")
    scan_parser.add_argument("--target", default="demo-weak", choices=["demo-weak", "demo-hardened", "http", "openai"], help="Target chatbot adapter to audit.")
    scan_parser.add_argument("--url", default="http://127.0.0.1:5000/chat", help="Target URL when using http adapter.")
    scan_parser.add_argument("--prompt-field", default="message", help="JSON field for prompt in HTTP requests.")
    scan_parser.add_argument("--response-path", default="response", help="Dot-notation path to extract response in JSON.")
    scan_parser.add_argument("--attacks", default="all", help="Attack category or specific attack ID to run, or 'all'.")
    scan_parser.add_argument("--report", default="all", choices=["all", "html", "json", "md"], help="Report formats to generate.")
    scan_parser.add_argument("--output-dir", default="reports_output", help="Directory where reports are stored.")
    scan_parser.add_argument("--threads", type=int, default=2, help="Number of concurrent worker threads.")
    scan_parser.add_argument("--delay", type=float, default=0.05, help="Delay in seconds between requests.")
    scan_parser.add_argument("--live", action="store_true", help="Use live LLM API instead of mock engine for demo target.")
    scan_parser.add_argument("--model", default="gpt-3.5-turbo", help="Model name for OpenAI adapter.")
    scan_parser.add_argument("--agree-authorized", action="store_true", help="Bypass interactive authorization disclaimer for CI.")
    scan_parser.add_argument("--fail-on-risk", type=float, default=None, help="Exit code 1 if Risk Score > threshold (for CI/CD).")

    # Subcommand: compare
    compare_parser = subparsers.add_parser("compare", help="Compare two scan result JSON files (e.g. Weak vs Hardened).")
    compare_parser.add_argument("--baseline", required=True, help="Path to baseline JSON report (e.g. weak_bot.json)")
    compare_parser.add_argument("--candidate", required=True, help="Path to candidate JSON report (e.g. hardened_bot.json)")

    # Subcommand: demo-server
    server_parser = subparsers.add_parser("demo-server", help="Launch the local Demo Target HTTP server.")
    server_parser.add_argument("--host", default="127.0.0.1", help="Server host IP")
    server_parser.add_argument("--port", type=int, default=5000, help="Server port")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "compare":
        cmd_compare(args)
    elif args.command == "demo-server":
        cmd_server(args)


if __name__ == "__main__":
    main()
