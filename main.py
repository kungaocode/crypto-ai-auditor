#!/usr/bin/env python3
"""
AI-Assisted Cryptographic Code Security Auditor
Entrypoint: runs static analysis, LLM triage, and report generation.
"""

import argparse
import sys
from pathlib import Path

from analyzer.semgrep_runner import run_semgrep
from analyzer.ast_scanner import run_ast_scan
from analyzer.parser import extract_context
from agent.agent import SecurityAgent
from evaluation.report_generator import generate_report

DEFAULT_RULES_DIR = Path(__file__).parent / "rules"
DEFAULT_OUTPUT_DIR = Path(__file__).parent / "reports"
DEFAULT_CONFIG_PATH = Path(__file__).parent / "configs" / "benchmark.yaml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cryptographic code security auditor (Semgrep + AST + LLM Agent)"
    )
    parser.add_argument(
        "--input", "-i", type=Path, default=None,
        help="Path to a Python file or directory to audit"
    )
    parser.add_argument(
        "--rules", "-r", type=Path, default=DEFAULT_RULES_DIR,
        help="Path to Semgrep rules directory (default: ./rules)"
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=DEFAULT_OUTPUT_DIR,
        help="Output directory for reports (default: ./reports)"
    )
    parser.add_argument(
        "--format", "-f", choices=["json", "md"], default="md",
        help="Report format (default: md)"
    )
    parser.add_argument(
        "--benchmark", action="store_true",
        help="Run benchmark mode against a labeled test set"
    )
    parser.add_argument(
        "--config", type=Path,
        help="Path to a YAML config file for model / pipeline settings"
    )
    parser.add_argument(
        "--no-ast", action="store_true",
        help="Skip the AST-based scanner (legacy security module)"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.input is None and not args.benchmark:
        print("[!] --input/-i is required unless --benchmark is used.")
        return 1

    if args.benchmark:
        from evaluation.benchmark import run_benchmark
        cfg_path = args.config or DEFAULT_CONFIG_PATH
        if not Path(cfg_path).exists():
            print(f"[!] Benchmark needs a config file; none found at {cfg_path}")
            print("    Copy configs/benchmark.yaml and point --config at it.")
            return 1
        run_benchmark(Path(cfg_path), out_dir=DEFAULT_OUTPUT_DIR / "benchmark")
        return 0

    findings: list[dict] = []

    # 1a. Semgrep static analysis
    print(f"[*] Running Semgrep on {args.input} ...")
    findings.extend(run_semgrep(args.input, args.rules))
    print(f"[*] Semgrep raw findings: {len(findings)}")

    # 1b. AST-based scanner (legacy security module)
    if not args.no_ast:
        print(f"[*] Running AST scanner on {args.input} ...")
        ast_findings = run_ast_scan(args.input)
        print(f"[*] AST raw findings: {len(ast_findings)}")
        findings.extend(ast_findings)

    # 2. Context extraction
    print("[*] Extracting AST context ...")
    for f in findings:
        f["context"] = extract_context(f)

    # 3. LLM Agent triage
    print("[*] Running Security Agent ...")
    agent = SecurityAgent(config_path=args.config)
    verdicts = agent.triage(findings)

    # 4. Report generation
    print(f"[*] Generating {args.format} report ...")
    generate_report(verdicts, args.output, fmt=args.format)

    print("[+] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
