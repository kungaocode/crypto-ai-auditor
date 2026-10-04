#!/usr/bin/env python3
"""Merge successful model-audit retries and rebuild the Round-6 review queue."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.audit_real_crypto_with_llm import (  # noqa: E402
    DEFAULT_ADVISORY_DIR,
    DEFAULT_COST_REPORT,
    DEFAULT_MODEL_OUT,
    DEFAULT_QUEUE_OUT,
    _actual_cost,
    _actual_usage,
    _atomic_write_json,
    _display_path,
    _load_jsonl,
    _resolve_output,
    _write_jsonl,
    build_cost_report,
    build_queue,
    enrich_candidates_with_local_advisories,
)


DEFAULT_CANDIDATES = ROOT / "data/round6/candidates/real_crypto_candidates_a_functions.jsonl"


def _resolve_path(path: str | Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else ROOT / value


def _candidate_map(candidates: list[dict[str, Any]]) -> tuple[list[str], dict[str, dict[str, Any]]]:
    order: list[str] = []
    rows: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        candidate_id = str(candidate.get("candidate_id") or "").strip()
        if not candidate_id:
            raise ValueError("candidate file contains an empty candidate_id")
        if candidate_id in rows:
            raise ValueError(f"duplicate candidate_id in candidate file: {candidate_id}")
        order.append(candidate_id)
        rows[candidate_id] = candidate
    if not order:
        raise ValueError("candidate file is empty")
    return order, rows


def _audit_map(rows: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    audits: dict[str, dict[str, Any]] = {}
    for row in rows:
        candidate_id = str(row.get("candidate_id") or "").strip()
        if not candidate_id:
            raise ValueError(f"{label} contains an empty candidate_id")
        if candidate_id in audits:
            raise ValueError(f"{label} contains duplicate candidate_id: {candidate_id}")
        audits[candidate_id] = row
    return audits


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge a successful retry audit into the main Round-6 model audit."
    )
    parser.add_argument("--candidates", default=str(DEFAULT_CANDIDATES))
    parser.add_argument("--model-audit", default=str(DEFAULT_MODEL_OUT))
    parser.add_argument("--model-out", default=None, help="defaults to --model-audit")
    parser.add_argument("--retry-audit", required=True)
    parser.add_argument("--queue-out", default=str(DEFAULT_QUEUE_OUT))
    parser.add_argument("--cost-report-out", default=str(DEFAULT_COST_REPORT))
    parser.add_argument("--advisory-dir", default=str(DEFAULT_ADVISORY_DIR))
    parser.add_argument("--max-advisory-chars", type=int, default=12000)
    parser.add_argument("--model", default="kimi-k2.7-code")
    parser.add_argument("--reasoning-effort", default="high")
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    parser.add_argument("--assumed-output-tokens", type=int, default=800)
    parser.add_argument("--assumed-reasoning-tokens", type=int, default=4096)
    parser.add_argument("--max-code-chars", type=int, default=50000)
    parser.add_argument("--min-confidence", type=float, default=0.80)
    parser.add_argument("--sample-rate", type=float, default=0.15)
    parser.add_argument("--sample-seed", default="round6-kimi-audit-v1")
    parser.add_argument("--price-input", type=float, default=None)
    parser.add_argument("--price-output", type=float, default=None)
    parser.add_argument("--backup", action="store_true", help="keep a pre-merge copy of model-audit")
    parser.add_argument("--dry-run", action="store_true", help="validate and report without writing")
    args = parser.parse_args(argv)

    if (args.price_input is None) != (args.price_output is None):
        parser.error("--price-input and --price-output must be supplied together")
    if args.price_input is not None and (args.price_input < 0 or args.price_output < 0):
        parser.error("prices must be non-negative")
    if args.max_advisory_chars < 1:
        parser.error("--max-advisory-chars must be positive")
    if not 0 <= args.min_confidence <= 1:
        parser.error("--min-confidence must be between 0 and 1")
    if not 0 <= args.sample_rate <= 1:
        parser.error("--sample-rate must be between 0 and 1")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    candidates_path = _resolve_path(args.candidates)
    model_audit_path = _resolve_path(args.model_audit)
    retry_audit_path = _resolve_path(args.retry_audit)
    model_out_path = _resolve_path(args.model_out or args.model_audit)
    queue_out_path = _resolve_path(args.queue_out)
    cost_report_path = _resolve_path(args.cost_report_out)
    advisory_dir = _resolve_path(args.advisory_dir)

    try:
        candidates = _load_jsonl(candidates_path)
        candidate_order, candidates_by_id = _candidate_map(candidates)
        main_audits = _audit_map(_load_jsonl(model_audit_path), "model audit")
        retry_audits = _audit_map(_load_jsonl(retry_audit_path), "retry audit")
    except (OSError, ValueError) as exc:
        print(f"[merge] {exc}", file=sys.stderr)
        return 1

    unknown_main = sorted(set(main_audits) - set(candidates_by_id))
    if unknown_main:
        print(
            "[merge] main audit contains candidate_id absent from the candidate file: "
            + ", ".join(unknown_main[:20]),
            file=sys.stderr,
        )
        return 1
    unknown_retry = sorted(set(retry_audits) - set(candidates_by_id))
    if unknown_retry:
        print(
            "[merge] retry audit contains unknown candidate_id: " + ", ".join(unknown_retry),
            file=sys.stderr,
        )
        return 1
    missing_from_main = sorted(set(retry_audits) - set(main_audits))
    if missing_from_main:
        print(
            "[merge] retry audit contains candidates absent from the main audit: "
            + ", ".join(missing_from_main),
            file=sys.stderr,
        )
        return 1

    failed = sorted(
        candidate_id
        for candidate_id, audit in retry_audits.items()
        if str(audit.get("error") or "").strip()
    )
    if failed:
        print(
            "[merge] refusing to merge retry rows that still contain errors: " + ", ".join(failed),
            file=sys.stderr,
        )
        return 1

    merged = dict(main_audits)
    merged.update(retry_audits)
    audited_order = [candidate_id for candidate_id in candidate_order if candidate_id in merged]
    audited_candidates = [candidates_by_id[candidate_id] for candidate_id in audited_order]

    try:
        advisory_counts = enrich_candidates_with_local_advisories(
            audited_candidates,
            advisory_dir=advisory_dir,
            max_advisory_chars=args.max_advisory_chars,
        )
    except OSError as exc:
        print(f"[merge] cannot read advisory directory: {exc}", file=sys.stderr)
        return 1

    queue_args = SimpleNamespace(
        min_confidence=args.min_confidence,
        sample_rate=args.sample_rate,
        sample_seed=args.sample_seed,
    )
    queue = build_queue(audited_candidates, merged, queue_args)

    cost_args = SimpleNamespace(
        model=args.model,
        reasoning_effort=args.reasoning_effort,
        candidates_path=candidates_path,
        price_input=args.price_input,
        price_output=args.price_output,
        max_output_tokens=args.max_output_tokens,
        assumed_output_tokens=args.assumed_output_tokens,
        assumed_reasoning_tokens=args.assumed_reasoning_tokens,
        max_code_chars=args.max_code_chars,
    )
    cost_report = build_cost_report(audited_candidates, cost_args)
    actual_usage = _actual_usage(merged, audited_candidates)
    cost_report["actual_usage"] = actual_usage
    cost_report["actual_cost"] = _actual_cost(actual_usage, cost_args)
    cost_report["merged_retry_ids"] = sorted(retry_audits)

    summary = {
        "candidate_path": _display_path(candidates_path),
        "model_audit": _display_path(model_audit_path),
        "retry_audit": _display_path(retry_audit_path),
        "model_out": _display_path(model_out_path),
        "queue_out": _display_path(queue_out_path),
        "cost_report_out": _display_path(cost_report_path),
        "merged_retry_ids": sorted(retry_audits),
        "advisory_evidence": advisory_counts,
        "audited": len(merged),
        "queued_for_human_review": len(queue),
        "actual_cost": cost_report["actual_cost"],
        "dry_run": args.dry_run,
    }

    if not args.dry_run:
        if args.backup and model_out_path == model_audit_path and model_audit_path.exists():
            backup_path = model_audit_path.with_name(
                f"{model_audit_path.stem}.pre_retry_merge{model_audit_path.suffix}"
            )
            shutil.copyfile(model_audit_path, backup_path)
            summary["backup"] = _display_path(backup_path)
        _write_jsonl(model_out_path, [merged[candidate_id] for candidate_id in audited_order])
        _write_jsonl(queue_out_path, queue)
        _atomic_write_json(cost_report_path, cost_report)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("[merge] model results remain verified=false; human review is still required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
