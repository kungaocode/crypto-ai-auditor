#!/usr/bin/env python3
"""Build a de-duplicated human-review queue from completed model audits."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CANDIDATES = ROOT / "data/round6/candidates/real_crypto_candidates_a_functions.jsonl"
DEFAULT_MODEL_AUDIT = ROOT / "data/round6/candidates/model_audit.jsonl"
DEFAULT_OUT = ROOT / "data/round6/candidates/real_crypto_candidates_remaining_review_queue.jsonl"
DEFAULT_REVIEW_ROOT = ROOT / "data/round6/review/web"
DEFAULT_DECISIONS = ("confirmed", "uncertain")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{number}: invalid JSON ({exc})") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{number}: expected a JSON object")
        rows.append(row)
    if not rows:
        raise ValueError(f"file is empty: {path}")
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    temp.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    temp.replace(path)


def index_by_candidate_id(rows: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        candidate_id = str(row.get("candidate_id") or "").strip()
        if not candidate_id:
            raise ValueError(f"{label} contains an empty candidate_id")
        if candidate_id in indexed:
            raise ValueError(f"{label} contains duplicate candidate_id: {candidate_id}")
        indexed[candidate_id] = row
    return indexed


def load_reviewed_ids(review_root: Path) -> set[str]:
    reviewed: set[str] = set()
    if not review_root.exists():
        return reviewed
    for path in review_root.glob("*/labels/*/*.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read review label {path}: {exc}") from exc
        item_id = str(record.get("id") or "").strip()
        if item_id:
            reviewed.add(item_id)
    return reviewed


def select_rows(
    candidates: list[dict[str, Any]],
    audits: dict[str, dict[str, Any]],
    reviewed: set[str],
    decisions: set[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for candidate in candidates:
        candidate_id = str(candidate["candidate_id"])
        audit = audits.get(candidate_id)
        if not audit or str(audit.get("decision") or "") not in decisions:
            continue
        if candidate_id in reviewed:
            continue

        row = dict(candidate)
        row["model_audit"] = audit
        row["review_selection"] = {
            "source": "model_audit",
            "decision": audit.get("decision", ""),
            "confidence": audit.get("confidence"),
            "rule_id": audit.get("rule_id", ""),
            "cwe": audit.get("cwe", ""),
            "reason": f"model-{audit.get('decision', 'unknown')}",
        }
        selected.append(row)

    selected.sort(
        key=lambda row: (
            0 if (row.get("model_audit") or {}).get("decision") == "uncertain" else 1,
            -float((row.get("model_audit") or {}).get("confidence") or 0.0),
            str(row.get("cwe") or ""),
            str(row["candidate_id"]),
        )
    )

    stats = {
        "selected": len(selected),
        "decisions": dict(Counter((row["model_audit"].get("decision") or "?") for row in selected)),
        "cwe": dict(Counter(str(row.get("cwe") or "?") for row in selected)),
        "rules": dict(Counter(str((row["model_audit"].get("rule_id") or "?")) for row in selected)),
        "repos": len({str(row.get("repo_url") or "") for row in selected if row.get("repo_url")}),
        "advisories": len(
            {
                str(row.get("advisory_id") or row.get("cve_id") or "")
                for row in selected
                if row.get("advisory_id") or row.get("cve_id")
            }
        ),
    }
    return selected, stats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the next human-review queue from completed model pre-audits."
    )
    parser.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATES)
    parser.add_argument("--model-audit", type=Path, default=DEFAULT_MODEL_AUDIT)
    parser.add_argument("--review-root", type=Path, default=DEFAULT_REVIEW_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--decisions",
        default=",".join(DEFAULT_DECISIONS),
        help="comma-separated model decisions to include",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    decisions = {item.strip() for item in args.decisions.split(",") if item.strip()}
    if not decisions:
        raise SystemExit("--decisions must not be empty")

    candidates = load_jsonl(args.candidates)
    audit_by_id = index_by_candidate_id(load_jsonl(args.model_audit), "model audit")
    reviewed = load_reviewed_ids(args.review_root)
    selected, stats = select_rows(candidates, audit_by_id, reviewed, decisions)

    output = {
        "candidates": str(args.candidates.resolve().relative_to(ROOT)),
        "model_audit": str(args.model_audit.resolve().relative_to(ROOT)),
        "review_root": str(args.review_root.resolve().relative_to(ROOT)),
        "reviewed_ids_excluded": len(reviewed),
        "out": str(args.out.resolve().relative_to(ROOT)),
        "dry_run": args.dry_run,
        **stats,
    }
    if not args.dry_run:
        write_jsonl(args.out, selected)

    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
