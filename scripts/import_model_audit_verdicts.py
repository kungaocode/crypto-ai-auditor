#!/usr/bin/env python3
"""Import successful binary model audits into the review label store.

Only successful ``confirmed`` and ``rejected`` verdicts are imported. API errors
and malformed evidence are skipped. Imported labels carry explicit
``review_mode=model`` provenance and can be treated as finalized labels by the
normal review export path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reviewer.store import ReviewStore, ReviewStoreError  # noqa: E402
from scripts.build_round6_final_dataset import RULE_CWE, TARGET_CWES  # noqa: E402


DEFAULT_CANDIDATES = ROOT / "data/round6/candidates/real_crypto_candidates_a_functions.jsonl"
DEFAULT_AUDIT = ROOT / "data/round6/candidates/model_audit_k3_binary.jsonl"
DEFAULT_REPORT = ROOT / "reports/data_quality/model_audit_k3_import.json"
DEFAULT_REVIEWER = "reviewer-kimi"


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


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    temp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temp, path)


def index_rows(rows: Iterable[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        candidate_id = str(row.get("candidate_id") or "").strip()
        if not candidate_id:
            raise ValueError(f"{label} contains an empty candidate_id")
        if candidate_id in indexed:
            raise ValueError(f"{label} contains duplicate candidate_id: {candidate_id}")
        indexed[candidate_id] = row
    return indexed


def load_existing_reviews(store: ReviewStore) -> dict[str, dict[str, Any]]:
    labels_dir = store.run_dir / "labels"
    if not labels_dir.exists():
        return {}
    reviews: dict[str, dict[str, Any]] = {}
    # Only binary verdicts are part of the current review schema; legacy
    # non-binary directories (e.g. scope-out) are ignored so those candidates
    # can be re-audited into a strict confirm/reject label.
    for verdict in ("confirm", "reject"):
        for path in sorted((labels_dir / verdict).glob("*.json")):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(f"cannot read existing review {path}: {exc}") from exc
            item_id = str(record.get("id") or path.stem).strip()
            if not item_id:
                raise ValueError(f"existing review has an empty id: {path}")
            reviews[item_id] = record
    return reviews


def stable_split(seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    bucket = int.from_bytes(digest[:8], "big") % 100
    if bucket < 80:
        return "train"
    if bucket < 90:
        return "val"
    return "test"


def choose_split(
    candidate: dict[str, Any],
    repo_splits: dict[str, str],
) -> str:
    repo = str(candidate.get("repo_url") or "").strip()
    seed = repo or str(candidate.get("candidate_id") or "")
    if seed in repo_splits:
        return repo_splits[seed]
    split = stable_split(seed)
    repo_splits[seed] = split
    return split


def skip_record(candidate_id: str, reason: str, detail: str = "") -> dict[str, str]:
    return {
        "candidate_id": candidate_id,
        "reason": reason,
        "detail": detail,
    }


def resolve_confirm_cwe(candidate: dict[str, Any], audit: dict[str, Any], rule_id: str) -> str:
    """Pick a CWE accepted by the rule, preferring the model's own label.

    Advisories often carry a coarse CWE (e.g. CWE-326) while the concrete fix
    demonstrates a finer one (e.g. CWE-327). We accept the model CWE first,
    then the advisory's primary CWE, then any CWE the advisory also lists, as
    long as it is compatible with the chosen rule and inside the taxonomy.
    """
    accepted = RULE_CWE.get(rule_id, set())
    offered: list[str] = []
    for value in (audit.get("cwe"), candidate.get("cwe")):
        if value:
            offered.append(str(value).strip().upper())
    for value in candidate.get("cwe_all") or []:
        if value:
            offered.append(str(value).strip().upper())
    for value in offered:
        if value in accepted and value in TARGET_CWES:
            return value
    return ""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import successful binary model audits into reviewer labels."
    )
    parser.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATES)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--reviewer", default=DEFAULT_REVIEWER)
    parser.add_argument("--report-out", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace an existing label for the same candidate",
    )
    return parser.parse_args(argv)


def resolve_path(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    candidates_path = resolve_path(args.candidates)
    audit_path = resolve_path(args.audit)
    report_path = resolve_path(args.report_out)

    try:
        candidates = load_jsonl(candidates_path)
        audits = load_jsonl(audit_path)
        candidate_by_id = index_rows(candidates, "candidate file")
        audit_by_id = index_rows(audits, "model audit")
    except (OSError, ValueError) as exc:
        print(f"[import] {exc}", file=sys.stderr)
        return 1

    unknown = sorted(set(audit_by_id) - set(candidate_by_id))
    if unknown:
        print(
            "[import] audit contains candidate IDs absent from the candidate file: "
            + ", ".join(unknown[:20]),
            file=sys.stderr,
        )
        return 1

    try:
        store = ReviewStore(ROOT, args.reviewer, candidates_path=candidates_path)
        existing = load_existing_reviews(store)
    except (ReviewStoreError, ValueError) as exc:
        print(f"[import] cannot initialize reviewer store: {exc}", file=sys.stderr)
        return 1
    existing_count = len(existing)

    repo_splits: dict[str, str] = {}
    for record in existing.values():
        repo = str(record.get("repo_url") or "").strip()
        split = str(record.get("split") or "").strip()
        if repo and split in {"train", "val", "test"}:
            repo_splits.setdefault(repo, split)

    skipped: list[dict[str, str]] = []
    imported: list[str] = []
    imported_by_decision: Counter[str] = Counter()
    skipped_by_reason: Counter[str] = Counter()

    def skip(candidate_id: str, reason: str, detail: str = "") -> None:
        skipped.append(skip_record(candidate_id, reason, detail))
        skipped_by_reason[reason] += 1

    for candidate_id, audit in audit_by_id.items():
        candidate = candidate_by_id[candidate_id]
        if candidate_id in existing and not args.overwrite:
            skip(candidate_id, "already_reviewed")
            continue

        error = str(audit.get("error") or "").strip()
        if error:
            skip(candidate_id, "model_error", error)
            continue

        decision = str(audit.get("decision") or "").strip().lower()
        if decision not in {"confirmed", "rejected"}:
            skip(candidate_id, "non_binary_decision", decision or "missing")
            continue

        code_vuln = str(candidate.get("code_vuln") or "")
        code_fixed = str(candidate.get("code_fixed") or "")
        if not code_vuln.strip():
            skip(candidate_id, "missing_vulnerable_code")
            continue
        if decision == "confirmed" and not code_fixed.strip():
            skip(candidate_id, "confirmed_without_fixed_code")
            continue

        explanation = str(audit.get("explanation") or "").strip()
        if not explanation:
            skip(candidate_id, "missing_explanation")
            continue

        rule_id = str(audit.get("rule_id") or "").strip()
        cwe = str(audit.get("cwe") or "").strip().upper()
        if decision == "confirmed":
            if rule_id not in RULE_CWE:
                skip(candidate_id, "confirmed_without_valid_rule", rule_id or "missing")
                continue
            cwe = resolve_confirm_cwe(candidate, audit, rule_id)
            if not cwe:
                skip(
                    candidate_id,
                    "confirmed_with_invalid_taxonomy",
                    f"rule={rule_id} model_cwe={audit.get('cwe') or 'missing'} "
                    f"advisory_cwe={candidate.get('cwe') or 'missing'}",
                )
                continue
        else:
            if rule_id and rule_id not in RULE_CWE:
                rule_id = ""
            if cwe and (cwe not in TARGET_CWES or (rule_id and cwe not in RULE_CWE[rule_id])):
                cwe = str(candidate.get("cwe") or "").strip().upper()
                if cwe not in TARGET_CWES:
                    cwe = ""

        severity = str(audit.get("severity") or "").strip().upper()
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            severity = "HIGH"

        candidate_repo = str(candidate.get("repo_url") or "").strip()
        split = choose_split(candidate, repo_splits)
        payload = {
            "code_vuln": code_vuln,
            "code_fixed": code_fixed,
            "rule_id": rule_id,
            "cwe": cwe,
            "severity": severity,
            "split": split,
            "explanation": explanation,
            "finding": str(audit.get("finding") or "").strip(),
            "note": str(audit.get("evidence_notes") or "").strip(),
            "review_mode": "model",
            "model": str(audit.get("model") or "kimi-k3"),
            "model_confidence": audit.get("confidence"),
            "source_audit": str(audit_path.relative_to(ROOT)),
            "repo_url": candidate_repo,
        }
        verdict = "confirm" if decision == "confirmed" else "reject"

        if args.dry_run:
            imported.append(candidate_id)
            imported_by_decision[decision] += 1
            continue

        try:
            store.review({"id": candidate_id, "verdict": verdict, **payload})
        except ReviewStoreError as exc:
            skip(candidate_id, "review_validation_failed", str(exc))
            continue
        imported.append(candidate_id)
        imported_by_decision[decision] += 1
        existing[candidate_id] = {
            "id": candidate_id,
            "repo_url": candidate_repo,
            "split": split,
        }

    export_result: dict[str, Any] | None = None
    if not args.dry_run:
        try:
            export_result = store.export()
        except ReviewStoreError as exc:
            print(f"[import] export failed: {exc}", file=sys.stderr)
            return 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "candidate_path": str(candidates_path.relative_to(ROOT)),
        "audit_path": str(audit_path.relative_to(ROOT)),
        "reviewer": args.reviewer,
        "audit_rows": len(audits),
        "candidate_rows": len(candidates),
        "existing_reviews": existing_count,
        "imported": len(imported),
        "imported_by_decision": dict(sorted(imported_by_decision.items())),
        "skipped": len(skipped),
        "skipped_by_reason": dict(sorted(skipped_by_reason.items())),
        "imported_ids": imported,
        "skipped_rows": skipped,
        "export": export_result,
        "dry_run": args.dry_run,
    }
    if not args.dry_run:
        write_json(report_path, report)

    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
