#!/usr/bin/env python3
"""Validate real Python-crypto vulnerability candidates before they become data.

Input is the candidate JSONL produced by the advisory-harvesting prompt in
docs/dataset_source_strategy.md (see data/round6/candidates/SCHEMA.md). This
script is deliberately read-only: it checks evidence shape, rule/CWE mapping,
duplicates and the A/B/C/D spread, and reports what is missing. It never writes
training data and never marks anything human-verified.

Usage:
    python3 scripts/validate_real_crypto_candidates.py \
        data/round6/candidates/real_crypto_candidates.jsonl --min-a 20

Exit codes:
    0  no structural errors (and, with --min-a, enough A-class candidates)
    1  structural errors or the A-class floor was not met
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.build_round6_final_dataset import RULE_CWE, TARGET_CWES  # noqa: E402

VALID_CLASSES = {"A", "B", "C", "D"}
COARSE_TARGET_CWES = TARGET_CWES | {"CWE-208", "CWE-256", "CWE-295"}


def load_jsonl(path: Path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def norm_code(code: str) -> str:
    return re.sub(r"\s+", " ", code or "").strip().lower()


def get(record, *keys):
    for key in keys:
        value = record.get(key)
        if value:
            return value
    return ""


def validate_candidate(record) -> list:
    """Return a list of structural errors for one candidate (A-class stricter)."""
    errors = []
    cid = record.get("candidate_id") or "?"

    def err(msg):
        errors.append(f"{cid}: {msg}")

    if not record.get("candidate_id"):
        err("missing candidate_id")
    if not record.get("source"):
        err("missing source")
    klass = record.get("preliminary_class")
    if klass not in VALID_CLASSES:
        err(f"preliminary_class must be one of {sorted(VALID_CLASSES)} (got {klass!r})")
        return errors

    cwe = (record.get("cwe") or "").strip()
    rule = (record.get("rule_id") or record.get("rule") or "").strip()
    if rule and rule not in RULE_CWE:
        err(f"unknown rule_id {rule!r}; expected CRYPTO-001..013")
    if cwe and cwe not in COARSE_TARGET_CWES:
        # Out-of-scope CWE is only acceptable for B/C/D candidates.
        if klass == "A":
            err(f"cwe {cwe} is outside the project's target crypto CWE set")
    if rule and cwe and cwe not in RULE_CWE[rule]:
        err(f"cwe {cwe} does not match rule {rule} ({sorted(RULE_CWE[rule])})")

    advisory = get(record, "advisory_id", "cve_id")
    repo = get(record, "repo_url")
    vuln_commit = get(record, "vuln_commit")
    fix_commit = get(record, "fix_commit")
    file_path = get(record, "file_path", "file")
    function_name = get(record, "function_name", "file")
    license_ = (record.get("license") or "").strip()

    if klass == "A":
        if not advisory:
            err("A-class requires advisory_id or cve_id")
        if not repo:
            err("A-class requires repo_url")
        if not (vuln_commit or fix_commit):
            err("A-class requires vuln_commit or fix_commit")
        if not file_path:
            err("A-class requires file_path")
        if not function_name:
            err("A-class requires function_name")
        if not rule:
            err("A-class requires a rule_id in CRYPTO-001..013")
        if not cwe:
            err("A-class requires a cwe")
        if not license_ or license_.lower() in {"unknown", "n/a", "none", "tbd"}:
            err("A-class requires a concrete license")
        if get(record, "human_verdict") in ("", None):
            err("A-class requires human_verdict (Confirm/Reject/Scope-out)")

    return errors


def find_duplicates(records) -> list:
    errors = []
    seen = {"advisory": {}, "commit": {}, "code": {}}
    for r in records:
        cid = r.get("candidate_id", "?")
        advisory = get(r, "advisory_id", "cve_id")
        if advisory:
            if advisory in seen["advisory"]:
                errors.append(f"{cid}: duplicate advisory/cve {advisory} (also {seen['advisory'][advisory]})")
            else:
                seen["advisory"][advisory] = cid
        repo = get(r, "repo_url")
        commit = get(r, "fix_commit", "vuln_commit")
        if repo and commit:
            key = (repo, commit, get(r, "file_path"))
            if key in seen["commit"]:
                errors.append(f"{cid}: duplicate repo+commit+file {key} (also {seen['commit'][key]})")
            else:
                seen["commit"][key] = cid
        code = norm_code(r.get("code_vuln") or "")
        if code:
            if code in seen["code"]:
                errors.append(f"{cid}: duplicate vulnerable code (also {seen['code'][code]})")
            else:
                seen["code"][code] = cid
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate real crypto candidate JSONL")
    ap.add_argument("candidates", type=Path, help="Candidate JSONL file")
    ap.add_argument("--min-a", type=int, default=0,
                    help="Fail if fewer than this many A-class candidates are present")
    args = ap.parse_args()

    path = args.candidates
    if not path.is_absolute():
        path = ROOT / path
    if not path.exists():
        print(f"[FAIL] candidate file not found: {path}")
        return 1

    records = load_jsonl(path)
    print(f"Candidates: {len(records)}  ({display_path(path)})")

    errors = []
    for r in records:
        errors += validate_candidate(r)
    errors += find_duplicates(records)

    classes = Counter(r.get("preliminary_class", "?") for r in records)
    print("\nPreliminary class distribution:")
    for klass in ("A", "B", "C", "D", "?"):
        if classes.get(klass):
            print(f"  {klass}: {classes[klass]}")

    a_records = [r for r in records if r.get("preliminary_class") == "A"]
    if a_records:
        print("\nA-class coverage:")
        print(f"  distinct advisories: {len({get(r, 'advisory_id', 'cve_id') for r in a_records if get(r, 'advisory_id', 'cve_id')})}")
        print(f"  distinct repos:      {len({get(r, 'repo_url') for r in a_records if get(r, 'repo_url')})}")
        for dim, key in (("cwe", "cwe"), ("rule", "rule_id")):
            dist = Counter(r.get(key) or "?" for r in a_records)
            print(f"  {dim}: " + ", ".join(f"{k}={v}" for k, v in sorted(dist.items())))

    if errors:
        print(f"\n[FAIL] {len(errors)} structural error(s):")
        for e in errors[:40]:
            print(f"  {e}")
        return 1

    print("\n[PASS] candidate structure is valid")
    if args.min_a and len(a_records) < args.min_a:
        print(f"[FAIL] A-class floor not met: {len(a_records)} < {args.min_a}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
