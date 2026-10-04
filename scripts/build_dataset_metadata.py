#!/usr/bin/env python3
"""Generate data/dataset_metadata.csv from the curated v2 sources.

Covers the provenance that matters for the domain data: the R4 real-repository
validation set and the R5/R6 curated and rule-fixture additions. Generates one
row per record.
"""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "dataset_metadata.csv"

SOURCES = [
    "data/round4/real_validation/detect.jsonl",
    "data/round4/real_validation/triage.jsonl",
    "data/round5/final/known_forms_detect.jsonl",
    "data/round5/final/known_forms_triage.jsonl",
    "data/round6/new_detect.jsonl",
    "data/round6/new_triage.jsonl",
    "data/round6/supplement_detect.jsonl",
    "data/round6/supplement_triage.jsonl",
    "data/round6/supplement_v2_detect.jsonl",
    "data/round6/supplement_v2_triage.jsonl",
    "data/round6/rule_fixture_detect.jsonl",
    "data/round6/rule_fixture_triage.jsonl",
    # Optional advisory-backed records merged into Round 6 when present.
    "data/round6/real_verified_detect.jsonl",
    "data/round6/real_verified_triage.jsonl",
]

FIELDS = [
    "sample_id", "file_path", "cwe", "severity", "vulnerable", "generator",
    "repo_source", "split", "label_verified_by", "notes",
]


def load(path: Path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def row_for(record: dict, rel_path: str) -> dict:
    label = record.get("label", {})
    task = record.get("task", "")
    verified = record.get("verified")
    if task == "detect":
        vulnerable = label.get("vulnerable")
        verdict = ""
    else:
        vulnerable = ""
        verdict = label.get("verdict", "")
    notes = " ".join(
        s for s in (
            f"task={task}",
            f"verdict={verdict}" if verdict else "",
            f"rule={record.get('rule', '')}" if record.get("rule") else "",
            f"category={record.get('category', '')}" if record.get("category") else "",
        ) if s
    )
    return {
        "sample_id": record.get("id", ""),
        "file_path": rel_path,
        "cwe": label.get("cwe", ""),
        "severity": label.get("severity", ""),
        "vulnerable": "" if vulnerable is None else str(bool(vulnerable)).lower(),
        "generator": record.get("source", ""),
        "repo_source": record.get("repo_url", "") or "original",
        "split": record.get("split", ""),
        "label_verified_by": verified_by(record),
        "notes": notes,
    }


def verified_by(record: dict) -> str:
    """Keep review provenance honest in the exported metadata table."""
    if record.get("verified") is not True:
        return "unverified"
    review_mode = str(record.get("review_mode") or "").strip().lower()
    if review_mode == "model":
        return f"model:{record.get('model') or 'unknown'}"
    if review_mode == "manual":
        return "human"
    return "verified_legacy"


def main():
    rows = []
    for rel in SOURCES:
        path = ROOT / rel
        if not path.exists():
            print(f"[skip] missing {rel}")
            continue
        recs = load(path)
        rows += [row_for(r, rel) for r in recs]
        print(f"[+] {rel}: {len(recs)}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] {OUT}: {len(rows)} rows")


if __name__ == "__main__":
    main()
