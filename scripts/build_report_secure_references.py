#!/usr/bin/env python3
"""Build the R6 non-training secure-reference layer.

The fixed-commit report audit produces seven rows whose recommended role is
``secure_reference``. This builder promotes those rows into a provenance-rich
companion artifact after owner approval. It does not create Detect or Triage
training rows and does not change the R6 train/val/test manifest.

Outputs:
  data/round6/references/report_secure_references.jsonl
  reports/data_quality/report_secure_references_stats.json
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CANDIDATES = ROOT / "data" / "round6" / "candidates" / "report_secure_controls.jsonl"
OUT = ROOT / "data" / "round6" / "references" / "report_secure_references.jsonl"
STATS_OUT = (
    ROOT / "reports" / "data_quality" / "report_secure_references_stats.json"
)

APPROVED_BY = "user"
APPROVED_AT = "2026-10-04"
TRAINING_ELIGIBLE = False


def load_jsonl(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sorted_counter(counter):
    return dict(sorted(counter.items()))


def build_reference(record):
    if record.get("recommended_dataset_role") != "secure_reference":
        raise ValueError(
            f"{record.get('candidate_id')}: expected secure_reference role"
        )
    if not record.get("code"):
        raise ValueError(f"{record.get('candidate_id')}: missing extracted code")

    return {
        "reference_id": record["candidate_id"],
        "language": "python",
        "code": record["code"],
        "package": record["package"],
        "repo_url": record["repo_url"],
        "commit": record["commit"],
        "reported_commit": record["reported_commit"],
        "file_path": record["file_path"],
        "reported_file_path": record["reported_file_path"],
        "function_name": record["function_name"],
        "reported_function_name": record["reported_function_name"],
        "source_url": record["source_url"],
        "reported_source_url": record["reported_source_url"],
        "license": record["license"],
        "source_class": record["source_class"],
        "claim_validation": record["claim_validation"],
        "source_status": record["source_status"],
        "decision": record["decision"],
        "confidence": record["confidence"],
        "rule_mapping": record["rule_mapping"],
        "reported_cwes": record["reported_cwes"],
        "safe_controls": record["safe_controls"],
        "actual_behavior": record["actual_behavior"],
        "missing_evidence": record["missing_evidence"],
        "r6_merge_status": record["r6_merge_status"],
        "source_sha256": record["source_sha256"],
        "code_sha256": record["code_sha256"],
        "approved_by": APPROVED_BY,
        "approved_at": APPROVED_AT,
        "review_status": "approved_reference_only",
        "merge_scope": "r6_secure_reference_only",
        "training_eligible": TRAINING_ELIGIBLE,
        "verified": False,
    }


def build_stats(references, candidates, output_path):
    excluded = [
        record
        for record in candidates
        if record.get("recommended_dataset_role") != "secure_reference"
    ]
    stats = {
        "schema_version": 1,
        "approved_by": APPROVED_BY,
        "approved_at": APPROVED_AT,
        "candidate_records": len(candidates),
        "reference_records": len(references),
        "excluded_records": len(excluded),
        "training_eligible_count": sum(
            1 for record in references if record["training_eligible"]
        ),
        "verified_true_count": sum(
            1 for record in references if record["verified"] is True
        ),
        "by_package": sorted_counter(
            Counter(record["package"] for record in references)
        ),
        "by_claim_validation": sorted_counter(
            Counter(record["claim_validation"] for record in references)
        ),
        "by_source_status": sorted_counter(
            Counter(record["source_status"] for record in references)
        ),
        "by_merge_status": sorted_counter(
            Counter(record["r6_merge_status"] for record in references)
        ),
        "by_coverage_status": sorted_counter(
            Counter(
                record["rule_mapping"]["coverage_status"]
                for record in references
            )
        ),
        "references": [
            {
                "reference_id": record["reference_id"],
                "package": record["package"],
                "function_name": record["function_name"],
                "claim_validation": record["claim_validation"],
                "source_status": record["source_status"],
                "r6_merge_status": record["r6_merge_status"],
                "source_sha256": record["source_sha256"],
                "code_sha256": record["code_sha256"],
            }
            for record in references
        ],
        "output": {
            "path": str(output_path.relative_to(ROOT)),
            "sha256": sha256_file(output_path),
        },
    }
    return stats


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True))
            handle.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--emit",
        action="store_true",
        help="write the reference JSONL and statistics",
    )
    args = parser.parse_args()

    candidates = load_jsonl(CANDIDATES)
    references = [
        build_reference(record)
        for record in candidates
        if record.get("recommended_dataset_role") == "secure_reference"
    ]

    if len(references) != 7:
        raise SystemExit(
            f"[FAIL] expected 7 approved secure references, got {len(references)}"
        )

    print(f"candidates: {len(candidates)}")
    print(f"secure references: {len(references)}")
    print(f"training eligible: {sum(r['training_eligible'] for r in references)}")
    for record in references:
        print(
            f"  {record['reference_id']} {record['package']} "
            f"{record['function_name']} [{record['r6_merge_status']}]"
        )

    if not args.emit:
        print("[dry-run] no files written")
        return 0

    write_jsonl(OUT, references)
    stats = build_stats(references, candidates, OUT)
    STATS_OUT.parent.mkdir(parents=True, exist_ok=True)
    STATS_OUT.write_text(
        json.dumps(stats, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    print(f"[+] {OUT}")
    print(f"[+] {STATS_OUT}")
    print(f"[+] reference sha256={stats['output']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
