#!/usr/bin/env python3
"""Harvest real-crypto *candidates* from the local PyCode-Vul CSV mirror.

The advisory mirrors (GHSA / OSV / PyPA) are drained for PyPI x target-CWE, so
the next on-disk source is ``data/raw/pycode-vul``: one CSV per official split
where every row is a real Python function pulled from a real repository, with
``vulnerable_function_source`` / ``patched_function_source`` and a
``predicted_cwe_ids`` model label. It is a different file type from the
advisory JSON/YAML trees, so it needed its own reader.

What this emits:
  data/round6/candidates/real_crypto_candidates_pycode_vul.jsonl

Honesty constraints (do not relax):
  * ``predicted_cwe_ids`` is a *model prediction*, not ground truth. Rows keep
    ``preliminary_class`` "B" and ``verified=false`` and say so in
    ``match_reasons`` (``pycode-vul:predicted-cwe``).
  * PyCode-Vul rows carry repo + sha but **no advisory/CVE id**, so they can
    never become A-class records on their own. The screen caps them at P3; they
    are volume for review/negative-control, not advisory-backed positives.
  * The test CSV feeds the held-out ``domain_eval`` set, so it is skipped by
    default to avoid leaking it into training. Pass ``--include-test`` only for
    a deliberate, documented audit.

Usage:
  python3 scripts/harvest_pycode_vul_candidates.py --emit
  python3 scripts/harvest_pycode_vul_candidates.py --stats-out reports/data_quality/harvest_pycode_vul_stats.json
"""
import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.build_round6_final_dataset import TARGET_CWES  # noqa: E402

RAW_DIR = ROOT / "data" / "raw" / "pycode-vul"
TRAIN_CSV = RAW_DIR / "PyCode_Vul-_train-set.csv"
TEST_CSV = RAW_DIR / "PyCode_Vul_test-set.csv"
DEFAULT_OUT = ROOT / "data" / "round6" / "candidates" / "real_crypto_candidates_pycode_vul.jsonl"
DEFAULT_STATS = ROOT / "reports" / "data_quality" / "harvest_pycode_vul_stats.json"

# Target CWEs plus the adjacent crypto CWEs the OSV pass also widens to. These
# extra CWEs are *recall* only: they are outside the shipped CRYPTO-001..013
# taxonomy and need a human/rule mapping before they can be promoted.
EXTRA_CWES = {"CWE-330", "CWE-328", "CWE-347", "CWE-798", "CWE-319", "CWE-311"}
CRYPTO_CWES = set(TARGET_CWES) | EXTRA_CWES

NOISE_CWES = {"CWE-703", "CWE-Unknown", "UNKNOWN", "nan", ""}
DATASET_LICENSE = "cc-by-4.0"
SOURCE = "pycode-vul"
ID_PREFIX = "pycodevul"


def split_cwes(value: str):
    out = []
    for part in re.split(r"[;,|]", value or ""):
        part = part.strip()
        if part and part not in NOISE_CWES and part not in out:
            out.append(part)
    return out


def norm_code(code: str) -> str:
    return "".join((code or "").split())


def candidate_id(repo: str, sha: str, code: str) -> str:
    slug = re.sub(r"[^0-9a-zA-Z]+", "-", repo or "unknown").strip("-").lower()
    digest = hashlib.sha1(norm_code(code).encode("utf-8")).hexdigest()[:8]
    return f"{ID_PREFIX}-{slug}-{sha[:8] or 'nosha'}-{digest}"


def build_candidate(row: dict, cwes: list):
    """One PyCode-Vul row -> one B-class candidate. Never verified."""
    code_vuln = row.get("vulnerable_function_source") or ""
    code_fixed = row.get("patched_function_source") or ""
    repo = (row.get("repo") or "").strip()
    sha = (row.get("sha") or "").strip()
    file_path = (row.get("file_path") or "").strip()
    cve = (row.get("cve_ids") or "").strip()
    if cve.upper() in NOISE_CWES:
        cve = ""
    return {
        "candidate_id": candidate_id(repo, sha, code_vuln),
        "source": SOURCE,
        "advisory_id": "",
        "cve_id": cve,
        "package": "",
        "repo_url": f"https://github.com/{repo}" if repo else "",
        "vuln_commit": "",
        # PyCode-Vul keeps the patched function at `sha`; treat it as the fix
        # commit but flag the semantics as unconfirmed in match_reasons.
        "fix_commit": sha,
        "affected_versions": "",
        "fixed_version": "",
        "file_path": file_path,
        "function_name": "",
        "cwe": cwes[0] if cwes else "",
        "cwe_all": cwes,
        "match_reasons": (
            ["pycode-vul:predicted-cwe"] + [f"predicted:{c}" for c in cwes]
            + ["pycode-vul:sha-semantics-unconfirmed"]
        ),
        "rule_id": "",
        "code_vuln_url": "",
        "code_fixed_url": "",
        "notification_url": "",
        "code_vuln": code_vuln,
        "code_fixed": code_fixed,
        "static_finding": "",
        "preliminary_class": "B",
        "human_verdict": "",
        "verified": False,
        "verified_by": "",
        "license": DATASET_LICENSE,
        "collected_at": date.today().isoformat(),
        "split": "pycodevul-train",
    }


def harvest(paths, *, include_test: bool, cwe_only: bool):
    scanned = 0
    skipped_label = 0
    skipped_no_code = 0
    skipped_no_crypto = 0
    skipped_identical = 0
    emitted = []
    by_cwe = Counter()
    for path in paths:
        if path == TEST_CSV and not include_test:
            continue
        if not path.exists():
            continue
        csv.field_size_limit(2 ** 31 - 1)
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                scanned += 1
                cwes = [c for c in split_cwes(row.get("predicted_cwe_ids")) if c in CRYPTO_CWES]
                if not cwes:
                    skipped_no_crypto += 1
                    continue
                if (row.get("label") or "").strip() != "1":
                    skipped_label += 1
                    continue
                code_vuln = row.get("vulnerable_function_source") or ""
                code_fixed = row.get("patched_function_source") or ""
                if not code_vuln.strip() or not code_fixed.strip():
                    skipped_no_code += 1
                    continue
                if norm_code(code_vuln) == norm_code(code_fixed):
                    skipped_identical += 1
                    continue
                if cwe_only and not (set(cwes) & TARGET_CWES):
                    continue
                emitted.append(build_candidate(row, cwes))
                for c in cwes:
                    by_cwe[c] += 1
    stats = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_label": SOURCE,
        "inputs": [str(p.relative_to(ROOT)) for p in paths
                   if p.exists() and (p != TEST_CSV or include_test)],
        "include_test": include_test,
        "crypto_cwes": sorted(CRYPTO_CWES),
        "target_cwes": sorted(TARGET_CWES),
        "scanned": scanned,
        "skipped_no_crypto": skipped_no_crypto,
        "skipped_label": skipped_label,
        "skipped_no_code": skipped_no_code,
        "skipped_identical_pair": skipped_identical,
        "emitted": len(emitted),
        "by_cwe": dict(by_cwe.most_common()),
        "note": "predicted_cwe_ids is a model label; rows are B-class and cannot reach A-class without an advisory/CVE.",
    }
    return emitted, stats


def main() -> int:
    ap = argparse.ArgumentParser(description="Harvest PyCode-Vul crypto candidates")
    ap.add_argument("--train-csv", type=Path, default=TRAIN_CSV)
    ap.add_argument("--test-csv", type=Path, default=TEST_CSV)
    ap.add_argument("--include-test", action="store_true",
                    help="Also read the test split (feeds domain_eval; leakage risk)")
    ap.add_argument("--cwe-only", action="store_true",
                    help="Keep only rows whose predicted CWE is in the shipped taxonomy")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--stats-out", type=Path, default=DEFAULT_STATS)
    ap.add_argument("--emit", action="store_true")
    args = ap.parse_args()

    train = args.train_csv if args.train_csv.is_absolute() else ROOT / args.train_csv
    test = args.test_csv if args.test_csv.is_absolute() else ROOT / args.test_csv
    emitted, stats = harvest([train, test], include_test=args.include_test,
                             cwe_only=args.cwe_only)

    print(f"scanned {stats['scanned']}  emitted {stats['emitted']}")
    print(f"  skipped no crypto CWE : {stats['skipped_no_crypto']}")
    print(f"  skipped label != 1    : {stats['skipped_label']}")
    print(f"  skipped no code pair  : {stats['skipped_no_code']}")
    print(f"  skipped identical pair: {stats['skipped_identical_pair']}")
    print("by CWE:", stats["by_cwe"])

    if args.emit:
        out = args.out if args.out.is_absolute() else ROOT / args.out
        stats_path = args.stats_out if args.stats_out.is_absolute() else ROOT / args.stats_out
        out.parent.mkdir(parents=True, exist_ok=True)
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in emitted) + "\n",
                       encoding="utf-8")
        stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
                              encoding="utf-8")
        print(f"[+] wrote {out}")
        print(f"[+] wrote {stats_path}")
    else:
        print("[dry] pass --emit to write the pool and stats report")
    return 0


if __name__ == "__main__":
    sys.exit(main())
