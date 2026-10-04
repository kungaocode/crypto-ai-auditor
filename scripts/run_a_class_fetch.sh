#!/usr/bin/env bash
# Pull and rebuild the high-precision A-class fetch queue.
#
# Required: GITHUB_TOKEN (or a working `gh auth login`).
# Optional: A_SCOPE=target|keyword|all A_LIMIT=20 A_SLEEP=0.5
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

QUEUE="data/round6/candidates/real_crypto_candidates_a_fetch_queue.jsonl"
ENRICHED="data/round6/candidates/real_crypto_candidates_a_enriched.jsonl"
FUNCTIONS="data/round6/candidates/real_crypto_candidates_a_functions.jsonl"
REVIEW="data/round6/candidates/real_crypto_candidates_a_functions_review.tsv"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    GITHUB_TOKEN="$(gh auth token)"
    export GITHUB_TOKEN
  else
    echo "[FAIL] GITHUB_TOKEN is unset and gh has no valid login." >&2
    echo "       Run: gh auth login -h github.com" >&2
    echo "       Or:  export GITHUB_TOKEN=<fine-grained-token-with-public-read>" >&2
    exit 1
  fi
fi

LIMIT_ARGS=()
if [[ -n "${A_LIMIT:-}" ]]; then
  LIMIT_ARGS=(--limit "$A_LIMIT")
fi

python3 -W ignore scripts/build_a_fetch_queue.py --scope "${A_SCOPE:-target}" --emit
python3 -W ignore scripts/fetch_fix_code.py \
  --in "$QUEUE" \
  --out "$ENRICHED" \
  --sleep "${A_SLEEP:-0.5}" \
  "${LIMIT_ARGS[@]}"
python3 -W ignore scripts/rebuild_candidate_functions.py \
  --in "$ENRICHED" \
  --out "$FUNCTIONS" \
  --sleep "${A_SLEEP:-0.5}" \
  "${LIMIT_ARGS[@]}"
python3 -W ignore scripts/validate_real_crypto_candidates.py "$FUNCTIONS"

python3 -W ignore - "$FUNCTIONS" "$REVIEW" <<'PY'
import json
import csv
import sys
from collections import Counter
from pathlib import Path

path = Path(sys.argv[1])
rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
function_pairs = [row for row in rows if row.get("code_quality") == "function"]
licensed = [row for row in function_pairs if row.get("license")]
columns = [
    "rank", "candidate_id", "priority", "package", "cwe", "rule_id", "license",
    "license_fetch_status", "fetch_status", "rebuild_status", "selected_file_reason",
    "file_path", "function_name", "repo_url", "vuln_commit", "fix_commit",
    "code_vuln_url", "code_fixed_url", "advisory_url",
]
review_path = Path(sys.argv[2])
with review_path.open("w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns, delimiter="\t")
    writer.writeheader()
    for rank, row in enumerate(function_pairs, 1):
        writer.writerow({
            "rank": rank,
            "candidate_id": row.get("candidate_id", ""),
            "priority": row.get("a_fetch_priority", ""),
            "package": row.get("package", ""),
            "cwe": row.get("cwe", ""),
            "rule_id": row.get("rule_id", ""),
            "license": row.get("license", ""),
            "license_fetch_status": row.get("license_fetch_status", ""),
            "fetch_status": row.get("fetch_status", ""),
            "rebuild_status": row.get("rebuild_status", ""),
            "selected_file_reason": row.get("selected_file_reason", ""),
            "file_path": row.get("file_path", ""),
            "function_name": row.get("function_name", ""),
            "repo_url": row.get("repo_url", ""),
            "vuln_commit": row.get("vuln_commit", ""),
            "fix_commit": row.get("fix_commit_full", row.get("fix_commit", "")),
            "code_vuln_url": row.get("code_vuln_url", ""),
            "code_fixed_url": row.get("code_fixed_url", ""),
            "advisory_url": row.get("notification_url", ""),
        })
fetch_status_counts = Counter(row.get("fetch_status") or "not-run" for row in rows)
rebuild_status_counts = Counter(row.get("rebuild_status") or "not-run" for row in rows)
ready_for_human = [
    row for row in function_pairs
    if row.get("license")
    and row.get("rule_id")
    and row.get("repo_url")
    and row.get("vuln_commit")
    and row.get("fix_commit")
    and row.get("file_path")
]
print(f"\nA-class fetch summary: {len(function_pairs)}/{len(rows)} function-level pairs, "
      f"{len(licensed)} with a concrete SPDX license.")
print(f"Ready for human review after fetch/rebuild: {len(ready_for_human)} "
      "(still preliminary_class=B, verified=false).")
print("Fetch status:", dict(fetch_status_counts))
print("Rebuild status:", dict(rebuild_status_counts))
print("By CWE:", dict(Counter(row.get("cwe") or "?" for row in function_pairs)))
print(f"Human review sheet: {review_path}")
print("Rows remain preliminary_class=B and verified=false until human review.")
PY
