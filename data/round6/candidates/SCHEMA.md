# Real Crypto Candidate and Verified-Record Schema

This directory holds the Round-6 finalization inputs for the real-crypto
positive shortage. Everything here is a **candidate** until a human reviews
the advisory and the fix commit and marks it verified.

There is no separate Round 7. Verified real records are merged into Round 6 by
`scripts/build_round6_final_dataset.py --emit`; freeze and re-check the hashes
before training.

## 1. Candidate pool

Files:

- `data/round6/candidates/real_crypto_candidates.jsonl` - watchlist packages only
- `data/round6/candidates/real_crypto_candidates_broad.jsonl` - any PyPI package
- `data/round6/candidates/real_crypto_candidates_{ghsa,osv_pypi,pypa,pycode_vul}.jsonl`
  - dedicated harvester outputs
- `data/round6/candidates/real_crypto_candidates_enriched.jsonl` - produced by
  `scripts/fetch_fix_code.py` (adds `code_vuln`/`code_fixed`/`file_path`)
- `data/round6/candidates/real_crypto_candidates_functions.jsonl` - function-level
  rebuild output
- `data/round6/candidates/real_crypto_candidates_local.jsonl` - compatible local
  JSON/JSONL records adapted by `screen_real_crypto_candidates.py`

Produced by the harvesting prompt in `docs/dataset_source_strategy.md` (§9),
then completed by hand. `scripts/harvest_real_crypto_candidates.py` reads a local
GitHub Advisory Database clone, and `scripts/fetch_fix_code.py` pulls the fix
commit diff over the GitHub API so the vulnerable/fixed snippets are filled in.
The screening pass also scans compatible `.json`/`.jsonl` records discovered
under `data/`, normalizes common field aliases, and carries source-file
provenance into the candidate. Dedicated advisory mirrors, generated training
sets, validation trees, project fixtures, and candidate outputs are excluded by
policy. Use `--no-local-json` to reproduce the older pool-only count.
One JSON object per line:

```json
{
  "candidate_id": "ghsa-xxxx-pkg-2024-001",
  "source": "GHSA/OSV",
  "advisory_id": "GHSA-....",
  "cve_id": "CVE-....",
  "package": "cryptography",
  "repo_url": "https://github.com/owner/repo",
  "vuln_commit": "",
  "fix_commit": "",
  "affected_versions": "",
  "fixed_version": "",
  "file_path": "src/pkg/module.py",
  "function_name": "verify_token",
  "cwe": "CWE-327",
  "rule_id": "CRYPTO-002",
  "code_vuln_url": "",
  "code_fixed_url": "",
  "code_vuln": "",
  "static_finding": "",
  "preliminary_class": "A",
  "human_verdict": "",
  "verified": false,
  "verified_by": "",
  "license": "",
  "collected_at": "",
  "split": "",
  "local_source_path": "",
  "local_source_locator": "",
  "local_original_id": ""
}
```

Validate with:

```bash
python3 scripts/validate_real_crypto_candidates.py \
    data/round6/candidates/real_crypto_candidates.jsonl --min-a 20
```

## 1.0 High-precision A-class fetch queue

The advisory mirrors are already drained locally. Build the compact A-class
fetch queue with:

```bash
python3 scripts/build_a_fetch_queue.py --scope target --emit
```

This writes:

- `data/round6/candidates/real_crypto_candidates_a_fetch_queue.jsonl`
- `data/round6/candidates/real_crypto_candidates_a_review.tsv`
- `reports/data_quality/a_fetch_queue_stats.json`

The `target` scope keeps only the project's target crypto CWEs. Use
`--scope keyword` or `--scope all` only after the target queue is exhausted.
Nothing in this queue is A-class yet; every row remains
`preliminary_class=B` and `verified=false`.

Run the network stage on the host (not inside the offline sandbox):

```bash
gh auth login -h github.com
A_LIMIT=5 scripts/run_a_class_fetch.sh   # smoke test
scripts/run_a_class_fetch.sh
```

The runner fetches fix commits, extracts complete function-level vulnerable and
fixed pairs, records the repository SPDX license through the GitHub license API,
and validates the result. The file selector rejects tests, fixtures, examples,
and documentation before choosing the changed implementation file; the choice
and its score are written to `selected_file_reason` and `py_file_candidates`.
Use `A_SCOPE=keyword` for the larger fallback queue. Successful rows are
summarized in
`data/round6/candidates/real_crypto_candidates_a_functions_review.tsv`.

Status fields make failed evidence auditable:

- `fetch_status`: commit/file-selection result, including the skip reason;
- `license_fetch_status`: GitHub license API result;
- `selected_file_reason`: why this implementation file won the ranking;
- `rebuild_status`: whether a complete parseable function pair was recovered.

None of these fields changes the candidate class. The fetch queue remains
`preliminary_class=B` and `verified=false` until a human writes the verdict.

## 1.1 Model pre-audit queue

`scripts/audit_real_crypto_with_llm.py` keeps model output separate from human
labels:

- `model_audit.jsonl` contains one machine result per candidate with
  `verified=false` and `review_status=model_only`.
- `real_crypto_candidates_uncertain.jsonl` is the human queue. Each row carries
  the original candidate, a nested `model_audit`, and a `review_selection`
  reason list.

The queue is selected from uncertain/low-confidence results, candidates with
missing code/evidence, taxonomy conflicts, and a deterministic sample of
otherwise high-confidence results (`--sample-rate`, default `0.15`). The
browser reviewer may prefill fields from `model_audit`, but it still requires a
human click and writes the normal human record before export.

Class definitions (from `docs/dataset_source_strategy.md` §4):

| class | meaning |
|---|---|
| A | real code crypto misuse, security property affected, fix changes it, evidence chain complete |
| B | related but semantics / rule mapping / patch still needs review |
| C | library compatibility, protocol/parser defect, test vector, dependency bump, non-security use |
| D | wrong language, task or CWE |

## 1.2 Report secure-control source audit

The fixed-commit report source extraction is reproducible with:

```bash
python3 scripts/build_report_secure_control_candidates.py
python3 scripts/build_report_secure_control_candidates.py --emit
```

This writes:

- `data/round6/candidates/report_secure_controls.jsonl`
- `reports/data_quality/report_secure_controls_stats.json`

The source files are pinned under
`data/round6/sources/secure_controls/`. The builder extracts only named AST
nodes, records the file and code SHA-256 values, and keeps
`verified=false` plus `review_status=unreviewed` on every row.

Important status fields:

- `source_status`: `verified_source`, `report_target_missing`, or
  `source_missing`;
- `claim_validation`: whether the report claim is `confirmed`, `partial`,
  `report_mismatch`, `context_dependent`, or `not_evaluable`;
- `r6_merge_status`: why a row is not eligible for automatic merge, including
  missing source, report mismatch, non-target CWE, unsafe compatibility code,
  or a weak parameter floor;
- `recommended_dataset_role`: only a recommendation. `secure_reference` rows
  still require human review before they can become supplement input.

No row in this file is registered in `R6_SOURCE_FILES`. The builder is a
provenance and review step, not a training-data merge step.

After owner approval, the seven `secure_reference` rows are promoted to the
separate non-training reference bundle:

```bash
python3 scripts/build_report_secure_references.py --emit
```

This writes `data/round6/references/report_secure_references.jsonl` and
`reports/data_quality/report_secure_references_stats.json`. These rows remain
`verified=false` and `training_eligible=false`; they do not enter
`R6_SOURCE_FILES`, `R6_OPTIONAL_SOURCES`, or the emitted R6 train/val/test
manifest.

## 2. Verified records

Only A-class candidates go here, after human review. Detect and triage live in
separate files:

```
data/round6/real_verified_detect.jsonl
data/round6/real_verified_triage.jsonl
```

These use the project's curated v2 schema plus the evidence fields. The builder
fails closed if a record violates this contract.

Detect record (positive; use `"vulnerable": false` with the same evidence chain
for a verified safe function from the same repository):

```json
{
  "id": "r6-real-<advisory>-detect",
  "language": "python",
  "task": "detect",
  "code": "<vulnerable snippet from the repo, pinned to vuln_commit>",
  "label": {
    "vulnerable": true,
    "cwe": "CWE-327",
    "severity": "HIGH",
    "confidence": "high",
    "explanation": "<why this is crypto misuse in this context>"
  },
  "rule": "CRYPTO-002",
  "source": "round6-real-ghsa-osv",
  "license": "Apache-2.0",
  "repo_url": "https://github.com/owner/repo",
  "advisory_id": "GHSA-....",
  "cve_id": "CVE-....",
  "vuln_commit": "<sha>",
  "fix_commit": "<sha>",
  "file": "src/pkg/module.py",
  "verified": true,
  "verified_by": "<reviewer>",
  "split": "train"
}
```

Triage record (adds the static finding the model must judge):

```json
{
  "id": "r6-real-<advisory>-triage",
  "language": "python",
  "task": "triage",
  "code": "<vulnerable snippet, pinned to vuln_commit>",
  "finding": "[CRYPTO-002] SHA-1 used for token signing (CWE-327).",
  "label": {
    "cwe": "CWE-327",
    "severity": "HIGH",
    "verdict": "Confirm",
    "explanation": "<what the flagged output protects and why the fix matters>",
    "patch": "<the fixed snippet from fix_commit>"
  },
  "rule": "CRYPTO-002",
  "source": "round6-real-ghsa-osv",
  "license": "Apache-2.0",
  "repo_url": "https://github.com/owner/repo",
  "advisory_id": "GHSA-....",
  "cve_id": "CVE-....",
  "vuln_commit": "<sha>",
  "fix_commit": "<sha>",
  "file": "src/pkg/module.py",
  "verified": true,
  "verified_by": "<reviewer>",
  "split": "train"
}
```

## 3. Rules the builder enforces

- `verified` must be exactly `true`.
- `license` must be concrete (not `unknown` / `n/a` / `none`).
- Evidence: advisory or CVE, `repo_url`, a commit, a file, and a code snippet.
- `rule` must be `CRYPTO-001..013`, and the label `cwe` must match that rule.
- Detect positives need a rule and a target CWE; triage Confirm needs a rule;
  triage records need `finding`.
- No duplicate advisory/CVE or repo+commit+file within the same task, and no
  repository split across train/val/test.

Nothing here is grounds for claiming generalisation on its own. Report real
records separately from the curated slices and always give numerator/denominator.
