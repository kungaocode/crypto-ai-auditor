# Dataset Documentation

Scope: this release targets **known** cryptographic misuse patterns and their known
safe replacements. Novel-pattern discovery is out of scope. See
[`crypto_vuln_taxonomy.md`](crypto_vuln_taxonomy.md) for the 13 rule families
(`CRYPTO-001..013`).

## 1. Sources

| source | role | license | committed? |
|---|---|---|---|
| [PyCode-Vul](https://github.com/S-AIR-L/PyCode-Vul) | generic web/Django vulnerability detection slice | CC-BY-4.0 | upstream referenced, raw kept under `data/raw/pycode-vul/` |
| Real Python crypto libs | real-repository triage/detect validation | per-repo (BSD/MIT/Apache) | metadata + snippets only (`data/round4/real_validation/`) |
| Round 2-3 curated pairs | known vulnerable form + safe replacement | original | yes (`data/round3/`) |
| Round 5 known-forms / library audit | password-storage, KDF, timing, library-legacy negatives | original | yes (`data/round5/final/`) |
| Round 6 additions | full rule-family coverage + safe-library hedging | original | yes (`data/round6/`) |
| Optional verified real records | advisory/OSV-backed Python crypto vulnerable/fixed evidence | per upstream repository | merged into R6 when present |

Real-repository set: `itsdangerous`, `passlib`, `pyjwt`, `python-rsa`,
`pycryptodome`, pinned by commit in
[`data/round4/real_validation/manifest.json`](../data/round4/real_validation/manifest.json).
Upstream source is recorded, not committed verbatim.

## 2. Round lineage and artifact map

| round | curated records | training artifact | eval artifact |
|---|---|---|---|
| 3 | vulnerable/secure pairs + 77 negatives | `data/round3/upload/` | `data/round3/eval/` |
| 4 | 456 synthetic + 187 real negatives | `data/round4/upload/` | `data/round4/eval/` |
| 5 | 148 (detect=93, triage=55) | `data/round5/final/upload/full/` | `data/round5/validation/` |
| 6 | 401 additions (322 baseline + 79 verified real) | `data/round6/final/upload/full/` | `data/round6/validation_frozen/` |

Committed R5 base is `train=2764 / val=321 / test=636`. Round-6 finalization
merges 322 curated/rule-fixture additions plus 79 advisory-backed verified real
records for 401 new records total:

```
train = 3115   val = 347   test = 660   total = 4122
```

Task mix: Detect 3633 (2037 pos / 1596 neg), Triage 489 (251 Confirm / 238
Reject). The 79 verified real records split 30 Detect (23 K3-reviewed, 7 manual)
and 49 Triage (37 K3-reviewed, 12 manual). See
`reports/data_quality/r6_final_feasibility.md`.

Rebuild the merged Round-6 upload set (chatml) with:

```bash
python3 scripts/build_round6_final_dataset.py --emit
```

The builder declares its eight required source files in `R6_SOURCE_FILES` and two
advisory-backed sources in `R6_OPTIONAL_SOURCES`. Missing optional files leave the
322-record baseline unchanged. When present, verified real records are validated,
merged into R6, and included in the emitted
`data/round6/final/r6_manifest.json`, which records per-source and per-artifact
SHA-256 values. Do not hand-edit the `upload/full/*.jsonl` files; regenerate them.
The finalized `r6_manifest.json` records `r6_new_total=401` and
`verified_real_total=79`.

## 3. Schemas

Curated (v2) records:

```
id, language, task (detect|triage), code, label, source, license,
repo_url, commit, verified, split, [finding, rule, category, file]
```

- `detect` label: `{vulnerable: bool, cwe, severity, confidence, explanation}`
- `triage` label: `{verdict: Confirm|Reject, cwe, severity, explanation, patch}`

Upload (chatml) records: `{"messages": [{role: system}, {role: user}, {role: assistant}]}`.
Triage user messages in **final** artifacts omit `TRIAGE_PURPOSE_GUIDE`; inference
re-appends it (`model/prompts.py`).

The strengthened schema for advisory-backed real records and the candidate pool is
documented in [`data/round6/candidates/SCHEMA.md`](../data/round6/candidates/SCHEMA.md).

## 4. Split policy

- Splits are assigned by rule family and sample type, not randomly by row, so that
  each family appears in train/val/test.
- `val` is used for model selection; `test` is the internal held-out slice of the
  curated data.
- Neither `val` nor `test` is a substitute for an external benchmark. See §5.

## 5. Leakage controls

Cross-round reuse was audited with `scripts/audit_dataset_leakage.py`, which compares
every eval slice against optimization-visible artifacts (R5/R6 final train **and**
val) on three signals: exact normalized text, `ast.dump()`, and
`(repo_url, commit, file)`.

Run:

```bash
python3 scripts/audit_dataset_leakage.py --out reports/data_quality/leakage_report
python3 scripts/audit_dataset_leakage.py --write-frozen
```

Findings at the time of writing:

| eval slice | n | optimization-visible overlap (exact) | overlap (AST) |
|---|---|---|---|
| r6 `detect_eval` | 19 | 0 | 0 |
| r6 `triage_eval` (pre-freeze) | 42 | 4 | 2 |

After de-leaking, the frozen R6 slices are 19 detect and 36 triage rows
(6 `round4-real-passlib` triage rows dropped).

The de-leaked slices live in `data/round6/validation_frozen/` with a `manifest.json`
recording kept/dropped counts and label distributions. `configs/benchmark_round6.yaml`
points at these frozen slices. Real-repository records that recur across rounds are
the dominant source of reuse; they are flagged in
`reports/data_quality/leakage_report.md`.

### Known residual risk

- AST normalization catches structural reuse but **not** near-duplicate rewrites
  (renamed variables, reordered statements, same template with edits).
- AST-based comparison is blind to snippets that do not parse standalone (34/2764
  of the R5 final train chatml, 34/2856 of R6); those rows are still covered by the
  exact-text check but cannot be structurally matched.
- `repo_url`-level leakage only covers records that carry repo metadata; curated
  synthetic samples cannot be traced to a repository.
- The frozen triage slice has only **4 Confirm** positives, so any confirm-recall
  number from it is low-power and must be reported as a count, not an acceptance
  gate.

## 6. Label provenance and verification

| artifact | verified | labeling mode |
|---|---|---|
| R4 real-repository triage (35) | true | manual review against upstream source; all Reject |
| R4 real-repository detect (7) | true | manual review; all safe functions |
| R5 curated (148) | mixed | hand-authored / generator-assisted |
| R6 baseline additions (322) | **false (322/322)** | curated/rule-fixture data, model/hand-assisted, not independently reviewed |
| R6 verified real records (79) | true | advisory-backed fix-commit evidence; 60 K3-reviewed (23 detect / 37 triage) + 19 manual (7 detect / 12 triage) |

`verified=false` means the sample is a hypothesis, not ground truth. Metrics computed
over unverified samples must be labeled as such in any report.

## 7. Metadata table

`data/dataset_metadata.csv` is generated by
`scripts/build_dataset_metadata.py` from the curated v2 sources. Columns:

```
sample_id,file_path,cwe,severity,vulnerable,generator,repo_source,split,label_verified_by,notes
```

## 8. Reproduction

```bash
python3 scripts/build_round5_final_dataset.py --emit   # R5 final base
python3 scripts/harvest_real_crypto_candidates.py --advisories /path/to/advisory-database/advisories
python3 scripts/validate_real_crypto_candidates.py \
    data/round6/candidates/real_crypto_candidates.jsonl --min-a 20
# Human-review A-class candidates and write:
# data/round6/real_verified_detect.jsonl
# data/round6/real_verified_triage.jsonl
python3 scripts/build_round6_final_dataset.py --emit   # R6 merged upload sets
python3 scripts/audit_dataset_leakage.py --write-frozen
python3 scripts/build_dataset_metadata.py
```

The harvest/validate pair is optional and fails until real A-class candidates are
actually present. The final builder remains reproducible without them.

## 9. Limitations (the real bottleneck)

1. **Evaluation distribution mismatch.** PyCode-Vul is dominated by generic
   web/Django vulnerabilities (SQLi, command injection, deserialization). The 13
   crypto rules cover only a small part of it, so PyCode-Vul recall cannot measure
   crypto-audit quality.
2. **Too few real crypto positives.** The R6 verified real set is now 30 unique
   confirmed Detect positives and 30 Triage Confirm, below the 50-100 A-class gate.
   The frozen Triage slice still has only 4 Confirm rows, so confirm-recall remains
   report-only.
3. **Synthetic/manual samples dominate** the curated additions, and near-duplicate
   detection is limited to exact + AST.
4. **Small frozen eval.** 19 detect / 36 triage, of which only 4 triage are Confirm.
   Confidence intervals on these slices are wide.

The highest-value next data investment is not more same-family synthetic variants: it
is harvesting real crypto-misuse fixes (CWE-321/326/327/329/338/916/208) from security
advisories and fix commits, with repository-level and time-based splits.

The R6 model was subsequently trained and evaluated on these artifacts. It did
not pass the documented acceptance gates, so the project is temporarily closed
as a research baseline; see
[`data/round6/eval/RESULTS.md`](../data/round6/eval/RESULTS.md) for measured
results and [`README.md`](../README.md) for the closure scope and future-work
plan.

For the source-by-source assessment, evidence rules, and the R6 finalization
collection gate, see [`dataset_source_strategy.md`](dataset_source_strategy.md).
