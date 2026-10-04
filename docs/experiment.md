# Experiment Protocol and Results

This file records what was actually run. Numbers are grouped by round; do not mix
rounds in a single table.

## 1. Metric definitions

- **detect**: given a function, predict `vulnerable` (+ CWE). Reported as
  recall / precision / F1 / accuracy; `cwe_acc` is computed over GT-positive
  functions only.
- **triage**: given code + a static finding, predict `Confirm` / `Reject`.
  `confirm_recall` = fraction of GT-Confirm findings kept; `fpr` = fraction of
  GT-Reject findings that were wrongly confirmed.
- **18-probe**: acceptance probe set (12 vulnerable + 6 safe), reported as correct
  verdicts out of 18.

All metrics are computed by `evaluation/benchmark.py` and written to
`reports/benchmark/benchmark.{json,md}`.

## 2. How to run

```bash
# deterministic local self-test (no credentials)
python main.py --benchmark --config configs/benchmark.yaml

# real model: set kind:cloud and export LLM_API_KEY / LLM_BASE_URL / LLM_MODEL_ID
python main.py --benchmark --config configs/benchmark_round6.yaml
```

Relative paths inside a config are resolved against the repository root.

**System scope** (implemented):

| slice | supported systems |
|---|---|
| detect | `static` (Semgrep), `llm` |
| triage | `static` (accept-all baseline), `llm`, `agent` |

`agent` on the detect slice is an alias of `llm`. Base-LLM / Static+Base /
Static+Fine-tuned rows are **not implemented**; the earlier "five-system ablation"
claim is retracted.

## 3. Round history

### Round 3 (baseline)

| metric | value |
|---|---|
| detect tp/fp/fn/tn | 302/260/3/4 |
| detect recall / precision / F1 | 0.990 / 0.537 / 0.697 |
| detect cwe_acc | 0.921 |
| domain confirm_recall / fpr | 0.929 / 0.067 |
| 18-probe | 18/18 |

### Round 4 (incremental vs full retrain)

| metric | R3 | incremental | full 50:50 |
|---|---|---|---|
| detect recall | 0.990 | 0.584 | 0.984 |
| detect precision | 0.537 | 0.549 | 0.536 |
| detect F1 | 0.697 | 0.566 | 0.694 |
| domain confirm_recall | 0.929 | 0.071 | 0.929 |
| domain fpr | 0.067 | 0.000 | 0.067 |
| 18-probe | 18/18 | 17/18 | 18/18 |

Real-repository validation (42 records, all Reject/safe): detect 4/7 safe functions
correct; triage fpr 0.571 (full) / 0.429 (incremental); passlib legacy-hash 0/11
confirmed by both. Conclusion: incremental fine-tuning caused catastrophic
forgetting and was dropped; the full retrain matched R3 but did not fix
real-repository over-confirmation. See `data/round4/eval/RESULTS.md`.

### Round 5 (regression)

The committed `reports/benchmark/benchmark.json` is a degraded Round-5 run:

| slice | metric | value |
|---|---|---|
| detect (n=13) | tp/fp/fn/tn | 0/2/3/8 |
| detect | F1 | 0.000 |
| detect | accuracy | 0.615 |
| triage (n=41) | gt Confirm / Reject | 3 / 38 |
| triage | confirm_recall | 1.000 |
| triage | fpr | 0.368 |

`confirm_recall = 1.000` here is over 3 positives and is not a meaningful result.
Detect F1 0.0 indicates the R5 model failed the detect slice outright. The R5
dataset's own QA report (`data/round5/final/qa_report.md`) is **FAIL**
(`backtest_pos_missing=22`, `backtest_bneg_no_fire=25`); R5 should not be treated
as a validated release. A same-config rerun of this cloud endpoint produced
`0/1/3/9` on detect and FPR `0.289` on triage, so individual R5 point estimates
varied across runs; the regression is nevertheless unambiguous.

### Round 6 (finalized, awaiting train)

Round 6 rebuilt the data (322 curated/rule-fixture additions plus 79
advisory-backed verified-real records = 401 additions, all 13 rule families
covered) and froze a de-leaked eval set. There is no separate Round 7: verified
records were merged directly into R6. The emitted
`data/round6/final/r6_manifest.json` freezes source and artifact hashes.
**The Round-6 retrain has not been run**, so no Round-6 metrics are reported. Run
`configs/benchmark_round6.yaml` after training. Feasibility summary:
`reports/data_quality/r6_final_feasibility.md`.

## 4. Acceptance criteria

For a Round-6 candidate:

| gate | criterion | status |
|---|---|---|
| detect precision | > 0.54 (R3/R4 baseline) | required |
| domain fpr | ≤ 0.06 | required |
| confirm_recall | report-only | not a gate: frozen slice has 4 Confirm |
| 18-probe | ≥ 0.95 | required |
| real-repository fpr | no worse than R3/R4 | required |

## 5. Reproducibility checklist

1. `python3 scripts/build_round5_final_dataset.py --emit`
2. Optional real-data finalization:
   `python3 scripts/harvest_real_crypto_candidates.py --advisories /path/to/advisory-database/advisories`,
   then human-review the A-class records into
   `data/round6/real_verified_{detect,triage}.jsonl`.
   Validate with `scripts/validate_real_crypto_candidates.py ... --min-a 20`.
3. `python3 scripts/build_round6_final_dataset.py --emit`
   (asserts source parity and prints artifact hashes)
4. Re-check `data/round6/final/r6_manifest.json` and keep the emitted
   train/val/test hashes unchanged through training.
5. `python3 scripts/audit_dataset_leakage.py --write-frozen`
   (writes `data/round6/validation_frozen/` + `manifest.json`)
6. `python3 scripts/build_dataset_metadata.py`
7. Train from a **fresh base** on `data/round6/final/upload/full/` (no incremental
   continuation).
8. `python main.py --benchmark --config configs/benchmark_round6.yaml`
9. Record the model id and artifact hashes alongside the resulting
   `reports/benchmark/benchmark.json`.

## 6. Reporting rules

- Never mix rounds in one table; label every number with its round and eval slice.
- Never report `confirm_recall` without the positive count.
- Label unverified samples: the R6 baseline additions are `verified=false`
  (322/322). Report the verified real records (79, of which 60 are K3-reviewed
  and 19 manual) separately with counts by advisory, repository, rule, and split,
  keeping `review_mode` provenance intact.
- Distinguish PyCode-Vul (generic web vulnerabilities) from crypto-rule metrics.
