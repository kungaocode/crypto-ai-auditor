# Round-6 Final Dataset Feasibility

Date: 2026-10-04

Built from the frozen artifacts in `data/round6/final/upload/full/` and the
source exports `data/round6/real_verified_{detect,triage}.jsonl`. This report
supersedes `reports/data_quality/r6_dataset_evaluation.md`, which was written
against the 4062-record intermediate state (19 verified records).

## 1. Decision

The frozen Round-6 dataset is usable for the next **full base retrain**
(QLoRA, fresh base, three epochs). Its strongest, defensible role is a broad
Python vulnerability-audit assistant: generic detection plus Confirm/Reject
triage across the 13 shipped CRYPTO-* rules.

It is **not yet** evidence of a stable Python-crypto-specific model. The
verified real crypto signal rests on **30 unique confirmed positives**, below
the 50-100 target agreed for the A-class gate. Report crypto-specific numbers
separately, and do not headline a crypto generalization claim from the
aggregate score.

## 2. Final Inventory

Frozen artifacts (`data/round6/final/upload/full/`, hashes in
`data/round6/final/r6_manifest.json`):

| Split | Detect | Triage | Total |
|---|---:|---:|---:|
| Train | 2732 | 383 | 3115 |
| Val | 299 | 48 | 347 |
| Test | 602 | 58 | 660 |
| **Total** | **3633** | **489** | **4122** |

- Detect: 2037 positives / 1596 negatives.
- Triage: 251 Confirm / 238 Reject.
- Aggregate class balance is fine; the risk is composition, not balance.

### Round-6 contribution

R6 adds **401** records over the R5 base: **322** curated/rule-fixture
additions (`verified=false`) plus **79** advisory-backed reviewed records
(`verified=true`).

| R6 new | Detect | Triage | Total |
|---|---:|---:|---:|
| pos/neg or Confirm/Reject | 130 : 86 | 113 : 72 | 401 |
| of which verified real | 30 | 49 | 79 |

## 3. Provenance Layers (do not mix these when reporting)

| Layer | Records | `verified` | Use |
|---|---:|---|---|
| Rule fixtures (Semgrep/Bandit derived) | 208 (104 detect + 104 triage) | `false` | Tool regression: finding + negative/Reject coverage |
| Curated/synthetic baseline additions | 114 | `false` | Hand/model-assisted rule-family coverage |
| Verified real records | 79 (30 detect + 49 triage) | `true` | Advisory-backed attacked/patched real code |

Verified-real provenance: **60 K3-reviewed** (23 detect + 37 triage) and
**19 manually reviewed** (7 detect + 12 triage). Provenance is stored per
record in `review_mode` (`manual` vs `model`) and `model` (`kimi-k3`); do not
rewrite model-reviewed labels as human labels when reporting.

Distribution of the 30 verified Detect positives by CWE:
CWE-295 (12), CWE-208 (9), CWE-327 (3), CWE-338 (2), CWE-321 (2), CWE-326 (1),
CWE-256 (1). The verified Triage exports are 30 Confirm / 19 Reject across
CRYPTO-001/005/007/008/009/010/011/013, with CRYPTO-010 (12 Confirm) and
CRYPTO-013 (9 Confirm) carrying most of the real Reject-vs-Confirm signal.

## 4. Detect: Target-Crypto Coverage and Dilution

Only **434 of 2037** Detect positives carry a target crypto CWE. The remaining
**1603** positives are generic (web/app/memory) vulnerabilities, dominated by
CWE-89, CWE-79, CWE-330, CWE-259, CWE-78, CWE-605, CWE-94, CWE-22, CWE-20 and
CWE-502. The model can look balanced while spending most of its positive
supervision on non-crypto defects.

| Target CWE | Positives |
|---|---:|
| CWE-327 | 275 |
| CWE-326 | 63 |
| CWE-295 | 33 |
| CWE-208 | 18 |
| CWE-338 | 14 |
| CWE-916 | 11 |
| CWE-256 | 10 |
| CWE-321 | 5 |
| CWE-329 | 5 |
| **Total** | **434** |

Rare CWEs (CWE-321, CWE-329, CWE-916, CWE-256, CWE-208) are the thinnest
slices; per-CWE recall there will have high variance.

## 5. Triage Rule Distribution

| Rule | Confirm | Reject |
|---|---:|---:|
| CRYPTO-001 | 63 | 79 |
| CRYPTO-002 | 32 | 32 |
| CRYPTO-003 | 6 | 13 |
| CRYPTO-004 | 6 | 7 |
| CRYPTO-005 | 9 | 6 |
| CRYPTO-006 | 5 | 5 |
| CRYPTO-007 | 8 | 4 |
| CRYPTO-008 | 17 | 9 |
| CRYPTO-009 | 18 | 21 |
| CRYPTO-010 | 47 | 27 |
| CRYPTO-011 | 4 | 6 |
| CRYPTO-012 | 4 | 8 |
| CRYPTO-013 | 4 | 6 |
| Unmapped (no parseable rule prefix) | 28 | 15 |

43 rows have no parseable `[CRYPTO-xxx]` prefix in the serialized finding.
Normalize the finding prefix before computing per-rule Triage metrics, or those
rows will silently drop out of rule-level recall.

## 6. Length Slices

| Task | n | median | p95 | max | < 4 lines | > 120 lines |
|---|---:|---:|---:|---:|---:|---:|
| Detect | 3633 | 56 | 416 | 1378 | 107 | 960 |
| Triage | 489 | 6 | 142 | 5798 | 121 | 34 |

Report short/normal/long slices separately. A single aggregate score hides
truncation failures on long snippets and degenerate behavior on very short
ones. The longest Triage snippets (up to ~5.8k lines) are the ones most likely
to exceed `max_length=2048`.

## 7. Leakage Risk (residual, disclose it)

The de-leaked frozen eval slices (`data/round6/validation_frozen/`) are clean
against the optimization-visible train/val artifacts:

- R6 detect eval: 19 rows (7 pos / 12 neg), 0 dropped.
- R6 triage eval: 36 rows (4 Confirm / 32 Reject), 6 dropped
  (`round4-real-passlib` duplicates).
- R5 slices regenerated likewise (13 detect / 35 triage).

The builder's own duplicate/AST QA passes for the R6-new slice, but an
independent cross-split audit of the **merged** artifact still finds residual
near-duplicates:

| Pair | Exact rows | AST-identical rows |
|---|---:|---:|
| train / val | 2 | 21 |
| train / test | 2 | 17 |
| val / test | 2 | 2 |

These come from inherited R5/R4 rows, not the R6-new sources. Keep
repository/commit-level splits for newly merged data, and do not claim zero
leakage from the merged artifact.

## 8. Recommended Evaluation Protocol

Report at least these slices, and never fold them into a single headline number:

- Detect overall accuracy/F1; **target-crypto macro-F1**; per-CWE recall for the
  9 target CWEs, calling out the rare CWEs (CWE-321/329/916/256/208).
- Detect short / normal / long length slices.
- Triage Confirm/Reject precision and recall **per rule**; the frozen slice is
  only 4 Confirm, so confirm-recall is report-only (counts + confidence
  interval, no pass/fail gate).
- The 30 verified Detect positives and 49 verified Triage records as a
  separate "real verified" slice, distinct from rule fixtures and generic
  negatives.
- Time/repository holdout to bound contamination.

## 9. What Is Still Missing

1. **Verified real crypto positives: 30, target 50-100.** The single largest
   gap. Continue the GHSA/OSV → fix-commit → parent-source → review pipeline
   until the confirmed set reaches the gate.
2. **Verified Reject records: 19.** Enough to demonstrate the schema, thin for
   estimating false-positive control per rule.
3. **Rare-CWE coverage** (CWE-321/329/916/256/208): low single digits to ~18
   positives each.
4. **Frozen Triage Confirm slice: 4 rows.** Add de-leaked real Confirm rows
   before treating confirm-recall as meaningful.
5. **License hygiene.** Rule-fixture rows sourced from Semgrep carry the
   Semgrep Rules License v1.0; Bandit-derived rows are Apache-2.0. Handle the
   Semgrep-derived rows accordingly if the dataset is redistributed.

## 10. Closure Path

1. Train the full base on the frozen artifacts; verify the three SHA-256
   hashes in `r6_manifest.json` immediately before the run.
2. Add a **train-only crypto-focus sampler** (oversample target-crypto
   positives by CWE and rule, keep generic negatives, never touch val/test or
   cross repository/commit boundaries).
3. Keep expanding the verified-real pool toward the 50-100 gate; merge as R6
   successor sources rather than a new round.
4. Evaluate with the protocol in section 8 and publish crypto-specific and
   real-verified metrics separately from the aggregate.
