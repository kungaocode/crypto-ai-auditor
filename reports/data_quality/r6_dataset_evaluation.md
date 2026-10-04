# R6 Fine-Tuning Dataset Evaluation

Date: 2026-10-04

> **SUPERSEDED (2026-10-04).** This report was written against the 4062-record
> intermediate state, before the K3 binary review import. It reports 19 verified
> real records and 322 R6 additions. The finalized artifacts are **4122**
> records (3115/347/660) with **401** R6 additions and **79** verified real
> records. See `reports/data_quality/r6_final_feasibility.md` for the current
> numbers. The qualitative risks below (crypto dilution, thin Triage Confirm
> slice, length slices, residual leakage) still hold.

## 1. Current Inventory

The frozen R6 upload artifacts contain:

| Split | Detect | Triage | Total |
|---|---:|---:|---:|
| Train | 2712 | 349 | 3061 |
| Val | 297 | 46 | 343 |
| Test | 601 | 57 | 658 |
| Total | 3610 | 452 | 4062 |

Detect has 2014 positives and 1596 negatives. Triage has 228 Confirm and
224 Reject. The aggregate class balance is acceptable.

R6 contributes 341 new records. Only 19 of them are advisory-backed real
records with `verified=true`; all 19 are currently in train:

- 7 Detect positives
- 12 Triage records: 7 Confirm and 5 Reject

## 2. Main Risk: Crypto Dilution

Only 411 of the 2014 Detect positives use a target crypto CWE. The remaining
1603 positives are generic non-target vulnerabilities.

| Split | Target crypto positives | Non-target positives |
|---|---:|---:|
| Train | 315 | 1206 |
| Val | 25 | 144 |
| Test | 71 | 253 |
| Total | 411 | 1603 |

Target-positive coverage:

| CWE | Count |
|---|---:|
| CWE-327 | 274 |
| CWE-326 | 62 |
| CWE-295 | 22 |
| CWE-338 | 12 |
| CWE-916 | 11 |
| CWE-208 | 11 |
| CWE-256 | 10 |
| CWE-329 | 5 |
| CWE-321 | 4 |
| Total | 411 |

Dominant non-target positives include CWE-89, CWE-79, CWE-330, CWE-259,
CWE-78, CWE-605, CWE-94, CWE-22, CWE-20, and CWE-502. The model can therefore
look balanced while spending most of its positive supervision on generic web
and application vulnerabilities.

## 3. Triage Evaluation

Triage rule distribution:

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

Six rows could not be mapped back to a rule from the serialized finding
prefix. They should be normalized before the final evaluation run.

The frozen R6 triage evaluation slice has only 4 Confirm and 32 Reject. A
single Confirm changes confirm recall by 25 percentage points, so this slice
can be reported but must not be the main acceptance gate.

## 4. Length and Generalization Risks

Detect snippets have median 57 lines, p95 416 lines, and maximum 1378 lines.
There are 107 snippets below 4 lines and 959 above 120 lines.

Triage snippets have median 5 lines, p95 141 lines, and maximum 724 lines.
There are 121 below 4 lines and 31 above 120 lines.

The final evaluation should include separate short, normal, and long
slices. A single aggregate score will hide truncation and context failures.

## 5. A-Class Status and Candidate Pool

The current verified real inventory does not yet satisfy the original A-class
targets:

- 7 verified real Detect positives
- 12 verified real Triage records, including only 3 real Reject records
- One verified Triage record has no CVE
- All 19 verified records are assigned to train

The strong-model pre-audit contains 44 rows:

- 28 confirmed
- 3 uncertain
- 7 rejected
- 6 out_of_scope

After excluding 17 already-reviewed items, 22 remain for human review:
21 model-confirmed and 1 model-uncertain. These span 22 repositories and
22 advisories.

The generated review queue is:

`data/round6/candidates/real_crypto_candidates_remaining_review_queue.jsonl`

## 6. Concrete Supplementation Plan

### Step 1: Finish the current high-confidence queue

Start the reviewer with the generated remaining queue:

```bash
python3 scripts/annotate_real_crypto.py \
  --candidates data/round6/candidates/real_crypto_candidates_remaining_review_queue.jsonl \
  --reviewer reviewer-kimi \
  --open
```

This is the cheapest path to increase verified real positives. The 21
model-confirmed rows are not automatically accepted; each still requires
human Confirm or Reject.

### Step 2: Rebuild and validate R6

```bash
python3 scripts/build_round6_final_dataset.py --dry-run
python3 scripts/build_round6_final_dataset.py --emit
python3 scripts/audit_dataset_leakage.py --write-frozen
python3 scripts/build_dataset_metadata.py
```

Do not edit `data/round6/validation_frozen/` manually.

### Step 3: Fetch the remaining target-CWE code pairs

There are 61 target-CWE candidates in `need_code`, covering 56 repositories.
The high-precision fetch queue currently contains 60 rows: 35 P0 and 25 P1.

```bash
python3 scripts/build_a_fetch_queue.py --scope target --emit
GITHUB_TOKEN=ghp_xxx bash scripts/run_a_class_fetch.sh
```

The fetch pipeline may only use a real parent commit or an exact advisory
reference. If the vulnerable source cannot be reconstructed from a verified
parent, leave the record in the candidate pool; do not invent it.

### Step 4: Pre-audit new pairs before human review

```bash
python3 scripts/audit_real_crypto_with_llm.py \
  --candidates data/round6/candidates/real_crypto_candidates_a_functions.jsonl \
  --estimate-only \
  --model kimi-k2.7-code \
  --reasoning-effort high \
  --price-input 6.5 \
  --price-output 27
```

Then run the model audit only after the estimate is accepted. The previous
44-row audit cost CNY 3.17, so another small batch is inexpensive relative to
the value of verified positives.

### Step 5: Expand external candidate pools

Use these as candidate pools, not as automatic truth:

- GHSA Advisory Database
- OSV and PyPI advisories
- PyPA Advisory Database
- CVEfixes, MoreFixes, ReposVul, and CrossVul Python/CWE subsets
- Semgrep, Bandit, and CodeQL fixtures for findings and Reject data

Every candidate still needs an advisory, repository, fixed commit, parent
source, concrete license, and human verdict. CWE labels alone are not
enough to promote a record.

### Step 6: Improve training focus without changing the frozen files

Create a train-only crypto-focus view or sampler that:

- oversamples target-crypto positives by rule and CWE
- preserves generic negatives needed to control false positives
- keeps val and test unchanged
- never crosses repository or commit boundaries

A practical target is to reach 50 to 100 verified real crypto positives and
at least 20 verified Reject records before treating generalization claims as
stable.

## 7. Final Evaluation Requirements

Report at least these slices:

- Detect: overall, target-crypto macro-F1, per-CWE recall, short/normal/long
- Rare CWEs: CWE-321, CWE-329, CWE-916, CWE-256, CWE-208
- Triage: Confirm/Reject precision and recall by rule
- Real verified subset separately from rule-fixture and synthetic rows
- Time and repository holdout for leakage resistance

The builder's exact and AST checks pass for the frozen R6 files, but an
independent AST audit still finds 39 cross-split duplicate groups. Disclose
this residual risk and keep repository-level splits for newly merged data.

## 8. Decision

R6 is usable for the next full fine-tune, but it is not yet strong evidence of
general Python crypto auditing. Its main role is broad vulnerability
instruction-following. The immediate closure path is:

1. human-review the 22 remaining queue rows
2. merge the accepted records into R6
3. fetch and audit the remaining target-CWE code pairs
4. add a crypto-focused train view
5. report crypto-specific and real-verified metrics separately
