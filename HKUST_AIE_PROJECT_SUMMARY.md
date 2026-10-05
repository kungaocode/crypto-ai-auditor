# HKUST AIE Application Project Summary

> Project: AI-Assisted Cryptographic Code Security Auditor
>
> Repository root: `01-ai-crypto-code-security-auditor`
>
> Status: temporary research closure, 2026-10-05
>
> Intended use: HKUST AIE application, interview preparation, project portfolio,
> and future R7 planning

---

## 1. One-Sentence Pitch

I built a reproducible research prototype that combines static analysis, a
fine-tuned small language model, and an agent-style triage workflow to detect
known Python cryptographic misuse patterns, classify their CWE types, filter
false positives, and generate structured audit reports.

The project is deliberately honest about its maturity: Round 6 recovered from a
serious Round 5 regression and demonstrated basic discrimination ability, but
it is not yet a production-grade security auditor.

---

## 2. Motivation

Static application security testing tools are good at finding suspicious
patterns, but they often produce many false positives. General-purpose large
language models can explain code, but they may hallucinate security context,
confuse compatibility code with a real vulnerability, or produce inconsistent
verdicts.

This project explores a middle ground:

- use static analysis as a high-recall candidate generator;
- use a small fine-tuned model as a semantic detector and triage layer;
- keep a human-review path for uncertain records;
- measure results on frozen evaluation slices instead of relying on anecdotes;
- treat data provenance and leakage control as first-class engineering issues.

The long-term product hypothesis is an audit copilot for Python software teams:
not a replacement for security engineers, but a system that reduces manual
screening time and explains why a finding should be confirmed or rejected.

---

## 3. Problem Definition and Scope

### 3.1 Tasks

The prototype supports two tasks.

| Task | Input | Output |
|---|---|---|
| Detect | Python function or code snippet | `vulnerable`, CWE, severity, confidence, explanation |
| Triage | Code plus a static finding | `Confirm` or `Reject`, explanation, optional patch |

### 3.2 Current Scope

The current release targets known cryptographic misuse patterns only:

- weak hash algorithms;
- broken ciphers such as DES, 3DES, and RC4;
- AES-ECB and unsafe IV or nonce usage;
- hard-coded keys;
- weak random number generation;
- weak key lengths;
- disabled TLS verification;
- plaintext password storage;
- weak KDF parameters;
- non-constant-time comparison.

It does not claim the ability to discover previously unknown cryptographic
vulnerability classes. Novel vulnerability discovery is a separate research
problem.

### 3.3 Non-Goals

- No exploit generation.
- No real-system attack capability.
- No claim of production readiness.
- No claim that model-generated review is equivalent to human ground truth.
- No claim of zero data leakage.

---

## 4. System Architecture

```text
Python source code
        |
        v
Custom Semgrep rules
        |
        v
Candidate findings
        |
        v
Fine-tuned Qwen3-4B model
   detect: vulnerability + CWE
   triage: Confirm / Reject + explanation
        |
        v
Structured JSON and Markdown audit report
```

Main components:

- `rules/`: 13 custom Semgrep rules covering CRYPTO-001 through CRYPTO-013.
- `analyzer/`: Semgrep and AST execution.
- `agent/`: security agent workflow and fixture guard.
- `model/`: cloud and deterministic mock backends.
- `evaluation/`: benchmark and report generation.
- `scripts/`: dataset builders, leakage audits, review queues, and evaluation.
- `reviewer/`: browser-based human review workflow.

---

## 5. Data Engineering and Model-Assisted Review

### 5.1 Final Round 6 Dataset

| Item | Value |
|---|---:|
| Total records | 4,122 |
| Train | 3,115 |
| Validation | 347 |
| Test | 660 |
| Round 6 new records | 401 |
| Advisory-backed verified real records | 79 |
| Unique verified crypto positives | 30 |
| Frozen detect eval | 19 rows |
| Frozen triage eval | 36 rows, including 4 Confirm rows |

### 5.2 Data Sources and Provenance

- PyCode-Vul for generic Python vulnerability detection.
- Advisory-backed records tied to package advisories and fix commits.
- Public crypto-library code pinned to specific commits.
- Hand-built rule fixtures and curated records for the 13 known rule families.
- Model-assisted review output, explicitly marked as model-reviewed rather than
  human-reviewed.

### 5.3 Review Workflow

The review process was designed to reduce manual workload:

1. Collect candidate records from advisories, repositories, and rule fixtures.
2. Estimate model token cost before paid review.
3. Use a stronger model to screen uncertain candidates.
4. Import only uncertain or sampled records into the browser review platform.
5. Keep source metadata and review provenance attached to each record.
6. Freeze training and evaluation artifacts with hashes.

### 5.4 Important Provenance Rule

Model review is not human review. The project records 60 K3-reviewed records
and 19 manually reviewed records separately. Future reports should preserve
this distinction.

---

## 6. Experiment History

### Round 1: Initial Dual-Task Baseline

Goal: establish both detect and triage capabilities.

Outcome:

- detect showed usable generic performance but over-reported vulnerable code;
- triage over-confirmed weak primitives used for non-security purposes.

Lesson: detection and triage need different data and decision criteria.

### Round 2: Incremental Triage Training

Goal: add triage samples to reduce false positives.

Outcome:

- the incremental update caused catastrophic forgetting;
- triage improved on the immediate target while detect and domain recall
  collapsed.

Lesson: small incremental LoRA updates are unsafe when the task or data
distribution changes materially.

### Round 3: Fresh-Base Full Retraining

Goal: recover both tasks by retraining from a fresh base on merged data.

Outcome:

- detect recall `0.990`, precision `0.537`, F1 `0.697`;
- CWE accuracy `0.921`;
- domain triage recall `0.929`, FPR `0.067`;
- 18/18 probe accuracy.

Lesson: fresh-base full retraining became the stable engineering pattern.

### Round 4: Adding More Negative Samples

Goal: reduce detect over-reporting on safe cryptographic code.

Outcome:

- the full retrain roughly matched Round 3;
- the negative samples did not move the main detect false-positive behavior;
- incremental retraining again caused forgetting.

Lesson: adding synthetic negatives is not enough when the model lacks real
security-boundary context.

### Round 5: Regression

Goal: continue improving the data and model pipeline.

Outcome:

- detect F1 fell to `0.000` on the committed validation slice;
- triage FPR was `0.368`;
- the dataset QA report was `FAIL`.

Lesson: dataset quality gates and frozen evaluation are necessary. A model
cannot compensate for a broken or poorly validated data round.

### Round 6: Recovery and Reproducible Baseline

Goal: rebuild the data, freeze de-leaked evaluation slices, retrain from the
base model, and evaluate the result honestly.

Final model:

| Item | Value |
|---|---|
| Deployment model ID | `qwen3-4b-instruct-2507-5f8261ad123d` |
| Fine-tune job | `ft-202610051556-cc87` |
| Base model | `qwen3-4b-instruct-2507` |
| LoRA rank / alpha / dropout | `16 / 32 / 0.005` |
| Learning rate | `1e-4` |
| Epochs | `3` |
| Batch size | `128` |
| Maximum length | `4096` |

---

## 7. Round 6 Final Results

### 7.1 Main Metrics

| Suite | Sample Size | Result |
|---|---:|---|
| Frozen detect | 19 | recall `0.714`, precision `0.500`, F1 `0.588`, CWE accuracy `0.400` |
| Frozen triage | 36, 4 Confirm | Confirm recall `1.000`, FPR `0.125`, accuracy `0.889` |
| Real triage probes | 18 | accuracy `0.667`, Confirm recall `0.500`, FPR `0.000` |
| R6 test-split detect | 602 | recall `0.859`, precision `0.550`, F1 `0.671`, CWE accuracy `0.724` |
| R6 test-split triage | 58 | Confirm recall `0.571`, FPR `0.200`, accuracy `0.690` |
| Rule capability matrix | 26 | detected `11/13`, CWE correct `6/13`, safe not flagged `10/13` |
| Secure-library anti-FP | 10 | not flagged `8/10`, FPR `0.20` |

### 7.2 Acceptance Gates

| Gate | Target | R6 Result | Status |
|---|---|---|---|
| Detect precision | greater than `0.54` | `0.500` frozen | Fail |
| Domain FPR | less than or equal to `0.06` | `0.125` frozen, `0.200` test | Fail |
| 18-probe accuracy | greater than or equal to `0.95` | `0.667` | Fail |
| Confirm recall | report-only because only 4 frozen positives | `1.000` on 4 rows | Not statistically meaningful |

### 7.3 Improvement over Round 5

| Metric | Round 5 | Round 6 | Interpretation |
|---|---:|---:|---|
| Detect F1 | `0.000` | `0.588` frozen, `0.671` test | Recovered from detection collapse |
| Detect recall | `0.000` | `0.714` frozen, `0.859` test | Basic detection ability returned |
| Triage FPR | `0.368` | `0.125` frozen | Frozen-slice false positives decreased |
| Triage accuracy | `0.658` | `0.889` frozen | Better on the frozen slice |
| Triage Confirm recall | `1.000` on 3 positives | `0.500` on 18 probes | The result does not generalize |

The comparison is directional rather than strictly like-for-like because the
Round 5 and Round 6 evaluation slices are not identical. Round 5 also varied
between runs.

---

## 8. What Round 6 Proves and What It Does Not Prove

### It Does Prove

- A fresh-base full-retraining pipeline can recover from a failed round.
- The model learned basic signals for explicit crypto misuse patterns.
- Static rules plus LLM triage can be evaluated end to end.
- Data provenance, leakage audits, frozen evaluation, and model review queues
  can be implemented in one reproducible repository.
- Small positive count and weak context labels are major bottlenecks.

### It Does Not Prove

- production-level detection precision;
- reliable Confirm recall on real vulnerabilities;
- robust CWE routing;
- zero false positives on safe crypto libraries;
- generalization to unseen cryptographic vulnerability patterns;
- readiness for autonomous deployment.

### Application-Relevant Interpretation

For the available resources, Round 6 is a reasonable research baseline. It
shows that the model has basic discrimination ability, but its ceiling is
limited by data quality, label context, and evaluation-set size. The next
improvement should not be described as simply "train longer."

---

## 9. Main Technical Findings

1. **Fresh-base retraining is safer than incremental LoRA updates.** Two
   incremental experiments caused catastrophic forgetting.
2. **Data quality gates matter more than raw sample count.** Round 5 failed
   because the dataset itself did not satisfy its QA checks.
3. **Small positive sets make recall unstable.** The frozen triage slice has
   only four Confirm rows, so one prediction changes recall by 25 percentage
   points.
4. **Prompt alignment affects verdict consistency.** Training and inference
   used different purpose guidance, and Round 6 produced explanation/verdict
   contradictions.
5. **Explicit patterns are easier than contextual security reasoning.** The
   model recognizes MD5, DES, RC4, ECB, and similar patterns more reliably than
   it judges whether a weak primitive is used for a security-sensitive purpose.
6. **Safe library code is a difficult negative class.** AESGCM and
   `nacl.SecretBox` still triggered false positives.
7. **PyCode-Vul and crypto-specific evaluation must remain separate.** Generic
   web vulnerability labels cannot measure crypto-specific generalization.
8. **LLM-assisted review improves throughput but is not a replacement for
   provenance-aware ground truth.**

---

## 10. Common Application and Interview Questions

### Q1. Why did you choose cryptographic code security?

Cryptographic misuse is a useful intersection of security, static analysis,
and language-model reasoning. The rules are concrete enough to evaluate, but
the real-world context is difficult enough to expose the limits of both static
analysis and general-purpose LLMs.

### Q2. Why combine static analysis and an LLM?

Static rules provide recall and traceability. The LLM adds semantic filtering
and explanation. Neither is sufficient alone: rules create false positives,
while a standalone LLM may hallucinate security context.

### Q3. Why fine-tune a small model instead of using a larger API model?

A small fine-tuned model is cheaper, easier to deploy, and useful for studying
domain adaptation. The project intentionally treats the large model as an
annotation and review assistant, not as the final deployed auditor.

### Q4. What is the most important lesson from the failed rounds?

Model quality cannot compensate for bad data QA. Round 5 showed that a model
can fail because the dataset itself is invalid. Round 6 therefore prioritized
artifact freezing, de-leaked evaluation slices, provenance, and reproducible
scripts.

### Q5. How do you know Round 6 is better than Round 5?

Round 5 had detect F1 `0.000`, while Round 6 reached `0.588` on the frozen
slice and `0.671` on the R6 test split. Frozen triage FPR also dropped from
`0.368` to `0.125`. However, Round 6 still fails the precision, FPR, and probe
accuracy gates.

### Q6. Why do you say the model has basic discrimination ability?

It detects explicit misuse patterns and can explain many correct decisions.
The 13-rule capability matrix detects 11 of 13 vulnerable examples, and the
frozen detect recall is `0.714`. The limitation is that it often fails when the
decision depends on purpose, context, or subtle API semantics.

### Q7. Why is Confirm recall a problem?

On the 18 real triage probes, recall is only `0.500`. Six true Confirm cases
were rejected. Three responses contained a correct explanation but emitted the
wrong verdict, and three hallucinated cache, ETag, or test-fixture context.

### Q8. Why not claim zero data leakage?

The merged training artifact still contains residual exact and AST-identical
cross-split overlaps inherited from earlier rounds. The frozen evaluation set
avoids optimization-visible overlap, but the full corpus is not duplicate-free.
The honest statement is that leakage was audited and reduced, not eliminated.

### Q9. Why is the CWE result weak?

The model often collapses different vulnerabilities into CWE-327, CWE-259, or
CWE-798. Frozen CWE accuracy is `0.400`, and only 6 of 13 rule probes receive
the expected CWE. The model learned coarse weakness-oriented labels more easily
than fine-grained taxonomy routing.

### Q10. What would you do next?

The first priority is data and metadata, not another immediate retrain. The
next target is 50 to 100 verified real crypto positives, at least 20 verified
Reject records, commit-pinned provenance, repository-level and time-based
splits, and a larger de-leaked Confirm evaluation slice.

### Q11. Would you optimize the base model next?

Yes, but after the data gate. A stronger 8B to 14B base model is a reasonable
R7 direction, but replacing the model before improving labels would make it
hard to distinguish a genuine capability gain from better fitting of noisy
data.

### Q12. What metadata would improve the dataset most?

The highest-value metadata includes repository, commit, package, version, CWE,
rule ID, function boundary, call target, data source, license, review
provenance, security purpose, exposure to untrusted input, credential or key
handling, test or compatibility context, and split group.

### Q13. How can this project be relevant to AIE or entrepreneurship?

The product hypothesis is an audit copilot that helps software teams reduce
manual triage time and explain findings. The project demonstrates the full
cycle: identify a user problem, build an MVP, measure it, discover a data
bottleneck, and redesign the roadmap based on evidence. It is not yet a
commercial claim, but it is a concrete example of turning an AI idea into a
measurable technical system.

### Q14. What was the hardest engineering trade-off?

The trade-off between recall and precision. A rule-only system catches many
patterns but over-confirms. A model-only system may be too confident without
traceability. The project settled on static analysis as the recall layer and
the model as the triage layer, with the human review workflow retained for
uncertain cases.

### Q15. What would you improve in the evaluation methodology?

I would add per-CWE and per-rule metrics, a larger real-crypto Confirm slice,
an adversarial safe-library slice, consistency checks for explanation versus
verdict, and an explicit separation between generic PyCode-Vul performance and
crypto-specific evidence.

### Q16. What does the project say about your approach to failure?

It documents failed rounds instead of hiding them. Round 5 was a regression,
but it produced a stronger process: dataset QA gates, frozen slices, leakage
audits, provenance labels, and acceptance criteria. That is useful evidence of
engineering judgment.

---

## 11. Experimental Matters and Reproducibility Notes

### 11.1 Do

- Freeze data artifacts and record hashes.
- Keep train, validation, and test splits separate.
- Audit exact and AST-level leakage before claiming a clean benchmark.
- Use a frozen evaluation set for final reporting.
- Report sample size and positive count with every recall metric.
- Separate human-reviewed, model-reviewed, and curated data.
- Keep generic vulnerability evaluation separate from crypto-specific
  evaluation.
- Estimate paid-model cost before running large annotation batches.
- Store secrets only in local environment files that are not committed.
- Record model IDs, fine-tune job IDs, hyperparameters, and evaluation scripts.
- Use fresh-base full retraining when the task or data distribution changes.

### 11.2 Do Not

- Do not call model output human ground truth.
- Do not mix Round 3, Round 4, Round 5, and Round 6 metrics in one table
  without a compatibility note.
- Do not report a single recall value without the number of positive examples.
- Do not use the frozen evaluation set for iterative prompt tuning and then
  describe it as untouched.
- Do not claim production readiness from the R6 test split alone.
- Do not commit API keys, raw external datasets, large candidate pools, or
  generated local review files.
- Do not add more synthetic examples before checking the real-data bottleneck.
- Do not describe the project as discovering unknown vulnerabilities.

### 11.3 Reproduction Entry Points

```bash
# Validate Python syntax
python3 -m py_compile \
  scripts/run_round6_eval.py \
  scripts/run_round6_test_split.py \
  scripts/run_round6_capability.py

# Validate JSON outputs
python3 - <<'PY'
import json, pathlib
for path in pathlib.Path("data/round6/eval").glob("*.json"):
    json.loads(path.read_text())
    print("valid", path)
PY

# Check Git diff cleanliness
git diff --check
```

The main evaluation evidence is in:

- `data/round6/eval/RESULTS.md`
- `data/round6/eval/benchmark_r6.json`
- `data/round6/eval/test_split_r6.json`
- `data/round6/eval/capability_r6.json`
- `data/round6/eval/triage_probe_results_r6.json`
- `docs/experiment.md`
- `reports/benchmark/benchmark.md`
- `reports/data_quality/r6_final_feasibility.md`

---

## 12. Personal Contribution Framing

The following claims can be adapted to the application. Keep only the parts
that accurately reflect the applicant's actual contribution.

- Designed and implemented an end-to-end Python cryptographic code auditing
  prototype.
- Built a static-analysis plus LLM plus agent workflow.
- Created 13 Semgrep rules mapped to CWE categories and remediation guidance.
- Constructed and evaluated Round 6 training and frozen evaluation artifacts.
- Built scripts for dataset construction, leakage auditing, model evaluation,
  capability probing, and anti-false-positive testing.
- Implemented a browser-based human review platform for candidate annotations.
- Used a stronger model as a review assistant while preserving provenance
  between model-reviewed and manually reviewed records.
- Diagnosed catastrophic forgetting and changed the training strategy to
  fresh-base full retraining.
- Documented failed rounds, acceptance gates, residual leakage, and deployment
  limitations instead of overstating model performance.

---

## 13. Resume-Style Bullet Draft

- Built a static-analysis x fine-tuned LLM x agent prototype for Python
  cryptographic code auditing, covering 13 known crypto misuse rules and two
  tasks: vulnerability detection and finding triage.
- Rebuilt a 4,122-record Round 6 dataset with 79 advisory-backed verified
  records, frozen de-leaked evaluation slices, artifact hashes, and a
  provenance-aware review workflow.
- Evaluated a QLoRA fine-tuned Qwen3-4B model across four suites; recovered
  detect F1 from `0.000` in Round 5 to `0.588` on the frozen slice and `0.671`
  on the Round 6 test split.
- Identified the remaining bottlenecks as verified-positive scarcity, weak
  contextual metadata, triage verdict inconsistency, and residual data
  overlap; proposed data-first R7 optimization before base-model replacement.

---

## 14. Future Work: R7 Direction

### Stage A: Data and Metadata

- Expand verified crypto positives from 30 toward 50 to 100.
- Add at least 20 verified Reject records.
- Pin every real example to a repository commit and package version.
- Add security-purpose, exposure, compatibility, fixture, and credential
  metadata.
- Keep repository-level and time-based splits.
- Build a larger de-leaked Confirm evaluation slice.

### Stage B: Triage Alignment

- Make training and inference use the same purpose prompt.
- Test whether the trailing Reject cue biases the verdict.
- Add deterministic checks for explanation and verdict consistency.
- Evaluate false positives separately for safe library implementations.

### Stage C: Base-Model Optimization

- Compare Qwen3-4B against one or two stronger 8B to 14B base models.
- Keep the frozen evaluation set unchanged.
- Run the same data, prompt, and decoding settings for every candidate.
- Report per-CWE, per-rule, per-repository, and real-probe results.

### Stage D: Product Exploration

- Position the system as an audit copilot, not an autonomous gate.
- Integrate with existing SAST output instead of replacing it.
- Measure human review time saved and explanation usefulness.
- Explore a business hypothesis around DevSecOps teams, fintech, and software
  supply-chain security.

---

## 15. Final Reflection

The most important outcome of this project is not a single benchmark number.
It is the discovery of where the real bottleneck lies.

The model already has basic discrimination ability. Explicit weak
cryptographic patterns can often be detected, and static rules plus LLM triage
create a coherent architecture. However, the system still lacks enough
verified real positives, enough contextual metadata, a sufficiently large
Confirm evaluation slice, and consistent triage behavior.

For an AIE application, the project demonstrates:

- technical execution across rules, data, fine-tuning, evaluation, and review;
- ability to diagnose and correct a failed experiment;
- honesty about limitations;
- understanding that model capability is bounded by data and evaluation
  quality;
- a clear path from research prototype to product hypothesis.

The recommended next step is therefore:

> Strengthen real data and metadata first, retrain on the same base model,
> compare against a stronger base model with an unchanged frozen evaluation,
> and only then consider preference tuning or production deployment.

