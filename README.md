# AI-Assisted Cryptographic Code Security Auditor

A hybrid **static analysis x fine-tuned LLM x agent** research prototype that audits Python code for known cryptographic misuse patterns, classifies findings by CWE, filters false positives, and produces a structured security report.

> **Temporary closure (2026-10-05).** Round 6 was fully retrained and evaluated.
> It recovered from the Round-5 detect collapse, but it did **not** pass the
> documented acceptance gates: frozen detect precision `0.500`, frozen triage
> FPR `0.125`, 18-probe accuracy `0.667`, and secure-library FPR `0.20`. Treat
> this as a research baseline, not a production crypto auditor. See
> [Round-6 final evaluation](data/round6/eval/RESULTS.md).
>
> The next investment is data and evaluation quality, not another immediate
> retrain: expand verified real crypto positives from 30 toward 50-100, build a
> larger de-leaked Confirm slice, fix triage consistency, and only then revisit
> the base model.

---

## Highlights

- **13 hand-written Semgrep rules** (`rules/CRYPTO-001..013`) targeting common crypto misuse (MD5, SHA-1, DES/3DES, RC4, AES-ECB, predictable IV, hard-coded keys, weak randomness, weak key length, insecure TLS, plaintext password storage, weak KDF parameters, non-constant-time comparison), each with CWE, severity, and fix recommendation.
- **Round-6 model**: fresh-base QLoRA retraining of `Qwen3-4B-Instruct` on 4,122
  train/val/test records across `detect` and `triage`. Deployment model ID:
  `qwen3-4b-instruct-2507-5f8261ad123d`.
- **Round-6 final evaluation**: frozen detect F1 `0.588`; full test-split detect
  F1 `0.671`; frozen triage accuracy `0.889` but FPR `0.125`; 18 real probes
  `12/18` correct; secure-library FPR `0.20`.
- **Archived Round 3/4 results remain useful context**: detect F1 `0.694` and
  domain triage FPR `0.067` on their respective held-out slices. They are not
  comparable to the Round-6 frozen slices.
- No credentials required to self-test: a deterministic `mock` backend runs the
  whole benchmark for CI.

## Key Results

### Round 6 final evaluation (2026-10-05)

| suite | n | key result |
|---|---:|---|
| frozen detect | 19 (7 pos / 12 neg) | recall `0.714`, precision `0.500`, F1 `0.588`, CWE accuracy `0.400` |
| frozen triage | 36 (4 Confirm / 32 Reject) | Confirm recall `1.000` (report-only), FPR `0.125`, accuracy `0.889` |
| real triage probes | 18 (12 Confirm / 6 Reject) | accuracy `0.667`, Confirm recall `0.500`, FPR `0.000` |
| R6 test split | 602 detect / 58 triage | detect F1 `0.671`; triage Confirm recall `0.571`, FPR `0.200` |
| rule capability matrix | 13 vulnerable + 13 safe | detected `11/13`, CWE correct `6/13`, safe not flagged `10/13` |
| secure-library anti-FP | 10 | not flagged `8/10`, FPR `0.20` |

| acceptance gate | target | observed | status |
|---|---|---|---|
| detect precision | `> 0.54` | `0.500` frozen / `0.550` test | FAIL on frozen slice |
| domain FPR | `<= 0.06` | `0.125` frozen / `0.200` test | FAIL |
| 18-probe accuracy | `>= 0.95` | `0.667` | FAIL |
| triage Confirm recall | report-only | `1.000` on 4 positives | not statistically meaningful |

**Read:** R6 is a real improvement over the Round-5 detect collapse, but it is
not a release-quality crypto audit model. The main failures are low Confirm
recall on real probes, high false-positive rates, weak CWE routing, and false
positives on secure-library code such as `AESGCM` and `nacl.SecretBox`.
Evidence and per-row predictions are in
[`data/round6/eval/RESULTS.md`](data/round6/eval/RESULTS.md).

### Round 3/4 archived results

#### Generic detection slice — PyCode-Vul official test split (n = 569)

| system | recall | precision | F1 | accuracy | CWE acc |
|---|---|---|---|---|---|
| Static (Semgrep) | 0.112 | 1.000 | **0.201** | 0.524 | 0.324 |
| Fine-tuned LLM (Qwen3-4B) | 0.984 | 0.536 | **0.694** | 0.534 | 0.897 |

#### Domain triage slice — crypto findings (n = 29)

| system | confirm recall | FPR | accuracy |
|---|---|---|---|
| Static (Semgrep, all-alarm baseline) | 1.000 | **1.000** | 0.483 |
| Fine-tuned LLM | 0.929 | **0.067** | 0.931 |
| Agent (LLM + fixture guard) | 0.929 | **0.067** | 0.931 |

**Read**: On the Round 3/4 slices, Semgrep alone confirms everything
(FPR 1.0); the fine-tuned LLM/agent cut the false-positive rate to 0.067 while
keeping recall at 0.929 on the domain slice, and reached 0.694 F1 on generic
detection. The Round-6 frozen evaluation above supersedes these as the current
release status.

> System scope actually implemented in `evaluation/benchmark.py`: detect supports
> `static` and `llm`; triage supports `static` (accept-all), `llm`, and `agent`.
> `agent` on the detect slice is an alias of `llm`, and Base-LLM / Static+Base /
> Static+Fine-tuned rows are **not implemented**. The five-system ablation is out
> of scope for this release.

## Scope (current release): known patterns only

This release is deliberately limited to **predicting already-known crypto
vulnerability patterns and their known fixes**. Discovering or generalizing to
*previously unknown* vulnerability patterns is out of scope and left to a
follow-up project.

Consequences for data, rules, and evaluation:

- **Data** only contains examples of a *known vulnerable form* paired with its
  *known safe replacement* (e.g. CRYPTO-001: MD5-on-credentials → SHA-256 /
  HMAC / scrypt / Argon2id). The model is taught to reproduce the mapping
  `known pattern → known fix`, not to invent new fixes.
- **Static rules** are a closed list (`CRYPTO-001..013`). New rules are
  admitted only when they encode a *documented* vulnerable form with a
  standards-backed fix (`docs/crypto_vuln_taxonomy.md`).
- **Triage** may Reject a finding only when the exception is itself documented
  in the taxonomy (weak primitive in a non-security purpose; a crypto *library*
  implementing a legacy format for compatibility). Unseen/ambiguous cases are
  treated as out of scope, not guessed.
- **Evaluation** measures how well the pipeline recognizes and routes *known*
  forms (detection recall/precision, triage confirm-recall/FPR on held-out
  known-form and real-library slices).

Unknown-pattern discovery (novel misuse shapes, new algorithm weaknesses,
pattern-independent generation) is explicitly **not** a goal of this release.

## Pipeline

```
Python code
   │
   ▼
Semgrep (13 CRYPTO rules) ─────────────► candidate findings   [recall layer]
   │
   ▼
LLM Agent (fine-tuned Qwen3-4B)
   │   detect   : code → {vulnerable, CWE, severity}
   │   triage   : finding + context → {Confirm/Reject, explanation, fix}
   │
   ▼
Structured JSON ──► Markdown report (+ LaTeX/PDF export)
```

Components: `analyzer/` (Semgrep + AST runners), `agent/` (SecurityAgent), `model/` (cloud & mock LLM backends), `evaluation/` (benchmark + report generators).

## Quickstart

### 1. Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # semgrep, openai, pyyaml, pandas ...
```

### 2. Audit a file or directory

```bash
python main.py -i examples/demo_crypto_vulns.py -o reports
python main.py -i path/to/codebase -o reports
```

This runs Semgrep + AST scan → context extraction → agent triage → report (`reports/*.md`, or `-f json`).

### 3. Reproduce the benchmark (no credentials needed)

```bash
python main.py --benchmark --config configs/benchmark.yaml
```

`configs/benchmark.yaml` defaults to `model.kind: mock` — a deterministic local self-test. To evaluate the real model, set `kind: cloud` and provide:

```bash
export LLM_API_KEY=...     # DashScope/ModelScope OpenAI-compatible key
export LLM_BASE_URL=...    # default: https://dashscope.aliyuncs.com/compatible-mode/v1
export LLM_MODEL_ID=...    # e.g. your fine-tuned qwen3-4b deployment id
```

### 4. Validate the Semgrep rules

```bash
semgrep --test --config rules
```

## Custom Rules (`rules/`)

| ID | Name | CWE |
|---|---|---|
| CRYPTO-001 | MD5 | CWE-327 |
| CRYPTO-002 | SHA-1 | CWE-327 |
| CRYPTO-003 | DES/3DES | CWE-327 |
| CRYPTO-004 | RC4 | CWE-327 |
| CRYPTO-005 | AES-ECB | CWE-327 |
| CRYPTO-006 | Predictable IV | CWE-329 |
| CRYPTO-007 | Hard-coded key | CWE-321 |
| CRYPTO-008 | Weak randomness | CWE-338 |
| CRYPTO-009 | Weak key length | CWE-326 |
| CRYPTO-010 | Insecure TLS | CWE-326 / CWE-295 |
| CRYPTO-011 | Plaintext password storage | CWE-256 |
| CRYPTO-012 | Weak KDF parameters | CWE-916 |
| CRYPTO-013 | Non-constant-time compare | CWE-208 |

Every rule carries `rule_id / name / cwe / severity / pattern / description / recommendation / references` and passes `semgrep --test`.

## Data & Evaluation

- **Generic slice**: [PyCode-Vul](https://github.com/S-AIR-L/PyCode-Vul) (`cc-by-4.0`, Zenodo DOI [10.5281/zenodo.19746552](https://doi.org/10.5281/zenodo.19746552)); split by repository to prevent leakage; official train/test split used for evaluation.
- **Domain slice**: vulnerable/secure crypto pairs labeled against `docs/crypto_vuln_taxonomy.md` (weak pattern → real impact → safe alternative).
- **Real-world held-out set**: metadata + labels for 5 open-source Python crypto libraries — `itsdangerous`, `passlib`, `pyjwt`, `python-rsa`, `pycryptodome` (see [manifest](data/round4/real_validation/manifest.json)); upstream source repos are recorded, not committed verbatim.
- **Round-5/6 lineage**: Round-6 merges the R5 final base with 322 curated/rule-fixture additions plus 79 advisory-backed verified real records (401 new total, `train/val/test = 3115/347/660`); rebuild with `scripts/build_round6_final_dataset.py --emit`. Advisory-backed real records are merged into R6 from `data/round6/real_verified_{detect,triage}.jsonl`; there is no separate Round 7. The emitted artifact hashes are frozen in `data/round6/final/r6_manifest.json`. The de-leaked Round-6 eval slices are in `data/round6/validation_frozen/`, produced by `scripts/audit_dataset_leakage.py --write-frozen`. See [docs/dataset.md](docs/dataset.md), [reports/data_quality/r6_final_feasibility.md](reports/data_quality/r6_final_feasibility.md), and [the final R6 evaluation](data/round6/eval/RESULTS.md) for provenance, splits, leakage controls, and measured results.
- **Model-assisted real-data review**: `scripts/audit_real_crypto_with_llm.py --estimate-only` estimates Kimi token use before any paid call. The model pass writes only `model_audit.jsonl` with `verified=false` and builds an uncertain/sampled human queue; `reviewer/README.md` documents the browser review flow. Model output never enters the verified-real training exports.

## Model & Fine-Tuning

- Base: `Qwen3-4B-Instruct`, served through an OpenAI-compatible cloud endpoint
  (Bailian/DashScope).
- Round-6 deployment: `qwen3-4b-instruct-2507-5f8261ad123d`; fine-tune job
  `ft-202610051556-cc87`; workspace `ws-avxkjb2tq5lq1gwm`.
- QLoRA fine-tune: **rank 16 / alpha 32 / dropout 0.005**, learning rate
  `1e-4`, three epochs, batch size 128, max length 4096, cosine schedule.
- Key lesson (documented in round-4 eval notes): incremental fine-tuning caused
  **catastrophic forgetting** (detect recall 0.990 -> 0.584); Round 6 therefore
  started from a fresh base and merged all R6 records before training.

## Known Limitations

- Python only (v1); static rules are intentionally recall-focused — precision is handled downstream by the LLM.
- Generic detection is trained mostly on public web/Django-style vulnerabilities; crypto-negative samples barely move that metric.
- Real library *legacy-hash implementations* (e.g. passlib) were over-confirmed
  in R4/R5. R6 added a "library-legacy / compatibility-implementation" negative
  class, but real-library false positives remain: the secure-library probe has
  FPR `0.20`, including false positives on `AESGCM` and `nacl.SecretBox`.
- Five-system ablation rows for **Base LLM / Static+Base / Static+Fine-tuned** are not implemented; the supported systems are documented above.
- The Round-6 baseline additions are **unverified curated/rule-fixture** samples
  (`verified=false` on 322/322). R6 adds **79** advisory-backed verified real
  records (60 K3-reviewed + 19 manually reviewed), but the verified real crypto
  set is only **30 unique confirmed positives** and the frozen triage slice has
  only **4 Confirm** positives, so confirm-recall remains report-only. No
  real-crypto generalisation claim is supported.
- R6 fails the documented FPR and 18-probe acceptance gates. The 18-probe run
  contains six `Confirm -> Reject` misses, three explanation/verdict
  contradictions, and three hallucinated unsafe-context explanations.
- CWE routing is weak: frozen CWE accuracy is `0.400`, and only `6/13` rule
  probes receive the expected CWE.
- The merged training artifact is **not duplicate-free**. An independent audit
  found residual exact and AST-identical overlaps inherited from R4/R5
  (`train/val`, `train/test`, `val/test`). Do not claim zero leakage.

## Temporary Closure and Future Work

This release is intentionally paused as a reproducible research baseline. The
next cycle should prioritize the bottlenecks in this order:

1. **Data**: expand advisory-backed, commit-pinned real crypto positives from
   30 toward 50-100; target CWE-321/326/327/329/338/916/208 and build at least
   20 verified Reject records. Keep repository-level and time-based splits.
2. **Evaluation**: add a de-leaked Confirm slice large enough to make
   confirm-recall meaningful; report per-CWE and per-rule metrics; keep generic
   PyCode-Vul scores separate from crypto-specific evidence.
3. **Triage alignment**: make training and inference use the same purpose
   prompt, remove the trailing Reject-biased cue or train against it explicitly,
   and add consistency checks that fail when explanation and verdict disagree.
4. **Base-model optimization**: after the data/eval gates are met, retrain on a
   stronger base model (8B-14B or a newer instruction model), keep the frozen
   evaluation unchanged, and compare against the current Qwen3-4B baseline.
   Consider preference tuning for verdict consistency only after supervised
   data quality is stable.
5. **Product use**: keep the model behind the static-analysis and human-review
   workflow. Do not deploy it as a standalone gate until FPR, Confirm recall,
   and CWE routing pass the documented gates.

## Security & Ethics

Defensive security research only: this project detects crypto misuse, assists audits, and filters false positives. It does not attack real systems or generate exploit code. See the in-repo project plan for the full scope statement.

## Repository Layout

```
crypto-ai-auditor/
├── main.py                  # CLI entrypoint (audit / benchmark)
├── rules/                   # 13 custom Semgrep CRYPTO rules
├── analyzer/                # semgrep_runner / ast_scanner / parser
├── agent/                   # SecurityAgent (detect + triage, fixture guard)
├── model/                   # LLM backends (cloud / mock) + prompts
├── evaluation/              # benchmark.py, report_generator.py
├── configs/                 # base / benchmark / real-projects YAML
├── data/                    # splits, SFT chatml, round-2/3/4 evals, real-project manifest
├── docs/                    # architecture / taxonomy / experiment / dataset notes
├── reports/                 # benchmark reports + experiment report (LaTeX/PDF)
├── scripts/                 # dataset builders, SFT prep, probe runners
└── examples/                # demo vulnerable code
```

## References

- [PyCode-Vul](https://github.com/S-AIR-L/PyCode-Vul) — public vulnerability dataset (`cc-by-4.0`)
- MITRE CWE — label taxonomy (CWE-321/326/327/328/329/330/338/759/916)
- NIST SP 800-131A — algorithm transitions used by the rule taxonomy
- `reports/round1-4_experiment_report.pdf` — full experiment write-up (LaTeX source included)
