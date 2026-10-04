# AI-Assisted Cryptographic Code Security Auditor

A hybrid **static analysis × fine-tuned LLM × agent** pipeline that audits Python code for cryptographic misuse, classifies findings by CWE, filters false positives, and produces a structured security report.

> **One-line claim**: combining custom Semgrep rules (recall), a QLoRA-fine-tuned `Qwen3-4B` (triage), and a lightweight agent (false-positive filtering) detects more real crypto risks with far fewer false alarms than static rules alone — and the numbers are reproducible from this repo.

---

## Highlights

- **13 hand-written Semgrep rules** (`rules/CRYPTO-001..013`) targeting common crypto misuse (MD5, SHA-1, DES/3DES, RC4, AES-ECB, predictable IV, hard-coded keys, weak randomness, weak key length, insecure TLS, plaintext password storage, weak KDF parameters, non-constant-time comparison), each with CWE, severity, and fix recommendation.
- **Domain-adapted LLM**: QLoRA fine-tuning (rank 16 / alpha 32) of `Qwen3-4B-Instruct` on a balanced vulnerable/secure SFT set across two tasks — `detect` (function-level vulnerability + CWE + severity) and `triage` (confirm/reject a static finding with an explanation).
- **Two-slice evaluation**: a *generic slice* (569 held-out functions from the official
  PyCode-Vul test split) and a *domain slice* of crypto findings authored against
  [the in-repo taxonomy](docs/crypto_vuln_taxonomy.md).
- **Real-world probes (Round 3 acceptance run)**: 18/18 correct verdicts (12 vulnerable
  + 6 safe) → FPR 0 on that probe set.
- No credentials required to self-test: a deterministic `mock` backend runs the whole benchmark for CI.

> **Round status.** The numbers below are **Round 3/4 archived results**. Round 5
> regressed (the committed `reports/benchmark/benchmark.json` is a degraded Round-5
> run: detect F1 0.0, triage FPR 0.368 on 41 findings). Round 6 rebuilt the data and
> a frozen eval set (`data/round6/validation_frozen/`); the Round-6 retrain is **not
> yet run**, so no Round-6 metrics are published here.

## Key Results

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

**Read**: Semgrep alone confirms everything (FPR 1.0); the fine-tuned LLM/agent cuts the false-positive rate to 0.067 while keeping recall at 0.929 on the domain slice, and reaches 0.694 F1 on generic detection.

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
- **Round-5/6 lineage**: Round-6 merges the R5 final base with 322 curated/rule-fixture additions plus 79 advisory-backed verified real records (401 new total, `train/val/test = 3115/347/660`); rebuild with `scripts/build_round6_final_dataset.py --emit`. Advisory-backed real records are merged into R6 from `data/round6/real_verified_{detect,triage}.jsonl`; there is no separate Round 7. The emitted artifact hashes are frozen in `data/round6/final/r6_manifest.json`. The de-leaked Round-6 eval slices are in `data/round6/validation_frozen/`, produced by `scripts/audit_dataset_leakage.py --write-frozen`. See [docs/dataset.md](docs/dataset.md) and [reports/data_quality/r6_final_feasibility.md](reports/data_quality/r6_final_feasibility.md) for provenance, splits, and leakage controls.
- **Model-assisted real-data review**: `scripts/audit_real_crypto_with_llm.py --estimate-only` estimates Kimi token use before any paid call. The model pass writes only `model_audit.jsonl` with `verified=false` and builds an uncertain/sampled human queue; `reviewer/README.md` documents the browser review flow. Model output never enters the verified-real training exports.

## Model & Fine-Tuning

- Base: `Qwen3-4B-Instruct`, served through an OpenAI-compatible cloud endpoint (DashScope/ModelScope).
- QLoRA fine-tune: **rank 16 / alpha 32**, two explicit tasks (`detect` / `triage`), temperature 0.1 for stable JSON output.
- Key lesson (documented in round-4 eval notes): incremental fine-tuning caused **catastrophic forgetting** (detect recall 0.990 → 0.584); the shipped model was instead **retrained from base on a balanced 50:50 vulnerable/secure set**.

## Known Limitations

- Python only (v1); static rules are intentionally recall-focused — precision is handled downstream by the LLM.
- Generic detection is trained mostly on public web/Django-style vulnerabilities; crypto-negative samples barely move that metric.
- Real library *legacy-hash implementations* (e.g. passlib) were over-confirmed in R4/R5; R6 adds a "library-legacy / compatibility-implementation" negative class, but the effect is unmeasured until the R6 model is trained.
- Five-system ablation rows for **Base LLM / Static+Base / Static+Fine-tuned** are not implemented; the supported systems are documented above.
- The Round-6 baseline additions are **unverified curated/rule-fixture** samples (`verified=false` on 322/322). R6 adds **79** advisory-backed verified real records (60 K3-reviewed + 19 manually reviewed), but the verified real crypto set is only **30 unique confirmed positives** and the frozen triage slice has only **4 Confirm** positives, so confirm-recall is report-only. No real-crypto generalisation claim is supported until the 50-100 A-class gate is met and the R6 retrain has been evaluated.

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
