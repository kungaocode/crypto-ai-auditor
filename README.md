# AI-Assisted Cryptographic Code Security Auditor

A hybrid **static analysis × fine-tuned LLM × agent** pipeline that audits Python code for cryptographic misuse, classifies findings by CWE, filters false positives, and produces a structured security report.

> **One-line claim**: combining custom Semgrep rules (recall), a QLoRA-fine-tuned `Qwen3-4B` (triage), and a lightweight agent (false-positive filtering) detects more real crypto risks with far fewer false alarms than static rules alone — and the numbers are reproducible from this repo.

---

## Highlights

- **10 hand-written Semgrep rules** (`rules/CRYPTO-001..010`) targeting common crypto misuse (MD5, SHA-1, DES/3DES, RC4, AES-ECB, predictable IV, hard-coded keys, weak randomness, weak key length, insecure TLS), each with CWE, severity, and fix recommendation.
- **Domain-adapted LLM**: QLoRA fine-tuning (rank 16 / alpha 32) of `Qwen3-4B-Instruct` on a balanced vulnerable/secure SFT set across two tasks — `detect` (function-level vulnerability + CWE + severity) and `triage` (confirm/reject a static finding with an explanation).
- **Two-slice evaluation** (see [reports/benchmark/benchmark.md](reports/benchmark/benchmark.md)):
  - *Generic slice*: 569 held-out functions from the official PyCode-Vul test split.
  - *Domain slice*: 29 crypto findings (vulnerable/secure pairs authored against [the in-repo taxonomy](docs/crypto_vuln_taxonomy.md)).
- **Real-world probes**: 18/18 correct verdicts (12 vulnerable + 6 safe) → **FPR 0** on that probe set.
- No credentials required to self-test: a deterministic `mock` backend runs the whole benchmark for CI.

## Key Results

### Generic detection slice — PyCode-Vul official test split (n = 569)

| system | recall | precision | F1 | accuracy | CWE acc |
|---|---|---|---|---|---|
| Static (Semgrep) | 0.112 | 1.000 | **0.201** | 0.524 | 0.324 |
| Fine-tuned LLM (Qwen3-4B) | 0.984 | 0.536 | **0.694** | 0.534 | 0.897 |

### Domain triage slice — crypto findings (n = 29)

| system | confirm recall | FPR | accuracy |
|---|---|---|---|
| Static (Semgrep, all-alarm baseline) | 1.000 | **1.000** | 0.483 |
| Fine-tuned LLM | 0.929 | **0.067** | 0.931 |
| Agent (LLM + fixture guard) | 0.929 | **0.067** | 0.931 |

**Read**: Semgrep alone confirms everything (FPR 1.0); the fine-tuned LLM/agent cuts the false-positive rate to 0.067 while keeping recall at 0.929 on the domain slice, and reaches 0.694 F1 on generic detection.

> A full five-system ablation (Static only / Base LLM / Static+Base / Static+Fine-tuned / Full Agent) is in progress; current published rows are **Static**, **Fine-tuned LLM**, and **Agent**.

## Pipeline

```
Python code
   │
   ▼
Semgrep (10 CRYPTO rules) ─────────────► candidate findings   [recall layer]
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

Every rule carries `rule_id / name / cwe / severity / pattern / description / recommendation / references` and passes `semgrep --test`.

## Data & Evaluation

- **Generic slice**: [PyCode-Vul](https://github.com/S-AIR-L/PyCode-Vul) (`cc-by-4.0`, Zenodo DOI [10.5281/zenodo.19746552](https://doi.org/10.5281/zenodo.19746552)); split by repository to prevent leakage; official train/test split used for evaluation.
- **Domain slice**: vulnerable/secure crypto pairs labeled against `docs/crypto_vuln_taxonomy.md` (weak pattern → real impact → safe alternative).
- **Real-world held-out set**: metadata + labels for 5 open-source Python crypto libraries — `itsdangerous`, `passlib`, `pyjwt`, `python-rsa`, `pycryptodome` (see [manifest](data/round4/real_validation/manifest.json)); upstream source repos are recorded, not committed verbatim.
- SFT sets (`data/sft/*_chatml.jsonl`) and all round-2/3/4 evaluation artifacts are committed for reproducibility.

## Model & Fine-Tuning

- Base: `Qwen3-4B-Instruct`, served through an OpenAI-compatible cloud endpoint (DashScope/ModelScope).
- QLoRA fine-tune: **rank 16 / alpha 32**, two explicit tasks (`detect` / `triage`), temperature 0.1 for stable JSON output.
- Key lesson (documented in round-4 eval notes): incremental fine-tuning caused **catastrophic forgetting** (detect recall 0.990 → 0.584); the shipped model was instead **retrained from base on a balanced 50:50 vulnerable/secure set**.

## Known Limitations

- Python only (v1); static rules are intentionally recall-focused — precision is handled downstream by the LLM.
- Generic detection is trained mostly on public web/Django-style vulnerabilities; crypto-negative samples barely move that metric.
- Real library *legacy-hash implementations* (e.g. passlib) are still over-confirmed (0/11 on an internal held-out check) — new "library-legacy" negative class is a planned next step.
- Five-system ablation rows for **Base LLM / Static+Base / Static+Fine-tuned** are not yet published.

## Security & Ethics

Defensive security research only: this project detects crypto misuse, assists audits, and filters false positives. It does not attack real systems or generate exploit code. See the in-repo project plan for the full scope statement.

## Repository Layout

```
crypto-ai-auditor/
├── main.py                  # CLI entrypoint (audit / benchmark)
├── rules/                   # 10 custom Semgrep CRYPTO rules
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
