# Round-6 Real-Crypto Reviewer

Local browser app for binary review of advisory-backed Python crypto candidates.
It uses only the Python standard library and native HTML/CSS/JavaScript. Each
item has exactly two outcomes: `confirm` or `reject`. There is no uncertain,
scope-out, or license field in the UI.

## Start

```bash
python3 scripts/annotate_real_crypto.py --open
```

The default candidate file is
`data/round6/candidates/real_crypto_candidates_enriched.jsonl`; if it is
absent, the app falls back to `real_crypto_candidates.jsonl`.

Useful overrides:

```bash
python3 scripts/annotate_real_crypto.py \
  --reviewer kun \
  --port 8766 \
  --candidates data/round6/candidates/real_crypto_candidates_broad.jsonl
```

## Strong-model (K3) pre-audit

For batches where a review pass is delegated to a model, run the strict binary
audit with `kimi-k3`. The model returns only `confirmed` or `rejected`; any
insufficient-evidence case is forced to `rejected`, and transport/parse
failures are recorded as `error` and never imported.

Estimate token usage and currency cost first (the script never guesses prices):

```bash
python3 scripts/audit_real_crypto_with_llm.py \
  --candidates data/round6/candidates/real_crypto_candidates_a_functions.jsonl \
  --model kimi-k3 \
  --reasoning-effort high \
  --workers 2 \
  --no-resume \
  --model-out data/round6/candidates/model_audit_k3_binary.jsonl \
  --queue-out data/round6/candidates/model_audit_k3_binary_queue.jsonl \
  --cost-report-out reports/data_quality/model_audit_k3_cost.json \
  --estimate-only \
  --price-input 20 \
  --price-output 100
```

Drop `--estimate-only` to actually call the API. The key is read from
`MOONSHOT_API_KEY`/`KIMI_API_KEY`, then `api.txt`, then `apitxt`, and is never
printed.

Import the successful binary verdicts into the review store and rebuild the
verified exports:

```bash
python3 scripts/import_model_audit_verdicts.py \
  --candidates data/round6/candidates/real_crypto_candidates_a_functions.jsonl \
  --audit data/round6/candidates/model_audit_k3_binary.jsonl \
  --reviewer reviewer-kimi
```

The importer maps `confirmed -> confirm` and `rejected -> reject`, skips
`error`/malformed/missing-evidence rows, keeps existing labels unless
`--overwrite` is passed, and writes a provenance report to
`reports/data_quality/model_audit_k3_import.json`.

## Review outcomes

- `confirm`: exports one Detect positive and one Triage `Confirm`.
- `reject`: exports one Triage `Reject`.

`confirm` requires a target rule, a valid target CWE, an explanation, and two
Python snippets that parse with `ast.parse`. `reject` requires the vulnerable
snippet and an explanation. The reviewer may correct snippets inside the
browser before confirming.

## Provenance

Labels carry their own provenance so the dataset is never misrepresented as
fully human-verified:

- `review_mode=manual` for records entered in the browser.
- `review_mode=model` with `model` (e.g. `kimi-k3`), `model_confidence`, and
  `source_audit` for records imported from a model audit.

Both modes export the same way once a binary label exists, which lets a model
pass stand in as the finalized label while keeping the audit trail honest.

## Storage

Each verdict is the source of truth:

```text
data/round6/review/web/<reviewer>/labels/<verdict>/<candidate_id>.json
```

The app also maintains a JSONL index and rebuilds:

```text
data/round6/real_verified_detect.jsonl
data/round6/real_verified_triage.jsonl
```

Both outputs are optional inputs to:

```bash
python3 scripts/build_round6_final_dataset.py --dry-run
```

No label is invented by the app. A candidate only enters the verified-real
exports after a `confirm` or `reject` is recorded, either by a reviewer in the
browser or by the K3 importer.
