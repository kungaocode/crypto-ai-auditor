# Web Audit Feedback Dataset

This directory receives source files submitted through the CryptoAudit web
application. Records are written to `submissions.jsonl`, one JSON object per
source file. The JSONL file is intentionally ignored by Git because submitted
code may contain proprietary, credential-adjacent, or otherwise sensitive
material.

## Runtime controls

- `CRYPTOAUDIT_FEEDBACK=0` disables retention.
- `CRYPTOAUDIT_FEEDBACK_DIR=/path/to/dataset` changes the output directory.

## Record contract

Each row contains:

- `id`, `audit_id`, `created_at`: traceability back to the web audit.
- `language`, `file`, `code`, `code_sha256`, `bytes`, `lines`: source data.
- `task`: `detect` when no local findings exist, otherwise `triage`.
- `label`: a review-pending static/model candidate, not a verified label.
- `findings`: normalized findings, verdicts, explanations, and patches.
- `provenance`: model mode, model ID, and scan options.
- `verified=false`, `review_status=pending`, `training_ready=false`.

The model-produced label is suitable for weak supervision or active-learning
ranking. It must not be reported as human ground truth.

## Promoting records into training

1. Review each row and set `review_status=reviewed`.
2. Set `verified=true` only when supporting evidence exists.
3. Normalize approved rows into the repository's v2 schema
   (`id, language, task, code, label, finding, source, license, verified, split`).
4. Run `scripts/prepare_sft_data.py` to emit platform-ready chat messages.
5. Audit exact, AST-level, and source-level leakage before adding the rows to a
   training split.

Recommended split assignment:

- Group rows from the same project or `code_sha256` family into one split.
- Keep a held-out validation slice before any retraining run.
- Never place a reviewed row in both the training and evaluation sets.
