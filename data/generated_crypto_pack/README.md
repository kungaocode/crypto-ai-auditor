# Generated Python Crypto Training Pack

This pack contains hand-authored Python cryptographic code for quick model and
web-auditor smoke tests. It is not a replacement for the verified Round-6
dataset.

## Contents

- `python/` contains every sample as a standalone `.py` snippet or class.
- `source/all.jsonl` is the v2 source schema used by the repository.
- `source/detect.jsonl` and `source/triage.jsonl` are task-specific views.
- `upload/{train,val,test}.jsonl` are chatml files for platform fine-tuning.
- `generated_crypto_pack.zip` contains every standalone Python sample in a
  form that can be uploaded directly through the web app.
- `manifest.json` records counts and output paths.

## Coverage

The pack covers all 13 rule families, `CRYPTO-001` through `CRYPTO-013`. It
includes vulnerable examples, safe modern implementations, and benign uses of
weak primitives where collision resistance or unpredictability is not a
security requirement. Triage samples include both `Confirm` and `Reject`
verdicts, with safe patches for confirmed findings.

## Important Provenance

Every generated record has `verified=false`. The labels are suitable for
smoke testing, weak supervision, and dataset planning, but they must not be
presented as independently verified real-world ground truth.

Rebuild the pack with:

```bash
./venv/bin/python scripts/build_generated_crypto_pack.py
```

For an immediate web-app test, upload `generated_crypto_pack.zip` through the
upload view or paste an individual example from `python/`.
