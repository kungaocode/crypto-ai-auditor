#!/usr/bin/env python3
"""Evaluate the deployed R6 model on the full held-out test split.

Source: data/round6/final/upload/full/test.jsonl (n=660, the SFT test split;
detect 602 / triage 58). Each record is {"messages":[system,user,assistant]};
the assistant message is the ground-truth JSON label.

The deployed inference path is used (triage appends TRIAGE_PURPOSE_GUIDE), so
this measures the model as it actually runs in the pipeline.

Usage (from repo root):
  export LLM_API_KEY="$(sed -n '2p' api.txt)"
  export LLM_MODEL_ID="qwen3-4b-instruct-2507-5f8261ad123d"
  export LLM_WORKSPACE="ws-avxkjb2tq5lq1gwm"
  python3 scripts/run_round6_test_split.py
"""
import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from model.inference import CloudBackend, LLMError
from evaluation.benchmark import _detect_metrics, _triage_metrics

TEST_PATH = ROOT / "data" / "round6" / "final" / "upload" / "full" / "test.jsonl"
OUT_DIR = ROOT / "data" / "round6" / "eval"
DEFAULT_MODEL_ID = "qwen3-4b-instruct-2507-5f8261ad123d"

# gentle global rate limiter (requests/min bound) shared across workers
_rate_lock = threading.Lock()
_last_ts = [0.0]


def _throttle(min_interval=0.15):
    with _rate_lock:
        now = time.time()
        wait = _last_ts[0] + min_interval - now
        if wait > 0:
            time.sleep(wait)
        _last_ts[0] = time.time()


def parse_record(rec):
    """Return (task, code, finding, gt_dict) from an SFT record."""
    msgs = rec["messages"]
    user = msgs[1]["content"]
    gt = json.loads(msgs[2]["content"])
    if "Task: detect" in user:
        task = "detect"
        code = user.split("Code:\n", 1)[1]
        finding = ""
    else:
        task = "triage"
        # finding sits between "Static Finding: " and "\nCode:\n"
        rest = user.split("Static Finding: ", 1)[1]
        finding = rest.split("\nCode:\n", 1)[0]
        code = rest.split("\nCode:\n", 1)[1]
    return task, code, finding, gt


def _norm_verdict(v) -> str:
    v = (v or "").strip().lower()
    if "confirm" in v:
        return "Confirm"
    if "reject" in v:
        return "Reject"
    return "?"


def call_one(backend, idx, task, code, finding):
    _throttle()
    for attempt in range(4):
        try:
            if task == "detect":
                return idx, backend.detect(code), None
            return idx, backend.triage(code, finding), None
        except LLMError as e:
            if attempt < 3:
                time.sleep(2.0 * (attempt + 1))
                continue
            return idx, {}, str(e)
    return idx, {}, "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model-id", default=None)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--limit", type=int, default=0, help="cap records (debug)")
    args = ap.parse_args()

    model_id = args.model_id or DEFAULT_MODEL_ID
    backend = CloudBackend(model_id=model_id)
    print(f"[*] backend: {type(backend).__name__} model={backend.model_id}")

    recs = [json.loads(l) for l in TEST_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    if args.limit:
        recs = recs[: args.limit]
    print(f"[*] test split: n={len(recs)}")

    jobs = [(i, *parse_record(r)) for i, r in enumerate(recs)]

    preds = [None] * len(jobs)
    errors = []
    done = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(call_one, backend, idx, task, code, finding): idx
                for idx, task, code, finding, _ in jobs}
        for fut in as_completed(futs):
            idx, out, err = fut.result()
            preds[idx] = out
            if err:
                errors.append((idx, err))
            done += 1
            if done % 100 == 0 or done == len(jobs):
                el = time.time() - t0
                print(f"    {done}/{len(jobs)}  ({el:.0f}s, {done/el:.1f} rec/s)")
                # checkpoint raw predictions so a later crash does not lose the run
                (args.out_dir / "_test_split_preds_partial.json").write_text(
                    json.dumps({"preds": preds, "errors": errors}), encoding="utf-8")

    detect_recs, triage_recs = [], []
    detect_preds, triage_preds = [], []
    for i, task, code, finding, gt in jobs:
        p = preds[i] or {}
        if task == "detect":
            detect_recs.append({"id": f"test-{i}", "label": gt, "code": code})
            detect_preds.append(p)
        else:
            triage_recs.append({"id": f"test-{i}", "label": gt, "code": code, "finding": finding})
            triage_preds.append(p)

    out = {
        "model_id": model_id,
        "n_total": len(recs),
        "n_detect": len(detect_recs),
        "n_triage": len(triage_recs),
        "errors": errors,
        "detect": {"metrics": _detect_metrics(detect_recs, detect_preds)},
        "triage": {"metrics": _triage_metrics(triage_recs, triage_preds)},
        # compact per-record: id + gt + pred (for auditability without dumping code)
        "detect_rows": [
            {"id": f"test-{i}", "gt_vuln": bool(r["label"].get("vulnerable")),
             "gt_cwe": r["label"].get("cwe", ""), "pred_vuln": bool((p or {}).get("vulnerable")),
             "pred_cwe": (p or {}).get("cwe", "")}
            for i, (r, p) in enumerate(zip(detect_recs, detect_preds))
        ],
        "triage_rows": [
            {"id": f"test-{i}", "gt": r["label"].get("verdict"),
             "pred": _norm_verdict((p or {}).get("verdict"))}
            for i, (r, p) in enumerate(zip(triage_recs, triage_preds))
        ],
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "test_split_r6.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n==== DETECT (test split) ====")
    m = out["detect"]["metrics"]
    print(f"  n={m['n']} tp={m['tp']} fp={m['fp']} fn={m['fn']} tn={m['tn']} "
          f"recall={m['recall']} precision={m['precision']} f1={m['f1']} "
          f"acc={m['accuracy']} cwe_acc={m['cwe_acc']}")
    print("\n==== TRIAGE (test split) ====")
    m = out["triage"]["metrics"]
    print(f"  n={m['n']} gt_confirm={m['gt_confirm']} gt_reject={m['gt_reject']} "
          f"confirm_recall={m['confirm_recall']} fpr={m['fpr']} acc={m['accuracy']}")
    print(f"\n[+] wrote {args.out_dir}/test_split_r6.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
