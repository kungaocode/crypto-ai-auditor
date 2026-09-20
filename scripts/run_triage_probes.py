#!/usr/bin/env python3
"""Run the 18 grounded triage probes against a live cloud model and compare.

These probes are hand-labelled snippets where the flagged crypto call is ALWAYS
visible in the code (unlike the context-misaligned domain split), so they measure
the model's real Confirm/Reject judgment. Used to locate weaknesses before a
fine-tune and to verify improvement after it.

Usage (from repo root):
  # summarize an existing results file (no API call), e.g. the pre-training run:
  python scripts/run_triage_probes.py --results data/round2/eval/triage_probe_results_before.json

  # run against the live model (needs env LLM_API_KEY + LLM_MODEL_ID):
  export LLM_API_KEY="$(sed -n '2p' api.txt)"
  export LLM_MODEL_ID="qwen3-4b-instruct-2507-<NEW-SUFFIX>"
  python scripts/run_triage_probes.py --out data/round2/eval/triage_probe_results_after.json

  # then diff after vs before:
  python scripts/run_triage_probes.py --results data/round2/eval/triage_probe_results_after.json \
      --compare data/round2/eval/triage_probe_results_before.json
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROBES = ROOT / "data/round2/eval/triage_probes.json"
DEFAULT_OUT = ROOT / "data/round2/eval/triage_probe_results_after.json"

sys.path.insert(0, str(ROOT))


def _norm(v: str) -> str:
    v = (v or "").strip().lower()
    if "confirm" in v:
        return "Confirm"
    if "reject" in v:
        return "Reject"
    return v or "?"


def summarize(rows) -> dict:
    n = len(rows)
    gtc = [r for r in rows if r["gt"] == "Confirm"]
    gtr = [r for r in rows if r["gt"] == "Reject"]
    cp = sum(1 for r in gtc if r["pred"] == "Confirm")
    fp = sum(1 for r in gtr if r["pred"] == "Confirm")
    ok = sum(1 for r in rows if r["pred"] == r["gt"])
    return {
        "n": n,
        "n_confirm_gt": len(gtc), "n_reject_gt": len(gtr),
        "confirm_recall": (cp / len(gtc)) if gtc else None,
        "fpr": (fp / len(gtr)) if gtr else None,   # GT-Reject but Confirm
        "accuracy": ok / n,
        "mismatches": [r for r in rows if r["pred"] != r["gt"]],
    }


def print_summary(tag: str, m: dict) -> None:
    print(f"\n[{tag}] n={m['n']}  GT Confirm={m['n_confirm_gt']}  GT Reject={m['n_reject_gt']}")
    print(f"  confirm_recall={m['confirm_recall']:.3f}  fpr={m['fpr']:.3f}  accuracy={m['accuracy']:.3f}")
    if m["mismatches"]:
        print("  mismatches:")
        for r in m["mismatches"]:
            print(f"    #{r['idx']} gt={r['gt']:<7} pred={r['pred']:<7} | {r['name']}")


def load_rows(path: Path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list) and data and isinstance(data[0], dict):
        # already a results file {gt, pred|verdict, ...}
        rows = []
        for r in data:
            pred = _norm(r.get("pred") or r.get("verdict") or "")
            rows.append({"idx": r.get("idx"), "gt": r["gt"], "pred": pred,
                         "name": r.get("name", ""), "explanation": r.get("explanation", "")})
        return rows
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--probes", type=Path, default=DEFAULT_PROBES)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--results", type=Path, default=None,
                    help="summarize an existing results json (no model call)")
    ap.add_argument("--compare", type=Path, default=None,
                    help="a second results file to diff against (e.g. the pre-training run)")
    args = ap.parse_args()

    if args.results:
        rows = load_rows(args.results)
        if rows is None:
            print(f"[!] {args.results} is not a recognized results/probes file")
            return 2
        print_summary(str(args.results.name), summarize(rows))
        if args.compare:
            other = load_rows(args.compare)
            if other:
                print_summary(f"compare {args.compare.name}", summarize(other))
        return 0

    from model.inference import CloudBackend, LLMError
    probes = json.loads(Path(args.probes).read_text(encoding="utf-8"))
    backend = CloudBackend()  # model_id/api_key/base_url from env
    rows = []
    for i, (gt, finding, code) in enumerate(probes):
        try:
            out = backend.triage(code, finding)
        except LLMError as e:
            print(f"  !! probe #{i} error: {e}")
            out = {}
        pred = _norm(out.get("verdict"))
        name = (code.strip().splitlines()[0] if code.strip() else "")[:60]
        rows.append({"idx": i, "gt": gt, "pred": pred,
                     "name": name, "explanation": out.get("explanation", "")})
        flag = "OK" if pred == gt else "**"
        print(f"  #{i:<2} gt={gt:<7} pred={pred:<7} {flag}  {name}")

    m = summarize(rows)
    print_summary("RUN", m)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] saved -> {args.out}")
    if args.compare:
        other = load_rows(args.compare)
        if other:
            mo = summarize(other)
            print("\n=== DELTA (before -> after) ===")
            print(f"  confirm_recall : {mo['confirm_recall']:.3f} -> {m['confirm_recall']:.3f}")
            print(f"  fpr            : {mo['fpr']:.3f} -> {m['fpr']:.3f}")
            print(f"  accuracy       : {mo['accuracy']:.3f} -> {m['accuracy']:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
