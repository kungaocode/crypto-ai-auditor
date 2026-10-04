#!/usr/bin/env python3
"""Cross-round dataset leakage audit for the crypto auditor project.

The Round-5 / Round-6 lineage reuses code across rounds (R4 real-project
validation -> R5 eval -> R5 training base -> R6 eval). This script measures
that reuse instead of assuming it away.

It reports three overlap signals between named artifacts:
  1. exact   : whitespace/case-normalized source text
  2. ast     : ast.dump() of the parsed snippet (structure-only)
  3. repo    : (repo_url, commit, file) triple for real-repository records

Run:
    python3 scripts/audit_dataset_leakage.py \
        --out reports/data_quality/leakage_report

Add --write-frozen to emit eval slices with every optimization-visible
overlap removed into data/round6/validation_frozen/.
"""
import argparse
import ast
import json
import re
import warnings
from collections import Counter
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

warnings.filterwarnings("ignore", category=SyntaxWarning)

TRAIN_VISIBLE = {
    "r5_final_train": ROOT / "data/round5/final/upload/full/train.jsonl",
    "r5_final_val": ROOT / "data/round5/final/upload/full/val.jsonl",
    "r6_final_train": ROOT / "data/round6/final/upload/full/train.jsonl",
    "r6_final_val": ROOT / "data/round6/final/upload/full/val.jsonl",
}

EVAL_SETS = {
    "r5_validation_detect": ROOT / "data/round5/validation/detect_eval.jsonl",
    "r5_validation_triage": ROOT / "data/round5/validation/triage_eval.jsonl",
    "r6_validation_detect": ROOT / "data/round6/validation/detect_eval.jsonl",
    "r6_validation_triage": ROOT / "data/round6/validation/triage_eval.jsonl",
}


def load_jsonl(path: Path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


@lru_cache(maxsize=None)
def normalize(code: str) -> str:
    return re.sub(r"\s+", " ", code).strip().lower()


@lru_cache(maxsize=None)
def ast_key(code: str):
    try:
        return ast.dump(ast.parse(code))
    except SyntaxError:
        return None


def _messages_to_text(record: dict) -> str:
    return "\n".join(m.get("content", "") for m in record.get("messages", []))


def _extract_code_from_messages(record: dict) -> str:
    user = next((m["content"] for m in record.get("messages", [])
                 if m.get("role") == "user"), "")
    if "Code:\n" not in user:
        return ""
    code = user.split("Code:\n", 1)[1]
    # Triage inference prompts append the purpose guide; strip it if present.
    marker = "\n\nBefore your verdict,"
    if marker in code:
        code = code.split(marker, 1)[0]
    return code.strip()


def get_code(record: dict) -> str:
    if "code" in record:
        return record["code"]
    return _extract_code_from_messages(record)


def get_id(record: dict) -> str:
    if "id" in record:
        return record["id"]
    user = next((m["content"] for m in record.get("messages", [])
                 if m.get("role") == "user"), "")
    first_line = user.splitlines()[0] if user else "?"
    code = get_code(record)
    return f"{first_line}|{normalize(code)[:48]}"


def get_task(record: dict) -> str:
    if record.get("task"):
        return record["task"]
    user = next((m["content"] for m in record.get("messages", [])
                 if m.get("role") == "user"), "")
    m = re.match(r"Task:\s*(\w+)", user)
    return m.group(1) if m else "?"


def index_by(records, keyfunc):
    idx = {}
    for rec in records:
        key = keyfunc(rec)
        if key is None:
            continue
        idx.setdefault(key, []).append(get_id(rec))
    return idx


def overlap(a: dict, b: dict):
    keys = set(a) & set(b)
    return {k: {"a": a[k], "b": b[k]} for k in keys}


def repo_key(record: dict):
    if not record.get("repo_url"):
        return None
    return (record.get("repo_url", ""), record.get("commit", ""), record.get("file", ""))


def audit(artifacts: dict):
    report = {"artifacts": {}, "checks": []}
    for name, path in artifacts.items():
        records = load_jsonl(path)
        codes = [get_code(r) for r in records]
        parsed = [ast_key(c) for c in codes]
        report["artifacts"][name] = {
            "path": str(path.relative_to(ROOT)),
            "n": len(records),
            "task": dict(Counter(get_task(r) for r in records)),
            "unparseable": sum(1 for p in parsed if p is None),
        }

    # --- exact + ast overlap: every eval set against every train-visible set ---
    eval_records = {n: load_jsonl(p) for n, p in EVAL_SETS.items()}
    train_records = {n: load_jsonl(p) for n, p in TRAIN_VISIBLE.items()}

    for eval_name, ev in eval_records.items():
        for dim, keyfunc in (
            ("exact", lambda r: normalize(get_code(r))),
            ("ast", lambda r: ast_key(get_code(r))),
        ):
            ev_idx = index_by(ev, keyfunc)
            for tr_name, tr in train_records.items():
                tr_idx = index_by(tr, keyfunc)
                hits = overlap(ev_idx, tr_idx)
                report["checks"].append({
                    "eval": eval_name,
                    "train": tr_name,
                    "dimension": dim,
                    "overlap": len(hits),
                    "eval_unique_keys": len(ev_idx),
                    "details": [{"key": k[:120], "eval_ids": v["a"], "train_ids": v["b"]}
                                for k, v in list(hits.items())[:50]],
                })

    # --- repo-level overlap across the union of all artifacts ---
    all_artifacts = {**train_records, **eval_records}
    for name, recs in all_artifacts.items():
        idx = index_by(recs, repo_key)
        report["artifacts"].setdefault(name, {})["repo_records"] = sum(
            1 for r in recs if repo_key(r))
    return report


def render_md(report: dict) -> str:
    lines = ["# Dataset Leakage Audit", ""]
    lines.append("Generated by `scripts/audit_dataset_leakage.py`.")
    lines.append("")
    lines.append("## Artifacts")
    lines.append("")
    lines.append("| artifact | n | task mix | unparseable |")
    lines.append("|---|---|---|---|")
    for name, meta in report["artifacts"].items():
        lines.append(
            f"| {name} | {meta.get('n', '?')} | {meta.get('task', {})} | "
            f"{meta.get('unparseable', '?')} |")
    lines.append("")
    lines.append("## Eval vs optimization-visible overlap")
    lines.append("")
    lines.append("| eval | train-visible | dim | overlap | eval unique |")
    lines.append("|---|---|---|---|---|")
    for c in report["checks"]:
        if c["overlap"] == 0:
            continue
        lines.append(
            f"| {c['eval']} | {c['train']} | {c['dimension']} | "
            f"**{c['overlap']}** | {c['eval_unique_keys']} |")
    clean = [c for c in report["checks"] if c["overlap"] == 0]
    lines.append("")
    lines.append(f"Zero-overlap checks: {len(clean)} / {len(report['checks'])}.")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_frozen(report: dict, out_dir: Path):
    """Emit eval slices with any optimization-visible code removed."""
    out_dir.mkdir(parents=True, exist_ok=True)
    train_keys = {"exact": set(), "ast": set()}
    for tr in TRAIN_VISIBLE.values():
        for r in load_jsonl(tr):
            code = get_code(r)
            train_keys["exact"].add(normalize(code))
            k = ast_key(code)
            if k:
                train_keys["ast"].add(k)

    manifest = {
        "generated_by": "scripts/audit_dataset_leakage.py --write-frozen",
        "policy": (
            "Eval rows whose whitespace-normalized code OR ast.dump() appears in any "
            "optimization-visible artifact (R5/R6 final train or val) are removed."
        ),
        "optimization_visible": {
            name: str(path.relative_to(ROOT)) for name, path in TRAIN_VISIBLE.items()
        },
        "slices": {},
    }

    for eval_name, path in EVAL_SETS.items():
        kept, dropped = [], []
        for r in load_jsonl(path):
            code = get_code(r)
            k = ast_key(code)
            if normalize(code) in train_keys["exact"] or (k and k in train_keys["ast"]):
                dropped.append(r)
            else:
                kept.append(r)
        payload = "\n".join(json.dumps(r, ensure_ascii=False) for r in kept) + "\n"
        targets = [out_dir / f"{eval_name}.jsonl"]
        if eval_name.startswith("r6_"):
            # Config-friendly alias used by configs/benchmark_round6.yaml.
            targets.append(out_dir / path.name)
        for out_path in targets:
            out_path.write_text(payload, encoding="utf-8")
        print(f"[frozen] {eval_name}: kept={len(kept)} dropped={len(dropped)}")

        detect = [r for r in kept if get_task(r) == "detect"]
        triage = [r for r in kept if get_task(r) == "triage"]
        manifest["slices"][eval_name] = {
            "source": str(path.relative_to(ROOT)),
            "kept": len(kept),
            "dropped_leaks": len(dropped),
            "dropped_ids": [get_id(r) for r in dropped],
            "detect_pos": sum(1 for r in detect if r.get("label", {}).get("vulnerable")),
            "detect_neg": sum(1 for r in detect if not r.get("label", {}).get("vulnerable")),
            "triage_confirm": sum(
                1 for r in triage if r.get("label", {}).get("verdict") == "Confirm"),
            "triage_reject": sum(
                1 for r in triage if r.get("label", {}).get("verdict") == "Reject"),
            "verified_true": sum(1 for r in kept if r.get("verified")),
            "verified_false": sum(1 for r in kept if r.get("verified") is False),
            "rule_distribution": dict(Counter(r.get("rule", "") for r in kept if r.get("rule"))),
        }

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[frozen] manifest: {manifest_path}")
    print(json.dumps({k: {kk: vv for kk, vv in v.items()
                          if kk in ("kept", "dropped_leaks", "detect_pos", "detect_neg",
                                    "triage_confirm", "triage_reject")}
                      for k, v in manifest["slices"].items()}, indent=2))


def main():
    ap = argparse.ArgumentParser(description="Cross-round dataset leakage audit")
    ap.add_argument("--out", default="reports/data_quality/leakage_report",
                    help="Output prefix (writes .json and .md)")
    ap.add_argument("--write-frozen", action="store_true",
                    help="Write de-leaked eval slices to data/round6/validation_frozen/")
    args = ap.parse_args()

    report = audit({**TRAIN_VISIBLE, **EVAL_SETS})

    out_prefix = ROOT / args.out
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    out_prefix.with_suffix(".json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_prefix.with_suffix(".md").write_text(render_md(report), encoding="utf-8")
    print(f"[+] {out_prefix.with_suffix('.json')}")
    print(f"[+] {out_prefix.with_suffix('.md')}")

    leaks = [c for c in report["checks"] if c["overlap"]]
    print(f"\nOverlap checks with hits: {len(leaks)} / {len(report['checks'])}")
    for c in leaks:
        print(f"  {c['eval']} vs {c['train']} [{c['dimension']}]: {c['overlap']}")

    if args.write_frozen:
        write_frozen(report, ROOT / "data/round6/validation_frozen")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
