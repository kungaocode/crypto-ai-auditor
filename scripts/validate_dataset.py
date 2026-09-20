#!/usr/bin/env python3
"""
Validate unified v2 JSONL dataset files (roadmap P1a / schema 3.4).

Checks per file:
  - schema: required keys present, correct types; `label` field constraints.
  - dedup : no duplicate `id`, and no duplicate normalized code within a file.
  - label consistency:
      * detect  vulnerable=true  -> must carry a CWE (rule-evidenced or predicted)
      * detect  vulnerable=false -> negative (no CWE expected)
      * triage                   -> must carry `verdict` + `finding`
      * verified=true            -> must carry cwe + explanation (rule-evidenced)
  - leakage: no normalized code appears in BOTH a train/val file and a test/domain file.

Usage: python scripts/validate_dataset.py [--data data/splits] [glob ...]
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

REQUIRED_KEYS = [
    "id", "language", "task", "code", "label", "source", "license", "verified", "split",
]
LABEL_KEYS = {"detect": ["vulnerable"], "triage": ["verdict"]}


def norm_code(s: str) -> str:
    return "".join(s.split())


def load_records(path: Path) -> list:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def validate_file(path: Path) -> dict:
    recs = load_records(path)
    errs, warns = [], []
    ids, codes = set(), set()
    cwe_lack, triage_missing, verified_lite = 0, 0, 0

    for r in recs:
        for k in REQUIRED_KEYS:
            if k not in r:
                errs.append(f"{r.get('id','?')}: missing required key '{k}'")
        if "code" in r and not isinstance(r["code"], str):
            errs.append(f"{r.get('id','?')}: code not a string")
        rid = r.get("id")
        if rid in ids:
            errs.append(f"{rid}: duplicate id")
        ids.add(rid)
        nc = norm_code(r.get("code", ""))
        if nc in codes:
            errs.append(f"{rid}: duplicate normalized code")
        codes.add(nc)

        label = r.get("label", {})
        task = r.get("task")
        if task == "detect":
            if label.get("vulnerable") is True:
                if not label.get("cwe"):
                    cwe_lack += 1
                if r.get("verified") and not (label.get("cwe") and label.get("explanation")):
                    verified_lite += 1
                    errs.append(f"{rid}: verified=True but label lacks cwe/explanation")
            elif label.get("vulnerable") is not False:
                errs.append(f"{rid}: detect label.vulnerable must be bool")
        elif task == "triage":
            if not label.get("verdict"):
                triage_missing += 1
                errs.append(f"{rid}: triage label missing verdict")
            if not r.get("finding"):
                errs.append(f"{rid}: triage record missing finding")
        else:
            errs.append(f"{rid}: unknown task {task!r}")

    return {
        "path": path, "n": len(recs), "errs": errs, "warns": warns,
        "codes": codes, "cwe_lack": cwe_lack, "triage_missing": triage_missing,
        "verified_lite": verified_lite,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate v2 dataset JSONL files")
    ap.add_argument("--data", type=Path, default=Path(__file__).resolve().parent.parent / "data" / "splits")
    ap.add_argument("--files", nargs="*", default=None,
                    help="explicit file names; default = *.jsonl in --data")
    args = ap.parse_args()

    if args.files:
        paths = [args.data / f if not Path(f).is_absolute() else Path(f) for f in args.files]
    else:
        paths = sorted(args.data.glob("*.jsonl"))
    if not paths:
        print(f"[!] no jsonl files under {args.data}")
        return 1

    results = [validate_file(p) for p in paths]
    total_errs = 0

    # leakage check across train/val vs test/domain
    safe = [r for r in results if r["path"].name.startswith(("detect_train", "detect_val"))]
    held = [r for r in results if r["path"].name.startswith(("detect_test", "domain_eval"))]
    if safe and held:
        train_codes = set()
        for r in safe:
            train_codes |= r["codes"]
        for r in held:
            leak = train_codes & r["codes"]
            if leak:
                total_errs += len(leak)
                print(f"[LEAK] {r['path'].name}: {len(leak)} code(s) also present in train/val")

    for r in results:
        nerr = len(r["errs"])
        total_errs += nerr
        flags = []
        if r["cwe_lack"]:
            flags.append(f"{r['cwe_lack']} pos-no-cwe")
        if r["triage_missing"]:
            flags.append(f"{r['triage_missing']} triage-no-verdict")
        status = "OK " if nerr == 0 else "BAD"
        extra = "  [" + ", ".join(flags) + "]" if flags else ""
        print(f"{status} {r['path'].name}: {r['n']} records, {nerr} errors{extra}")
        for e in r["errs"][:8]:
            print(f"      - {e}")
        if len(r["errs"]) > 8:
            print(f"      ... (+{len(r['errs']) - 8} more)")

    # quick per-file label balance summary
    print("\n-- label balance --")
    for r in results:
        recs = load_records(r["path"])
        cnt = Counter()
        for x in recs:
            lab = x.get("label", {})
            if x.get("task") == "triage":
                cnt[f"triage:{lab.get('verdict')}"] += 1
            elif lab.get("vulnerable") is True:
                cnt["detect:vulnerable"] += 1
            else:
                cnt["detect:secure"] += 1
        cwes = Counter()
        for x in recs:
            c = x.get("label", {}).get("cwe")
            if c:
                cwes[c] += 1
        print(f"  {r['path'].name}: {dict(cnt)}  top-cwes={cwes.most_common(4)}")

    print(f"\n{'ALL CHECKS PASSED' if total_errs == 0 else str(total_errs) + ' ERROR(S)'}")
    return 0 if total_errs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
