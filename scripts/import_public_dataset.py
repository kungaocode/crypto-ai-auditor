#!/usr/bin/env python3
"""
Import PyCode-Vul into the v2 unified schema via Semgrep rule backtest.

Source   : HuggingFace S-AIR-L/PyCode-Vul (cc-by-4.0; Zenodo DOI 19746552).
           Two CSVs are the OFFICIAL split: `PyCode_Vul- train-set.csv` and
           `PyCode_Vul test-set.csv`. We keep them apart (no leakage).
           Columns differ: train has `vulnerable_function_source`, test has
           `function_code` + `class`.

Ground-truth `cwe_ids`/`cve_ids` are 'UNKNOWN' in this release; only noisy model
`predicted_cwe_ids` and `label`/`class` exist. Rule backtest gives
self-evidenced labels (roadmap D16 / D20 / D22):

  T1 rule-evidenced   : vulnerable source HIT by one of our CRYPTO rules.
                        `verified=True` MEANS "semgrep rule fired" - NOT a human
                        confirmation. Split by code context:
                          * production/non-test scope -> genuine misuse candidate:
                              detect positive + triage Confirm (with real patch)
                          * test/fixture code          -> false-positive control:
                              triage Reject ("hash used on fixture data, not
                              security-sensitive"). Excluded from detect positives
                              to avoid contradictory vulnerable/secure signals.
  T2 plausible        : label=1, real patch change, non-test code, concrete
                        predicted CWE -> {vulnerable:true, cwe} ONLY
                        (verified=False; predicted severity/explanation untrusted).
  Negative            : paired patched source of a positive our rules do NOT hit.

Outputs (data/splits/):
  detect_train.jsonl / detect_val.jsonl   detect train+val (10% by repo, seed 0)
  detect_test.jsonl                       general detection eval (test CSV)
  triage_train.jsonl                      rule-hit rows of TRAIN CSV (Confirm for
                                          production, Reject for test/fixture)
  domain_eval.jsonl                       rule-hit rows of TEST CSV (held-out
                                          domain control: Confirm + Reject)

Usage: python scripts/import_public_dataset.py
"""
import argparse
import hashlib
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

import pandas as pd
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = REPO_ROOT / "data" / "raw" / "pycode-vul"
RULES_DIR = REPO_ROOT / "rules"

DATASET_LICENSE = "cc-by-4.0"
SOURCE = "pycode-vul"
NOISE_CWES = {"CWE-703", "CWE-Unknown", "UNKNOWN", "nan", ""}

REJECT_NOTE = "Hash used in test/fixture code, not security-sensitive; rule false positive."


def norm_code(s: str) -> str:
    return "".join(s.split())


def make_id(repo: str, code: str, tag: str = "") -> str:
    slug = (repo or "").replace("/", "-").replace("_", "-")
    h = hashlib.sha1(norm_code(code).encode()).hexdigest()[:8]
    return f"{SOURCE}-{slug}-{h}{'-' + tag if tag else ''}"


def load_rule_meta(rules_dir: Path) -> dict:
    meta = {}
    for y in sorted(rules_dir.glob("crypto-*/rule.yaml")):
        for r in yaml.safe_load(y.read_text(encoding="utf-8")).get("rules", []):
            md = r.get("metadata", {})
            meta[r["id"]] = {
                "cwe": md.get("cwe", ""),
                "severity": r.get("severity", md.get("severity", "WARNING")),
                "message": r.get("message", r["id"]),
            }
    return meta


def run_backtest(code_strs: list, rules_dir: Path) -> dict:
    """Scan code strings with our rules -> {index: [rule_id, ...]}."""
    if not code_strs:
        return {}
    with tempfile.TemporaryDirectory(prefix="pyvul_bt_") as td:
        for i, s in enumerate(code_strs):
            Path(td, f"f{i:06d}.py").write_text(s, encoding="utf-8")
        proc = subprocess.run(
            ["semgrep", "--config", str(rules_dir), "--json", "--quiet", td],
            capture_output=True, text=True,
        )
        try:
            results = json.loads(proc.stdout or "{}").get("results", [])
        except json.JSONDecodeError:
            results = []
        idx2rules: dict = {}
        for h in results:
            idx = int(Path(h["path"]).name[1:6])
            idx2rules.setdefault(idx, []).append(h["check_id"].split(".")[-1])
        return idx2rules


def first_cwe(s) -> str:
    for part in str(s or "").split(","):
        part = part.strip()
        if part.startswith("CWE-") and part not in NOISE_CWES:
            return part
    return ""


def is_test_code(file_path: str, code: str) -> bool:
    fp = (file_path or "").lower()
    return "/test" in fp or code.startswith(("def test_", "async def test_"))


def _base(r: dict) -> dict:
    return {
        "source": SOURCE, "license": DATASET_LICENSE,
        "repo_url": f"https://github.com/{r['repo']}" if r.get("repo") else "",
        "commit": r.get("sha", ""),
    }


def rec_detect(r: dict, vuln: bool, *, verified: bool, label_extra=None) -> dict:
    label = {"vulnerable": vuln}
    if label_extra:
        label.update(label_extra)
    return {
        "id": make_id(r["repo"], r["code"]),
        "language": "python", "task": "detect", "code": r["code"], "label": label,
        "verified": verified, "split": "", **_base(r),
    }


def rec_triage(r: dict, rule: str, verdict: str, rule_meta: dict,
               explain_override: str = "") -> dict:
    m = rule_meta[rule]
    return {
        "id": make_id(r["repo"], r["code"], tag=f"{rule}-{verdict}"),
        "language": "python", "task": "triage", "code": r["code"],
        "finding": f"[{rule}] {m['message']}",
        "label": {
            "cwe": m["cwe"], "severity": m["severity"], "verdict": verdict,
            "explanation": explain_override or m["message"],
            "patch": r.get("patched", "") if verdict == "Confirm" else "",
        },
        "verified": True, "split": "", **_base(r),
    }


def process_csv(df: pd.DataFrame, rule_meta: dict,
                rules_dir: Path) -> dict:
    """Return {pos, neg, t1} for one CSV: pos=detect positives (non-test T1+T2),
    neg=detect negatives, t1=[(candidate, rule_id)] every rule-hit row (incl. tests)."""
    vuln_col = "vulnerable_function_source" if "vulnerable_function_source" in df.columns \
        else "function_code"
    lab_col = "label" if "label" in df.columns else "class"

    cand = []
    for _, r in df.iterrows():
        v, p = r.get(vuln_col), r.get("patched_function_source")
        if not (isinstance(v, str) and isinstance(p, str) and v.strip()):
            continue
        if str(r.get(lab_col, "")).strip() not in {"1", "1.0"} or v == p:
            continue
        cand.append({
            "code": v, "patched": p,
            "repo": str(r.get("repo", "") or ""), "sha": str(r.get("sha", "") or ""),
            "file_path": str(r.get("file_path", "") or ""),
            "pred": first_cwe(r.get("predicted_cwe_ids", "")),
            "is_test": is_test_code(str(r.get("file_path", "") or ""), v),
        })

    vuln_rules = run_backtest([c["code"] for c in cand], rules_dir)

    pos, t1, seen_pos = [], [], set()
    for i, c in enumerate(cand):
        rules = list(vuln_rules.get(i, []))
        nc = norm_code(c["code"])
        if nc in seen_pos:
            continue
        if rules:  # T1 rule-evidenced -> triage buckets (pos only if non-test)
            rule = next((x for x in rules if rule_meta[x]["cwe"]), rules[0])
            t1.append((c, rule))
            if c["is_test"]:
                continue  # fixture usage: not a detect positive
            seen_pos.add(nc)
            pos.append(rec_detect(c, True, verified=True, label_extra={
                "cwe": rule_meta[rule]["cwe"], "severity": rule_meta[rule]["severity"],
                "confidence": "HIGH", "explanation": rule_meta[rule]["message"],
                "patch": c["patched"],
            }))
        elif not c["is_test"] and c["pred"]:  # T2 plausible general
            seen_pos.add(nc)
            pos.append(rec_detect(c, True, verified=False, label_extra={"cwe": c["pred"]}))

    # negatives from patched sources of positives
    pos_ncs = {norm_code(p["code"]) for p in pos}
    neg_rows = []
    for c in cand:
        if c["is_test"] or not c["pred"]:
            continue
        nc = norm_code(c["patched"])
        if nc in pos_ncs:
            continue
        neg_rows.append(dict(c, code=c["patched"]))
    patched_rules = run_backtest([r["code"] for r in neg_rows], rules_dir)
    neg, seen_neg = [], set()
    for i, c in enumerate(neg_rows):
        if i in patched_rules:
            continue
        nc = norm_code(c["code"])
        if nc in seen_neg or nc in pos_ncs:
            continue
        seen_neg.add(nc)
        neg.append(rec_detect(c, False, verified=False))
    return {"pos": pos, "neg": neg, "t1": t1}


def write_jsonl(path: Path, records: list) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"[+] {path.name}: {len(records)} records")


def stratified_val_split(records: list, frac: float, seed: int) -> tuple[list, list]:
    rng = random.Random(seed)
    by_repo: dict = {}
    for rec in records:
        by_repo.setdefault(rec["repo_url"], []).append(rec)
    val, train = [], []
    for grp in by_repo.values():
        k = max(1, round(len(grp) * frac))
        rng.shuffle(grp)
        val.extend(grp[:k])
        train.extend(grp[k:])
    return train, val


def triage_records(t1_rows: list, rule_meta: dict) -> list:
    out = []
    for c, rule in t1_rows:
        verdict = "Reject" if c["is_test"] else "Confirm"
        override = REJECT_NOTE if verdict == "Reject" else ""
        out.append(rec_triage(c, rule, verdict, rule_meta, override))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Import PyCode-Vul -> v2 JSONL (rule backtest)")
    ap.add_argument("--rules", type=Path, default=REPO_ROOT / "rules")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "data" / "splits")
    args = ap.parse_args()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    rule_meta = load_rule_meta(args.rules)

    tr = pd.read_csv(RAW_DIR / "PyCode_Vul-_train-set.csv")
    tr.columns = [c.strip() for c in tr.columns]
    trd = process_csv(tr, rule_meta, args.rules)
    nv = sum(1 for p in trd["pos"] if p["verified"])
    print(f"[train] pos={len(trd['pos'])} (rule-evidenced non-test={nv}) "
          f"neg={len(trd['neg'])} t1={len(trd['t1'])}")
    train, val = stratified_val_split(trd["pos"] + trd["neg"], frac=0.10, seed=0)
    write_jsonl(out / "detect_train.jsonl", train)
    write_jsonl(out / "detect_val.jsonl", val)
    write_jsonl(out / "triage_train.jsonl", triage_records(trd["t1"], rule_meta))

    te = pd.read_csv(RAW_DIR / "PyCode_Vul_test-set.csv")
    te.columns = [c.strip() for c in te.columns]
    ted = process_csv(te, rule_meta, args.rules)
    nv = sum(1 for p in ted["pos"] if p["verified"])
    print(f"[test] pos={len(ted['pos'])} (rule-evidenced non-test={nv}) "
          f"neg={len(ted['neg'])} t1={len(ted['t1'])}")
    train_codes = {norm_code(r["code"]) for r in (trd["pos"] + trd["neg"])}
    te_pos = [r for r in ted["pos"] if norm_code(r["code"]) not in train_codes]
    te_neg = [r for r in ted["neg"] if norm_code(r["code"]) not in train_codes]
    te_domain = [r for c, rule in ted["t1"]
                 if norm_code(c["code"]) not in train_codes
                 for r in [rec_triage(
                     c, rule,
                     "Reject" if c["is_test"] else "Confirm", rule_meta,
                     REJECT_NOTE if c["is_test"] else "")]]
    write_jsonl(out / "detect_test.jsonl", te_pos + te_neg)
    write_jsonl(out / "domain_eval.jsonl", te_domain)
    return 0


if __name__ == "__main__":
    sys.exit(main())
