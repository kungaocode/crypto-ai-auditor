#!/usr/bin/env python3
"""
Build the FINAL Round-6 SFT dataset for full base retrain on Qwen3-4B.

Merges:
  1. R5 upload base (data/round5/final/upload/full/{train,val,test}.jsonl, 2764+321+636)
  2. R6 new samples      — new_detect.jsonl + new_triage.jsonl
  3. R6 supplement       — supplement_detect.jsonl + supplement_triage.jsonl
  4. R6 supplement v2    — supplement_v2_detect.jsonl + supplement_v2_triage.jsonl
  5. R6 rule fixtures    — rule_fixture_detect.jsonl + rule_fixture_triage.jsonl
  6. R6 verified real    — real_verified_{detect,triage}.jsonl  (OPTIONAL)

The verified-real sources are advisory-backed records harvested from real Python
packages. They are merged into Round 6 (there is no separate Round 7) only when
present. When they are absent the builder reproduces the 322-addition baseline
unchanged. Training must use the frozen artifacts emitted here together with the
per-file SHA-256 recorded in r6_manifest.json.

QA pipeline: duplicate IDs, required fields, syntax, label consistency, split leakage.
Emits a stable per-file SHA-256 and asserts the emitted R6 slice equals the union of
all declared R6 sources (guards against the v2-drop regression).

Output: data/round6/final/upload/full/{train,val,test}.jsonl  (chatml format)
"""
import argparse
import ast
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
R5_BASE = ROOT / "data" / "round5" / "final" / "upload" / "full"
R6_DIR = ROOT / "data" / "round6"
R6_FINAL = R6_DIR / "final"

# Ordered list of every source file that makes up the R6 slice. Keep this as the
# single source of truth: the emitted R6 records must equal the union of these.
R6_SOURCE_FILES = [
    "new_detect.jsonl",
    "new_triage.jsonl",
    "supplement_detect.jsonl",
    "supplement_triage.jsonl",
    "supplement_v2_detect.jsonl",
    "supplement_v2_triage.jsonl",
    "rule_fixture_detect.jsonl",
    "rule_fixture_triage.jsonl",
]

# Advisory-backed records that a reviewer or audited model has finalized.
# Kept in a separate list so the required baseline stays reproducible when they
# are absent; when present they are merged and subject to stricter validation.
R6_OPTIONAL_SOURCES = [
    "real_verified_detect.jsonl",
    "real_verified_triage.jsonl",
]

# Rule -> accepted CWE(s), mirrored from rules/CRYPTO-0xx. Used to reject real
# records whose rule/CWE mapping disagrees with the shipped taxonomy.
RULE_CWE = {
    "CRYPTO-001": {"CWE-327"},
    "CRYPTO-002": {"CWE-327"},
    "CRYPTO-003": {"CWE-327"},
    "CRYPTO-004": {"CWE-327"},
    "CRYPTO-005": {"CWE-327"},
    "CRYPTO-006": {"CWE-329"},
    "CRYPTO-007": {"CWE-321"},
    "CRYPTO-008": {"CWE-338"},
    "CRYPTO-009": {"CWE-326"},
    "CRYPTO-010": {"CWE-326", "CWE-295"},
    "CRYPTO-011": {"CWE-256"},
    "CRYPTO-012": {"CWE-916"},
    "CRYPTO-013": {"CWE-208"},
}
TARGET_CWES = set().union(*RULE_CWE.values())

sys.path.insert(0, str(ROOT))
from scripts.prepare_sft_data import build_messages  # noqa: E402


def load_jsonl(path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def evidence_field(record, *keys):
    """Look a field up at top level, then inside an optional `evidence` dict."""
    ev = record.get("evidence") or {}
    for key in keys:
        value = record.get(key) or ev.get(key)
        if value:
            return value
    return ""


def validate_real_records(records, source_name):
    """Fail-closed checks for advisory-backed records under real_verified_*.

    These records must carry a complete evidence chain and finalized review
    provenance; a machine can only confirm the shape, not semantic truth.
    """
    errors = []
    seen_advisory = {}
    seen_repo_commit = {}

    for r in records:
        rid = r.get("id") or "?"

        def err(msg):
            errors.append(f"{source_name}:{rid}: {msg}")

        if not r.get("id"):
            err("id is required")
        if r.get("verified") is not True:
            err("verified must be true for real_verified_* sources")
        if not r.get("source"):
            err("source is required")
        if r.get("language") != "python":
            err(f"language must be 'python' (got {r.get('language')!r})")
        if r.get("split") not in ("train", "val", "test"):
            err("split must be one of train/val/test")

        license_ = (r.get("license") or "").strip()
        if not license_ or license_.lower() in {"unknown", "n/a", "none", "tbd"}:
            err("license is required and must not be unknown/empty")

        task = r.get("task")
        label = r.get("label") or {}
        rule = (r.get("rule") or "").strip()

        advisories = [evidence_field(r, "advisory_id", "cve_id")]
        repos = [evidence_field(r, "repo_url")]
        commits = [evidence_field(r, "fix_commit"), evidence_field(r, "vuln_commit"),
                   evidence_field(r, "commit")]
        files = [evidence_field(r, "file", "file_path")]
        if not advisories[0]:
            err("missing advisory_id/cve_id evidence")
        if not repos[0]:
            err("missing repo_url evidence")
        if not any(commits):
            err("missing vuln_commit/fix_commit evidence")
        if not files[0]:
            err("missing file/file_path evidence")
        if not r.get("code"):
            err("missing code snippet")

        if rule:
            if rule not in RULE_CWE:
                err(f"unknown rule {rule!r}; expected one of CRYPTO-001..013")
            else:
                cwe = (label.get("cwe") or "").strip()
                if cwe and cwe not in RULE_CWE[rule]:
                    err(f"cwe {cwe} does not match rule {rule} ({sorted(RULE_CWE[rule])})")

        if task == "detect":
            if label.get("vulnerable") is True:
                if not rule:
                    err("detect positive must carry a rule in CRYPTO-001..013")
                cwe = (label.get("cwe") or "").strip()
                if not cwe:
                    err("detect positive must carry a cwe")
                elif cwe not in TARGET_CWES:
                    err(f"cwe {cwe} is outside the target crypto CWE set")
            elif label.get("vulnerable") is not False:
                err("detect label.vulnerable must be a bool")
        elif task == "triage":
            verdict = label.get("verdict")
            if verdict not in ("Confirm", "Reject"):
                err("triage label.verdict must be Confirm or Reject")
            if not r.get("finding"):
                err("triage record must carry the static finding")
            if verdict == "Confirm" and not rule:
                err("triage Confirm must carry the triggering rule")
            if verdict == "Confirm":
                cwe = (label.get("cwe") or "").strip()
                if not cwe:
                    err("triage Confirm must carry a cwe")
                elif cwe not in TARGET_CWES:
                    err(f"cwe {cwe} is outside the target crypto CWE set")
        else:
            err(f"unknown task {task!r}")

        # Duplicate keys are scoped by task so a detect positive and its paired
        # triage Confirm may share the same advisory/commit without colliding.
        if advisories[0]:
            key = (str(advisories[0]), task)
            if key in seen_advisory:
                err(f"duplicate advisory/cve {advisories[0]} (also {seen_advisory[key]})")
            else:
                seen_advisory[key] = rid
        if repos[0]:
            for commit in commits:
                if not commit:
                    continue
                key = (str(repos[0]), str(commit), str(files[0]), task)
                if key in seen_repo_commit:
                    err(f"duplicate repo+commit+file {key} (also {seen_repo_commit[key]})")
                else:
                    seen_repo_commit[key] = rid

    return errors


def check_real_repo_split(records):
    """A repository's records must not be spread across train/val/test."""
    errors = []
    assigned = {}
    for r in records:
        repo = evidence_field(r, "repo_url")
        if not repo:
            continue
        split = r.get("split")
        if repo in assigned and assigned[repo] != split:
            errors.append(
                f"repo {repo} appears in splits {assigned[repo]} and {split} "
                f"(record {r.get('id')})"
            )
        else:
            assigned[repo] = split
    return errors


def check_duplicate_ids(records):
    ids = [r["id"] for r in records]
    dupes = [i for i, c in Counter(ids).items() if c > 1]
    return dupes


def check_required_fields(records):
    required = ["id", "language", "task", "code", "label", "source", "split"]
    missing = []
    for r in records:
        for f in required:
            if f not in r:
                missing.append((r.get("id", "?"), f))
        if r.get("task") == "triage" and "finding" not in r:
            missing.append((r["id"], "finding"))
        if r["task"] == "detect" and "vulnerable" not in r.get("label", {}):
            missing.append((r["id"], "label.vulnerable"))
        if r["task"] == "triage" and "verdict" not in r.get("label", {}):
            missing.append((r["id"], "label.verdict"))
    return missing


def check_syntax(records):
    errors = []
    for r in records:
        try:
            ast.parse(r["code"])
        except SyntaxError as e:
            errors.append((r["id"], str(e)))
    return errors


def check_label_consistency(records):
    """Check no conflicting labels for the same normalized code within a task."""
    norm_map = {}
    conflicts = []
    for r in records:
        norm = re.sub(r'\s+', ' ', r["code"]).strip().lower()
        key = (r["task"], norm)
        if key in norm_map:
            prev = norm_map[key]
            if r["label"] != prev["label"]:
                conflicts.append((prev["id"], r["id"], norm[:80]))
        else:
            norm_map[key] = r
    return conflicts


def check_split_leakage(records):
    """Check code doesn't appear in multiple splits."""
    code_splits = {}
    leakage = []
    for r in records:
        norm = re.sub(r'\s+', ' ', r["code"]).strip().lower()
        split = r["split"]
        if norm not in code_splits:
            code_splits[norm] = split
        elif code_splits[norm] != split:
            leakage.append((f"{code_splits[norm]}→{split}", norm[:80]))
    return leakage


def compute_distribution(records):
    stats = {}
    detect_all = [r for r in records if r["task"] == "detect"]
    triage_all = [r for r in records if r["task"] == "triage"]

    d_pos = sum(1 for r in detect_all if r["label"].get("vulnerable"))
    d_neg = len(detect_all) - d_pos
    t_conf = sum(1 for r in triage_all if r["label"].get("verdict") == "Confirm")
    t_rej = len(triage_all) - t_conf

    stats["detect_total"] = len(detect_all)
    stats["detect_pos_neg"] = f"{d_pos}:{d_neg}"
    stats["triage_total"] = len(triage_all)
    stats["triage_confirm_reject"] = f"{t_conf}:{t_rej}"
    stats["detect_verified_true"] = sum(1 for r in detect_all if r.get("verified") is True)
    stats["triage_verified_true"] = sum(1 for r in triage_all if r.get("verified") is True)

    for split in ("train", "val", "test"):
        d = sum(1 for r in detect_all if r["split"] == split)
        t = sum(1 for r in triage_all if r["split"] == split)
        stats[f"split_{split}"] = f"detect={d} triage={t} total={d+t}"

    return stats


def run_qa(all_new):
    report = {"pass": True, "checks": {}}

    print("=" * 72)
    print("R6 QUALITY ASSURANCE")
    print("=" * 72)

    dupes = check_duplicate_ids(all_new)
    report["checks"]["duplicate_ids"] = len(dupes)
    if dupes:
        print(f"  [FAIL] duplicate IDs ({len(dupes)}): {dupes}")
        report["pass"] = False
    else:
        print(f"  [PASS] duplicate IDs: 0")

    missing = check_required_fields(all_new)
    report["checks"]["missing_fields"] = len(missing)
    if missing:
        print(f"  [FAIL] missing fields ({len(missing)}): {missing[:10]}")
        report["pass"] = False
    else:
        print(f"  [PASS] missing fields: 0")

    syntax_errs = check_syntax(all_new)
    report["checks"]["syntax_errors"] = len(syntax_errs)
    if syntax_errs:
        print(f"  [FAIL] syntax errors ({len(syntax_errs)}):")
        for rid, err in syntax_errs[:10]:
            print(f"    {rid}: {err}")
        report["pass"] = False
    else:
        print(f"  [PASS] syntax errors: 0")

    conflicts = check_label_consistency(all_new)
    report["checks"]["label_conflicts"] = len(conflicts)
    if conflicts:
        print(f"  [FAIL] label conflicts ({len(conflicts)})")
        for id1, id2, code in conflicts[:5]:
            print(f"    {id1} vs {id2}: {code}...")
        report["pass"] = False
    else:
        print(f"  [PASS] label conflicts: 0")

    leakage = check_split_leakage(all_new)
    report["checks"]["split_leakage"] = len(leakage)
    if leakage:
        print(f"  [FAIL] split leakage ({len(leakage)})")
        for direction, code in leakage[:5]:
            print(f"    {direction}: {code}...")
        report["pass"] = False
    else:
        print(f"  [PASS] split leakage: 0")

    dist = compute_distribution(all_new)
    report["checks"]["distribution"] = dist
    print(f"\n  R6 new samples distribution:")
    for split_key in ("split_train", "split_val", "split_test"):
        if split_key in dist:
            print(f"    {split_key}: {dist[split_key]}")
    print(f"  detect: {dist['detect_total']} ({dist['detect_pos_neg']})")
    print(f"  triage: {dist['triage_total']} ({dist['triage_confirm_reject']})")
    print(f"  verified=true: detect={dist['detect_verified_true']} "
          f"triage={dist['triage_verified_true']}")

    return report


def emit_merged(r5_train, r5_val, r5_test, all_new, out_dir):
    """Merge R5 base with R6 new, convert to chatml, emit upload sets."""
    new_train_d = [r for r in all_new if r["split"] == "train" and r["task"] == "detect"]
    new_train_t = [r for r in all_new if r["split"] == "train" and r["task"] == "triage"]
    new_val_d = [r for r in all_new if r["split"] == "val" and r["task"] == "detect"]
    new_val_t = [r for r in all_new if r["split"] == "val" and r["task"] == "triage"]
    new_test_d = [r for r in all_new if r["split"] == "test" and r["task"] == "detect"]
    new_test_t = [r for r in all_new if r["split"] == "test" and r["task"] == "triage"]

    print(f"\nR6 new: train_d={len(new_train_d)} train_t={len(new_train_t)} "
          f"val_d={len(new_val_d)} val_t={len(new_val_t)} "
          f"test_d={len(new_test_d)} test_t={len(new_test_t)}")

    # Convert new records to chatml (training=True strips PURPOSE_GUIDE)
    train_ct = r5_train + [{"messages": build_messages(r, training=True)}
                           for r in new_train_d + new_train_t]
    val_ct = r5_val + [{"messages": build_messages(r, training=True)}
                        for r in new_val_d + new_val_t]
    test_ct = r5_test + [{"messages": build_messages(r, training=True)}
                          for r in new_test_d + new_test_t]

    upload_dir = out_dir / "upload" / "full"
    upload_dir.mkdir(parents=True, exist_ok=True)

    for name, data in [("train", train_ct), ("val", val_ct), ("test", test_ct)]:
        p = upload_dir / f"{name}.jsonl"
        p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in data) + "\n",
                      encoding="utf-8")
        print(f"[+] {p}: {len(data)} records")

    # Save v2 source files for reference
    src_dir = out_dir
    src_dir.mkdir(parents=True, exist_ok=True)
    v2_all = new_train_d + new_train_t + new_val_d + new_val_t + new_test_d + new_test_t
    src_d = src_dir / "r6_new_detect.jsonl"
    src_t = src_dir / "r6_new_triage.jsonl"
    src_d.write_text("\n".join(json.dumps(r, ensure_ascii=False)
                                for r in v2_all if r["task"] == "detect") + "\n", encoding="utf-8")
    src_t.write_text("\n".join(json.dumps(r, ensure_ascii=False)
                                for r in v2_all if r["task"] == "triage") + "\n", encoding="utf-8")
    print(f"[+] {src_d} ({sum(1 for r in v2_all if r['task']=='detect')} records)")
    print(f"[+] {src_t} ({sum(1 for r in v2_all if r['task']=='triage')} records)")


def verify_source_parity(all_new, out_dir):
    """Emitted r6_new_* must contain exactly the records loaded from R6 sources."""
    emitted = load_jsonl(out_dir / "r6_new_detect.jsonl") + load_jsonl(
        out_dir / "r6_new_triage.jsonl"
    )
    src_ids = [r["id"] for r in all_new]
    out_ids = [r["id"] for r in emitted]
    missing = sorted(set(src_ids) - set(out_ids))
    extra = sorted(set(out_ids) - set(src_ids))
    dupes = sorted(i for i, c in Counter(out_ids).items() if c > 1)
    if missing or extra or dupes or len(out_ids) != len(src_ids):
        print(f"  [FAIL] source parity: missing={missing} extra={extra} dupes={dupes}")
        return False
    print(f"  [PASS] source parity: emitted {len(out_ids)} == sources {len(src_ids)}")
    return True


def write_manifest(loaded_sources, all_new, real_records, out_dir):
    """Freeze provenance: per-source hashes plus the merged artifact hashes."""
    manifest = {
        "generated_by": "scripts/build_round6_final_dataset.py --emit",
        "policy": (
            "R6 finalization: advisory-backed reviewed records are merged into "
            "Round 6 before training. Re-check this manifest's hashes right before the "
            "run and do not mutate the emitted train/val/test afterwards. Training must "
            "start from a fresh base; incremental continuation is forbidden."
        ),
        "sources": [
            {
                "file": str(path.relative_to(ROOT)),
                "records": len(recs),
                "sha256": sha256_file(path),
            }
            for path, recs in loaded_sources
        ],
        "r6_new_total": len(all_new),
        "verified_real_total": len(real_records),
        "verified_real_by_rule": dict(sorted(
            Counter(r.get("rule", "") for r in real_records if r.get("rule")).items())),
        "distribution": compute_distribution(all_new),
        "artifacts": {},
    }
    for name in ("train", "val", "test"):
        p = out_dir / "upload" / "full" / f"{name}.jsonl"
        manifest["artifacts"][name] = {
            "path": str(p.relative_to(ROOT)),
            "records": len(load_jsonl(p)),
            "sha256": sha256_file(p),
        }
    out_path = out_dir / "r6_manifest.json"
    out_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[+] {out_path}")
    return manifest


def main():
    ap = argparse.ArgumentParser(description="Build final R6 dataset with merge + QA")
    ap.add_argument("--emit", action="store_true", help="Write final dataset to disk")
    ap.add_argument("--dry-run", action="store_true", help="QA only, do not write")
    args = ap.parse_args()

    # Load R5 base (chatml format)
    r5_train = load_jsonl(R5_BASE / "train.jsonl")
    r5_val = load_jsonl(R5_BASE / "val.jsonl")
    r5_test = load_jsonl(R5_BASE / "test.jsonl")
    print(f"R5 base: train={len(r5_train)} val={len(r5_val)} test={len(r5_test)}")

    # Load R6 new (v2 schema) from every declared source file.
    all_new = []
    real_records = []
    loaded_sources = []  # (path, records) for the manifest
    print("R6 sources:")
    for name in R6_SOURCE_FILES:
        path = R6_DIR / name
        if not path.exists():
            raise SystemExit(f"[FAIL] missing required R6 source: {path}")
        recs = load_jsonl(path)
        all_new += recs
        loaded_sources.append((path, recs))
        print(f"  {name}: {len(recs)} records  sha256={sha256_file(path)[:12]}")

    print("R6 optional verified-real sources:")
    for name in R6_OPTIONAL_SOURCES:
        path = R6_DIR / name
        if not path.exists():
            print(f"  {name}: absent (skipped)")
            continue
        recs = load_jsonl(path)
        errors = validate_real_records(recs, name)
        if errors:
            print(f"  [FAIL] {name}: {len(errors)} validation error(s)")
            for e in errors[:25]:
                print(f"    {e}")
            return 1
        real_records += recs
        all_new += recs
        loaded_sources.append((path, recs))
        print(f"  {name}: {len(recs)} records  sha256={sha256_file(path)[:12]}")

    if real_records:
        split_errors = check_real_repo_split(real_records)
        if split_errors:
            print("  [FAIL] verified-real repo/split leakage:")
            for e in split_errors[:25]:
                print(f"    {e}")
            return 1
        print(f"  [PASS] verified-real repo/split consistency")

    print(f"R6 new total: {len(all_new)} (verified-real={len(real_records)})")

    # QA
    report = run_qa(all_new)

    # Show source distribution
    print(f"\n  R6 source breakdown:")
    for src, cnt in sorted(Counter(r["source"] for r in all_new).items()):
        print(f"    {src}: {cnt}")

    # Show split distribution by source
    print(f"\n  R6 split breakdown by type:")
    for task in ("detect", "triage"):
        subset = [r for r in all_new if r["task"] == task]
        for split in ("train", "val", "test"):
            s = [r for r in subset if r["split"] == split]
            if task == "detect":
                pos = sum(1 for r in s if r["label"].get("vulnerable"))
                neg = sum(1 for r in s if not r["label"].get("vulnerable"))
                print(f"    {task:8s} {split:5s}: {len(s)} (pos={pos} neg={neg})")
            else:
                conf = sum(1 for r in s if r["label"].get("verdict") == "Confirm")
                rej = sum(1 for r in s if r["label"].get("verdict") == "Reject")
                print(f"    {task:8s} {split:5s}: {len(s)} (Confirm={conf} Reject={rej})")

    # Show val/test samples
    for split in ("val", "test"):
        held = [r for r in all_new if r["split"] == split]
        if held:
            print(f"\n  {split.upper()} held-out samples:")
            for r in sorted(held, key=lambda x: x["id"]):
                print(f"    {r['id']} ({r['task']}, vul={r['label'].get('vulnerable','?')}"
                      f" verdict={r['label'].get('verdict','?')})")

    summary = "PASSED" if report["pass"] else "FAILED"
    print(f"\n{'='*72}")
    print(f"QA SUMMARY: {summary}")
    n_detect = sum(1 for r in all_new if r["task"] == "detect")
    n_triage = sum(1 for r in all_new if r["task"] == "triage")
    print(f"R6 new: {len(all_new)} samples (detect={n_detect} triage={n_triage})")
    if real_records:
        print(f"  verified-real merged: {len(real_records)} (advisory-backed)")
    else:
        print("  [WARN] no verified real records present: this is the curated "
              "baseline, not the real-crypto-positive fix for the data bottleneck")
    print(f"Merged total would be: train={len(r5_train)+sum(1 for r in all_new if r['split']=='train')}"
          f" val={len(r5_val)+sum(1 for r in all_new if r['split']=='val')}"
          f" test={len(r5_test)+sum(1 for r in all_new if r['split']=='test')}")

    if args.emit and not args.dry_run:
        emit_merged(r5_train, r5_val, r5_test, all_new, R6_FINAL)
        if not verify_source_parity(all_new, R6_FINAL):
            return 1
        print("\nFinal artifact hashes:")
        for name in ("train", "val", "test"):
            p = R6_FINAL / "upload" / "full" / f"{name}.jsonl"
            print(f"  {name}.jsonl: {sha256_file(p)}")
        write_manifest(loaded_sources, all_new, real_records, R6_FINAL)

    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
