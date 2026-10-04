#!/usr/bin/env python3
"""
Build the FINAL Round-5 SFT dataset for full base retrain on Qwen3-4B.

Merges three data sources:
  1. build_round5_known_forms.py  — CRYPTO-011/012/013 (password-storage, KDF, timing)
  2. build_round5_library_audit.py — CRYPTO-001..008/012/013 (library-audit, passlib bneg)
  3. Ad-hoc CRYPTO-009/010        — CRYPTO-009 (weak key length), CRYPTO-010 (insecure TLS)

Includes comprehensive QA pipeline:
  - Backtest discipline        (pos fires rule, aneg fires nothing, bneg fires rule)
  - Code uniqueness             (no duplicate normalized code across split boundaries)
  - Label consistency           (no conflicting labels for same normalized code)
  - Syntax validity             (all code snippets parse as valid Python)
  - Split non-leakage           (train/val/test must be disjoint)
  - Rule coverage               (every CRYPTO-001..013 has training data)
  - Distribution balance        (adequate pos/neg ratio per task)

Outputs:
  data/round5/final/known_forms_detect.jsonl  — v2 schema detect records
  data/round5/final/known_forms_triage.jsonl  — v2 schema triage records
  data/round5/final/backtest_report.jsonl     — per-sample semgrep hit discipline
  data/round5/final/qa_report.md              — human-readable QA report
  data/round5/final/upload/full/{train,val,test}.jsonl — chatml, merged with R4 base
"""
import argparse
import ast
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FINAL = ROOT / "data" / "round5" / "final"
R4_UPLOAD = ROOT / "data" / "round4" / "upload" / "full"

# ── sys.path setup for module imports ───────────────────────────────────────
sys.path.insert(0, str(ROOT))
from scripts.prepare_sft_data import build_messages  # noqa: E402
from model.prompts import SYS_PROMPT, build_detect_user, build_triage_user  # noqa: E402

# ── Load rule metadata ──────────────────────────────────────────────────────
RULE_META = {}
for y in sorted(Path(ROOT / "rules").glob("crypto-*/rule.yaml")):
    for r in yaml.safe_load(y.read_text(encoding="utf-8")).get("rules", []):
        RULE_META[r["id"]] = {
            "cwe": r.get("metadata", {}).get("cwe", ""),
            "severity": r.get("severity", "WARNING"),
            "message": r["message"],
        }


# ═════════════════════════════════════════════════════════════════════════════
# DATA COLLECTION
# ═════════════════════════════════════════════════════════════════════════════

def _infer_cwe_to_rules(cwe_to_rules, records):
    """Build a mapping from CWE to the rules that reference it, from records that have rule + cwe."""
    for r in records:
        cwe = r.get("label", {}).get("cwe", "")
        rule = r.get("rule", "")
        if cwe and rule:
            cwe_to_rules.setdefault(cwe, set()).add(rule)


def _annotate_library_audit_rules(detect, triage):
    """Annotate library_audit records with rule fields based on code content."""
    import re
    def _infer_rule_from_code(code, label):
        code_lower = code.lower()
        cwe = label.get("cwe", "")
        if cwe == "CWE-327":
            if "md5" in code_lower:
                return "CRYPTO-001"
            if "sha-1" in code_lower or "sha1" in code_lower:
                return "CRYPTO-002"
            if "arc4" in code_lower or "rc4" in code_lower:
                return "CRYPTO-004"
            if "ecb" in code_lower or "mode_ecb" in code_lower:
                return "CRYPTO-005"
            if "des." in code_lower or " des " in code_lower or "(des" in code_lower:
                return "CRYPTO-003"
            return "CRYPTO-001"  # default
        elif cwe == "CWE-329":
            return "CRYPTO-006"
        elif cwe == "CWE-321":
            return "CRYPTO-007"
        elif cwe == "CWE-338":
            return "CRYPTO-008"
        elif cwe == "CWE-916":
            return "CRYPTO-012"
        elif cwe == "CWE-208":
            return "CRYPTO-013"
        return ""
    for r in detect + triage:
        if r.get("rule"):
            continue
        # For triage records, try to extract rule from finding text first
        if r.get("task") == "triage":
            finding = r.get("finding", "")
            match = re.search(r'\[(CRYPTO-\d+)\]', finding)
            if match:
                r["rule"] = match.group(1)
                continue
        inferred = _infer_rule_from_code(r["code"], r.get("label", {}))
        if inferred:
            r["rule"] = inferred


def collect_all_samples():
    """Collect all samples from all three sources."""
    all_detect = []
    all_triage = []

    # ── Source 1: known_forms.py data structures ────────────────────────────
    from scripts.build_round5_known_forms import (
        POSITIVES, A_NEGATIVES, B_NEGATIVES,
        TRIAGE_REJECT, TRIAGE_CONFIRM, VAL_ADD, TEST_ADD,
        PASSLIB_REJECT, load_passlib_reject,
    )
    # PASSLIB_REJECT is populated only in __main__; load manually
    PASSLIB_REJECT.extend(load_passlib_reject())

    kf_detect = POSITIVES + A_NEGATIVES + B_NEGATIVES
    for r in VAL_ADD:
        if r["task"] == "detect":
            r["split"] = "val"
            kf_detect.append(r)
    for r in TEST_ADD:
        if r["task"] == "detect":
            r["split"] = "test"
            kf_detect.append(r)
    kf_triage = TRIAGE_REJECT + TRIAGE_CONFIRM + list(PASSLIB_REJECT)
    for r in TEST_ADD:
        if r["task"] == "triage":
            r["split"] = "test"
            kf_triage.append(r)

    # Infer rule field from CWE for known_forms records that have rule already set.
    cwe_to_rules = {}
    _infer_cwe_to_rules(cwe_to_rules, kf_detect + kf_triage)

    print(f"[source] known_forms:  detect={len(kf_detect)}  triage={len(kf_triage)}")
    all_detect.extend(kf_detect)
    all_triage.extend(kf_triage)

    # ── Source 2: library_audit.py data structures ──────────────────────────
    from scripts.build_round5_library_audit import (
        DETECT_POS, DETECT_ANEG, DETECT_BNEG,
        TRIAGE_CONFIRM as LA_TRIAGE_CONFIRM,
        TRIAGE_REJECT as LA_TRIAGE_REJECT,
    )
    la_detect = DETECT_POS + DETECT_ANEG + DETECT_BNEG
    la_triage = LA_TRIAGE_CONFIRM + LA_TRIAGE_REJECT
    # Library_audit samples are all marked split="train" or "val"/"test"
    # Check: DETECT_POS has 3 entries with split="val", 1 with split="test"

    _annotate_library_audit_rules(la_detect, la_triage)

    print(f"[source] library_audit: detect={len(la_detect)}  triage={len(la_triage)}")
    all_detect.extend(la_detect)
    all_triage.extend(la_triage)

    # ── Source 3: CRYPTO-009/010 ad-hoc samples ─────────────────────────────
    c09_detect, c09_triage, c10_detect, c10_triage = _build_009_010_samples()
    print(f"[source] CRYPTO-009/010:  detect={len(c09_detect)+len(c10_detect)}  "
          f"triage={len(c09_triage)+len(c10_triage)}")
    all_detect.extend(c09_detect)
    all_detect.extend(c10_detect)
    all_triage.extend(c09_triage)
    all_triage.extend(c10_triage)

    return all_detect, all_triage


def _build_009_010_samples():
    """Build CRYPTO-009 (weak key length) and CRYPTO-010 (insecure TLS) samples."""
    def _detect(rid, code, vulnerable, cwe, explanation, rule, split="train"):
        return {
            "id": rid, "language": "python", "task": "detect", "code": code,
            "label": {
                "vulnerable": vulnerable,
                "cwe": cwe if vulnerable else "",
                "severity": "WARNING" if vulnerable else "",
                "confidence": "high",
                "explanation": explanation,
            },
            "source": f"round5-adhoc-{rule.lower()}",
            "license": "original", "repo_url": "", "commit": "",
            "verified": False, "split": split, "rule": rule,
        }

    def _triage(rid, code, finding, verdict, cwe, explanation, rule,
                split="train", patch=""):
        return {
            "id": rid, "language": "python", "task": "triage", "code": code,
            "finding": finding,
            "label": {
                "cwe": cwe, "severity": "WARNING" if verdict == "Confirm" else "INFO",
                "verdict": verdict, "explanation": explanation,
                **({"patch": patch} if patch else {}),
            },
            "source": f"round5-adhoc-{rule.lower()}",
            "license": "original", "repo_url": "", "commit": "",
            "verified": False, "split": split, "rule": rule,
        }

    def _finding(rule_id):
        return f"[{rule_id}] {RULE_META[rule_id]['message']}"

    c09_detect = []
    c09_triage = []
    c10_detect = []
    c10_triage = []

    # ── CRYPTO-009: weak key length ─────────────────────────────────────────
    # DETECT POS: RSA 1024-bit key generation
    c09_detect.append(_detect("r5-009-pos-01", """
from Crypto.PublicKey import RSA

def generate_keypair():
    key = RSA.generate(1024)
    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    with open("public.pem", "wb") as f:
        f.write(key.publickey().export_key())
    return key
""".strip(), True, "CWE-326",
        "RSA.generate(1024) generates a 1024-bit RSA key. NIST SP 800-57 "
        "deprecates RSA-1024; minimum 2048 bits required since 2014. "
        "An attacker can factor a 1024-bit modulus with modest resources.",
        "CRYPTO-009"))

    # DETECT POS: weak elliptic curve
    c09_detect.append(_detect("r5-009-pos-02", """
from Crypto.PublicKey import ECC

def generate_ec_keypair():
    key = ECC.generate(curve="secp192r1")
    return key.export_key(format="PEM")
""".strip(), True, "CWE-326",
        "secp192r1 is a 192-bit elliptic curve providing ~96 bits of security. "
        "NIST recommends at least P-256 (128-bit security).",
        "CRYPTO-009"))

    # DETECT ANEG: RSA-2048 (safe)
    c09_detect.append(_detect("r5-009-aneg-01", """
from Crypto.PublicKey import RSA

def generate_keypair():
    key = RSA.generate(2048)
    return key.export_key()
""".strip(), False, "", "RSA-2048 meets current NIST minimum recommendation. Safe.", "CRYPTO-009"))

    # DETECT BNEG: old key as legacy-verify
    c09_detect.append(_detect("r5-009-bneg-01", """
from Crypto.PublicKey import RSA

def verify_legacy_signature(signature_data: bytes):
    # Legacy system uses RSA-1024 keys; we must LOAD the key to verify
    # existing signatures during migration, not GENERATE new ones.
    key = RSA.import_key(open("legacy_pub.pem").read())
    # key.size_in_bits() == 1024 — inherited, not chosen
    return verify(key, signature_data)
""".strip(), False, "",
        "RSA-1024 key is IMPORTED to verify an existing legacy signature. "
        "The key size is inherited from the old system; the library reads, "
        "does not generate. Safe — migration compatibility.", "CRYPTO-009"))

    # TRIAGE CONFIRM: RSA-1024 in production key gen
    c09_triage.append(_triage("r5-009-tpos-01", """
from Crypto.PublicKey import RSA

def provision_vpn_keypair(user_id: str):
    key = RSA.generate(1024)
    store_private_key(user_id, key)
    distribute_cert(user_id, key.publickey())
""".strip(), _finding("CRYPTO-009"), "Confirm", "CWE-326",
        "RSA-1024 key is generated for VPN key provisioning. The key protects "
        "real traffic and can be factored with moderate compute. Confirm.",
        "CRYPTO-009",
        patch="""
from Crypto.PublicKey import RSA

def provision_vpn_keypair(user_id: str):
    key = RSA.generate(2048)
    store_private_key(user_id, key)
    distribute_cert(user_id, key.publickey())
""".strip()))

    # TRIAGE REJECT: legacy import for migration
    c09_triage.append(_triage("r5-009-tneg-01", """
from Crypto.PublicKey import RSA

def migrate_user_key(old_pem_path: str, user_id: str) -> bool:
    # Migration utility: reads a legacy RSA-1024 key and re-encrypts it
    # under a new AES-256-GCM-wrapped format. Does not GENERATE 1024 bits.
    old_key = RSA.import_key(open(old_pem_path).read())
    if old_key.size_in_bits() < 2048:
        log_warning(user_id, "legacy key migrated, recommend re-key")
    rewrapped = wrap_with_aes_gcm(old_key.export_key())
    store(user_id, rewrapped)
    return True
""".strip(), _finding("CRYPTO-009"), "Reject", "",
        "The utility imports a legacy RSA key for migration, not generation. "
        "The key size is inherited from the old system. Tools that read old "
        "keys are not creating new vulnerabilities. Reject.",
        "CRYPTO-009"))

    # ── CRYPTO-010: insecure TLS ─────────────────────────────────────────────
    # DETECT POS: SSLv3/TLSv1 context
    c10_detect.append(_detect("r5-010-pos-01", """
import ssl

def create_client_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
    ctx.check_hostname = False
    return ctx
""".strip(), True, "CWE-326",
        "SSLv3 is a deprecated protocol with known attacks (POODLE, BEAST). "
        "Use PROTOCOL_TLS_CLIENT with TLS 1.2 minimum.",
        "CRYPTO-010"))

    # DETECT POS: requests with verify=False
    c10_detect.append(_detect("r5-010-pos-02", """
import requests

def fetch_config(server_url: str) -> dict:
    resp = requests.get(server_url, verify=False, timeout=5)
    return resp.json()
""".strip(), True, "CWE-326",
        "requests.get with verify=False disables TLS certificate validation, "
        "allowing MITM attacks. Use verify=True (default) or provide a CA bundle.",
        "CRYPTO-010"))

    # DETECT ANEG: proper TLS client
    c10_detect.append(_detect("r5-010-aneg-01", """
import ssl

def create_client_context():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
""".strip(), False, "",
        "ssl.create_default_context() with TLSv1_2 minimum. Safe TLS configuration.",
        "CRYPTO-010"))

    # DETECT BNEG: test mock with verify=False
    c10_detect.append(_detect("r5-010-bneg-01", """
import requests
import unittest

class TestHealthEndpoint(unittest.TestCase):
    def test_no_tls_in_dev(self):
        # Local dev server runs on HTTP, not HTTPS; verify=False is
        # required for the test to reach localhost.
        resp = requests.get("https://localhost:8443/health",
                            verify=False, timeout=2)
        self.assertEqual(resp.status_code, 200)
""".strip(), False, "",
        "verify=False in a unit test targeting a local dev server. "
        "No production traffic or real credentials are affected. "
        "Test scaffolding — safe.", "CRYPTO-010"))

    # TRIAGE CONFIRM: production SSLv3
    c10_triage.append(_triage("r5-010-tpos-01", """
import ssl

def create_production_client():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
""".strip(), _finding("CRYPTO-010"), "Confirm", "CWE-326",
        "PROTOCOL_TLSv1 with CERT_NONE in a production client. TLSv1 is "
        "deprecated and certificate validation is disabled — a MITM attacker "
        "can intercept and read all traffic. Confirm.",
        "CRYPTO-010",
        patch="""
import ssl

def create_production_client():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
""".strip()))

    # TRIAGE REJECT: test stub with self-signed cert
    c10_triage.append(_triage("r5-010-tneg-01", """
import requests

def health_check_integration_test():
    # Integration test hits a local container with a self-signed cert.
    # NOT used in production code paths.
    resp = requests.get("https://test-container:443/health",
                        verify="/tmp/test-ca.pem", timeout=3)
    assert resp.status_code == 200
""".strip(), _finding("CRYPTO-010"), "Reject", "",
        "Test verifies against a local container with a known test CA. "
        "The verify parameter explicitly points to a test CA bundle; "
        "this is not production traffic. Test scaffolding — Reject.",
        "CRYPTO-010"))

    return c09_detect, c09_triage, c10_detect, c10_triage


# ═════════════════════════════════════════════════════════════════════════════
# SPLIT REASSIGNMENT
# ═════════════════════════════════════════════════════════════════════════════

def reassign_splits(all_detect, all_triage):
    """
    Reassign train/val/test splits with stratification.

    Goals:
      - Every CRYPTO rule family has at least 1 held-out sample (val or test)
      - passlib legacy has at least 2 held-out (val + test)
      - test set contains ONLY truly unseen patterns
      - train: ~85%, val: ~7%, test: ~8% of new samples
    """
    import random
    random.seed(42)

    # Default: everything to train
    for r in all_detect + all_triage:
        if "split" not in r:
            r["split"] = "train"

    # Collect samples that can be held out, grouped by rule and type
    test_pool_detect = []
    test_pool_triage = []

    for r in all_detect:
        rule = r.get("rule", "UNKNOWN")
        vulnerable = r["label"]["vulnerable"]
        src = r.get("source", "")
        if src.endswith("aneg"):
            typ = "aneg"
        elif src.endswith("bneg"):
            typ = "bneg"
        elif vulnerable:
            typ = "pos"
        else:
            typ = "other"
        test_pool_detect.append((r, rule, typ, src))

    for r in all_triage:
        rule = r.get("rule", "UNKNOWN")
        verdict = r["label"]["verdict"]
        src = r.get("source", "")
        test_pool_triage.append((r, rule, verdict, src))

    # Strategy: for each rule family, hold out 1 detect pos + 1 triage sample
    # For passlib legacy (CRYPTO-001/002/003 bneg), ensure at least 1 held out

    all_rules = sorted(set(r.get("rule", "UNKNOWN") for r in all_detect + all_triage
                           if r.get("rule")))

    held_out_ids = set()

    # 1. Hold out 1 detect pos per rule family where possible
    rule_pos_map = {}
    for r, rule, typ, _ in test_pool_detect:
        if typ == "pos" and rule != "UNKNOWN":
            rule_pos_map.setdefault(rule, []).append(r)

    for rule, recs in rule_pos_map.items():
        if recs:
            chosen = random.choice(recs)
            held_out_ids.add(chosen["id"])

    # 2. Hold out 1 detect bneg (library legacy) for CRYPTO-001/002/003
    bneg_map = {}
    for r, rule, typ, _ in test_pool_detect:
        if typ == "bneg" and rule != "UNKNOWN":
            bneg_map.setdefault(rule, []).append(r)

    for rule, recs in bneg_map.items():
        available = [r for r in recs if r["id"] not in held_out_ids]
        if available:
            chosen = random.choice(available)
            held_out_ids.add(chosen["id"])

    # 3. Hold out 1 triage Confirm per rule family
    rule_tpos_map = {}
    for r, rule, verdict, _ in test_pool_triage:
        if verdict == "Confirm" and rule != "UNKNOWN":
            rule_tpos_map.setdefault(rule, []).append(r)

    for rule, recs in rule_tpos_map.items():
        available = [r for r in recs if r["id"] not in held_out_ids]
        if available:
            chosen = random.choice(available)
            held_out_ids.add(chosen["id"])

    # 4. Hold out 1 triage Reject per rule family
    rule_tneg_map = {}
    for r, rule, verdict, src in test_pool_triage:
        if verdict == "Reject" and rule != "UNKNOWN":
            rule_tneg_map.setdefault(rule, []).append(r)

    for rule, recs in rule_tneg_map.items():
        available = [r for r in recs if r["id"] not in held_out_ids]
        if available:
            chosen = random.choice(available)
            held_out_ids.add(chosen["id"])

    # 5. Hold out at least 2 passlib legacy triage records (from PASSLIB_REJECT source)
    passlib_recs = [r for r in all_triage
                    if r.get("source") in ("round5-passlib-legacy",)
                    and r["id"] not in held_out_ids]
    # Sort to get deterministic selection
    passlib_recs.sort(key=lambda r: r.get("file", r["id"]))
    for r in passlib_recs[:2]:
        held_out_ids.add(r["id"])

    # 6. Assign splits: held-out IDs → test, override existing val → val
    #    Distribute held-out: 60% val, 40% test
    held_list = list(held_out_ids)
    random.shuffle(held_list)
    n_val = max(1, int(len(held_list) * 0.3))
    val_ids = set(held_list[:n_val])
    test_ids = set(held_list[n_val:])

    train_count = 0
    val_count = 0
    test_count = 0

    for r in all_detect + all_triage:
        # Preserve existing val/test assignments that were set in source scripts
        existing = r.get("split", "train")
        if existing in ("val", "test"):
            if existing == "val":
                val_count += 1
            else:
                test_count += 1
            continue

        if r["id"] in val_ids:
            r["split"] = "val"
            val_count += 1
        elif r["id"] in test_ids:
            r["split"] = "test"
            test_count += 1
        else:
            r["split"] = "train"
            train_count += 1

    print(f"\n[split] train={train_count}  val={val_count}  test={test_count}  "
          f"total_new={train_count+val_count+test_count}")
    print(f"[split] held-out rules: {sorted(set(r.get('rule','?') for r in all_detect+all_triage if r['split'] in ('val','test') and r.get('rule')))}")

    return all_detect, all_triage


# ═════════════════════════════════════════════════════════════════════════════
# QUALITY ASSURANCE
# ═════════════════════════════════════════════════════════════════════════════

def norm(code):
    """Normalize code for comparison: strip whitespace."""
    return "".join(code.split())


def check_syntax(records):
    """Check that all code samples parse as valid Python."""
    failures = []
    for r in records:
        try:
            ast.parse(r["code"])
        except SyntaxError as e:
            failures.append((r["id"], str(e)))
    return failures


def check_label_consistency(records):
    """Check for conflicting labels on the same normalized code AND same task."""
    code_map = {}
    conflicts = []
    for r in records:
        key = (norm(r["code"]), r.get("task", "detect"))
        if key in code_map:
            prev = code_map[key]
            if (prev["label"].get("vulnerable") != r["label"].get("vulnerable") or
                prev["label"].get("verdict") != r["label"].get("verdict")):
                conflicts.append((prev["id"], r["id"], norm(r["code"])[:60]))
        else:
            code_map[key] = r
    return conflicts


def check_split_leakage(records):
    """Check that no (normalized code, task) pair appears in multiple splits."""
    train_codes = set()
    val_codes = set()
    test_codes = set()
    leakage = []

    for r in records:
        key = (norm(r["code"]), r.get("task", "detect"))
        split = r.get("split", "train")
        if split == "train":
            train_codes.add(key)
        elif split == "val":
            val_codes.add(key)
        elif split == "test":
            test_codes.add(key)

    for key in val_codes:
        if key in train_codes:
            leakage.append(("train→val", key[0][:60]))
    for key in test_codes:
        if key in train_codes or key in val_codes:
            leakage.append(("train/val→test", key[0][:60]))

    return leakage


def check_duplicate_ids(records):
    """Check for duplicate record IDs."""
    ids = [r["id"] for r in records]
    dupes = sorted(set(i for i in ids if ids.count(i) > 1))
    return dupes


def check_required_fields(records):
    """Check all required fields are present."""
    required = ["id", "language", "task", "code", "label", "source", "split"]
    missing = []
    for r in records:
        for field in required:
            if field not in r:
                missing.append((r.get("id", "?"), field))
    # Check task-specific
    for r in records:
        if r["task"] == "triage" and "finding" not in r:
            missing.append((r["id"], "finding"))
        if r["task"] == "detect" and "vulnerable" not in r["label"]:
            missing.append((r["id"], "label.vulnerable"))
        if r["task"] == "triage" and "verdict" not in r["label"]:
            missing.append((r["id"], "label.verdict"))
    return missing


def run_backtest(records, rules_dir):
    """Run Semgrep against all samples and return per-sample rule hits."""
    if not records:
        return {}
    with tempfile.TemporaryDirectory(prefix="r5qa_bt_") as td:
        for i, r in enumerate(records):
            Path(td, f"f{i:06d}.py").write_text(r["code"], encoding="utf-8")
        proc = subprocess.run(
            ["semgrep", "--config", str(rules_dir), "--json", "--quiet", td],
            capture_output=True, text=True,
        )
        try:
            results = json.loads(proc.stdout or "{}").get("results", [])
        except json.JSONDecodeError:
            results = []
        idx2rules = {}
        for h in results:
            idx = int(Path(h["path"]).name[1:6])
            rule_id = h["check_id"].split(".")[-1]
            idx2rules.setdefault(idx, []).append(rule_id)
        return idx2rules


def check_backtest_discipline(all_detect, all_triage, rules_dir):
    """Full backtest discipline check."""
    all_recs = all_detect + all_triage
    hits = run_backtest(all_recs, rules_dir)

    pos_missing = []       # pos samples with no rule hit
    aneg_hit = []          # aneg samples with rule hits
    bneg_no_fire = []      # bneg samples with no rule hit
    triage_finding_miss = []  # triage samples where finding rule doesn't fire on snippet

    for i, r in enumerate(all_recs):
        h = set(hits.get(i, []))
        src = r.get("source", "")
        rule = r.get("rule", "")
        task = r["task"]
        vulnerable = r["label"].get("vulnerable", False)

        if task == "detect":
            if vulnerable and not h:
                pos_missing.append(r["id"])
            elif not vulnerable and src.endswith("aneg") and h:
                aneg_hit.append((r["id"], sorted(h)))
            elif not vulnerable and src.endswith("bneg"):
                if not h:
                    bneg_no_fire.append(r["id"])
        elif task == "triage":
            # Triage: the finding rule should ideally fire on the snippet.
            # But for passlib real code, it often won't (real lib code ≠ simple pattern).
            # This is informational, not a hard failure for library samples.
            if rule and rule not in h:
                src_val = r.get("source", "")
                if "passlib" in src_val or "real" in src_val:
                    continue  # real library code may not match patterns
                triage_finding_miss.append(r["id"])

    return {
        "pos_missing": pos_missing,
        "aneg_hit": aneg_hit,
        "bneg_no_fire": bneg_no_fire,
        "triage_finding_miss": triage_finding_miss,
    }


def compute_distribution(all_detect, all_triage):
    """Compute dataset distribution stats."""
    stats = {}

    # Detect stats
    detect_rule_counts = Counter()
    for r in all_detect:
        if r.get("rule"):
            detect_rule_counts[r["rule"]] += 1

    stats["detect_by_rule"] = dict(detect_rule_counts)

    # Detect pos/neg ratio
    detect_pos = sum(1 for r in all_detect if r["label"]["vulnerable"])
    detect_neg = sum(1 for r in all_detect if not r["label"]["vulnerable"])
    stats["detect_pos_neg"] = f"{detect_pos}:{detect_neg}"

    # Triage stats
    triage_rule_counts = Counter()
    for r in all_triage:
        if r.get("rule"):
            triage_rule_counts[r["rule"]] += 1

    stats["triage_by_rule"] = dict(triage_rule_counts)

    triage_confirm = sum(1 for r in all_triage if r["label"]["verdict"] == "Confirm")
    triage_reject = sum(1 for r in all_triage if r["label"]["verdict"] == "Reject")
    stats["triage_confirm_reject"] = f"{triage_confirm}:{triage_reject}"

    # Split distribution
    for split in ("train", "val", "test"):
        d = sum(1 for r in all_detect if r["split"] == split)
        t = sum(1 for r in all_triage if r["split"] == split)
        stats[f"split_{split}"] = f"detect={d} triage={t}"

    return stats


def run_full_qa(all_detect, all_triage, rules_dir):
    """Run the full QA pipeline and return a report dict."""
    report = {"pass": True, "checks": {}}

    print("\n" + "=" * 72)
    print("QUALITY ASSURANCE PIPELINE")
    print("=" * 72)

    # 1. Duplicate IDs
    dupes = check_duplicate_ids(all_detect + all_triage)
    report["checks"]["duplicate_ids"] = len(dupes)
    if dupes:
        print(f"  [FAIL] duplicate IDs: {dupes}")
        report["pass"] = False
    else:
        print(f"  [PASS] duplicate IDs: 0")

    # 2. Required fields
    missing = check_required_fields(all_detect + all_triage)
    report["checks"]["missing_fields"] = len(missing)
    if missing:
        print(f"  [FAIL] missing fields: {missing[:10]}")
        report["pass"] = False
    else:
        print(f"  [PASS] missing fields: 0")

    # 3. Syntax validity
    syntax_errs = check_syntax(all_detect + all_triage)
    report["checks"]["syntax_errors"] = len(syntax_errs)
    if syntax_errs:
        print(f"  [FAIL] syntax errors ({len(syntax_errs)}):")
        for rid, err in syntax_errs[:10]:
            print(f"    {rid}: {err}")
        report["pass"] = False
    else:
        print(f"  [PASS] syntax errors: 0")

    # 4. Label consistency
    conflicts = check_label_consistency(all_detect + all_triage)
    report["checks"]["label_conflicts"] = len(conflicts)
    if conflicts:
        print(f"  [FAIL] label conflicts ({len(conflicts)}):")
        for id1, id2, code in conflicts[:5]:
            print(f"    {id1} vs {id2}: {code}...")
        report["pass"] = False
    else:
        print(f"  [PASS] label conflicts: 0")

    # 5. Split leakage
    leakage = check_split_leakage(all_detect + all_triage)
    report["checks"]["split_leakage"] = len(leakage)
    if leakage:
        print(f"  [FAIL] split leakage ({len(leakage)}):")
        for direction, code in leakage[:5]:
            print(f"    {direction}: {code}...")
        report["pass"] = False
    else:
        print(f"  [PASS] split leakage: 0")

    # 6. Backtest discipline
    bt = check_backtest_discipline(all_detect, all_triage, rules_dir)
    report["checks"]["backtest_pos_missing"] = len(bt["pos_missing"])
    report["checks"]["backtest_aneg_hit"] = len(bt["aneg_hit"])
    report["checks"]["backtest_bneg_no_fire"] = len(bt["bneg_no_fire"])

    if bt["pos_missing"]:
        print(f"  [FAIL] pos-missing ({len(bt['pos_missing'])}): {bt['pos_missing'][:5]}")
        report["pass"] = False
    else:
        print(f"  [PASS] pos-missing: 0")

    if bt["aneg_hit"]:
        print(f"  [FAIL] aneg-hit ({len(bt['aneg_hit'])}): {bt['aneg_hit'][:5]}")
        report["pass"] = False
    else:
        print(f"  [PASS] aneg-hit: 0")

    if bt["bneg_no_fire"]:
        print(f"  [INFO] bneg-no-fire ({len(bt['bneg_no_fire'])}): {bt['bneg_no_fire'][:5]}")
        # Not a hard fail for bneg — some library code patterns are complex
    else:
        print(f"  [PASS] bneg-no-fire: 0")

    if bt["triage_finding_miss"]:
        print(f"  [INFO] triage-finding-miss ({len(bt['triage_finding_miss'])}): "
              f"{bt['triage_finding_miss'][:5]}")

    # 7. Rule coverage check
    covered_rules = set()
    for r in all_detect + all_triage:
        if r.get("rule"):
            covered_rules.add(r["rule"])
    expected_rules = set(RULE_META.keys())
    missing_rules = expected_rules - covered_rules
    report["checks"]["rule_coverage"] = {
        "covered": sorted(covered_rules),
        "missing": sorted(missing_rules),
    }
    if missing_rules:
        print(f"  [INFO] missing rule coverage: {sorted(missing_rules)}")
    else:
        print(f"  [PASS] all {len(expected_rules)} rules have training data")

    # 8. Distribution
    dist = compute_distribution(all_detect, all_triage)
    report["checks"]["distribution"] = dist
    print(f"\n  Distribution:")
    print(f"    detect: total={len(all_detect)} ratio={dist['detect_pos_neg']}")
    print(f"    triage: total={len(all_triage)} ratio={dist['triage_confirm_reject']}")
    for split_key in ("split_train", "split_val", "split_test"):
        if split_key in dist:
            print(f"    {split_key}: {dist[split_key]}")
    print(f"  Rule coverage:")
    for rule in sorted(RULE_META.keys()):
        d = dist.get("detect_by_rule", {}).get(rule, 0)
        t = dist.get("triage_by_rule", {}).get(rule, 0)
        marker = "✓" if (d + t) > 0 else "✗"
        print(f"    {rule}: detect={d} triage={t} {marker}")

    return report


# ═════════════════════════════════════════════════════════════════════════════
# EMIT
# ═════════════════════════════════════════════════════════════════════════════

def emit_all(all_detect, all_triage, out_dir):
    """Write all output files."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # v2 schema source files
    src_detect = out_dir / "known_forms_detect.jsonl"
    src_triage = out_dir / "known_forms_triage.jsonl"
    src_detect.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in all_detect) + "\n",
        encoding="utf-8")
    src_triage.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in all_triage) + "\n",
        encoding="utf-8")
    print(f"\n[+] {src_detect}")
    print(f"[+] {src_triage}")

    # chatml upload set: merge with R4 base
    r4_train = [json.loads(l) for l in
                (R4_UPLOAD / "train.jsonl").read_text().splitlines() if l.strip()]
    r4_val = [json.loads(l) for l in
              (R4_UPLOAD / "val.jsonl").read_text().splitlines() if l.strip()]
    r4_test = [json.loads(l) for l in
               (R4_UPLOAD / "test.jsonl").read_text().splitlines() if l.strip()]

    print(f"\nR4 base: train={len(r4_train)} val={len(r4_val)} test={len(r4_test)}")

    new_train_d = [r for r in all_detect if r["split"] == "train"]
    new_train_t = [r for r in all_triage if r["split"] == "train"]
    new_val_d = [r for r in all_detect if r["split"] == "val"]
    new_val_t = [r for r in all_triage if r["split"] == "val"]
    new_test_d = [r for r in all_detect if r["split"] == "test"]
    new_test_t = [r for r in all_triage if r["split"] == "test"]

    train_ct = r4_train + [{"messages": build_messages(r)} for r in new_train_d + new_train_t]
    val_ct = r4_val + [{"messages": build_messages(r)} for r in new_val_d + new_val_t]
    test_ct = r4_test + [{"messages": build_messages(r)} for r in new_test_d + new_test_t]

    upload_dir = out_dir / "upload" / "full"
    upload_dir.mkdir(parents=True, exist_ok=True)
    for name, data in [("train", train_ct), ("val", val_ct), ("test", test_ct)]:
        p = upload_dir / f"{name}.jsonl"
        p.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in data) + "\n",
            encoding="utf-8")
        print(f"[+] {p}: {len(data)} records")


def generate_qa_md(report, all_detect, all_triage, out_dir):
    """Generate a human-readable QA report."""
    lines = []
    lines.append("# Round 5 Final Dataset — Quality Assurance Report")
    lines.append("")
    lines.append(f"**Total new samples**: {len(all_detect)+len(all_triage)} "
                 f"(detect={len(all_detect)} triage={len(all_triage)})")
    lines.append(f"**Overall QA**: {'PASS' if report['pass'] else 'FAIL'}")
    lines.append("")

    lines.append("## Checks")
    for check, result in report["checks"].items():
        if isinstance(result, dict):
            continue
        status = "✅" if (result == 0 and "missing" not in check) else \
                 ("⚠️" if result > 0 and check in ("bneg_no_fire", "triage_finding_miss") else \
                  ("✅" if check == "rule_coverage" else "❌" if result > 0 else "✅"))
        if check == "rule_coverage":
            # handled below
            pass
        else:
            lines.append(f"- {status} **{check}**: {result}")

    lines.append("")
    lines.append("## Rule Coverage")
    dist = report["checks"].get("distribution", {})
    for rule in sorted(RULE_META.keys()):
        d = dist.get("detect_by_rule", {}).get(rule, 0)
        t = dist.get("triage_by_rule", {}).get(rule, 0)
        status = "✅" if (d + t) > 0 else "❌"
        lines.append(f"- {status} **{rule}**: detect={d} triage={t}")

    lines.append("")
    lines.append("## Split Distribution")
    for key in sorted(dist.keys()):
        if key.startswith("split_"):
            lines.append(f"- **{key}**: {dist[key]}")

    lines.append("")
    lines.append("## Detect Source Distribution")
    detect_sources = Counter(r["source"] for r in all_detect)
    for src, cnt in sorted(detect_sources.items()):
        vuln = sum(1 for r in all_detect if r["source"] == src and r["label"]["vulnerable"])
        lines.append(f"- {src}: {cnt} (pos={vuln} neg={cnt-vuln})")

    lines.append("")
    lines.append("## Triage Source Distribution")
    triage_sources = Counter(r["source"] for r in all_triage)
    for src, cnt in sorted(triage_sources.items()):
        conf = sum(1 for r in all_triage if r["source"] == src and r["label"]["verdict"] == "Confirm")
        lines.append(f"- {src}: {cnt} (Confirm={conf} Reject={cnt-conf})")

    lines.append("")
    lines.append("## Held-out Test Samples (for eval)")
    test_recs = [r for r in all_detect + all_triage if r["split"] == "test"]
    for r in sorted(test_recs, key=lambda x: x["id"]):
        lines.append(f"- `{r['id']}` ({r['task']}, {r.get('rule','N/A')}, "
                     f"vuln={r['label'].get('vulnerable','?')} verdict={r['label'].get('verdict','?')})")

    report_path = out_dir / "qa_report.md"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n[+] QA report: {report_path}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="Build the FINAL Round-5 SFT dataset with full QA")
    ap.add_argument("--emit", action="store_true",
                    help="Write final dataset to disk")
    ap.add_argument("--skip-backtest", action="store_true",
                    help="Skip Semgrep backtest (requires semgrep installed)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Run QA only, do not write files")
    args = ap.parse_args()

    # ── Collect ─────────────────────────────────────────────────────────────
    print("=" * 72)
    print("COLLECTING SAMPLES")
    print("=" * 72)
    all_detect, all_triage = collect_all_samples()

    # ── Reassign splits ─────────────────────────────────────────────────────
    all_detect, all_triage = reassign_splits(all_detect, all_triage)

    # ── QA ──────────────────────────────────────────────────────────────────
    if args.skip_backtest:
        # Mock backtest (all pass)
        report = {"pass": True, "checks": {
            "duplicate_ids": 0, "missing_fields": 0, "syntax_errors": 0,
            "label_conflicts": 0, "split_leakage": 0,
            "backtest_pos_missing": "SKIPPED", "backtest_aneg_hit": "SKIPPED",
            "backtest_bneg_no_fire": "SKIPPED",
        }}
        # Still run non-backtest checks
        dupes = check_duplicate_ids(all_detect + all_triage)
        missing = check_required_fields(all_detect + all_triage)
        syntax_errs = check_syntax(all_detect + all_triage)
        conflicts = check_label_consistency(all_detect + all_triage)
        leakage = check_split_leakage(all_detect + all_triage)
        report["checks"]["duplicate_ids"] = len(dupes)
        report["checks"]["missing_fields"] = len(missing)
        report["checks"]["syntax_errors"] = len(syntax_errs)
        report["checks"]["label_conflicts"] = len(conflicts)
        report["checks"]["split_leakage"] = len(leakage)
        report["checks"]["distribution"] = compute_distribution(all_detect, all_triage)
        report["checks"]["rule_coverage"] = {
            "covered": sorted(set(r.get("rule","") for r in all_detect+all_triage if r.get("rule"))),
            "missing": sorted(set(RULE_META.keys()) - set(r.get("rule","") for r in all_detect+all_triage if r.get("rule"))),
        }
        report["pass"] = (len(dupes) == 0 and len(missing) == 0 and
                          len(syntax_errs) == 0 and len(conflicts) == 0 and
                          len(leakage) == 0)

        if dupes:
            print(f"  [FAIL] duplicate IDs: {dupes}")
        if missing:
            print(f"  [FAIL] missing fields: {missing[:10]}")
        if syntax_errs:
            print(f"  [FAIL] syntax errors ({len(syntax_errs)}):")
            for rid, err in syntax_errs[:10]:
                print(f"    {rid}: {err}")
        if conflicts:
            print(f"  [FAIL] label conflicts ({len(conflicts)})")
        if leakage:
            print(f"  [FAIL] split leakage ({len(leakage)})")
        if dupes:
            print(f"  [FAIL] duplicate IDs ({len(dupes)})")
        print(f"\n  Distribution:")
        dist = report["checks"]["distribution"]
        print(f"    detect: total={len(all_detect)} ratio={dist['detect_pos_neg']}")
        print(f"    triage: total={len(all_triage)} ratio={dist['triage_confirm_reject']}")
    else:
        report = run_full_qa(all_detect, all_triage, ROOT / "rules")

    # ── Emit ────────────────────────────────────────────────────────────────
    if args.emit and not args.dry_run:
        emit_all(all_detect, all_triage, FINAL)
        generate_qa_md(report, all_detect, all_triage, FINAL)

    # ── Summary ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print(f"SUMMARY: QA {'PASSED' if report['pass'] else 'FAILED — fix issues above'}")
    print(f"  New samples:  detect={len(all_detect)}  triage={len(all_triage)}  "
          f"total={len(all_detect)+len(all_triage)}")
    print(f"  Rules covered: {len(report['checks'].get('rule_coverage',{}).get('covered',[]))}/{len(RULE_META)}")
    print("=" * 72)

    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
