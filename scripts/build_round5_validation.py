#!/usr/bin/env python3
"""Round-5 post-training validation slice builder.

Round-5's acceptance gates are only measurable with a held-out eval set:

  * real-project regression : re-run the round-4 real_validation slice (42
    triage Reject + 7 secure detect) -- the passlib legacy-hash records that
    round-4 Confirmed 11/11 are the key regression target (8 now taught, 2
    remain truly held-out in upload/full/test.jsonl, 1 in val).
  * known-forms held-out    : fresh, hand-curated probes for CRYPTO-011/012/013
    (2 Confirm + 2 Reject per family + 1 pos + 1 aneg per family) that are NOT
    in the round-5 training set. Code is disjoint from known_forms_*.jsonl.

Outputs (data/round5/validation/):
  detect_eval.jsonl  triage_eval.jsonl  manifest.json
  configs/benchmark_round5.yaml  (detect -> detect_eval, domain -> triage_eval)

Usage: python scripts/build_round5_validation.py [--backtest]
"""
import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scripts.build_round5_known_forms as b5  # noqa: E402  (helpers only)

ROOT = Path(__file__).resolve().parent.parent
R5 = ROOT / "data" / "round5"
OUT = R5 / "validation"
CONF = ROOT / "configs" / "benchmark_round5.yaml"
R4_REAL = ROOT / "data" / "round4" / "real_validation"


def norm(s: str) -> str:
    return "".join(s.split())


def finding(rule: str) -> str:
    return f"[{rule}] {b5.RULE_META[rule]['message']}"


def v_detect(fam, rid, code, vulnerable, explanation, rule) -> dict:
    """detect record with explicit vulnerable flag (True=pos / False=aneg)."""
    meta = b5.RULE_META[rule]
    return {
        "id": rid, "language": "python", "task": "detect", "code": code,
        "label": {"vulnerable": vulnerable,
                  "cwe": meta["cwe"] if vulnerable else "",
                  "severity": meta["severity"] if vulnerable else "",
                  "confidence": "high", "explanation": explanation},
        "source": "round5-validation", "license": "original", "repo_url": "",
        "commit": "", "verified": True, "split": "test",
        "family": b5.FAMILIES[fam]["family"], "rule": rule,
    }


def v_triage(fam, rid, code, verdict, explanation, rule, patch="") -> dict:
    sev = "WARNING" if verdict == "Confirm" else "INFO"
    return {
        "id": rid, "language": "python", "task": "triage", "code": code,
        "finding": finding(rule),
        "label": {"cwe": b5.RULE_META[rule]["cwe"] if verdict == "Confirm" else "",
                  "severity": sev, "verdict": verdict,
                  "explanation": explanation,
                  **({"patch": patch} if patch else {})},
        "source": "round5-validation", "license": "original", "repo_url": "",
        "commit": "", "verified": True, "split": "test",
        "family": b5.FAMILIES[fam]["family"], "rule": rule,
    }


# =============================================================================
# Held-out known-forms probes. All code is freshly written and disjoint from
# data/round5/known_forms_*.jsonl (asserted below).
# =============================================================================
DETECT_EVAL = [
    # positives: one weak known form per family, must fire its CRYPTO rule
    v_detect("011", "r5v-011-pos", """def save_profile(db, profile, form_data):
    profile.password = form_data["password"]
    db.commit(profile)""",
        True,
        "A user profile persists the raw password from form data (CWE-256). "
        "Store a salted KDF digest instead.", "CRYPTO-011"),
    v_detect("012", "r5v-012-pos", """import hashlib

def store_secret_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 8000)""",
        True,
        "PBKDF2-HMAC-SHA256 with only 8k iterations (CWE-916) -- offline brute "
        "force recovers the password in seconds.", "CRYPTO-012"),
    v_detect("013", "r5v-013-pos", """def verify_api_hmac(computed_mac, provided_guess):
    if computed_mac == provided_guess:
        return accept()
    return deny()""",
        True,
        "Digest equality with == leaks timing on the HMAC comparison (CWE-208); "
        "use hmac.compare_digest.", "CRYPTO-013"),
    # negatives: modern secure forms, must fire NOTHING
    v_detect("011", "r5v-011-aneg", """import hashlib

def save_account(user, raw):
    user.password_hash = hashlib.pbkdf2_hmac("sha256", raw.encode(), b"salt", 310000).hex()
    db.save(user)""",
        False,
        "password_hash stores a KDF digest; the plaintext never touches the DB "
        "-> safe.", "CRYPTO-011"),
    v_detect("012", "r5v-012-aneg", """import hashlib

def hash_secret(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)""",
        False,
        "PBKDF2 with 600k iterations (>=100k, OWASP-preferred range) -> safe.",
        "CRYPTO-012"),
    v_detect("013", "r5v-013-aneg", """import secrets

def check_cookie_equal(server_cookie, client_cookie):
    return secrets.compare_digest(server_cookie, client_cookie)""",
        False,
        "Session cookie compared with secrets.compare_digest (constant time) -> "
        "safe.", "CRYPTO-013"),
]

TRIAGE_EVAL = [
    # ---- Confirm: the same known forms protecting a real secret -------------
    v_triage("011", "r5v-011-tpos", """def create_account(db, registration):
    acc = db.Account()
    acc.email = registration["email"]
    acc.passwd = registration["password"]
    db.add(acc)""",
        "Confirm",
        "The account password is persisted verbatim; DB readers recover the "
        "plaintext credential (CWE-256).",
        "CRYPTO-011",
        patch="""def create_account(db, registration):
    acc = db.Account()
    acc.email = registration["email"]
    acc.passwd = make_password(registration["password"])
    db.add(acc)"""),
    v_triage("012", "r5v-012-tpos", """import hashlib

def verify_credential(password, salt, stored):
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 60000)
    return hmac.compare_digest(candidate, stored)""",
        "Confirm",
        "Live credentials verified with only 60k PBKDF2 iterations (CWE-916) -- "
        "below the 100k minimum for password hashing.",
        "CRYPTO-012",
        patch="""import hashlib

def verify_credential(password, salt, stored):
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return hmac.compare_digest(candidate, stored)"""),
    v_triage("013", "r5v-013-tpos", """def authorize_user(user, attempt):
    if user.passwd_hash != attempt:
        return "denied"
    return issue_session(user)""",
        "Confirm",
        "Password digest compared with != (CWE-208): timing leaks how many "
        "prefix bytes matched; use secrets.compare_digest.",
        "CRYPTO-013",
        patch="""import secrets

def authorize_user(user, attempt):
    if not secrets.compare_digest(user.passwd_hash, attempt):
        return "denied"
    return issue_session(user)"""),
    # ---- Reject: documented exceptions (benign/test/legacy/benchmark) -------
    v_triage("011", "r5v-011-tneg", """import hashlib

def sync_account_digest(user, raw):
    user.password = hashlib.pbkdf2_hmac("sha256", raw.encode(), user.salt, 600000)
    db.save(user)""",
        "Reject",
        "`.password` receives a 600k-iteration PBKDF2 digest, not plaintext; "
        "the all-alarm static hit is a false positive -> Reject.",
        "CRYPTO-011"),
    v_triage("012", "r5v-012-tneg", """import hashlib

def bench_scrypt_throughput():
    for _ in range(200):
        hashlib.scrypt(b"bench", salt=b"bench-salt", n=1024, r=8, p=1)""",
        "Reject",
        "Deliberately cheap scrypt inside a throughput benchmark; no credential "
        "depends on the output -> Reject (B 类 benchmark).",
        "CRYPTO-012"),
    v_triage("013", "r5v-013-tneg", """def serve_from_cache(cache, request_digest):
    if cache.digest == request_digest:
        return serve(cache)
    return fetch_and_store(request_digest)""",
        "Reject",
        "Digest equality is a cache-hit check; no credential or signature "
        "depends on the compare -> Reject (B 类 non-security purpose).",
        "CRYPTO-013"),
]


def _load_r5_known():
    recs = []
    for name in ("known_forms_detect.jsonl", "known_forms_triage.jsonl"):
        p = R5 / name
        if p.exists():
            recs += [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return recs


def leakage_check(fresh: list) -> list:
    """Return any fresh record whose normalized code already appears in the
    round-5 training sources (would contaminate the held-out slice)."""
    train_codes = {norm(r["code"]) for r in _load_r5_known()}
    return [r["id"] for r in fresh if norm(r["code"]) in train_codes]


def build(backtest: bool) -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    # regression: round-4 real-project records (already v2, split=test, verified)
    reg_detect = [json.loads(l) for l in
                  (R4_REAL / "detect.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    reg_triage = [json.loads(l) for l in
                  (R4_REAL / "triage.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]

    fresh = DETECT_EVAL + TRIAGE_EVAL
    leaks = leakage_check(fresh)
    if leaks:
        print(f"[!] LEAK: fresh validation records found in round-5 training: {leaks}")
        return 1
    # also no intra-slice duplicate code
    seen, dup = set(), []
    for r in fresh:
        nc = norm(r["code"])
        if nc in seen:
            dup.append(r["id"])
        seen.add(nc)
    if dup:
        print(f"[!] duplicate code inside validation slice: {dup}")
        return 1

    def dump(recs, name):
        p = OUT / name
        with open(p, "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"[+] wrote {len(recs)} -> {p}")

    dump(reg_detect + DETECT_EVAL, "detect_eval.jsonl")
    dump(reg_triage + TRIAGE_EVAL, "triage_eval.jsonl")

    manifest = {
        "round": 5,
        "created": "2026-09-20",
        "detect": {
            "n": len(reg_detect) + len(DETECT_EVAL),
            "regression_real_secure": len(reg_detect),
            "known_forms_pos": sum(1 for r in DETECT_EVAL if r["label"]["vulnerable"]),
            "known_forms_aneg": sum(1 for r in DETECT_EVAL if not r["label"]["vulnerable"]),
        },
        "triage": {
            "n": len(reg_triage) + len(TRIAGE_EVAL),
            "regression_real_reject": len(reg_triage),
            "known_forms_confirm": sum(1 for r in TRIAGE_EVAL if r["label"]["verdict"] == "Confirm"),
            "known_forms_reject": sum(1 for r in TRIAGE_EVAL if r["label"]["verdict"] == "Reject"),
        },
        "notes": (
            "reg_triage = round-4 42 real-project Rejects (passlib 11 were the R4 "
            "11/11 Confirm failure -- 8 now in R5 train, 2 held-out in "
            "upload/full/test.jsonl, 1 in val). fresh probes are disjoint from "
            "the R5 training set."
        ),
    }
    (OUT / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if backtest:
        report = b5.backtest(fresh)
        problems = []
        for rid, v in report.items():
            hit = set(v["rules_hit"])
            exp = v["expected_rule"]
            if rid.endswith("-pos"):
                if hit != {exp}:
                    problems.append((rid, sorted(hit)))
            elif rid.endswith("-aneg"):
                if hit:
                    problems.append((rid, sorted(hit)))
            elif rid.endswith("-tpos") or rid.endswith("-tneg"):
                if exp not in hit:
                    problems.append((rid, sorted(hit)))
        print(f"[backtest-fresh] {len(fresh)} probes | problems={len(problems)} "
              f"(pos must fire own rule only, aneg none, triage finding fired)")
        for rid, hits in problems:
            print(f"  [!] {rid}: {hits}")

    cfg = {
        "model": {"kind": "cloud", "model_id": "qwen3-4b"},
        "static": {"rules": "rules/"},
        "splits": {
            "detect": str(OUT / "detect_eval.jsonl"),
            "domain": str(OUT / "triage_eval.jsonl"),
        },
        "systems": ["llm"],
    }
    CONF.parent.mkdir(parents=True, exist_ok=True)
    CONF.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    print(f"[+] wrote config -> {CONF}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Build round-5 validation slice")
    ap.add_argument("--backtest", action="store_true",
                    help="also run semgrep over the fresh probes to assert rule discipline")
    args = ap.parse_args()
    sys.exit(build(args.backtest))
