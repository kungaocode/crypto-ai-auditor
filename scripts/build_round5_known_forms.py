#!/usr/bin/env python3
"""Round-5 known-forms builder: CRYPTO-011/012/013 families (detect + triage).

Motivation (see data/round5/ROUND5_GUIDE.md). Round-4 showed the model still
fails where it matters most:
  * detect_train has ZERO positives for CWE-256 (CRYPTO-011), CWE-916 (012),
    CWE-208 (013) -- the three rules added in the last commit have no training
    support, so the model never learned the *known forms* they encode.
  * triage confirms every passlib legacy-hash implementation (11/11), because
    "a password library must reproduce legacy formats" was never taught.
  * CRYPTO-011 is deliberately all-alarm: the static rule fires on ANY
    `.password = X`, including `user.password = hash_password(pw)` (RHS is a
    KDF digest). Triage must learn to Reject those benign assignments.

This script emits (all v2 schema, see scripts/prepare_sft_data.py):
  data/round5/known_forms_detect.jsonl  detect positives/A-neg/B-neg/train+val+test
  data/round5/known_forms_triage.jsonl  triage Confirm/Reject (curated + passlib 11)
  data/round5/backtest_report.jsonl     Semgrep per-sample hit discipline
  data/round5/upload/full/{train,val,test}.jsonl   chatml, base = round-4
             full/train (2672) + new samples, for a FULL BASE RETRAIN (never
             incremental: round-2/4-微量 proved catastrophic forgetting twice).

Sample classes (mirror docs/crypto_vuln_taxonomy.md §3):
  pos  : vulnerable=true,  weak known form, must fire its own CRYPTO rule
  aneg : vulnerable=false, A 类 secure modern form, must fire ZERO rules
  bneg : vulnerable=false, B 类 weak form x non-security purpose, rule FIRES
         (model must look past the rule hit to the purpose)
  tneg : triage Reject    (finding is a known exception: benign assignment,
         legacy-format verification, test/benchmark scaffolding)
  tpos : triage Confirm   (weak form protecting a real credential/key)

Usage: python scripts/build_round5_known_forms.py [--backtest] [--emit]
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.prepare_sft_data import build_messages  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
R5 = ROOT / "data" / "round5"

# Rule metadata -- single source of truth = the rule files themselves.
RULES_YAML = sorted(Path(ROOT / "rules").glob("crypto-*/rule.yaml"))
RULE_META = {}
for y in RULES_YAML:
    for r in yaml.safe_load(y.read_text(encoding="utf-8")).get("rules", []):
        RULE_META[r["id"]] = {
            "cwe": r.get("metadata", {}).get("cwe", ""),
            "severity": r.get("severity", "WARNING"),
            "message": r["message"],
        }

FAMILIES = {
    "011": {"rule": "CRYPTO-011", "family": "password-storage"},
    "012": {"rule": "CRYPTO-012", "family": "kdf-params"},
    "013": {"rule": "CRYPTO-013", "family": "timing-compare"},
}
RULE_BY_FAMILY = {v["rule"]: k for k, v in FAMILIES.items()}

SEV_CONFIRM = "WARNING"   # matches prior crypto triage Confirm convention
SEV_REJECT = "INFO"       # matches round-4 real-project Reject convention


def finding(rule: str) -> str:
    return f"[{rule}] {RULE_META[rule]['message']}"


def pos(fam: str, rid: str, code: str, explanation: str, split: str = "train") -> dict:
    rule = FAMILIES[fam]["rule"]
    return {
        "id": rid, "language": "python", "task": "detect", "code": code,
        "label": {"vulnerable": True, "cwe": RULE_META[rule]["cwe"],
                  "severity": RULE_META[rule]["severity"], "confidence": "high",
                  "explanation": explanation},
        "source": f"round5-known-{FAMILIES[fam]['family']}-pos",
        "license": "original", "repo_url": "", "commit": "",
        "verified": False, "split": split, "family": FAMILIES[fam]["family"],
        "rule": rule,
    }


def aneg(fam: str, rid: str, code: str, explanation: str, split: str = "train") -> dict:
    rule = FAMILIES[fam]["rule"]
    return {
        "id": rid, "language": "python", "task": "detect", "code": code,
        "label": {"vulnerable": False, "cwe": "", "severity": "",
                  "confidence": "high", "explanation": explanation},
        "source": f"round5-known-{FAMILIES[fam]['family']}-aneg",
        "license": "original", "repo_url": "", "commit": "",
        "verified": False, "split": split, "family": FAMILIES[fam]["family"],
        "rule": rule,
    }


def bneg(fam: str, rid: str, code: str, explanation: str, split: str = "train") -> dict:
    rule = FAMILIES[fam]["rule"]
    return {
        "id": rid, "language": "python", "task": "detect", "code": code,
        "label": {"vulnerable": False, "cwe": "", "severity": "",
                  "confidence": "high", "explanation": explanation},
        "source": f"round5-known-{FAMILIES[fam]['family']}-bneg",
        "license": "original", "repo_url": "", "commit": "",
        "verified": False, "split": split, "family": FAMILIES[fam]["family"],
        "rule": rule,
    }


def tneg(fam: str, rid: str, code: str, explanation: str, split: str = "train") -> dict:
    rule = FAMILIES[fam]["rule"]
    return {
        "id": rid, "language": "python", "task": "triage", "code": code,
        "finding": finding(rule),
        "label": {"cwe": "", "severity": SEV_REJECT, "verdict": "Reject",
                  "explanation": explanation},
        "source": f"round5-known-{FAMILIES[fam]['family']}-tneg",
        "license": "original", "repo_url": "", "commit": "",
        "verified": False, "split": split, "family": FAMILIES[fam]["family"],
        "rule": rule,
    }


def tpos(fam: str, rid: str, code: str, explanation: str, patch: str,
         split: str = "train") -> dict:
    rule = FAMILIES[fam]["rule"]
    return {
        "id": rid, "language": "python", "task": "triage", "code": code,
        "finding": finding(rule),
        "label": {"cwe": RULE_META[rule]["cwe"], "severity": SEV_CONFIRM,
                  "verdict": "Confirm", "explanation": explanation, "patch": patch},
        "source": f"round5-known-{FAMILIES[fam]['family']}-tpos",
        "license": "original", "repo_url": "", "commit": "",
        "verified": False, "split": split, "family": FAMILIES[fam]["family"],
        "rule": rule,
    }


# =============================================================================
# DETECT POSITIVES -- vulnerable=true, known weak forms, each fires its rule.
# =============================================================================
POSITIVES = [
    # ---------- CRYPTO-011 plaintext-password storage ------------------------
    pos("011", "r5-011-pos-01", """def register(db, form):
    user = db.User()
    user.email = form["email"]
    user.password = form["password"]
    db.add(user)
    return user""",
        "The raw password from the registration form is stored verbatim in the "
        "user record. Anyone who reads the DB row gets the plaintext secret "
        "(CWE-256). Store only a salted KDF digest."),
    pos("011", "r5-011-pos-02", """def change_password(db, user_id, old_pw, new_pw):
    user = db.get(user_id)
    user.passwd = new_pw
    db.commit()""",
        "A new password is assigned to the account column in plaintext; the "
        "database then holds the user's live password (CWE-256). Hash with a "
        "KDF before persisting."),
    pos("011", "r5-011-pos-03", """def reset_password(api, user_id, plaintext):
    user = api.users[user_id]
    user.set_password(plaintext)
    api.save(user)""",
        "set_password() receives the plaintext and stores it without a one-way "
        "hash, so the account secret is persisted in recoverable form (CWE-256)."),
    pos("011", "r5-011-pos-04", """def import_legacy_user(conn, row):
    u = User()
    u.pwd = row["password"]
    conn.add(u)""",
        "A legacy import copies the password column straight into the user "
        "object without hashing (CWE-256)."),
    pos("011", "r5-011-pos-05", """def provision_remote_account(host, login, secret):
    account = RemoteAccount(host)
    account.password = secret
    deploy(account)""",
        "A provisioned account stores the raw secret on the object and is then "
        "deployed; the credential circulates and persists in plaintext (CWE-256)."),
    pos("011", "r5-011-pos-06", """def open_session_login(user, raw):
    session = Session(user)
    session.password = raw
    persist(session)""",
        "The login password is copied into a persisted session record, "
        "leaking the plaintext credential (CWE-256)."),

    # ---------- CRYPTO-012 weak KDF parameters -------------------------------
    pos("012", "r5-012-pos-01", """from hashlib import pbkdf2_hmac

def hash_password(password, salt):
    return pbkdf2_hmac("sha256", password.encode(), salt, 10000)""",
        "PBKDF2-HMAC-SHA256 with only 10k iterations (CWE-916). OWASP/NIST "
        "recommend >=100k; 300k-600k preferred for SHA-256. GPU attacks brute "
        "force 10k-iteration hashes in seconds."),
    pos("012", "r5-012-pos-02", """import hashlib
import os

def set_password(user, password):
    salt = os.urandom(16)
    user.password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 5000)""",
        "PBKDF2 with only 5k iterations (CWE-916); should be >=100k (300k-600k "
        "preferred) to slow offline brute force."),
    pos("012", "r5-012-pos-03", """from Crypto.Protocol.KDF import PBKDF2

def derive_data_key(password, salt):
    return PBKDF2(password, salt, 32, count=20000)""",
        "PBKDF2 count=20000 is far below the 100k minimum (CWE-916); the derived "
        "key protects real data and is cheap to brute force."),
    pos("012", "r5-012-pos-04", """from Crypto.Protocol.KDF import PBKDF2

def derive_master_key(pin, salt):
    return PBKDF2(pin, salt, 16, 1000)""",
        "PBKDF2 with 1k iterations (CWE-916) makes the master key derivable in "
        "milliseconds; use >=100k iterations."),
    pos("012", "r5-012-pos-05", """import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4))""",
        "bcrypt cost 4 (< 12) is trivially fast (CWE-916). Raise the work "
        "factor to cost >=12."),
    pos("012", "r5-012-pos-06", """import hashlib

def hash_password(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=1024, r=8, p=1)""",
        "scrypt n=2**10 is far below the recommended n>=2**14 (CWE-916), so the "
        "memory-hardness that makes scrypt strong is effectively disabled."),
    pos("012", "r5-012-pos-07", """import hashlib

def derive_key(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=8192, r=8, p=1)""",
        "scrypt n=2**13 < 2**14 (CWE-916); too small a CPU/memory cost for "
        "password hashing in 2026."),

    # ---------- CRYPTO-013 timing-unsafe comparison --------------------------
    pos("013", "r5-013-pos-01", """def login(user, input_password):
    if user.password == input_password:
        create_session(user)
        return "ok"
    return "denied" """,
        "Passwords are compared with == (CWE-208). The early-exit timing leaks "
        "the prefix; with enough requests an attacker recovers the password "
        "byte-by-byte. Use hmac.compare_digest."),
    pos("013", "r5-013-pos-02", """def authorize(request, valid_token):
    if request.token != valid_token:
        raise PermissionDenied
    return grant(request)""",
        "An auth token is compared with != (CWE-208); timing reveals how many "
        "leading bytes match. Use secrets.compare_digest."),
    pos("013", "r5-013-pos-03", """def verify_webhook(computed_signature, expected_signature):
    return computed_signature == expected_signature""",
        "Webhook signature verified with == (CWE-208); an attacker measures "
        "timing to forge the MAC. Use hmac.compare_digest."),
    pos("013", "r5-013-pos-04", """def check_otp(stored_secret, guess):
    return stored_secret == guess""",
        "OTP/2FA secret compared with == (CWE-208); timing leaks the code. Use "
        "hmac.compare_digest with the generated code."),
    pos("013", "r5-013-pos-05", """import hmac
import hashlib

def check_tag(message, key, provided_mac):
    digest = hmac.new(key, message, hashlib.sha256).digest()
    return digest == provided_mac""",
        "An HMAC tag is verified with == (CWE-208). Tag comparisons must be "
        "constant-time (hmac.compare_digest), especially for online MAC "
        "forgery resistance."),
    pos("013", "r5-013-pos-06", """def authenticate(user, input_pw):
    if user.pw == input_pw:
        return issue_token(user)
    return None""",
        "Password check via == (CWE-208); timing side channel discloses the "
        "password prefix. Use hmac.compare_digest(user.pw, input_pw)."),
]

# =============================================================================
# DETECT A-NEGATIVES -- vulnerable=false, A 类 secure modern forms, 0 rule hits.
# =============================================================================
A_NEGATIVES = [
    # ---------- CRYPTO-011 safe password storage -----------------------------
    aneg("011", "r5-011-aneg-01", """import hashlib
import os

def hash_password(password):
    salt = os.urandom(16)
    return salt.hex() + hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()

def save_user(user, password):
    user.password_hash = hash_password(password)""",
        "The stored field is password_hash and its value is a salted scrypt "
        "digest (n=2**14). No plaintext password is persisted -> safe."),
    aneg("011", "r5-011-aneg-02", """def create_user(db, email, raw):
    hashed = argon2_hasher.hash(raw)
    db.insert({"email": email, "password_hash": hashed})""",
        "argon2 (memory-hard KDF) with a random salt is stored under "
        "password_hash; the plaintext never touches the DB -> safe."),
    aneg("011", "r5-011-aneg-03", """def store_user(conn, username, raw_password):
    digest = make_password(raw_password)
    conn.execute(
        "INSERT INTO accounts (username, password_hash) VALUES (?, ?)",
        (username, digest),
    )""",
        "Only a KDF digest (from make_password) is written to the password_hash "
        "column; the raw password is not stored -> safe."),
    aneg("011", "r5-011-aneg-04", """def register(request):
    user = User(username=request.POST["username"])
    user.password_hash = make_password(request.POST["password"])
    user.save()""",
        "Django-style registration hashes with make_password() (PBKDF2/argon2) "
        "into password_hash; plaintext is never persisted -> safe."),

    # ---------- CRYPTO-012 strong KDF parameters -----------------------------
    aneg("012", "r5-012-aneg-01", """import hashlib

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)""",
        "PBKDF2-HMAC-SHA256 with 310k iterations, above the 100k minimum -> "
        "adequate password hashing."),
    aneg("012", "r5-012-aneg-02", """import hashlib

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)""",
        "PBKDF2 with 600k iterations, in the preferred 300k-600k range -> safe."),
    aneg("012", "r5-012-aneg-03", """from Crypto.Protocol.KDF import PBKDF2

def derive_data_key(password, salt):
    return PBKDF2(password, salt, 32, count=600000)""",
        "PBKDF2 count=600k (>=100k) with a random salt -> safe key derivation."),
    aneg("012", "r5-012-aneg-04", """import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))""",
        "bcrypt cost 12, meeting the >=12 recommendation -> safe."),
    aneg("012", "r5-012-aneg-05", """import hashlib

def hash_password(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)""",
        "scrypt n=2**14 with r=8, p=1 -> the recommended memory-hard "
        "parameters -> safe."),
    aneg("012", "r5-012-aneg-06", """from argon2 import PasswordHasher

def hash_password(password):
    return PasswordHasher().hash(password)""",
        "argon2 via PasswordHasher uses strong defaults (memory-hard, salted) "
        "-> safe."),

    # ---------- CRYPTO-013 constant-time / non-credential comparison ---------
    aneg("013", "r5-013-aneg-01", """import hmac

def verify_password(stored_hash, candidate):
    return hmac.compare_digest(stored_hash, candidate)""",
        "Credential digest compared with hmac.compare_digest (constant time) "
        "-> safe."),
    aneg("013", "r5-013-aneg-02", """import secrets

def verify_reset_token(stored, provided):
    return secrets.compare_digest(stored, provided)""",
        "One-time reset token compared in constant time -> safe."),
    aneg("013", "r5-013-aneg-03", """def same_user(user, provided_name):
    return user.name == provided_name""",
        "A display name, not a credential, is compared with ==; no secret "
        "depends on the comparison -> safe."),
    aneg("013", "r5-013-aneg-04", """def is_success(status_code, expected_code):
    return status_code == expected_code""",
        "HTTP status-code equality; nothing security-sensitive is compared -> "
        "safe (no constant-time need)."),
    aneg("013", "r5-013-aneg-05", """def is_expected_size(file_size, expected_size):
    return file_size == expected_size""",
        "File size check; not a credential/digest -> safe."),
    aneg("013", "r5-013-aneg-06", """import secrets

def verify_hmac_tag(computed, provided_tag):
    return secrets.compare_digest(computed, provided_tag)""",
        "HMAC tag verified in constant time with secrets.compare_digest -> safe."),
]

# =============================================================================
# DETECT B-NEGATIVES -- vulnerable=false, B 类 exceptions; rule FIRES but the
# weak form serves a non-security purpose so the model must say "safe".
# =============================================================================
B_NEGATIVES = [
    # ---------- CRYPTO-011 benign assignment / test scaffolding --------------
    bneg("011", "r5-011-bneg-01", """import hashlib
import os

def hash_password(password):
    salt = os.urandom(16)
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)

def save_user(user, password):
    user.password = hash_password(password)""",
        "The static rule fires on any `.password = X`, but the assigned value "
        "is already a salted scrypt digest, not the plaintext. The rule is "
        "all-alarm by design; the model must reject -> safe."),
    bneg("011", "r5-011-bneg-02", """from argon2 import PasswordHasher

def save_user(user, raw_password):
    user.password = PasswordHasher().hash(raw_password)""",
        "`.password` gets an argon2 digest (memory-hard KDF), so the stored "
        "value is not recoverable plaintext -> safe despite the rule firing."),
    bneg("011", "r5-011-bneg-03", """import bcrypt

def save_user(user, raw_password):
    user.password = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt())""",
        "`.password` holds a bcrypt hash (default cost 12), never the raw "
        "password -> safe; static all-alarm hit is a known false positive."),
    bneg("011", "r5-011-bneg-04", """def seed_test_user(db):
    user = db.User(username="tester")
    user.password = "test-password-123"
    return user""",
        "A unit-test fixture seeds a fake user with a throwaway test password; "
        "no real credential or database production value depends on it -> safe "
        "(test scaffolding)."),

    # ---------- CRYPTO-012 low KDF params in test/benchmark/legacy-verify ----
    bneg("012", "r5-012-bneg-01", """import hashlib

def bench_pbkdf2():
    for _ in range(1000):
        hashlib.pbkdf2_hmac("sha256", b"bench", b"salt", 1000)""",
        "PBKDF2 with 1k iterations inside a throughput benchmark: the low cost "
        "is the point, no credential depends on the output -> safe (B 类)."),
    bneg("012", "r5-012-bneg-02", """from hashlib import pbkdf2_hmac

def test_derive_known_vector():
    key = pbkdf2_hmac("sha256", b"password", b"salt", 1000)
    assert key == RFC_TEST_VECTOR""",
        "A unit test derives a fixed RFC test vector with 1k iterations to keep "
        "the test fast; no production secret is protected -> safe (test "
        "scaffolding)."),
    bneg("012", "r5-012-bneg-03", """import hmac
from hashlib import pbkdf2_hmac

def verify_legacy_pbkdf2(password, salt, stored_hash):
    candidate = pbkdf2_hmac("sha256", password.encode(), salt, 1000)
    return hmac.compare_digest(candidate, stored_hash)""",
        "A password library verifying an OLD account hash that was stored with "
        "1k iterations must reproduce the original parameters; reducing them "
        "would change the hash -> safe (legacy-format exception)."),

    # ---------- CRYPTO-013 non-credential equality (change detection/dedup) --
    bneg("013", "r5-013-bneg-01", """def get_cached(path, content_bytes):
    expected_hash = fingerprint(content_bytes)
    if content_hash == expected_hash:
        return get_cached(path)
    return None""",
        "Digest equality is used as a change-detection cache key (ETag-like); "
        "no credential, token or signature depends on the comparison -> safe "
        "(B 类), though the static rule fires."),
    bneg("013", "r5-013-bneg-02", """def dedupe_upload(blob, existing_digest):
    if blob.digest == existing_digest:
        return {"skipped": True, "id": existing_digest}
    return upload(blob)""",
        "Upload dedup compares content digests; timing leaks nothing "
        "security-relevant -> safe (B 类)."),
    bneg("013", "r5-013-bneg-03", """def test_token_generation():
    generated_token = make_test_token("alice")
    assert generated_token == expected_token""",
        "A unit test asserts a generated test token equals an expected literal; "
        "test scaffolding only -> safe."),
    bneg("013", "r5-013-bneg-04", """def content_addressed_store(blob, stored_hash_id):
    if blob_hash == stored_hash_id:
        return reuse(blob_hash)
    return store(blob)""",
        "Content-addressed storage keys on the hash of the blob; the comparison "
        "guards availability/dedup, not a secret -> safe (B 类)."),
]

# =============================================================================
# TRIAGE REJECT -- documented exceptions. 011: benign KDF assignment / test
# fixture; 012: test/benchmark/legacy-verify; 013: change-detection/dedup/test.
# =============================================================================
TRIAGE_REJECT = [
    tneg("011", "r5-011-tneg-01", """import hashlib
import os

def hash_password(password):
    salt = os.urandom(16)
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)

def save_user(user, password):
    user.password = hash_password(password)""",
        "CRYPTO-011 is all-alarm: it fires on any `.password = X`. Here the "
        "right-hand side is already a salted scrypt digest, so no plaintext is "
        "stored -- a known static false positive -> Reject."),
    tneg("011", "r5-011-tneg-02", """from argon2 import PasswordHasher

def save_user(user, raw_password):
    user.password = PasswordHasher().hash(raw_password)""",
        "The assigned value is an argon2 digest, not the raw password; the "
        "finding pattern cannot see semantics -> Reject (benign assignment)."),
    tneg("011", "r5-011-tneg-03", """import bcrypt

def save_user(user, raw_password):
    user.password = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt())""",
        "`.password` receives a bcrypt hash; no plaintext credential is stored "
        "-> Reject (benign assignment, all-alarm static hit)."),
    tneg("011", "r5-011-tneg-04", """def seed_test_user(db):
    user = db.User(username="tester")
    user.password = "test-password-123"
    return user""",
        "Test fixture seeds a fake account with a throwaway password; no real "
        "secret depends on it -> Reject (test scaffolding)."),
    tneg("011", "r5-011-tneg-05", """def register(request):
    user = User(username=request.POST["username"])
    user.password = make_password(request.POST["password"])
    user.save()""",
        "make_password() returns a KDF digest, so the 'plaintext password' "
        "finding is a static false positive -> Reject."),
    tneg("012", "r5-012-tneg-01", """from hashlib import pbkdf2_hmac

def test_derive_known_vector():
    key = pbkdf2_hmac("sha256", b"password", b"salt", 1000)
    assert key == RFC_TEST_VECTOR""",
        "Low iteration count in a unit test reproducing an RFC test vector; "
        "fast tests are the goal and no production credential is protected -> "
        "Reject (test scaffolding)."),
    tneg("012", "r5-012-tneg-02", """import hashlib

def bench_pbkdf2():
    for _ in range(1000):
        hashlib.pbkdf2_hmac("sha256", b"bench", b"salt", 1000)""",
        "Low-cost PBKDF2 in a throughput benchmark is deliberate; the output "
        "protects nothing -> Reject (benchmark, B 类)."),
    tneg("012", "r5-012-tneg-03", """import hmac
from hashlib import pbkdf2_hmac

def verify_legacy_pbkdf2(password, salt, stored_hash):
    candidate = pbkdf2_hmac("sha256", password.encode(), salt, 1000)
    return hmac.compare_digest(candidate, stored_hash)""",
        "A password library must reproduce the iterations an old stored hash "
        "was created with (1k) or verification breaks; this is the legacy-format "
        "exception, not a new weak hash -> Reject."),
    tneg("013", "r5-013-tneg-01", """def get_cached(path, content_bytes):
    expected_hash = fingerprint(content_bytes)
    if content_hash == expected_hash:
        return get_cached(path)
    return None""",
        "Digest equality is an ETag-style change-detection cache key; no "
        "credential, token or signature depends on it -> Reject (B 类, "
        "non-security purpose)."),
    tneg("013", "r5-013-tneg-02", """def dedupe_upload(blob, existing_digest):
    if blob.digest == existing_digest:
        return {"skipped": True, "id": existing_digest}
    return upload(blob)""",
        "Content-digest equality for upload dedup; timing leaks nothing "
        "security-relevant -> Reject."),
    tneg("013", "r5-013-tneg-03", """def test_token_generation():
    generated_token = make_test_token("alice")
    assert generated_token == expected_token""",
        "Unit-test assertion comparing a generated test token to an expected "
        "literal; test scaffolding only -> Reject."),
]

# =============================================================================
# TRIAGE CONFIRM -- the same known forms when they DO protect a real secret.
# =============================================================================
TRIAGE_CONFIRM = [
    tpos("011", "r5-011-tpos-01", """def register(db, form):
    user = db.User()
    user.email = form["email"]
    user.password = form["password"]
    db.add(user)
    return user""",
        "The raw registration password is persisted verbatim; anyone with DB "
        "read access gets the plaintext credential -> Confirm.",
        """def register(db, form):
    user = db.User()
    user.email = form["email"]
    user.password = hash_password(form["password"])
    db.add(user)
    return user

def hash_password(password):
    salt = os.urandom(16)
    return salt.hex() + hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()"""),
    tpos("011", "r5-011-tpos-02", """def reset_password(api, user_id, plaintext):
    user = api.users[user_id]
    user.set_password(plaintext)
    api.save(user)""",
        "set_password() stores the plaintext password without a one-way KDF -> "
        "Confirm.",
        """def reset_password(api, user_id, plaintext):
    user = api.users[user_id]
    user.password_hash = make_password(plaintext)
    api.save(user)"""),
    tpos("012", "r5-012-tpos-01", """from hashlib import pbkdf2_hmac

def hash_password(password, salt):
    return pbkdf2_hmac("sha256", password.encode(), salt, 10000)""",
        "User passwords hashed with only 10k PBKDF2 iterations; GPU brute force "
        "recovers them quickly -> Confirm.",
        """from hashlib import pbkdf2_hmac

def hash_password(password, salt):
    return pbkdf2_hmac("sha256", password.encode(), salt, 310000)"""),
    tpos("012", "r5-012-tpos-02", """import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4))""",
        "bcrypt cost 4 for real user passwords is far too fast -> Confirm.",
        """import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))"""),
    tpos("013", "r5-013-tpos-01", """def login(user, input_password):
    if user.password == input_password:
        create_session(user)
        return "ok"
    return "denied" """,
        "Live password comparison with == leaks timing and enables byte-by-byte "
        "recovery -> Confirm.",
        """import hmac

def login(user, input_password):
    if hmac.compare_digest(user.password, input_password):
        create_session(user)
        return "ok"
    return "denied" """),
    tpos("013", "r5-013-tpos-02", """def authorize(request, valid_token):
    if request.token != valid_token:
        raise PermissionDenied
    return grant(request)""",
        "An auth token compared with != leaks match-length timing -> Confirm.",
        """import secrets

def authorize(request, valid_token):
    if not secrets.compare_digest(request.token, valid_token):
        raise PermissionDenied
    return grant(request)"""),
]

# =============================================================================
# PASSlib legacy-hash implementations (11) -- triage Reject, moved into TRAINING
# from the round-4 held-out set because the round-4 model confirmed all 11.
# Real code, real findings; the library MUST reproduce these legacy formats.
# =============================================================================
PASSLIB_REJECT = []


def load_passlib_reject() -> list:
    """Re-id the 11 round-4 passlib legacy Reject records into round-5 train."""
    src = ROOT / "data" / "round4" / "real_validation" / "triage.jsonl"
    out = []
    for r in (json.loads(l) for l in src.read_text(encoding="utf-8").splitlines() if l.strip()):
        if r.get("category") != "legacy-hash-scheme":
            continue
        scheme = r["file"].split("/")[-1].removesuffix(".py")
        new = dict(r)
        import textwrap
        new["code"] = textwrap.dedent(r["code"]).strip()
        new["id"] = r["id"].replace("round4-real-", "round5-", 1)
        new["source"] = "round5-passlib-legacy"
        new["split"] = "train"
        new["family"] = "weak-hash"
        new["label"] = {
            "cwe": "", "severity": "INFO", "verdict": "Reject",
            "explanation": (
                f"passlib implements the legacy {scheme} password-hash format so "
                "existing accounts with that stored format can still be "
                "verified. Reproducing a documented legacy scheme is the "
                "library's job, not a vulnerability: no new secret is protected "
                "by the weak digest alone -> Reject."
            ),
        }
        out.append(new)
    # Provenance-driven split: 8 train / 1 val / 2 test so round-5 evaluation
    # still has held-out passlib Reject evidence (round-4 model Confirmed 11/11).
    out.sort(key=lambda r: r["file"])
    for i, r in enumerate(out):
        r["split"] = "train" if i < len(out) - 3 else ("val" if i == len(out) - 3 else "test")
    return out


# =============================================================================
# VAL / TEST additions -- fresh code, disjoint from the training snippets.
# =============================================================================
VAL_ADD = [
    pos("011", "r5-val-011-pos", """def sync_user_from_ldap(db, entry):
    user = db.get_user(entry["uid"])
    user.password = entry["userPassword"]
    db.commit()""",
        "LDAP sync writes the plaintext userPassword into the account record "
        "without a KDF -> vulnerable (CWE-256)."),
    aneg("012", "r5-val-012-aneg", """import hashlib

def hash_user_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 300_000).hex()""",
        "300k-iteration PBKDF2 (>=100k) with a random salt -> safe."),
    aneg("013", "r5-val-013-aneg", """import secrets

def verify_reset_token(stored_token, candidate):
    return secrets.compare_digest(stored_token, candidate)""",
        "Reset token verified in constant time -> safe."),
]

TEST_ADD = [
    tneg("011", "r5-test-011-tneg", """def migrate_user_password(user, legacy_digest):
    user.password = legacy_digest
    db.update(user)""",
        "Migration copies an already-derived KDF digest into the password "
        "field; the all-alarm static hit is a false positive -> Reject."),
    bneg("011", "r5-test-011-bneg", """def restore_fixture(db):
    test_user = db.create_user("alice")
    test_user.password = "test-password"
    db.save(test_user)""",
        "Test fixture seeds a throwaway password on a fake account; no real "
        "secret -> safe (test scaffolding)."),
    tneg("012", "r5-test-012-tneg", """import hashlib

def test_derive_key_matches_rfc():
    key = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1000)
    assert key == RFC_KEY_VECTOR""",
        "Unit test deriving an RFC vector with 1k iterations to stay fast; no "
        "production credential -> Reject."),
    bneg("012", "r5-test-012-bneg", """import hashlib
import time
import statistics

def measure_kdf_throughput():
    samples = []
    for _ in range(50):
        t0 = time.perf_counter()
        hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 1000)
        samples.append(time.perf_counter() - t0)
    return statistics.mean(samples)""",
        "KDF throughput benchmark with deliberately low cost; nothing "
        "security-relevant -> safe (B 类)."),
    tneg("013", "r5-test-013-tneg", """def cache_lookup(path, content_bytes, expected_digest):
    digest = sha256(content_bytes).digest()
    if digest == expected_digest:
        return get_cached(path)
    return None""",
        "Change-detection cache check on a content digest; no credential "
        "depends on it -> Reject (B 类)."),
    bneg("013", "r5-test-013-bneg", """def dedupe_archive(blob, existing_digest):
    if blob.digest == existing_digest:
        return {"skipped": True}
    return archive(blob)""",
        "Archive dedup via content-digest equality; timing leaks nothing "
        "secret -> safe (B 类)."),
]


def all_detect() -> list:
    recs = POSITIVES + A_NEGATIVES + B_NEGATIVES
    for r in VAL_ADD:
        if r["task"] == "detect":
            r["split"] = "val"
            recs.append(r)
    for r in TEST_ADD:
        if r["task"] == "detect":
            r["split"] = "test"
            recs.append(r)
    return recs


def all_triage() -> list:
    triage = TRIAGE_REJECT + TRIAGE_CONFIRM + PASSLIB_REJECT
    for r in TEST_ADD:
        if r["task"] == "triage":
            r["split"] = "test"
            triage.append(r)
    return triage


# =============================================================================
# Backtest discipline: pos fires own rule (and only it), aneg fires nothing,
# bneg fires >=1 rule (ideally own), triage: finding rule should fire on snippet
# (informational; passlib snippets may need imports, then it's just a note).
# =============================================================================
def backtest(records: list) -> dict:
    rules_dir = ROOT / "rules"
    hits = {}
    with tempfile.TemporaryDirectory(prefix="r5_bt_") as td:
        for i, r in enumerate(records):
            Path(td, f"f{i:05d}.py").write_text(r["code"], encoding="utf-8")
        proc = subprocess.run(
            ["semgrep", "--config", str(rules_dir), "--json", "--quiet", td],
            capture_output=True, text=True,
        )
        try:
            results = json.loads(proc.stdout or "{}").get("results", [])
        except json.JSONDecodeError:
            results = []
        for h in results:
            idx = int(Path(h["path"]).name[1:6])
            rule = h["check_id"].split(".")[-1]
            hits.setdefault(idx, []).append(rule)
    report = {}
    for i, r in enumerate(records):
        got = sorted(set(hits.get(i, [])))
        report[r["id"]] = {"source": r["source"], "task": r["task"],
                           "expected_rule": r.get("rule", ""), "rules_hit": got}
    return report


def backtest_ok(report: dict) -> tuple:
    bad_pos = bad_aneg = 0
    bad_pos_list = []
    multi_hit = []
    bneg_no_fire, bneg_other_rule, triage_miss = [], [], []
    for rid, v in report.items():
        src = v["source"]
        exp = v["expected_rule"]
        hit = set(v["rules_hit"])
        if src.endswith("-pos"):
            if not hit:
                bad_pos_list.append(rid)
            elif hit != {exp}:
                multi_hit.append((rid, sorted(hit)))
        elif src.endswith("-aneg"):
            if hit:
                bad_aneg += 1
        elif src.endswith("-bneg"):
            if not hit:
                bneg_no_fire.append(rid)
            elif exp in hit and len(hit) > 1:
                pass
            elif exp not in hit:
                bneg_other_rule.append((rid, sorted(hit)))
        elif v["task"] == "triage":
            if exp and exp not in hit:
                triage_miss.append((rid, sorted(hit)))
    return (bad_pos, bad_aneg, multi_hit, bneg_no_fire, bneg_other_rule,
            triage_miss, bad_pos_list)


# =============================================================================
# Emit: source files + chatml upload (full base retrain only; no incremental).
# =============================================================================
def write_jsonl(records: list, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[+] wrote {len(records)} -> {path}")


def to_chatml(records: list) -> list:
    return [{"messages": build_messages(r)} for r in records]


def _load(path: Path) -> list:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def emit_upload_sets(detect: list, triage: list) -> None:
    base_train = _load(ROOT / "data/round4/upload/full/train.jsonl")
    base_val = _load(ROOT / "data/round4/upload/full/val.jsonl")
    base_test = _load(ROOT / "data/round4/upload/full/test.jsonl")

    new_train = [r for r in detect + triage if r["split"] == "train"]
    new_val = [r for r in detect + triage if r["split"] == "val"]
    new_test = [r for r in detect + triage if r["split"] == "test"]

    # base round-4 files are ALREADY chatml -- never re-wrap them; only the new
    # v2 records go through to_chatml (base * new = double-wrap -> KeyError).
    write_jsonl(base_train + to_chatml(new_train), R5 / "upload" / "full" / "train.jsonl")
    write_jsonl(base_val + to_chatml(new_val), R5 / "upload" / "full" / "val.jsonl")
    write_jsonl(base_test + to_chatml(new_test), R5 / "upload" / "full" / "test.jsonl")

    dnew = [r for r in detect if r["split"] == "train"]
    tnew = [r for r in triage if r["split"] == "train"]
    pos_n = sum(1 for r in dnew if r["label"]["vulnerable"])
    sec_n = len(dnew) - pos_n
    print(f"\n[round5-new] detect train: pos={pos_n} secure={sec_n} triage train={len(tnew)}")
    print(f"[full] train={len(base_train)+len(new_train)} "
          f"val={len(base_val)+len(new_val)} test={len(base_test)+len(new_test)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Build round-5 known-forms dataset")
    ap.add_argument("--backtest", action="store_true")
    ap.add_argument("--emit", action="store_true")
    args = ap.parse_args()

    PASSLIB_REJECT.extend(load_passlib_reject())
    detect = all_detect()
    triage = all_triage()
    all_recs = detect + triage

    if args.backtest:
        report = backtest(all_recs)
        write_jsonl([{"id": k, **v} for k, v in report.items()],
                    R5 / "backtest_report.jsonl")
        (bad_pos, bad_aneg, multi_hit, bneg_no_fire, bneg_other, triage_miss,
         bad_pos_list) = backtest_ok(report)
        print(f"[backtest] {len(all_recs)} samples | pos-missing={bad_pos} "
              f"aneg-hit={bad_aneg} multi-rule-pos={len(multi_hit)} "
              f"bneg-no-fire={len(bneg_no_fire)} bneg-other-rule={len(bneg_other)} "
              f"triage-finding-miss={len(triage_miss)}")
        for rid in bad_pos_list:
            print(f"  [!] pos no rule fire: {rid}")
        for rid, hits in multi_hit + bneg_other + triage_miss:
            print(f"  [!] {rid}: {hits}")
        for rid in bneg_no_fire:
            print(f"  [!] bneg no rule fire: {rid}")

    if args.emit:
        write_jsonl(detect, R5 / "known_forms_detect.jsonl")
        write_jsonl(triage, R5 / "known_forms_triage.jsonl")
        emit_upload_sets(detect, triage)

    if not (args.backtest or args.emit):
        ap.print_help()
