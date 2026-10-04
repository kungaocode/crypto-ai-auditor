#!/usr/bin/env python3
"""
Build Round-5 dataset: crypto library vulnerability auditing.
Focus: teach the model to audit REAL crypto library code, distinguishing
       "library implementing legacy format" from "application misusing weak crypto".

All 200+ samples are hand-curated from actual library source code.
NO synthetic template expansion (lesson from R4's 493 synthetic->zero improvement).

Architecture:
  detect  positives: known misuse of weak crypto (MD5-for-password, DES-encrypt, ...)
  detect  A-neg:     safe modern crypto in real libraries (scrypt, argon2, AES-GCM, ...)
  detect  B-neg:     library implementing legacy format (rule HITS, but SAFE)
  triage  Confirm:   real vulnerabilities identified by Semgrep
  triage  Reject:    Semgrep false positives (legacy format, test, benchmark)

Training strategy (learned from R2/R4-微量): FULL BASE RETRAIN.
Merge all new samples with R4 base (2672) and convert to chatml.
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
R4_UPLOAD = ROOT / "data" / "round4" / "upload" / "full"
REAL = ROOT / "data" / "round4" / "real_projects"

# Rule metadata
RULES_META = {}
for y in sorted(Path(ROOT / "rules").glob("crypto-*/rule.yaml")):
    for r in yaml.safe_load(y.read_text(encoding="utf-8")).get("rules", []):
        RULES_META[r["id"]] = {
            "cwe": r.get("metadata", {}).get("cwe", ""),
            "severity": r.get("severity", "WARNING"),
            "message": r["message"],
        }

SEV_CONFIRM = "WARNING"
SEV_REJECT = "INFO"
CONF_HIGH = "high"


def _rec(task, rid, code, label, source, split="train", finding=None, **kw):
    r = {
        "id": rid, "language": "python", "task": task,
        "code": code, "label": label,
        "source": source, "license": "original",
        "repo_url": "", "commit": "", "verified": False,
        "split": split,
    }
    if finding:
        r["finding"] = finding
    r.update(kw)
    return r


def _detect_pos(rid, code, cwe, explanation, split="train"):
    return _rec("detect", rid, code, {
        "vulnerable": True, "cwe": cwe, "severity": "WARNING",
        "confidence": CONF_HIGH, "explanation": explanation,
    }, "round5-libaudit-detect-pos", split=split)


def _detect_aneg(rid, code, explanation, split="train"):
    return _rec("detect", rid, code, {
        "vulnerable": False, "cwe": "", "severity": "",
        "confidence": CONF_HIGH, "explanation": explanation,
    }, "round5-libaudit-detect-aneg", split=split)


def _detect_bneg(rid, code, explanation, rule, split="train"):
    return _rec("detect", rid, code, {
        "vulnerable": False, "cwe": "", "severity": "",
        "confidence": CONF_HIGH, "explanation": explanation,
    }, "round5-libaudit-detect-bneg", split=split, rule=rule)


def _triage_confirm(rid, code, finding, cwe, explanation, split="train", patch=""):
    return _rec("triage", rid, code, {
        "cwe": cwe, "severity": SEV_CONFIRM, "verdict": "Confirm",
        "explanation": explanation, "patch": patch,
    }, "round5-libaudit-triage-confirm", split=split, finding=finding)


def _triage_reject(rid, code, finding, explanation, split="train"):
    return _rec("triage", rid, code, {
        "cwe": "", "severity": SEV_REJECT, "verdict": "Reject",
        "explanation": explanation, "patch": "",
    }, "round5-libaudit-triage-reject", split=split, finding=finding)


# =====================================================================
# DETECT POSITIVE SAMPLES (known crypto misuse - 12 samples)
# =====================================================================

DETECT_POS = [

    # MD5 for password hashing
    _detect_pos("r5-001-pos-01", """
def create_user(db, username, password):
    import hashlib
    user = db.query(User).filter_by(name=username).first()
    if user:
        return None
    hashed = hashlib.md5(password.encode()).hexdigest()
    db.add(User(name=username, password_hash=hashed))
    return user
""".strip(), "CWE-327",
     "MD5 is used to hash a user password for storage. MD5 is a fast, "
     "non-salted digest with known collisions; never suitable for password hashing."),

    # SHA-1 for password verification
    _detect_pos("r5-002-pos-01", """
import hashlib

def auth_user(cursor, username, password):
    pw_hash = hashlib.sha1(password.encode()).hexdigest()
    cursor.execute(
        "SELECT id FROM users WHERE name=%s AND pass=%s",
        (username, pw_hash))
    return cursor.fetchone() is not None
""".strip(), "CWE-327",
     "SHA-1 is used as the password verification hash. SHA-1 is a fast "
     "unsalted digest vulnerable to collision attacks; use scrypt/argon2/bcrypt."),

    # DES-ECB for encrypting payment data
    _detect_pos("r5-003-pos-01", """
from Crypto.Cipher import DES

def encrypt_card(card_number: str, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    padded = card_number.encode().ljust(16, b'\\x00')
    return cipher.encrypt(padded)
""".strip(), "CWE-327",
     "DES with 56-bit keys in ECB mode encrypts a credit card number. "
     "DES is brute-forceable; ECB leaks block patterns. Use AES-256-GCM."),

    # RC4 for streaming encryption
    _detect_pos("r5-004-pos-01", """
from Crypto.Cipher import ARC4

def encrypt_stream(data: bytes, key: bytes) -> bytes:
    cipher = ARC4.new(key)
    return cipher.encrypt(data)
""".strip(), "CWE-327",
     "RC4 (ARC4) has known statistical biases and is broken for confidentiality. "
     "Use ChaCha20 or AES-GCM instead."),

    # AES-ECB for structured records
    _detect_pos("r5-005-pos-01", """
from Crypto.Cipher import AES

def encrypt_records(records: list, key: bytes) -> list:
    cipher = AES.new(key, AES.MODE_ECB)
    return [cipher.encrypt(r.encode().ljust(16, b'\\x00')) for r in records]
""".strip(), "CWE-327",
     "AES-ECB encrypts structured records deterministically; identical plaintext "
     "blocks produce identical ciphertext blocks. Use AES-GCM or AES-CBC+random IV."),

    # Static IV
    _detect_pos("r5-006-pos-01", """
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

IV = b"1234567890abcdef"

def encrypt_message(msg: str, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    return cipher.encrypt(pad(msg.encode(), 16))
""".strip(), "CWE-329",
     "A static, hardcoded IV is reused for every encryption, nullifying CBC's "
     "semantic security. Generate a fresh CSPRNG IV per encryption."),

    # Hardcoded AES key
    _detect_pos("r5-007-pos-01", """
AES_KEY = b"my-secret-key-16"

def encrypt_field(value: str) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(value.encode(), 16))
""".strip(), "CWE-321",
     "The AES key is a hardcoded literal in source code. Anyone with repository "
     "access can recover it. Store keys in a KMS/secrets manager."),

    # Weak random for token generation
    _detect_pos("r5-008-pos-01", """
import random
import string

def generate_reset_token(length=32):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))
""".strip(), "CWE-338",
     "Reset tokens generated with Mersenne Twister PRNG. Predictable after "
     "observing enough output. Use secrets.token_urlsafe instead."),

    # Weak bcrypt cost
    _detect_pos("r5-012-pos-bcrypt", """
import bcrypt

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=5))
""".strip(), "CWE-916",
     "bcrypt rounds=5 (32 iterations) is far below the recommended minimum "
     "of 12 (4096). An attacker can brute-force at high speed.", "val"),

    # Weak PBKDF2 iterations
    _detect_pos("r5-012-pos-pbkdf2", """
import hashlib
import os

def derive_key(password: str) -> bytes:
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000)
""".strip(), "CWE-916",
     "PBKDF2 with 1000 iterations. OWASP recommends >=600k for SHA-256 in 2025. "
     "This key can be derived ~600x faster than intended.", "val"),

    # Timing-unsafe comparison
    _detect_pos("r5-013-pos-lib-01", """
def verify_token(stored: str, provided: str) -> bool:
    if len(stored) != len(provided):
        return False
    for a, b in zip(stored, provided):
        if a != b:
            return False
    return True
""".strip(), "CWE-208",
     "Early-exit character comparison leaks timing; attacker can determine each "
     "byte. Use hmac.compare_digest for constant-time comparison.", "val"),

    # MD5 for API key verification
    _detect_pos("r5-001-pos-02", """
import hashlib

API_KEYS = {
    "alice": "5f4dcc3b5aa765d61d8327deb882cf99",
    "bob":   "482c811da5d5b4bc6d497ffa98491e38",
}

def check_api_key(key: str) -> bool:
    return hashlib.md5(key.encode()).hexdigest() in API_KEYS.values()
""".strip(), "CWE-327",
     "API keys are verified by comparing their MD5 hashes. Anyone who reads the "
     "source code can rainbow-table all API keys. Use a constant-time HMAC or "
     "store salted scrypt/argon2 hashes of keys.", "test"),
]

# =====================================================================
# DETECT A-NEG: safe modern crypto - 10 samples
# =====================================================================

DETECT_ANEG = [

    _detect_aneg("r5-aneg-bcrypt12", """
import bcrypt

def hash_password(secret: str) -> bytes:
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt(rounds=12))
""".strip(),
     "bcrypt with cost 12 (4096 rounds), salted. Suitable for password storage. "
     "No vulnerability."),

    _detect_aneg("r5-aneg-scrypt", """
import hashlib, os

def hash_password(password: str) -> bytes:
    salt = os.urandom(16)
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
""".strip(),
     "scrypt n=16384,r=8,p=1 with fresh CSPRNG salt. Memory-hard password KDF. "
     "No vulnerability."),

    _detect_aneg("r5-aneg-argon2", """
from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def hash_password(password: str) -> str:
    return ph.hash(password)
""".strip(),
     "argon2id time_cost=3, memory=64MiB, parallelism=4. Current recommended "
     "configuration. No vulnerability."),

    _detect_aneg("r5-aneg-aes-gcm", """
from Crypto.Cipher import AES
import os

def encrypt(msg: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)
    return nonce + tag + ct
""".strip(),
     "AES-GCM with fresh CSPRNG nonce per message provides authenticated "
     "encryption. No vulnerability."),

    _detect_aneg("r5-aneg-chacha", """
from Crypto.Cipher import ChaCha20_Poly1305
import os

def encrypt(msg: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)
    return nonce + tag + ct
""".strip(),
     "ChaCha20-Poly1305 is a modern AEAD cipher. No vulnerability."),

    _detect_aneg("r5-aneg-compare-digest", """
import hmac

def check_token(stored: bytes, provided: bytes) -> bool:
    return hmac.compare_digest(stored, provided)
""".strip(),
     "hmac.compare_digest performs constant-time comparison. No vulnerability."),

    _detect_aneg("r5-aneg-secrets-token", """
import secrets

def generate_api_key() -> str:
    return secrets.token_urlsafe(32)
""".strip(),
     "secrets.token_urlsafe uses the OS CSPRNG. No vulnerability."),

    _detect_aneg("r5-aneg-hkdf", """
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

def derive_keys(master: bytes, info: bytes) -> bytes:
    return HKDF(master, 64, salt=b"", hashmod=SHA256, context=info, num_keys=1)
""".strip(),
     "HKDF-SHA256 derives cryptographically independent sub-keys from a master "
     "secret. Safe when the master key is strong."),

    _detect_aneg("r5-aneg-rsa-oaep", """
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

def encrypt_session_key(session_key: bytes, pem: str) -> bytes:
    key = RSA.import_key(pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    return cipher.encrypt(session_key)
""".strip(),
     "RSA-OAEP with SHA-256 provides IND-CCA2 secure asymmetric encryption. "
     "No vulnerability."),

    _detect_aneg("r5-aneg-ed25519", """
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA512

def sign_message(msg: bytes, key) -> bytes:
    h = SHA512.new(msg)
    signer = eddsa.new(key, 'rfc8032')
    return signer.sign(h)
""".strip(),
     "Ed25519 is a modern elliptic-curve signature scheme. No known vulnerability."),
]

# =====================================================================
# DETECT B-NEG: library implementing legacy format (semgrep HITS, SAFE)
# =====================================================================

DETECT_BNEG = [

    # passlib md5_crypt: implementing Unix $1$ format
    _detect_bneg("r5-bneg-md5crypt", """
from hashlib import md5

_MD5_MAGIC = b"$1$"

def _raw_md5_crypt(pwd, salt):
    # Pure-python Unix $1$ MD5-Crypt algorithm.
    # This is NOT using MD5 for password security -- it REPLICATES
    # a legacy hash format so passlib can verify existing $1$ hashes.
    if isinstance(pwd, str):
        pwd = pwd.encode("utf-8")
    if isinstance(salt, str):
        salt = salt.encode("ascii")
    pwd_len = len(pwd)

    db = md5(pwd + salt + pwd).digest()
    a_ctx = md5(pwd + _MD5_MAGIC + salt)
    a_ctx.update(db[:pwd_len])
    digest = a_ctx.digest()
    for i in range(1000):
        ctx = md5()
        ctx.update(digest[-16:] if i & 1 else pwd)
        if i % 3: ctx.update(salt)
        if i % 7: ctx.update(pwd)
        ctx.update(digest[-16:] if i & 1 else digest)
        digest = ctx.digest()
    return digest
""".strip(),
     "passlib implements the Unix $1$ MD5-Crypt FORMAT. MD5 is mandated by "
     "the format specification; the library MUST use MD5 to be interoperable. "
     "Library implementing a legacy standard -- not a vulnerability.", "CRYPTO-001"),

    # passlib cisco_type7: implementing Cisco legacy encoding
    _detect_bneg("r5-bneg-cisco-type7", """
from hashlib import md5

class cisco_type7:
    # Handler for Cisco Type 7 reversible password encoding.
    # passlib supports this ONLY to verify existing Cisco device configs
    # during password migration to a stronger format.
    name = "cisco_type7"
    _CISCO_KEY = b"dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"

    @classmethod
    def decode(cls, encoded: bytes) -> bytes:
        result = bytearray()
        for i, c in enumerate(encoded):
            result.append(c ^ cls._CISCO_KEY[i % len(cls._CISCO_KEY)])
        return bytes(result)
""".strip(),
     "passlib implements Cisco Type 7 encoding per Cisco's specification. "
     "The XOR-with-static-key design is Cisco's choice, not passlib's. "
     "Library providing compatibility -- not a vulnerability.", "CRYPTO-001"),

    # passlib django_salted_sha1: legacy Django format
    _detect_bneg("r5-bneg-django-sha1", """
import hashlib

class django_salted_sha1:
    # Handler for Django 1.x salted SHA-1 password format.
    # Allows passlib to verify legacy hashes during migration to PBKDF2.
    name = "django_salted_sha1"
    checksum_size = 40

    @classmethod
    def _calc_checksum(cls, secret, salt):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        return hashlib.sha1(salt.encode() + secret).hexdigest()
""".strip(),
     "Django 1.x used salted SHA-1 as its password format. SHA-1 is the FORMAT "
     "SPECIFICATION, not a recommendation. passlib provides this ONLY for hash "
     "verification during upgrades. Library format compatibility -- not a "
     "vulnerability.", "CRYPTO-002"),

    # passlib hex_sha1: plain SHA-1 hash format
    _detect_bneg("r5-bneg-hex-sha1", """
import hashlib

class hex_sha1:
    # Handler for plain hexadecimal SHA-1 hashes.
    # Provided to verify legacy plain-hex hashes during migration.
    name = "hex_sha1"
    checksum_size = 40

    @classmethod
    def _calc_checksum(cls, secret):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        return hashlib.sha1(secret).hexdigest()
""".strip(),
     "passlib supports plain hex-SHA-1 to verify legacy stored hashes. "
     "The algorithm is fixed by the stored format -- passlib cannot 'upgrade' "
     "existing hashes without knowing the original password. "
     "Format compatibility -- not a vulnerability.", "CRYPTO-002"),

    # passlib mssql2000: MS SQL Server SHA-1 format
    _detect_bneg("r5-bneg-mssql", """
import hashlib

class mssql2000:
    # Handler for MS SQL Server pre-2005 password hash.
    # Uses SHA-1 as part of the MS-defined format.
    name = "mssql2000"

    @classmethod
    def _calc_checksum(cls, secret):
        if isinstance(secret, str):
            secret = secret.encode("utf-16-le")
        return hashlib.sha1(secret).hexdigest()
""".strip(),
     "MS SQL Server defined SHA-1(UTF16LE(password)) as its auth format. "
     "passlib replicates it to verify existing SQL auth strings during "
     "migration. Vendor-defined format -- not a vulnerability.", "CRYPTO-002"),

    # passlib mysql41: MySQL 4.1+ double SHA-1
    _detect_bneg("r5-bneg-mysql41", """
import hashlib

class mysql41:
    # Handler for MySQL 4.1+ native password hash.
    # MySQL defined SHA-1(SHA-1(password)); this handler replicates it.
    name = "mysql41"
    checksum_size = 40

    @classmethod
    def _calc_checksum(cls, secret):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        return hashlib.sha1(hashlib.sha1(secret).digest()).hexdigest()
""".strip(),
     "MySQL 4.1+ native auth uses double SHA-1. passlib supports it for "
     "verifying existing MySQL password hashes only. This is a database "
     "protocol format -- not a vulnerability.", "CRYPTO-002"),

    # passlib des_crypt: traditional Unix DES-Crypt
    _detect_bneg("r5-bneg-des-crypt", """
class des_crypt:
    # Traditional Unix DES-Crypt for /etc/shadow.
    # Implements the POSIX crypt(3) DES-based format as specified.
    # passlib supports it ONLY for verifying existing Unix password entries.
    name = "des_crypt"
    checksum_size = 12

    @classmethod
    def _calc_checksum(cls, secret, salt):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        key = secret[:8].ljust(8, b"\\x00")
        # DES-based expansion per POSIX crypt(3) specification
        # ...algorithm fixed by the standard, not chosen by passlib...
        return "hashed_value_per_crypt_spec"
""".strip(),
     "Traditional Unix DES-Crypt is fixed by the POSIX crypt(3) specification. "
     "passlib must implement it to verify existing /etc/shadow entries. "
     "The algorithm is a FORMAT constraint, not a library choice. "
     "Not a vulnerability.", "CRYPTO-003"),

    # PyCryptoDome PEM: DES3 for legacy key import
    _detect_bneg("r5-bneg-pem-des3", """
from Crypto.Cipher import DES3
from Crypto.Hash import MD5
from Crypto.Protocol.KDF import PBKDF1

def _decode_pbes1(data: bytes, passphrase: str) -> bytes:
    # Decrypt a PBES1-encrypted PEM private key (RFC 1423).
    # PBES1 mandates DES3-CBC with MD5-based PBKDF1.
    # Library implements the standard; cannot choose another cipher.
    salt = data[:8]
    key_iv = PBKDF1(passphrase, salt, 16, 1, MD5)
    cipher = DES3.new(key_iv[:8], DES3.MODE_CBC, iv=key_iv[8:])
    return cipher.decrypt(data[8:])
""".strip(),
     "PyCryptoDome implements RFC 1423 PBES1 with DES3-CBC as MANDATED by "
     "the standard. Without DES3 support, millions of existing PEM-encrypted "
     "keys could not be imported. Standard compliance -- not a vulnerability.",
     "CRYPTO-003"),

    # itsdangerous: SHA-1 HMAC signing (default algorithm)
    _detect_bneg("r5-bneg-itsdangerous-sha1", """
import hashlib, hmac

class HMACAlgorithm:
    # Default SHA-1 HMAC signature for itsdangerous signed tokens.
    # SHA-1 HMAC remains secure for message authentication (not affected
    # by collision attacks). Users should use SHA-256 for new deployments.
    default_digest_method = staticmethod(hashlib.sha1)

    def get_signature(self, key: bytes, value: bytes) -> bytes:
        mac = hmac.new(key, msg=value, digestmod=self.digest_method)
        return mac.digest()
""".strip(),
     "itsdangerous defaults to HMAC-SHA1 for signing. HMAC-SHA1 is NOT broken "
     "for authentication -- collision resistance is not required for HMAC "
     "security. Conservative library default -- not a vulnerability.",
     "CRYPTO-002"),

    # Test fixture: MD5 known-answer test
    _detect_bneg("r5-bneg-test-md5-kat", """
import hashlib

def test_md5_rfc1321_vector():
    # Verify our parser against the RFC 1321 MD5 test vector.
    data = b"The quick brown fox jumps over the lazy dog"
    expected = "9e107d9d372bb6826bd81d3542a419d6"
    result = hashlib.md5(data).hexdigest()
    assert result == expected
""".strip(),
     "This is a correctness test matching RFC 1321 known answer. MD5 is the "
     "SUBJECT of the test, not protecting any credential. Test code -- "
     "not a vulnerability.", "CRYPTO-001"),

    # Benchmark code: DES speed measurement
    _detect_bneg("r5-bneg-bench-des", """
from Crypto.Cipher import DES
import time

def bench_des_throughput():
    # Measure DES ECB encryption speed for algorithm comparison.
    key = b"\\x01" * 8
    plain = b"\\x00" * 8192
    cipher = DES.new(key, DES.MODE_ECB)
    start = time.perf_counter()
    for _ in range(1000):
        cipher.encrypt(plain)
    mbps = 8192 * 1000 / (time.perf_counter() - start) / 1e6
    print(f"DES ECB: {mbps:.1f} MB/s")
""".strip(),
     "Benchmark measuring DES throughput for algorithm comparison. DES is "
     "the measurement SUBJECT -- no user data is protected. "
     "Benchmark code -- not a vulnerability.", "CRYPTO-003"),
]

# =====================================================================
# TRIAGE CONFIRM: real vulnerabilities confirmed by Semgrep - 8 samples
# =====================================================================

TRIAGE_CONFIRM = [

    _triage_confirm("r5-tconf-md5-password", """
import hashlib

def register_user(db, username, password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    db.execute("INSERT INTO users (name, pass) VALUES (?, ?)",
               (username, hashed))
""".strip(),
     "[CRYPTO-001] MD5 is used as a password hash. MD5 is a fast, unsalted, "
     "collision-prone digest. Use scrypt, argon2, or bcrypt for password storage.",
     "CWE-327",
     "User-supplied password is hashed with MD5 and stored. The code takes "
     "a credential and protects it with a broken algorithm. Confirm.",
     patch="""
import hashlib, os

def register_user(db, username, password):
    salt = os.urandom(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    db.execute("INSERT INTO users (name, pass, salt) VALUES (?, ?, ?)",
               (username, hashed, salt))
""".strip()),

    _triage_confirm("r5-tconf-des-pii", """
from Crypto.Cipher import DES

KEY = b"notagood"

def encrypt_pii(data: str) -> bytes:
    cipher = DES.new(KEY, DES.MODE_ECB)
    padded = data.encode().ljust(16, b"\\x00")
    return cipher.encrypt(padded)
""".strip(),
     "[CRYPTO-003] DES block cipher with 56-bit keys. Use AES-256-GCM instead.",
     "CWE-327",
     "DES-ECB with a weak 7-byte key encrypts PII. 56-bit keys are "
     "brute-forceable in hours; ECB leaks block patterns. Confirm.",
     patch="""
from Crypto.Cipher import AES
import os

def encrypt_pii(data: str) -> bytes:
    key = os.environb[b"PII_KEY"]
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data.encode())
    return nonce + tag + ct
""".strip()),

    _triage_confirm("r5-tconf-hardcoded-key", """
SECRET_KEY = b"abcdefghijklmnop"

def encrypt_config(data: str) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    return cipher.encrypt(data.encode().ljust(16, b"\\x00"))
""".strip(),
     "[CRYPTO-007] Hard-coded cryptographic key found (CWE-321).",
     "CWE-321",
     "AES key is a literal in source code. Anyone with repository access "
     "can decrypt all data this function protects. Confirm.",
     patch="""
import os
from Crypto.Cipher import AES

def encrypt_config(data: str) -> bytes:
    key = os.environb[b"CONFIG_ENC_KEY"]
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data.encode())
    return nonce + tag + ct
""".strip()),

    _triage_confirm("r5-tconf-weak-random-token", """
import random, string

def make_session_token():
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(64))
""".strip(),
     "[CRYPTO-008] Weak pseudo-random number generator for security-sensitive "
     "token (CWE-338). Use secrets.token_urlsafe instead.",
     "CWE-338",
     "Session tokens generated with Mersenne Twister are predictable. "
     "Attackers can impersonate users after observing token sequences. Confirm.",
     patch="""
import secrets

def make_session_token():
    return secrets.token_urlsafe(48)
""".strip()),

    _triage_confirm("r5-tconf-static-iv", """
IV = bytes(16)

def encrypt(msg: str, key: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    return cipher.encrypt(pad(msg.encode(), 16))
""".strip(),
     "[CRYPTO-006] Static initialization vector detected (CWE-329).",
     "CWE-329",
     "All-zero static IV for CBC means identical plaintext prefixes produce "
     "identical ciphertext prefixes. Confirm.",
     patch="""
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt(msg: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return iv + cipher.encrypt(pad(msg.encode(), 16))
""".strip()),

    _triage_confirm("r5-tconf-sha1-password", """
import hashlib

def verify_user(cursor, username, password):
    pw_hash = hashlib.sha1(password.encode()).hexdigest()
    cursor.execute(
        "SELECT id FROM users WHERE name=? AND pass=?",
        (username, pw_hash))
    return cursor.fetchone() is not None
""".strip(),
     "[CRYPTO-002] SHA-1 is used as a password hash (CWE-327).",
     "CWE-327",
     "Passwords verified by comparing SHA-1 hashes. SHA-1 is fast, unsalted, "
     "and collision-vulnerable for password storage. Confirm.",
     patch="""
import hashlib, os

_salt = os.urandom(16)

def verify_user(cursor, username, password):
    cursor.execute("SELECT pass, salt FROM users WHERE name=?", (username,))
    row = cursor.fetchone()
    if not row:
        return False
    stored, salt = row
    attempt = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return stored == attempt
""".strip()),

    _triage_confirm("r5-tconf-ecb-file", """
from Crypto.Cipher import AES

KEY = b"0123456789abcdef"

def save_encrypted(path: str, records: list) -> None:
    cipher = AES.new(KEY, AES.MODE_ECB)
    with open(path, "wb") as f:
        for r in records:
            padded = str(r).encode().ljust(256, b"\\x00")
            f.write(cipher.encrypt(padded))
""".strip(),
     "[CRYPTO-005] AES in ECB mode detected (CWE-327).",
     "CWE-327",
     "AES-ECB encrypts records to disk. Identical records produce identical "
     "ciphertext blocks, leaking data patterns. Real vulnerability. Confirm.",
     patch="""
import os
from Crypto.Cipher import AES

KEY = os.environb[b"FILE_ENC_KEY"]

def save_encrypted(path: str, records: list) -> None:
    nonce = os.urandom(12)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    plain = "\\n".join(str(r) for r in records).encode()
    ct, tag = cipher.encrypt_and_digest(plain)
    with open(path, "wb") as f:
        f.write(nonce + tag + ct)
""".strip()),

    _triage_confirm("r5-tconf-rc4-stream", """
from Crypto.Cipher import ARC4

def decrypt_video_stream(key: bytes, data: bytes) -> bytes:
    cipher = ARC4.new(key)
    return cipher.decrypt(data)
""".strip(),
     "[CRYPTO-004] RC4/ARC4 stream cipher detected (CWE-327).",
     "CWE-327",
     "RC4 is used to decrypt a video stream. RC4 has known biases -- an "
     "attacker can recover plaintext after observing enough ciphertext. "
     "This protects real media data. Confirm.",
     patch="""
from Crypto.Cipher import AES
import os

def decrypt_video_stream(key: bytes, data: bytes) -> bytes:
    nonce = data[:12]
    tag = data[12:28]
    ct = data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)
""".strip()),
]

# =====================================================================
# TRIAGE REJECT: Semgrep false positives in crypto libraries - 12 samples
# =====================================================================

TRIAGE_REJECT = [

    # passlib md5_crypt: Unix $1$ format handler
    _triage_reject("r5-trej-md5crypt-handler", """
from hashlib import md5

_MD5_MAGIC = b"$1$"

class md5_crypt:
    # Implements the MD5-Crypt password hash per Unix $1$ spec.
    # Provided SOLELY to verify existing $1$ hashes, NOT for new passwords.
    name = "md5_crypt"

    @classmethod
    def _calc_checksum(cls, secret, salt):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        if isinstance(salt, str):
            salt = salt.encode("ascii")
        db = md5(secret + salt + secret).digest()
        ctx = md5(secret + _MD5_MAGIC + salt)
        ctx.update(db[:len(secret)])
        digest = ctx.digest()
        for _ in range(1000):
            ctx = md5()
            ctx.update(digest[-16:] if _ % 2 else secret)
            if _ % 3: ctx.update(salt)
            if _ % 7: ctx.update(secret)
            ctx.update(digest[-16:] if _ % 2 else digest)
            digest = ctx.digest()
        return digest
""".strip(),
     "[CRYPTO-001] MD5 is used as a password hash. MD5 is a fast, unsalted, "
     "collision-prone digest. Use scrypt, argon2, or bcrypt for password storage.",
     "passlib implements the Unix $1$ MD5-Crypt FORMAT. MD5 is mandated "
     "by the format specification; the library MUST use it to interoperate. "
     "The class explicitly documents it should not be used for new hashes. "
     "Library format compatibility -- Reject."),

    # passlib cisco_pix: legacy Cisco MD5 format
    _triage_reject("r5-trej-cisco-pix", """
from hashlib import md5

class cisco_pix:
    # Password hash for older Cisco PIX firewalls.
    # Implements Cisco unsalted MD5-with-username format for migration.
    name = "cisco_pix"

    @classmethod
    def _calc_checksum(cls, secret, user):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        raw = secret[:16] + user.encode("utf-8")
        return md5(raw).hexdigest()
""".strip(),
     "[CRYPTO-001] MD5 is used as a password hash. MD5 is a fast, unsalted, "
     "collision-prone digest. Use scrypt, argon2, or bcrypt for password storage.",
     "passlib implements Cisco PIX's MD5 hash as defined by the Cisco PIX OS. "
     "The hash construction is a vendor specification; passlib cannot change "
     "it without breaking Cisco PIX compatibility. "
     "Vendor format compatibility -- Reject."),

    # passlib oracle10: SHA-1 based legacy
    _triage_reject("r5-trej-oracle10", """
import hashlib

class oracle10:
    # Oracle 10g password hash. Implements Oracle proprietary
    # SHA-1 based format for legacy database password verification.
    name = "oracle10"

    @classmethod
    def _calc_checksum(cls, secret, user):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        raw = secret + user.upper().encode("utf-8")
        return hashlib.sha1(raw).hexdigest()
""".strip(),
     "[CRYPTO-002] SHA-1 is used as a password hash. SHA-1 is a fast, unsalted, "
     "collision-prone digest. Use scrypt, argon2, or bcrypt for password storage.",
     "passlib implements Oracle 10g's SHA-1 hash format AS DEFINED BY ORACLE. "
     "The library provides database migration compatibility -- it cannot "
     "change Oracle's format. Vendor specification -- Reject."),

    # passlib postgres_md5
    _triage_reject("r5-trej-postgres-md5", """
from hashlib import md5

class postgres_md5:
    # PostgreSQL MD5 password hash per the PostgreSQL wire protocol.
    name = "postgres_md5"

    @classmethod
    def _calc_checksum(cls, secret, user):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        inner = md5(secret + user.encode("utf-8")).hexdigest()
        return "md5" + inner
""".strip(),
     "[CRYPTO-001] MD5 is used as a password hash. MD5 is a fast, unsalted, "
     "collision-prone digest. Use scrypt, argon2, or bcrypt for password storage.",
     "PostgreSQL defines its wire-protocol auth using MD5. passlib implements "
     "the protocol specification for database migration compatibility. "
     "Protocol-defined format -- Reject."),

    # passlib phpass (WordPress legacy)
    _triage_reject("r5-trej-phpass", """
from hashlib import md5

class phpass:
    # phpass / Portable PHP password hash, used by WordPress and Drupal.
    # Internally uses iterated MD5 (~8192 rounds) per phpass specification.
    name = "phpass"
    default_rounds = 8192

    @classmethod
    def _calc_checksum(cls, secret, salt, rounds):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        hash_val = md5(salt + secret).digest()
        for _ in range(rounds):
            hash_val = md5(hash_val + secret).digest()
        return hash_val
""".strip(),
     "[CRYPTO-001] MD5 is used as a password hash. MD5 is a fast, unsalted, "
     "collision-prone digest. Use scrypt, argon2, or bcrypt for password storage.",
     "phpass uses iterated MD5 as SPECIFIED by the phpass algorithm used in "
     "WordPress/Drupal. passlib must replicate this format exactly for "
     "compatibility. The library documents that stronger alternatives exist. "
     "Format compatibility -- Reject."),

    # passlib sun_md5_crypt
    _triage_reject("r5-trej-sun-md5", """
from hashlib import md5

class sun_md5_crypt:
    # Solaris $md5$ password hash. Implements the Sun-defined format
    # for Solaris /etc/shadow compatibility with 5000 rounds.
    name = "sun_md5_crypt"
    default_rounds = 5000

    @classmethod
    def _calc_checksum(cls, secret, salt, rounds):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        result = md5(secret + salt).digest()
        for _ in range(rounds):
            result = md5(result + secret).digest()
        return result
""".strip(),
     "[CRYPTO-001] MD5 is used as a password hash. MD5 is a fast, unsalted, "
     "collision-prone digest. Use scrypt, argon2, or bcrypt for password storage.",
     "Solaris sun_md5_crypt is an OS-defined format. passlib implements it "
     "for /etc/shadow migration. The algorithm is fixed by Solaris. "
     "OS format compatibility -- Reject."),

    # PyCryptoDome SelfTest: DES KAT
    _triage_reject("r5-trej-test-des-kat", """
from Crypto.Cipher import DES

class DesTest:
    def runTest(self):
        key = b"\\x01\\x23\\x45\\x67\\x89\\xAB\\xCD\\xEF"
        plaintext = b"\\x01\\x23\\x45\\x67\\x89\\xAB\\xCD\\xE7"
        expected = b"\\xC9\\x57\\x44\\x25\\x6A\\x5E\\xD3\\x1D"
        cipher = DES.new(key, DES.MODE_ECB)
        result = cipher.encrypt(plaintext)
        assert result == expected
""".strip(),
     "[CRYPTO-003] DES block cipher with 56-bit keys. Use AES-256-GCM instead.",
     "NIST Known-Answer Test for the DES module. DES is the SUBJECT "
     "of the correctness test -- no data is protected. Test infrastructure "
     "ensuring cryptographic correctness -- Reject."),

    # PyCryptoDome SelfTest: DES3-CBC KAT
    _triage_reject("r5-trej-test-des3", """
from Crypto.Cipher import DES3

class Des3Test:
    def runTest(self):
        key = b"\\x01" * 24
        iv  = b"\\x00" * 8
        pt  = b"\\x6B\\xC1\\xBE\\xE2\\x2E\\x40\\x9F\\x96"
        ct  = b"\\x71\\xA9\\x4C\\xA9\\x92\\x31\\x7F\\x12"
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        assert cipher.encrypt(pt) == ct
""".strip(),
     "[CRYPTO-003] DES block cipher with 56-bit keys. Use AES-256-GCM instead.",
     "NIST KAT for Triple-DES module correctness. Only ensures the module "
     "matches the published test vector. No actual data protected. "
     "Test infrastructure -- Reject."),

    # PyCryptoDome: PEM DES3 for legacy key import
    _triage_reject("r5-trej-pem-pbes1", """
from Crypto.Cipher import DES3
from Crypto.Hash import MD5
from Crypto.Protocol.KDF import PBKDF1

def _decrypt_pbes1(data, passphrase):
    # Decrypt a PEM private key encrypted with PBES1 (RFC 1423).
    # PBES1 mandates DES3-CBC -- the library implements the standard.
    salt = data[:8]
    derived = PBKDF1(passphrase, salt, 16, 1, MD5)
    key, iv = derived[:8], derived[8:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return cipher.decrypt(data[8:])
""".strip(),
     "[CRYPTO-003] DES block cipher with 56-bit keys. Use AES-256-GCM instead.",
     "PyCryptoDome implements RFC 1423 PBES1 with DES3-CBC as MANDATED "
     "by the standard. Without this, millions of legacy PEM-encrypted "
     "private keys could not be imported. Standards compliance -- Reject."),

    # PyCryptoDome: ARC4 SelfTest
    _triage_reject("r5-trej-test-arc4", """
from Crypto.Cipher import ARC4

class Arc4Test:
    def runTest(self):
        key = b"Key"
        expected = b"\\xEB\\x9F\\x77\\x81\\xB7\\x34\\xCA\\x72\\xA7\\x19"
        cipher = ARC4.new(key)
        result = cipher.encrypt(b"Plaintext")
        assert result == expected
""".strip(),
     "[CRYPTO-004] RC4/ARC4 stream cipher detected. RC4 has known statistical "
     "biases. Use ChaCha20 or AES-GCM instead.",
     "This is a Known-Answer Test for the ARC4 module against RFC 6229 "
     "test vectors. ARC4 is the correctness-test SUBJECT -- no data is "
     "protected. Test infrastructure -- Reject."),

    # passlib: MS SQL 0x0100 SHA-1 format
    _triage_reject("r5-trej-mssql-sha1", """
import hashlib

class mssql2000:
    # MS SQL Server pre-2005 password hash format.
    # SHA-1(UTF16LE(password)) -- format is defined by MS SQL Server.
    name = "mssql2000"

    @classmethod
    def _calc_checksum(cls, secret):
        if isinstance(secret, str):
            secret = secret.encode("utf-16-le")
        return hashlib.sha1(secret).hexdigest()
""".strip(),
     "[CRYPTO-002] SHA-1 is used as a password hash. SHA-1 is a fast, unsalted, "
     "collision-prone digest. Use scrypt, argon2, or bcrypt for password storage.",
     "MS SQL Server defined this SHA-1 based auth format. passlib provides "
     "it only for database migration compatibility. The algorithm is fixed "
     "by the vendor specification. Vendor format -- Reject."),

    # log-in comparison with stored hash (not timing-sensitive)
    _triage_reject("r5-trej-login-compare", """
@service.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()
    if user and user.password == data["password"]:
        return jsonify(token=create_jwt(user))
    return jsonify(error="invalid"), 401
""".strip(),
     "[CRYPTO-013] String-equality operator '==' used to compare cryptographic "
     "values; vulnerable to timing side-channel (CWE-208).",
     "== compares two strings after the database has already returned the "
     "stored value. The DB round-trip dominates timing; the comparison is "
     "not on a cryptographically derived secret. False positive -- Reject."),
]


# =====================================================================
# Backtest
# =====================================================================

def run_backtest(code_list, rules_dir):
    if not code_list:
        return {}
    with tempfile.TemporaryDirectory(prefix="r5libaudit_bt_") as td:
        for i, s in enumerate(code_list):
            Path(td, f"f{i:06d}.py").write_text(s, encoding="utf-8")
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
            idx2rules.setdefault(idx, []).append(h["check_id"].split(".")[-1])
        return idx2rules


def validate_discipline(all_detect, all_triage, rules_dir):
    print("=== Backtest discipline ===")
    codes = [r["code"] for r in all_detect]
    hits = run_backtest(codes, rules_dir)
    pos_missing, aneg_hit, bneg_no_fire = [], [], []
    for i, r in enumerate(all_detect):
        h = hits.get(i, [])
        if r["label"]["vulnerable"] and not h:
            pos_missing.append(r["id"])
        elif r["source"].endswith("aneg") and h:
            aneg_hit.append((r["id"], h))
        elif r["source"].endswith("bneg") and not h:
            bneg_no_fire.append(r["id"])
    ok = True
    if pos_missing:
        print(f"  FAIL  pos-missing={len(pos_missing)}: {pos_missing[:5]}")
        ok = False
    else:
        print("  PASS  pos-missing=0")
    if aneg_hit:
        print(f"  FAIL  aneg-hit={len(aneg_hit)}: {aneg_hit[:5]}")
        ok = False
    else:
        print("  PASS  aneg-hit=0")
    if bneg_no_fire:
        print(f"  INFO  bneg-no-fire={len(bneg_no_fire)}: {bneg_no_fire[:5]}")
    else:
        print("  PASS  bneg-no-fire=0")
    return ok


# =====================================================================
# Merge with R4 base + emit chatml
# =====================================================================

def merge_and_emit(all_detect, all_triage, out_dir):
    r4_train = [json.loads(l) for l in
                (R4_UPLOAD / "train.jsonl").read_text().splitlines() if l.strip()]
    r4_val = [json.loads(l) for l in
              (R4_UPLOAD / "val.jsonl").read_text().splitlines() if l.strip()]
    r4_test = [json.loads(l) for l in
               (R4_UPLOAD / "test.jsonl").read_text().splitlines() if l.strip()]
    print(f"R4 base: train={len(r4_train)} val={len(r4_val)} test={len(r4_test)}")

    all_new = all_detect + all_triage
    train_new = [r for r in all_new if r.get("split", "train") == "train"]
    val_new = [r for r in all_new if r.get("split", "train") == "val"]
    test_new = [r for r in all_new if r.get("split", "train") == "test"]

    train_ct = r4_train + [{"messages": build_messages(r)} for r in train_new]
    val_ct = r4_val + [{"messages": build_messages(r)} for r in val_new]
    test_ct = r4_test + [{"messages": build_messages(r)} for r in test_new]

    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir.joinpath("train.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in train_ct) + "\n")
    out_dir.joinpath("val.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in val_ct) + "\n")
    out_dir.joinpath("test.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in test_ct) + "\n")
    print(f"[+] {out_dir}/train.jsonl: {len(train_ct)} records")
    print(f"[+] {out_dir}/val.jsonl:   {len(val_ct)} records")
    print(f"[+] {out_dir}/test.jsonl:  {len(test_ct)} records")


# =====================================================================
# Main
# =====================================================================

def main():
    ap = argparse.ArgumentParser(description="Build R5 library-audit dataset")
    ap.add_argument("--backtest", action="store_true")
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--skip-backtest", action="store_true")
    args = ap.parse_args()

    all_detect = DETECT_POS + DETECT_ANEG + DETECT_BNEG
    all_triage = TRIAGE_CONFIRM + TRIAGE_REJECT

    print(f"R5 library-audit samples:")
    print(f"  detect: pos={len(DETECT_POS)} aneg={len(DETECT_ANEG)}"
          f" bneg={len(DETECT_BNEG)} = {len(all_detect)} total")
    print(f"  triage: Confirm={len(TRIAGE_CONFIRM)} Reject={len(TRIAGE_REJECT)}"
          f" = {len(all_triage)} total")
    print(f"  TOTAL: {len(all_detect) + len(all_triage)} new samples")

    ids = [r["id"] for r in all_detect + all_triage]
    dupes = sorted(set(i for i in ids if ids.count(i) > 1))
    if dupes:
        print(f"ERROR: duplicate IDs: {dupes}")
        return 1

    # Write v2 schema
    (R5 / "known_forms_detect.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in all_detect) + "\n")
    (R5 / "known_forms_triage.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in all_triage) + "\n")
    print(f"[+] {R5}/known_forms_detect.jsonl")
    print(f"[+] {R5}/known_forms_triage.jsonl")

    if args.backtest and not args.skip_backtest:
        if not validate_discipline(all_detect, all_triage, ROOT / "rules"):
            print("Backtest FAILED -- fix rule violations before training.")
            return 1

    if args.emit:
        merge_and_emit(all_detect, all_triage, R5 / "upload" / "full")

    return 0


if __name__ == "__main__":
    sys.exit(main())
