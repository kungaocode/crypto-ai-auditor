#!/usr/bin/env python3
"""Round-4 negative-sample builder (detect task, vulnerable=false).

Purpose: teach the safe/unsafe decision boundary the round-3 model still lacks
(see data/round3/eval/ACCEPTANCE.md "detect 层近乎全报": 562/569 predicted
vulnerable). Root cause: detect training negatives were all generic non-crypto
Django code (cwe: None), so the model never saw *crypto code that is safe*.

Two classes (per docs/crypto_vuln_taxonomy.md):
  A 类 — secure modern crypto   : correct usage that must NOT fire any rule.
  B 类 — weak primitive, non-security purpose : MD5/SHA-1/random used for cache,
                                  dedup, sharding, change-detection, jitter, A/B
                                  buckets, benchmarks, test scaffolding. The
                                  primitive is weak but nothing security-relevant
                                  depends on it -> not a vuln (the "effective
                                  false positive" of To Fix or Not to Fix).

Outputs (all under data/round4/):
  negative_source.jsonl         v2 schema, all negatives (split: train/val/test)
  backtest_report.json          Semgrep per-sample hit results
  upload/incr/{train,val,test}.jsonl   incremental set (negatives only, for
                                       continue-training the round-3 model)
  upload/full/{train,val,test}.jsonl   merged set (detect_train + negatives +
                                       triage_all, for base retrain)

Usage:  python scripts/build_round4_negatives.py [--backtest] [--emit]
"""
import argparse
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.prepare_sft_data import build_messages  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
R4 = ROOT / "data" / "round4"


def neg(rid: str, code: str, explanation: str, cls: str, split: str = "train") -> dict:
    return {
        "id": rid, "language": "python", "task": "detect", "code": code,
        "label": {"vulnerable": False, "cwe": "", "severity": "",
                  "confidence": "high", "explanation": explanation},
        "source": f"round4-negative-{cls}", "license": "original",
        "repo_url": "", "commit": "", "verified": False, "split": split,
    }


# =============================================================================
# CURATED CORE. Each entry: neg(id, code, explanation, class[, split]).
# id convention: round4-neg-<CLASS><n>-<slug>
# =============================================================================
NEGATIVES = [
    # ===== 0. 跨领域安全写法 (A 类) =========================================
    neg("round4-neg-A001-scrypt", """import hashlib
import secrets

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + digest.hex()""",
        "Passwords are hashed with scrypt (slow, salted, memory-hard KDF) and a "
        "per-password CSPRNG salt. No weak or fast digest protects the secret -> safe.", "A"),
    neg("round4-neg-A002-argon2", """from argon2 import PasswordHasher

_ph = PasswordHasher()

def hash_password(password: str) -> str:
    return _ph.hash(password)""",
        "Passwords go through argon2 (PasswordHasher), the current recommended "
        "memory-hard KDF with a random salt. Correct password storage -> safe.", "A"),
    neg("round4-neg-A003-bcrypt", """import bcrypt

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)""",
        "bcrypt with a fresh random salt hashes the password. bcrypt is a slow, "
        "salted KDF designed for this; no weak digest -> safe.", "A"),
    neg("round4-neg-A004-pbkdf2", """import hashlib
import os

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return salt.hex() + digest.hex()""",
        "PBKDF2-HMAC-SHA256 with a random salt and a high iteration count "
        "(310k). Adequate for password hashing -> safe.", "A"),
    neg("round4-neg-A005-aesgcm", """import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_payload(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)""",
        "AES-GCM (authenticated encryption) with a fresh 96-bit CSPRNG nonce per "
        "message. No ECB, fixed IV, or unauthenticated cipher -> safe.", "A"),
    neg("round4-neg-A006-aesgcm-pycrypto", """import os
from Crypto.Cipher import AES

def encrypt_record(record: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(record)
    return nonce + tag + ct""",
        "AES-GCM via pycryptodome with a fresh random nonce and a MAC tag. "
        "Authenticated encryption, no ECB/fixed-IV -> safe.", "A"),
    neg("round4-neg-A007-fernet", """from cryptography.fernet import Fernet
import os

def encrypt_field(value: str) -> bytes:
    f = Fernet(os.environ["APP_SECRET_KEY"].encode())
    return f.encrypt(value.encode())""",
        "Fernet (authenticated, high-level) with a key from the environment, not "
        "hardcoded. Correct symmetric encryption -> safe.", "A"),
    neg("round4-neg-A008-hmac-sha256", """import hashlib
import hmac

def verify_webhook(secret: bytes, body: bytes, expected: bytes) -> bool:
    actual = hmac.new(secret, body, hashlib.sha256).digest()
    return hmac.compare_digest(actual, expected)""",
        "HMAC-SHA256 with a constant-time comparison verifies the signature. No "
        "weak digest and no timing leak -> safe.", "A"),
    neg("round4-neg-A009-secrets-token", """import secrets

def generate_api_token() -> str:
    return secrets.token_urlsafe(32)""",
        "The API token comes from secrets.token_urlsafe (CSPRNG, 256-bit "
        "entropy). No predictable random.* or weak digest -> safe.", "A"),
    neg("round4-neg-A010-secrets-nonce", """import secrets

def generate_nonce() -> bytes:
    return secrets.token_bytes(16)""",
        "A cryptographic nonce is drawn from secrets.token_bytes (CSPRNG). "
        "Nonce material must be unpredictable -> safe.", "A"),
    neg("round4-neg-A011-cbc-random-iv", """import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_block(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return iv + enc.update(data) + enc.finalize()""",
        "AES-CBC uses a fresh random IV per encryption (prepended to the "
        "ciphertext). No fixed or predictable IV -> safe.", "A"),
    neg("round4-neg-A012-sha256-integrity", """import hashlib

def verify_download(file_path: str, expected_hash: str) -> bool:
    with open(file_path, "rb") as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    return actual == expected_hash""",
        "Download integrity uses SHA-256, not MD5/SHA-1. SHA-256 is still "
        "collision-resistant -> safe.", "A"),
    neg("round4-neg-A013-sha256-fingerprint", """import hashlib

def certificate_fingerprint(cert_pem: bytes) -> str:
    return hashlib.sha256(cert_pem).hexdigest()""",
        "A certificate fingerprint is SHA-256. Fingerprints for security "
        "comparison need a collision-resistant hash -> safe.", "A"),
    neg("round4-neg-A014-rsa2048", """from Crypto.PublicKey import RSA

def generate_signing_key():
    return RSA.generate(2048)""",
        "RSA-2048 is generated (>= 112-bit security strength per SP 800-131A). "
        "No short 1024-bit key -> safe.", "A"),
    neg("round4-neg-A015-ecc-p256", """from Crypto.PublicKey import ECC

def generate_ec_key():
    return ECC.generate(curve="P-256")""",
        "An ECDSA key on the NIST P-256 curve (128-bit strength). Correct key "
        "size and curve -> safe.", "A"),
    neg("round4-neg-A016-default-tls", """import ssl

def create_client_context():
    return ssl.create_default_context()""",
        "ssl.create_default_context() validates certificates and negotiates "
        "modern TLS. No unverified context or legacy protocol -> safe.", "A"),
    neg("round4-neg-A017-requests-verify", """import requests

def fetch_public_data(url: str):
    return requests.get(url, timeout=10)""",
        "requests.get uses TLS certificate verification by default. No "
        "verify=False -> safe.", "A"),
    neg("round4-neg-A018-compare-digest", """import hmac

def password_matches(stored_hash: bytes, supplied: bytes) -> bool:
    return hmac.compare_digest(stored_hash, supplied)""",
        "Constant-time comparison via hmac.compare_digest avoids a timing side "
        "channel when checking a secret. Correct -> safe.", "A"),
    neg("round4-neg-A019-kdf-derived-key", """import hashlib
import os

def derive_encryption_key(passphrase: str) -> bytes:
    salt = os.urandom(16)
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)""",
        "An encryption key is derived from a passphrase with scrypt + random "
        "salt, not hardcoded. Correct key derivation -> safe.", "A"),

    # ===== CRYPTO-001 MD5 =====================================================
    neg("round4-neg-B001-md5-cache", """import hashlib

def cache_key(query: str) -> str:
    return hashlib.md5(query.encode()).hexdigest()""",
        "MD5 only maps a query string to a cache/lookup key. The digest "
        "identifies data for memoization, not to protect a secret; collisions "
        "are irrelevant -> not a vulnerability.", "B"),
    neg("round4-neg-B002-md5-dedup", """import hashlib

def deduplicate(files):
    seen = {}
    for f in files:
        digest = hashlib.md5(f.read()).hexdigest()
        seen.setdefault(digest, f)
    return list(seen.values())""",
        "MD5 deduplicates files by content hash. The digest groups identical "
        "data; collision resistance is irrelevant for dedup -> not a vulnerability.", "B"),
    neg("round4-neg-B003-md5-etag", """import hashlib

def etag_for(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()""",
        "MD5 is used as an HTTP ETag (change detector / cache validator). It "
        "protects no secret; only detects if content changed -> not a vulnerability.", "B"),
    neg("round4-neg-B004-md5-cas", """import hashlib

def object_address(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()[:20]""",
        "MD5 derives a content-addressed storage key. It names an object, it "
        "does not protect a secret or verify integrity -> not a vulnerability.", "B"),
    neg("round4-neg-B005-md5-corruption-check", """import hashlib

def checksum_ok(blob: bytes, stored: str) -> bool:
    return hashlib.md5(blob).hexdigest() == stored""",
        "MD5 only detects accidental corruption of a blob. It assumes a "
        "non-adversarial channel; no integrity guarantee against attackers -> "
        "not a vulnerability.", "B"),
    neg("round4-neg-B006-md5-partition", """import hashlib

def partition(key: str, n: int) -> int:
    return int(hashlib.md5(key.encode()).hexdigest(), 16) % n""",
        "MD5 maps a key to one of n partitions for distribution. Collision "
        "resistance is irrelevant to routing -> not a vulnerability.", "B"),
    neg("round4-neg-A020-sha256-integrity-api", """import hashlib
import hmac

def sign_request(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()""",
        "An API request signature is HMAC-SHA256, not MD5. HMAC-SHA256 is "
        "collision-resistant and standard -> safe.", "A"),
    neg("round4-neg-A021-md5-none", """import hashlib

def hash_password_v2(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()""",
        "Passwords use scrypt, never MD5. No weak fast digest on a secret -> safe.", "A"),

    # ===== CRYPTO-002 SHA-1 ===================================================
    neg("round4-neg-B007-sha1-shard", """import hashlib

def shard_index(key: str, num_shards: int) -> int:
    return int(hashlib.sha1(key.encode()).hexdigest(), 16) % num_shards""",
        "SHA-1 only spreads keys across shards for load distribution. No secret "
        "or integrity guarantee depends on the digest -> not a vulnerability.", "B"),
    neg("round4-neg-B008-sha1-logindex", """import hashlib

def log_key(line: str) -> str:
    return hashlib.sha1(line.encode()).hexdigest()[:16]""",
        "SHA-1 fingerprints log lines for indexing/lookup. The digest is not a "
        "security control; collisions are irrelevant -> not a vulnerability.", "B"),
    neg("round4-neg-B009-sha1-objectid", """import hashlib

def blob_oid(content: bytes) -> str:
    return "blob " + hashlib.sha1(content).hexdigest()""",
        "SHA-1 derives a git-style object id. It names content in a store, not "
        "a signature or secret -> not a vulnerability.", "B"),
    neg("round4-neg-B010-sha1-fingerprint-nonsec", """import hashlib

def feature_id(user_id: int) -> str:
    return hashlib.sha1(str(user_id).encode()).hexdigest()[:12]""",
        "SHA-1 shortens a user id into a stable feature flag key. No security "
        "property relies on collision resistance -> not a vulnerability.", "B"),
    neg("round4-neg-A022-sha256-session", """import secrets

def session_id() -> str:
    return secrets.token_urlsafe(32)""",
        "Session ids come from a CSPRNG, not SHA-1 of predictable data. "
        "Correct -> safe.", "A"),
    neg("round4-neg-A023-sha256-certfp", """import hashlib

def cert_fingerprint(cert_der: bytes) -> str:
    return hashlib.sha256(cert_der).hexdigest()""",
        "Certificate fingerprints use SHA-256. Correct for security comparison "
        "-> safe.", "A"),

    # ===== CRYPTO-003 DES/3DES ================================================
    neg("round4-neg-A024-aesgcm-not-3des", """import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_card(card: bytes, key: bytes) -> bytes:
    a = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + a.encrypt(nonce, card, None)""",
        "Payment data is encrypted with AES-GCM, not 3DES/ECB. No 64-bit block "
        "Sweet32 exposure and authenticated -> safe.", "A"),
    neg("round4-neg-B011-des-benchmark", """from Crypto.Cipher import DES
import time

def des_throughput(key: bytes) -> float:
    cipher = DES.new(key, DES.MODE_ECB)
    start = time.time()
    for _ in range(10_000):
        cipher.encrypt(bytes(8))
    return time.time() - start""",
        "DES only appears in a microbenchmark on throwaway zero input. No real "
        "data is encrypted; performance scaffolding -> not a vulnerability.", "B"),
    neg("round4-neg-B012-3des-testvec", """from Crypto.Cipher import DES3

def test_3des_vector() -> None:
    key = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef")
    cipher = DES3.new(key, DES3.MODE_ECB)
    assert len(cipher.encrypt(bytes(8))) == 8""",
        "3DES is instantiated only to pin a known test vector in a unit test. "
        "No real plaintext -> not a vulnerability.", "B"),

    # ===== CRYPTO-004 RC4 =====================================================
    neg("round4-neg-A025-aesgcm-not-rc4", """import os
from Crypto.Cipher import AES

def encrypt_message(msg: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)
    return nonce + tag + ct""",
        "Data is encrypted with AES-GCM, not RC4. No keystream bias and "
        "authenticated -> safe.", "A"),
    neg("round4-neg-B013-rc4-golden", """from Crypto.Cipher import ARC4

def test_rc4_vector() -> None:
    cipher = ARC4.new(b"Key")
    assert cipher.encrypt(b"Plaintext") == bytes.fromhex("bbf317e5342426b1")""",
        "RC4 reproduces a known test vector inside a unit test. No real data "
        "flows through the cipher -> not a vulnerability.", "B"),
    neg("round4-neg-B014-rc4-obfuscate", """from Crypto.Cipher import ARC4

def obfuscate_save(save_data: bytes, key: bytes) -> bytes:
    cipher = ARC4.new(key)
    return cipher.encrypt(save_data)""",
        "RC4 only obfuscates a local save-game file. The data is not a secret; "
        "obfuscation deters casual editing, not attackers -> not a vulnerability.", "B"),

    # ===== CRYPTO-005 AES-ECB =================================================
    neg("round4-neg-A026-aesgcm-not-ecb", """import os
from Crypto.Cipher import AES

def encrypt_profile(profile: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(profile)
    return nonce + tag + ct""",
        "User profile data uses AES-GCM, not ECB. No plaintext-pattern leakage "
        "and authenticated -> safe.", "A"),
    neg("round4-neg-B015-ecb-testvec", """from Crypto.Cipher import AES

def test_aes_roundtrip() -> None:
    key = bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(bytes(16))
    assert cipher.decrypt(ct) == bytes(16)""",
        "AES-ECB appears only in a unit test verifying round-trip on zero "
        "input. No real plaintext -> not a vulnerability.", "B"),
    neg("round4-neg-B016-ecb-benchmark", """from Crypto.Cipher import AES
import time

def ecb_throughput(key: bytes) -> float:
    cipher = AES.new(key, AES.MODE_ECB)
    start = time.time()
    for _ in range(10_000):
        cipher.encrypt(bytes(16))
    return time.time() - start""",
        "AES-ECB appears only in a throughput microbenchmark on zero input. "
        "No real data -> not a vulnerability.", "B"),

    # ===== CRYPTO-006 Predictable IV ==========================================
    neg("round4-neg-A027-random-iv-cbc", """import os
from Crypto.Cipher import AES

def encrypt_section(section: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    return iv + cipher.encrypt(section)""",
        "AES-CBC uses a fresh random IV per record, prepended to the output. "
        "No fixed/predictable IV -> safe.", "A"),
    neg("round4-neg-B017-fixed-iv-test", """from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def test_cbc_smoke() -> None:
    cipher = Cipher(algorithms.AES(bytes(16)), modes.CBC(bytes(16)))
    enc = cipher.encryptor()
    assert len(enc.update(bytes(16))) == 16""",
        "A fixed all-zero IV appears only in a smoke test exercising the cipher "
        "object. Nothing real is encrypted -> not a vulnerability.", "B"),
    neg("round4-neg-B018-fixed-iv-bench", """from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import time

def cbc_bench() -> float:
    cipher = Cipher(algorithms.AES(bytes(16)), modes.CBC(bytes(16)))
    enc = cipher.encryptor()
    start = time.time()
    for _ in range(1000):
        enc.update(bytes(16))
    return time.time() - start""",
        "A fixed IV appears only in a microbenchmark on zero input. No real "
        "data -> not a vulnerability.", "B"),

    # ===== CRYPTO-007 Hard-coded key ==========================================
    neg("round4-neg-A028-env-key", """import os
from Crypto.Cipher import AES

def encrypt_session(data: bytes) -> bytes:
    key = os.environ["SESSION_KEY"].encode()
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ct""",
        "The session key is loaded from the environment, not hardcoded. Keys "
        "belong outside source -> safe.", "A"),
    neg("round4-neg-A029-kdf-key", """import hashlib
import os

def load_secret_key() -> bytes:
    salt = os.urandom(16)
    return hashlib.scrypt(os.environ["PASSPHRASE"].encode(), salt=salt, n=2**14, r=8, p=1)""",
        "The key is derived from an env passphrase via scrypt. No literal key "
        "in source -> safe.", "A"),
    neg("round4-neg-B019-test-key", """from cryptography.fernet import Fernet

def test_fernet_roundtrip() -> None:
    f = Fernet(b"test-only-sample-key-0000000000000")
    token = f.encrypt(b"test message")
    assert f.decrypt(token) == b'test message'""",
        "A hardcoded key appears only inside a unit test generating throwaway "
        "fixtures. It never touches real data -> not a vulnerability.", "B"),

    # ===== CRYPTO-008 Weak random =============================================
    neg("round4-neg-A030-secrets-randbits", """import secrets

def generate_session_token() -> int:
    return secrets.randbits(256)""",
        "A session token uses secrets.randbits (CSPRNG). Not the predictable "
        "Mersenne Twister -> safe.", "A"),
    neg("round4-neg-B020-random-jitter", """import random

def backoff_delay(attempt: int) -> float:
    backoff_salt = random.uniform(0.0, 1.0)
    return min(2 ** attempt, 60) + backoff_salt""",
        "random.uniform adds a jitter salt to a retry backoff to avoid a "
        "thundering herd. The jitter is not a secret, nonce, or token; "
        "predictability has no security impact -> not a vulnerability.", "B"),
    neg("round4-neg-B021-random-shard", """import random

def route_to_worker(num_workers: int) -> int:
    shard_key = random.randrange(num_workers)
    return shard_key""",
        "random.randrange picks a worker for load distribution. The shard key "
        "is not a secret or cryptographic control; predictability is harmless "
        "-> not a vulnerability.", "B"),
    neg("round4-neg-B022-random-simulation", """import random

def monte_carlo_pi(n: int) -> float:
    inside = sum(1 for _ in range(n) if random.random()**2 + random.random()**2 < 1)
    return 4 * inside / n""",
        "random.random drives a Monte-Carlo simulation. No secret, token, or "
        "cryptographic control depends on the samples -> not a vulnerability.", "B"),
    neg("round4-neg-B023-random-testdata", """import random

def make_test_rows(n: int):
    return [{"id": i, "score": random.randint(0, 100)} for i in range(n)]""",
        "random.randint generates throwaway test fixtures. Test data carries no "
        "security role -> not a vulnerability.", "B"),
    neg("round4-neg-B024-random-trace-id", """import random

def trace_id() -> str:
    trace_token = random.randint(0, 0xFFFF)
    return f'{trace_token:04x}'""",
        "random.randint builds a trace token for logging. It is not a secret; "
        "predicting it reveals nothing sensitive -> not a vulnerability.", "B"),
    neg("round4-neg-A031-os-urandom-salt", """import os

def new_salt() -> bytes:
    return os.urandom(16)""",
        "A password-hashing salt comes from os.urandom (CSPRNG). Correct for "
        "security-sensitive randomness -> safe.", "A"),

    # ===== CRYPTO-009 Weak key length =========================================
    neg("round4-neg-A032-rsa2048-sign", """from Crypto.PublicKey import RSA

def new_signing_key():
    return RSA.generate(2048)""",
        "RSA-2048 meets the SP 800-131A 112-bit minimum for signing keys. "
        "No short key -> safe.", "A"),
    neg("round4-neg-A033-ed25519", """from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def new_ed25519_key():
    return Ed25519PrivateKey.generate()""",
        "An Ed25519 key (128-bit strength) is generated. Modern elliptic-curve "
        "signature key -> safe.", "A"),
    neg("round4-neg-B025-rsa1024-test", """from Crypto.PublicKey import RSA

def test_rsa_keygen() -> None:
    key = RSA.generate(1024)
    assert key.size_in_bits() == 1024""",
        "RSA.generate(1024) appears only in a unit test asserting key "
        "generation works. The key never touches real data -> not a vulnerability.", "B"),
    neg("round4-neg-B026-rsa1024-bench", """from Crypto.PublicKey import RSA
import time

def rsa_keygen_bench() -> float:
    start = time.time()
    for _ in range(10):
        RSA.generate(1024)
    return time.time() - start""",
        "RSA.generate(1024) appears only in a microbenchmark of keygen "
        "throughput. Throwaway keys -> not a vulnerability.", "B"),

    # ===== CRYPTO-010 Insecure TLS ============================================
    neg("round4-neg-A034-requests-default", """import requests

def post_analytics(url: str, payload: dict) -> int:
    return requests.post(url, json=payload, timeout=10).status_code""",
        "requests.post verifies TLS certificates by default. No verify=False "
        "-> safe.", "A"),
    neg("round4-neg-A035-tls12-min", """import ssl

def secure_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx""",
        "The TLS context enforces TLS 1.2 minimum and validates certificates. "
        "No legacy protocol -> safe.", "A"),
    neg("round4-neg-B027-localhost-health", """import requests

def wait_for_server(url: str) -> bool:
    for _ in range(10):
        try:
            if requests.get(url, verify=False, timeout=2).status_code == 200:
                return True
        except requests.ConnectionError:
            pass
    return False""",
        "verify=False only appears in a startup loop waiting for a localhost "
        "dev server. No remote endpoint or sensitive data -> not a vulnerability.", "B"),
    neg("round4-neg-B028-localhost-db", """import requests

def wait_for_db(host: str, port: int) -> bool:
    url = f"http://{host}:{port}/health"
    for _ in range(30):
        try:
            if requests.get(url, verify=False, timeout=2).status_code == 200:
                return True
        except requests.ConnectionError:
            pass
    return False""",
        "verify=False only appears while polling a local database health "
        "endpoint at startup. Not a security-relevant TLS decision -> not a "
        "vulnerability.", "B"),

    # ===== Round-4 batch 2: knowledge-grounded additions =====================
    # 来源：crypto_and_security/（NIST/FIPS 标准文本）+ docs/crypto_vuln_taxonomy.md。
    # 覆盖 taxonomy 未触及的安全写法（ChaCha20-Poly1305、SHA-3、HKDF、ECDH、
    # AES-256 密钥生成、会话 id、恒定时间校验），以及更接近真实代码的 B 类。

    # --- A 类：NIST 认可的安全现代密码 --------------------------------------
    # SP 800-63B「preferably ChaCha20-Poly1305」→ 认证加密的又一对等安全写法。
    neg("round4-neg-A036-chacha20poly1305", """from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import secrets

def encrypt_payload(plaintext: bytes, key: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(12)
    return nonce + aead.encrypt(nonce, plaintext, None)""",
        "ChaCha20-Poly1305 (authenticated AEAD) with a fresh CSPRNG nonce per "
        "message. An approved AES-GCM alternative -> safe.", "A"),
    neg("round4-neg-A037-sha3-256", """import hashlib

def content_fingerprint(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()""",
        "Integrity uses SHA3-256, the current NIST-approved secure hash. Not "
        "the broken MD5/SHA-1 -> safe.", "A"),
    neg("round4-neg-A038-hkdf", """from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets

def derive_key(master_secret: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"app-key")
    return hkdf.derive(master_secret)""",
        "A sub-key is derived via HKDF-SHA256 (NIST SP 800-56C) from a master "
        "secret. No weak digest or hardcoded key -> safe.", "A"),
    neg("round4-neg-A039-ecdh", """from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def agree_key(my_private: ec.EllipticCurvePrivateKey,
              peer_public: ec.EllipticCurvePublicKey) -> bytes:
    shared = my_private.exchange(ec.ECDH(), peer_public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"kex").derive(shared)""",
        "A shared secret is agreed over ECDH on a NIST curve and stretched with "
        "HKDF. Approved key establishment -> safe.", "A"),
    neg("round4-neg-A040-aes256-key", """import secrets

def new_data_key() -> bytes:
    return secrets.token_bytes(32)""",
        "A 256-bit data-encryption key comes from secrets.token_bytes "
        "(CSPRNG, 256 bits of strength). Not weak randomness -> safe.", "A"),
    neg("round4-neg-A041-session-id", """import secrets

def new_session_id() -> str:
    return secrets.token_hex(32)""",
        "The session id is 256 bits from a CSPRNG (SP 800-63B requires >=128 "
        "bits, unique). Not the predictable Mersenne Twister -> safe.", "A"),
    neg("round4-neg-A042-verify-password", """import hashlib
import hmac

def verify_password(stored: str, supplied: str) -> bool:
    salt = bytes.fromhex(stored[:32])
    digest = hashlib.pbkdf2_hmac("sha256", supplied.encode(), salt, 310_000)
    return hmac.compare_digest(digest.hex().encode(), stored[32:].encode())""",
        "PBKDF2-SHA256 hash compared with hmac.compare_digest (constant time). "
        "Correct password verification, no timing leak -> safe.", "A"),

    # --- B 类：弱原语 × 非安全目的（更接近真实代码的模块化写法）--------------
    neg("round4-neg-B029-md5-cachebust", """import hashlib

_cache: dict[str, str] = {}

def cache_bust(url: str) -> str:
    digest = hashlib.md5(url.encode()).hexdigest()[:8]
    return f"{url}?v={digest}" if "?" not in url else f"{url}&v={digest}" """,
        "MD5 appends a cache-busting query param so browsers refetch changed "
        "assets. It protects no secret; only defeats stale caches -> not a "
        "vulnerability.", "B"),
    neg("round4-neg-B030-sha1-content-addr", """import hashlib

class BlobStore:
    def put(self, data: bytes) -> str:
        object_id = hashlib.sha1(data).hexdigest()
        self._write(object_id, data)
        return object_id

    def _write(self, object_id: str, data: bytes) -> None:
        ...""",
        "SHA-1 addresses a content blob by its digest (git-style addressing). "
        "The digest is an address/lookup key, not an authenticity check -> not "
        "a vulnerability.", "B"),
    neg("round4-neg-B031-md5-dedup", """import hashlib
from pathlib import Path

def backup_files(paths: list[Path]) -> int:
    seen: set[str] = set()
    saved = 0
    for p in paths:
        digest = hashlib.md5(p.read_bytes()).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        _store(p, digest)
        saved += 1
    return saved

def _store(p: Path, digest: str) -> None:
    ...""",
        "MD5 dedups identical files in a backup job. The digest only detects "
        "byte-for-byte duplicates; no authenticity or integrity of a secret is "
        "claimed -> not a vulnerability.", "B"),
    neg("round4-neg-B032-random-seeded-test", """import random

def make_fixture(n: int) -> list[dict]:
    rng = random.Random(42)
    return [{"id": i, "token": rng.randbytes(8).hex()} for i in range(n)]""",
        "random.Random(42) builds reproducible test fixtures; the 'token' field "
        "is inert test data, not a real credential -> not a vulnerability.", "B"),
    neg("round4-neg-B033-random-ab-bucket", """import random

def variant(user_id: str) -> str:
    salt = random.random()
    return "A" if salt < 0.5 else "B" """,
        "random.random splits users into A/B feature-flag buckets. The bucket "
        "salt has no security role and predicting it leaks nothing -> not a "
        "vulnerability.", "B"),
    neg("round4-neg-B034-md5-watch", """import hashlib
from pathlib import Path

def config_changed(path: Path, cached: str) -> bool:
    return hashlib.md5(path.read_bytes()).hexdigest() != cached""",
        "MD5 detects whether a config file changed since last read (freshness "
        "watch). It does not authenticate the file or protect a secret -> not "
        "a vulnerability.", "B"),
    neg("round4-neg-B035-random-shuffle", """import random

def pick_order(servers: list[str]) -> list[str]:
    shuffled = list(servers)
    random.shuffle(shuffled)
    return shuffled""",
        "random.shuffle randomizes server order for load spreading. The order "
        "is not a secret or cryptographic control -> not a vulnerability.", "B"),
]


# =============================================================================
# Backtest: run Semgrep over each sample, record rule hits.
#   A 类 must hit NOTHING (clean).  B 类 should hit its expected rule (proves the
#   discriminator must look past the rule hit to the usage context).
# =============================================================================
def backtest(records: list) -> dict:
    rules_dir = ROOT / "rules"
    codes = [r["code"] for r in records]
    hits = {}
    with tempfile.TemporaryDirectory(prefix="r4_bt_") as td:
        for i, c in enumerate(codes):
            Path(td, f"f{i:05d}.py").write_text(c, encoding="utf-8")
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
        report[r["id"]] = {"class": r["source"].split("-")[-1], "rules_hit": got}
    return report


def backtest_ok(report: dict) -> tuple[int, int]:
    """Return (n_bad_A, n_bad_B): A 类样本命中规则、或 B 类样本零命中都算异常。"""
    bad_a = bad_b = 0
    for rid, v in report.items():
        cls = v["class"]
        hit = bool(v["rules_hit"])
        if cls == "A" and hit:
            bad_a += 1
        if cls == "B" and not hit:
            bad_b += 1
    return bad_a, bad_b


# =============================================================================
# Emit: split negatives into train/val/test, write source + chatml upload sets.
# =============================================================================
def write_jsonl(records: list, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[+] wrote {len(records)} -> {path}")


def to_chatml(records: list) -> list:
    out = []
    for r in records:
        out.append({"messages": build_messages(r)})
    return out


def _load(path: Path) -> list:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def emit_upload_sets(negatives: list) -> None:
    train = [r for r in negatives if r["split"] == "train"]
    val = [r for r in negatives if r["split"] == "val"]
    test = [r for r in negatives if r["split"] == "test"]
    for name, recs in [("train", train), ("val", val), ("test", test)]:
        write_jsonl(to_chatml(recs), R4 / "upload" / "incr" / f"{name}.jsonl")

    # --- full merge (base retrain): detect + negatives + triage all ---------
    detect_train = _load(ROOT / "data/splits/detect_train.jsonl")
    # triage train = round-1 (132) + round-2 fixes (54) + round-3 signature (3)
    triage_all = (_load(ROOT / "data/splits/triage_train.jsonl")
                  + _load(ROOT / "data/round2/triage_fix_source.jsonl")
                  + _load(ROOT / "data/round3/signature_fix_source.jsonl"))
    neg_train = [r for r in negatives if r["split"] == "train"]
    merged = detect_train + neg_train + triage_all
    write_jsonl(to_chatml(merged), R4 / "upload" / "full" / "train.jsonl")

    # val/test: mixed detect + triage (round-3 style, both tasks guarded)
    triage_val = _load(ROOT / "data/round3/val_source.jsonl")
    triage_test = _load(ROOT / "data/round3/test_source.jsonl")
    for name, src, extra in [
        ("val", "detect_val.jsonl", triage_val),
        ("test", "detect_test.jsonl", triage_test),
    ]:
        recs = _load(ROOT / "data/splits" / src) + extra
        write_jsonl(to_chatml(recs), R4 / "upload" / "full" / f"{name}.jsonl")

    # ratio report (detect only; triage is a separate task axis)
    vuln = sum(1 for r in detect_train if r["label"].get("vulnerable"))
    sec = len(detect_train) - vuln + len(neg_train)
    print(f"\n[ratio] detect_train after negatives: vulnerable={vuln} "
          f"secure={sec} -> {vuln/(vuln+sec):.0%}:{sec/(vuln+sec):.0%}")
    print(f"[full]  train={len(merged)} (detect {len(detect_train)+len(neg_train)} "
          f"+ triage {len(triage_all)})  val={len(_load(ROOT/'data/splits/detect_val.jsonl'))+len(triage_val)} "
          f"test={len(_load(ROOT/'data/splits/detect_test.jsonl'))+len(triage_test)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Build round-4 detect negatives")
    ap.add_argument("--backtest", action="store_true")
    ap.add_argument("--emit", action="store_true")
    args = ap.parse_args()

    if args.backtest:
        report = backtest(NEGATIVES)
        bad_a, bad_b = backtest_ok(report)
        write_jsonl([{"id": k, **v} for k, v in report.items()],
                    R4 / "backtest_report.jsonl")
        print(f"[backtest] {len(NEGATIVES)} samples: A-class-rule-hit={bad_a} "
              f"(must be 0), B-class-no-hit={bad_b} (informational)")
        for rid, v in report.items():
            if v["class"] == "A" and v["rules_hit"]:
                print(f"  [!] A 类异常命中 {rid}: {v['rules_hit']}")
        # B 类 no-hit 仅信息性：非安全命名的 weak 负样本本就不该触发规则，
        # 强负样本（带 key/salt/token 等命名）应命中对应规则。
        strong_b = [rid for rid, v in report.items()
                    if v["class"] == "B" and v["rules_hit"]]
        weak_b = [rid for rid, v in report.items()
                  if v["class"] == "B" and not v["rules_hit"]]
        print(f"  strong-B (rule fires, model must override): {len(strong_b)}")
        print(f"  weak-B   (no rule, trivially safe):       {len(weak_b)}")

    if args.emit:
        write_jsonl(NEGATIVES, R4 / "negative_source.jsonl")
        emit_upload_sets(NEGATIVES)

    if not (args.backtest or args.emit):
        ap.print_help()
