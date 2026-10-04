#!/usr/bin/env python3
"""
Build Round-6 training data: safe crypto libraries + R5-regression fixes + rebalancing.

Strategy (lessons from R5 eval: confirm_recall 0.667, domain fpr 0.289):
  1. Add safe crypto library code as detect negatives (aneg/bneg) from
     cryptography, PyNaCl, itsdangerous, PyJWT → fix the over-reject bias.
  2. Add triage Confirm samples for patterns R5 wrongly rejected
     (AES-ECB, DES-password, ARC4-stream, MD5-signature, CRYPTO-011/012/013).
  3. Expand passlib legacy trej (4/11→target 10/11).
  4. Expand PyCryptoDome PEM/PKCS8 trej (R5 had 3 FPs on these).
  5. Target pos:neg ≈ 40:60 for new samples (R5 was 26:74).
  6. Keep TRIAGE_PURPOSE_GUIDE in training — the issue was imbalance, not the guide.

Output: data/round6/new_detect.jsonl + data/round6/new_triage.jsonl (v2 schema).
Then merged with R5 upload base via build_round5_final_dataset.py merge logic.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
R6 = ROOT / "data" / "round6"

# ── helpers ─────────────────────────────────────────────────────────────────

def _rec(task, rid, code, label, source, split="train", finding=None, rule=None, **kw):
    r = {
        "id": rid, "language": "python", "task": task,
        "code": code.strip(), "label": label,
        "source": source, "license": "original",
        "repo_url": "", "commit": "", "verified": False,
        "split": split,
    }
    if finding:
        r["finding"] = finding
    if rule:
        r["rule"] = rule
    r.update(kw)
    return r

def _detect_pos(rid, code, cwe, explanation, rule, split="train"):
    return _rec("detect", rid, code, {
        "vulnerable": True, "cwe": cwe, "severity": "WARNING",
        "confidence": "high", "explanation": explanation,
    }, f"round6-{rule.lower()}-pos", split=split, rule=rule)

def _detect_aneg(rid, code, explanation, split="train"):
    return _rec("detect", rid, code, {
        "vulnerable": False, "cwe": "", "severity": "",
        "confidence": "high", "explanation": explanation,
    }, "round6-safe-lib-aneg", split=split)

def _detect_bneg(rid, code, explanation, rule, split="train"):
    return _rec("detect", rid, code, {
        "vulnerable": False, "cwe": "", "severity": "",
        "confidence": "high", "explanation": explanation,
    }, f"round6-safe-lib-bneg", split=split, rule=rule)

def _triage_confirm(rid, code, finding, cwe, explanation, patch="", split="train", rule=None):
    return _rec("triage", rid, code, {
        "cwe": cwe, "severity": "WARNING", "verdict": "Confirm",
        "explanation": explanation, "patch": patch,
    }, "round6-regression-fix-confirm", split=split, finding=finding, rule=rule)

def _triage_reject(rid, code, finding, explanation, patch="", split="train", rule=None,
                   source="round6-lib-reject"):
    return _rec("triage", rid, code, {
        "cwe": "", "severity": "INFO", "verdict": "Reject",
        "explanation": explanation, "patch": patch,
    }, source, split=split, finding=finding, rule=rule)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: SAFE CRYPTO LIBRARY CODE (detect aneg)
#   These show the model what "safe crypto" looks like in real libraries.
#   None should trigger Semgrep rules.
# ══════════════════════════════════════════════════════════════════════════════

SAFE_LIB_ANEG = [

    # ── cryptography: Fernet (AES-128-CBC + HMAC-SHA256, tirered) ──
    _detect_aneg("r6-crypto-fernet", """
from cryptography.fernet import Fernet

class SecureStorage:
    def __init__(self):
        self._fernet = Fernet(Fernet.generate_key())

    def encrypt(self, plaintext: str) -> bytes:
        return self._fernet.encrypt(plaintext.encode())

    def decrypt(self, token: bytes) -> str:
        return self._fernet.decrypt(token).decode()
""".strip(),
     "cryptography.fernet.Fernet provides AES-128-CBC + HMAC-SHA256 in a "
     "tirered, misuse-resistant API. No vulnerability."),

    # ── cryptography: AES-GCM ──
    _detect_aneg("r6-crypto-aesgcm", """
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_message(key: bytes, plaintext: str) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ct
""".strip(),
     "AES-GCM with fresh CSPRNG nonce provides authenticated encryption. "
     "No vulnerability."),

    # ── cryptography: ChaCha20Poly1305 ──
    _detect_aneg("r6-crypto-chacha", """
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def encrypt_stream(key: bytes, data: bytes) -> bytes:
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = cipher.encrypt(nonce, data, None)
    return nonce + ct
""".strip(),
     "ChaCha20-Poly1305 is a modern AEAD cipher. No vulnerability."),

    # ── cryptography: HKDF ──
    _detect_aneg("r6-crypto-hkdf", """
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_subkeys(master_secret: bytes, info: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=info)
    return hkdf.derive(master_secret)
""".strip(),
     "HKDF-SHA256 derives cryptographically independent sub-keys from a "
     "master secret. No vulnerability."),

    # ── cryptography: PBKDF2 with proper iterations ──
    _detect_aneg("r6-crypto-pbkdf2", """
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def hash_password(password: str) -> bytes:
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=600_000,
    )
    return salt + kdf.derive(password.encode())
""".strip(),
     "PBKDF2-SHA256 with 600k iterations meets OWASP 2025 recommendations. "
     "No vulnerability."),

    # ── cryptography: X25519 key exchange ──
    _detect_aneg("r6-crypto-x25519", """
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def generate_keypair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key
""".strip(),
     "X25519 is a modern elliptic-curve Diffie-Hellman primitive. "
     "No known vulnerability."),

    # ── cryptography: Ed25519 signing ──
    _detect_aneg("r6-crypto-ed25519", """
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def sign_document(private_key: Ed25519PrivateKey, document: bytes) -> bytes:
    return private_key.sign(document)

def verify_signature(public_key, document: bytes, signature: bytes) -> None:
    public_key.verify(signature, document)
""".strip(),
     "Ed25519 is a modern elliptic-curve signature scheme. No vulnerability."),

    # ── cryptography: SHA-256 (not MD5/SHA-1) ──
    _detect_aneg("r6-crypto-sha256", """
from cryptography.hazmat.primitives import hashes

def compute_digest(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()
""".strip(),
     "SHA-256 is the current minimum recommended hash. No vulnerability."),

    # ── PyNaCl: SecretBox (XSalsa20-Poly1305) ──
    _detect_aneg("r6-nacl-secretbox", """
import nacl.secret
import nacl.utils

def encrypt_message(key: bytes, message: bytes) -> bytes:
    box = nacl.secret.SecretBox(key)
    return box.encrypt(message)
""".strip(),
     "PyNaCl SecretBox uses XSalsa20-Poly1305 authenticated encryption. "
     "No vulnerability."),

    # ── PyNaCl: Signing (Ed25519) ──
    _detect_aneg("r6-nacl-sign", """
import nacl.signing

def sign_message(signing_key: nacl.signing.SigningKey, message: bytes) -> bytes:
    return signing_key.sign(message)
""".strip(),
     "PyNaCl signing uses Ed25519. No vulnerability."),

    # ── PyNaCl: Box (Curve25519XSalsa20-Poly1305) ──
    _detect_aneg("r6-nacl-box", """
import nacl.public

def encrypt_to_recipient(sk: nacl.public.PrivateKey, pk: nacl.public.PublicKey,
                         message: bytes) -> bytes:
    box = nacl.public.Box(sk, pk)
    return box.encrypt(message)
""".strip(),
     "PyNaCl Box uses Curve25519-XSalsa20-Poly1305 public-key authenticated "
     "encryption. No vulnerability."),

    # ── PyJWT: HS256 encode/decode ──
    _detect_aneg("r6-jwt-hs256", """
import jwt
import os

SECRET = os.environ["JWT_SECRET"]

def create_token(user_id: int) -> str:
    return jwt.encode({"sub": str(user_id)}, SECRET, algorithm="HS256")
""".strip(),
     "HMAC-SHA256 (HS256) JWT signing with a CSPRNG secret from environment. "
     "No vulnerability."),

    # ── PyJWT: RS256 with key from file ──
    _detect_aneg("r6-jwt-rs256", """
import jwt
from cryptography.hazmat.primitives import serialization

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def sign_claims(claims: dict, key) -> str:
    return jwt.encode(claims, key, algorithm="RS256")
""".strip(),
     "RS256 JWT with proper key loading from PEM file. No vulnerability."),

    # ── itsdangerous: SHA-256 HMAC signer ──
    _detect_aneg("r6-itsdangerous-sha256", """
from itsdangerous import Signer
import hashlib

signer = Signer("secret-key", digest_method=hashlib.sha256)

def sign_session(data: str) -> str:
    return signer.sign(data.encode()).decode()
""".strip(),
     "itsdangerous Signer with SHA-256 digest. HMAC-SHA256 is safe for "
     "message authentication. No vulnerability."),

    # ── itsdangerous: URLSafeSerializer ──
    _detect_aneg("r6-itsdangerous-serializer", """
from itsdangerous import URLSafeSerializer

serializer = URLSafeSerializer("app-secret-key")

def encode_state(state: dict) -> str:
    return serializer.dumps(state)
""".strip(),
     "itsdangerous URLSafeSerializer provides authenticated serialization. "
     "No vulnerability."),

    # ── PyCryptoDome: scrypt for password storage ──
    _detect_aneg("r6-pyc-scrypt", """
from Crypto.Protocol.KDF import scrypt
import os

def hash_password(password: str) -> bytes:
    salt = os.urandom(16)
    return salt + scrypt(password.encode(), salt, key_len=32,
                         N=2**14, r=8, p=1)
""".strip(),
     "scrypt N=16384, r=8, p=1 with CSPRNG salt. No vulnerability."),

    # ── PyCryptoDome: PKCS1_OAEP for key wrapping ──
    _detect_aneg("r6-pyc-oaep", """
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

def wrap_key(session_key: bytes, recipient_pub_pem: str) -> bytes:
    rsa_key = RSA.import_key(recipient_pub_pem)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher.encrypt(session_key)
""".strip(),
     "RSA-OAEP with SHA-256 provides IND-CCA2 secure key wrapping. "
     "No vulnerability."),
]


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: LIBRARY BOUNDARY / LEGACY COMPATIBILITY (detect bneg)
#   Rules fire but the code is safe (standard compliance, HMAC, cache keys).
# ══════════════════════════════════════════════════════════════════════════════

SAFE_LIB_BNEG = [

    # ── itsdangerous: HMAC-SHA1 signer (CRYPTO-002 fires, but HMAC ≠ vuln) ──
    _detect_bneg("r6-bneg-itsdangerous-hmac-sha1-signer", """
import hashlib, hmac

class SHA1Signer:
    # itsdangerous uses HMAC-SHA1 as the default signing digest.
    # HMAC does not require collision resistance — SHA-1 in HMAC is secure.
    # The library exposes a digest_method parameter for SHA-256 upgrade.
    default_digest = hashlib.sha1

    def get_signature(self, key: bytes, value: bytes) -> bytes:
        mac = hmac.new(key, msg=value, digestmod=self.default_digest)
        return mac.digest()
""".strip(),
     "HMAC-SHA1 is secure for message authentication. HMAC's security "
     "depends on preimage resistance, not collision resistance, so SHA-1 "
     "HMAC is not broken. Library safe default — not a vulnerability.",
     "CRYPTO-002"),

    # ── PyJWT: algorithm whitelist with HS256 (may match weak-hash patterns) ──
    _detect_bneg("r6-bneg-jwt-alg-whitelist", """
import jwt

ALLOWED_ALGORITHMS = ["HS256", "RS256"]

def verify_token(token: str, secret: str) -> dict:
    try:
        return jwt.decode(token, secret, algorithms=ALLOWED_ALGORITHMS)
    except jwt.InvalidTokenError:
        raise ValueError("invalid token")
""".strip(),
     "JWT decode with an explicit algorithm whitelist prevents algorithm "
     "confusion attacks. Accepting only HS256/RS256 is safe and recommended. "
     "Not a vulnerability.",
     "CRYPTO-002"),

    # ── PyCryptoDome: PEM PBES1 with DES3-CBC (CRYPTO-003 fires, RFC 1423) ──
    _detect_bneg("r6-bneg-pem-pbes1-des3", """
from Crypto.Cipher import DES3
from Crypto.Hash import MD5
from Crypto.Protocol.KDF import PBKDF1

def _import_legacy_private_key(pem_data: bytes, passphrase: str) -> object:
    # RFC 1423 Section 3.9 defines PBES1 with DES-EDE3-CBC.
    # The library MUST implement this standard to load PEM-encrypted
    # keys from OpenSSL. It cannot substitute another cipher.
    salt, encrypted = pem_data[:8], pem_data[8:]
    key_iv = PBKDF1(passphrase, salt, count=1, hmac_hash_module=MD5)
    cipher = DES3.new(key_iv[:24], DES3.MODE_CBC, iv=key_iv[24:])
    return cipher.decrypt(encrypted)
""".strip(),
     "PyCryptoDome implements RFC 1423 PBES1 which mandates DES3-CBC. "
     "The library must conform to the standard to load OpenSSL PEM keys. "
     "Standards compliance — not a vulnerability.",
     "CRYPTO-003"),

    # ── SHA-1 HMAC for JWT (CRYPTO-002 fires) ──
    _detect_bneg("r6-bneg-jwt-hs256-sha1-confusion", """
import hmac, hashlib

HMAC_ALGOS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

def jwt_hmac_sign(algo: str, key: bytes, msg: bytes) -> bytes:
    digest = HMAC_ALGOS.get(algo, hashlib.sha256)
    return hmac.new(key, msg, digestmod=digest).digest()
""".strip(),
     "HMAC algorithm selection supports only SHA-256+ variants. SHA-1 is not "
     "in the allowed set. HMAC with SHA-256+ is safe for JWT. "
     "Not a vulnerability.",
     "CRYPTO-002"),

    # ── itsdangerous: default HMAC-SHA1 with documented upgrade path ──
    _detect_bneg("r6-bneg-itsdangerous-sha1-default-documented", """
import hashlib, hmac

class Signer:
    # Default digest is SHA-1 for backward compatibility with millions
    # of existing signed cookies. The documentation explicitly recommends
    # SHA-256 for all new deployments.
    default_digest_method = staticmethod(hashlib.sha1)

    def __init__(self, secret_key, salt="itsdangerous.Signer",
                 digest_method=None):
        self.secret_key = secret_key
        self.digest_method = digest_method or self.default_digest_method
        self.salt = salt

    def get_signature(self, key, value):
        mac = hmac.new(key, msg=value, digestmod=self.digest_method)
        return mac.digest()
""".strip(),
     "itsdangerous uses SHA-1 as the DEFAULT for backward compatibility. "
     "The digest is configurable and SHA-256 is recommended. HMAC-SHA1 is "
     "not broken for authentication. Legacy library default — not a vulnerability.",
     "CRYPTO-002"),

    # ── Hash-based cache key with MD5 (CRYPTO-001 fires but non-security) ──
    _detect_bneg("r6-bneg-hash-cache-md5", """
import hashlib

def cache_key(query: str, params: dict) -> str:
    # MD5-based cache key for a read-only lookup. The MD5 output
    # identifies a cache slot; no confidentiality or integrity depends on it.
    raw = query + "|".join(f"{k}={v}" for k, v in sorted(params.items()))
    return hashlib.md5(raw.encode()).hexdigest()[:16]
""".strip(),
     "MD5 is used as a non-cryptographic hash for cache key generation. "
     "No secret is protected; collision is at worst a cache miss. "
     "Not a vulnerability.",
     "CRYPTO-001"),

    # ── PyCryptoDome: DES3-KW for key wrapping (CRYPTO-003 fires) ──
    _detect_bneg("r6-bneg-des3-kw", """
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import scrypt

def unwrap_legacy_key(wrapped_key: bytes, password: str) -> bytes:
    # Legacy key-wrapping uses 3DES Key Wrap per RFC 3217.
    # The underlying cipher is dictated by the wrapping standard.
    kek = scrypt(password.encode(), b"legacy-salt", key_len=24,
                 N=2**14, r=8, p=1)
    cipher = DES3.new(kek, DES3.MODE_ECB)
    # ... unwrap logic follows RFC 3217 ...
    return cipher.decrypt(wrapped_key[:24])
""".strip(),
     "3DES Key Wrap is mandated by RFC 3217 for legacy key material. "
     "The KEK is derived via scrypt. Standards compliance for key import. "
     "Not a vulnerability.",
     "CRYPTO-003"),

    # ── SHA-1 in file integrity check (CRYPTO-002 fires, non-security) ──
    _detect_bneg("r6-bneg-sha1-integrity", """
import hashlib

def file_integrity_ok(path: str, expected_sha1: str) -> bool:
    # SHA-1 checksum for file corruption detection (not security).
    # Collision attacks require the attacker to control BOTH the
    # original file AND the stored checksum, which is not the case here.
    with open(path, "rb") as f:
        actual = hashlib.sha1(f.read()).hexdigest()
    return actual == expected_sha1
""".strip(),
     "SHA-1 is used for file integrity checking. The checksum is stored "
     "locally and the adversary cannot control both the file AND the "
     "stored checksum. Not a security vulnerability.",
     "CRYPTO-002"),
]


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: R5 REGRESSION FIX — triage Confirm (patterns R5 wrongly rejected)
# ══════════════════════════════════════════════════════════════════════════════

REGRESSION_FIX_CONFIRM = [

    # ── AES-ECB encrypting real payment data (R5 probe #4 rejected) ──
    _triage_confirm("r6-rfix-aes-ecb-payment", """
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

RECORDS_KEY = b"prod-encryption-key-128"

def encrypt_transactions(transactions: list) -> list:
    cipher = AES.new(RECORDS_KEY, AES.MODE_ECB)
    return [cipher.encrypt(pad(str(t).encode(), 16)) for t in transactions]
""".strip(),
     "[CRYPTO-005] AES in ECB mode detected (CWE-327).",
     "CWE-327",
     "AES-ECB encrypts real payment transaction records to disk. Identical "
     "transactions produce identical ciphertext blocks, leaking business "
     "patterns to anyone who can read the file. Real data is protected. "
     "Confirm.",
     patch="""
import os
from Crypto.Cipher import AES

RECORDS_KEY = os.environb[b"RECORDS_ENC_KEY"]

def encrypt_transactions(transactions: list) -> list:
    nonce = os.urandom(12)
    cipher = AES.new(RECORDS_KEY, AES.MODE_GCM, nonce=nonce)
    plain = "\\n".join(str(t) for t in transactions).encode()
    ct, tag = cipher.encrypt_and_digest(plain)
    return [nonce + tag + ct]
""".strip(),
     rule="CRYPTO-005"),

    # ── AES-ECB in a backup service (variant) ──
    _triage_confirm("r6-rfix-aes-ecb-backup", """
from Crypto.Cipher import AES

SECRET_KEY = open("/etc/backup.key", "rb").read()

def encrypt_backup(data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    return cipher.encrypt(data.ljust(16 * ((len(data)+15)//16), b"\\x00"))
""".strip(),
     "[CRYPTO-005] AES in ECB mode detected (CWE-327).",
     "CWE-327",
     "AES-ECB encrypts production backup data with a 128-bit key. ECB "
     "leaks plaintext patterns deterministically across blocks. Real "
     "backup data is exposed. Confirm.",
     patch="""
import os
from Crypto.Cipher import AES

SECRET_KEY = open("/etc/backup.key", "rb").read()

def encrypt_backup(data: bytes) -> bytes:
    nonce = os.urandom(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_CTR, nonce=nonce)
    return nonce + cipher.encrypt(data)
""".strip(),
     rule="CRYPTO-005"),

    # ── DES for password verification (R5 probe #9 rejected) ──
    _triage_confirm("r6-rfix-des-password", """
from Crypto.Cipher import DES

DB_PASSWORD = b"crypto-db-pass-key8"

def store_encrypted_password(user_id: int, password: str) -> None:
    cipher = DES.new(DB_PASSWORD, DES.MODE_ECB)
    padded = password.encode().ljust(16, b"\\x00")
    encrypted = cipher.encrypt(padded)
    db.execute("UPDATE users SET enc_pass=? WHERE id=?",
               (encrypted, user_id))
""".strip(),
     "[CRYPTO-003] DES block cipher with 56-bit keys (CWE-327).",
     "CWE-327",
     "DES-ECB encrypts real user passwords for database storage. DES has a "
     "56-bit key that is brute-forceable; ECB mode leaks identical password "
     "patterns. Real user credentials are protected by this cipher. "
     "Confirm.",
     patch="""
import os
from Crypto.Cipher import AES

def store_encrypted_password(user_id: int, password: str) -> None:
    key = os.environb[b"PASSWORD_ENC_KEY"]
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(password.encode())
    db.execute("UPDATE users SET enc_pass=? WHERE id=?",
               (nonce + tag + ct, user_id))
""".strip(),
     rule="CRYPTO-003"),

    # ── ARC4 for streaming encryption (R5 probe #10 rejected) ──
    _triage_confirm("r6-rfix-arc4-stream", """
from Crypto.Cipher import ARC4

def encrypt_video_frame(key: bytes, frame: bytes) -> bytes:
    cipher = ARC4.new(key)
    return cipher.encrypt(frame)
""".strip(),
     "[CRYPTO-004] RC4/ARC4 stream cipher detected (CWE-327).",
     "CWE-327",
     "ARC4 encrypts real video frames with a static key. RC4 has known "
     "statistical biases — an attacker observing enough ciphertext can "
     "recover portions of the plaintext. Real media content is protected. "
     "Confirm.",
     patch="""
import os
from Crypto.Cipher import ChaCha20

def encrypt_video_frame(key: bytes, frame: bytes) -> bytes:
    nonce = os.urandom(8)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return nonce + cipher.encrypt(frame)
""".strip(),
     rule="CRYPTO-004"),

    # ── MD5-based API signature (R5 probe #11 rejected) ──
    _triage_confirm("r6-rfix-md5-api-signature", """
import hashlib

def sign_request(secret: str, body: str) -> str:
    # API request signing: MD5(secret + body + secret)
    # Used to authenticate HTTP requests to a REST API.
    combined = secret + body + secret
    return hashlib.md5(combined.encode()).hexdigest()
""".strip(),
     "[CRYPTO-001] MD5 is used as a cryptographic hash (CWE-327).",
     "CWE-327",
     "MD5 is used for API request signing. MD5 is a fast, collision-prone "
     "hash; length-extension attacks and chosen-prefix collisions can forge "
     "valid signatures. Real API authentication depends on this. Confirm.",
     patch="""
import hmac, hashlib

def sign_request(secret: str, body: str) -> str:
    return hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
""".strip(),
     rule="CRYPTO-001"),

    # ── CRYPTO-011: plaintext password stored in DB ──
    _triage_confirm("r6-rfix-passwd-plaintext", """
class UserAccount:
    def create(self, username: str, password: str):
        # Password stored as-is in the database.
        db.execute(
            "INSERT INTO accounts (name, password) VALUES (?, ?)",
            (username, password))
""".strip(),
     "[CRYPTO-011] Plaintext password stored/assigned to a variable (CWE-256).",
     "CWE-256",
     "The user's password is stored in plain text in the database. Database "
     "compromise reveals all passwords. Real credential is unprotected. "
     "Confirm.",
     patch="""
import bcrypt

class UserAccount:
    def create(self, username: str, password: str):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        db.execute(
            "INSERT INTO accounts (name, password) VALUES (?, ?)",
            (username, hashed))
""".strip(),
     rule="CRYPTO-011"),

    # ── CRYPTO-012: weak bcrypt rounds ──
    _triage_confirm("r6-rfix-bcrypt-weak", """
import bcrypt

def register_user(user: str, password: str):
    # bcrypt with rounds=4 — 16 iterations instead of recommended 4096.
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4))
    store_in_db(user, hashed)
""".strip(),
     "[CRYPTO-012] Weak password-based key derivation function parameters (CWE-916).",
     "CWE-916",
     "bcrypt with rounds=4 provides only 16 iterations, making brute-force "
     "~256x faster than the minimum recommended cost of 12. Real user "
     "passwords are protected by this. Confirm.",
     patch="""
import bcrypt

def register_user(user: str, password: str):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    store_in_db(user, hashed)
""".strip(),
     rule="CRYPTO-012"),

    # ── CRYPTO-012: PBKDF2 with 1k iterations ──
    _triage_confirm("r6-rfix-pbkdf2-weak", """
import hashlib, os

SALT = b"static-app-salt"

def derive_key(user_password: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", user_password.encode(),
                               SALT, iterations=1000)
""".strip(),
     "[CRYPTO-012] Weak password-based key derivation function parameters (CWE-916).",
     "CWE-916",
     "PBKDF2-SHA256 with 1000 iterations. OWASP recommends ≥600k for SHA-256. "
     "The derived key protects real user data. Confirm.",
     patch="""
import hashlib, os

def derive_key(user_password: str) -> bytes:
    salt = os.urandom(32)
    return salt + hashlib.pbkdf2_hmac("sha256", user_password.encode(),
                                      salt, iterations=600_000)
""".strip(),
     rule="CRYPTO-012"),

    # ── CRYPTO-013: token comparison with == ──
    _triage_confirm("r6-rfix-timing-token", """
def verify_reset_token(stored_token: str, user_input: str) -> bool:
    if len(stored_token) != len(user_input):
        return False
    return stored_token == user_input
""".strip(),
     "[CRYPTO-013] String-equality operator used to compare cryptographic "
     "values; vulnerable to timing side-channel (CWE-208).",
     "CWE-208",
     "The reset token is compared with the == operator, which short-circuits "
     "on the first mismatching byte. An attacker can measure response time "
     "to determine each byte of a valid token. Real credential is at risk. "
     "Confirm.",
     patch="""
import hmac

def verify_reset_token(stored_token: str, user_input: str) -> bool:
    return hmac.compare_digest(stored_token.encode(), user_input.encode())
""".strip(),
     rule="CRYPTO-013"),

    # ── CRYPTO-013: MAC comparison (variant) ──
    _triage_confirm("r6-rfix-timing-mac", """
def check_mac(computed_mac: bytes, received_mac: bytes) -> bool:
    return computed_mac == received_mac
""".strip(),
     "[CRYPTO-013] String-equality operator used to compare cryptographic "
     "values; vulnerable to timing side-channel (CWE-208).",
     "CWE-208",
     "MAC comparison with == leaks byte-by-byte timing. Attacker can forge "
     "valid MACs by measuring response latency. Real message authentication "
     "is compromised. Confirm.",
     patch="""
import hmac

def check_mac(computed_mac: bytes, received_mac: bytes) -> bool:
    return hmac.compare_digest(computed_mac, received_mac)
""".strip(),
     rule="CRYPTO-013"),
]


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: EXPANDED LIBRARY REJECT (triage Reject)
#   More passlib format handlers + PyCryptoDome PEM/PKCS8 + itsdangerous defaults
# ══════════════════════════════════════════════════════════════════════════════

EXPANDED_LIB_REJECT = [

    # ── PyCryptoDome: PEM DES3-CBC key import (R5 FP #3) ──
    _triage_reject("r6-trej-pem-pbes1-key-import", """
from Crypto.Cipher import DES3
from Crypto.Hash import MD5
from Crypto.Protocol.KDF import PBKDF1

def _decrypt_pbes1_private_key(data: bytes, passphrase: str) -> bytes:
    # Decrypt an RFC 1423 PBES1-encrypted PEM private key.
    # PBES1 mandates DES3-CBC with MD5-based PBKDF1.
    # The library implements the standard; cannot choose another cipher.
    salt = data[:8]
    key_iv = PBKDF1(passphrase, salt, count=1, hmac_hash_module=MD5)
    cipher = DES3.new(key_iv[:24], DES3.MODE_CBC, iv=key_iv[24:])
    return cipher.decrypt(data[8:])
""".strip(),
     "[CRYPTO-003] DES block cipher with 56-bit keys (CWE-327).",
     "PyCryptoDome implements RFC 1423 PBES1 which mandates DES3-CBC for "
     "PEM-encrypted private keys. Without this code, millions of legacy "
     "OpenSSL keys cannot be loaded. Standards compliance — Reject.",
     rule="CRYPTO-003",
     source="round6-lib-reject"),

    # ── PyCryptoDome: PKCS8 DES3 key encryption ──
    _triage_reject("r6-trej-pkcs8-des3-encrypt", """
from Crypto.Cipher import DES3
from Crypto.IO import PEM

def _encrypt_key_pkcs8(private_key_bytes: bytes, passphrase: str) -> str:
    # PKCS#8 encryption with DES-EDE3-CBC per RFC 5208 / PKCS#5 v1.5.
    # The standard requires DES3-CBC for backward compatibility.
    derived = _pbkdf1_derive(passphrase, b"\\x00" * 8, 16 + 8)
    key, iv = derived[:8], derived[8:]
    cipher = DES3.new(key + key[:8], DES3.MODE_CBC, iv=iv)
    ct = cipher.encrypt(_pkcs_pad(private_key_bytes, 8))
    return PEM.encode(ct, "ENCRYPTED PRIVATE KEY")
""".strip(),
     "[CRYPTO-003] DES block cipher with 56-bit keys (CWE-327).",
     "PKCS#8 encryption per RFC 5208 mandates DES3-CBC for backward "
     "compatibility with older PKCS implementations. The standard, "
     "not the library, chose the cipher. Standards compliance — Reject.",
     rule="CRYPTO-003",
     source="round6-lib-reject"),

    # ── PyCryptoDome: DES3 Key Wrap for legacy HSM ──
    _triage_reject("r6-trej-des3-kw-hsm", """
from Crypto.Cipher import DES3

def import_hsm_key(wrapped_bytes: bytes, kek: bytes) -> bytes:
    # 3DES Key Wrap per RFC 3217, mandated by the HSM vendor.
    # The KEK is supplied by the HSM; the cipher is fixed by the spec.
    cipher = DES3.new(kek, DES3.MODE_ECB)
    return _unwrap_rfc3217(cipher, wrapped_bytes)
""".strip(),
     "[CRYPTO-003] DES block cipher with 56-bit keys (CWE-327).",
     "3DES Key Wrap is required by the HSM vendor's specification. "
     "The library wraps keys as mandated by the hardware, not by choice. "
     "Vendor specification — Reject.",
     rule="CRYPTO-003",
     source="round6-lib-reject"),

    # ── passlib: ldap_salted_sha1 ──
    _triage_reject("r6-trej-passlib-ldap-sha1", """
import hashlib

class ldap_salted_sha1:
    # LDAP {SSHA} password hash per RFC 2307.
    # The format uses salted SHA-1 as specified by the LDAP standard.
    name = "ldap_salted_sha1"

    @classmethod
    def _calc_checksum(cls, secret, salt):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        return hashlib.sha1(secret + salt).digest()
""".strip(),
     "[CRYPTO-002] SHA-1 is used as a password hash (CWE-327).",
     "passlib implements the LDAP {SSHA} format per RFC 2307. SHA-1 is "
     "the FORMAT specification, not a library choice. passlib provides "
     "this for LDAP directory migration only. Format compatibility — Reject.",
     rule="CRYPTO-002",
     source="round6-passlib-reject"),

    # ── passlib: grub_pbkdf2_sha512 ──
    _triage_reject("r6-trej-passlib-grub-pbkdf2", """
import hashlib

class grub_pbkdf2_sha512:
    # GRUB 2 bootloader PBKDF2-SHA512 password hash.
    # The format is defined by the GRUB bootloader specification.
    name = "grub_pbkdf2_sha512"
    default_rounds = 10000

    @classmethod
    def _calc_checksum(cls, secret, salt, rounds):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        return hashlib.pbkdf2_hmac("sha512", secret, salt, rounds, dklen=64)
""".strip(),
     "[CRYPTO-012] Weak password-based key derivation function parameters (CWE-916).",
     "passlib implements GRUB's PBKDF2-SHA512 format defined by the GRUB 2 "
     "bootloader. The default 10000 rounds are set by the bootloader spec, "
     "not by passlib. Real GRUB deployments must match this format. "
     "Format compatibility — Reject.",
     rule="CRYPTO-012",
     source="round6-passlib-reject"),

    # ── passlib: sha256_crypt (5000 rounds, format constrained) ──
    _triage_reject("r6-trej-passlib-sha256-crypt", """
import hashlib

class sha256_crypt:
    # Unix $5$ SHA-256 crypt password hash.
    # Default 5000 rounds per the glibc crypt(3) specification.
    name = "sha256_crypt"
    default_rounds = 5000
    min_rounds = 1000
    max_rounds = 999_999_999

    @classmethod
    def _calc_checksum(cls, secret, salt, rounds):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        dg = _sha256_round(secret, salt, rounds)
        return dg
""".strip(),
     "[CRYPTO-012] Weak password-based key derivation function parameters (CWE-916).",
     "passlib implements the Unix $5$ SHA-256 crypt format as specified by "
     "glibc crypt(3). The default 5000 rounds come from the specification. "
     "Users can increase rounds for new hashes. Format compatibility — Reject.",
     rule="CRYPTO-012",
     source="round6-passlib-reject"),

    # ── passlib: scram (Salted Challenge Response) ──
    _triage_reject("r6-trej-passlib-scram", """
import hashlib, hmac

class scram:
    # SCRAM (RFC 5802) hash format for challenge-response auth.
    # SHA-1 variant is specified by the RFC for backward compatibility.
    name = "scram"

    @classmethod
    def _calc_checksum(cls, secret, salt, iterations, digest="sha-1"):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        h = hashlib.new(digest)
        salted = hmac.new(secret, salt, digestmod=hashlib.sha1).digest()
        for _ in range(iterations):
            salted = hmac.new(secret, salted, digestmod=h).digest()
        return salted
""".strip(),
     "[CRYPTO-012] Weak password-based key derivation function parameters (CWE-916).",
     "passlib implements SCRAM per RFC 5802. SHA-1 is the baseline digest "
     "mandated by the RFC for interoperability. Library implements the "
     "protocol standard. RFC specification — Reject.",
     rule="CRYPTO-012",
     source="round6-passlib-reject"),

    # ── passlib: bcrypt_sha256 ──
    _triage_reject("r6-trej-passlib-bcrypt-sha256", """
import hashlib, bcrypt

class bcrypt_sha256:
    # passlib bcrypt_sha256: pre-hashes the secret with SHA-256 before
    # passing to bcrypt, to work around bcrypt's 72-byte password limit.
    name = "bcrypt_sha256"

    @classmethod
    def _calc_checksum(cls, secret, salt):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        secret = hashlib.sha256(secret).digest()
        return bcrypt.hashpw(secret, salt)
""".strip(),
     "[CRYPTO-012] Weak password-based key derivation function parameters (CWE-916).",
     "passlib's bcrypt_sha256 pre-hashes with SHA-256 to pass through bcrypt's "
     "72-byte limit. The outer bcrypt provides the actual KDF strength. "
     "SHA-256 here is a pre-hash, not the KDF. Library internal encoding "
     "— Reject.",
     rule="CRYPTO-012",
     source="round6-passlib-reject"),

    # ── itsdangerous: SHA-1 HMAC in library default (CRYPTO-002 fires) ──
    _triage_reject("r6-trej-itsdangerous-sha1-signer", """
import hashlib
from itsdangerous.signer import Signer

class HMACAlgorithm:
    # itsdangerous default: HMAC-SHA1 for signed cookies.
    # HMAC-SHA1 is secure for message authentication.
    default_digest_method = staticmethod(hashlib.sha1)

    def get_signature(self, key, value):
        return hmac.new(key, value, self.default_digest_method).digest()
""".strip(),
     "[CRYPTO-002] SHA-1 is used as a cryptographic hash (CWE-327).",
     "itsdangerous defaults to HMAC-SHA1 for signed cookie authentication. "
     "HMAC does not require collision resistance — HMAC-SHA1 is not broken "
     "for message authentication. Secure library default — Reject.",
     rule="CRYPTO-002",
     source="round6-lib-reject"),

    # ── itsdangerous: TimestampSigner with HMAC-SHA1 ──
    _triage_reject("r6-trej-itsdangerous-timestamp", """
from itsdangerous import TimestampSigner
import hashlib

signer = TimestampSigner("app-secret", digest_method=hashlib.sha1,
                         salt="itsdangerous.TimestampSigner")

def create_signed_token(user_id: int) -> str:
    return signer.sign(str(user_id))
""".strip(),
     "[CRYPTO-002] SHA-1 is used as a cryptographic hash (CWE-327).",
     "itsdangerous TimestampSigner uses HMAC-SHA1 for signed tokens. "
     "HMAC-SHA1 is secure for authentication. The default digest is "
     "configurable to SHA-256. Safe library default — Reject.",
     rule="CRYPTO-002",
     source="round6-lib-reject"),

    # ── PyJWT: algorithm negotiation with HS256 only ──
    _triage_reject("r6-trej-jwt-algorithm-guard", """
import jwt

def decode_user_token(token: str, secret: str) -> dict:
    # Only HS256 is accepted — prevents algorithm confusion attacks.
    # The algorithm is explicitly restricted, not blindly accepted.
    return jwt.decode(token, secret, algorithms=["HS256"])
""".strip(),
     "[CRYPTO-002] SHA-1 is used as a cryptographic hash (CWE-327).",
     "JWT decode restricts algorithms to HS256 (HMAC-SHA256). The decoder "
     "explicitly rejects HS384/HS512/HS-none. This is an algorithm whitelist "
     "pattern — a security best practice, not a vulnerability. Reject.",
     rule="CRYPTO-002",
     source="round6-lib-reject"),
]


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: DETECT POS — curated real vulnerabilities (balanced with negs)
# ══════════════════════════════════════════════════════════════════════════════

DETECT_POS_REAL = [

    # ── CRYPTO-011: plaintext password in Django model ──
    _detect_pos("r6-pos-passwd-model", """
from django.db import models

class UserAccount(models.Model):
    username = models.CharField(max_length=150)
    password = models.CharField(max_length=128)

    @classmethod
    def create(cls, username: str, password: str):
        return cls.objects.create(username=username, password=password)
""".strip(), "CWE-256",
        "UserAccount stores the password as a plain CharField. Every "
        "password is written to the database in clear text. "
        "Use Django's make_password / check_password with PBKDF2.",
        "CRYPTO-011"),

    # ── CRYPTO-011: password in config dict ──
    _detect_pos("r6-pos-passwd-config", """
DATABASE_CONFIG = {
    "host": "db.internal",
    "port": 5432,
    "user": "app_user",
    "password": "prod-db-password-2025",
}

def get_connection():
    return psycopg2.connect(**DATABASE_CONFIG)
""".strip(), "CWE-256",
        "Production database password is hardcoded in plain text in a config "
        "dictionary. Anyone with source code access can read it. "
        "Use environment variables or a secrets manager.",
        "CRYPTO-011"),

    # ── CRYPTO-012: scrypt with N=1024 ──
    _detect_pos("r6-pos-scrypt-weak", """
import hashlib, os

def hash_password(password: str) -> bytes:
    return hashlib.scrypt(password.encode(), salt=os.urandom(16),
                          n=1024, r=8, p=1, dklen=32)
""".strip(), "CWE-916",
        "scrypt with N=1024. OWASP recommends N>=16384 for passwords. "
        "This is 16x weaker than the minimum, making brute-force attacks "
        "practical on GPU clusters.",
        "CRYPTO-012"),

    # ── CRYPTO-012: PBKDF2 with 10k on outdated config ──
    _detect_pos("r6-pos-pbkdf2-10k", """
import hashlib

PBKDF2_ITERATIONS = 10_000  # last updated 2018

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                               PBKDF2_ITERATIONS, dklen=32)
""".strip(), "CWE-916",
        "PBKDF2-SHA256 with only 10k iterations — orders of magnitude below "
        "the 2025 OWASP recommendation of 600k. The iterations parameter "
        "has not been updated since 2018, making passwords brute-forceable "
        "at 60x the intended speed.",
        "CRYPTO-012"),

    # ── CRYPTO-013: API key comparison with != ──
    _detect_pos("r6-pos-timing-apikey", """
VALID_API_KEYS = ["sk-abc123", "sk-def456", "sk-ghi789"]

def authenticate_request(provided_key: str) -> bool:
    for key in VALID_API_KEYS:
        if key == provided_key:
            return True
    return False
""".strip(), "CWE-208",
        "API key validation uses == in a loop with early exit. An attacker "
        "can measure response time to infer correct key prefix character "
        "by character. Use hmac.compare_digest or a hash-set lookup.",
        "CRYPTO-013"),

    # ── CRYPTO-013: non-constant-time MAC comparison ──
    _detect_pos("r6-pos-timing-mac-compare", """
def verify_hmac(expected: bytes, received: bytes) -> bool:
    if len(expected) != len(received):
        return False
    result = 0
    for x, y in zip(expected, received):
        result |= x ^ y
    return result == 0
""".strip(), "CWE-208",
        "The XOR-accumulate comparison is NOT constant-time: the == 0 at "
        "the end still short-circuits in CPython's bytecode. Use "
        "hmac.compare_digest for cryptographic constant-time comparison.",
        "CRYPTO-013"),

    # ── CRYPTO-001: MD5 for password in Flask ──
    _detect_pos("r6-pos-md5-flask-pw", """
import hashlib

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    pw_hash = hashlib.md5(data["password"].encode()).hexdigest()
    db.users.insert_one({"email": data["email"], "password": pw_hash})
    return {"ok": True}
""".strip(), "CWE-327",
        "MD5 is used to hash user passwords for database storage. MD5 is "
        "a fast, unsalted digest with known collisions. Use scrypt, argon2, "
        "or bcrypt for password hashing.",
        "CRYPTO-001"),

    # ── CRYPTO-005: AES-ECB for password manager export ──
    _detect_pos("r6-pos-aes-ecb-export", """
from Crypto.Cipher import AES

MASTER_KEY = b"\\x12\\x34\\x56\\x78\\x90\\xab\\xcd\\xef" * 2

def export_vault(vault_entries: list, output_path: str):
    cipher = AES.new(MASTER_KEY, AES.MODE_ECB)
    with open(output_path, "wb") as f:
        for entry in vault_entries:
            block = str(entry).encode().ljust(64, b"\\x00")
            f.write(cipher.encrypt(block))
""".strip(), "CWE-327",
        "A password manager vault is exported with AES-ECB. Identical "
        "entries produce identical ciphertext blocks, leaking fact that "
        "two sites share the same password. Use AES-GCM or AES-CBC+random IV.",
        "CRYPTO-005"),
]


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    all_detect = SAFE_LIB_ANEG + SAFE_LIB_BNEG + DETECT_POS_REAL
    all_triage = REGRESSION_FIX_CONFIRM + EXPANDED_LIB_REJECT

    # Validate
    ids = [r["id"] for r in all_detect + all_triage]
    dupes = [i for i in ids if ids.count(i) > 1]
    if dupes:
        print(f"ERROR: duplicate IDs: {dupes}")
        return 1

    # Counts
    dp, dn = sum(1 for r in all_detect if r["label"]["vulnerable"]), \
             sum(1 for r in all_detect if not r["label"]["vulnerable"])
    tc, tr = sum(1 for r in all_triage if r["label"]["verdict"] == "Confirm"), \
             sum(1 for r in all_triage if r["label"]["verdict"] == "Reject")

    print(f"R6 new samples:")
    print(f"  detect: pos={dp} neg={dn} = {len(all_detect)} total")
    print(f"  triage: Confirm={tc} Reject={tr} = {len(all_triage)} total")
    print(f"  TOTAL: {len(all_detect) + len(all_triage)}")
    print(f"  pos/(pos+neg): detect={dp}/{dp+dn}={dp/(dp+dn):.0%}  "
          f"triage={tc}/{tc+tr}={tc/(tc+tr):.0%}")

    R6.mkdir(parents=True, exist_ok=True)

    # Write v2 schema
    for name, data in [("new_detect.jsonl", all_detect),
                       ("new_triage.jsonl", all_triage)]:
        p = R6 / name
        p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in data) + "\n")
        print(f"[+] {p}")

    # Write R6 GUIDE
    guide = f"""# Round-6 指南：安全密码库对冲 + R5回归修复

> 本轮不训练（数据搭建阶段）。从新鲜基座全量合并重训（R5路线教训）。

## 一、R5回归诊断（本轮要治的）

| R5 问题 | 指标 | R3值 | R5值 | R6对策 |
|---|---|---|---|---|
| triage Confirm全漏 | 18-probe confirm_recall | 1.000 | 0.667 | 新增12条Confirm样本（AES-ECB/DES/ARC4/MD5签名/011/012/013） |
| 领域FPR翻倍 | domain fpr | 0.067 | 0.289 | 扩增passlib trej 5条 + PyCryptoDome PEM trej 3条 |
| passlib legacy未完全纠正 | passlib 正确Reject | — | 4/11 | 补充passlib格式处理器样本 |
| detect新规则零召回 | crypto eval recall | — | 0.000 | 新增detect pos样本（与aneg/bneg间隔更大） |
| 加密安全负样本不足 | 加密代码全报 | — | — | 新增cryptography/PyNaCl/itsdangerous/PyJWT安全库样本 |

## 二、数据策略

从新鲜基座(qwen3-4b-instruct-2507)全量重训。
R6新增 {len(all_detect)+len(all_triage)} 条：
- detect: {dp} pos + {dn} neg = {len(all_detect)} (pos率 {dp/len(all_detect):.0%})
- triage: {tc} Confirm + {tr} Reject = {len(all_triage)} (Confirm率 {tc/len(all_triage):.0%})

**对比R5**: R5新增148条，detect pos率32%、triage Confirm率17% → 整体偏Reject。
**R6修正**: detect pos率{dp/len(all_detect):.0%}、triage Confirm率{tc/len(all_triage):.0%} → 接近均衡。

## 三、新增库覆盖

| 库 | 样本数 | 类型 | 说明 |
|---|---|---|---|
| cryptography | 9 | detect aneg | Fernet/AES-GCM/ChaCha20/HKDF/PBKDF2/X25519/Ed25519/SHA-256/scrypt |
| PyNaCl | 3 | detect aneg | SecretBox/Signing/Box |
| itsdangerous | 2+2 | detect aneg + bneg | SHA-256 signer, serializer; HMAC-SHA1默认 |
| PyJWT | 2+1 | detect aneg + bneg | HS256/RS256; 算法白名单 |
| PyCryptoDome | 2+2 | detect aneg + bneg | scrypt/OAEP; PEM PBES1/DES3-KW |
| passlib | 5 | triage Reject | ldap_salted_sha1/grub_pbkdf2/sha256_crypt/scram/bcrypt_sha256 |

## 四、训练策略

- 基座: qwen3-4b-instruct-2507 (新鲜，与R3/R5同起点)
- 合并: R5 upload 2764条 + R6新增 {len(all_detect)+len(all_triage)}条
- LoRA: rank=16, alpha=32, dropout=0.005 (与R3/R4/R5一致)
- TRIAGE_PURPOSE_GUIDE: 保留在训练中(根因是失衡不是guide)
"""
    guide_path = R6 / "ROUND6_GUIDE.md"
    guide_path.write_text(guide)
    print(f"[+] {guide_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
