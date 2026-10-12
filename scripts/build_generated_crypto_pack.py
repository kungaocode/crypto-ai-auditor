#!/usr/bin/env python3
"""Build a self-contained Python crypto training and smoke-test pack.

The pack is intentionally hand-authored and de-identified. It covers all
CRYPTO-001..013 rule families, includes safe implementations and benign weak-
primitive negatives, and emits both the v2 source schema and chatml upload
splits. Every generated sample remains ``verified=false`` because it has not
undergone independent security review.
"""

from __future__ import annotations

import json
import shutil
import sys
import textwrap
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.prepare_sft_data import build_messages  # noqa: E402

OUTPUT_DIR = ROOT / "data" / "generated_crypto_pack"
PYTHON_DIR = OUTPUT_DIR / "python"
SOURCE_DIR = OUTPUT_DIR / "source"
UPLOAD_DIR = OUTPUT_DIR / "upload"
SOURCE = "generated-crypto-training-pack-v1"


def code(value: str) -> str:
    return textwrap.dedent(value).strip() + "\n"


DETECT_SAMPLES = [
    {
        "slug": "md5-password-digest",
        "split": "train",
        "rule": "CRYPTO-001",
        "category": "hash",
        "vulnerable": True,
        "cwe": "CWE-327",
        "severity": "WARNING",
        "explanation": (
            "MD5 is used to derive a password verifier. MD5 is collision-broken "
            "and unsuitable for credentials; use a salted password KDF such as "
            "scrypt, Argon2id, or bcrypt."
        ),
        "code": code(
            """
            import hashlib


            def password_digest(password: str) -> str:
                return hashlib.md5(password.encode("utf-8")).hexdigest()
            """
        ),
    },
    {
        "slug": "sha1-credential-signature",
        "split": "train",
        "rule": "CRYPTO-002",
        "category": "hash",
        "vulnerable": True,
        "cwe": "CWE-327",
        "severity": "WARNING",
        "explanation": (
            "SHA-1 is used to authenticate a credential-like message. SHA-1 is "
            "collision-broken; use HMAC-SHA-256 or a modern signature scheme."
        ),
        "code": code(
            """
            import hashlib


            def sign_login_assertion(secret: bytes, assertion: bytes) -> str:
                return hashlib.sha1(secret + assertion).hexdigest()
            """
        ),
    },
    {
        "slug": "des-patient-record",
        "split": "train",
        "rule": "CRYPTO-003",
        "category": "cipher",
        "vulnerable": True,
        "cwe": "CWE-327",
        "severity": "WARNING",
        "explanation": (
            "DES protects patient records, but its 56-bit key and 64-bit block "
            "are obsolete. Replace it with AES-GCM or ChaCha20-Poly1305."
        ),
        "code": code(
            """
            from Crypto.Cipher import DES


            def encrypt_patient_record(key: bytes, data: bytes) -> bytes:
                block = data.ljust(16 * ((len(data) + 15) // 16), b"\\x00")
                return DES.new(key, DES.MODE_ECB).encrypt(block)
            """
        ),
    },
    {
        "slug": "rc4-session-payload",
        "split": "train",
        "rule": "CRYPTO-004",
        "category": "cipher",
        "vulnerable": True,
        "cwe": "CWE-327",
        "severity": "WARNING",
        "explanation": (
            "RC4 encrypts session payloads. RC4 has known keystream biases and "
            "no authentication; use an authenticated encryption mode."
        ),
        "code": code(
            """
            from Crypto.Cipher import ARC4


            def encrypt_session_payload(key: bytes, payload: bytes) -> bytes:
                return ARC4.new(key).encrypt(payload)
            """
        ),
    },
    {
        "slug": "aes-ecb-financial-records",
        "split": "train",
        "rule": "CRYPTO-005",
        "category": "cipher-mode",
        "vulnerable": True,
        "cwe": "CWE-327",
        "severity": "WARNING",
        "explanation": (
            "AES-ECB encrypts financial records. Equal plaintext blocks produce "
            "equal ciphertext blocks, leaking data structure; use AES-GCM."
        ),
        "code": code(
            """
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad


            def encrypt_financial_record(key: bytes, record: bytes) -> bytes:
                cipher = AES.new(key, AES.MODE_ECB)
                return cipher.encrypt(pad(record, AES.block_size))
            """
        ),
    },
    {
        "slug": "constant-iv-profile-encryption",
        "split": "train",
        "rule": "CRYPTO-006",
        "category": "iv",
        "vulnerable": True,
        "cwe": "CWE-329",
        "severity": "WARNING",
        "explanation": (
            "CBC mode reuses an all-zero IV for every profile encryption. A new "
            "unpredictable IV must be generated per message."
        ),
        "code": code(
            """
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


            def encrypt_profile(key: bytes, profile: bytes) -> bytes:
                encryptor = Cipher(
                    algorithms.AES(key),
                    modes.CBC(bytes(16)),
                ).encryptor()
                return encryptor.update(profile) + encryptor.finalize()
            """
        ),
    },
    {
        "slug": "hardcoded-encryption-key",
        "split": "train",
        "rule": "CRYPTO-007",
        "category": "key-management",
        "vulnerable": True,
        "cwe": "CWE-321",
        "severity": "WARNING",
        "explanation": (
            "A production encryption key is embedded directly in source code. "
            "Anyone with repository access can recover the key; load it from a "
            "secret manager or environment variable."
        ),
        "code": code(
            """
            from Crypto.Cipher import AES


            def encrypt_customer_note(note: bytes) -> bytes:
                return AES.new(
                    b"0123456789abcdef",
                    AES.MODE_GCM,
                    nonce=b"123456789012",
                ).encrypt(note)
            """
        ),
    },
    {
        "slug": "random-reset-token",
        "split": "train",
        "rule": "CRYPTO-008",
        "category": "randomness",
        "vulnerable": True,
        "cwe": "CWE-338",
        "severity": "WARNING",
        "explanation": (
            "The random module generates a password-reset token. Mersenne "
            "Twister output is predictable; use secrets.token_urlsafe()."
        ),
        "code": code(
            """
            import random


            def create_reset_token() -> str:
                token = random.getrandbits(128)
                return f"{token:032x}"
            """
        ),
    },
    {
        "slug": "rsa-1024-license-key",
        "split": "val",
        "rule": "CRYPTO-009",
        "category": "key-length",
        "vulnerable": True,
        "cwe": "CWE-326",
        "severity": "WARNING",
        "explanation": (
            "A 1024-bit RSA key signs software licenses. That size is below the "
            "current security floor; use at least RSA-2048 and preferably "
            "RSA-3072 or Ed25519."
        ),
        "code": code(
            """
            from Crypto.PublicKey import RSA


            def generate_license_signing_key():
                return RSA.generate(1024)
            """
        ),
    },
    {
        "slug": "tls-verification-disabled",
        "split": "val",
        "rule": "CRYPTO-010",
        "category": "tls",
        "vulnerable": True,
        "cwe": "CWE-295",
        "severity": "WARNING",
        "explanation": (
            "Certificate verification is disabled on a production API request. "
            "This permits man-in-the-middle attacks; keep verification enabled "
            "and use the system trust store."
        ),
        "code": code(
            """
            import requests


            def fetch_account_balance(account_id: str) -> dict:
                url = f"https://api.example.test/accounts/{account_id}"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                return response.json()
            """
        ),
    },
    {
        "slug": "plaintext-password-field",
        "split": "test",
        "rule": "CRYPTO-011",
        "category": "password-storage",
        "vulnerable": True,
        "cwe": "CWE-256",
        "severity": "WARNING",
        "explanation": (
            "The registration path stores a live password verbatim in a user "
            "record. A database leak exposes every password; persist a salted "
            "KDF digest instead."
        ),
        "code": code(
            """
            def register_user(db, email: str, password: str):
                user = db.User(email=email)
                user.password = password
                db.add(user)
                db.commit()
                return user
            """
        ),
    },
    {
        "slug": "weak-pbkdf2-iterations",
        "split": "test",
        "rule": "CRYPTO-012",
        "category": "kdf",
        "vulnerable": True,
        "cwe": "CWE-916",
        "severity": "WARNING",
        "explanation": (
            "PBKDF2-HMAC-SHA256 uses only 1,200 iterations for password "
            "storage. This is cheap to brute-force; increase the work factor "
            "substantially or use Argon2id/scrypt."
        ),
        "code": code(
            """
            import hashlib


            def derive_password_key(password: bytes, salt: bytes) -> bytes:
                return hashlib.pbkdf2_hmac("sha256", password, salt, 1200, dklen=32)
            """
        ),
    },
    {
        "slug": "token-equals-comparison",
        "split": "test",
        "rule": "CRYPTO-013",
        "category": "timing",
        "vulnerable": True,
        "cwe": "CWE-208",
        "severity": "WARNING",
        "explanation": (
            "A session token is compared with ==. Early-exit comparison can "
            "leak the matching prefix through timing; use hmac.compare_digest."
        ),
        "code": code(
            """
            def validate_session_token(provided_token: str, stored_token: str) -> bool:
                if provided_token != stored_token:
                    return False
                return True
            """
        ),
    },
    {
        "slug": "scrypt-password-store",
        "split": "train",
        "rule": "",
        "category": "password-storage",
        "vulnerable": False,
        "cwe": "",
        "severity": "",
        "explanation": (
            "Passwords are stored as salted scrypt digests and verified with a "
            "constant-time comparison. The parameters and API usage are safe."
        ),
        "code": code(
            """
            import hashlib
            import hmac
            import os


            class PasswordStore:
                N = 2**15
                R = 8
                P = 1
                KEY_LEN = 32

                def hash_password(self, password: str) -> bytes:
                    salt = os.urandom(16)
                    digest = hashlib.scrypt(
                        password.encode("utf-8"),
                        salt=salt,
                        n=self.N,
                        r=self.R,
                        p=self.P,
                        dklen=self.KEY_LEN,
                    )
                    return salt + digest

                def verify_password(self, password: str, stored: bytes) -> bool:
                    salt, expected = stored[:16], stored[16:]
                    actual = hashlib.scrypt(
                        password.encode("utf-8"),
                        salt=salt,
                        n=self.N,
                        r=self.R,
                        p=self.P,
                        dklen=self.KEY_LEN,
                    )
                    return hmac.compare_digest(actual, expected)
            """
        ),
    },
    {
        "slug": "aesgcm-message-cipher",
        "split": "train",
        "rule": "",
        "category": "cipher",
        "vulnerable": False,
        "cwe": "",
        "severity": "",
        "explanation": (
            "AES-GCM with a fresh random 96-bit nonce provides confidentiality "
            "and integrity through an authenticated encryption API."
        ),
        "code": code(
            """
            import os

            from cryptography.hazmat.primitives.ciphers.aead import AESGCM


            class MessageCipher:
                def __init__(self, key: bytes):
                    if len(key) not in (16, 24, 32):
                        raise ValueError("AES key must be 128, 192, or 256 bits")
                    self._cipher = AESGCM(key)

                def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
                    nonce = os.urandom(12)
                    return nonce + self._cipher.encrypt(nonce, plaintext, aad)

                def decrypt(self, payload: bytes, aad: bytes = b"") -> bytes:
                    nonce, ciphertext = payload[:12], payload[12:]
                    return self._cipher.decrypt(nonce, ciphertext, aad)
            """
        ),
    },
    {
        "slug": "hmac-token-signer",
        "split": "train",
        "rule": "",
        "category": "mac",
        "vulnerable": False,
        "cwe": "",
        "severity": "",
        "explanation": (
            "Tokens are authenticated with HMAC-SHA-256 and verified with a "
            "constant-time comparison. The secret is injected by the caller."
        ),
        "code": code(
            """
            import base64
            import hashlib
            import hmac


            class TokenSigner:
                def __init__(self, secret: bytes):
                    self._secret = secret

                def sign(self, user_id: str) -> str:
                    payload = base64.urlsafe_b64encode(user_id.encode("utf-8"))
                    mac = hmac.new(self._secret, payload, hashlib.sha256).digest()
                    return payload.decode("ascii") + "." + base64.urlsafe_b64encode(mac).decode("ascii")

                def verify(self, token: str, user_id: str) -> bool:
                    payload = base64.urlsafe_b64encode(user_id.encode("utf-8"))
                    expected = hmac.new(self._secret, payload, hashlib.sha256).digest()
                    try:
                        _, encoded_mac = token.rsplit(".", 1)
                        provided = base64.urlsafe_b64decode(encoded_mac)
                    except (ValueError, TypeError):
                        return False
                    return hmac.compare_digest(provided, expected)
            """
        ),
    },
    {
        "slug": "verified-tls-client",
        "split": "train",
        "rule": "",
        "category": "tls",
        "vulnerable": False,
        "cwe": "",
        "severity": "",
        "explanation": (
            "The client uses create_default_context, which enables certificate "
            "verification and secure protocol defaults."
        ),
        "code": code(
            """
            import ssl

            import requests


            def build_api_client() -> requests.Session:
                context = ssl.create_default_context()
                session = requests.Session()
                adapter = requests.adapters.HTTPAdapter()
                session.mount("https://", adapter)
                session.verify = context
                return session
            """
        ),
    },
    {
        "slug": "rsa-oaep-pss-service",
        "split": "val",
        "rule": "",
        "category": "public-key",
        "vulnerable": False,
        "cwe": "",
        "severity": "",
        "explanation": (
            "RSA-3072 is used with OAEP encryption and PSS signatures, both "
            "with SHA-256. The key size and padding constructions are current."
        ),
        "code": code(
            """
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding, rsa


            class LicenseCrypto:
                def __init__(self):
                    self._private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=3072,
                    )

                def encrypt(self, message: bytes) -> bytes:
                    return self.public_key().encrypt(
                        message,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                def decrypt(self, ciphertext: bytes) -> bytes:
                    return self._private_key.decrypt(
                        ciphertext,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                def sign(self, message: bytes) -> bytes:
                    return self._private_key.sign(
                        message,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )

                def public_key(self):
                    return self._private_key.public_key()
            """
        ),
    },
    {
        "slug": "secrets-session-token",
        "split": "val",
        "rule": "",
        "category": "randomness",
        "vulnerable": False,
        "cwe": "",
        "severity": "",
        "explanation": (
            "Session identifiers are generated with secrets.token_urlsafe, "
            "which is backed by the operating system CSPRNG."
        ),
        "code": code(
            """
            import secrets


            class SessionManager:
                def new_session_id(self) -> str:
                    return secrets.token_urlsafe(32)

                def new_csrf_token(self) -> str:
                    return secrets.token_urlsafe(24)
            """
        ),
    },
    {
        "slug": "sha256-content-manifest",
        "split": "test",
        "rule": "",
        "category": "hash",
        "vulnerable": False,
        "cwe": "",
        "severity": "",
        "explanation": (
            "SHA-256 is used for file integrity manifests, a security purpose "
            "for which it remains appropriate."
        ),
        "code": code(
            """
            import hashlib
            from pathlib import Path


            def file_digest(path: Path) -> str:
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                return digest.hexdigest()
            """
        ),
    },
    {
        "slug": "md5-cache-key-negative",
        "split": "train",
        "rule": "CRYPTO-001",
        "category": "hash",
        "vulnerable": False,
        "cwe": "",
        "severity": "",
        "explanation": (
            "MD5 is used only to build a cache key for public configuration "
            "data. No credential, signature, or secret depends on collision "
            "resistance, so this is an effective false positive."
        ),
        "code": code(
            """
            import hashlib


            def config_cache_key(public_config: bytes) -> str:
                return "config:" + hashlib.md5(public_config).hexdigest()
            """
        ),
    },
    {
        "slug": "sha1-shard-key-negative",
        "split": "train",
        "rule": "CRYPTO-002",
        "category": "hash",
        "vulnerable": False,
        "cwe": "",
        "severity": "",
        "explanation": (
            "SHA-1 is used only to choose a load-balancing shard. Collision "
            "resistance is not required for this non-security routing task."
        ),
        "code": code(
            """
            import hashlib


            def routing_shard(tenant_id: str, shard_count: int) -> int:
                digest = hashlib.sha1(tenant_id.encode("utf-8")).hexdigest()
                return int(digest[:8], 16) % shard_count
            """
        ),
    },
    {
        "slug": "random-jitter-negative",
        "split": "val",
        "rule": "CRYPTO-008",
        "category": "randomness",
        "vulnerable": False,
        "cwe": "",
        "severity": "",
        "explanation": (
            "The random module adds retry jitter to a worker backoff. The value "
            "does not protect a token, key, nonce, or credential, so this is a "
            "non-security use."
        ),
        "code": code(
            """
            import random


            def calculate_retry_delay(attempt: int) -> float:
                base = min(30.0, 0.5 * (2**attempt))
                return base + random.uniform(0.0, base * 0.25)
            """
        ),
    },
]


TRIAGE_SAMPLES = [
    {
        "slug": "confirm-md5-password-store",
        "split": "train",
        "rule": "CRYPTO-001",
        "finding": "[CRYPTO-001] Use of MD5 which is not collision-resistant.",
        "verdict": "Confirm",
        "cwe": "CWE-327",
        "severity": "WARNING",
        "explanation": (
            "The MD5 digest is the persisted password verifier for user "
            "accounts. A fast, collision-broken hash is unsuitable for "
            "credentials, and a database leak enables efficient offline "
            "password cracking."
        ),
        "patch": code(
            """
            import hashlib
            import os


            def password_digest(password: str) -> bytes:
                salt = os.urandom(16)
                digest = hashlib.scrypt(
                    password.encode("utf-8"),
                    salt=salt,
                    n=2**15,
                    r=8,
                    p=1,
                    dklen=32,
                )
                return salt + digest
            """
        ),
        "code": code(
            """
            import hashlib


            def set_account_password(password: str) -> str:
                verifier = hashlib.md5(password.encode("utf-8")).hexdigest()
                return verifier
            """
        ),
    },
    {
        "slug": "confirm-aes-ecb-records",
        "split": "train",
        "rule": "CRYPTO-005",
        "finding": "[CRYPTO-005] AES in ECB mode leaks patterns in plaintext.",
        "verdict": "Confirm",
        "cwe": "CWE-327",
        "severity": "WARNING",
        "explanation": (
            "The encrypted value is stored as a production account record. "
            "AES-ECB reveals equality and repetition patterns across records, "
            "so the data is not safely protected."
        ),
        "patch": code(
            """
            import os

            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad


            def encrypt_account_record(key: bytes, record: bytes) -> bytes:
                nonce = os.urandom(12)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(pad(record, 16))
                return nonce + tag + ciphertext
            """
        ),
        "code": code(
            """
            from Crypto.Cipher import AES


            def encrypt_account_record(key: bytes, record: bytes) -> bytes:
                cipher = AES.new(key, AES.MODE_ECB)
                return cipher.encrypt(record.ljust(16 * ((len(record) + 15) // 16), b"\\x00"))
            """
        ),
    },
    {
        "slug": "confirm-static-iv",
        "split": "train",
        "rule": "CRYPTO-006",
        "finding": "[CRYPTO-006] Predictable IV used in a block cipher mode.",
        "verdict": "Confirm",
        "cwe": "CWE-329",
        "severity": "WARNING",
        "explanation": (
            "Every profile encryption uses the same zero IV. Reusing a "
            "predictable IV in CBC mode exposes relationships between "
            "messages and weakens confidentiality."
        ),
        "patch": code(
            """
            import os

            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


            def encrypt_profile(key: bytes, profile: bytes) -> bytes:
                iv = os.urandom(16)
                encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
                return iv + encryptor.update(profile) + encryptor.finalize()
            """
        ),
        "code": code(
            """
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


            def encrypt_profile(key: bytes, profile: bytes) -> bytes:
                encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
                return encryptor.update(profile) + encryptor.finalize()
            """
        ),
    },
    {
        "slug": "confirm-random-reset-token",
        "split": "val",
        "rule": "CRYPTO-008",
        "finding": "[CRYPTO-008] random module used for a security-sensitive value.",
        "verdict": "Confirm",
        "cwe": "CWE-338",
        "severity": "WARNING",
        "explanation": (
            "The generated value is the bearer token for password reset. "
            "Predictable Mersenne Twister output can let an attacker guess the "
            "token and take over an account."
        ),
        "patch": code(
            """
            import secrets


            def create_reset_token() -> str:
                return secrets.token_urlsafe(32)
            """
        ),
        "code": code(
            """
            import random


            def create_reset_token() -> str:
                reset_token = random.getrandbits(128)
                return f"{reset_token:032x}"
            """
        ),
    },
    {
        "slug": "confirm-token-comparison",
        "split": "test",
        "rule": "CRYPTO-013",
        "finding": "[CRYPTO-013] Credential/digest compared with a non-constant-time operator.",
        "verdict": "Confirm",
        "cwe": "CWE-208",
        "severity": "WARNING",
        "explanation": (
            "The comparison validates a session token. The == operator exits "
            "early at the first mismatch, which can leak the expected token "
            "prefix through timing measurements."
        ),
        "patch": code(
            """
            import hmac


            def token_is_valid(provided_token: str, stored_token: str) -> bool:
                return hmac.compare_digest(provided_token, stored_token)
            """
        ),
        "code": code(
            """
            def token_is_valid(provided_token: str, stored_token: str) -> bool:
                return provided_token == stored_token
            """
        ),
    },
    {
        "slug": "reject-md5-cache-key",
        "split": "train",
        "rule": "CRYPTO-001",
        "finding": "[CRYPTO-001] Use of MD5 which is not collision-resistant.",
        "verdict": "Reject",
        "cwe": "",
        "severity": "",
        "explanation": (
            "The MD5 output is only a cache key for public configuration. No "
            "credential, signature, or security decision depends on collision "
            "resistance, so the static finding is not a real vulnerability."
        ),
        "patch": "",
        "code": code(
            """
            import hashlib


            def cache_key(public_config: bytes) -> str:
                return hashlib.md5(public_config).hexdigest()
            """
        ),
    },
    {
        "slug": "reject-sha1-sharding",
        "split": "train",
        "rule": "CRYPTO-002",
        "finding": "[CRYPTO-002] Use of SHA-1 which is not collision-resistant.",
        "verdict": "Reject",
        "cwe": "",
        "severity": "",
        "explanation": (
            "SHA-1 chooses a shard in a load balancer. The output has no "
            "security role and does not authenticate or protect a secret, so "
            "collision resistance is irrelevant."
        ),
        "patch": "",
        "code": code(
            """
            import hashlib


            def shard_for_tenant(tenant_id: str, shard_count: int) -> int:
                digest = hashlib.sha1(tenant_id.encode("utf-8")).digest()
                return int.from_bytes(digest[:4], "big") % shard_count
            """
        ),
    },
    {
        "slug": "reject-random-backoff-jitter",
        "split": "train",
        "rule": "CRYPTO-008",
        "finding": "[CRYPTO-008] random module used for a security-sensitive value.",
        "verdict": "Reject",
        "cwe": "",
        "severity": "",
        "explanation": (
            "The random value only spreads retry delays across workers. It is "
            "not a token, key, nonce, or credential, so predictability has no "
            "security impact."
        ),
        "patch": "",
        "code": code(
            """
            import random


            def retry_delay(attempt: int) -> float:
                jitter = random.uniform(0.0, 0.25)
                return min(30.0, 0.5 * (2**attempt)) + jitter
            """
        ),
    },
    {
        "slug": "reject-des-test-vector",
        "split": "val",
        "rule": "CRYPTO-003",
        "finding": "[CRYPTO-003] Use of DES which has a small block size and weak key.",
        "verdict": "Reject",
        "cwe": "",
        "severity": "",
        "explanation": (
            "DES appears only in a known-answer test vector. The code is test "
            "scaffolding and does not protect real user data, so it should not "
            "be confirmed as a production vulnerability."
        ),
        "patch": "",
        "code": code(
            """
            from Crypto.Cipher import DES


            def test_des_known_vector():
                cipher = DES.new(b"8bytekey", DES.MODE_ECB)
                assert cipher.encrypt(b"plaintex") == bytes.fromhex(
                    "5b21b1b349b3c5f0"
                )
            """
        ),
    },
    {
        "slug": "reject-rc4-benchmark",
        "split": "test",
        "rule": "CRYPTO-004",
        "finding": "[CRYPTO-004] Use of RC4 which has statistical biases.",
        "verdict": "Reject",
        "cwe": "",
        "severity": "",
        "explanation": (
            "RC4 is exercised only by a benchmark that measures primitive "
            "throughput. No real message, credential, or secret is protected "
            "by this code."
        ),
        "patch": "",
        "code": code(
            """
            from Crypto.Cipher import ARC4


            def benchmark_arc4(data: bytes) -> int:
                for _ in range(100):
                    ARC4.new(b"bench-key").encrypt(data)
                return len(data)
            """
        ),
    },
]


def detect_record(sample: dict) -> dict:
    return {
        "id": f"gen-detect-{sample['slug']}",
        "language": "python",
        "task": "detect",
        "code": sample["code"],
        "label": {
            "vulnerable": sample["vulnerable"],
            "cwe": sample["cwe"],
            "severity": sample["severity"],
            "confidence": "high",
            "explanation": sample["explanation"],
        },
        "source": SOURCE,
        "license": "original",
        "repo_url": "",
        "commit": "",
        "verified": False,
        "split": sample["split"],
        "rule": sample["rule"],
        "category": sample["category"],
    }


def triage_record(sample: dict) -> dict:
    return {
        "id": f"gen-triage-{sample['slug']}",
        "language": "python",
        "task": "triage",
        "code": sample["code"],
        "finding": sample["finding"],
        "label": {
            "cwe": sample["cwe"],
            "severity": sample["severity"],
            "verdict": sample["verdict"],
            "confidence": "high",
            "explanation": sample["explanation"],
            "patch": sample["patch"],
        },
        "source": SOURCE,
        "license": "original",
        "repo_url": "",
        "commit": "",
        "verified": False,
        "split": sample["split"],
        "rule": sample["rule"],
    }


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False, sort_keys=False) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )


def main() -> int:
    records = [detect_record(item) for item in DETECT_SAMPLES]
    records += [triage_record(item) for item in TRIAGE_SAMPLES]

    if PYTHON_DIR.exists():
        shutil.rmtree(PYTHON_DIR)

    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        raise RuntimeError("generated sample IDs are not unique")

    for record in records:
        try:
            compile(record["code"], record["id"], "exec")
        except SyntaxError as exc:
            raise RuntimeError(f"{record['id']} is not valid Python: {exc}") from exc

    detect = [record for record in records if record["task"] == "detect"]
    triage = [record for record in records if record["task"] == "triage"]

    for record in records:
        path = PYTHON_DIR / record["task"] / f"{record['id']}.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(record["code"], encoding="utf-8")
        record["file"] = str(path.relative_to(OUTPUT_DIR))

    write_jsonl(SOURCE_DIR / "detect.jsonl", detect)
    write_jsonl(SOURCE_DIR / "triage.jsonl", triage)
    write_jsonl(SOURCE_DIR / "all.jsonl", records)

    for split in ("train", "val", "test"):
        split_records = [record for record in records if record["split"] == split]
        write_jsonl(
            UPLOAD_DIR / f"{split}.jsonl",
            [
                {"messages": build_messages(record, training=True)}
                for record in split_records
            ],
        )

    zip_path = OUTPUT_DIR / "generated_crypto_pack.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for record in records:
            source_path = OUTPUT_DIR / record["file"]
            archive.write(source_path, arcname=record["file"])

    by_split = {
        split: sum(1 for record in records if record["split"] == split)
        for split in ("train", "val", "test")
    }
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": SOURCE,
        "verified": False,
        "counts": {
            "total": len(records),
            "detect": len(detect),
            "detect_vulnerable": sum(
                1 for record in detect if record["label"]["vulnerable"]
            ),
            "detect_negative": sum(
                1 for record in detect if not record["label"]["vulnerable"]
            ),
            "triage": len(triage),
            "triage_confirm": sum(
                1 for record in triage if record["label"]["verdict"] == "Confirm"
            ),
            "triage_reject": sum(
                1 for record in triage if record["label"]["verdict"] == "Reject"
            ),
            "by_split": by_split,
        },
        "paths": {
            "python": "python/",
            "source": "source/all.jsonl",
            "upload": "upload/",
            "zip": zip_path.name,
        },
    }
    (OUTPUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"[+] generated {len(records)} records: "
        f"detect={len(detect)} triage={len(triage)} "
        f"train/val/test={by_split['train']}/{by_split['val']}/{by_split['test']}"
    )
    print(f"[+] upload zip: {zip_path}")
    print(f"[+] output: {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
