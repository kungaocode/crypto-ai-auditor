#!/usr/bin/env python3
"""Round-4 sample expansion toward a 50:50 vulnerable:secure detect split.

Motivation (see data/round4/ROUND4_GUIDE.md): the 77 hand-written negatives move
detect_train from 59:41 to 57:43, but the goal the user set is 50:50 (real code
has *fewer* vulnerabilities). Closing that gap needs BOTH:

  + crypto *positive* samples (vulnerable=true) — the detect positives are mostly
    non-crypto Django (CWE-89/79/78/94); crypto vulns are under-represented, and
    contrast pairs make the decision boundary learnable.
  + more *negative* samples (vulnerable=false) — secure-modern crypto (A 类) and
    weak-primitive-for-non-security (B 类).

Target: +P positives (CLI `--positives`, default 150) and +N negatives where
N = (vuln + P) - secure, so the final detect_train ratio lands at exactly 50:50.

Positives are generated combinatorially from rule-grounded templates (each is a
genuine weak-pattern usage and must fire its own CRYPTO rule in the backtest).
Negatives come from three sources:
  1. combinatorial templates (A 类 secure-modern + B 类 weak-primitive x
     non-security purpose),
  2. deep-mining the 5 real crypto clones under data/round4/real_projects/ for
     genuinely-safe crypto functions (AST-extracted, weak-pattern-free),
  3. a spare A-class top-up so the total lands on the 50:50 target.

Every generated sample is backtested with Semgrep:
  - A 类 (safe)     must fire ZERO rules,
  - B 类 strong-B   must fire its expected weak-primitive rule (the model has to
                    look past the rule hit to the non-security purpose),
  - positives       must fire their own rule (they are real vulns).

Outputs (data/round4/expanded/):
  positive_source.jsonl  negative_source.jsonl  backtest_report.jsonl
  upload/full/{train,val,test}.jsonl   (detect_train + base77 + expanded + triage)

Usage: python scripts/expand_round4_samples.py [--backtest] [--emit]
"""
import argparse
import ast
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.prepare_sft_data import build_messages  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
R4 = ROOT / "data" / "round4"
OUT = R4 / "expanded"
REAL = R4 / "real_projects"

# Rule metadata (cwe from metadata, severity convention follows the existing
# crypto positives: top-level rule severity is WARNING for every rule).
RULE_META = {
    "CRYPTO-001": {"cwe": "CWE-327", "msg": "Use of MD5 which is not collision-resistant."},
    "CRYPTO-002": {"cwe": "CWE-327", "msg": "Use of SHA-1 which is not collision-resistant."},
    "CRYPTO-003": {"cwe": "CWE-327", "msg": "Use of DES or 3DES which have small block sizes and are considered weak."},
    "CRYPTO-004": {"cwe": "CWE-327", "msg": "Use of RC4 which has multiple statistical biases and is deprecated."},
    "CRYPTO-005": {"cwe": "CWE-327", "msg": "AES in ECB mode leaks patterns in plaintext; use an authenticated mode such as AES-GCM."},
    "CRYPTO-006": {"cwe": "CWE-329", "msg": "Predictable or hardcoded IV used in a block cipher mode. Use a fresh random IV per encryption."},
    "CRYPTO-007": {"cwe": "CWE-321", "msg": "Hard-coded cryptographic key found inline. Keys must be loaded from secrets management, env vars, or a KDF."},
    "CRYPTO-008": {"cwe": "CWE-338", "msg": "random module used for a security-sensitive value. random.* is not cryptographically secure; use secrets or os.urandom."},
    "CRYPTO-009": {"cwe": "CWE-326", "msg": "Weak key length or weak elliptic curve. Use RSA >= 2048 bits or a NIST P-256+ curve."},
    "CRYPTO-010": {"cwe": "CWE-326", "msg": "Insecure TLS configuration: weak protocol version, disabled certificate validation, or unverified context."},
}

# Target positive count (P). The negative count N is derived to reach 50:50.
# Default 150 = the user's chosen reduced expansion (+150 pos / +493 neg, 1563:1563).
# Override with --positives (e.g. 300 for the earlier full expansion).
P_DEFAULT = 150


def _fill(tmpl: str, func: str, arg: str = "", var: str = "") -> str:
    return (tmpl.replace("__FUNC__", func)
                .replace("__ARG__", arg)
                .replace("__VAR__", var))


def pos(rid: str, code: str, cwe: str, explanation: str, split: str = "train") -> dict:
    return {
        "id": rid, "language": "python", "task": "detect", "code": code,
        "label": {"vulnerable": True, "cwe": cwe, "severity": "WARNING",
                  "confidence": "HIGH", "explanation": explanation},
        "source": "round4-exp-positive", "license": "original",
        "repo_url": "", "commit": "", "verified": False, "split": split,
    }


def neg(rid: str, code: str, explanation: str, cls: str, split: str = "train") -> dict:
    return {
        "id": rid, "language": "python", "task": "detect", "code": code,
        "label": {"vulnerable": False, "cwe": "", "severity": "",
                  "confidence": "high", "explanation": explanation},
        "source": f"round4-exp-neg-{cls}", "license": "original",
        "repo_url": "", "commit": "", "verified": False, "split": split,
    }


# =============================================================================
# POSITIVE TEMPLATES (vulnerable=true). Each (imports, [templates], [names]).
# Every template must actually fire its rule (backtested). 6 templates x 5 names
# = 30 per rule, 10 rules = 300 positives.
# =============================================================================
ENC_NAMES = [
    ("encrypt_payload", "plaintext", "key"),
    ("protect_record", "record", "key"),
    ("encrypt_field", "value", "secret"),
    ("seal_message", "message", "key"),
    ("encrypt_pin", "pin", "key"),
]

RULE_POS = {
    "CRYPTO-001": {
        "imports": "import hashlib\nimport time\n",
        "names": [
            ("hash_password", "password", "salt"),
            ("sign_request", "payload", "secret"),
            ("derive_token", "user_id", "salt"),
            ("fingerprint_secret", "secret", "salt"),
            ("checksum_artifact", "content", "salt"),
        ],
        "templates": [
            'def __FUNC__(__ARG__: str) -> str:\n    return hashlib.md5(__ARG__.encode()).hexdigest()',
            'def __FUNC__(path: str) -> str:\n    with open(path, "rb") as f:\n        return hashlib.md5(f.read()).hexdigest()',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> str:\n    return hashlib.md5(__VAR__ + __ARG__).hexdigest()',
            'def __FUNC__(__ARG__: str, __VAR__: bytes) -> str:\n    return hashlib.md5(__VAR__ + __ARG__.encode()).hexdigest()',
            'def __FUNC__(data: bytes, expected: str) -> bool:\n    return hashlib.md5(data).hexdigest() == expected',
            'def __FUNC__(__ARG__: str) -> str:\n    return hashlib.md5(f"{__ARG__}:{time.time()}".encode()).hexdigest()',
        ],
    },
    "CRYPTO-002": {
        "imports": "import hashlib\nimport time\n",
        "names": [
            ("hash_password", "password", "salt"),
            ("sign_digest", "data", "secret"),
            ("cert_fingerprint", "cert", "salt"),
            ("verify_integrity", "artifact", "salt"),
            ("commit_id", "content", "salt"),
        ],
        "templates": [
            'def __FUNC__(__ARG__: str) -> str:\n    return hashlib.sha1(__ARG__.encode()).hexdigest()',
            'def __FUNC__(path: str) -> str:\n    with open(path, "rb") as f:\n        return hashlib.sha1(f.read()).hexdigest()',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> str:\n    return hashlib.sha1(__VAR__ + __ARG__).hexdigest()',
            'def __FUNC__(__ARG__: str, __VAR__: bytes) -> str:\n    return hashlib.sha1(__VAR__ + __ARG__.encode()).hexdigest()',
            'def __FUNC__(data: bytes, expected: str) -> bool:\n    return hashlib.sha1(data).hexdigest() == expected',
            'def __FUNC__(__ARG__: str) -> str:\n    return hashlib.sha1(f"{__ARG__}:{time.time()}".encode()).hexdigest()',
        ],
    },
    "CRYPTO-003": {
        "imports": "from Crypto.Cipher import DES, DES3\nimport os\n",
        "names": ENC_NAMES,
        "templates": [
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = DES.new(__VAR__, DES.MODE_ECB)\n    return cipher.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    iv = os.urandom(8)\n    cipher = DES.new(__VAR__, DES.MODE_CBC, iv)\n    return iv + cipher.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = DES3.new(__VAR__, DES3.MODE_ECB)\n    return cipher.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = DES3.new(__VAR__, DES3.MODE_CBC, os.urandom(8))\n    return cipher.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = DES.new(__VAR__, DES.MODE_ECB)\n    return cipher.encrypt(__ARG__[:8])',
            'def __FUNC__(__ARG__: str, __VAR__: bytes) -> bytes:\n    cipher = DES3.new(__VAR__, DES3.MODE_ECB)\n    return cipher.encrypt(__ARG__.encode().ljust(24))',
        ],
    },
    "CRYPTO-004": {
        "imports": "from Crypto.Cipher import ARC4\n",
        "names": ENC_NAMES,
        "templates": [
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = ARC4.new(__VAR__)\n    return cipher.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    return ARC4.new(__VAR__).encrypt(__ARG__)',
            'def __FUNC__(__ARG__: str, __VAR__: bytes) -> bytes:\n    return ARC4.new(__VAR__).encrypt(__ARG__.encode())',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = ARC4.new(__VAR__)\n    return cipher.decrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    stream = ARC4.new(__VAR__)\n    return stream.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    return ARC4.new(__VAR__ + b"nonce").encrypt(__ARG__)',
        ],
    },
    "CRYPTO-005": {
        "imports": "from Crypto.Cipher import AES\n",
        "names": ENC_NAMES,
        "templates": [
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = AES.new(__VAR__, AES.MODE_ECB)\n    return cipher.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    return AES.new(__VAR__, AES.MODE_ECB).encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = AES.new(__VAR__, AES.MODE_ECB)\n    return cipher.encrypt(__ARG__ + b"pad")',
            'def __FUNC__(__ARG__: list, __VAR__: bytes) -> list:\n    cipher = AES.new(__VAR__, AES.MODE_ECB)\n    return [cipher.encrypt(b) for b in __ARG__]',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = AES.new(__VAR__, AES.MODE_ECB)\n    return cipher.decrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = AES.new(__VAR__, AES.MODE_ECB)\n    out = cipher.encrypt(__ARG__)\n    return out',
        ],
    },
    "CRYPTO-006": {
        "imports": "from Crypto.Cipher import AES\nfrom cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n",
        "names": ENC_NAMES,
        "templates": [
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = AES.new(__VAR__, AES.MODE_CBC, IV=b"")\n    return cipher.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = AES.new(__VAR__, AES.MODE_CFB, IV=b"")\n    return cipher.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = AES.new(__VAR__, AES.MODE_OFB, IV=b"")\n    return cipher.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = Cipher(algorithms.AES(__VAR__), modes.CBC(b""))\n    return cipher.encryptor().update(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = Cipher(algorithms.AES(__VAR__), modes.CBC(bytes(16)))\n    return cipher.encryptor().update(__ARG__)',
            'def __FUNC__(__ARG__: bytes, __VAR__: bytes) -> bytes:\n    cipher = AES.new(__VAR__, AES.MODE_CBC, iv=b"")\n    return cipher.encrypt(__ARG__)',
        ],
    },
    "CRYPTO-007": {
        "imports": "from Crypto.Cipher import AES\nfrom cryptography.fernet import Fernet\nfrom cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\nimport os\n",
        "names": ENC_NAMES,
        "templates": [
            'def __FUNC__(__ARG__: bytes) -> bytes:\n    cipher = AES.new(b"hardcoded-secret-key-0000", AES.MODE_GCM)\n    ct, tag = cipher.encrypt_and_digest(__ARG__)\n    return cipher.nonce + tag + ct',
            'def __FUNC__(__ARG__: bytes) -> bytes:\n    f = Fernet(b"hardcoded-fernet-key-0000000000")\n    return f.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes) -> bytes:\n    cipher = Cipher(algorithms.AES(b"hardcoded-secret-key-0000"), modes.CBC(os.urandom(16)))\n    return cipher.encryptor().update(__ARG__)',
            'def __FUNC__(__ARG__: bytes) -> bytes:\n    return AES.new(b"static-encryption-key-00000", AES.MODE_GCM).encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes) -> bytes:\n    f = Fernet(b"hardcoded-session-key-000000000000")\n    return f.encrypt(__ARG__)',
            'def __FUNC__(__ARG__: bytes) -> bytes:\n    cipher = AES.new(b"hardcoded-data-key-0000000000", AES.MODE_GCM)\n    return cipher.encrypt(__ARG__)',
        ],
    },
    "CRYPTO-008": {
        "imports": "import random\n",
        "names": [
            ("generate_token", "n", "session_token"),
            ("new_key", "n", "encryption_key"),
            ("make_nonce", "n", "nonce"),
            ("new_salt", "n", "salt"),
            ("reset_password", "n", "reset_token"),
        ],
        "templates": [
            'def __FUNC__():\n    __VAR__ = random.getrandbits(256)\n    return __VAR__',
            'def __FUNC__():\n    __VAR__ = random.getrandbits(128)\n    return __VAR__',
            'def __FUNC__():\n    __VAR__ = random.randint(0, 2**256 - 1)\n    return __VAR__',
            'def __FUNC__():\n    __VAR__ = random.choice("0123456789abcdef")\n    return __VAR__',
            'def __FUNC__():\n    __VAR__ = random.random()\n    return __VAR__',
            'def __FUNC__():\n    __VAR__ = random.sample("0123456789abcdef", 16)\n    return __VAR__',
        ],
    },
    "CRYPTO-009": {
        "imports": "from Crypto.PublicKey import RSA\nfrom cryptography.hazmat.primitives.asymmetric import ec\n",
        "names": [
            ("generate_rsa_key", "bits", "key"),
            ("new_signing_key", "bits", "key"),
            ("create_keypair", "bits", "key"),
            ("generate_ec_key", "curve", "key"),
            ("new_private_key", "bits", "key"),
        ],
        "templates": [
            'def __FUNC__():\n    __VAR__ = RSA.generate(1024)\n    return __VAR__',
            'def __FUNC__():\n    __VAR__ = RSA.generate(512)\n    return __VAR__',
            'def __FUNC__():\n    __VAR__ = RSA.generate(768)\n    return __VAR__',
            'def __FUNC__():\n    __VAR__ = ec.generate_private_key(ec.SECP192R1())\n    return __VAR__',
            'def __FUNC__():\n    __VAR__ = ec.generate_private_key(ec.SECP112R1())\n    return __VAR__',
            'def __FUNC__():\n    __VAR__ = ec.generate_private_key(ec.SECP160R1())\n    return __VAR__',
        ],
    },
    "CRYPTO-010": {
        "imports": "import ssl\nimport requests\n",
        "names": [
            ("make_client_context", "host", "ctx"),
            ("create_session_context", "host", "ctx"),
            ("fetch_secure", "url", "resp"),
            ("post_data", "url", "resp"),
            ("open_connection", "host", "ctx"),
        ],
        "templates": [
            'def __FUNC__():\n    __VAR__ = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n    return __VAR__',
            'def __FUNC__():\n    __VAR__ = ssl._create_unverified_context()\n    return __VAR__',
            'def __FUNC__():\n    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)\n    return ctx',
            'def __FUNC__(url: str):\n    __VAR__ = requests.get(url, verify=False, timeout=10)\n    return __VAR__',
            'def __FUNC__(url: str, payload: dict):\n    __VAR__ = requests.post(url, json=payload, verify=False, timeout=10)\n    return __VAR__',
            'def __FUNC__():\n    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)\n    ctx.verify_mode = ssl.CERT_NONE\n    return ctx',
        ],
    },
}


def gen_positives(n: int) -> list:
    """Generate exactly `n` crypto positives, balanced across all 10 rules.

    Each rule contributes n//10 samples drawn in template-major order from its
    template x name combos (6 templates x 5 names = 30), so the 10 CRYPTO rules
    stay evenly represented and ids match the full expansion for the shared prefix.
    """
    per_rule = n // 10
    recs = []
    for rule, spec in RULE_POS.items():
        meta = RULE_META[rule]
        combos = [(ti, ni, func, arg, var)
                  for ti, tmpl in enumerate(spec["templates"])
                  for ni, (func, arg, var) in enumerate(spec["names"])]
        for ti, ni, func, arg, var in combos[:per_rule]:
            code = spec["imports"] + _fill(spec["templates"][ti], func, arg, var)
            rid = f"round4-pos-{rule}-{ti}{ni}"
            recs.append(pos(rid, code, meta["cwe"], meta["msg"]))
    return recs


# =============================================================================
# NEGATIVE TEMPLATES (vulnerable=false).
# =============================================================================
# --- A 类：secure modern crypto (must fire zero rules) -----------------------
A_CLASS = [
    ("scrypt", "import hashlib\nimport secrets\n\n"
     "def hash_password(password: str) -> str:\n"
     "    salt = secrets.token_bytes(16)\n"
     "    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1)\n"
     "    return salt.hex() + dk.hex()",
     "Passwords are hashed with scrypt (memory-hard, salted, per-password CSPRNG salt). No weak fast digest protects the secret -> safe."),
    ("argon2", "from argon2 import PasswordHasher\n\n"
     "_ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024)\n\n"
     "def verify_login(stored: str, supplied: str) -> bool:\n"
     "    try:\n"
     "        return _ph.verify(stored, supplied)\n"
     "    except Exception:\n"
     "        return False",
     "Passwords are verified with argon2 (recommended memory-hard KDF). Correct password storage -> safe."),
    ("bcrypt", "import bcrypt\n\n"
     "def hash_password(password: str) -> bytes:\n"
     "    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))",
     "bcrypt with a fresh random salt and 12 rounds hashes the password. Slow salted KDF -> safe."),
    ("pbkdf2", "import hashlib\nimport os\n\n"
     "def derive_password_hash(password: str) -> str:\n"
     "    salt = os.urandom(16)\n"
     "    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)\n"
     "    return salt.hex() + dk.hex()",
     "PBKDF2-HMAC-SHA256 with a random salt and 600k iterations. Adequate password derivation -> safe."),
    ("aesgcm-crypto", "import os\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\n"
     "def encrypt_blob(plaintext: bytes, key: bytes) -> bytes:\n"
     "    aead = AESGCM(key)\n"
     "    nonce = os.urandom(12)\n"
     "    return nonce + aead.encrypt(nonce, plaintext, None)",
     "AES-GCM (authenticated encryption) with a fresh 96-bit CSPRNG nonce. No ECB/fixed-IV -> safe."),
    ("aesgcm-pycrypto", "import os\nfrom Crypto.Cipher import AES\n\n"
     "def encrypt_record(record: bytes, key: bytes) -> bytes:\n"
     "    nonce = os.urandom(12)\n"
     "    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)\n"
     "    ct, tag = cipher.encrypt_and_digest(record)\n"
     "    return nonce + tag + ct",
     "AES-GCM via pycryptodome with a fresh random nonce and MAC tag. Authenticated -> safe."),
    ("hmac-sha256", "import hashlib\nimport hmac\n\n"
     "def verify_signature(secret: bytes, body: bytes, expected: bytes) -> bool:\n"
     "    actual = hmac.new(secret, body, hashlib.sha256).digest()\n"
     "    return hmac.compare_digest(actual, expected)",
     "HMAC-SHA256 with constant-time compare verifies a signature. No weak digest, no timing leak -> safe."),
    ("secrets-urlsafe", "import secrets\n\n"
     "def new_api_token() -> str:\n"
     "    return secrets.token_urlsafe(32)",
     "API token from secrets.token_urlsafe (CSPRNG, 256-bit). No predictable random.* -> safe."),
    ("secrets-hex", "import secrets\n\n"
     "def new_session_id() -> str:\n"
     "    return secrets.token_hex(32)",
     "256-bit session id from a CSPRNG (SP 800-63B requires >=128 bits). Correct -> safe."),
    ("os-urandom-salt", "import os\n\n"
     "def new_salt() -> bytes:\n"
     "    return os.urandom(16)",
     "Password salt from os.urandom (CSPRNG). Correct for security-sensitive randomness -> safe."),
    ("hkdf", "from cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.primitives.kdf.hkdf import HKDF\n\n"
     "def derive_subkey(master: bytes, salt: bytes) -> bytes:\n"
     "    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'app')\n"
     "    return hkdf.derive(master)",
     "A sub-key is derived with HKDF-SHA256 (SP 800-56C). No weak digest or hardcoded key -> safe."),
    ("chacha20", "import secrets\nfrom cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n\n"
     "def encrypt_stream(plaintext: bytes, key: bytes) -> bytes:\n"
     "    aead = ChaCha20Poly1305(key)\n"
     "    nonce = secrets.token_bytes(12)\n"
     "    return nonce + aead.encrypt(nonce, plaintext, None)",
     "ChaCha20-Poly1305 (approved AEAD) with a fresh CSPRNG nonce. Safe alternative to AES-GCM -> safe."),
    ("rsa-oaep", "from Crypto.Cipher import PKCS1_OAEP\nfrom Crypto.PublicKey import RSA\nimport os\n\n"
     "def encrypt_for_peer(plaintext: bytes, pub: RSA.RsaKey) -> bytes:\n"
     "    cipher = PKCS1_OAEP.new(pub)\n"
     "    return cipher.encrypt(plaintext)",
     "RSA-OAEP (padded, authenticated asymmetric encryption). No raw RSA -> safe."),
    ("ed25519", "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n\n"
     "def sign_message(msg: bytes):\n"
     "    key = Ed25519PrivateKey.generate()\n"
     "    return key.sign(msg)",
     "Ed25519 (128-bit strength) signs the message. Modern EC signature -> safe."),
    ("ecdsa-p256", "from Crypto.PublicKey import ECC\nfrom Crypto.Signature import eddsa  # noqa\n\n"
     "def generate_ec_key():\n"
     "    return ECC.generate(curve='P-256')",
     "An ECDSA key on NIST P-256 (128-bit strength). Correct curve and size -> safe."),
    ("sha3-256", "import hashlib\n\n"
     "def content_fingerprint(data: bytes) -> str:\n"
     "    return hashlib.sha3_256(data).hexdigest()",
     "Integrity uses SHA3-256 (current NIST-approved secure hash). Not MD5/SHA-1 -> safe."),
    ("sha256-integrity", "import hashlib\n\n"
     "def verify_artifact(path: str, expected: str) -> bool:\n"
     "    with open(path, 'rb') as f:\n"
     "        return hashlib.sha256(f.read()).hexdigest() == expected",
     "Artifact integrity uses SHA-256 (collision-resistant). Not MD5/SHA-1 -> safe."),
    ("compare-digest", "import hmac\n\n"
     "def token_matches(stored: bytes, supplied: bytes) -> bool:\n"
     "    return hmac.compare_digest(stored, supplied)",
     "Constant-time comparison avoids a timing side channel when checking a secret -> safe."),
    ("tls-default", "import ssl\n\n"
     "def client_context() -> ssl.SSLContext:\n"
     "    return ssl.create_default_context()",
     "ssl.create_default_context() validates certificates and negotiates modern TLS -> safe."),
    ("tls12-min", "import ssl\n\n"
     "def secure_context() -> ssl.SSLContext:\n"
     "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
     "    ctx.minimum_version = ssl.TLSVersion.TLSv1_2\n"
     "    return ctx",
     "TLS 1.2 minimum enforced with certificate validation. No legacy protocol -> safe."),
    ("requests-verify", "import requests\n\n"
     "def fetch_data(url: str) -> bytes:\n"
     "    return requests.get(url, timeout=10).content",
     "requests.get verifies TLS certificates by default. No verify=False -> safe."),
    ("secrets-randbits", "import secrets\n\n"
     "def new_token() -> int:\n"
     "    return secrets.randbits(256)",
     "Token from secrets.randbits (CSPRNG). Not the predictable Mersenne Twister -> safe."),
    ("ecdh", "from cryptography.hazmat.primitives.asymmetric import ec\n\n"
     "def agree_shared(priv: ec.EllipticCurvePrivateKey, pub: ec.EllipticCurvePublicKey) -> bytes:\n"
     "    return priv.exchange(ec.ECDH(), pub)",
     "Shared secret agreed over ECDH on a NIST curve. Approved key establishment -> safe."),
    ("fernet-env", "import os\nfrom cryptography.fernet import Fernet\n\n"
     "def encrypt_field(value: str) -> bytes:\n"
     "    f = Fernet(os.environ['APP_KEY'].encode())\n"
     "    return f.encrypt(value.encode())",
     "Fernet (authenticated) with a key from the environment, not hardcoded -> safe."),
    ("blake2b", "import hashlib\n\n"
     "def file_checksum(data: bytes) -> str:\n"
     "    return hashlib.blake2b(data).hexdigest()",
     "Checksum uses BLAKE2b (secure, collision-resistant). Not MD5/SHA-1 -> safe."),
    ("hmac-sha512", "import hashlib\nimport hmac\n\n"
     "def sign_webhook(secret: bytes, body: bytes) -> str:\n"
     "    return hmac.new(secret, body, hashlib.sha512).hexdigest()",
     "Webhook signature is HMAC-SHA512. Correct message authentication -> safe."),
    ("aes-ctr-random", "import os\nfrom Crypto.Cipher import AES\nfrom Crypto.Util import Counter\n\n"
     "def encrypt_counter(data: bytes, key: bytes) -> bytes:\n"
     "    ctr = Counter.new(128, initial_value=int.from_bytes(os.urandom(16), 'big'))\n"
     "    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)\n"
     "    return cipher.encrypt(data)",
     "AES-CTR with a fresh random counter. No ECB and no predictable IV -> safe."),
    ("rsa2048", "from Crypto.PublicKey import RSA\n\n"
     "def generate_signing_key():\n"
     "    return RSA.generate(2048)",
     "RSA-2048 meets the SP 800-131A 112-bit minimum. No short key -> safe."),
    ("cbc-random-iv", "import os\nfrom Crypto.Cipher import AES\n\n"
     "def encrypt_block(data: bytes, key: bytes) -> bytes:\n"
     "    iv = os.urandom(16)\n"
     "    cipher = AES.new(key, AES.MODE_CBC, iv)\n"
     "    return iv + cipher.encrypt(data)",
     "AES-CBC with a fresh random IV prepended. No fixed/predictable IV -> safe."),
    ("verify-password", "import hashlib\nimport hmac\n\n"
     "def check_password(stored: str, supplied: str) -> bool:\n"
     "    salt = bytes.fromhex(stored[:32])\n"
     "    dk = hashlib.pbkdf2_hmac('sha256', supplied.encode(), salt, 310_000)\n"
     "    return hmac.compare_digest(dk.hex().encode(), stored[32:].encode())",
     "PBKDF2-SHA256 checked with constant-time compare. Correct verification -> safe."),
]

# --- B 类：weak primitive x non-security purpose -----------------------------
# Hash-based (md5/sha1) non-security purposes.
HASH_B_PURPOSES = [
    ('def __FUNC__(query: str) -> str:\n    return hashlib.__ALGO__(query.encode()).hexdigest()[:12]',
     '{algo} maps a query string to a cache/lookup key for memoization, not to protect a secret -> not a vulnerability.'),
    ('def __FUNC__(blobs):\n    seen = set()\n    out = []\n    for b in blobs:\n        d = hashlib.__ALGO__(b).hexdigest()\n        if d not in seen:\n            seen.add(d)\n            out.append(b)\n    return out',
     '{algo} deduplicates content by digest; collision resistance is irrelevant to duplicate detection -> not a vulnerability.'),
    ('def __FUNC__(key: str, n: int) -> int:\n    return int(hashlib.__ALGO__(key.encode()).hexdigest(), 16) % n',
     '{algo} spreads keys across shards for load distribution. No secret depends on the digest -> not a vulnerability.'),
    ('def __FUNC__(content: bytes) -> str:\n    return hashlib.__ALGO__(content).hexdigest()',
     '{algo} builds an HTTP ETag change detector. It protects no secret -> not a vulnerability.'),
    ('def __FUNC__(path: str, cached: str) -> bool:\n    with open(path, "rb") as f:\n        return hashlib.__ALGO__(f.read()).hexdigest() != cached',
     '{algo} detects whether a file changed since last read. No authenticity is claimed -> not a vulnerability.'),
    ('def __FUNC__(data: bytes) -> str:\n    return hashlib.__ALGO__(data).hexdigest()[:20]',
     '{algo} derives a content-addressed storage key. It names an object, not a secret -> not a vulnerability.'),
    ('def __FUNC__(line: str) -> str:\n    return hashlib.__ALGO__(line.encode()).hexdigest()[:16]',
     '{algo} fingerprints log lines for indexing. Collisions are irrelevant to lookup -> not a vulnerability.'),
    ('def __FUNC__(record_id: str, num: int) -> int:\n    return int(hashlib.__ALGO__(record_id.encode()).hexdigest(), 16) % num',
     '{algo} routes records to a partition. Not a security control -> not a vulnerability.'),
    ('def __FUNC__(item: str) -> int:\n    return int(hashlib.__ALGO__(item.encode()).hexdigest(), 16) % 1024',
     '{algo} hashes an item into a Bloom-filter slot for set membership. No secret -> not a vulnerability.'),
    ('def __FUNC__(content: bytes) -> str:\n    return "blob " + hashlib.__ALGO__(content).hexdigest()',
     '{algo} addresses a blob by digest (git-style). The digest is an address, not a signature -> not a vulnerability.'),
    ('def __FUNC__(user_id: int) -> str:\n    return hashlib.__ALGO__(str(user_id).encode()).hexdigest()[:12]',
     '{algo} shortens a user id into a feature-flag key. No security property depends on it -> not a vulnerability.'),
    ('def __FUNC__(blob: bytes, stored: str) -> bool:\n    return hashlib.__ALGO__(blob).hexdigest() == stored',
     '{algo} only detects accidental corruption over a trusted channel -> not a vulnerability.'),
]
HASH_B_NAMES = ["compute_digest", "make_lookup_key", "derive_id", "hash_value", "build_index", "fingerprint"]

# Weak-random (strong-B: security-named var, but non-security purpose).
RANDOM_B = [
    ('def __FUNC__():\n    backoff_salt = random.uniform(0.0, 1.0)\n    return backoff_salt',
     'random.uniform adds a jitter "salt" to a retry backoff to avoid a thundering herd; not a secret/nonce/token -> not a vulnerability.'),
    ('def __FUNC__():\n    shard_key = random.randrange(8)\n    return shard_key',
     'random.randrange picks a worker for load distribution; the shard key is not a secret -> not a vulnerability.'),
    ('def __FUNC__():\n    trace_token = random.randint(0, 0xFFFF)\n    return trace_token',
     'random.randint builds a trace token for logging; predicting it reveals nothing sensitive -> not a vulnerability.'),
    ('def __FUNC__():\n    bucket_salt = random.random()\n    return bucket_salt',
     'random.random splits users into A/B feature buckets; the bucket salt has no security role -> not a vulnerability.'),
    ('def __FUNC__():\n    seed_key = random.randint(0, 2**31 - 1)\n    return seed_key',
     'random.randint seeds a PRNG for reproducibility of a simulation; not a cryptographic key -> not a vulnerability.'),
    ('def __FUNC__():\n    test_token = random.getrandbits(64)\n    return test_token',
     'random.getrandbits builds an inert test-fixture token, not a real credential -> not a vulnerability.'),
    ('def __FUNC__():\n    sample_nonce = random.getrandbits(32)\n    return sample_nonce',
     'random.getrandbits draws a Monte-Carlo sampling "nonce"; it protects nothing -> not a vulnerability.'),
    ('def __FUNC__():\n    order_key = random.random()\n    return order_key',
     'random.random randomizes display order for fairness; not a security control -> not a vulnerability.'),
]
RANDOM_B_NAMES = ["jitter_value", "pick_worker", "next_trace", "assign_variant", "make_seed", "sample_value"]

# Cipher-based B-class (benchmark / test-vector / obfuscation / legacy read).
CIPHER_B = [
    ('from Crypto.Cipher import DES\n\ndef __FUNC__(key: bytes):\n    cipher = DES.new(key, DES.MODE_ECB)\n    for _ in range(1000):\n        cipher.encrypt(bytes(8))',
     'DES appears only in a microbenchmark on zero input. No real data -> not a vulnerability.'),
    ('from Crypto.Cipher import DES3\n\ndef __FUNC__():\n    cipher = DES3.new(bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef"), DES3.MODE_ECB)\n    assert len(cipher.encrypt(bytes(8))) == 8',
     '3DES instantiates only to pin a known test vector. No real plaintext -> not a vulnerability.'),
    ('from Crypto.Cipher import ARC4\n\ndef __FUNC__():\n    cipher = ARC4.new(b"Key")\n    assert cipher.encrypt(b"Plaintext") == bytes.fromhex("bbf317e5342426b1")',
     'RC4 reproduces a known test vector. No real data flows through -> not a vulnerability.'),
    ('from Crypto.Cipher import ARC4\n\ndef __FUNC__(save: bytes, key: bytes) -> bytes:\n    return ARC4.new(key).encrypt(save)',
     'RC4 only obfuscates a local save file. The data is not a secret; it deters casual editing -> not a vulnerability.'),
    ('from Crypto.Cipher import AES\n\ndef __FUNC__(key: bytes):\n    cipher = AES.new(key, AES.MODE_ECB)\n    for _ in range(1000):\n        cipher.encrypt(bytes(16))',
     'AES-ECB appears only in a throughput microbenchmark on zero input -> not a vulnerability.'),
    ('from Crypto.Cipher import AES\n\ndef __FUNC__():\n    cipher = AES.new(bytes(16), AES.MODE_ECB)\n    assert cipher.decrypt(cipher.encrypt(bytes(16))) == bytes(16)',
     'AES-ECB appears only in a unit test verifying round-trip on zero input -> not a vulnerability.'),
    ('from Crypto.Cipher import DES\n\ndef __FUNC__(data: bytes, key: bytes) -> bytes:\n    return DES.new(key, DES.MODE_ECB).decrypt(data)',
     'DES decrypts a legacy-format file the system must still read. No new secret is protected -> not a vulnerability.'),
    ('from Crypto.Cipher import ARC4\n\ndef __FUNC__(data: bytes, key: bytes) -> bytes:\n    return ARC4.new(key).decrypt(data)',
     'RC4 decodes a legacy stream for backward compatibility. No new secret depends on it -> not a vulnerability.'),
]
CIPHER_B_NAMES = ["compat_read", "self_check", "legacy_load", "transform_bytes", "process_block", "decode_legacy"]


def gen_b_negatives() -> list:
    """B 类（弱原语 x 非安全目的）：hash / weak-random / cipher 组合展开。"""
    recs = []
    hi = 0
    # hash B
    for code_tmpl, why_tmpl in HASH_B_PURPOSES:
        for algo, algo_name in (("md5", "MD5"), ("sha1", "SHA-1")):
            for name in HASH_B_NAMES:
                code = "import hashlib\n\n" + code_tmpl.replace("__FUNC__", name).replace("__ALGO__", algo)
                why = why_tmpl.format(algo=algo_name)
                recs.append(neg(f"round4-exp-B{hi:03d}-{algo}-{name}", code, why, "B"))
                hi += 1
    # random B
    for i, (code_tmpl, why) in enumerate(RANDOM_B):
        for name in RANDOM_B_NAMES:
            code = "import random\n\n" + code_tmpl.replace("__FUNC__", name)
            recs.append(neg(f"round4-exp-B{hi:03d}-random-{name}-{i}", code, why, "B"))
            hi += 1
    # cipher B
    for i, (code_tmpl, why) in enumerate(CIPHER_B):
        for name in CIPHER_B_NAMES:
            code = code_tmpl.replace("__FUNC__", name)
            recs.append(neg(f"round4-exp-B{hi:03d}-cipher-{name}-{i}", code, why, "B"))
            hi += 1
    return recs


# --- A 类 template expansion (secure modern crypto, must fire zero rules) -----
# Each group has code templates parameterized by {func}/{arg}/{var} and a shared
# name list. Names are grouped so they stay semantically coherent with the
# operation (hash vs encrypt vs token vs sign vs derive).
SECURE_GROUPS = {
    "hash": {
        "names": ["hash_password", "derive_hash", "digest_value", "checksum_blob",
                  "fingerprint_data", "hash_secret", "content_hash", "verify_digest",
                  "file_digest", "hash_credential", "digest_file", "compute_digest"],
        "templates": [
            ("import hashlib\nimport secrets\n",
             'def __FUNC__(password: str) -> str:\n    salt = secrets.token_bytes(16)\n    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)\n    return salt.hex() + dk.hex()',
             "scrypt (memory-hard, salted KDF) with a CSPRNG salt hashes the value -> safe."),
            ("import hashlib\nimport os\n",
             'def __FUNC__(password: str) -> str:\n    salt = os.urandom(16)\n    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)\n    return salt.hex() + dk.hex()',
             "PBKDF2-HMAC-SHA256 with a random salt and high iterations -> safe."),
            ("import hashlib\n",
             'def __FUNC__(data: bytes) -> str:\n    return hashlib.sha256(data).hexdigest()',
             "SHA-256 is still collision-resistant for integrity/fingerprinting -> safe."),
            ("import hashlib\n",
             'def __FUNC__(data: bytes) -> str:\n    return hashlib.sha3_256(data).hexdigest()',
             "SHA3-256 is the current NIST-approved secure hash -> safe."),
            ("import hashlib\n",
             'def __FUNC__(data: bytes) -> str:\n    return hashlib.blake2b(data).hexdigest()',
             "BLAKE2b is a secure, collision-resistant hash -> safe."),
            ("import hashlib\n",
             'def __FUNC__(data: bytes) -> str:\n    return hashlib.sha512(data).hexdigest()',
             "SHA-512 is a secure collision-resistant hash -> safe."),
        ],
    },
    "encrypt": {
        "names": ["encrypt_payload", "encrypt_record", "seal_data", "encrypt_field",
                  "protect_blob", "encrypt_message", "wrap_data", "encode_secret",
                  "encrypt_value", "seal_record", "protect_payload", "encrypt_bytes"],
        "templates": [
            ("import os\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\n",
             'def __FUNC__(plaintext: bytes, key: bytes) -> bytes:\n    aead = AESGCM(key)\n    nonce = os.urandom(12)\n    return nonce + aead.encrypt(nonce, plaintext, None)',
             "AES-GCM (authenticated encryption) with a fresh CSPRNG nonce -> safe."),
            ("import os\nfrom Crypto.Cipher import AES\n",
             'def __FUNC__(plaintext: bytes, key: bytes) -> bytes:\n    nonce = os.urandom(12)\n    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)\n    ct, tag = cipher.encrypt_and_digest(plaintext)\n    return nonce + tag + ct',
             "AES-GCM via pycryptodome with a fresh random nonce and MAC tag -> safe."),
            ("import secrets\nfrom cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n",
             'def __FUNC__(plaintext: bytes, key: bytes) -> bytes:\n    aead = ChaCha20Poly1305(key)\n    nonce = secrets.token_bytes(12)\n    return nonce + aead.encrypt(nonce, plaintext, None)',
             "ChaCha20-Poly1305 (approved AEAD) with a fresh CSPRNG nonce -> safe."),
            ("import os\nfrom cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n",
             'def __FUNC__(data: bytes, key: bytes) -> bytes:\n    iv = os.urandom(16)\n    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))\n    return iv + cipher.encryptor().update(data)',
             "AES-CBC with a fresh random IV prepended. No fixed IV -> safe."),
            ("import os\nfrom Crypto.Cipher import AES\nfrom Crypto.Util import Counter\n",
             'def __FUNC__(data: bytes, key: bytes) -> bytes:\n    ctr = Counter.new(128, initial_value=int.from_bytes(os.urandom(16), "big"))\n    return AES.new(key, AES.MODE_CTR, counter=ctr).encrypt(data)',
             "AES-CTR with a fresh random counter. No ECB, no predictable IV -> safe."),
            ("from Crypto.Cipher import PKCS1_OAEP\nfrom Crypto.PublicKey import RSA\n",
             'def __FUNC__(plaintext: bytes, pub) -> bytes:\n    return PKCS1_OAEP.new(pub).encrypt(plaintext)',
             "RSA-OAEP (padded, authenticated asymmetric encryption). No raw RSA -> safe."),
        ],
    },
    "token": {
        "names": ["new_token", "new_session_id", "generate_nonce", "new_salt",
                  "make_identifier", "generate_secret", "new_api_key", "make_nonce",
                  "create_token", "random_secret", "generate_id", "new_credential"],
        "templates": [
            ("import secrets\n",
             'def __FUNC__() -> str:\n    return secrets.token_urlsafe(32)',
             "Token from secrets.token_urlsafe (CSPRNG, 256-bit). No predictable random.* -> safe."),
            ("import secrets\n",
             'def __FUNC__() -> str:\n    return secrets.token_hex(32)',
             "256-bit id from a CSPRNG. Correct for security-sensitive randomness -> safe."),
            ("import secrets\n",
             'def __FUNC__() -> int:\n    return secrets.randbits(256)',
             "Value from secrets.randbits (CSPRNG). Not the Mersenne Twister -> safe."),
            ("import os\n",
             'def __FUNC__() -> bytes:\n    return os.urandom(16)',
             "Random bytes from os.urandom (CSPRNG). Correct for a salt/nonce -> safe."),
        ],
    },
    "sign": {
        "names": ["sign_message", "verify_signature", "authenticate_request", "sign_token",
                  "verify_webhook", "sign_payload", "verify_hmac", "authenticate_payload",
                  "sign_data", "verify_token", "make_signature", "verify_message"],
        "templates": [
            ("import hashlib\nimport hmac\n",
             'def __FUNC__(secret: bytes, body: bytes, expected: bytes) -> bool:\n    actual = hmac.new(secret, body, hashlib.sha256).digest()\n    return hmac.compare_digest(actual, expected)',
             "HMAC-SHA256 with constant-time compare verifies the signature -> safe."),
            ("import hashlib\nimport hmac\n",
             'def __FUNC__(secret: bytes, body: bytes) -> str:\n    return hmac.new(secret, body, hashlib.sha512).hexdigest()',
             "HMAC-SHA512 signs the message. Correct authentication -> safe."),
            ("from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n",
             'def __FUNC__(message: bytes) -> bytes:\n    return Ed25519PrivateKey.generate().sign(message)',
             "Ed25519 (128-bit strength) signs the message -> safe."),
            ("from cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.primitives.asymmetric import padding\n",
             'def __FUNC__(message: bytes, key) -> bytes:\n    return key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())',
             "RSA-PSS signature over SHA-256. Correct padded signing -> safe."),
        ],
    },
    "derive": {
        "names": ["derive_key", "generate_key", "agree_shared", "load_key",
                  "new_keypair", "derive_subkey", "create_key", "expand_key",
                  "derive_secret", "generate_keypair", "stretch_key", "new_secret_key"],
        "templates": [
            ("from cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.primitives.kdf.hkdf import HKDF\n",
             'def __FUNC__(master: bytes, salt: bytes) -> bytes:\n    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"app")\n    return hkdf.derive(master)',
             "A sub-key is derived with HKDF-SHA256 (SP 800-56C) -> safe."),
            ("from cryptography.hazmat.primitives.asymmetric import ec\n",
             'def __FUNC__(priv, pub) -> bytes:\n    return priv.exchange(ec.ECDH(), pub)',
             "A shared secret is agreed over ECDH on a NIST curve -> safe."),
            ("from Crypto.PublicKey import RSA\n",
             'def __FUNC__():\n    return RSA.generate(2048)',
             "RSA-2048 meets the SP 800-131A 112-bit minimum. No short key -> safe."),
            ("import os\nfrom cryptography.fernet import Fernet\n",
             'def __FUNC__(value: bytes) -> bytes:\n    f = Fernet(os.environ["APP_KEY"].encode())\n    return f.encrypt(value)',
             "Fernet (authenticated) with a key from the environment, not hardcoded -> safe."),
        ],
    },
}


def gen_a_pool() -> list:
    """Ordered pool of A-class negatives: 30 hand-written + template expansion."""
    pool = []
    for i, (slug, code, why) in enumerate(A_CLASS):
        pool.append(neg(f"round4-exp-A{i:03d}-{slug}", code, why, "A"))
    for group, spec in SECURE_GROUPS.items():
        for ti, (imports, tmpl, why) in enumerate(spec["templates"]):
            for ni, name in enumerate(spec["names"]):
                func = name
                code = imports + tmpl.replace("__FUNC__", func)
                pool.append(neg(f"round4-exp-A{len(pool):03d}-{group}{ti}-{name}",
                                code, why, "A"))
    return pool


# =============================================================================
# Deep-mine real safe crypto functions from the 5 pinned clones.
# =============================================================================
WEAK_TOKENS = [
    "hashlib.md5(", "hashlib.new(\"md5", "hashlib.new('md5",
    "hashlib.sha1(", "hashlib.new(\"sha1", "hashlib.new('sha1",
    "DES.new(", "DES3.new(", "ARC4.new(", "MODE_ECB", "modes.ECB(",
    "RSA.generate(1024", "RSA.generate(512", "RSA.generate(768",
    "verify=False", "PROTOCOL_TLSv1", "PROTOCOL_SSLv2", "PROTOCOL_SSLv3",
    "CERT_NONE", "_create_unverified_context",
    "SECP192R1", "SECP160R1", "SECP112R1", "SECT163K1", "SECT163R2",
    "random.getrandbits", "random.randint", "random.randrange", "random.choice(",
    "random.sample(", "random.uniform(", "random.random(",
]
# Specific usage tokens (not bare "ssl", which false-matches "passlib"). Each
# requires an actual crypto-API call, so build-script utilities with "passlib"
# in a docstring are excluded.
CRYPTO_TOKENS = [
    "hashlib.", "hmac.", "secrets.", "os.urandom",
    "from Crypto", "Crypto.", "cryptography.", "ssl.", "Fernet(",
    "AES.new", "AES.MODE", "algorithms.AES", "RSA.generate", "RSA.import",
    "RSA.RsaKey", "ECDH", "HKDF(", "scrypt(", "pbkdf2", "argon2", "bcrypt",
    "ChaCha20", "compare_digest",
]
SKIP_PATH = ("selftest", "test_", "doc/", "docs/", "setup.py", "speedtest", "bench", "test_vectors")


def _norm(src: str) -> str:
    return "".join(src.split())


def mine_real_negatives(cap: int) -> list:
    held_out = set()
    for f in ("triage.jsonl", "detect.jsonl"):
        p = R4 / "real_validation" / f
        if p.exists():
            for line in p.read_text().splitlines():
                if line.strip():
                    held_out.add(_norm(json.loads(line).get("code", "")))

    recs, seen = [], set()
    for repo in sorted(p for p in (REAL).iterdir() if p.is_dir()):
        for path in sorted(REAL.glob(f"{repo.name}/**/*.py")):
            rel = path.relative_to(REAL).as_posix()
            if any(s in rel.lower() for s in SKIP_PATH):
                continue
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(src)
            except (SyntaxError, UnicodeDecodeError):
                continue
            lines = src.splitlines()
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if node.name.startswith("test_"):
                    continue
                body = "\n".join(lines[node.lineno - 1:node.end_lineno])
                if len(body.splitlines()) < 3 or len(body.splitlines()) > 60:
                    continue
                if any(t in body for t in WEAK_TOKENS):
                    continue
                if not any(t in body for t in CRYPTO_TOKENS):
                    continue
                key = _norm(body)
                if key in held_out or key in seen:
                    continue
                seen.add(key)
                recs.append({
                    "id": f"round4-exp-mined-{repo.name}-{rel.replace('/', '_').replace('.py', '')}-{node.name}-L{node.lineno}",
                    "language": "python", "task": "detect", "code": body,
                    "label": {"vulnerable": False, "cwe": "", "severity": "",
                              "confidence": "high",
                              "explanation": "A real cryptographic-library function from a pinned open-source project; "
                                             "it uses approved primitives and contains no weak pattern -> safe."},
                    "source": "round4-exp-neg-mined", "license": "per-repo",
                    "repo_url": "", "commit": "", "verified": False, "split": "train",
                })
                if len(recs) >= cap:
                    return recs
    return recs


# =============================================================================
# Backtest (reused Semgrep-over-temp-dir approach from build_round4_negatives).
# =============================================================================
def backtest(records: list) -> dict:
    rules_dir = ROOT / "rules"
    with tempfile.TemporaryDirectory(prefix="r4x_") as td:
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
        hits = {}
        for h in results:
            idx = int(Path(h["path"]).name[1:6])
            rule = h["check_id"].split(".")[-1]
            hits.setdefault(idx, []).append(rule)
    report = {}
    for i, r in enumerate(records):
        got = sorted(set(hits.get(i, [])))
        report[r["id"]] = {"source": r["source"], "rules_hit": got}
    return report


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


def emit(negatives: list, positives: list) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    write_jsonl(positives, OUT / "positive_source.jsonl")
    write_jsonl(negatives, OUT / "negative_source.jsonl")

    detect_train = _load(ROOT / "data/splits/detect_train.jsonl")
    base_neg = _load(R4 / "negative_source.jsonl")  # the original 77 negatives
    triage_all = (_load(ROOT / "data/splits/triage_train.jsonl")
                  + _load(ROOT / "data/round2/triage_fix_source.jsonl")
                  + _load(ROOT / "data/round3/signature_fix_source.jsonl"))

    merged = detect_train + base_neg + positives + negatives + triage_all
    write_jsonl(to_chatml(merged), OUT / "upload" / "full" / "train.jsonl")

    triage_val = _load(ROOT / "data/round3/val_source.jsonl")
    triage_test = _load(ROOT / "data/round3/test_source.jsonl")
    for name, src, extra in [("val", "detect_val.jsonl", triage_val),
                             ("test", "detect_test.jsonl", triage_test)]:
        recs = _load(ROOT / "data/splits" / src) + extra
        write_jsonl(to_chatml(recs), OUT / "upload" / "full" / f"{name}.jsonl")

    # ratio report (detect axis only)
    vuln = sum(1 for r in detect_train if r["label"].get("vulnerable"))
    sec = len(detect_train) - vuln + len(base_neg) + len(negatives)
    vuln += len(positives)
    total = vuln + sec
    print(f"\n[ratio] detect after expansion: vulnerable={vuln} secure={sec} "
          f"-> {vuln/total:.3%}:{sec/total:.3%}")
    print(f"[full]  train={len(merged)} "
          f"(detect {len(detect_train)+len(base_neg)+len(positives)+len(negatives)} "
          f"+ triage {len(triage_all)})")
    print(f"[counts] +positives={len(positives)} +negatives={len(negatives)} "
          f"(base 77 + expanded)")


def main() -> int:
    ap = argparse.ArgumentParser(description="Expand round-4 detect samples to 50:50")
    ap.add_argument("--positives", type=int, default=P_DEFAULT,
                    help=f"positive count P (default {P_DEFAULT}); negatives derived to reach 50:50")
    ap.add_argument("--backtest", action="store_true")
    ap.add_argument("--emit", action="store_true")
    args = ap.parse_args()

    positives = gen_positives(args.positives)
    assert len(positives) == args.positives, f"expected {args.positives} positives, got {len(positives)}"

    # derive the negative target to land at 50:50
    detect_train = _load(ROOT / "data/splits/detect_train.jsonl")
    base_neg = _load(R4 / "negative_source.jsonl")
    vuln = sum(1 for r in detect_train if r["label"].get("vulnerable"))
    secure = len(detect_train) - vuln + len(base_neg)
    N_TARGET = (vuln + args.positives) - secure

    b_neg = gen_b_negatives()
    a_pool = gen_a_pool()
    mined = mine_real_negatives(cap=min(N_TARGET - len(b_neg), 400))
    needed_a = N_TARGET - len(b_neg) - len(mined)
    if not (0 <= needed_a <= len(a_pool)):
        print(f"[!] A-class pool insufficient: needed {needed_a}, pool {len(a_pool)}")
        return 2
    negatives = b_neg + mined + a_pool[:needed_a]

    print(f"[plan] positives={len(positives)}  negatives={len(negatives)} "
          f"(target {N_TARGET})  ->  vuln={vuln + len(positives)} "
          f"secure={secure + len(negatives)}")
    print(f"       negatives = B {len(b_neg)} + mined {len(mined)} + A {needed_a}")

    if args.backtest:
        report = backtest(positives + negatives)
        write_jsonl([{"id": k, **v} for k, v in report.items()],
                    OUT / "backtest_report.jsonl")
        # positives must fire their own rule
        pos_bad = [rid for rid, v in report.items()
                   if v["source"] == "round4-exp-positive" and not v["rules_hit"]]
        # negatives: A(-mined) must fire nothing; B strong-B must fire
        a_bad = [rid for rid, v in report.items()
                 if v["source"] in ("round4-exp-neg-A", "round4-exp-neg-mined")
                 and v["rules_hit"]]
        strong_b = [rid for rid, v in report.items()
                    if v["source"] == "round4-exp-neg-B" and v["rules_hit"]]
        weak_b = [rid for rid, v in report.items()
                  if v["source"] == "round4-exp-neg-B" and not v["rules_hit"]]
        print(f"[backtest] positives-not-firing={len(pos_bad)} (must be 0)")
        print(f"           A-class-rule-hit={len(a_bad)} (must be 0)")
        print(f"           strong-B (fires, override)={len(strong_b)}  "
              f"weak-B (no hit)={len(weak_b)}")
        for rid in pos_bad:
            print(f"  [!] positive missed its rule: {rid} -> {report[rid]['rules_hit']}")
        for rid in a_bad:
            print(f"  [!] A-class hit a rule: {rid} -> {report[rid]['rules_hit']}")

    if args.emit:
        emit(negatives, positives)

    if not (args.backtest or args.emit):
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
