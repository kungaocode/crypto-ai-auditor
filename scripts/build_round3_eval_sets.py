#!/usr/bin/env python3
"""Build round-3 validation / test sets: 130 rows each = 100 detect + 30 triage.

- detect: sample 100 from existing detect_val / detect_test splits
- triage: 30 new hand-written samples (15 Confirm + 15 Reject, 10 rules × 3 each)

Writes:
- data/round3/val_source.jsonl (v2 schema, 130 rows)
- data/round3/test_source.jsonl (v2 schema, 130 rows)
- data/round3/upload/val.jsonl (chatml, 130 rows)
- data/round3/upload/test.jsonl (chatml, 130 rows)
"""
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.prepare_sft_data import build_messages  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

MSG = {
    "CRYPTO-001": "Use of MD5 which is not collision-resistant.",
    "CRYPTO-002": "Use of SHA-1 which is not collision-resistant.",
    "CRYPTO-003": "Use of DES or 3DES which have small block sizes and are considered weak.",
    "CRYPTO-004": "Use of RC4 which has multiple statistical biases and is deprecated.",
    "CRYPTO-005": "AES in ECB mode leaks patterns in plaintext; use an authenticated mode such as AES-GCM.",
    "CRYPTO-006": "Predictable or hardcoded IV used in a block cipher mode. Use a fresh random IV per encryption.",
    "CRYPTO-007": "Hard-coded cryptographic key found inline. Keys must be loaded from secrets management, env vars, or a KDF.",
    "CRYPTO-008": "random module used for a security-sensitive value. random.* is not cryptographically secure; use secrets or os.urandom.",
    "CRYPTO-009": "Weak key length or weak elliptic curve. Use RSA >= 2048 bits or a NIST P-256+ curve.",
    "CRYPTO-010": "Insecure TLS configuration: weak protocol version, disabled certificate validation, or unverified context.",
}
CWE = {
    "CRYPTO-001": "CWE-327", "CRYPTO-002": "CWE-327", "CRYPTO-003": "CWE-327",
    "CRYPTO-004": "CWE-327", "CRYPTO-005": "CWE-327", "CRYPTO-006": "CWE-329",
    "CRYPTO-007": "CWE-321", "CRYPTO-008": "CWE-338", "CRYPTO-009": "CWE-326",
    "CRYPTO-010": "CWE-326",
}


def rec(id, rule, verdict, code, expl, patch=""):
    return {
        "id": id, "language": "python", "task": "triage", "code": code,
        "finding": f"[{rule}] {MSG[rule]}",
        "label": {"cwe": CWE[rule], "severity": "WARNING", "verdict": verdict,
                  "explanation": expl, "patch": patch},
        "source": "round3-" + id.split("-")[0], "license": "original",
        "repo_url": "", "commit": "", "verified": True,
        "split": "val" if id.startswith("val-") else "test",
    }


# ============== VAL TRIAGE (30 rows: 15 Confirm + 15 Reject) ==============
VAL_TRIAGE = [
    # CRYPTO-001 MD5: 2 Confirm + 1 Reject
    rec("val-CRYPTO-001-3-Confirm", "CRYPTO-001", "Confirm",
"""import hashlib

def generate_csrf_token(session_id):
    return hashlib.md5(session_id.encode()).hexdigest()""",
"MD5 derives a CSRF token from the session id. MD5 is collision-broken and too fast; an attacker can brute-force or forge tokens. Security-sensitive value -> Confirm.",
"""import secrets

def generate_csrf_token(session_id):
    return secrets.token_urlsafe(32)"""),

    rec("val-CRYPTO-001-4-Confirm", "CRYPTO-001", "Confirm",
"""import hashlib

def verify_legacy_password(user, raw):
    stored = db.get_password_hash(user)
    return stored == hashlib.md5(raw.encode()).hexdigest()""",
"MD5 compares a user-supplied password against a stored hash. MD5 is fast and collision-broken, making offline cracking trivial; password verification needs a slow salted KDF. Real finding -> Confirm.",
"""import hashlib, secrets

def verify_legacy_password(user, raw):
    salt, stored = db.get_password_record(user)
    return stored == hashlib.scrypt(raw.encode(), salt=salt, n=2**14, r=8, p=1).hex()"""),

    rec("val-CRYPTO-001-5-Reject", "CRYPTO-001", "Reject",
"""def deduplicate_files(file_list):
    import hashlib
    seen = {}
    for f in file_list:
        h = hashlib.md5(f.read()).hexdigest()
        if h not in seen:
            seen[h] = f
    return list(seen.values())""",
"MD5 only deduplicates files by content hash. The hash identifies data for grouping, not for security; collision resistance is irrelevant for backup dedup -> Reject."),

    # CRYPTO-002 SHA-1: 2 Confirm + 1 Reject
    rec("val-CRYPTO-002-3-Confirm", "CRYPTO-002", "Confirm",
"""import hashlib

def hash_api_key(key):
    return hashlib.sha1(key.encode()).hexdigest()""",
"SHA-1 hashes an API key for storage. SHA-1 is fast and collision-broken; if the hash leaks, the key can be brute-forced. API key storage needs a slow KDF or HMAC. Real finding -> Confirm.",
"""import hashlib, secrets

def hash_api_key(key):
    salt = secrets.token_bytes(16)
    return salt.hex() + hashlib.scrypt(key.encode(), salt=salt, n=2**14, r=8, p=1).hex()"""),

    rec("val-CRYPTO-002-4-Confirm", "CRYPTO-002", "Confirm",
"""import hashlib

def verify_saml_signature(response_xml, expected_sig):
    digest = hashlib.sha1(response_xml.encode()).digest()
    return digest == expected_sig""",
"SHA-1 verifies a SAML response signature. SHA-1 is collision-broken; an attacker can forge a signature. SAML signatures require SHA-256+. Real finding -> Confirm.",
"""import hashlib

def verify_saml_signature(response_xml, expected_sig):
    digest = hashlib.sha256(response_xml.encode()).digest()
    return digest == expected_sig"""),

    rec("val-CRYPTO-002-5-Reject", "CRYPTO-002", "Reject",
"""def index_log_line(line):
    import hashlib
    return hashlib.sha1(line.encode()).hexdigest()[:16]""",
"SHA-1 fingerprints log lines for indexing. The digest identifies data in the pipeline, it does not protect it; no signature, credential, or integrity guarantee relies on it -> Reject."),

    # CRYPTO-003 DES: 1 Confirm + 2 Reject
    rec("val-CRYPTO-003-3-Confirm", "CRYPTO-003", "Confirm",
"""from Crypto.Cipher import DES3

def encrypt_legacy_payment_data(card_number):
    key = load_legacy_3des_key()
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(pad(card_number, 8))""",
"3DES encrypts payment card data. 3DES has a 64-bit block size and is vulnerable to Sweet32; payment data needs AES-GCM. Real finding -> Confirm.",
"""from Crypto.Cipher import AES

def encrypt_legacy_payment_data(card_number):
    key = load_aes_key()
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(pad(card_number, 16))
    return cipher.nonce + tag + ct"""),

    rec("val-CRYPTO-003-4-Reject", "CRYPTO-003", "Reject",
"""def test_des3_block_size():
    from Crypto.Cipher import DES3
    key = bytes.fromhex("0123456789abcdef01234567")
    cipher = DES3.new(key, DES3.MODE_ECB)
    assert len(cipher.encrypt(bytes(8))) == 8""",
"3DES appears only inside a unit test asserting block-size behaviour on throwaway zero input. No real plaintext is encrypted and the cipher never leaves the test -> Reject."),

    rec("val-CRYPTO-003-5-Reject", "CRYPTO-003", "Reject",
"""def benchmark_des_performance():
    from Crypto.Cipher import DES
    import time
    key = b"\\x00" * 8
    cipher = DES.new(key, DES.MODE_ECB)
    start = time.time()
    for _ in range(10000):
        cipher.encrypt(bytes(8))
    return time.time() - start""",
"DES appears only in a microbenchmark measuring encryption throughput on throwaway zero input. No real data is encrypted; this is performance testing scaffolding -> Reject."),

    # CRYPTO-004 RC4: 1 Confirm + 2 Reject
    rec("val-CRYPTO-004-3-Confirm", "CRYPTO-004", "Confirm",
"""from Crypto.Cipher import ARC4

def decrypt_legacy_config(encrypted_blob, key):
    cipher = ARC4.new(key)
    return cipher.decrypt(encrypted_blob)""",
"RC4 decrypts a legacy configuration blob. RC4 has known keystream biases and no authentication; plaintext can be recovered and tampered with. Real finding -> Confirm.",
"""from Crypto.Cipher import AES

def decrypt_legacy_config(encrypted_blob, key):
    nonce = encrypted_blob[:16]
    tag = encrypted_blob[16:32]
    ct = encrypted_blob[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)"""),

    rec("val-CRYPTO-004-4-Reject", "CRYPTO-004", "Reject",
"""def test_rc4_golden_vector():
    from Crypto.Cipher import ARC4
    cipher = ARC4.new(b"Key")
    plaintext = b"Plaintext"
    expected = bytes.fromhex("bbf317e5342426b1")
    assert cipher.encrypt(plaintext) == expected""",
"RC4 is instantiated only to reproduce a known test vector inside a unit test. The literal key is a fixture and no real data flows through the cipher -> Reject."),

    rec("val-CRYPTO-004-5-Reject", "CRYPTO-004", "Reject",
"""def obfuscate_save_game(save_data):
    from Crypto.Cipher import ARC4
    key = bytes.fromhex("deadbeef" * 4)
    cipher = ARC4.new(key)
    return cipher.encrypt(save_data)""",
"RC4 obfuscates a local save-game file. The data is not security-sensitive (no credentials, no PII); obfuscation is cosmetic to prevent casual editing, not to protect against attackers -> Reject."),

    # CRYPTO-005 AES-ECB: 1 Confirm + 2 Reject
    rec("val-CRYPTO-005-3-Confirm", "CRYPTO-005", "Confirm",
"""from Crypto.Cipher import AES

def encrypt_user_profile(profile_data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(profile_data, 16))""",
"AES-ECB encrypts user profile data. ECB leaks plaintext patterns (identical blocks produce identical ciphertext); user data needs AES-GCM or AES-CBC with random IV. Real finding -> Confirm.",
"""from Crypto.Cipher import AES

def encrypt_user_profile(profile_data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(profile_data)
    return cipher.nonce + tag + ct"""),

    rec("val-CRYPTO-005-4-Reject", "CRYPTO-005", "Reject",
"""def test_ecb_encrypt_empty_block():
    from Crypto.Cipher import AES
    key = bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    assert len(cipher.encrypt(bytes(16))) == 16""",
"AES-ECB appears only inside a unit test asserting block-size behaviour on throwaway zero input. No real plaintext is encrypted and the cipher never leaves the test -> Reject."),

    rec("val-CRYPTO-005-5-Reject", "CRYPTO-005", "Reject",
"""def benchmark_aes_ecb_throughput():
    from Crypto.Cipher import AES
    import time
    key = bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    start = time.time()
    for _ in range(10000):
        cipher.encrypt(bytes(16))
    return time.time() - start""",
"AES-ECB appears only in a microbenchmark measuring encryption throughput on throwaway zero input. No real data is encrypted; this is performance testing scaffolding -> Reject."),

    # CRYPTO-006 Predictable IV: 1 Confirm + 2 Reject
    rec("val-CRYPTO-006-3-Confirm", "CRYPTO-006", "Confirm",
"""from Crypto.Cipher import AES

def encrypt_config_section(section, key):
    cipher = AES.new(key, AES.MODE_CBC, IV=b"")
    return cipher.encrypt(pad(section, 16))""",
"CBC encryption uses a fixed all-zero IV for every record. Identical prefixes leak and related plaintexts become linkable; each encryption needs a fresh unpredictable IV. Real finding -> Confirm.",
"""from Crypto.Cipher import AES
import secrets

def encrypt_config_section(section, key):
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    return iv + cipher.encrypt(pad(section, 16))"""),

    rec("val-CRYPTO-006-4-Reject", "CRYPTO-006", "Reject",
"""def test_cbc_zero_iv_roundtrip():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(bytes(16)), modes.CBC(bytes(16)))
    enc = cipher.encryptor()
    assert len(enc.update(bytes(16))) == 16""",
"modes.CBC(bytes(16)) appears only in a smoke test that exercises the cipher object with fixed zero input. Nothing real is encrypted and the fixture never leaves the test -> Reject."),

    rec("val-CRYPTO-006-5-Reject", "CRYPTO-006", "Reject",
"""def benchmark_cbc_mode():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import time
    cipher = Cipher(algorithms.AES(bytes(16)), modes.CBC(bytes(16)))
    start = time.time()
    for _ in range(1000):
        enc = cipher.encryptor()
        enc.update(bytes(16))
    return time.time() - start""",
"modes.CBC(bytes(16)) appears only in a microbenchmark measuring encryption throughput on throwaway zero input. No real data is encrypted; this is performance testing scaffolding -> Reject."),

    # CRYPTO-007 Hard-coded Key: 2 Confirm + 1 Reject
    rec("val-CRYPTO-007-3-Confirm", "CRYPTO-007", "Confirm",
"""from Crypto.Cipher import AES

def encrypt_session_cookie(cookie_data):
    cipher = AES.new(b"session-secret-key-2024", AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(cookie_data)
    return cipher.nonce + tag + ct""",
"The session cookie encryption key is hardcoded in source. Anyone with repo access can decrypt every session cookie and hijack accounts; keys belong in a secrets manager or env-based configuration. Real finding -> Confirm.",
"""import os
from Crypto.Cipher import AES

def encrypt_session_cookie(cookie_data):
    key = os.environ["SESSION_KEY"].encode()
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(cookie_data)
    return cipher.nonce + tag + ct"""),

    rec("val-CRYPTO-007-4-Confirm", "CRYPTO-007", "Confirm",
"""from cryptography.fernet import Fernet

def encrypt_api_response(response_data):
    f = Fernet(b"api-response-encryption-key-prod")
    return f.encrypt(response_data)""",
"The API response encryption key is hardcoded as a Fernet key. Anyone with repo access can decrypt every API response; keys belong in a secrets manager or env-based configuration. Real finding -> Confirm.",
"""import os
from cryptography.fernet import Fernet

def encrypt_api_response(response_data):
    f = Fernet(os.environ["API_KEY"].encode())
    return f.encrypt(response_data)"""),

    rec("val-CRYPTO-007-5-Reject", "CRYPTO-007", "Reject",
"""def test_fernet_roundtrip():
    from cryptography.fernet import Fernet
    f = Fernet(b"test-only-sample-key-0000000000000")
    token = f.encrypt(b'test message')
    assert f.decrypt(token) == b'test message'""",
"Fernet appears only inside a unit test that generates a fresh key and verifies round-trip behaviour. The key is test scaffolding that never touches real data -> Reject."),

    # CRYPTO-008 Weak Random: 2 Confirm + 1 Reject
    rec("val-CRYPTO-008-3-Confirm", "CRYPTO-008", "Confirm",
"""import random

def generate_session_token():
    token_secret = random.getrandbits(128)
    return token_secret""",
"A session token is generated with random.getrandbits. The Mersenne Twister is predictable once a few outputs are seen, so an attacker can reconstruct the token and hijack sessions. Security-sensitive value -> Confirm.",
"""import secrets

def generate_session_token():
    token_secret = secrets.randbits(128)
    return token_secret"""),

    rec("val-CRYPTO-008-4-Confirm", "CRYPTO-008", "Confirm",
"""import random

def generate_nonce():
    nonce_val = random.randint(0, 2**64)
    return nonce_val""",
"A cryptographic nonce is generated with random.randint. The Mersenne Twister is predictable; an attacker can forecast nonces and break replay protection. Security-sensitive value -> Confirm.",
"""import secrets

def generate_nonce():
    nonce_val = secrets.randbelow(2**64)
    return nonce_val"""),

    rec("val-CRYPTO-008-5-Reject", "CRYPTO-008", "Reject",
"""def generate_request_id():
    import random
    request_token = random.randint(100000, 999999)
    return request_token""",
"random.randint generates a request id for logging/tracing. The id is not security-sensitive (no authentication, no replay protection); predicting it reveals nothing sensitive. Not security-sensitive -> Reject."),

    # CRYPTO-009 Weak Key Length: 1 Confirm + 2 Reject
    rec("val-CRYPTO-009-3-Confirm", "CRYPTO-009", "Confirm",
"""from Crypto.PublicKey import RSA

def generate_code_signing_key():
    return RSA.generate(1024)""",
"A 1024-bit RSA key is generated for code signing. 1024-bit RSA is within reach of well-resourced attackers; signing keys need >= 2048 bits. Real finding -> Confirm.",
"""from Crypto.PublicKey import RSA

def generate_code_signing_key():
    return RSA.generate(2048)"""),

    rec("val-CRYPTO-009-4-Reject", "CRYPTO-009", "Reject",
"""def test_rsa_key_generation():
    from Crypto.PublicKey import RSA
    key = RSA.generate(1024)
    assert key.size_in_bits() == 1024""",
"RSA.generate(2048) appears only inside a unit test verifying key generation works correctly. The key is test scaffolding that never touches real data -> Reject."),

    rec("val-CRYPTO-009-5-Reject", "CRYPTO-009", "Reject",
"""def benchmark_rsa_keygen():
    from Crypto.PublicKey import RSA
    import time
    start = time.time()
    for _ in range(10):
        RSA.generate(1024)
    return time.time() - start""",
"RSA.generate(2048) appears only in a microbenchmark measuring key generation throughput. The keys are throwaway and never touch real data; this is performance testing scaffolding -> Reject."),

    # CRYPTO-010 Insecure TLS: 2 Confirm + 1 Reject
    rec("val-CRYPTO-010-3-Confirm", "CRYPTO-010", "Confirm",
"""import requests

def fetch_payment_gateway(url, payload):
    return requests.post(url, json=payload, timeout=10, verify=False)""",
"Production payment gateway delivery disables TLS certificate validation, so any on-path attacker can intercept or modify the payload with a bogus certificate. Real finding -> Confirm.",
"""import requests

def fetch_payment_gateway(url, payload):
    return requests.post(url, json=payload, timeout=10)"""),

    rec("val-CRYPTO-010-4-Confirm", "CRYPTO-010", "Confirm",
"""import ssl

def create_legacy_ssl_context():
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)""",
"TLS 1.0 is disabled in modern browsers and has known vulnerabilities (BEAST, POODLE). Production TLS needs TLS 1.2+. Real finding -> Confirm.",
"""import ssl

def create_legacy_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx"""),

    rec("val-CRYPTO-010-5-Reject", "CRYPTO-010", "Reject",
"""def check_local_health(url):
    import requests
    for _ in range(10):
        try:
            r = requests.get(url, verify=False, timeout=2)
            if r.status_code == 200:
                return True
        except requests.ConnectionError:
            pass
    return False""",
"verify=False only appears in a startup loop that waits for a localhost dev server to come up. There is no remote endpoint and nothing sensitive in flight; not a security-relevant TLS decision -> Reject."),
]


# ============== TEST TRIAGE (30 rows: 15 Confirm + 15 Reject) ==============
TEST_TRIAGE = [
    # CRYPTO-001 MD5: 2 Confirm + 1 Reject
    rec("test-CRYPTO-001-3-Confirm", "CRYPTO-001", "Confirm",
"""import hashlib

def generate_password_reset_token(user_id):
    return hashlib.md5(user_id.encode()).hexdigest()""",
"MD5 derives a password reset token from the user id. MD5 is collision-broken and too fast; an attacker can brute-force or forge tokens. Security-sensitive value -> Confirm.",
"""import secrets

def generate_password_reset_token(user_id):
    return secrets.token_urlsafe(32)"""),

    rec("test-CRYPTO-001-4-Confirm", "CRYPTO-001", "Confirm",
"""import hashlib

def verify_download_integrity(file_path, expected_hash):
    with open(file_path, "rb") as f:
        actual = hashlib.md5(f.read()).hexdigest()
    return actual == expected_hash""",
"MD5 verifies download integrity. MD5 is collision-broken; an attacker can substitute a malicious file with the same hash. Integrity verification needs SHA-256+. Real finding -> Confirm.",
"""import hashlib

def verify_download_integrity(file_path, expected_hash):
    with open(file_path, "rb") as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    return actual == expected_hash"""),

    rec("test-CRYPTO-001-5-Reject", "CRYPTO-001", "Reject",
"""def generate_cache_key(url):
    import hashlib
    return hashlib.md5(url.encode()).hexdigest()""",
"MD5 derives a cache key from the URL. The key identifies data for caching, not for security; collision resistance is irrelevant for cache lookups -> Reject."),

    # CRYPTO-002 SHA-1: 2 Confirm + 1 Reject
    rec("test-CRYPTO-002-3-Confirm", "CRYPTO-002", "Confirm",
"""import hashlib

def hash_session_id(session_data):
    return hashlib.sha1(session_data.encode()).hexdigest()""",
"SHA-1 hashes session data to produce a session id. SHA-1 is fast and collision-broken; if the hash leaks, the session can be hijacked. Session ids need a CSPRNG. Real finding -> Confirm.",
"""import secrets

def hash_session_id(session_data):
    return secrets.token_urlsafe(32)"""),

    rec("test-CRYPTO-002-4-Confirm", "CRYPTO-002", "Confirm",
"""import hashlib

def verify_certificate_fingerprint(cert_pem, expected_fp):
    digest = hashlib.sha1(cert_pem).digest()
    return digest == expected_fp""",
"SHA-1 verifies a certificate fingerprint. SHA-1 is collision-broken; an attacker can forge a certificate with the same fingerprint. Certificate fingerprints require SHA-256+. Real finding -> Confirm.",
"""import hashlib

def verify_certificate_fingerprint(cert_pem, expected_fp):
    digest = hashlib.sha256(cert_pem).digest()
    return digest == expected_fp"""),

    rec("test-CRYPTO-002-5-Reject", "CRYPTO-002", "Reject",
"""def generate_file_id(content):
    import hashlib
    return hashlib.sha1(content).hexdigest()[:20]""",
"SHA-1 derives a file id from content. The id identifies data for storage, not for security; collision resistance is irrelevant for file lookups -> Reject."),

    # CRYPTO-003 DES: 1 Confirm + 2 Reject
    rec("test-CRYPTO-003-3-Confirm", "CRYPTO-003", "Confirm",
"""from Crypto.Cipher import DES

def encrypt_legacy_credentials(username, password):
    key = load_legacy_des_key()
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(f"{username}:{password}", 8))""",
"DES encrypts legacy credentials. DES has a 56-bit key and is brute-forceable; credentials need AES-GCM. Real finding -> Confirm.",
"""from Crypto.Cipher import AES

def encrypt_legacy_credentials(username, password):
    key = load_aes_key()
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(f"{username}:{password}".encode())
    return cipher.nonce + tag + ct"""),

    rec("test-CRYPTO-003-4-Reject", "CRYPTO-003", "Reject",
"""def test_des_encrypt_block():
    from Crypto.Cipher import DES
    key = b"\\x00" * 8
    cipher = DES.new(key, DES.MODE_ECB)
    assert len(cipher.encrypt(bytes(8))) == 8""",
"DES appears only inside a unit test asserting block-size behaviour on throwaway zero input. No real plaintext is encrypted and the cipher never leaves the test -> Reject."),

    rec("test-CRYPTO-003-5-Reject", "CRYPTO-003", "Reject",
"""def benchmark_des3_throughput():
    from Crypto.Cipher import DES3
    import time
    key = b"\\x00" * 24
    cipher = DES3.new(key, DES3.MODE_ECB)
    start = time.time()
    for _ in range(10000):
        cipher.encrypt(bytes(8))
    return time.time() - start""",
"3DES appears only in a microbenchmark measuring encryption throughput on throwaway zero input. No real data is encrypted; this is performance testing scaffolding -> Reject."),

    # CRYPTO-004 RC4: 1 Confirm + 2 Reject
    rec("test-CRYPTO-004-3-Confirm", "CRYPTO-004", "Confirm",
"""from Crypto.Cipher import ARC4

def encrypt_chat_history(messages, key):
    cipher = ARC4.new(key)
    return cipher.encrypt(messages)""",
"RC4 encrypts chat history. RC4 has known keystream biases and no authentication; plaintext can be recovered and tampered with. Real finding -> Confirm.",
"""from Crypto.Cipher import AES

def encrypt_chat_history(messages, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(messages)
    return cipher.nonce + tag + ct"""),

    rec("test-CRYPTO-004-4-Reject", "CRYPTO-004", "Reject",
"""def test_rc4_encrypt_empty():
    from Crypto.Cipher import ARC4
    key = bytes(16)
    cipher = ARC4.new(key)
    assert len(cipher.encrypt(bytes(8))) == 8""",
"RC4 appears only inside a unit test asserting output length on throwaway zero input. No real plaintext is encrypted and the cipher never leaves the test -> Reject."),

    rec("test-CRYPTO-004-5-Reject", "CRYPTO-004", "Reject",
"""def benchmark_rc4_throughput():
    from Crypto.Cipher import ARC4
    import time
    key = b"\\x00" * 16
    cipher = ARC4.new(key)
    start = time.time()
    for _ in range(10000):
        cipher.encrypt(bytes(16))
    return time.time() - start""",
"RC4 appears only in a microbenchmark measuring encryption throughput on throwaway zero input. No real data is encrypted; this is performance testing scaffolding -> Reject."),

    # CRYPTO-005 AES-ECB: 1 Confirm + 2 Reject
    rec("test-CRYPTO-005-3-Confirm", "CRYPTO-005", "Confirm",
"""from Crypto.Cipher import AES

def encrypt_database_field(field_data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(field_data, 16))""",
"AES-ECB encrypts a database field. ECB leaks plaintext patterns (identical blocks produce identical ciphertext); database fields need AES-GCM or AES-CBC with random IV. Real finding -> Confirm.",
"""from Crypto.Cipher import AES
import secrets

def encrypt_database_field(field_data, key):
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    return iv + cipher.encrypt(pad(field_data, 16))"""),

    rec("test-CRYPTO-005-4-Reject", "CRYPTO-005", "Reject",
"""def test_ecb_decrypt_block():
    from Crypto.Cipher import AES
    key = bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(bytes(16))
    assert cipher.decrypt(ct) == bytes(16)""",
"AES-ECB appears only inside a unit test verifying round-trip behaviour on throwaway zero input. No real plaintext is encrypted and the cipher never leaves the test -> Reject."),

    rec("test-CRYPTO-005-5-Reject", "CRYPTO-005", "Reject",
"""def benchmark_aes_modes():
    from Crypto.Cipher import AES
    import time
    key = bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    start = time.time()
    for _ in range(1000):
        cipher.encrypt(bytes(16))
    return time.time() - start""",
"AES-ECB appears only in a microbenchmark comparing mode throughput on throwaway zero input. No real data is encrypted; this is performance testing scaffolding -> Reject."),

    # CRYPTO-006 Predictable IV: 1 Confirm + 2 Reject
    rec("test-CRYPTO-006-3-Confirm", "CRYPTO-006", "Confirm",
"""from Crypto.Cipher import AES

def encrypt_log_entry(entry, key):
    cipher = AES.new(key, AES.MODE_CFB, IV=b"")
    return cipher.encrypt(entry)""",
"CFB encryption uses a fixed all-zero IV for every record. Identical prefixes leak and related plaintexts become linkable; each encryption needs a fresh unpredictable IV. Real finding -> Confirm.",
"""from Crypto.Cipher import AES
import secrets

def encrypt_log_entry(entry, key):
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, IV=iv)
    return iv + cipher.encrypt(entry)"""),

    rec("test-CRYPTO-006-4-Reject", "CRYPTO-006", "Reject",
"""def test_cfb_zero_iv():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(bytes(16)), modes.CBC(bytes(16)))
    enc = cipher.encryptor()
    assert len(enc.update(bytes(16))) == 16""",
"modes.CFB(bytes(16)) appears only in a smoke test that exercises the cipher object with fixed zero input. Nothing real is encrypted and the fixture never leaves the test -> Reject."),

    rec("test-CRYPTO-006-5-Reject", "CRYPTO-006", "Reject",
"""def benchmark_cfb_mode():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import time
    cipher = Cipher(algorithms.AES(bytes(16)), modes.CBC(bytes(16)))
    start = time.time()
    for _ in range(1000):
        enc = cipher.encryptor()
        enc.update(bytes(16))
    return time.time() - start""",
"modes.CFB(bytes(16)) appears only in a microbenchmark measuring encryption throughput on throwaway zero input. No real data is encrypted; this is performance testing scaffolding -> Reject."),

    # CRYPTO-007 Hard-coded Key: 2 Confirm + 1 Reject
    rec("test-CRYPTO-007-3-Confirm", "CRYPTO-007", "Confirm",
"""from Crypto.Cipher import AES

def encrypt_audit_log(log_entry):
    cipher = AES.new(b"audit-log-encryption-key-2024", AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(log_entry)
    return cipher.nonce + tag + ct""",
"The audit log encryption key is hardcoded in source. Anyone with repo access can decrypt every audit log and hide malicious activity; keys belong in a secrets manager or env-based configuration. Real finding -> Confirm.",
"""import os
from Crypto.Cipher import AES

def encrypt_audit_log(log_entry):
    key = os.environ["AUDIT_KEY"].encode()
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(log_entry)
    return cipher.nonce + tag + ct"""),

    rec("test-CRYPTO-007-4-Confirm", "CRYPTO-007", "Confirm",
"""from cryptography.fernet import Fernet

def encrypt_user_email(email):
    f = Fernet(b"user-email-encryption-key-prod")
    return f.encrypt(email)""",
"The user email encryption key is hardcoded as a Fernet key. Anyone with repo access can decrypt every user email; keys belong in a secrets manager or env-based configuration. Real finding -> Confirm.",
"""import os
from cryptography.fernet import Fernet

def encrypt_user_email(email):
    f = Fernet(os.environ["EMAIL_KEY"].encode())
    return f.encrypt(email)"""),

    rec("test-CRYPTO-007-5-Reject", "CRYPTO-007", "Reject",
"""def test_aes_generate_key():
    from Crypto.Cipher import AES
    cipher = AES.new(b"test-only-sample-key-0000000", AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(b"test")
    assert len(ct) == 4""",
"AES appears only inside a unit test that generates a fresh key and verifies encryption works. The key is test scaffolding that never touches real data -> Reject."),

    # CRYPTO-008 Weak Random: 2 Confirm + 1 Reject
    rec("test-CRYPTO-008-3-Confirm", "CRYPTO-008", "Confirm",
"""import random

def generate_api_key():
    api_key_secret = random.getrandbits(256)
    return api_key_secret""",
"An API key is generated with random.getrandbits. The Mersenne Twister is predictable once a few outputs are seen, so an attacker can reconstruct the key. Security-sensitive value -> Confirm.",
"""import secrets

def generate_api_key():
    api_key_secret = secrets.randbits(256)
    return api_key_secret"""),

    rec("test-CRYPTO-008-4-Confirm", "CRYPTO-008", "Confirm",
"""import random

def generate_salt():
    salt_val = random.randint(0, 2**128)
    return salt_val""",
"A cryptographic salt is generated with random.randint. The Mersenne Twister is predictable; an attacker can forecast salts and weaken password hashing. Security-sensitive value -> Confirm.",
"""import secrets

def generate_salt():
    salt_val = secrets.randbelow(2**128)
    return salt_val"""),

    rec("test-CRYPTO-008-5-Reject", "CRYPTO-008", "Reject",
"""def generate_trace_id():
    import random
    trace_token = random.randint(1000000, 9999999)
    return trace_token""",
"random.randint generates a trace id for distributed tracing. The id is not security-sensitive (no authentication, no replay protection); predicting it reveals nothing sensitive. Not security-sensitive -> Reject."),

    # CRYPTO-009 Weak Key Length: 1 Confirm + 2 Reject
    rec("test-CRYPTO-009-3-Confirm", "CRYPTO-009", "Confirm",
"""from Crypto.PublicKey import RSA

def generate_jwt_signing_key():
    return RSA.generate(1024)""",
"A 1024-bit RSA key is generated for JWT signing. 1024-bit RSA is within reach of well-resourced attackers; signing keys need >= 2048 bits. Real finding -> Confirm.",
"""from Crypto.PublicKey import RSA

def generate_jwt_signing_key():
    return RSA.generate(2048)"""),

    rec("test-CRYPTO-009-4-Reject", "CRYPTO-009", "Reject",
"""def test_rsa_encrypt_decrypt():
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    key = RSA.generate(1024)
    cipher = PKCS1_OAEP.new(key)
    ct = cipher.encrypt(b'test')
    assert cipher.decrypt(ct) == b'test'""",
"RSA.generate(2048) appears only inside a unit test verifying encryption round-trip works correctly. The key is test scaffolding that never touches real data -> Reject."),

    rec("test-CRYPTO-009-5-Reject", "CRYPTO-009", "Reject",
"""def benchmark_rsa_encrypt():
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    import time
    key = RSA.generate(1024)
    cipher = PKCS1_OAEP.new(key)
    start = time.time()
    for _ in range(100):
        cipher.encrypt(b"test")
    return time.time() - start""",
"RSA.generate(2048) appears only in a microbenchmark measuring encryption throughput. The keys are throwaway and never touch real data; this is performance testing scaffolding -> Reject."),

    # CRYPTO-010 Insecure TLS: 2 Confirm + 1 Reject
    rec("test-CRYPTO-010-3-Confirm", "CRYPTO-010", "Confirm",
"""import requests

def fetch_user_data(api_url, user_id):
    return requests.get(f"{api_url}/users/{user_id}", verify=False, timeout=10)""",
"Production user data fetch disables TLS certificate validation, so any on-path attacker can intercept or modify the payload with a bogus certificate. Real finding -> Confirm.",
"""import requests

def fetch_user_data(api_url, user_id):
    return requests.get(f"{api_url}/users/{user_id}", timeout=10)"""),

    rec("test-CRYPTO-010-4-Confirm", "CRYPTO-010", "Confirm",
"""import ssl

def create_internal_api_context():
    return ssl._create_unverified_context()""",
"An unverified SSL context is created for internal API calls. This disables certificate validation, so any on-path attacker can intercept or modify the payload. Real finding -> Confirm.",
"""import ssl

def create_internal_api_context():
    ctx = ssl.create_default_context()
    return ctx"""),

    rec("test-CRYPTO-010-5-Reject", "CRYPTO-010", "Reject",
"""def wait_for_database(host, port):
    import requests
    import time
    url = f"http://{host}:{port}/health"
    for _ in range(30):
        try:
            r = requests.get(url, verify=False, timeout=2)
            if r.status_code == 200:
                return True
        except requests.ConnectionError:
            time.sleep(1)
    return False""",
"verify=False only appears in a startup loop that waits for a local database health endpoint to come up. There is no remote endpoint and nothing sensitive in flight; not a security-relevant TLS decision -> Reject."),
]


def write_triage_set(records, src_path):
    """Write v2-schema source file."""
    with open(src_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[+] {src_path}: {len(records)} 条")


def detect_to_chatml(detect_rows):
    """Convert detect v2 rows to chatml format."""
    chatml_rows = []
    for r in detect_rows:
        chatml_rows.append({"messages": build_messages(r)})
    return chatml_rows


def triage_to_chatml(triage_rows):
    """Convert triage v2 rows to chatml format."""
    chatml_rows = []
    for r in triage_rows:
        chatml_rows.append({"messages": build_messages(r)})
    return chatml_rows


def merge_and_write(detect_chatml, triage_chatml, out_path):
    """Merge detect + triage chatml and write to file."""
    all_rows = detect_chatml + triage_chatml
    with open(out_path, "w", encoding="utf-8") as f:
        for r in all_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[+] {out_path}: {len(all_rows)} 条 (detect={len(detect_chatml)}, triage={len(triage_chatml)})")


if __name__ == "__main__":
    import shutil

    # Sample detect rows
    random.seed(42)
    detect_val_src = list(map(json.loads, (ROOT / "data/splits/detect_val.jsonl").read_text().splitlines()))
    detect_test_src = list(map(json.loads, (ROOT / "data/splits/detect_test.jsonl").read_text().splitlines()))

    detect_val_sample = random.sample(detect_val_src, 100)
    detect_test_sample = random.sample(detect_test_src, 100)

    print(f"Sampled detect: val={len(detect_val_sample)}, test={len(detect_test_sample)}")

    # Convert to chatml
    detect_val_chatml = detect_to_chatml(detect_val_sample)
    detect_test_chatml = detect_to_chatml(detect_test_sample)
    triage_val_chatml = triage_to_chatml(VAL_TRIAGE)
    triage_test_chatml = triage_to_chatml(TEST_TRIAGE)

    # Write source files (v2 schema)
    write_triage_set(VAL_TRIAGE, ROOT / "data/round3/val_source.jsonl")
    write_triage_set(TEST_TRIAGE, ROOT / "data/round3/test_source.jsonl")

    # Merge and write chatml files
    merge_and_write(detect_val_chatml, triage_val_chatml, ROOT / "data/round3/upload/val.jsonl")
    merge_and_write(detect_test_chatml, triage_test_chatml, ROOT / "data/round3/upload/test.jsonl")

    print(f"\n[✓] Round 3 eval sets ready:")
    print(f"  - val:  130 条 (100 detect + 30 triage)")
    print(f"  - test: 130 条 (100 detect + 30 triage)")
