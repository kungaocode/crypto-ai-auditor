#!/usr/bin/env python3
"""Build round-2 validation / test sets (independent of the 54 training samples).

Writes v2-schema sources to data/round2/{val,test}_source.jsonl and converts
them to chatml via prepare_sft_data.build_messages into data/sft/.
"""
import json
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
        "source": "round2-" + id.split("-")[0], "license": "original",
        "repo_url": "", "commit": "", "verified": True,
        "split": "val" if id.startswith("val-") else "test",
    }


VAL = [
    # ---------------- Confirm (6) ----------------
    rec("val-CRYPTO-001-1-Confirm", "CRYPTO-001", "Confirm",
"""def issue_session_cookie(username, password, client_ip):
    import hashlib
    cookie = hashlib.md5((password + client_ip).encode()).hexdigest()
    return set_cookie(username, cookie)""",
"A session cookie is derived from md5(password + client_ip). MD5 is broken and the input is guessable, so the cookie can be forged or brute-forced; session tokens must come from a CSPRNG. Real finding -> Confirm.",
"""def issue_session_cookie(username, password, client_ip):
    import secrets
    cookie = secrets.token_urlsafe(32)
    return set_cookie(username, cookie)"""),

    rec("val-CRYPTO-002-1-Confirm", "CRYPTO-002", "Confirm",
"""def store_credentials(user, raw):
    import hashlib
    db.save(user, hashlib.sha1(raw.encode("utf-8")).hexdigest())""",
"User passwords are stored as unsalted SHA-1 digests. SHA-1 is fast and collision-broken, making offline cracking trivial; password storage needs a slow salted KDF. Real finding -> Confirm.",
"""def store_credentials(user, raw):
    import hashlib, secrets
    salt = secrets.token_bytes(16)
    db.save(user, salt.hex() + hashlib.scrypt(raw.encode("utf-8"), salt=salt, n=2**14, r=8, p=1).hex())"""),

    rec("val-CRYPTO-003-1-Confirm", "CRYPTO-003", "Confirm",
"""from Crypto.Cipher import DES

def encrypt_session_token(token):
    key = load_des_key()
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(token, 8))""",
"Session tokens are encrypted with DES in ECB mode. DES has a 56-bit key and ECB leaks plaintext structure; both make the token recoverable. Real finding -> Confirm.",
"""from Crypto.Cipher import AES

def encrypt_session_token(token):
    key = load_aes_key()
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(token)
    return cipher.nonce + tag + ct"""),

    rec("val-CRYPTO-008-1-Confirm", "CRYPTO-008", "Confirm",
"""import random

def password_reset_code(user):
    reset_token = random.randint(100000, 999999)
    mail.send(user.email, f"Your reset code: {reset_token}")
    return reset_token""",
"A password reset code is drawn from random.randint, whose state is predictable after a few outputs; an attacker can forecast upcoming codes and take over accounts. Security-sensitive value -> Confirm.",
"""import secrets

def password_reset_code(user):
    reset_token = "".join(secrets.choice("0123456789") for _ in range(6))
    mail.send(user.email, f"Your reset code: {reset_token}")
    return reset_token"""),

    rec("val-CRYPTO-009-1-Confirm", "CRYPTO-009", "Confirm",
"""from Crypto.PublicKey import RSA

def make_signing_key():
    return RSA.generate(1024)""",
"A 1024-bit RSA key is generated for signing. 1024-bit RSA is within reach of well-resourced attackers; signing keys need >= 2048 bits. Real finding -> Confirm.",
"""from Crypto.PublicKey import RSA

def make_signing_key():
    return RSA.generate(2048)"""),

    rec("val-CRYPTO-010-1-Confirm", "CRYPTO-010", "Confirm",
"""import requests

def deliver_webhook(url, payload):
    return requests.post(url, json=payload, timeout=10, verify=False)""",
"Production webhook delivery disables TLS certificate validation, so any on-path attacker can intercept or modify the payload with a bogus certificate. Real finding -> Confirm.",
"""import requests

def deliver_webhook(url, payload):
    return requests.post(url, json=payload, timeout=10)"""),

    # ---------------- Reject (6) ----------------
    rec("val-CRYPTO-001-2-Reject", "CRYPTO-001", "Reject",
"""def asset_fingerprint(content):
    import hashlib
    return hashlib.md5(content).hexdigest()[:12]""",
"MD5 only derives a short cache-busting fingerprint for static assets. The value just needs to change when the content changes; no security decision depends on it being collision-resistant -> Reject."),

    rec("val-CRYPTO-002-2-Reject", "CRYPTO-002", "Reject",
"""def object_id(blob):
    import hashlib
    header = b"blob " + str(len(blob)).encode() + b"\\x00"
    return hashlib.sha1(header + blob).hexdigest()""",
"SHA-1 computes a git-style content-addressed object id used to locate stored blobs. The digest identifies data, it does not protect it; no signature, credential, or integrity guarantee relies on it -> Reject."),

    rec("val-CRYPTO-008-2-Reject", "CRYPTO-008", "Reject",
"""def poll_sensor(sensor_id):
    import random, time
    while True:
        sample = read(sensor_id)
        if sample.ready:
            return sample.value
        poll_salt = random.uniform(0.2, 0.8)
        time.sleep(poll_salt)""",
"The random value only spaces out sensor polls so concurrent readers do not hammer the device in lockstep. It never feeds a credential, key, or identifier; predicting it reveals nothing sensitive. Rule matched on the variable name, not on a security use -> Reject."),

    rec("val-CRYPTO-005-2-Reject", "CRYPTO-005", "Reject",
"""def test_ecb_roundtrip_smoke():
    from Crypto.Cipher import AES
    key = bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    assert len(cipher.encrypt(bytes(16))) == 16""",
"ECB appears only inside a unit test asserting block-size behaviour on throwaway zero input. No real plaintext is encrypted and the cipher never leaves the test -> Reject."),

    rec("val-CRYPTO-007-2-Reject", "CRYPTO-007", "Reject",
"""def test_unpack_sample_invoice():
    from cryptography.fernet import Fernet
    plain = Fernet(b"test-only-sample-key-000000").decrypt(SAMPLE_INVOICE_BLOB)
    assert plain.startswith(b"INVOICE")""",
"The literal key only unpacks a bundled sample invoice inside a unit test. It protects no real data and exists purely as fixture scaffolding -> Reject."),

    rec("val-CRYPTO-010-2-Reject", "CRYPTO-010", "Reject",
"""def wait_for_local_server(url):
    import time
    import requests
    for _ in range(30):
        try:
            return requests.get(url, verify=False, timeout=2).status_code
        except requests.ConnectionError:
            time.sleep(1)""",
"verify=False only appears in a startup loop that waits for a localhost dev server to come up; there is no remote endpoint and nothing sensitive in flight. Not a security-relevant TLS decision -> Reject."),
]

TEST = [
    # ---------------- Confirm (6) ----------------
    rec("test-CRYPTO-001-1-Confirm", "CRYPTO-001", "Confirm",
"""from Crypto.Cipher import AES

def derive_backup_key(passphrase):
    import hashlib
    digest = hashlib.md5(passphrase.encode()).digest()
    return AES.new(digest, AES.MODE_GCM)""",
"An encryption key is derived by taking MD5 of a passphrase. MD5 is collision-broken and far too fast, so the key can be brute-forced through the hash; key derivation needs a slow KDF. Real finding -> Confirm.",
"""from Crypto.Cipher import AES

def derive_backup_key(passphrase):
    import hashlib
    salt = get_or_create_kdf_salt()
    digest = hashlib.scrypt(passphrase.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return AES.new(digest, AES.MODE_GCM)"""),

    rec("test-CRYPTO-002-1-Confirm", "CRYPTO-002", "Confirm",
"""def ldap_password_entry(user, raw):
    import hashlib
    digest = hashlib.sha1(raw.encode()).digest()
    return "{SHA}" + base64.b64encode(digest).decode()""",
"Directory passwords are stored as unsalted {SHA} (SHA-1) digests. SHA-1 is fast and collision-broken, so captured entries crack quickly; password storage needs a slow salted KDF. Real finding -> Confirm.",
"""def ldap_password_entry(user, raw):
    from argon2 import PasswordHasher
    return PasswordHasher().hash(raw)"""),

    rec("test-CRYPTO-004-1-Confirm", "CRYPTO-004", "Confirm",
"""from Crypto.Cipher import ARC4

def encrypt_chat_message(shared_key, message):
    cipher = ARC4.new(shared_key)
    return cipher.encrypt(message)""",
"Chat messages are encrypted with RC4, whose keystream has known statistical biases and no authentication; plaintext can be recovered and tampered with. Real finding -> Confirm.",
"""from Crypto.Cipher import AES

def encrypt_chat_message(shared_key, message):
    cipher = AES.new(shared_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(message)
    return cipher.nonce + tag + ct"""),

    rec("test-CRYPTO-006-1-Confirm", "CRYPTO-006", "Confirm",
"""from Crypto.Cipher import AES

def encrypt_record(key, record):
    cipher = AES.new(key, AES.MODE_CBC, IV=b"")
    return cipher.encrypt(pad(record, 16))""",
"CBC encryption reuses a fixed all-zero IV for every record, so identical prefixes leak and related plaintexts become linkable; each encryption needs a fresh unpredictable IV. Real finding -> Confirm.",
"""from Crypto.Cipher import AES

def encrypt_record(key, record):
    import secrets
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    return iv + cipher.encrypt(pad(record, 16))"""),

    rec("test-CRYPTO-007-1-Confirm", "CRYPTO-007", "Confirm",
"""from Crypto.Cipher import AES

def encrypt_backup(data):
    cipher = AES.new(b"backup-encryption-key-2024", AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ct""",
"The backup encryption key is hardcoded in source. Anyone with repo access (or a leaked build) can decrypt every backup; keys belong in a secrets manager or env-based configuration. Real finding -> Confirm.",
"""import base64, os
from Crypto.Cipher import AES

def encrypt_backup(data):
    key = base64.b64decode(os.environ["BACKUP_KEY"])
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ct"""),

    rec("test-CRYPTO-008-1-Confirm", "CRYPTO-008", "Confirm",
"""import random

def pick_totp_seed(user):
    seed_secret = random.getrandbits(128)
    store_totp_seed(user, seed_secret)""",
"A TOTP seed is generated with random.getrandbits. The Mersenne Twister is predictable once a few outputs are seen, so an attacker can reconstruct the seed and forge one-time codes. Security-sensitive value -> Confirm.",
"""import secrets

def pick_totp_seed(user):
    seed_secret = secrets.randbits(128)
    store_totp_seed(user, seed_secret)"""),

    # ---------------- Reject (6) ----------------
    rec("test-CRYPTO-001-2-Reject", "CRYPTO-001", "Reject",
"""def etag_for_response(body):
    import hashlib
    return '"' + hashlib.md5(body).hexdigest() + '"'""",
"MD5 produces an HTTP ETag, a change indicator that caches compare between responses. It authenticates nothing and guards no secret; collision resistance is irrelevant for this use -> Reject."),

    rec("test-CRYPTO-002-2-Reject", "CRYPTO-002", "Reject",
"""def log_dedupe_id(line):
    import hashlib
    return hashlib.sha1(line.encode()).hexdigest()[:20]""",
"SHA-1 fingerprints log lines so exact duplicates collapse in the pipeline. The digest is an internal dedup id and never feeds a security decision -> Reject."),

    rec("test-CRYPTO-008-2-Reject", "CRYPTO-008", "Reject",
"""def should_throttle(request):
    import random
    drop_token = random.random()
    return drop_token < load_factor()""",
"random.random() drives probabilistic load shedding; drop_token is a coin flip, not a credential. Knowing it only predicts which requests get throttled, which an attacker can already observe. Not security-sensitive -> Reject."),

    rec("test-CRYPTO-003-2-Reject", "CRYPTO-003", "Reject",
"""def test_des3_roundtrip_fixture():
    from Crypto.Cipher import DES3
    cipher = DES3.new(b"0123456789abcdef01234567", DES3.MODE_ECB)
    assert len(cipher.encrypt(bytes(8))) == 8""",
"3DES is constructed only to round-trip a known fixture inside a unit test; the literal key is test scaffolding that never touches real data -> Reject."),

    rec("test-CRYPTO-006-2-Reject", "CRYPTO-006", "Reject",
"""def test_cbc_mode_zero_iv_smoke():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(bytes(16)), modes.CBC(bytes(16)))
    enc = cipher.encryptor()
    assert len(enc.update(bytes(16))) == 16""",
"modes.CBC(bytes(16)) appears only in a smoke test that exercises the cipher object with fixed zero input; nothing real is encrypted and the fixture never leaves the test -> Reject."),

    rec("test-CRYPTO-004-2-Reject", "CRYPTO-004", "Reject",
"""def test_arc4_keystream_fixture():
    from Crypto.Cipher import ARC4
    cipher = ARC4.new(b"fixture-key")
    assert cipher.encrypt(b"\\x00" * 8) == bytes.fromhex(RC4_GOLDEN)""",
"RC4 is instantiated only to reproduce a golden keystream vector inside a unit test; the literal key is a fixture and no real data flows through the cipher -> Reject."),
]


def write_set(records, src_path, chatml_path):
    with open(src_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(chatml_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps({"messages": build_messages(r)}, ensure_ascii=False) + "\n")
    print(f"[+] {src_path}: {len(records)} 条 -> {chatml_path}")


if __name__ == "__main__":
    import shutil

    write_set(VAL, ROOT / "data/round2/val_source.jsonl",
              ROOT / "data/sft/triage_val_chatml.jsonl")
    write_set(TEST, ROOT / "data/round2/test_source.jsonl",
              ROOT / "data/sft/triage_test_chatml.jsonl")

    # 同步平台可上传副本到 data/round2/upload/（与第一轮 chatml 同格式）
    up = ROOT / "data/round2/upload"
    up.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "data/sft/triage_fix_chatml.jsonl", up / "train.jsonl")
    shutil.copyfile(ROOT / "data/sft/triage_val_chatml.jsonl", up / "val.jsonl")
    shutil.copyfile(ROOT / "data/sft/triage_test_chatml.jsonl", up / "test.jsonl")
    print(f"[+] 已同步可上传文件到 {up}/ : train.jsonl / val.jsonl / test.jsonl")
