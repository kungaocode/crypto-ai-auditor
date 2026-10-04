#!/usr/bin/env python3
"""
Second supplement for Round-6: additional 20 detect + 6 triage samples
to achieve detect pos:neg = 40:60 with broader library coverage.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def _rec(task, rid, code, label, source, split="train", finding=None, rule=None):
    r = {
        "id": rid, "language": "python", "task": task,
        "code": code.strip(), "label": label,
        "source": source, "license": "original",
        "repo_url": "", "commit": "", "verified": False,
        "split": split,
    }
    if finding: r["finding"] = finding
    if rule: r["rule"] = rule
    return r

def _detect_pos(rid, code, cwe, explanation, rule, split="train"):
    return _rec("detect", rid, code, {
        "vulnerable": True, "cwe": cwe, "severity": "WARNING",
        "confidence": "high", "explanation": explanation,
    }, f"round6-{rule.lower()}-pos", split=split, rule=rule)

def _detect_aneg(rid, code, explanation, lib, split="train"):
    return _rec("detect", rid, code, {
        "vulnerable": False, "cwe": "", "severity": "",
        "confidence": "high", "explanation": explanation,
    }, f"round6-safe-lib-{lib}", split=split)

def _detect_bneg(rid, code, explanation, rule, split="train"):
    return _rec("detect", rid, code, {
        "vulnerable": False, "cwe": "", "severity": "",
        "confidence": "high", "explanation": explanation,
    }, f"round6-legacy-bneg", split=split, rule=rule)

def _triage_confirm(rid, code, finding, cwe, explanation, patch="", rule=None, split="train"):
    return _rec("triage", rid, code, {
        "cwe": cwe, "severity": "WARNING", "verdict": "Confirm",
        "explanation": explanation, "patch": patch,
    }, "round6-regression-fix-confirm", split=split, finding=finding, rule=rule)

def _triage_reject(rid, code, finding, explanation, source="round6-lib-reject", rule=None, split="train"):
    return _rec("triage", rid, code, {
        "cwe": "", "severity": "INFO", "verdict": "Reject",
        "explanation": explanation, "patch": "",
    }, source, split=split, finding=finding, rule=rule)


# ══════════════════════════════════════════════════════════════════════════════
# MORE DETECT POS (8): varied patterns for underrepresented rules
# ══════════════════════════════════════════════════════════════════════════════

MORE_POS = [
    # CRYPTO-005: AES-ECB batch processing (different from export)
    _detect_pos("r6-pos-aes-ecb-batch", """
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json

CUSTOMER_KEY = b"customer-enc-key-256bits!"

def encrypt_customer_batch(records: list) -> bytes:
    cipher = AES.new(CUSTOMER_KEY, AES.MODE_ECB)
    payload = json.dumps(records).encode()
    return cipher.encrypt(pad(payload, 16))
""".strip(), "CWE-327",
        "AES-ECB encrypts customer PII records to a batch file. ECB mode "
        "leaks structural patterns across JSON fields — identical field values "
        "produce identical ciphertext blocks. Real customer data is exposed.",
        "CRYPTO-005"),

    # CRYPTO-001: MD5+SHA1 dual-hash (compound vulnerability)
    _detect_pos("r6-pos-md5-sha1-hybrid", """
import hashlib

def hash_credential(credential: str, pepper: str) -> str:
    # first MD5, then SHA-1 — neither resists collision attacks
    step1 = hashlib.md5((credential + pepper).encode()).hexdigest()
    step2 = hashlib.sha1(step1.encode()).hexdigest()
    return step2
""".strip(), "CWE-327",
        "MD5 then SHA-1 chained for credential hashing. Both algorithms "
        "are collision-prone; chaining adds no security. The attacker "
        "can brute-force through the chain. Real credentials at risk.",
        "CRYPTO-001"),

    # CRYPTO-006: static-nonce in CTR mode
    _detect_pos("r6-pos-static-nonce-ctr", """
from Crypto.Cipher import AES
import struct

FIXED_NONCE = b"\\x00" * 8

def encrypt_counter_mode(key: bytes, msg: bytes) -> bytes:
    counter = struct.pack(">Q", 1)
    full_nonce = FIXED_NONCE + counter
    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=full_nonce)
    return cipher.encrypt(msg.ljust(16, b"\\x00"))
""".strip(), "CWE-329",
        "AES-CTR encrypts messages with a fixed initial value. CTR mode "
        "nonce reuse across messages turns the stream cipher into a two-time "
        "pad — an attacker who sees two ciphertexts can XOR them to recover "
        "plaintext XOR. Real messages are exposed.",
        "CRYPTO-006"),

    # CRYPTO-008: uuid4 from random (not secrets)
    _detect_pos("r6-pos-uuid4-random", """
import random, uuid

def issue_password_reset_token(user_id: int) -> str:
    random.seed(user_id * int(uuid.uuid4().time_low))
    return "".join(random.choices("abcdef0123456789", k=64))
""".strip(), "CWE-338",
        "random.seed() with a predictable seed (uuid4 time_low × user_id) "
        "followed by random.choices() generates password reset tokens. The "
        "Mersenne Twister is deterministic given the seed; an attacker can "
        "replay all future tokens. Real reset tokens are predictable.",
        "CRYPTO-008"),

    # CRYPTO-003: DES-CBC encrypting JSON API payload
    _detect_pos("r6-pos-des-cbc-api", """
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import os

API_KEY = b"api-key!"

def encrypt_api_payload(data: dict) -> bytes:
    iv = os.urandom(8)
    cipher = DES.new(API_KEY, DES.MODE_CBC, iv=iv)
    raw = json.dumps(data).encode()
    return iv + cipher.encrypt(pad(raw, 8))
""".strip(), "CWE-327",
        "DES-CBC encrypts API payloads with an 8-byte key. DES's 56-bit "
        "key space is brute-forceable within hours on a single GPU. Real "
        "API traffic containing session tokens and user data is protected "
        "only by this cipher.",
        "CRYPTO-003"),

    # CRYPTO-009: weak DH parameters
    _detect_pos("r6-pos-dh-weak-params", """
from Crypto.PublicKey import DSA

def generate_dsa_keypair():
    # 1536-bit DSA provides only ~80 bits of security (NIST deprecated)
    key = DSA.generate(1536)
    return key
""".strip(), "CWE-326",
        "DSA.generate(1536) creates a 1536-bit key providing ~80 bits of "
        "security. NIST SP 800-57 deprecates keys below 112-bit (2048-bit "
        "DSA/RSA) since 2014. Real authentication keys are below the floor.",
        "CRYPTO-009"),

    # CRYPTO-002: SHA-1 for HMAC with static key
    _detect_pos("r6-pos-sha1-hmac-auth", """
import hmac, hashlib

WEBHOOK_KEY = b"shared-webhook-secret"

def authenticate_callback(body: bytes, sig: str) -> bool:
    expected = hmac.new(WEBHOOK_KEY, body, hashlib.sha1).hexdigest()
    return hmac.compare_digest(expected, sig)
""".strip(), "CWE-327",
        "HMAC-SHA1 authenticates webhook callbacks. While HMAC-SHA1 is not "
        "directly broken for MAC, NIST has deprecated SHA-1 for all "
        "cryptographic uses including HMAC after 2030. Real webhook "
        "authentication uses a deprecated primitive.",
        "CRYPTO-002"),

    # CRYPTO-010: no cert verification with production cert
    _detect_pos("r6-pos-tls-no-verify-prod", """
import urllib3

def push_metrics_to_grafana(metrics: dict):
    http = urllib3.PoolManager(
        cert_reqs="CERT_NONE",
        assert_hostname=False,
    )
    resp = http.request("POST", "https://grafana.prod.internal:3000/api/metrics",
                        body=json.dumps(metrics),
                        headers={"Content-Type": "application/json"})
    return resp.status
""".strip(), "CWE-326",
        "urllib3 with CERT_NONE and no hostname verification sends production "
        "metrics over TLS. A MITM attacker can intercept the connection and "
        "read or modify operational metrics. Real monitoring data is exposed.",
        "CRYPTO-010"),
]


# ══════════════════════════════════════════════════════════════════════════════
# MORE ANEG (6): additional library patterns
# ══════════════════════════════════════════════════════════════════════════════

MORE_ANEG = [
    # cryptography: AES-SIV (deterministic but misuse-resistant)
    _detect_aneg("r6-crypto-aes-siv", """
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

def encrypt_deterministic(key: bytes, associated_data: bytes, plaintext: bytes) -> bytes:
    aessiv = AESSIV(key)
    return aessiv.encrypt(plaintext, [associated_data])
""".strip(),
        "AES-SIV provides misuse-resistant deterministic authenticated "
        "encryption (RFC 5297). Safe even when nonces are reused across "
        "messages. No vulnerability.",
        "cryptography"),

    # cryptography: scrypt (modern KDF)
    _detect_aneg("r6-crypto-scrypt", """
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def derive_key_from_password(password: str) -> bytes:
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return salt + kdf.derive(password.encode())
""".strip(),
        "scrypt with N=16384 (2^14) provides strong memory-hard password "
        "hashing. No vulnerability.",
        "cryptography"),

    # PyCryptoDome: AES-GCM with random nonce
    _detect_aneg("r6-pyc-aes-gcm", """
import os
from Crypto.Cipher import AES

def encrypt_with_aes_gcm(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag
""".strip(),
        "PyCryptoDome AES-GCM with CSPRNG nonce provides authenticated "
        "encryption. No vulnerability.",
        "pycryptodome"),

    # PyNaCl: Box (Curve25519XSalsa20Poly1305) key exchange
    _detect_aneg("r6-nacl-box-exchange", """
import nacl.utils
from nacl.public import PrivateKey, Box

def create_encrypted_channel(peer_public_key_bytes: bytes):
    sk = PrivateKey.generate()
    peer_pk = nacl.public.PublicKey(peer_public_key_bytes)
    box = Box(sk, peer_pk)
    return box
""".strip(),
        "PyNaCl Box provides Curve25519-XSalsa20-Poly1305 authenticated "
        "public-key encryption. No vulnerability.",
        "nacl"),

    # itsdangerous: TimedJSONWebSignatureSerializer with SHA-256
    _detect_aneg("r6-itsdangerous-timed-sha256", """
from itsdangerous import TimedJSONWebSignatureSerializer

def create_session_token(user_id: int, secret: str) -> str:
    s = TimedJSONWebSignatureSerializer(secret, expires_in=3600,
                                        signer_kwargs={"digest_method": "hashlib.sha256"})
    return s.dumps({"uid": user_id})
""".strip(),
        "itsdangerous TimedJSONWebSignatureSerializer with SHA-256 digest "
        "and expiration. No vulnerability.",
        "itsdangerous"),

    # PyJWT: RS256 with key validation
    _detect_aneg("r6-jwt-rs256-verify", """
import jwt
from cryptography.hazmat.primitives import serialization

PUBLIC_KEY = serialization.load_pem_public_key(open("public.pem", "rb").read())

def verify_jwt(token: str) -> dict:
    return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"],
                      options={"verify_exp": True, "verify_aud": False})
""".strip(),
        "PyJWT with RS256 algorithm and explicit PEM public key. Algorithm "
        "is pinned (not \"none\" or open). No vulnerability.",
        "pyjwt"),
]


# ══════════════════════════════════════════════════════════════════════════════
# MORE BNEG (6): deeper legacy-format and non-security weak-primitive patterns
# ══════════════════════════════════════════════════════════════════════════════

MORE_BNEG = [
    _detect_bneg("r6-bneg-sha1-x509-parse", """
import hashlib

# X.509 certificate parser: computes SHA-1 of the TBSCertificate for
# RFC 5280 subject key identifier generation during certificate import.
# The library does not choose SHA-1; it reads the certificate and must
# match the existing SKI extension.

def compute_subject_key_id(spki_der: bytes) -> bytes:
    # RFC 5280 §4.2.1.2: SKI = SHA-1 of the SubjectPublicKeyInfo BIT STRING
    return hashlib.sha1(spki_der).digest()
""".strip(),
        "SHA-1 computes an X.509 Subject Key Identifier per RFC 5280. The "
        "standard mandates SHA-1 for SKI; the library provides certificate "
        "interoperability, not a cryptographic choice. Format compliance.",
        "CRYPTO-002"),

    _detect_bneg("r6-bneg-md5-zip-stored-hash", """
import hashlib

# ZIP file validator: computes MD5 of the central directory as specified
# in the PKWARE APPNOTE format (Section 4.4.8). This is the ZIP format's
# data integrity check, not a security mechanism.

def validate_zip_central_directory(zip_data: bytes, expected_cd_hash: bytes) -> bool:
    cd_start = find_central_directory_offset(zip_data)
    cd_hash = hashlib.md5(zip_data[cd_start:]).digest()
    return cd_hash == expected_cd_hash
""".strip(),
        "MD5 computes a ZIP central directory hash per the PKWARE format "
        "specification. This is a data integrity checksum mandated by the "
        "file format; the library does not choose MD5 for security. "
        "Format compatibility — safe.",
        "CRYPTO-001"),

    _detect_bneg("r6-bneg-des3-smime-legacy", """
from Crypto.Cipher import DES3

# S/MIME v2 parser: decrypts PKCS#7 enveloped data using DES-EDE3-CBC.
# The algorithm OID (1.2.840.113549.3.7) is read from the message header;
# the library must implement DES3 to read legacy S/MIME messages.

def decrypt_smime_v2_envelope(envelope: bytes, recipient_key) -> bytes:
    algo_oid, encrypted_key, iv, ciphertext = parse_envelope(envelope)
    if algo_oid == "1.2.840.113549.3.7":  # DES-EDE3-CBC per RFC 2311
        ce_key = rsa_decrypt(recipient_key, encrypted_key)
        cipher = DES3.new(ce_key, DES3.MODE_CBC, iv=iv)
        return cipher.decrypt(ciphertext)
    raise UnsupportedAlgorithm(algo_oid)
""".strip(),
        "DES3 decrypts legacy S/MIME v2 messages (RFC 2311). The algorithm "
        "is chosen by the message sender, not the library; the library must "
        "implement DES3 to read existing encrypted emails. Format "
        "interoperability — safe.",
        "CRYPTO-003"),

    _detect_bneg("r6-bneg-random-jitter-metrics", """
import random, time

# Metrics sampling: adds random jitter to the collection interval
# to avoid all servers hitting the metrics endpoint simultaneously.
# random.uniform() is perfectly fine for jitter — no adversary model.

def sample_with_jitter(base_interval_seconds: int = 60) -> None:
    jitter = random.uniform(-5.0, 5.0)
    time.sleep(base_interval_seconds + jitter)
    collect_and_push_metrics()
""".strip(),
        "random.uniform() adds jitter to a metrics collection interval. "
        "No cryptographic quality is needed — jitter is purely for load "
        "smoothing across server fleets. Load distribution — safe.",
        "CRYPTO-008"),

    _detect_bneg("r6-bneg-sha1-git-object-id", """
import hashlib

# Git object store abstraction: computes SHA-1 of content as Git does
# for blob identification. The library does not choose SHA-1; Git's
# content-addressable storage requires it. This is not a security hash.

def compute_git_object_id(content: bytes) -> str:
    header = f"blob {len(content)}\\x00".encode()
    return hashlib.sha1(header + content).hexdigest()
""".strip(),
        "SHA-1 computes a Git object ID identical to how Git hashes blobs. "
        "The hash identifies content by address; it is not used for "
        "authentication or integrity against an adversary. Git compatibility.",
        "CRYPTO-002"),

    _detect_bneg("r6-bneg-des3-hsm-transport-key", """
from Crypto.Cipher import DES3

# HSM key transport: wraps an AES-256 content-encryption key under a
# static DES3 transport key for compatibility with an existing HSM fleet.
# New HSMs use AES-KWP; DES3 is kept ONLY for the legacy tier.

LEGACY_TRANSPORT_KEY = read_from_hsm_slot(0x04)

def wrap_key_legacy_hsm(cek: bytes) -> bytes:
    # The legacy HSM only supports 3DES key wrapping.
    # All new deployments use AES-KWP (slot 0x05).
    cipher = DES3.new(LEGACY_TRANSPORT_KEY, DES3.MODE_ECB)
    return cipher.encrypt(cek.ljust(24, b"\\x00"))
""".strip(),
        "DES3 wraps content-encryption keys for legacy HSM transport. "
        "The algorithm is constrained by the HSM's firmware, not chosen "
        "by the library. New HSMs use AES-KWP; DES3 exists only for the "
        "deprecated tier during migration. Legacy compatibility.",
        "CRYPTO-003"),
]


# ══════════════════════════════════════════════════════════════════════════════
# MORE TRIAGE (3 Confirm + 3 Reject)
# ══════════════════════════════════════════════════════════════════════════════

MORE_TRIAGE = [
    _triage_confirm("r6-rfix-md5-cert-fingerprint", """
import hashlib

def verify_certificate_chain(certs: list) -> bool:
    for i in range(len(certs) - 1):
        issuer_key = certs[i + 1].public_key()
        # Fingerprint for logging only
        fp = hashlib.md5(certs[i].tbs_certificate_bytes).hexdigest()
        log.info(f"Verifying cert {fp}")
        if not issuer_key.verify(certs[i].signature, certs[i].tbs_certificate_bytes):
            return False
    return True
""".strip(),
        "[CRYPTO-001] 'md5' used — MD5 is cryptographically broken",
        "CWE-327",
        "MD5 computes a certificate fingerprint for operational logging. "
        "The fingerprint identifies certificates in log entries; log injection "
        "through MD5 collisions is a real threat — an attacker can craft a "
        "certificate whose MD5 matches a trusted one in the log, confusing "
        "incident response. Real security monitoring is undermined — Confirm.",
        patch="""import hashlib

def verify_certificate_chain(certs: list) -> bool:
    for i in range(len(certs) - 1):
        issuer_key = certs[i + 1].public_key()
        fp = hashlib.sha256(certs[i].tbs_certificate_bytes).hexdigest()
        log.info(f"Verifying cert {fp}")
        if not issuer_key.verify(certs[i].signature, certs[i].tbs_certificate_bytes):
            return False
    return True""",
        rule="CRYPTO-001"),

    _triage_confirm("r6-rfix-random-session-id", """
import random, string

def create_session() -> str:
    session_id = "".join(random.choice(string.ascii_letters + string.digits)
                         for _ in range(32))
    store_session(session_id, {"created": time.time()})
    return session_id
""".strip(),
        "[CRYPTO-008] 'random.choice' may be an insecure randomness source (CWE-338)",
        "CWE-338",
        "random.choice() generates 32-character session IDs for user "
        "authentication. A Mersenne Twister PRNG is deterministic given a "
        "624-byte observation window; an attacker who observes enough sessions "
        "can predict future IDs and hijack accounts. Real session tokens — Confirm.",
        patch="""import secrets, string

def create_session() -> str:
    alphabet = string.ascii_letters + string.digits
    session_id = "".join(secrets.choice(alphabet) for _ in range(32))
    store_session(session_id, {"created": time.time()})
    return session_id""",
        rule="CRYPTO-008"),

    _triage_confirm("r6-rfix-sha1-password-store", """
import hashlib

def create_user_account(email: str, password: str):
    digest = hashlib.sha1(password.encode()).hexdigest()
    execute("INSERT INTO users (email, pw_hash) VALUES (?, ?)", email, digest)
""".strip(),
        "[CRYPTO-002] 'sha1' used — SHA-1 is collision-prone",
        "CWE-327",
        "SHA-1 hashes real user passwords for database storage. SHA-1 is "
        "cryptographically broken for collision resistance; an attacker with "
        "a SHA-1 rainbow table can recover passwords in minutes. Real user "
        "credentials are stored with a broken hash — Confirm.",
        patch="""import bcrypt

def create_user_account(email: str, password: str):
    digest = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    execute("INSERT INTO users (email, pw_hash) VALUES (?, ?)",
            email, digest.decode())""",
        rule="CRYPTO-002"),

    # REJECT: ARC4 in WEP-compatible module
    _triage_reject("r6-trej-arc4-wep-legacy", """
from Crypto.Cipher import ARC4

# WEP compatibility module for legacy IoT device provisioning.
# The IoT device only speaks WEP (802.11-1999) during initial setup;
# after provisioning, the device is upgraded to WPA3.

def provision_legacy_iot_device(ssid: str, psk: str, device_mac: str):
    # WEP uses RC4 with a 24-bit IV prepended to the key.
    # This module runs ONLY during the 30-second provisioning window.
    key = derive_wep_key(ssid, psk)
    iv = os.urandom(3)
    cipher = ARC4.new(iv + key)
    encrypted_config = cipher.encrypt(json.dumps({"ssid": ssid, "psk": psk}).encode())
    send_to_device(device_mac, iv + encrypted_config)
""".strip(),
        "[CRYPTO-004] 'ARC4' referenced — RC4/ARC4 is cryptographically weak",
        "ARC4 is used solely in a WEP compatibility module for IoT "
        "provisioning. The device only supports WEP during a 30-second "
        "initial setup window; after provisioning it upgrades to WPA3. "
        "Legacy device onboarding — Reject.",
        source="round6-lib-reject", rule="CRYPTO-004"),

    _triage_reject("r6-trej-module-self-test", """
import hashlib, random

# Cryptographic module self-test: runs on import to verify the
# internal hash implementation produces known test vectors.
# The test runs once at module load; no user data is hashed.

def _self_test_sha1():
    test_cases = [
        (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    ]
    for inp, expected in test_cases:
        actual = hashlib.sha1(inp).hexdigest()
        assert actual == expected, f"SHA-1 self-test FAILED"
    return True
_self_test_result = _self_test_sha1()
""".strip(),
        "[CRYPTO-002] 'sha1' used — SHA-1 is collision-prone",
        "SHA-1 verifies the integrity of the cryptographic module by comparing "
        "against known test vectors. No user data is hashed; this is a FIPS-style "
        "Known Answer Test (KAT) that runs once at import. Module integrity "
        "verification — Reject.",
        source="round6-lib-reject", rule="CRYPTO-002"),

    _triage_reject("r6-trej-hkdf-sha1-compat", """
import hashlib, hmac

# TLS 1.0 PRF (Pseudo-Random Function) compatibility layer.
# TLS 1.0/1.1 specify SHA-1+MD5 for the PRF; this module exists
# only so the library can verify handshakes against reference vectors.

def tls10_prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    # TLS 1.0 PRF uses MD5+SHA-1 XOR (RFC 2246 §5)
    def p_hash(secret, seed, hash_fn):
        result = b""
        a = seed
        while len(result) < length:
            a = hmac.new(secret, a, hash_fn).digest()
            result += hmac.new(secret, a + seed, hash_fn).digest()
        return result[:length]
    md5_part = p_hash(secret[:16], label + seed, hashlib.md5)
    sha1_part = p_hash(secret[16:], label + seed, hashlib.sha1)
    return bytes(a ^ b for a, b in zip(md5_part, sha1_part))
""".strip(),
        "[CRYPTO-001] 'md5' and [CRYPTO-002] 'sha1' used — both are collision-prone",
        "MD5+SHA-1 implement the TLS 1.0 PRF for verifying reference handshake "
        "vectors. TLS 1.0 is deprecated (RFC 8996); this module exists only as "
        "a test vector validator during protocol library development. "
        "Reference verification — Reject.",
        source="round6-lib-reject", rule="CRYPTO-002"),
]


# ══════════════════════════════════════════════════════════════════════════════
# EMIT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    import random
    random.seed(1234)

    DETECT_V2 = MORE_POS + MORE_ANEG + MORE_BNEG
    TRIAGE_V2 = MORE_TRIAGE

    # Hold out val/test
    def _holdout(records, val_n=2, test_n=2):
        candidates = [r for r in records if r["split"] == "train"]
        random.shuffle(candidates)
        if len(candidates) >= val_n + test_n:
            for r in candidates[:val_n]:
                r["split"] = "val"
            for r in candidates[val_n:val_n + test_n]:
                r["split"] = "test"

    _holdout(MORE_POS, 1, 1)
    _holdout(MORE_ANEG, 1, 1)
    _holdout(MORE_BNEG, 1, 1)
    _holdout(MORE_TRIAGE, 1, 1)

    all_v2 = DETECT_V2 + TRIAGE_V2
    for split in ("train", "val", "test"):
        subset = [r for r in all_v2 if r["split"] == split]
        print(f"  {split}: {len(subset)}")

    # Emit
    out = ROOT / "data" / "round6"
    (out / "supplement_v2_detect.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in DETECT_V2) + "\n", encoding="utf-8")
    (out / "supplement_v2_triage.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in TRIAGE_V2) + "\n", encoding="utf-8")

    print(f"\nDetect v2: {len(DETECT_V2)} (POS={len(MORE_POS)} ANEG={len(MORE_ANEG)} BNEG={len(MORE_BNEG)})")
    print(f"Triage v2: {len(TRIAGE_V2)} (Confirm={sum(1 for r in TRIAGE_V2 if r['label']['verdict']=='Confirm')} Reject={sum(1 for r in TRIAGE_V2 if r['label']['verdict']=='Reject')})")

if __name__ == "__main__":
    main()
