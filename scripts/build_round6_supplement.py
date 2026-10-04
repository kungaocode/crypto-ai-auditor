#!/usr/bin/env python3
"""
Build supplementary Round-6 samples addressing gaps in the original R6 dataset.

Adds:
  - detect pos for missing rule families (CRYPTO-002/003/004/006/007/008/009/010)
  - detect aneg for new safe libraries (argon2-cffi, ecdsa, google-auth, oscrypto)
  - detect bneg for library-implements-legacy type
  - triage Confirm for additional regression cases
  - triage Reject for library legacy format compat
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
R6 = ROOT / "data" / "round6"

def _rec(task, rid, code, label, source, split="train", finding=None, rule=None, **kw):
    r = {
        "id": rid, "language": "python", "task": task,
        "code": code.strip(), "label": label,
        "source": source, "license": "original",
        "repo_url": "", "commit": "", "verified": False,
        "split": split,
    }
    if finding: r["finding"] = finding
    if rule: r["rule"] = rule
    r.update(kw)
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
# DETECT POS: missing rule families (8 new)
# ══════════════════════════════════════════════════════════════════════════════

DETECT_POS_NEW = [
    # CRYPTO-002: SHA-1 password hashing
    _detect_pos("r6-pos-sha1-pw", """
import hashlib

def create_user(username: str, password: str) -> dict:
    pw_hash = hashlib.sha1(password.encode()).hexdigest()
    return {"user": username, "hash": pw_hash}
""".strip(), "CWE-327",
        "SHA-1 hashes user passwords for database storage. SHA-1 is collision-prone "
        "and vulnerable to chosen-prefix attacks; rainbow tables trivialize recovery. "
        "Real user credentials are exposed.",
        "CRYPTO-002"),

    _detect_pos("r6-pos-sha1-key", """
import hashlib

ENCRYPTION_KEY = hashlib.sha1(b"admin-secret-2025").digest()

def encrypt_config(cfg: str) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CTR)
    return cipher.encrypt(cfg.encode())
""".strip(), "CWE-327",
        "SHA-1 derives a 160-bit encryption key from a static passphrase. "
        "SHA-1 is too fast for key derivation and the key is fixed at import time; "
        "an attacker who recovers the hash input fully compromises all ciphertexts.",
        "CRYPTO-002"),

    # CRYPTO-003: DES
    _detect_pos("r6-pos-des-userdata", """
from Crypto.Cipher import DES

ENC_KEY = b"8bytekey"  # 8 bytes = 56-bit DES key

def store_encrypted_profile(user_id: int, ssn: str) -> None:
    cipher = DES.new(ENC_KEY, DES.MODE_ECB)
    padded = ssn.encode().ljust(16, b"\\x00")
    db.save("profiles", user_id, cipher.encrypt(padded))
""".strip(), "CWE-327",
        "DES-ECB encrypts real user SSNs for database storage. DES has a 56-bit "
        "key space bruteforceable in hours on commodity hardware; ECB leaks "
        "identical-SSN patterns. Real PII is protected by this cipher.",
        "CRYPTO-003"),

    _detect_pos("r6-pos-des3-config", """
from Crypto.Cipher import DES3

SECRET = b"24-byte-triple-des-key!!"

def encrypt_config_file(path: str):
    with open(path, "rb") as f:
        data = f.read()
    cipher = DES3.new(SECRET, DES3.MODE_ECB)
    ct = cipher.encrypt(data.ljust(24 * ((len(data)+23)//24), b"\\x00"))
    with open(path + ".enc", "wb") as f:
        f.write(ct)
""".strip(), "CWE-327",
        "3DES-ECB encrypts configuration files. 3DES meets 112-bit security but "
        "is deprecated by NIST (SP 800-131A); ECB mode leaks plaintext patterns. "
        "Real configuration data is at risk.",
        "CRYPTO-003"),

    # CRYPTO-004: RC4
    _detect_pos("r6-pos-arc4-session", """
from Crypto.Cipher import ARC4

SESSION_KEY = b"static-session-key-arc4"

def encrypt_chat_message(msg: str) -> bytes:
    cipher = ARC4.new(SESSION_KEY)
    return cipher.encrypt(msg.encode())
""".strip(), "CWE-327",
        "ARC4 encrypts chat messages with a static key. RC4 has well-known "
        "statistical biases — repeated plaintext leaks through ciphertext. "
        "Real user messages are protected only by this stream cipher.",
        "CRYPTO-004"),

    _detect_pos("r6-pos-rc4-token", """
from Crypto.Cipher import ARC4

def generate_api_token(account_id: int) -> str:
    key = f"token-key-{account_id}".encode()[:16]
    cipher = ARC4.new(key)
    return cipher.encrypt(str(account_id).encode()).hex()
""".strip(), "CWE-327",
        "ARC4 generates API tokens from a predictable key structure. RC4 keystream "
        "biases allow an attacker to recover the token from observed ciphertexts "
        "over time. Real API authentication depends on this.",
        "CRYPTO-004"),

    # CRYPTO-006: static IV
    _detect_pos("r6-pos-static-iv-cbc", """
from Crypto.Cipher import AES

STATIC_IV = b"1234567890abcdef"

def encrypt_payload(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=STATIC_IV)
    ct = cipher.encrypt(data)
    return STATIC_IV + ct
""".strip(), "CWE-329",
        "AES-CBC uses a static, hard-coded IV. Identical first blocks across "
        "messages produce identical ciphertext; an attacker can detect repeated "
        "plaintext prefixes (e.g., 'user=admin'). Real data patterns are leaked.",
        "CRYPTO-006"),

    _detect_pos("r6-pos-nonce-reuse-gcm", """
from Crypto.Cipher import AES

COUNTER_NONCE = b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"

def encrypt_message(key: bytes, msg: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=COUNTER_NONCE)
    ct, tag = cipher.encrypt_and_digest(msg)
    return COUNTER_NONCE + ct + tag
""".strip(), "CWE-329",
        "AES-GCM reuses a fixed all-zero nonce across all messages. GCM nonce "
        "reuse completely breaks authentication: an attacker who observes two "
        "ciphertexts with the same nonce can forge valid tags. Catastrophic.",
        "CRYPTO-006"),
]

# CRYPTO-007/008/009/010
DETECT_POS_MORE = [
    # CRYPTO-007: hardcoded key
    _detect_pos("r6-pos-hardcoded-aes-key", """
from Crypto.Cipher import AES

DATABASE_KEY = b"prod-db-enc-key-2025"

def encrypt_credit_card(card_number: str) -> bytes:
    cipher = AES.new(DATABASE_KEY, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(card_number.encode())
    return cipher.nonce + ct + tag
""".strip(), "CWE-321",
        "The AES encryption key for credit card data is hard-coded in source. "
        "Anyone with repository access can decrypt all stored card numbers. "
        "Real payment data is protected by a key visible in version control.",
        "CRYPTO-007"),

    _detect_pos("r6-pos-hardcoded-hmac-key", """
import hmac, hashlib

WEBHOOK_SECRET = b"webhook-signing-secret-2024"

def verify_webhook(payload: bytes, signature: str) -> bool:
    expected = hmac.new(WEBHOOK_SECRET, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
""".strip(), "CWE-321",
        "The webhook HMAC signing key is hard-coded in source code. "
        "Repository compromise leaks the key, allowing an attacker to forge "
        "valid webhook signatures. Real webhook authentication is undermined.",
        "CRYPTO-007"),

    # CRYPTO-008: weak random source
    _detect_pos("r6-pos-weak-random-session", """
import random, string

def generate_session_token() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=32))
""".strip(), "CWE-338",
        "random.choices() uses the Mersenne Twister PRNG, which is NOT "
        "cryptographically secure. An attacker who observes a few tokens can "
        "predict future ones. Real session tokens must use secrets.token_urlsafe().",
        "CRYPTO-008"),

    _detect_pos("r6-pos-weak-random-2fa", """
import random

def generate_2fa_code() -> str:
    return f"{random.randint(100000, 999999)}"
""".strip(), "CWE-338",
        "random.randint() generates two-factor auth codes. The Mersenne Twister "
        "is predictable — an attacker who seeds the PRNG can replay codes. "
        "2FA codes must use secrets.randbelow() or a CSPRNG.",
        "CRYPTO-008"),

    # CRYPTO-009: weak key length
    _detect_pos("r6-pos-rsa-1024-keystore", """
from Crypto.PublicKey import RSA

def provision_device_key(device_id: str):
    key = RSA.generate(1024)
    with open(f"/secure/{device_id}.pem", "wb") as f:
        f.write(key.export_key("PEM", passphrase="device-secret"))
""".strip(), "CWE-326",
        "RSA.generate(1024) provisions device keys at 1024 bits. RSA-1024 "
        "is factorable with academic resources; NIST deprecated it in SP 800-57. "
        "Real device authentication keys are too weak.",
        "CRYPTO-009"),

    _detect_pos("r6-pos-ecc-p192-cert", """
from Crypto.PublicKey import ECC

def issue_certificate(subject: str) -> bytes:
    key = ECC.generate(curve="secp192r1")
    return sign_certificate(key, subject, validity_days=365)
""".strip(), "CWE-326",
        "secp192r1 provides ~96 bits of security. NIST SP 800-57 requires "
        "at least 112 bits (P-224) for 2030 and 128 bits (P-256) for new "
        "deployments. Certificates signed with this key are below the security floor.",
        "CRYPTO-009"),

    # CRYPTO-010: weak TLS
    _detect_pos("r6-pos-tlsv1-client", """
import ssl, socket

def connect_to_server(host: str, port: int = 443):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx.verify_mode = ssl.CERT_NONE
    ctx.check_hostname = False
    sock = ctx.wrap_socket(socket.socket(), server_hostname=host)
    sock.connect((host, port))
    return sock
""".strip(), "CWE-326",
        "PROTOCOL_TLSv1 with CERT_NONE and no hostname check. TLSv1 is "
        "deprecated (RFC 8996); certificate validation is completely disabled. "
        "A MITM attacker can intercept and decrypt all traffic.",
        "CRYPTO-010"),

    _detect_pos("r6-pos-requests-no-verify", """
import requests

AUTH_URL = "https://auth.internal.example.com"

def validate_token(token: str) -> dict:
    resp = requests.post(AUTH_URL, json={"token": token},
                         verify=False, timeout=10)
    return resp.json()
""".strip(), "CWE-326",
        "requests.post with verify=False disables TLS certificate validation. "
        "Real auth tokens are sent over an untrusted connection — a MITM can "
        "steal tokens and impersonate users.",
        "CRYPTO-010"),
]


# ══════════════════════════════════════════════════════════════════════════════
# DETECT ANEG: more safe libraries (6 new)
# ══════════════════════════════════════════════════════════════════════════════

DETECT_ANEG_NEW = [
    # argon2-cffi: Argon2id
    _detect_aneg("r6-argon2id", """
from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                    hash_len=32, salt_len=16)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hash_value: str, password: str) -> bool:
    return ph.verify(hash_value, password)
""".strip(),
        "Argon2id with OWASP-recommended parameters (t=3, m=64MB, p=4). "
        "No vulnerability — Argon2id is the current state-of-the-art password "
        "hashing function.",
        "argon2"),

    _detect_aneg("r6-argon2i", """
from argon2.low_level import hash_secret_raw, Type

def derive_key(password: bytes, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password, salt=salt,
        time_cost=4, memory_cost=131072, parallelism=2,
        hash_len=32, type=Type.I,
    )
""".strip(),
        "Argon2i with 4 iterations and 128MB memory. Argon2i is side-channel "
        "resistant; suitable for key derivation. No vulnerability.",
        "argon2"),

    # ecdsa: SECP256k1
    _detect_aneg("r6-ecdsa-sign", """
from ecdsa import SigningKey, SECP256k1

def generate_wallet_keypair():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    return sk, vk

def sign_transaction(sk: SigningKey, tx_hash: bytes) -> bytes:
    return sk.sign(tx_hash)
""".strip(),
        "ECDSA SECP256k1 key generation and signing. SECP256k1 provides "
        "~128-bit security. No vulnerability — modern elliptic curve.",
        "ecdsa"),

    _detect_aneg("r6-ecdsa-verify", """
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError

def verify_message(vk: VerifyingKey, message: bytes, sig: bytes) -> bool:
    try:
        return vk.verify(sig, message)
    except BadSignatureError:
        return False
""".strip(),
        "ECDSA SECP256k1 signature verification with BadSignatureError handling. "
        "No vulnerability.",
        "ecdsa"),

    # google-auth: OAuth2 token
    _detect_aneg("r6-google-auth", """
from google.oauth2 import service_account
from google.auth.transport.requests import AuthorizedSession

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

def get_authorized_session(credentials_path: str):
    creds = service_account.Credentials.from_service_account_file(
        credentials_path, scopes=SCOPES)
    return AuthorizedSession(creds)
""".strip(),
        "google-auth OAuth2 service-account session with proper credential "
        "loading from file. Token management is handled by the library. "
        "No vulnerability.",
        "google-auth"),

    # oscrypto: AES-KWP (Key Wrap with Padding)
    _detect_aneg("r6-oscrypto-aes-kwp", """
from oscrypto import symmetric

def wrap_private_key(key_material: bytes, kek: bytes) -> bytes:
    return symmetric.aes_key_wrap(kek, key_material)

def unwrap_private_key(wrapped_key: bytes, kek: bytes) -> bytes:
    return symmetric.aes_key_unwrap(kek, wrapped_key)
""".strip(),
        "oscrypto AES Key Wrap (RFC 3394/5649) for wrapping private key material. "
        "AES-KW provides authenticated key wrapping. No vulnerability.",
        "oscrypto"),
]


# ══════════════════════════════════════════════════════════════════════════════
# DETECT BNEG: library-implements-legacy type (6 new)
#   These are the CRITICAL missing category — libraries that implement weak
#   ciphers for format compatibility, not because they're choosing bad crypto.
# ══════════════════════════════════════════════════════════════════════════════

DETECT_BNEG_NEW = [
    _detect_bneg("r6-bneg-des-pkcs12-parser", """
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad

# PKCS#12 key derivation uses 3DES as part of the standard format.
# The library MUST implement DES3 to read PKCS#12 files correctly.

def derive_pkcs12_key(password: str, salt: bytes, iterations: int) -> bytes:
    # PKCS#12 appends a 2-byte ID extension to the password for each
    # derivation step, then hashes with SHA-1, truncates to 24 bytes,
    # and uses DES3 as mandated by RFC 7292 §B.2.
    material = password.encode("utf-16be") + b"\\x00\\x00"
    key = b""
    diversifier = b""
    for i in range(3):
        v = hashlib.sha1(material + diversifier + salt).digest()
        key += v
        diversifier = (int.from_bytes(diversifier or b"\\x00", "big") + 1).to_bytes(8, "big")
    return key[:24]  # 3*8 bytes for 3DES-EDE
""".strip(),
        "DES3 key derivation follows PKCS#12 (RFC 7292) specification. The library "
        "implements DES3 because the standard mandates it for backward compatibility; "
        "it is not choosing DES3 over a modern cipher. Format interoperability.",
        "CRYPTO-003"),

    _detect_bneg("r6-bneg-md5-legacy-hash-format", """
import hashlib

# This module implements the $1$ (MD5-crypt) password hash format for
# compatibility with legacy /etc/shadow entries during system migration.
# FreeBSD and older Linux distributions used md5_crypt as their default
# hashing scheme; the library must verify these hashes during migration.

def verify_md5_crypt_hash(password: str, stored_hash: str) -> bool:
    # stored_hash format: $1$salt$hash
    salt = stored_hash.split("$")[2]
    expected = stored_hash.split("$")[3]
    computed = hashlib.md5((password + salt + password).encode()).hexdigest()
    for _ in range(999):
        computed = hashlib.md5(computed.encode()).hexdigest()
    return computed == expected
""".strip(),
        "MD5 is used solely to verify existing $1$ legacy password hashes during "
        "a system migration. The library does not choose MD5 for new passwords; "
        "it only verifies existing hashes. Format interoperability — safe.",
        "CRYPTO-001"),

    _detect_bneg("r6-bneg-sha1-legacy-signature-verifier", """
import hashlib

# This module reads GPG keys with SHA-1 self-signatures from old keyrings.
# SHA-1 is part of the OpenPGP v4 fingerprint format; the library must
# compute SHA-1 to verify key ownership during import.

def verify_legacy_key_fingerprint(raw_key: bytes, expected_fp: str) -> bool:
    # OpenPGP v4 fingerprints are SHA-1 of the public key packet.
    # The library verifies, it does not generate new SHA-1 signatures.
    actual_fp = hashlib.sha1(raw_key).hexdigest()
    return actual_fp[-16:] == expected_fp[-16:]
""".strip(),
        "SHA-1 verifies an existing OpenPGP v4 key fingerprint. The format "
        "requires SHA-1 for fingerprint computation; the library does not "
        "choose SHA-1 — the standard does. Format interoperability.",
        "CRYPTO-002"),

    _detect_bneg("r6-bneg-rc4-legacy-protocol-handler", """
from Crypto.Cipher import ARC4

# This module implements the MS-CHAPv2 protocol for connecting to legacy
# RADIUS servers. MS-CHAPv2 (RFC 2759) specifies RC4 with specific key
# derivation; the library must implement RC4 to talk to existing hardware.

def ms_chapv2_challenge_response(password: str, challenge: bytes) -> bytes:
    # MS-CHAPv2 uses NT-hash -> padding -> DES3 first 16 bytes,
    # then ARC4 with the challenge for the response.
    key = derive_nt_hash(password)  # external
    cipher = ARC4.new(key)
    return cipher.encrypt(challenge)
""".strip(),
        "ARC4 is used solely to implement MS-CHAPv2 for legacy RADIUS "
        "authentication. The protocol mandates RC4; the library provides "
        "interoperability with existing infrastructure, not a new cryptographic "
        "choice. Protocol compatibility.",
        "CRYPTO-004"),

    _detect_bneg("r6-bneg-md5-file-integrity-check", """
import hashlib, os

# Database backup verification: compute MD5 of the backup file and compare
# to the stored checksum. MD5 is used for integrity (detect corruption),
# not for security (no adversary model).

def verify_backup_integrity(backup_path: str, expected_checksum: str) -> bool:
    h = hashlib.md5()
    with open(backup_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest() == expected_checksum
""".strip(),
        "MD5 checksums a backup file for corruption detection. No adversary "
        "is trying to craft collisions — this is an integrity check, not a "
        "cryptographic authentication. File integrity — safe.",
        "CRYPTO-001"),

    _detect_bneg("r6-bneg-sha1-cache-etag", """
import hashlib

# HTTP ETag generation for a CDN cache layer. SHA-1 of the response body
# is used to generate cache-busting ETags. Not a security primitive.

def generate_etag(response_data: bytes) -> str:
    return f'W/"sha1-{hashlib.sha1(response_data).hexdigest()}"'

def is_cache_fresh(etag: str, stored_etag: str) -> bool:
    return etag == stored_etag
""".strip(),
        "SHA-1 generates HTTP ETags for CDN cache validation. The ETag is "
        "used for cache invalidation, not authentication; an attacker "
        "generating SHA-1 collisions can only poison a cache, not forge "
        "credentials or steal data. Caching utility — safe.",
        "CRYPTO-002"),
]


# ══════════════════════════════════════════════════════════════════════════════
# TRIAGE: more Confirm + more Reject (8 new)
# ══════════════════════════════════════════════════════════════════════════════

TRIAGE_NEW = [
    # Confirm: hardcoded-key in production
    _triage_confirm("r6-rfix-hardcoded-key-prod", """
from Crypto.Cipher import AES

PROD_ENC_KEY = b"prod-encryption-key-2024"

def encrypt_audit_log(entry: str) -> bytes:
    cipher = AES.new(PROD_ENC_KEY, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(entry.encode())
    return cipher.nonce + ct + tag
""".strip(),
        "[CRYPTO-007] Secret 'PROD_ENC_KEY' may be a hard-coded key",
        "CWE-321",
        "AES-GCM encrypts real audit log entries with a key hard-coded in "
        "source. Audit logs contain sensitive operational data; the key is "
        "visible to anyone with repository access. Real security depends on "
        "this key — Confirm.",
        patch="""import os
from Crypto.Cipher import AES

PROD_ENC_KEY = os.environb[b"AUDIT_LOG_ENC_KEY"]

def encrypt_audit_log(entry: str) -> bytes:
    cipher = AES.new(PROD_ENC_KEY, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(entry.encode())
    return cipher.nonce + ct + tag""",
        rule="CRYPTO-007"),

    # Confirm: SSLv3 production
    _triage_confirm("r6-rfix-sslv3-prod", """
import ssl

def setup_production_listener():
    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
    ctx.load_cert_chain("/etc/ssl/certs/server.crt",
                        "/etc/ssl/private/server.key")
    return ctx
""".strip(),
        "[CRYPTO-010] Insecure SSL/TLS protocol version 'PROTOCOL_SSLv3' is used",
        "CWE-326",
        "SSLv3 is used for a production listener with a real server certificate. "
        "SSLv3 is vulnerable to POODLE and has been deprecated since 2015 "
        "(RFC 7568). Real client traffic is exposed — Confirm.",
        patch="""import ssl

def setup_production_listener():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain("/etc/ssl/certs/server.crt",
                        "/etc/ssl/private/server.key")
    return ctx""",
        rule="CRYPTO-010"),

    # Confirm: RSA-1024 production key gen
    _triage_confirm("r6-rfix-rsa1024-customer", """
from Crypto.PublicKey import RSA

def generate_customer_keypair(customer_id: str):
    key = RSA.generate(1024)
    store_private(customer_id, key)
    distribute_public(customer_id, key.publickey())
""".strip(),
        "[CRYPTO-009] RSA key size 1024 bits is cryptographically weak (CWE-326/CWE-327)",
        "CWE-326",
        "RSA-1024 key pair generated for customer authentication. The key "
        "protects real customer communication and can be factored with "
        "modest cloud resources. Real customer security is at risk — Confirm.",
        patch="""from Crypto.PublicKey import RSA

def generate_customer_keypair(customer_id: str):
    key = RSA.generate(2048)
    store_private(customer_id, key)
    distribute_public(customer_id, key.publickey())""",
        rule="CRYPTO-009"),

    # Reject: DES in PGP key format parser (library compatibility)
    _triage_reject("r6-trej-des-pgp-format", """
from Crypto.Cipher import DES3

# OpenPGP key format parser: reads keys from legacy PGP keyrings.
# DES3 is used only to decrypt private key material encrypted with
# the PGP symmetric-key encrypted session key packet (tag 3).
# This is format-driven: the algorithm ID comes FROM the keyring,
# never chosen by the library.

def parse_pgp_private_key(keyring_data: bytes, passphrase: str) -> bytes:
    algo, params = parse_s2k(keyring_data)  # reads algorithm ID
    if algo == 2:  # Triple-DES as specified in RFC 4880 §5.3
        key = derive_s2k_key(passphrase, params, 24)
        cipher = DES3.new(key, DES3.MODE_CFB, iv=keyring_data[2:10])
        pt = cipher.decrypt(keyring_data[10:])
        return pt
    raise UnsupportedAlgorithm(f"algo {algo}")
""".strip(),
        "[CRYPTO-003] 'DES3' referenced — DES/3DES may be weak encryption",
        "DES3 decrypts PGP private keys during keyring parsing. The algorithm "
        "ID comes from the keyring file (RFC 4880 §5.3), not from the library. "
        "The library must implement DES3 to read existing PGP keys; it does not "
        "generate new DES3-encrypted material. Format interoperability — Reject.",
        source="round6-lib-reject", rule="CRYPTO-003"),

    # Reject: MD5 in consistent hash ring (sharding)
    _triage_reject("r6-trej-md5-consistent-hash", """
import hashlib

# Consistent hash ring implementation for distributed cache.
# MD5 is used to map cache keys to ring positions — no adversary
# can benefit from finding MD5 collisions here: the worst case is
# two keys mapping to the same shard, which is the normal behavior
# of any hash ring under modulo.

def get_shard_node(key: str, ring_size: int = 160) -> int:
    digest = hashlib.md5(key.encode()).digest()
    return int.from_bytes(digest[:4], "big") % ring_size
""".strip(),
        "[CRYPTO-001] 'md5' hash used for key sharding — MD5 is cryptographically broken",
        "MD5 maps cache keys to shard nodes in a consistent hash ring. "
        "Collisions only cause cache co-location, not security compromise. "
        "No credentials, tokens, or secrets are protected by the hash output. "
        "Load distribution — Reject.",
        source="round6-lib-reject", rule="CRYPTO-001"),
]


# ══════════════════════════════════════════════════════════════════════════════
# EMIT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    all_detect_new = DETECT_POS_NEW + DETECT_POS_MORE + DETECT_ANEG_NEW + DETECT_BNEG_NEW
    all_triage_new = TRIAGE_NEW

    # Assign val/test splits (10% each, stratified)
    import random
    random.seed(42)

    # Pick val/test from each category
    def _holdout(records, category_name, val_n=1, test_n=1):
        candidates = [r for r in records if r["split"] == "train"]
        random.shuffle(candidates)
        if len(candidates) >= val_n + test_n:
            for r in candidates[:val_n]:
                r["split"] = "val"
            for r in candidates[val_n:val_n + test_n]:
                r["split"] = "test"
        print(f"  {category_name}: {len(records)} total, val={val_n}, test={test_n}")

    print("\nAssigning val/test splits...")
    _holdout(DETECT_POS_NEW, "detect-pos-new", 2, 2)
    _holdout(DETECT_POS_MORE, "detect-pos-more", 2, 2)
    _holdout(DETECT_ANEG_NEW, "detect-aneg-new", 1, 1)
    _holdout(DETECT_BNEG_NEW, "detect-bneg-new", 1, 1)
    _holdout(TRIAGE_NEW, "triage-new", 1, 1)

    # Print summary
    for task_name, records in [("detect", all_detect_new), ("triage", all_triage_new)]:
        print(f"\n{'='*50}")
        print(f"{task_name.upper()} — {len(records)} new samples")
        for split in ("train", "val", "test"):
            subset = [r for r in records if r["split"] == split]
            pos = sum(1 for r in subset if r["label"].get("vulnerable"))
            neg = sum(1 for r in subset if not r["label"].get("vulnerable"))
            total = len(subset)
            pct = f"{pos/total:.0%}" if total else "-"
            print(f"  {split}: {total} (pos={pos}={pct})")
            for r in subset:
                print(f"    {r['id']}")

    # Emit supplementary files
    out_d = R6
    p_d = out_d / "supplement_detect.jsonl"
    p_t = out_d / "supplement_triage.jsonl"

    p_d.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in all_detect_new) + "\n", encoding="utf-8")
    p_t.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in all_triage_new) + "\n", encoding="utf-8")
    print(f"\n[+] {p_d}")
    print(f"[+] {p_t}")

    total = len(all_detect_new) + len(all_triage_new)
    train = sum(1 for r in all_detect_new + all_triage_new if r["split"] == "train")
    val = sum(1 for r in all_detect_new + all_triage_new if r["split"] == "val")
    test = sum(1 for r in all_detect_new + all_triage_new if r["split"] == "test")
    print(f"\nTotal: {total} (train={train} val={val} test={test})")

if __name__ == "__main__":
    main()
