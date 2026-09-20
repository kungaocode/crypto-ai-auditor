"""Demo: intentionally vulnerable crypto patterns used to exercise the audit pipeline.
DO NOT use these patterns in real code.
"""
import hashlib
import os
import random
import ssl

import requests
from Crypto.Cipher import AES, PKCS1_v1_5


def legacy_digest(data):
    # CRYPTO-001 / CRYPTO-002: broken hash primitives
    h = hashlib.md5(data)
    h2 = hashlib.sha1(data)
    return h.hexdigest(), h2.hexdigest()


def aes_ecb_encrypt(key, plaintext):
    # CRYPTO-005: ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def aes_cbc_weak_iv(key, plaintext):
    # CRYPTO-006: empty IV
    iv = b""
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(plaintext)


def hardcoded_key():
    # CRYPTO-007: literal key in source
    key = b"0123456789abcdef"
    return AES.new(key, AES.MODE_GCM)


def weak_iv_source():
    # CRYPTO-008: random module for an IV
    iv = random.random()
    return AES.new(b"0000000000000000", AES.MODE_CBC, iv=bytes(iv * 16))


def weak_rsa():
    # CRYPTO-009: 1024-bit RSA
    from Crypto.PublicKey import RSA

    key = RSA.generate(1024)
    return key


def insecure_tls():
    # CRYPTO-010: old protocol + disabled verification
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    requests.get("https://example.com", verify=False)
    return ctx
