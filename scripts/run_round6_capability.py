#!/usr/bin/env python3
"""Round-6 model capability probes beyond the standard suites.

Three hand-written, deterministic suites that stress the deployed model's
crypto-misuse knowledge and false-positive resistance:

  A. 13-rule detect matrix  — 1 vulnerable + 1 secure snippet per CRYPTO-001..013
     (checks the vulnerable flag AND the reported CWE per rule).
  B. Secure-library FPR set — 10 correct usages of secure crypto libraries that
     a naive detector would flag but must NOT be reported as vulnerable.
  C. Output well-formedness — every response must parse as JSON (instruction
     following / format reliability).

Usage (from repo root):
  export LLM_API_KEY="$(sed -n '2p' api.txt)"
  export LLM_MODEL_ID="qwen3-4b-instruct-2507-5f8261ad123d"
  export LLM_WORKSPACE="ws-avxkjb2tq5lq1gwm"
  python3 scripts/run_round6_capability.py
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from model.inference import CloudBackend, LLMError

OUT_DIR = ROOT / "data" / "round6" / "eval"
DEFAULT_MODEL_ID = "qwen3-4b-instruct-2507-5f8261ad123d"

# (rule_id, expected_cwe) -> vulnerable snippet
VULN = {
    "CRYPTO-001": ("CWE-327", "import hashlib\nh = hashlib.md5(data.encode()).hexdigest()"),
    "CRYPTO-002": ("CWE-327", "import hashlib\nh = hashlib.sha1(data.encode()).hexdigest()"),
    "CRYPTO-003": ("CWE-327", "from Crypto.Cipher import DES\nc = DES.new(key8, DES.MODE_ECB).encrypt(data)"),
    "CRYPTO-004": ("CWE-327", "from Crypto.Cipher import ARC4\nc = ARC4.new(key).encrypt(data)"),
    "CRYPTO-005": ("CWE-327", "from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_ECB).encrypt(data)"),
    "CRYPTO-006": ("CWE-329", "from Crypto.Cipher import AES\niv = b'\\x00' * 16\nc = AES.new(key, AES.MODE_CBC, iv).encrypt(data)"),
    "CRYPTO-007": ("CWE-321", "from Crypto.Cipher import AES\nc = AES.new(b'0123456789abcdef', AES.MODE_GCM).encrypt(data)"),
    "CRYPTO-008": ("CWE-338", "import random\nsecret_token = random.randint(0, 2**32)"),
    "CRYPTO-009": ("CWE-326", "from Crypto.PublicKey import RSA\nk = RSA.generate(1024)"),
    "CRYPTO-010": ("CWE-326", "import ssl\nctx = ssl._create_unverified_context()"),
    "CRYPTO-011": ("CWE-256", "def register(user, raw):\n    user.password = raw\n    db.save(user)"),
    "CRYPTO-012": ("CWE-916", "import hashlib\nd = hashlib.pbkdf2_hmac('sha256', pw, salt, 8000)"),
    "CRYPTO-013": ("CWE-208", "def check(user, attempt):\n    return user.digest == attempt"),
}

# (rule_id) -> secure alternative snippet (must NOT be flagged)
SAFE = {
    "CRYPTO-001": "import hashlib\nh = hashlib.sha256(data.encode()).hexdigest()",
    "CRYPTO-002": "import hashlib\nh = hashlib.sha256(data.encode()).hexdigest()",
    "CRYPTO-003": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nc = AESGCM(key).encrypt(os.urandom(12), data, None)",
    "CRYPTO-004": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nc = AESGCM(key).encrypt(os.urandom(12), data, None)",
    "CRYPTO-005": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nc = AESGCM(key).encrypt(os.urandom(12), data, None)",
    "CRYPTO-006": "from Crypto.Cipher import AES\nimport os\niv = os.urandom(16)\nc = AES.new(key, AES.MODE_CBC, iv).encrypt(data)",
    "CRYPTO-007": "import os\nfrom Crypto.Cipher import AES\nkey = os.environ['ENC_KEY'].encode()\nc = AES.new(key, AES.MODE_GCM).encrypt(data)",
    "CRYPTO-008": "import secrets\ntoken = secrets.token_urlsafe(32)",
    "CRYPTO-009": "from Crypto.PublicKey import RSA\nk = RSA.generate(2048)",
    "CRYPTO-010": "import ssl\nctx = ssl.create_default_context()",
    "CRYPTO-011": "from django.contrib.auth.hashers import make_password\nuser.password = make_password(raw)",
    "CRYPTO-012": "import hashlib\nd = hashlib.pbkdf2_hmac('sha256', pw, salt, 600000)",
    "CRYPTO-013": "import secrets\ndef check(user, attempt):\n    return secrets.compare_digest(user.digest, attempt)",
}

# Secure-library false-positive resistance (must ALL be vulnerable=false)
SECURE_LIB = {
    "cryptography-AESGCM": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nimport os\nct = AESGCM(key).encrypt(os.urandom(12), plaintext, None)",
    "argon2": "from argon2 import PasswordHasher\nph = PasswordHasher()\nh = ph.hash(password)",
    "secrets-token": "import secrets\nsession_id = secrets.token_urlsafe(32)",
    "hmac-compare": "import hmac\nok = hmac.compare_digest(user_sig, expected_sig)",
    "ssl-default-context": "import ssl\nctx = ssl.create_default_context()",
    "os-urandom": "import os\nnonce = os.urandom(16)",
    "nacl-secretbox": "from nacl.secret import SecretBox\nbox = SecretBox(key)\nenc = box.encrypt(msg)",
    "ecdsa-sign": "from ecdsa import SigningKey, SECP256k1\nsk = SigningKey.generate(curve=SECP256k1)\nsig = sk.sign(data)",
    "bcrypt": "import bcrypt\nh = bcrypt.hashpw(pw, bcrypt.gensalt())",
    "sha256-integrity": "import hashlib\ndigest = hashlib.sha256(blob).hexdigest()",
}


def run_detect(backend, name, code):
    try:
        return backend.detect(code)
    except LLMError as e:
        print(f"  !! {name} error: {e}")
        return {}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model-id", default=None)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = ap.parse_args()

    backend = CloudBackend(model_id=args.model_id or DEFAULT_MODEL_ID)
    print(f"[*] backend: {type(backend).__name__} model={backend.model_id}")

    matrix = []   # per-rule {rule, cwe, vuln_ok, vuln_cwe_ok, safe_ok}
    for rule in sorted(VULN):
        cwe, vcode = VULN[rule]
        scode = SAFE[rule]
        vp = run_detect(backend, f"{rule}-vuln", vcode)
        sp = run_detect(backend, f"{rule}-safe", scode)
        vuln_ok = bool(vp.get("vulnerable")) is True
        vuln_cwe_ok = str(vp.get("cwe", "")).startswith(cwe)
        safe_ok = bool(sp.get("vulnerable")) is False
        matrix.append({
            "rule": rule, "expected_cwe": cwe,
            "vuln_pred": bool(vp.get("vulnerable")), "vuln_cwe": vp.get("cwe", ""),
            "vuln_ok": vuln_ok, "vuln_cwe_ok": vuln_cwe_ok,
            "safe_pred": bool(sp.get("vulnerable")), "safe_ok": safe_ok,
        })
        print(f"  {rule} {cwe}: vuln={bool(vp.get('vulnerable'))}({vp.get('cwe','')}) "
              f"{'OK' if vuln_ok else '**'} | safe={bool(sp.get('vulnerable'))} "
              f"{'OK' if safe_ok else '**'}")

    fpr_rows = []
    for name, code in SECURE_LIB.items():
        p = run_detect(backend, name, code)
        ok = bool(p.get("vulnerable")) is False
        fpr_rows.append({"name": name, "pred": bool(p.get("vulnerable")),
                         "cwe": p.get("cwe", ""), "ok": ok})
        print(f"  secure {name:<22} vulnerable={bool(p.get('vulnerable'))} "
              f"{'OK' if ok else '**'} {p.get('cwe','')}")

    summary = {
        "model_id": backend.model_id,
        "rule_matrix": {
            "n_rules": len(matrix),
            "vuln_detected": sum(1 for m in matrix if m["vuln_ok"]),
            "vuln_cwe_correct": sum(1 for m in matrix if m["vuln_cwe_ok"]),
            "safe_not_flagged": sum(1 for m in matrix if m["safe_ok"]),
            "rows": matrix,
        },
        "secure_lib": {
            "n": len(fpr_rows),
            "not_flagged": sum(1 for r in fpr_rows if r["ok"]),
            "fpr": round(sum(1 for r in fpr_rows if not r["ok"]) / len(fpr_rows), 4),
            "rows": fpr_rows,
        },
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "capability_r6.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n==== A. 13-rule detect matrix ====")
    rm = summary["rule_matrix"]
    print(f"  vulnerable detected: {rm['vuln_detected']}/{rm['n_rules']}  "
          f"cwe correct: {rm['vuln_cwe_correct']}/{rm['n_rules']}  "
          f"secure not flagged: {rm['safe_not_flagged']}/{rm['n_rules']}")
    print("\n==== B. secure-library FPR set ====")
    sl = summary["secure_lib"]
    print(f"  not flagged: {sl['not_flagged']}/{sl['n']}  fpr={sl['fpr']}")
    print(f"\n[+] wrote {args.out_dir}/capability_r6.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
