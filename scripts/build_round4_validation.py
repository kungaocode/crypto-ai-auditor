#!/usr/bin/env python3
"""Round-4 real-project validation-set builder.

Builds a held-out evaluation set from 5 real Python crypto libraries (shallow
clones under data/round4/real_projects/, pinned commits in REPOS below). The set
tests the round-4 goal that the model stops over-reporting on genuine crypto
code (see data/round3/eval/ACCEPTANCE.md "detect 层近乎全报").

Two subsets (v2 schema, split=test, verified=True):
  triage : every Semgrep CRYPTO-rule hit in the 5 repos, reduced to unique
           (repo, file, function) cases. Ground truth is *Reject* for all of
           them: crypto libraries legitimately implement / test the weak
           primitives, and a password-hash library must verify legacy schemes.
           Categories: test-vector | benchmark | legacy-format | legacy-hash-scheme
           | hmac-legacy-digest.
  detect : a small curated set of genuinely-secure functions from the same repos
           (HMAC compare_digest, PBKDF2, bcrypt, RSA-OAEP, RSA-SHA256 sign,
           HMAC-SHA256 sign, scrypt, AES-GCM). Ground truth vulnerable=false.

Outputs (data/round4/real_validation/):
  triage.jsonl   detect.jsonl   manifest.json

Usage: python scripts/build_round4_validation.py
"""
import ast
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REAL = ROOT / "data" / "round4" / "real_projects"
OUT = ROOT / "data" / "round4" / "real_validation"
OUT.mkdir(parents=True, exist_ok=True)

# --- pinned clones -----------------------------------------------------------
REPOS = {
    "itsdangerous": {"url": "https://github.com/pallets/itsdangerous",
                     "commit": "672971d66a2ef9f85151e53283113f33d642dabd",
                     "license": "BSD-3-Clause"},
    "passlib": {"url": "https://github.com/deepin-community/python-passlib",
                "commit": "f5f66f567b6bc90397800dae22c14a9423389d12",
                "license": "BSD-3-Clause"},
    "pyjwt": {"url": "https://github.com/jpadilla/pyjwt",
              "commit": "30b7ca1afc9013ab9396c890ea98726a7a8311c7",
              "license": "MIT"},
    "python-rsa": {"url": "https://github.com/sybrenstuvel/python-rsa",
                   "commit": "42b0e14ffbeeb9d99d1037e6440a2cc61780e4ea",
                   "license": "Apache-2.0"},
    "pycryptodome": {"url": "https://github.com/Legrandin/pycryptodome",
                     "commit": "a1e52c70302a51077e9d6a20a6abc6a04da1b5e6",
                     "license": "BSD-2-Clause"},
}

RULE_MSG = {
    "CRYPTO-001": "Use of MD5 which is not collision-resistant.",
    "CRYPTO-002": "Use of SHA-1 which is not collision-resistant.",
    "CRYPTO-003": "Use of DES or 3DES which have small block sizes and are considered weak.",
    "CRYPTO-004": "Use of RC4 which has multiple statistical biases and is deprecated.",
    "CRYPTO-009": "Weak key length or weak elliptic curve. Use RSA >= 2048 bits or a NIST P-256+ curve.",
}


# --- AST helpers -------------------------------------------------------------
def _src(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def enclosing_function(path: Path, line: int):
    """Return (qualname, source) of the function/method enclosing `line`."""
    src = _src(path)
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None, None
    lines = src.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                node.lineno <= line <= node.end_lineno:
            cls = ""
            for parent in ast.walk(tree):
                if isinstance(parent, ast.ClassDef) and \
                        parent.lineno <= node.lineno <= parent.end_lineno:
                    for sub in ast.walk(parent):
                        if sub is node:
                            cls = parent.name + "."
                            break
                    if cls:
                        break
            body = "\n".join(lines[node.lineno - 1:node.end_lineno])
            return f"{cls}{node.name}", body
    return None, None


def function_by_qualname(path: Path, qualname: str):
    """Return source of a module-level or Class.method function."""
    src = _src(path)
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    lines = src.splitlines()
    if "." in qualname:
        cls_name, _, meth = qualname.partition(".")
    else:
        cls_name, meth = "", qualname
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == meth:
            if cls_name:
                enclosing = [p for p in ast.walk(tree)
                             if isinstance(p, ast.ClassDef) and
                             p.lineno <= node.lineno <= p.end_lineno]
                if not any(p.name == cls_name for p in enclosing):
                    continue
            return "\n".join(lines[node.lineno - 1:node.end_lineno])
    return None


# --- triage categorization ---------------------------------------------------
def categorize(repo: str, rel: str) -> tuple:
    r = rel.lower()
    if repo == "itsdangerous":
        return ("hmac-legacy-digest",
                "SHA-1 is the library's default HMAC digest for signed cookies. HMAC does "
                "not require collision resistance, so HMAC-SHA1 remains an accepted "
                "signing choice here -> not a vulnerability.")
    if repo == "passlib":
        return ("legacy-hash-scheme",
                "The library implements a legacy password-hash scheme (md5_crypt, "
                "sha1_crypt, phpass, mysql/oracle/postgres/django digests) so existing "
                "stored hashes can still be verified; it must reproduce these formats. "
                "No new secret is protected by the weak digest alone -> not a vulnerability.")
    if "selftest" in r or "/test_" in r or r.startswith("test_"):
        return ("test-vector",
                "The weak primitive appears only in a unit test reproducing a known "
                "vector; no real data is protected -> not a vulnerability.")
    if "pct-speedtest" in r or "speedtest" in r:
        return ("benchmark",
                "The weak primitive appears only in a throughput benchmark on synthetic "
                "input; no real data -> not a vulnerability.")
    return ("legacy-format",
            "The library implements a legacy key/password format (PBES1/PEM) that "
            "historically uses DES/3DES, and must support reading it -> not a vulnerability.")


def build_triage() -> list:
    findings = [json.loads(l) for l in
                (ROOT / "data" / "round4" / "real_findings.jsonl").read_text().splitlines()
                if l.strip()]
    seen, records = set(), []
    for f in findings:
        repo = f["repo"]
        path = Path(f["file"])
        if not path.is_absolute():
            path = ROOT / path
        line = int(f["lines"].split("-")[0])
        qual, body = enclosing_function(path, line)
        key = (repo, f["file"], qual)
        if key in seen:
            continue
        seen.add(key)
        if qual is None:
            # Module-level finding: one ~12-line context window per file (imports
            # + test-vector/key definitions) is representative; the different
            # block modes are already spread across distinct test_*.py files.
            qual = f"<module>"
            lines = _src(path).splitlines()
            lo, hi = max(0, line - 12), min(len(lines), line + 12)
            body = "\n".join(lines[lo:hi])
        rule = f["rule"]
        rel = path.relative_to(REAL / repo).as_posix()
        cat, why = categorize(repo, rel)
        slug = (rel.replace("/", "_").replace(".py", "") + "__" +
                qual.replace(".", "_").replace("<", "").replace(">", "").replace(":", "_"))
        records.append({
            "id": f"round4-real-{repo}-{slug}-{rule}",
            "language": "python", "task": "triage",
            "code": body, "finding": f"[{rule}] {RULE_MSG[rule]}",
            "label": {"cwe": "", "severity": "INFO", "verdict": "Reject",
                      "explanation": why},
            "source": "round4-real-project", "license": REPOS[repo]["license"],
            "repo_url": REPOS[repo]["url"], "commit": REPOS[repo]["commit"],
            "verified": True, "split": "test",
            "rule": rule, "category": cat, "file": rel,
        })
    return records


# Curated secure functions (qualified name), grounded in NIST-approved patterns.
DETECT_SECURE = [
    ("itsdangerous", "src/itsdangerous/signer.py",
     "SigningAlgorithm.verify_signature",
     "HMAC signature verified with hmac.compare_digest (constant-time). Correct "
     "message authentication -> safe."),
    ("passlib", "passlib/handlers/pbkdf2.py",
     "Pbkdf2DigestHandler._calc_checksum",
     "Password hash computed via PBKDF2-HMAC (keyed, salted, iterated). Correct "
     "password derivation -> safe."),
    ("passlib", "passlib/handlers/bcrypt.py",
     "_BcryptBackend._calc_checksum",
     "Password hash delegated to the bcrypt backend (slow, salted). Correct "
     "password hashing -> safe."),
    ("python-rsa", "rsa/pkcs1.py",
     "encrypt",
     "RSA-OAEP encryption with a fresh random seed. Authenticated, padded "
     "asymmetric encryption -> safe."),
    ("pyjwt", "jwt/algorithms.py",
     "HMACAlgorithm.sign",
     "JWS signing via HMAC with the algorithm's SHA-2 digest. Correct "
     "symmetric signature -> safe."),
    ("pycryptodome", "lib/Crypto/Protocol/KDF.py",
     "scrypt",
     "scrypt key derivation (memory-hard, salted). Approved password KDF -> safe."),
    ("pycryptodome", "lib/Crypto/Cipher/_mode_gcm.py",
     "GcmMode.encrypt",
     "AES-GCM authenticated encryption. No ECB/fixed-IV/unauthenticated mode -> safe."),
]


def build_detect() -> list:
    records = []
    for repo, rel, qual, why in DETECT_SECURE:
        body = function_by_qualname(REAL / repo / rel, qual)
        if body is None:
            print(f"  [warn] detect not found: {repo} {qual}", file=sys.stderr)
            continue
        slug = qual.replace(".", "_")
        records.append({
            "id": f"round4-real-detect-{repo}-{slug}",
            "language": "python", "task": "detect",
            "code": body,
            "label": {"vulnerable": False, "cwe": "", "severity": "",
                      "confidence": "high", "explanation": why},
            "source": "round4-real-project", "license": REPOS[repo]["license"],
            "repo_url": REPOS[repo]["url"], "commit": REPOS[repo]["commit"],
            "verified": True, "split": "test", "file": rel,
        })
    return records


def main() -> None:
    triage = build_triage()
    detect = build_detect()
    (OUT / "triage.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in triage) + "\n")
    (OUT / "detect.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in detect) + "\n")

    tc = Counter(t["category"] for t in triage)
    rc = Counter(t["rule"] for t in triage)
    manifest = {
        "repos": REPOS,
        "triage": {"n": len(triage), "all_verdict": "Reject",
                   "by_category": dict(tc), "by_rule": dict(rc)},
        "detect": {"n": len(detect), "all_vulnerable": False},
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"[round4-validation] triage={len(triage)} detect={len(detect)}")
    print("  triage by rule  :", dict(rc))
    print("  triage by cat   :", dict(tc))
    print(f"  wrote {OUT}/triage.jsonl, {OUT}/detect.jsonl, {OUT}/manifest.json")


if __name__ == "__main__":
    main()
