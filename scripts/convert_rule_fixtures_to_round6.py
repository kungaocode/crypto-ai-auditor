#!/usr/bin/env python3
"""Convert tool-maintained crypto rule fixtures into Round-6 detect/triage rows.

Sources (already on disk under data/external/):
  * Semgrep official rule fixtures  -- python/**/*.py with `# ruleid:` / `# ok:`
    line annotations. The `.yaml` next to a fixture is the rule definition
    (id, message, CWE, severity).
  * Bandit example programs        -- PyCQA/bandit examples/ (Apache-2.0) whose
    insecure lines are asserted by tests/functional/test_functional.py.

What this emits:
  data/round6/rule_fixture_detect.jsonl  -- detect positives/negatives
  data/round6/rule_fixture_triage.jsonl  -- triage Confirm/Reject

Honesty constraints (do not relax):
  * These rows are FIXTURE-REGRESSION data. They are `verified=false` and must
    never be written into `real_verified_{detect,triage}.jsonl`.
  * Only statements whose rule maps onto the shipped CRYPTO-001..013 taxonomy
    AND whose code matches that rule's own scope guard are emitted. Everything
    else is skipped and reported, not silently mislabelled.
  * Positives (ruleid) become detect positives and triage Confirm.
    Negatives (ok) become detect negatives and triage Reject.
  * Paired `.fixed.py` snippets are not promoted into triage patches: upstream
    fix fixtures are illustrative and are not API-level retested here.

Semgrep's rule database is released under the Semgrep Rules License v1.0, which
restricts redistribution. Bandit's examples are Apache-2.0. Per-record `license`
records which applies; see the warning printed at the end of a run.

Usage:
  python3 scripts/convert_rule_fixtures_to_round6.py            # report only
  python3 scripts/convert_rule_fixtures_to_round6.py --emit     # write JSONL
"""
import argparse
import ast
import hashlib
import json
import re
import sys
import textwrap
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
EXTERNAL = ROOT / "data" / "external"
SEMGREP_PY = EXTERNAL / "semgrep-rules" / "python"
BANDIT_EXAMPLES = EXTERNAL / "bandit" / "examples"
OUT_DIR = ROOT / "data" / "round6"

SEMGREP_LICENSE = "Semgrep Rules License v1.0"
BANDIT_LICENSE = "Apache-2.0"


# --- shipped rule taxonomy (single source of truth = rules/crypto-*/rule.yaml) ---
def load_rule_meta():
    meta = {}
    for path in sorted((ROOT / "rules").glob("crypto-*/rule.yaml")):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8")).get("rules", []):
            meta[rule["id"]] = {
                "cwe": rule.get("metadata", {}).get("cwe", ""),
                "severity": rule.get("severity", "WARNING"),
                "message": rule["message"],
            }
    if len(meta) != 13:
        raise SystemExit(f"[FAIL] expected 13 CRYPTO rules, loaded {len(meta)}")
    return meta


RULE_META = load_rule_meta()


# --- external rule id -> shipped CRYPTO rule -------------------------------------
# Only rules whose semantics match a shipped CRYPTO rule exactly are mapped.
# Everything absent here (blowfish, rc2, idea, xor, md2/md4, JWT, empty key,
# no-set-ciphers, sha224, mode-without-authentication, ...) is deliberately
# skipped: mapping them would teach a rule/CWE pair the detector never emits.
SEMGREP_RULE_TO_CRYPTO = {
    "insecure-hash-algorithm-md5": "CRYPTO-001",
    "insecure-hash-algorithms-md5": "CRYPTO-001",
    "md5-used-as-password": "CRYPTO-001",
    "insecure-hash-algorithm-sha1": "CRYPTO-002",
    "insecure-cipher-algorithm-des": "CRYPTO-003",
    "insecure-cipher-algorithm-rc4": "CRYPTO-004",
    "insecure-cipher-mode-ecb": "CRYPTO-005",
    "insufficient-rsa-key-size": "CRYPTO-009",
    "insufficient-ec-key-size": "CRYPTO-009",
    "disabled-cert-validation": "CRYPTO-010",
    "unverified-ssl-context": "CRYPTO-010",
    "weak-ssl-version": "CRYPTO-010",
}

# A positive snippet must still look like the shipped rule fires on it. This is
# what stops over-broad upstream rules (e.g. Semgrep flags RSA bits=2048 as
# "insufficient", while CRYPTO-009 only fires below 2048) from entering the set.
SCOPE_GUARDS = {
    "CRYPTO-001": re.compile(r"(?i)\bmd5\b"),
    "CRYPTO-002": re.compile(r"(?i)\bsha-?1\b|new\(\s*['\"]sha['\"]"),
    "CRYPTO-003": re.compile(r"\bDES3?\b"),
    "CRYPTO-004": re.compile(r"\bARC4\b|\bRC4\b"),
    "CRYPTO-005": re.compile(r"MODE_ECB|modes\.ECB|\bECB\("),
    "CRYPTO-008": re.compile(r"\brandom\.(?!SystemRandom)"),
    "CRYPTO-009": re.compile(
        r"(?i)(key_size|bits)\s*=\s*(512|768|1024)\b"
        r"|generate\(\s*(512|768|1024)\b"
        r"|SECP192R1|SECP160R1|SECP112R1|SECT163"
    ),
    "CRYPTO-010": re.compile(
        r"ssl\.(PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_TLSv1|PROTOCOL_TLSv1_1)"
        r"|_create_unverified_context|CERT_NONE|verify\s*=\s*False"
    ),
}

# CRYPTO-008 additionally requires the assigned name to look security-relevant
# (mirrors the metavariable-regex in rules/crypto-008-weak-random/rule.yaml).
SECURITY_NAME_RE = re.compile(r"(?i).*(key|iv|token|salt|nonce|secret|password)")

# The functions CRYPTO-008 actually matches (metavariable-regex on $FUNC in
# rules/crypto-008-weak-random/rule.yaml). Bandit flags more random.* calls
# (Random(), choices(), randbytes()); those are real weaknesses but the shipped
# detector does not emit them, so they must not be labelled as CRYPTO-008 hits.
CRYPTO008_FUNCS = {"random", "randint", "randrange", "choice", "sample",
                   "uniform", "gauss", "triangular", "getrandbits", "shuffle"}

# Approximate "does the shipped rule fire on this snippet?" used to gate
# negatives. A negative is only honest when the detector would NOT flag it;
# gating negatives on the positive scope guard instead (i.e. requiring the bad
# token to be present) would silently discard every real contrast.
FIRE_PATTERNS = {
    "CRYPTO-001": re.compile(
        r"hashlib\.md5\s*\(|hashlib\.new\(\s*['\"](?:md5|MD5)['\"]"),
    "CRYPTO-002": re.compile(
        r"hashlib\.sha1\s*\(|hashlib\.new\(\s*['\"](?:sha1|SHA1)['\"]"),
    "CRYPTO-003": re.compile(
        r"\bDES3?\.new\s*\(|Crypto\.Cipher\.DES3?\b"),
    "CRYPTO-004": re.compile(
        r"\bARC4\.new\s*\(|Crypto\.Cipher\.ARC4\b"),
    "CRYPTO-005": re.compile(
        r"AES\.MODE_ECB|modes\.ECB\s*\("),
    "CRYPTO-009": re.compile(
        r"RSA\.generate\(\s*(?:512|768|1024)\b"
        r"|SECP192R1|SECP160R1|SECP112R1|SECT163K1|SECT163R2"),
    # Order inside the alternation matters: the TLSv1_1 branch is tried before
    # the TLSv1 branch, whose lookahead refuses a trailing `_2`/digit suffix.
    "CRYPTO-010": re.compile(
        r"ssl\.(?:PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_TLSv1_1"
        r"|PROTOCOL_TLSv1(?![_0-9]))"
        r"|_create_unverified_context|ssl\.CERT_NONE|verify\s*=\s*False"),
}

CRYPTO008_CALL_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*random\.(\w+)\s*\(")


def rule_fires(rule, code):
    """True when the shipped detector would (approximately) flag `code`."""
    if rule == "CRYPTO-008":
        m = CRYPTO008_CALL_RE.match(code)
        if not m:
            return False
        name, func = m.group(1), m.group(2)
        return func in CRYPTO008_FUNCS and bool(SECURITY_NAME_RE.match(name))
    pattern = FIRE_PATTERNS.get(rule)
    return bool(pattern and pattern.search(code))


# A negative is only emitted when the snippet visibly contains the *mitigated*
# form of the same weakness (the substitute a reviewer would recommend). This
# stops an upstream `ok` marker from turning into "not vulnerable" just because
# our narrow pattern happens to miss a still-broken call (e.g. `MD5.new()`).
SAFE_GUARDS = {
    "CRYPTO-001": re.compile(r"(?i)sha-?(?:256|384|512|3)|blake2|argon2|scrypt|pbkdf2|bcrypt"),
    "CRYPTO-002": re.compile(r"(?i)sha-?(?:256|384|512|3)|blake2|argon2|scrypt|pbkdf2|bcrypt"),
    "CRYPTO-003": re.compile(r"\bAES\b|ChaCha20"),
    "CRYPTO-004": re.compile(r"\bAES\b|ChaCha20"),
    "CRYPTO-005": re.compile(r"\b(?:GCM|CTR|CBC|CFB|OFB|EAX|CCM|SIV)\b"),
    "CRYPTO-008": re.compile(r"\bos\.urandom\b|secrets\.|SystemRandom"),
    "CRYPTO-009": re.compile(
        r"\b(?:2048|3072|4096)\b|SECP(?:256|384|521)|CURVE25519|X25519|ED25519"),
    "CRYPTO-010": re.compile(
        r"create_default_context|verify\s*=\s*True|CERT_REQUIRED"
        r"|PROTOCOL_TLSv1_[23]|PROTOCOL_TLS_CLIENT"),
}


def safe_ok(rule, code):
    guard = SAFE_GUARDS.get(rule)
    return bool(guard and guard.search(code))


CONFIRM_NOTES = {
    "CRYPTO-001": "MD5 is collision-broken and must not gate integrity, "
                  "signatures or credential storage.",
    "CRYPTO-002": "SHA-1 is collision-broken; chosen-prefix collisions are "
                  "practical, so it cannot protect integrity.",
    "CRYPTO-003": "DES/3DES has a 56-bit effective key and is brute-forced in "
                  "hardware today.",
    "CRYPTO-004": "RC4 keystream biases allow plaintext recovery from captured "
                  "ciphertext.",
    "CRYPTO-005": "ECB encrypts identical plaintext blocks to identical "
                  "ciphertext blocks, leaking structure in the payload.",
    "CRYPTO-008": "random.* is a Mersenne-Twister PRNG seeded predictably; it "
                  "must never produce keys, IVs, tokens or salts.",
    "CRYPTO-009": "A sub-2048-bit RSA modulus (or a <=192-bit curve) is within "
                  "reach of academic factoring and cannot protect long-lived data.",
    "CRYPTO-010": "Certificate validation is disabled or a deprecated TLS "
                  "protocol is pinned, so the transport can be intercepted.",
}

REJECT_NOTES = {
    "CRYPTO-001": "the flagged call does not hash with MD5",
    "CRYPTO-002": "the flagged call does not hash with SHA-1",
    "CRYPTO-003": "the flagged call does not use DES/3DES",
    "CRYPTO-004": "the flagged call does not use RC4",
    "CRYPTO-005": "the flagged call does not use ECB mode",
    "CRYPTO-008": "the flagged call uses a CSPRNG source",
    "CRYPTO-009": "the flagged call meets the minimum key/curve strength",
    "CRYPTO-010": "the flagged call keeps certificate verification enabled",
}


def reject_reason(rule, code):
    """Explain why an up-stream hit is a false positive, grounded in the snippet."""
    if "usedforsecurity=False" in code:
        return ("the digest is explicitly declared non-security "
                "(`usedforsecurity=False`), so no security boundary depends on it")
    if re.search(r"(?i)sha(256|384|512|3)", code):
        return "the flagged call uses a modern hash (SHA-2/SHA-3), not the broken one"
    if re.search(r"\b(AES|ChaCha20)\b", code):
        return "the flagged call uses a modern authenticated cipher, not the broken one"
    if re.search(r"gnutls|modern", code):
        return "the flagged call selects a modern TLS profile, not the deprecated one"
    if re.search(r"_create_default_context|create_default_context|verify\s*=\s*True", code):
        return "the flagged call keeps certificate verification enabled"
    if re.search(r"(?i)SECP(256|384|521)|bits\s*=\s*(2048|3072|4096)|key_size\s*=\s*(2048|3072|4096)", code):
        return "the flagged call meets the minimum key/curve strength"
    if re.search(r"os\.urandom|secrets\.|SystemRandom", code):
        return "the flagged call uses a cryptographically secure entropy source"
    return REJECT_NOTES[rule]


def confirm_explanation(rule):
    return f"{RULE_META[rule]['message']} {CONFIRM_NOTES[rule]}"


def reject_explanation(rule, code):
    return (f"{RULE_META[rule]['message']} However, {reject_reason(rule, code)}. "
            f"The finding is a false positive for this snippet.")


# --- fixture parsing -------------------------------------------------------------
KEYED_ANNOT_RE = re.compile(
    r"^\s*#\s*(deepruleid|ruleid|ok)\s*:\s*([A-Za-z0-9_.\-]+)\s*$")
BARE_OK_RE = re.compile(r"^\s*#\s*ok\s*$")


def strip_annotations(lines):
    kept = [l for l in lines
            if not KEYED_ANNOT_RE.match(l) and not BARE_OK_RE.match(l)]
    return "\n".join(kept).strip("\n")


def parse_annotations(path):
    """Yield (kind, rule_id, lineno) for each keyed annotation in `path`.

    A bare `# ok` inherits the most recently seen rule id (Semgrep convention in
    single-rule fixtures).
    """
    marks = []
    last_rule = None
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        keyed = KEYED_ANNOT_RE.match(line)
        if keyed:
            kind = "ruleid" if keyed.group(1) in ("ruleid", "deepruleid") else "ok"
            last_rule = keyed.group(2)
            marks.append((kind, last_rule, i))
        elif BARE_OK_RE.match(line) and last_rule:
            marks.append(("ok", last_rule, i))
    return marks


def _statements(tree):
    return [n for n in ast.walk(tree) if isinstance(n, ast.stmt)]


def find_statement(tree, lines, mark_lineno):
    """Locate the statement a `# ruleid:`/`# ok:` marker refers to.

    Markers usually sit on the line above the statement, but Semgrep also places
    them *inside* a multi-line call (e.g. before a `key_size=` argument), so the
    smallest enclosing statement is tried first.
    """
    stmts = _statements(tree)
    enclosing = [n for n in stmts
                 if n.lineno <= mark_lineno <= (n.end_lineno or n.lineno)]
    if enclosing:
        return min(enclosing,
                   key=lambda n: ((n.end_lineno or n.lineno) - n.lineno, n.lineno))

    idx = mark_lineno  # 0-based index of the line after the marker
    while idx < len(lines) and (not lines[idx].strip()
                                or lines[idx].lstrip().startswith("#")):
        idx += 1
    if idx >= len(lines):
        return None
    target = idx + 1
    starts = [n for n in stmts if n.lineno == target]
    if starts:
        return max(starts, key=lambda n: (n.end_lineno or n.lineno))
    return None


def snippet_for(tree, lines, node):
    if node is None:
        return None
    raw = lines[node.lineno - 1: node.end_lineno]
    code = textwrap.dedent(strip_annotations(raw)).strip()
    if not code:
        return None
    try:
        ast.parse(code)
    except SyntaxError:
        return None
    return code


def scope_ok(rule, code):
    guard = SCOPE_GUARDS.get(rule)
    if guard and not guard.search(code):
        return False
    if rule == "CRYPTO-008":
        target = code.split("=", 1)[0] if "=" in code else ""
        if not SECURITY_NAME_RE.match(target.strip()):
            return False
    return True


def normalized(code):
    return re.sub(r"\s+", " ", code).strip().lower()


def split_for(text):
    """Deterministic 90/5/5 split keyed on the code itself.

    Keying on the code guarantees identical snippets never straddle splits,
    which is what the R6 builder's leakage check enforces.
    """
    bucket = int(hashlib.sha256(normalized(text).encode()).hexdigest(), 16) % 100
    if bucket < 90:
        return "train"
    if bucket < 95:
        return "val"
    return "test"


def wrap_for_triage(stmt):
    """Present the flagged statement inside a function, as it appears in real code.

    Keeps detect and triage rows for the same statement textually distinct while
    staying syntactically valid.
    """
    body = textwrap.indent(stmt, "    ")
    return f"def process_request():\n{body}"


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:48]


class Emitter:
    def __init__(self):
        self.detect = []
        self.triage = []
        self.seen = set()          # (task, normalized code) -> first wins
        self.skipped = Counter()
        self.idx = Counter()

    def _new_id(self, prefix, key):
        self.idx[key] += 1
        return f"r6-fx-{prefix}-{slug(key)}-{self.idx[key]:02d}"

    def add(self, task, code, label, source, license_, rule, finding=None,
            repo_url="", commit=""):
        dedupe_key = (task, normalized(code))
        if dedupe_key in self.seen:
            self.skipped[f"duplicate-{task}"] += 1
            return
        self.seen.add(dedupe_key)
        prefix = {"detect-pos": "pos", "detect-neg": "neg",
                  "triage-con": "con", "triage-rej": "rej"}[label["_kind"]]
        record = {
            "id": self._new_id(prefix, rule),
            "language": "python",
            "task": task,
            "code": code,
            "label": {k: v for k, v in label.items() if k != "_kind"},
            "source": source,
            "license": license_,
            "repo_url": repo_url,
            "commit": commit,
            "verified": False,
            "split": split_for(code),
            "rule": rule,
        }
        if finding is not None:
            record["finding"] = finding
        (self.detect if task == "detect" else self.triage).append(record)

    def add_pair(self, rule, code, source, license_, repo_url="", commit=""):
        """Emit the detect+triage rows for one annotated statement."""
        if not scope_ok(rule, code):
            self.skipped[f"out-of-scope-{rule}"] += 1
            return
        finding = f"[{rule}] {RULE_META[rule]['message']}"
        cwe = RULE_META[rule]["cwe"]
        severity = RULE_META[rule]["severity"]
        self.add(
            "detect", code,
            {"_kind": "detect-pos", "vulnerable": True, "cwe": cwe,
             "severity": severity, "confidence": "high",
             "explanation": confirm_explanation(rule)},
            source, license_, rule, repo_url=repo_url, commit=commit)
        self.add(
            "triage", wrap_for_triage(code),
            {"_kind": "triage-con", "cwe": cwe, "severity": "WARNING",
             "verdict": "Confirm", "explanation": confirm_explanation(rule)},
            source, license_, rule, finding=finding,
            repo_url=repo_url, commit=commit)

    def add_negative(self, rule, code, source, license_, repo_url="", commit=""):
        if rule_fires(rule, code):
            # Would be a false label: the shipped rule still fires on it.
            self.skipped[f"fires-on-neg-{rule}"] += 1
            return
        if not safe_ok(rule, code):
            # No visible safe substitute; the code is at best "undetected", not
            # demonstrably safe, so it must not be labelled as a negative.
            self.skipped[f"ambiguous-neg-{rule}"] += 1
            return
        finding = f"[{rule}] {RULE_META[rule]['message']}"
        self.add(
            "detect", code,
            {"_kind": "detect-neg", "vulnerable": False, "cwe": "",
             "severity": "", "confidence": "high",
             "explanation": reject_explanation(rule, code)},
            source, license_, rule, repo_url=repo_url, commit=commit)
        self.add(
            "triage", wrap_for_triage(code),
            {"_kind": "triage-rej", "cwe": RULE_META[rule]["cwe"],
             "severity": "WARNING", "verdict": "Reject",
             "explanation": reject_explanation(rule, code)},
            source, license_, rule, finding=finding,
            repo_url=repo_url, commit=commit)


def convert_semgrep(emitter):
    """Walk every Semgrep python fixture with a mapped `ruleid:` annotation."""
    processed = 0
    for path in sorted(SEMGREP_PY.rglob("*.py")):
        if path.name.endswith(".fixed.py"):
            continue
        marks = parse_annotations(path)
        mapped = [(k, r, ln) for (k, r, ln) in marks
                  if r in SEMGREP_RULE_TO_CRYPTO]
        if not mapped:
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        tree = ast.parse("\n".join(lines))
        ruleid_marks = [(r, ln) for (k, r, ln) in mapped if k == "ruleid"]
        for rule_id, lineno in ruleid_marks:
            rule = SEMGREP_RULE_TO_CRYPTO[rule_id]
            node = find_statement(tree, lines, lineno)
            code = snippet_for(tree, lines, node)
            if not code:
                emitter.skipped["unparsed-snippet"] += 1
                continue
            emitter.add_pair(rule, code, "semgrep-rule-fixture", SEMGREP_LICENSE,
                             repo_url="https://github.com/semgrep/semgrep-rules")
            processed += 1
        for rule_id, lineno in [(r, ln) for (k, r, ln) in mapped if k == "ok"]:
            rule = SEMGREP_RULE_TO_CRYPTO[rule_id]
            code = snippet_for(tree, lines, find_statement(tree, lines, lineno))
            if not code:
                emitter.skipped["unparsed-snippet"] += 1
                continue
            # Only keep an `ok` line as a Reject when the snippet is really a
            # different (safe) form; identical code is deduped downstream.
            emitter.add_negative(rule, code, "semgrep-rule-fixture", SEMGREP_LICENSE,
                                 repo_url="https://github.com/semgrep/semgrep-rules")
            processed += 1
    return processed


# --- Bandit examples -------------------------------------------------------------
# Bandit's functional tests assert issue counts, not line numbers, so these files
# are converted with an explicit statement matcher instead of annotations.
BANDIT_PLACEHOLDER_RENAME = {"bad": "session_token", "good": "session_token"}

BANDIT_RANDOM_OK = {"SystemRandom"}


def rename_placeholder(code):
    out = code
    for old, new in BANDIT_PLACEHOLDER_RENAME.items():
        out = re.sub(rf"^\s*{old}\s*=", f"{new} =", out)
    return out


def bandit_statements(path, tree):
    """Every top-level/expression call statement in a Bandit example."""
    stmts = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.Expr)):
            value = node.value if isinstance(node, ast.Assign) else node.value
            if isinstance(value, ast.Call):
                text = ast.unparse(node)
                stmts.append((node, text))
    return stmts


def convert_bandit(emitter):
    processed = 0
    repo = "https://github.com/PyCQA/bandit"

    def unparse_call(node):
        return ast.unparse(node.value)

    def load(name):
        path = BANDIT_EXAMPLES / name
        if not path.exists():
            return None, None, None
        lines = path.read_text(encoding="utf-8").splitlines()
        return path, lines, ast.parse("\n".join(lines))

    def emit_statements(name, classify):
        nonlocal processed
        path, lines, tree = load(name)
        if tree is None:
            emitter.skipped[f"missing-bandit-{name}"] += 1
            return
        for node, text in bandit_statements(path, tree):
            verdict = classify(unparse_call(node))
            if verdict is None:
                continue
            rule, positive = verdict
            code = snippet_for(tree, lines, node)
            if not code:
                emitter.skipped["unparsed-bandit-snippet"] += 1
                continue
            code = rename_placeholder(code)
            if positive:
                emitter.add_pair(rule, code, "bandit-rule-fixture", BANDIT_LICENSE,
                                 repo_url=repo)
            else:
                emitter.add_negative(rule, code, "bandit-rule-fixture",
                                     BANDIT_LICENSE, repo_url=repo)
            processed += 1

    def classify_random(call):
        m = re.match(r"^random\.(\w+)\(", call)
        if m:
            name = m.group(1)
            if name in BANDIT_RANDOM_OK:
                return ("CRYPTO-008", False)
            # Only the shipped CRYPTO-008 function set produces positives; the
            # extra Bandit cases (Random/choices/randbytes) are real weaknesses
            # but outside the detector's metacoverage and are skipped.
            if name in CRYPTO008_FUNCS:
                return ("CRYPTO-008", True)
        if re.match(r"^(os\.urandom|secrets\.\w+)\(", call):
            return ("CRYPTO-008", False)
        return None

    def classify_hashlib_new(call):
        if "usedforsecurity=False" in call:
            return ("CRYPTO-001", False)
        m = re.match(r"^hashlib\.new\(\s*(?:name\s*=\s*)?['\"]([A-Za-z0-9]+)['\"]", call)
        if not m:
            return None
        algo = m.group(1).lower()
        if algo in ("md5", "md4", "md2"):
            return ("CRYPTO-001", True)
        if algo in ("sha1", "sha"):
            return ("CRYPTO-002", True)
        if algo in ("sha256", "sha512", "sha384", "sha3_256"):
            return ("CRYPTO-001", False)
        return None

    def classify_requests(call):
        m = re.match(r"^requests\.(\w+)\(", call)
        if not m:
            return None
        if re.search(r"verify\s*=\s*False", call):
            return ("CRYPTO-010", True)
        if re.search(r"verify\s*=\s*True", call):
            return ("CRYPTO-010", False)
        return None

    def classify_keysize(call):
        if re.search(r"(key_size|bits)\s*=\s*(512|768|1024)\b", call):
            return ("CRYPTO-009", True)
        if re.search(r"(key_size|bits)\s*=\s*(2048|3072|4096)\b", call):
            return ("CRYPTO-009", False)
        if re.search(r"SECT163", call):
            return ("CRYPTO-009", True)
        if re.search(r"SECP(256|384|521)", call):
            return ("CRYPTO-009", False)
        return None

    def classify_ssl(call):
        if re.search(r"ssl\.(PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_TLSv1"
                     r"|PROTOCOL_TLSv1_1)", call):
            return ("CRYPTO-010", True)
        return None

    emit_statements("random_module.py", classify_random)
    emit_statements("hashlib_new_insecure_functions.py", classify_hashlib_new)
    emit_statements("requests-ssl-verify-disabled.py", classify_requests)
    emit_statements("weak_cryptographic_key_sizes.py", classify_keysize)
    emit_statements("ssl-insecure-version.py", classify_ssl)
    return processed


def report(emitter):
    d = emitter.detect
    t = emitter.triage
    print("=" * 72)
    print("RULE-FIXTURE CONVERSION REPORT")
    print("=" * 72)
    print(f"detect: {len(d)}  (pos={sum(1 for r in d if r['label']['vulnerable'])} "
          f"neg={sum(1 for r in d if not r['label']['vulnerable'])})")
    print(f"triage: {len(t)}  (Confirm={sum(1 for r in t if r['label']['verdict']=='Confirm')} "
          f"Reject={sum(1 for r in t if r['label']['verdict']=='Reject')})")
    print("\nby rule (detect/triage):")
    for rule in sorted(RULE_META):
        nd = sum(1 for r in d if r["rule"] == rule)
        nt = sum(1 for r in t if r["rule"] == rule)
        if nd or nt:
            print(f"  {rule}: {nd}/{nt}")
    print("\nby split:")
    for split in ("train", "val", "test"):
        print(f"  {split}: detect={sum(1 for r in d if r['split']==split)} "
              f"triage={sum(1 for r in t if r['split']==split)}")
    print("\nby source:")
    for src, n in sorted(Counter([r["source"] for r in d + t]).items()):
        print(f"  {src}: {n}")
    print("\nskipped candidates:")
    for key, n in sorted(emitter.skipped.items()):
        print(f"  {key}: {n}")
    print("\ntriage rows carrying a paired fix patch: 0 (fixture patches are not trusted)")


def emit_files(emitter):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, rows in (("rule_fixture_detect.jsonl", emitter.detect),
                       ("rule_fixture_triage.jsonl", emitter.triage)):
        path = OUT_DIR / name
        with path.open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"[+] {path}: {len(rows)} records")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--emit", action="store_true", help="write the JSONL outputs")
    args = ap.parse_args()

    emitter = Emitter()
    n_semgrep = convert_semgrep(emitter)
    n_bandit = convert_bandit(emitter)
    report(emitter)
    print(f"\nannotated statements converted: semgrep={n_semgrep} bandit={n_bandit}")
    print("\n[WARN] Fixture rows are rule-regression data, not verified real-world "
          "findings. Keep them out of real_verified_*.jsonl.")
    print("[WARN] Semgrep fixture rows carry the Semgrep Rules License v1.0; drop "
          "them from any externally redistributed dataset if that license applies.")

    if args.emit:
        emit_files(emitter)
    else:
        print("\n(dry run: pass --emit to write data/round6/rule_fixture_*.jsonl)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
