#!/usr/bin/env python3
"""Second-pass screen of the real-crypto candidate pool.

This is a read-only triage layer between ``harvest_real_crypto_candidates.py``
and ``audit_real_crypto_with_llm.py``. It does **not** create labels and never
touches ``verified``: a candidate stays ``verified=false`` no matter how high it
scores. The score only decides what deserves scarce model/human review time.

What it does:

1. Merges every local candidate pool (watchlist, GHSA, OSV/PyPI, PyPA,
   PyCode-Vul, broad, enriched, functions) plus compatible JSON/JSONL records
   discovered under ``data/``. The generic local adapter normalizes common
   field aliases and preserves source-file provenance. Datasets that need a
   dedicated harvester (advisory mirrors, rule fixtures, project source trees)
   are excluded by policy instead of being partially re-parsed here.
2. Deduplicates by advisory id, by repo+commit+file, and by normalized
   vulnerable code.
3. Scores evidence strength (fix commit, code pair, production vs test file,
   crypto-API relevance, concrete CVE, watchlist package).
4. Caps advisory-less rows at P3: without an advisory/CVE they can never reach
   A-class, so they must not consume P1/P2 review time. A *model-predicted*
   CWE/CVE (PyCode-Vul) is not an advisory, so it is capped at P2 and flagged
   for a manual NVD/GHSA trace.
5. Splits P3 into ``p3_stock`` (finding/Reject stock) and ``p3_volume``
   (parseable, production, real vulnerable/fixed code pairs without an advisory
   -- B-class training volume, never A-class).
6. Buckets candidates into P1 (review first), P2 (review if time), P3 and
   writes a ranked JSONL plus a stats JSON. Follow-up queues:
   ``need_code`` (has a fix commit, needs the diff fetched), ``no_commit``
   (no commit at all, needs a manual advisory / PyPI-version trace),
   ``predicted_cve`` (model-predicted id, verify against NVD/GHSA) and
   ``volume`` (advisory-less but usable paired code).

Nothing here calls the network or any paid API.

Usage:
    python3 scripts/screen_real_crypto_candidates.py
    python3 scripts/screen_real_crypto_candidates.py --emit
"""
import argparse
import ast
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.build_round6_final_dataset import RULE_CWE, TARGET_CWES  # noqa: E402
from scripts.audit_real_crypto_with_llm import (  # noqa: E402
    build_messages,
    estimate_tokens,
)

CAND_DIR = ROOT / "data" / "round6" / "candidates"
DEFAULT_POOLS = [
    CAND_DIR / "real_crypto_candidates.jsonl",
    CAND_DIR / "real_crypto_candidates_ghsa.jsonl",
    CAND_DIR / "real_crypto_candidates_osv_pypi.jsonl",
    CAND_DIR / "real_crypto_candidates_pypa.jsonl",
    CAND_DIR / "real_crypto_candidates_pycode_vul.jsonl",
    CAND_DIR / "real_crypto_candidates_broad.jsonl",
    CAND_DIR / "real_crypto_candidates_enriched.jsonl",
    CAND_DIR / "real_crypto_candidates_functions.jsonl",
]
DEFAULT_OUT = CAND_DIR / "real_crypto_candidates_screened.jsonl"
DEFAULT_REVIEW = CAND_DIR / "real_crypto_candidates_review_queue.jsonl"
DEFAULT_TODO = CAND_DIR / "real_crypto_candidates_need_code.jsonl"
DEFAULT_NOCOMMIT = CAND_DIR / "real_crypto_candidates_no_commit.jsonl"
DEFAULT_PREDICTED = CAND_DIR / "real_crypto_candidates_predicted_cve.jsonl"
DEFAULT_VOLUME = CAND_DIR / "real_crypto_candidates_volume.jsonl"
DEFAULT_LOCAL_OUT = CAND_DIR / "real_crypto_candidates_local.jsonl"
DEFAULT_STATS = ROOT / "reports" / "data_quality" / "candidate_screen_stats.json"
DEFAULT_LOCAL_ROOTS = [ROOT / "data"]

# The generic local adapter is deliberately narrower than "parse every JSON".
# These trees either already have a dedicated harvester/converter or contain
# generated training/evaluation data that must not be recycled as fresh
# evidence. New datasets added under another data/ subdirectory are discovered.
LOCAL_EXCLUDED_PARTS = {
    ".git",
    "advisory-database", "osv-pypi", "pypa-advisory-database",
    "semgrep-rules", "trailofbits-semgrep-rules", "bandit",
    "real_projects", "candidates", "validation", "validation_frozen",
    "final", "eval", "upload", "splits", "sft", "processed",
    "expanded", "round2", "round3", "round5",
}
LOCAL_EXCLUDED_NAMES = {
    "backtest_report.json", "backtest_report.jsonl",
    "negative_source.jsonl", "preview_negatives.jsonl",
}
LOCAL_JSON_SUFFIXES = {".json", ".jsonl"}
LOCAL_CONTAINER_KEYS = (
    "records", "items", "findings", "results", "data", "samples",
)
LOCAL_CODE_KEYS = (
    "code_vuln", "vulnerable_code", "vulnerable_function_source",
    "vulnerable_function", "func_before", "function_before", "code_before",
    "before_code", "old_code", "vuln_code", "snippet", "source_code",
    "function_source", "code", "function",
)
LOCAL_FIXED_KEYS = (
    "code_fixed", "fixed_code", "patched_function_source", "patch",
    "patched_function", "func_after", "function_after", "code_after",
    "after_code", "new_code", "fixed_source",
)
LOCAL_REPO_KEYS = (
    "repo_url", "repository_url", "project_url", "repository", "repo",
)
LOCAL_FILE_KEYS = (
    "file_path", "filepath", "filename", "file_name", "relative_path",
    "file", "path",
)
LOCAL_COMMIT_KEYS = (
    "fix_commit", "fixed_commit", "fixed_commit_hash", "fixing_commit",
    "commit_hash", "commit", "vuln_commit",
)
LOCAL_ADVISORY_KEYS = (
    "advisory_id", "ghsa_id", "osv_id", "advisory",
)
LOCAL_CVE_KEYS = (
    "cve_id", "cve", "cve_ids", "cve_number",
)
LOCAL_CWE_KEYS = (
    "cwe", "cwe_id", "cwe_ids", "cwe_all", "predicted_cwe_ids",
)
LOCAL_LANGUAGE_KEYS = (
    "language", "lang", "programming_language",
)
LOCAL_RULE_KEYS = (
    "rule", "rule_id",
)
LOCAL_SYNTHETIC_SOURCE_PREFIXES = (
    "round4-exp", "round4-negative", "round4-pos", "round4-neg",
    "round5-", "round6-",
    "semgrep-rule-fixture", "bandit-rule-fixture",
)

# Watchlist packages: crypto-relevant Python ecosystem names from the harvester.
WATCHLIST = {
    "cryptography", "pycryptodome", "pycryptodomex", "pyjwt", "python-jose",
    "paramiko", "requests", "urllib3", "django", "passlib", "python-rsa",
    "rsa", "itsdangerous", "pyopenssl", "ecdsa", "pynacl", "argon2-cffi",
    "bcrypt", "scrypt", "authlib", "josepy", "certifi", "tornado", "aiohttp",
    "flask", "werkzeug", "oauthlib", "fido2",
}

# Coarse CWE -> rule hint, mirroring fetch_fix_code.py. CWE-327/326 stay empty:
# they map to several rules and need a human to pick the right one.
CWE_RULE_HINT = {
    "CWE-329": "CRYPTO-006",
    "CWE-321": "CRYPTO-007",
    "CWE-338": "CRYPTO-008",
    "CWE-256": "CRYPTO-011",
    "CWE-916": "CRYPTO-012",
    "CWE-208": "CRYPTO-013",
    "CWE-295": "CRYPTO-010",
}

# Local CWE taxonomy (data/raw/cwe/cwe_database.json). Advisory mirrors disagree
# about where the CWE lives -- GHSA often fills only ``cwe_all`` -- so this is
# used to (a) resolve a primary CWE and (b) label adjacent CWEs in the report.
CWE_DB_PATH = ROOT / "data" / "raw" / "cwe" / "cwe_database.json"


def load_cwe_db():
    try:
        raw = json.loads(CWE_DB_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if not isinstance(value, dict):
                continue
            cid = str(value.get("id") or key).strip().upper()
            if cid:
                out[cid] = value
    return out


CWE_DB = load_cwe_db()


def resolve_cwe(row):
    """Best available CWE for a row: explicit field, else first ``cwe_all`` hit.

    GHSA rows frequently carry a populated ``cwe_all`` list but an empty
    ``cwe``, while OSV/PyPA put the primary id in ``cwe``. Resolving through
    ``cwe_all`` keeps target-CWE rows from silently scoring as unknown.
    """
    explicit = str(row.get("cwe") or "").strip().upper()
    if explicit:
        return explicit
    all_cwes = [
        str(c).strip().upper()
        for c in (row.get("cwe_all") or [])
        if str(c).strip()
    ]
    for cwe in all_cwes:
        if cwe in TARGET_CWES:
            return cwe
    return all_cwes[0] if all_cwes else ""


def cwe_name(cwe):
    entry = CWE_DB.get(cwe) or {}
    return str(entry.get("name") or "").strip()


TEST_PATH = re.compile(
    r"(^|/)(tests?|testing|testdata|test_data|fixtures?|examples?|docs?|"
    r"benchmarks?|samples?)(/|$)|(^|/)test_[^/]*\.py$|(^|/)[^/]*_test\.py$",
    re.IGNORECASE,
)
CONFTEST = re.compile(r"(^|/)conftest\.py$", re.IGNORECASE)

CRYPTO_API = re.compile(
    r"\b(hashlib|hmac|secrets|ssl|pyjwt|jwt|cryptography|Crypto|Cryptodome|"
    r"pycryptodome|passlib|rsa|ecdsa|nacl|bcrypt|argon2|Fernet|AES|DES|"
    r"MD5|SHA1|sha1|md5|random|urandom|getrandbits|Token|JWT|verify|"
    r"certificate|cert_verify|verify_mode|check_hostname|load_pem|"
    r"salt|nonce|iv|key|token|signature|encrypt|decrypt)\b"
)
WEAK_PRIMITIVE = re.compile(r"\b(md5|sha1|random\.|Random\(|ECB|DES|RC4|"
                            r"unverified|verify=False|check_hostname=False)\b")

CODE_LINE_FLOOR = 4
CODE_LINE_CEILING = 120


def load_jsonl(path: Path):
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def first_value(record, keys):
    """Return the first non-empty scalar/list field under ``keys``."""
    for key in keys:
        value = record.get(key)
        if isinstance(value, (list, tuple)):
            value = next((v for v in value if v not in (None, "")), "")
        if value not in (None, "", [], {}):
            return value
    return ""


def as_list(value):
    if value in (None, "", [], {}):
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def nested_value(record, parent, keys):
    value = record.get(parent)
    if not isinstance(value, dict):
        return ""
    return first_value(value, keys)


def strip_code_line_prefixes(code: str) -> str:
    """Remove ``NN: `` display prefixes used by the Round-4 finding export."""
    lines = (code or "").splitlines()
    nonempty = [line for line in lines if line.strip()]
    prefixed = [
        line for line in nonempty
        if re.match(r"^\s*\d+\s*:\s?", line)
    ]
    if not prefixed or len(prefixed) < max(1, len(nonempty) // 2):
        return code or ""
    return "\n".join(re.sub(r"^\s*\d+\s*:\s?", "", line) for line in lines)


def normalize_repo(record):
    """Return ``(repo_url, package)`` without inventing a GitHub URL."""
    raw = str(first_value(record, LOCAL_REPO_KEYS) or "").strip()
    package = str(record.get("package") or "").strip()
    if raw.startswith(("http://", "https://")):
        return raw, package
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", raw):
        return f"https://github.com/{raw}", package
    if raw and not package:
        package = raw
    return "", package


def normalize_local_file_path(file_path: str, package: str) -> str:
    path = (file_path or "").replace("\\", "/")
    prefix = f"data/round4/real_projects/{package}/"
    if package and path.startswith(prefix):
        return path[len(prefix):]
    return path


def collect_cwe_strings(value):
    values = []
    for item in as_list(value):
        text = str(item)
        matches = re.findall(r"\bCWE[-\s]?(\d{1,4})\b", text, re.IGNORECASE)
        if matches:
            for match in matches:
                cwe = f"CWE-{int(match):03d}"
                if cwe not in values:
                    values.append(cwe)
            continue
        for part in re.split(r"[;,|]", text):
            cwe = part.strip().upper()
            if not cwe:
                continue
            if re.fullmatch(r"\d{1,4}", cwe):
                cwe = f"CWE-{int(cwe):03d}"
            if cwe not in values:
                values.append(cwe)
    return values


def collect_local_cwes(record, rule):
    values = []
    for key in LOCAL_CWE_KEYS:
        values.extend(collect_cwe_strings(record.get(key)))
    for parent in ("label", "labels", "metadata", "vulnerability", "problem"):
        nested = record.get(parent)
        if not isinstance(nested, dict):
            continue
        for key in LOCAL_CWE_KEYS:
            values.extend(collect_cwe_strings(nested.get(key)))
    out = list(dict.fromkeys(values))
    if rule in RULE_CWE:
        for cwe in sorted(RULE_CWE[rule]):
            if cwe not in out:
                out.insert(0, cwe)
    return out


def local_record_is_control(record) -> bool:
    label = record.get("label")
    label = label if isinstance(label, dict) else {}
    verdict = str(label.get("verdict") or record.get("verdict") or "").lower()
    vulnerable = label.get("vulnerable", record.get("vulnerable"))
    return vulnerable is False or verdict in {"reject", "false", "negative"}


def iter_json_records(path: Path):
    """Yield ``(record, locator)`` from JSON containers or JSONL files."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return

    if path.suffix.lower() == ".jsonl":
        for lineno, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                yield from _iter_json_obj(json.loads(line), f"line:{lineno}")
            except json.JSONDecodeError:
                continue
        return

    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return
    yield from _iter_json_obj(obj, "root")


def _iter_json_obj(obj, locator):
    if isinstance(obj, list):
        for index, item in enumerate(obj):
            yield from _iter_json_obj(item, f"{locator}[{index}]")
        return
    if not isinstance(obj, dict):
        return
    found_container = False
    for key in LOCAL_CONTAINER_KEYS:
        value = obj.get(key)
        if isinstance(value, list):
            found_container = True
            for index, item in enumerate(value):
                yield from _iter_json_obj(item, f"{locator}.{key}[{index}]")
        elif isinstance(value, dict) and value is not obj:
            found_container = True
            for child_key, item in value.items():
                yield from _iter_json_obj(item, f"{locator}.{key}.{child_key}")
    if not found_container:
        yield obj, locator


def local_source_label(path: Path, record) -> str:
    rel = path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path)
    if rel == "data/round4/real_findings.jsonl":
        return "round4-real-findings"
    explicit = str(record.get("source") or "").strip()
    if explicit:
        return explicit
    return rel.rsplit("/", 1)[0].replace("/", "-")


def local_path_is_excluded(path: Path) -> bool:
    rel_parts = (
        path.relative_to(ROOT).parts
        if path.is_relative_to(ROOT)
        else path.parts
    )
    return (
        any(part in LOCAL_EXCLUDED_PARTS for part in rel_parts)
        or path.name in LOCAL_EXCLUDED_NAMES
    )


def adapt_local_record(record, path: Path, locator: str):
    """Normalize one compatible local record; return ``None`` when out of scope."""
    if not isinstance(record, dict):
        return None, "not-object"
    if "messages" in record and "code" not in record:
        return None, "chat-message"
    if local_record_is_control(record):
        return None, "control-row"

    source_label = local_source_label(path, record)
    if source_label.lower().startswith(LOCAL_SYNTHETIC_SOURCE_PREFIXES):
        return None, "synthetic-source"

    code_vuln = strip_code_line_prefixes(
        str(first_value(record, LOCAL_CODE_KEYS) or "")
    ).strip()
    if not code_vuln:
        return None, "no-code"
    code_fixed = strip_code_line_prefixes(
        str(first_value(record, LOCAL_FIXED_KEYS) or "")
    ).strip()

    rule = str(first_value(record, LOCAL_RULE_KEYS) or "").strip().upper()
    cwes = collect_local_cwes(record, rule)
    if not rule and not cwes:
        return None, "no-crypto-taxonomy"
    if rule not in RULE_CWE and not (set(cwes) & TARGET_CWES):
        return None, "outside-taxonomy"

    repo_url, package = normalize_repo(record)
    file_path = normalize_local_file_path(
        str(first_value(record, LOCAL_FILE_KEYS) or ""), package)
    language = str(
        first_value(record, LOCAL_LANGUAGE_KEYS) or ""
    ).strip().lower()
    if language and not (
        language == "py" or language.startswith("python")
    ):
        return None, "non-python-language"
    suffix = Path(file_path).suffix.lower() if file_path else ""
    if not language and suffix and suffix not in {".py", ".pyi"}:
        return None, "non-python-file"
    fix_commit = str(first_value(
        record, ("fix_commit", "fixed_commit")) or "").strip()
    vuln_commit = str(first_value(
        record, ("vuln_commit", "vulnerable_commit")) or "").strip()
    advisory_id = str(first_value(record, LOCAL_ADVISORY_KEYS) or "").strip()
    cve_id = str(first_value(record, LOCAL_CVE_KEYS) or "").strip()
    original_id = str(record.get("id") or record.get("candidate_id") or "").strip()
    provenance = (
        f"{path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else path}"
        f"#{locator}"
    )
    digest = hashlib.sha1(
        f"{source_label}|{provenance}|{repo_url}|{rule}|{file_path}|"
        f"{norm_code(code_vuln)}".encode("utf-8")
    ).hexdigest()[:12]

    reasons = [
        f"local-json:{source_label}",
        f"local-source:{provenance}",
        "real-single-side-finding",
    ]
    if rule:
        reasons.append(f"local-rule:{rule}")
    if not advisory_id and not cve_id:
        reasons.append("no advisory/CVE -> stock only")
    if not fix_commit:
        reasons.append("no fix commit -> no vuln/fixed pair")

    return {
        "candidate_id": f"local-{digest}",
        "source": source_label,
        "advisory_id": advisory_id,
        "cve_id": cve_id,
        "package": package,
        "repo_url": repo_url,
        "vuln_commit": vuln_commit,
        "fix_commit": fix_commit,
        "affected_versions": str(record.get("affected_versions") or ""),
        "fixed_version": str(record.get("fixed_version") or ""),
        "file_path": file_path,
        "function_name": str(first_value(
            record, ("function_name", "function", "name")) or ""),
        "cwe": cwes[0] if cwes else "",
        "cwe_all": cwes,
        "match_reasons": reasons,
        "rule_id": rule,
        "code_vuln_url": "",
        "code_fixed_url": "",
        "notification_url": "",
        "code_vuln": code_vuln,
        "code_fixed": code_fixed,
        "static_finding": str(record.get("finding") or ""),
        "preliminary_class": "B",
        "human_verdict": "",
        "verified": False,
        "verified_by": "",
        "license": str(record.get("license") or "unknown"),
        "collected_at": str(record.get("collected_at") or ""),
        "split": "",
        "local_source_path": (
            path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path)
        ),
        "local_source_locator": locator,
        "local_original_id": original_id,
    }, ""


def load_local_json_candidates(roots):
    """Scan compatible local JSON/JSONL records and report every skip reason."""
    stats = Counter()
    adapted = []
    seen_ids = set()
    paths = []
    for root in roots:
        root = root if root.is_absolute() else ROOT / root
        if root.is_file():
            candidates = [root] if root.suffix.lower() in LOCAL_JSON_SUFFIXES else []
        elif root.exists():
            candidates = []
            for dirpath, dirnames, filenames in os.walk(root):
                kept_dirs = [
                    name for name in dirnames if name not in LOCAL_EXCLUDED_PARTS
                ]
                stats["directories_pruned_by_policy"] += len(dirnames) - len(kept_dirs)
                dirnames[:] = sorted(kept_dirs)
                for name in sorted(filenames):
                    path = Path(dirpath) / name
                    if path.suffix.lower() in LOCAL_JSON_SUFFIXES:
                        candidates.append(path)
        else:
            continue
        for path in candidates:
            if not path.is_file():
                continue
            stats["files_seen"] += 1
            if local_path_is_excluded(path):
                stats["files_excluded_by_policy"] += 1
                continue
            paths.append(path)
            stats["files_scanned"] += 1
            for record, locator in iter_json_records(path):
                stats["records_seen"] += 1
                row, reason = adapt_local_record(record, path, locator)
                if row is None:
                    stats[f"skipped_{reason}"] += 1
                    continue
                if row["candidate_id"] in seen_ids:
                    stats["skipped_duplicate-in-local-scan"] += 1
                    continue
                seen_ids.add(row["candidate_id"])
                adapted.append(row)
                stats["adapted"] += 1
    ranked_stats = {
        "files_seen": stats["files_seen"],
        "files_scanned": stats["files_scanned"],
        "files_excluded_by_policy": stats["files_excluded_by_policy"],
        "directories_pruned_by_policy": stats["directories_pruned_by_policy"],
        "records_seen": stats["records_seen"],
        "adapted": stats["adapted"],
        "skipped": {
            key.removeprefix("skipped_"): value
            for key, value in sorted(stats.items())
            if key.startswith("skipped_")
        },
        "inputs": [
            str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)
            for path in paths
        ],
    }
    return adapted, ranked_stats


def get(record, *keys):
    for key in keys:
        value = record.get(key)
        if value:
            return value
    return ""


def norm_code(code: str) -> str:
    return re.sub(r"\s+", " ", code or "").strip().lower()


def code_digest(code: str) -> str:
    return hashlib.sha256(norm_code(code).encode("utf-8")).hexdigest() if code else ""


def parses_as_python(code: str) -> bool:
    if not (code or "").strip():
        return False
    try:
        ast.parse(code or "")
        return True
    except (SyntaxError, ValueError):
        return False


def classify_path(file_path: str):
    """Return ('test'|'conftest'|'production') for a changed file path."""
    path = (file_path or "").replace("\\", "/")
    if not path:
        return "unknown"
    if CONFTEST.search(path):
        return "conftest"
    if TEST_PATH.search(path):
        return "test"
    return "production"


def merge_records(records):
    """Merge candidate records by candidate_id, preferring rows that carry code."""
    merged = {}
    order = []
    for row in records:
        if not isinstance(row, dict):
            continue
        cid = row.get("candidate_id")
        if not cid:
            continue
        if cid not in merged:
            merged[cid] = dict(row)
            order.append(cid)
            continue
        current = merged[cid]
        # Enriched rows win: they carry code_vuln/code_fixed/file_path.
        if len(json.dumps(row)) > len(json.dumps(current)):
            preserved = {k: v for k, v in current.items() if v and not row.get(k)}
            merged[cid] = {**preserved, **row}
    return [merged[cid] for cid in order]


def merge_pools(paths):
    """Load and merge candidate pool files by candidate_id."""
    return merge_records(
        row
        for path in paths
        for row in load_jsonl(path)
    )


def has_code_pair(row) -> bool:
    return bool((row.get("code_vuln") or "").strip()
                and (row.get("code_fixed") or "").strip())


def is_model_predicted(row) -> bool:
    """True when the only label signal is a model/dataset prediction.

    PyCode-Vul rows carry ``predicted_cwe_ids`` and sometimes a carried-over
    ``cve_ids`` string. Neither is an advisory: there is no GHSA/PYSEC record
    behind it, so it must never be ranked like an advisory-backed candidate.
    """
    for reason in row.get("match_reasons") or []:
        text = str(reason)
        if text.startswith("pycode-vul:") or text.startswith("predicted:"):
            return True
    return False


def is_volume_candidate(row) -> bool:
    """Real, parseable, production vulnerable/fixed pair with no advisory.

    These cannot reach A-class (the evidence chain is missing the advisory), but
    they are still usable B-class training volume: the code pair is real and
    both sides parse, so no function rebuild is needed. Emitting them
    separately keeps them out of the scarce P1/P2 model-review budget.
    """
    if not get(row, "fix_commit"):
        return False
    if not has_code_pair(row):
        return False
    if classify_path(get(row, "file_path")) != "production":
        return False
    return parses_as_python(row.get("code_vuln") or "") and parses_as_python(
        row.get("code_fixed") or "")


def row_keys(row):
    """Identity keys that make two rows the same finding."""
    keys = []
    advisory = get(row, "advisory_id", "cve_id")
    if advisory:
        keys.append(("advisory", advisory))
    repo = get(row, "repo_url")
    commit = get(row, "fix_commit", "vuln_commit")
    if repo and commit:
        keys.append(("commit", (repo, commit, get(row, "file_path"))))
    digest = code_digest(row.get("code_vuln") or "")
    if digest:
        keys.append(("code", digest))
    return keys


def dedupe(records):
    """Collapse rows that describe the same finding, keeping the strongest one.

    Two rows are the same finding when they share an advisory/CVE id, a
    repo+commit+file triple, or the same normalized vulnerable code. Rows are
    clustered transitively (union-find) and each cluster keeps its
    row that already carries a code pair, breaking ties on score. The code pair
    is the scarcer asset: two mirror rows for the same advisory may both score
    well, but only the enriched one has ``code_vuln``/``code_fixed``, so it must
    win the cluster or a rebuild result is silently thrown away.
    """
    parent = list(range(len(records)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        root_i, root_j = find(i), find(j)
        if root_i != root_j:
            parent[root_j] = root_i

    buckets = {}
    for i, row in enumerate(records):
        for key in row_keys(row):
            if key in buckets:
                union(buckets[key], i)
            else:
                buckets[key] = i

    clusters = {}
    for i in range(len(records)):
        clusters.setdefault(find(i), []).append(i)

    kept, dropped = [], []
    for members in clusters.values():
        if len(members) == 1:
            kept.append(records[members[0]])
            continue
        best = max(members, key=lambda i: (
            has_code_pair(records[i]), score_candidate(records[i])[0]))
        dropped.extend(
            (records[i].get("candidate_id", "?"),
             f"duplicate of {records[best].get('candidate_id', '?')}")
            for i in members if i != best
        )
        kept.append(records[best])
    return kept, dropped


def score_candidate(row):
    """Return (score, tier, reasons) for one candidate. Higher is better."""
    score, reasons = 0, []
    code_vuln = row.get("code_vuln") or ""
    code_fixed = row.get("code_fixed") or ""
    file_path = get(row, "file_path")
    path_kind = classify_path(file_path)

    if get(row, "fix_commit"):
        score += 3
        reasons.append("+3 fix_commit")
    if code_vuln.strip() and code_fixed.strip():
        score += 4
        reasons.append("+4 vulnerable/fixed pair")
        if parses_as_python(code_vuln) and parses_as_python(code_fixed):
            score += 2
            reasons.append("+2 both sides parse as Python")
        else:
            score -= 3
            reasons.append("-3 diff fragment does not parse (needs function rebuild)")
    if code_vuln.strip():
        lines = [l for l in code_vuln.splitlines() if l.strip()]
        if CODE_LINE_FLOOR <= len(lines) <= CODE_LINE_CEILING:
            score += 2
            reasons.append(f"+2 code size {len(lines)}")
        elif len(lines) < CODE_LINE_FLOOR:
            score -= 2
            reasons.append(f"-2 snippet too small ({len(lines)})")
        else:
            score -= 1
            reasons.append(f"-1 snippet large ({len(lines)})")
    if path_kind == "production":
        score += 3
        reasons.append("+3 production file")
    elif path_kind in ("test", "conftest"):
        score -= 4
        reasons.append(f"-4 {path_kind} file")
    if CRYPTO_API.search(code_vuln + "\n" + code_fixed):
        score += 2
        reasons.append("+2 crypto API present")
    if WEAK_PRIMITIVE.search(code_vuln):
        score += 2
        reasons.append("+2 weak primitive in vuln code")
    if get(row, "cve_id"):
        score += 2
        reasons.append("+2 concrete CVE")
    if (row.get("package") or "").lower() in WATCHLIST:
        score += 1
        reasons.append("+1 watchlist package")
    match_reasons = row.get("match_reasons") or []
    resolved_cwe = resolve_cwe(row)
    if resolved_cwe in TARGET_CWES:
        score += 2
        if (row.get("cwe") or "").strip():
            reasons.append("+2 target CWE")
        else:
            reasons.append(f"+2 target CWE (resolved from cwe_all: {resolved_cwe})")
    elif resolved_cwe:
        score += 1
        reasons.append(
            f"+1 adjacent CWE {resolved_cwe} (not in shipped taxonomy)")
    if any(r.startswith("keyword:") for r in match_reasons):
        score += 1
        reasons.append("+1 crypto keyword in advisory text")
    if row.get("patch_truncated"):
        score -= 3
        reasons.append("-3 patch truncated")
    if not get(row, "rule_id"):
        hint = CWE_RULE_HINT.get(resolved_cwe, "")
        if hint:
            reasons.append(f"rule hint {hint}")
        elif resolved_cwe in TARGET_CWES:
            reasons.append("rule unresolved (coarse CWE needs a human pick)")
        elif resolved_cwe:
            reasons.append(f"cwe {resolved_cwe} outside the shipped taxonomy")

    advisory_id = get(row, "advisory_id")
    cve_id = get(row, "cve_id")
    predicted = is_model_predicted(row)

    if not advisory_id and not cve_id:
        # A candidate with no advisory/CVE cannot satisfy the A-class evidence
        # chain (advisory -> repo -> commit -> code), so it never earns scarce
        # P1/P2 review time no matter how strong its code looks.
        tier = "P3"
        reasons.append("no advisory/CVE -> cannot reach A-class (volume/control only)")
    elif not get(row, "fix_commit") or not code_vuln.strip():
        tier = "P3"
        reasons.append("no fix-commit code pair -> finding/Reject stock only")
    elif path_kind in ("test", "conftest"):
        tier = "P3"
        reasons.append("test/fixture code -> false-positive control")
    elif score >= 12:
        tier = "P1"
    elif score >= 8:
        tier = "P2"
    else:
        tier = "P3"

    if predicted and not advisory_id:
        # A model-predicted CWE/CVE is not an advisory. It may still be a real
        # finding, so keep it reviewable -- but never alongside a row that
        # carries a GHSA/PYSEC record, and never above P2.
        if tier == "P1":
            tier = "P2"
            reasons.append("model-predicted id -> capped at P2 until verified vs NVD/GHSA")
        elif tier == "P2":
            reasons.append("model-predicted id -> not advisory-backed")
    return score, tier, reasons


def estimate_audit_tokens(records, *, max_code_chars=50000,
                          final_output_tokens=800, reasoning_tokens=4096):
    """Token estimate matched to the real audit prompt and high reasoning budget."""
    input_tokens = 0
    for row in records:
        messages = build_messages(row, max_code_chars=max_code_chars)
        input_tokens += estimate_tokens("\n".join(m["content"] for m in messages))
    return {
        "input_tokens": input_tokens,
        "output_tokens": (final_output_tokens + reasoning_tokens) * len(records),
        "final_output_tokens": final_output_tokens * len(records),
        "reasoning_tokens": reasoning_tokens * len(records),
    }


def cost_table(tokens, n):
    """Estimate CNY for the screened set under the documented Kimi price cards."""
    price = {
        "kimi-k3": {"in": 20.0, "out": 100.0},
        "kimi-k2.7-code": {"in": 6.5, "out": 27.0},
        "kimi-k2.7-code-highspeed": {"in": 13.0, "out": 54.0},
        "kimi-k2.6": {"in": 6.5, "out": 27.0},
    }
    table = {}
    for model, p in price.items():
        table[model] = round(
            tokens["input_tokens"] / 1_000_000 * p["in"]
            + tokens["output_tokens"] / 1_000_000 * p["out"], 2)
    table["_per_record_kimi_k2_7_code"] = round(table["kimi-k2.7-code"] / max(n, 1), 3)
    table["_per_record_kimi_k3"] = round(table["kimi-k3"] / max(n, 1), 3)
    return table


# Suffixes the local harvesters can parse today. Anything else on disk (raw
# .py/.rst/.md fixtures, tarballs, sqlite, ...) is not silently in scope.
HARVESTABLE_SUFFIXES = {".json", ".jsonl", ".yaml", ".yml", ".csv"}
DEFAULT_COVERAGE_ROOTS = [ROOT / "data" / "external", ROOT / "data" / "raw"]
DEFAULT_COVERAGE_OUT = ROOT / "reports" / "data_quality" / "local_data_coverage.json"


def count_jsonl(path: Path):
    try:
        return sum(1 for line in path.open(encoding="utf-8") if line.strip())
    except (OSError, UnicodeDecodeError):
        return None


def coverage_report(roots, pools):
    """Inventory the local data tree and flag what the screen can/cannot read.

    The screen keeps growing new pool files (GHSA/OSV/PyPA JSON, PyCode-Vul CSV,
    rule fixtures). This report answers "did we actually look at everything?"
    by listing every local source directory with its file suffixes, how many
    files the harvesters can parse, and how many rows each on-disk pool holds.
    """
    sources = {}
    for root in roots:
        root = root if root.is_absolute() else ROOT / root
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            rel = path.relative_to(ROOT)
            # data/<tier>/<source>/... -> key "data/external/<source>"
            key = "/".join(rel.parts[:3]) if len(rel.parts) >= 3 else "/".join(rel.parts)
            suffix = path.suffix.lower() or "<none>"
            bucket = sources.setdefault(key, {
                "files": 0, "by_suffix": Counter(), "harvestable_files": 0,
            })
            bucket["files"] += 1
            bucket["by_suffix"][suffix] += 1
            if suffix in HARVESTABLE_SUFFIXES:
                bucket["harvestable_files"] += 1

    pool_rows = {}
    for pool in pools:
        pool = pool if pool.is_absolute() else ROOT / pool
        if pool.exists():
            pool_rows[str(pool.relative_to(ROOT))] = count_jsonl(pool)

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "harvestable_suffixes": sorted(HARVESTABLE_SUFFIXES),
        "sources": {
            key: {
                "files": value["files"],
                "harvestable_files": value["harvestable_files"],
                "unharvestable_files": value["files"] - value["harvestable_files"],
                "by_suffix": dict(value["by_suffix"].most_common()),
            }
            for key, value in sorted(sources.items())
        },
        "screen_pools": pool_rows,
        "screen_pool_total_rows": sum(v for v in pool_rows.values() if v),
        "note": (
            "harvestable_files counts JSON/JSONL/YAML/CSV files the local "
            "harvesters can parse. unharvestable_files are raw source/fixture "
            "files consumed by dedicated converters instead (semgrep .py "
            "fixtures, bandit tests, ...), not by this screen directly."
        ),
    }
    return out


def summarize(records):
    by_tier = Counter(r["_screen"]["tier"] for r in records)
    reason_kinds = Counter(
        reason.split(":", 1)[0]
        for r in records for reason in (r.get("match_reasons") or ["legacy"])
    )
    by_cwe = Counter(resolve_cwe(r) or "?" for r in records)
    resolved = [resolve_cwe(r) for r in records]
    named = [c for c in resolved if c and cwe_name(c)]
    target = [c for c in resolved if c in TARGET_CWES]
    out = {
        "total": len(records),
        "by_tier": {k: by_tier.get(k, 0) for k in ("P1", "P2", "P3")},
        "by_source": dict(Counter(r.get("source") or "?" for r in records).most_common()),
        "by_match_reason": dict(reason_kinds.most_common()),
        "by_cwe": dict(by_cwe.most_common(40)),
        "by_cwe_raw": dict(Counter(r.get("cwe") or "?" for r in records).most_common(40)),
        "by_cwe_name": dict(Counter(cwe_name(c) or c for c in named).most_common(20)),
        "cwe_resolved_from_cwe_all": sum(
            1 for r in records
            if not (r.get("cwe") or "").strip() and resolve_cwe(r)),
        "cwe_named": len(named),
        "cwe_target_total": len(target),
        "by_package": dict(Counter(r.get("package") or "?" for r in records).most_common(25)),
        "with_code_pair": sum(
            1 for r in records if (r.get("code_vuln") or "").strip() and (r.get("code_fixed") or "").strip()),
        "production_code": sum(
            1 for r in records if classify_path(get(r, "file_path")) == "production"),
        "test_code": sum(
            1 for r in records if classify_path(get(r, "file_path")) in ("test", "conftest")),
        "parseable_code_pairs": sum(
            1 for r in records if r["_screen"].get("parses_as_python") is True),
        "p3_volume": sum(1 for r in records if r["_screen"].get("p3_bucket") == "p3_volume"),
        "p3_stock": sum(1 for r in records if r["_screen"].get("p3_bucket") == "p3_stock"),
        "model_predicted": sum(1 for r in records if r["_screen"].get("model_predicted")),
    }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Screen real-crypto candidates")
    ap.add_argument("--pools", nargs="*", type=Path, default=None)
    local = ap.add_mutually_exclusive_group()
    local.add_argument(
        "--local-roots", nargs="*", type=Path, default=None,
        help="Extra local roots/files to scan for compatible JSON/JSONL records "
             f"(default: {DEFAULT_LOCAL_ROOTS[0]})",
    )
    local.add_argument(
        "--no-local-json", action="store_true",
        help="Disable the generic local JSON/JSONL adapter",
    )
    ap.add_argument("--local-out", type=Path, default=DEFAULT_LOCAL_OUT)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--review-out", type=Path, default=DEFAULT_REVIEW)
    ap.add_argument("--todo-out", type=Path, default=DEFAULT_TODO)
    ap.add_argument("--no-commit-out", type=Path, default=DEFAULT_NOCOMMIT)
    ap.add_argument("--predicted-out", type=Path, default=DEFAULT_PREDICTED)
    ap.add_argument("--volume-out", type=Path, default=DEFAULT_VOLUME)
    ap.add_argument("--stats", type=Path, default=DEFAULT_STATS)
    ap.add_argument("--coverage", action="store_true",
                    help="Inventory every local data source/suffix and pool size")
    ap.add_argument("--coverage-out", type=Path, default=DEFAULT_COVERAGE_OUT)
    ap.add_argument("--emit", action="store_true",
                    help="Write the screened JSONL and stats report")
    args = ap.parse_args()

    pools = args.pools if args.pools else DEFAULT_POOLS
    pools = [p if p.is_absolute() else ROOT / p for p in pools]
    if args.no_local_json:
        local_roots = []
    elif args.local_roots is not None:
        local_roots = [
            p if p.is_absolute() else ROOT / p for p in args.local_roots
        ]
    else:
        local_roots = DEFAULT_LOCAL_ROOTS

    if args.coverage:
        coverage = coverage_report(DEFAULT_COVERAGE_ROOTS, pools)
        cov_path = (args.coverage_out if args.coverage_out.is_absolute()
                    else ROOT / args.coverage_out)
        cov_path.parent.mkdir(parents=True, exist_ok=True)
        cov_path.write_text(json.dumps(coverage, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
        print(f"{'source':52s} {'files':>8s} {'harvestable':>12s}")
        for key, value in coverage["sources"].items():
            print(f"{key:52s} {value['files']:8d} {value['harvestable_files']:12d}")
        print(f"\npool rows read (pre-merge): {coverage['screen_pool_total_rows']}")
        for key, rows in coverage["screen_pools"].items():
            print(f"  {key:58s} {rows}")
        print(f"\n[+] wrote {cov_path}")
        if not args.emit:
            return 0

    pool_rows = merge_pools(pools)
    local_rows, local_stats = load_local_json_candidates(local_roots)
    merged = merge_records([*pool_rows, *local_rows])
    kept, dropped = dedupe(merged)

    scored = []
    for row in kept:
        score, tier, reasons = score_candidate(row)
        row = dict(row)
        p3_bucket = ""
        if tier == "P3":
            p3_bucket = "p3_volume" if is_volume_candidate(row) else "p3_stock"
            if p3_bucket == "p3_volume":
                reasons = reasons + [
                    "paired production code -> B-class training volume "
                    "(needs model/human review, never A-class)"]
        row["_screen"] = {
            "score": score,
            "tier": tier,
            "p3_bucket": p3_bucket,
            "model_predicted": is_model_predicted(row),
            "cwe_resolved": resolve_cwe(row),
            "cwe_name": cwe_name(resolve_cwe(row)),
            "cwe_resolved_from_cwe_all": (
                not (row.get("cwe") or "").strip() and bool(resolve_cwe(row))),
            "path_kind": classify_path(get(row, "file_path")),
            "parses_as_python": (
                parses_as_python(row.get("code_vuln") or "")
                and parses_as_python(row.get("code_fixed") or "")
            ) if (row.get("code_vuln") or "").strip() else None,
            "reasons": reasons,
            "screened_at": datetime.now(timezone.utc).isoformat(),
        }
        scored.append(row)
    scored.sort(key=lambda r: (-r["_screen"]["score"], r.get("package") or ""))

    tiers = {
        "P1": [r for r in scored if r["_screen"]["tier"] == "P1"],
        "P2": [r for r in scored if r["_screen"]["tier"] == "P2"],
        "P3": [r for r in scored if r["_screen"]["tier"] == "P3"],
    }
    # Two distinct follow-up queues. ``need_code`` rows point at a fix commit
    # and only need the diff fetched. ``no_commit`` rows have no commit at all,
    # so they need a human/PyPI-version trace before any code can exist -- they
    # used to fall through both queues silently.
    need_code = [
        r for r in scored
        if get(r, "fix_commit") and not (r.get("code_vuln") or "").strip()
    ]
    no_commit = [
        r for r in scored
        if get(r, "advisory_id", "cve_id")
        and not get(r, "fix_commit")
        and not (r.get("code_vuln") or "").strip()
    ]
    # Model-predicted ids that still look like real findings: these need a cheap
    # manual NVD/GHSA trace before they can be treated as advisory-backed.
    predicted_cve = [
        r for r in scored
        if r["_screen"]["model_predicted"] and get(r, "cve_id")
    ]
    # Advisory-less but usable paired code: B-class training volume, not A-class.
    volume = [r for r in scored if r["_screen"]["p3_bucket"] == "p3_volume"]
    no_commit_repo_unresolved = sum(1 for r in no_commit if not get(r, "repo_url"))
    stats = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pools": [str(p) for p in pools],
        "merged_pool_rows": len(pool_rows),
        "local_json": local_stats,
        "local_adapted_rows": len(local_rows),
        "merged": len(merged),
        "dropped_duplicates": len(dropped),
        "drop_examples": [{"candidate_id": c, "reason": r} for c, r in dropped[:20]],
        "summary": summarize(scored),
        "queues": {
            "need_code": len(need_code),
            "no_commit": len(no_commit),
            "no_commit_repo_unresolved": no_commit_repo_unresolved,
            "predicted_cve": len(predicted_cve),
            "volume": len(volume),
        },
        "tier_tokens": {t: estimate_audit_tokens(rows) for t, rows in tiers.items()},
        "tier_cost_cny": {
            t: cost_table(estimate_audit_tokens(rows), len(rows)) for t, rows in tiers.items()
        },
        "note": "Model results are pre-screening only; verified stays false until human review.",
    }

    print(f"Merged candidates : {len(merged)}")
    print(f"  pool rows       : {len(pool_rows)}")
    print(f"  local JSON rows : {len(local_rows)} adapted")
    print(f"After dedupe      : {len(scored)}  (dropped {len(dropped)})")
    for tier in ("P1", "P2", "P3"):
        rows = tiers[tier]
        tok = stats["tier_tokens"][tier]
        cost = stats["tier_cost_cny"][tier]
        print(f"  {tier}: {len(rows):4d}  tokens in/out "
              f"{tok['input_tokens']}/{tok['output_tokens']}  "
              f"k3 ¥{cost['kimi-k3']}  k2.7-code ¥{cost['kimi-k2.7-code']}")
    print("\nP1 by CWE    :", dict(Counter(resolve_cwe(r) or "?" for r in tiers["P1"]).most_common()))
    print("P1 by package:", dict(Counter(r.get("package") or "?" for r in tiers["P1"]).most_common(12)))
    print(f"CWE resolved from cwe_all: {stats['summary']['cwe_resolved_from_cwe_all']}  "
          f"named via cwe_database.json: {stats['summary']['cwe_named']}")
    print(f"with code pair {stats['summary']['with_code_pair']}  "
          f"production {stats['summary']['production_code']}  "
          f"test/fixture {stats['summary']['test_code']}")

    if args.emit:
        out = args.out if args.out.is_absolute() else ROOT / args.out
        local_out = (
            args.local_out if args.local_out.is_absolute() else ROOT / args.local_out
        )
        stats_path = args.stats if args.stats.is_absolute() else ROOT / args.stats
        out.parent.mkdir(parents=True, exist_ok=True)
        local_out.parent.mkdir(parents=True, exist_ok=True)
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in scored) + "\n",
                       encoding="utf-8")
        local_out.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in local_rows) + "\n",
            encoding="utf-8")
        stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
                              encoding="utf-8")
        review = [r for r in scored if r["_screen"]["tier"] in ("P1", "P2")]
        review_path = args.review_out if args.review_out.is_absolute() else ROOT / args.review_out
        review_path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in review) + "\n",
            encoding="utf-8")
        todo_path = args.todo_out if args.todo_out.is_absolute() else ROOT / args.todo_out
        todo_path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in need_code) + "\n",
            encoding="utf-8")
        no_commit_path = (args.no_commit_out if args.no_commit_out.is_absolute()
                          else ROOT / args.no_commit_out)
        no_commit_path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in no_commit) + "\n",
            encoding="utf-8")
        predicted_path = (args.predicted_out if args.predicted_out.is_absolute()
                          else ROOT / args.predicted_out)
        predicted_path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in predicted_cve) + "\n",
            encoding="utf-8")
        volume_path = (args.volume_out if args.volume_out.is_absolute()
                       else ROOT / args.volume_out)
        volume_path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in volume) + "\n",
            encoding="utf-8")
        print(f"\n[+] wrote {out}")
        print(f"[+] wrote {local_out} ({len(local_rows)} adapted local JSON rows)")
        print(f"[+] wrote {review_path} ({len(review)} P1/P2 rows)")
        print(f"[+] wrote {todo_path} ({len(need_code)} need code fetch)")
        print(f"[+] wrote {no_commit_path} ({len(no_commit)} need an advisory trace, no commit)")
        print(f"[+] wrote {predicted_path} ({len(predicted_cve)} model-predicted ids to verify)")
        print(f"[+] wrote {volume_path} ({len(volume)} advisory-less B-class code pairs)")
        print(f"[+] wrote {stats_path}")
    else:
        print("\n[dry] pass --emit to write the screened pool and stats report")
    return 0


if __name__ == "__main__":
    sys.exit(main())
