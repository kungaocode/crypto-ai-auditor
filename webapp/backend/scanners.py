"""Static analysis layer for the web auditor.

Three engines feed one normalised finding model:

* Semgrep (``rules/`` directory) - primary, CWE-aware rule engine.
* The repository AST scanner (``security.audit``) - Python fallback and
  supplementary checks.
* A line-oriented pattern engine - keeps the product useful when Semgrep is
  not installed, and closes a few literal-value gaps in the rule set.

Every finding is normalised to the same dictionary so the model triage layer
and the UI do not need to care which engine produced it.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - import guard keeps the module usable standalone
    from security.audit.scanner import AuditScanner
    from security.audit.models import AuditConfig
except Exception:  # pragma: no cover
    AuditScanner = None  # type: ignore[assignment]
    AuditConfig = None  # type: ignore[assignment]


PYTHON_EXTENSIONS = {".py", ".pyw"}
C_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}
SUPPORTED_EXTENSIONS = PYTHON_EXTENSIONS | C_EXTENSIONS


@dataclass
class SourceFile:
    """One auditable file already materialised on disk."""

    name: str
    path: Path
    language: str
    source: str

    @property
    def lines(self) -> list[str]:
        return self.source.splitlines()


@dataclass
class ScanOutput:
    findings: list[dict[str, Any]] = field(default_factory=list)
    engines: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rule metadata (mirrors rules/*/rule.yaml; used for titles and fallback text)
# ---------------------------------------------------------------------------

RULE_META: dict[str, dict[str, str]] = {
    "CRYPTO-001": {
        "title": "弱哈希算法 MD5",
        "title_en": "Weak hash: MD5",
        "category": "哈希算法",
        "cwe": "CWE-327",
        "severity": "MEDIUM",
    },
    "CRYPTO-002": {
        "title": "弱哈希算法 SHA-1",
        "title_en": "Weak hash: SHA-1",
        "category": "哈希算法",
        "cwe": "CWE-327",
        "severity": "MEDIUM",
    },
    "CRYPTO-003": {
        "title": "弱分组密码 DES/3DES",
        "title_en": "Weak block cipher: DES/3DES",
        "category": "加密算法",
        "cwe": "CWE-327",
        "severity": "HIGH",
    },
    "CRYPTO-004": {
        "title": "已废弃流密码 RC4",
        "title_en": "Deprecated cipher: RC4",
        "category": "加密算法",
        "cwe": "CWE-327",
        "severity": "HIGH",
    },
    "CRYPTO-005": {
        "title": "AES ECB 模式",
        "title_en": "AES ECB mode",
        "category": "加密模式",
        "cwe": "CWE-327",
        "severity": "HIGH",
    },
    "CRYPTO-006": {
        "title": "可预测或硬编码 IV",
        "title_en": "Predictable or hard-coded IV",
        "category": "随机性",
        "cwe": "CWE-329",
        "severity": "HIGH",
    },
    "CRYPTO-007": {
        "title": "硬编码密钥",
        "title_en": "Hard-coded cryptographic key",
        "category": "密钥管理",
        "cwe": "CWE-321",
        "severity": "HIGH",
    },
    "CRYPTO-008": {
        "title": "不安全随机数",
        "title_en": "Insecure randomness",
        "category": "随机性",
        "cwe": "CWE-338",
        "severity": "HIGH",
    },
    "CRYPTO-009": {
        "title": "弱密钥长度或曲线",
        "title_en": "Weak key length or curve",
        "category": "密钥管理",
        "cwe": "CWE-326",
        "severity": "HIGH",
    },
    "CRYPTO-010": {
        "title": "不安全 TLS 配置",
        "title_en": "Insecure TLS configuration",
        "category": "传输安全",
        "cwe": "CWE-326",
        "severity": "HIGH",
    },
    "CRYPTO-011": {
        "title": "明文密码存储或传递",
        "title_en": "Plaintext password handling",
        "category": "凭据保护",
        "cwe": "CWE-256",
        "severity": "HIGH",
    },
    "CRYPTO-012": {
        "title": "弱 KDF 参数",
        "title_en": "Weak KDF parameters",
        "category": "凭据保护",
        "cwe": "CWE-916",
        "severity": "HIGH",
    },
    "CRYPTO-013": {
        "title": "非恒定时间比较",
        "title_en": "Non-constant-time comparison",
        "category": "凭据保护",
        "cwe": "CWE-208",
        "severity": "MEDIUM",
    },
}

_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def guess_language(name: str) -> str:
    suffix = Path(name).suffix.lower()
    if suffix in PYTHON_EXTENSIONS:
        return "python"
    if suffix in C_EXTENSIONS:
        return "c"
    return "text"


def is_supported(name: str) -> bool:
    return Path(name).suffix.lower() in SUPPORTED_EXTENSIONS


def _coerce_severity(value: Any, default: str = "MEDIUM") -> str:
    if isinstance(value, (list, tuple)) and value:
        value = value[0]
    text = str(value or default).strip().upper()
    if text in _SEVERITY_RANK:
        return text
    if text == "WARNING":
        return "MEDIUM"
    if text == "ERROR":
        return "HIGH"
    return default


def _coerce_cwe(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else "CWE-UNKNOWN"
    text = str(value or "").strip()
    return text or "CWE-UNKNOWN"


def _rule_id_from_check_id(check_id: str) -> str:
    match = re.search(r"(CRYPTO-\d+)", check_id or "")
    return match.group(1) if match else (check_id or "UNKNOWN").split(".")[-1]


def _line_snippet(source: str, start_line: int, end_line: int | None = None) -> str:
    lines = source.splitlines()
    if not lines or start_line < 1:
        return ""
    lo = max(1, start_line)
    hi = min(len(lines), end_line or start_line)
    return "\n".join(lines[lo - 1:hi]).strip()


def attach_context(finding: dict[str, Any], source_lookup: dict[str, SourceFile]) -> None:
    """Attach surrounding source lines and a stable fingerprint."""
    source_file = source_lookup.get(finding["file"])
    if source_file is None:
        finding.setdefault("context_lines", [])
        return
    lines = source_file.lines
    line = int(finding.get("line") or 1)
    lo = max(1, line - 3)
    hi = min(len(lines), line + 4)
    finding["context_start"] = lo
    finding["context_lines"] = [
        {"number": number, "text": lines[number - 1]}
        for number in range(lo, hi + 1)
    ]
    finding["context_snippet"] = "\n".join(lines[lo - 1:hi])
    if not finding.get("snippet"):
        finding["snippet"] = _line_snippet(
            source_file.source, line, int(finding.get("end_line") or line)
        )
    finding["fingerprint"] = (
        f"{finding['rule_id']}:{finding['file']}:{line}:{finding.get('column', 0)}"
    )


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------

def semgrep_path() -> str:
    return shutil.which("semgrep") or ""


def run_semgrep(
    target_dir: Path,
    rules_dir: Path,
    timeout: int = 90,
) -> tuple[list[dict[str, Any]], str]:
    """Run Semgrep over an entire staged directory in one process."""
    binary = semgrep_path()
    if not binary:
        return [], "not installed"
    cmd = [
        binary,
        "scan",
        "--config",
        str(rules_dir),
        "--json",
        "--quiet",
        "--no-git-ignore",
        ".",
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(target_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return [], f"timeout after {timeout}s"
    except OSError as exc:
        return [], f"failed: {exc}"
    if proc.returncode not in (0, 1):
        detail = (proc.stderr or "").strip().splitlines()
        return [], f"error: {detail[-1] if detail else proc.returncode}"
    import json

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [], "invalid JSON output"
    return payload.get("results", []) or [], "ok"


def _normalise_semgrep(
    raw_findings: Iterable[dict[str, Any]],
    source_lookup: dict[str, SourceFile],
) -> list[dict[str, Any]]:
    normalised: list[dict[str, Any]] = []
    for raw in raw_findings:
        extra = raw.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule_id = _rule_id_from_check_id(raw.get("check_id", ""))
        path = str(raw.get("path") or "").replace("\\", "/").lstrip("./")
        meta = RULE_META.get(rule_id, {})
        start = raw.get("start") or {}
        end = raw.get("end") or {}
        normalised.append(
            {
                "rule_id": rule_id,
                "title": meta.get("title", rule_id),
                "title_en": meta.get("title_en", ""),
                "category": meta.get("category", "其他"),
                "message": extra.get("message") or meta.get("title", rule_id),
                "severity": _coerce_severity(metadata.get("severity"), meta.get("severity", "MEDIUM")),
                "cwe": _coerce_cwe(metadata.get("cwe") or meta.get("cwe")),
                "language": guess_language(path),
                "file": path,
                "line": int(start.get("line") or 1),
                "column": int(start.get("col") or 0),
                "end_line": int(end.get("line") or start.get("line") or 1),
                "end_column": int(end.get("col") or 0),
                "snippet": "",
                "fix_suggestion": extra.get("fix") or metadata.get("fix") or "",
                "engine": "semgrep",
            }
        )
    return normalised


# ---------------------------------------------------------------------------
# Repository AST scanner (Python only)
# ---------------------------------------------------------------------------

_AST_RULE_MAP = {
    "python-weak-hash": "CRYPTO-001",
    "python-hardcoded-secret": "CRYPTO-007",
    "python-no-tls-verify": "CRYPTO-010",
}


def run_ast(sources: list[SourceFile], extended: bool = False) -> list[dict[str, Any]]:
    if AuditScanner is None or AuditConfig is None:
        return []
    scanner = AuditScanner(config=AuditConfig())
    out: list[dict[str, Any]] = []
    for source_file in sources:
        if source_file.language != "python":
            continue
        try:
            findings = scanner.scan_file(source_file.path)
        except Exception:
            continue
        for finding in findings:
            rule_id = _AST_RULE_MAP.get(finding.rule_id)
            if rule_id is None:
                if not extended:
                    continue
                rule_id = "SEC-" + finding.rule_id.replace("python-", "").upper()
                meta = {
                    "title": finding.title,
                    "title_en": finding.title,
                    "category": "扩展安全",
                    "severity": finding.severity.value,
                    "cwe": "CWE-UNKNOWN",
                }
            else:
                meta = RULE_META.get(rule_id, {})
                if rule_id in {"CRYPTO-001", "CRYPTO-002"}:
                    snippet_lower = (finding.snippet or "").lower()
                    if "sha1" in snippet_lower or "sha-1" in snippet_lower:
                        rule_id = "CRYPTO-002"
                    meta = RULE_META.get(rule_id, meta)
            out.append(
                {
                    "rule_id": rule_id,
                    "title": meta.get("title", finding.title),
                    "title_en": meta.get("title_en", ""),
                    "category": meta.get("category", "其他"),
                    "message": finding.description or finding.title,
                    "severity": _coerce_severity(meta.get("severity"), finding.severity.value),
                    "cwe": _coerce_cwe(meta.get("cwe")),
                    "language": "python",
                    "file": source_file.name,
                    "line": int(finding.location.line or 1),
                    "column": int(finding.location.column or 0),
                    "end_line": int(finding.location.line or 1),
                    "end_column": int(finding.location.column or 0),
                    "snippet": finding.snippet or "",
                    "fix_suggestion": finding.fix_suggestion or "",
                    "engine": "ast",
                }
            )
    return out


# ---------------------------------------------------------------------------
# Pattern engine (always-on supplement / Semgrep fallback)
# ---------------------------------------------------------------------------

_COMMENT_PREFIXES = ("#", "//", "/*", "*")

_PATTERN_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("CRYPTO-001", re.compile(r"hashlib\.md5\s*\(|hashlib\.new\s*\(\s*[\"']md5[\"']", re.I)),
    ("CRYPTO-002", re.compile(r"hashlib\.sha1\s*\(|hashlib\.new\s*\(\s*[\"']sha-?1[\"']", re.I)),
    ("CRYPTO-003", re.compile(r"Crypto\.Cipher\.DES3?\b|\bDES3?\.new\s*\(|import\s+DES3?\b", re.I)),
    ("CRYPTO-004", re.compile(r"\bARC4\b|\bRC4\b", re.I)),
    ("CRYPTO-005", re.compile(r"MODE_ECB|modes\.ECB", re.I)),
    ("CRYPTO-006", re.compile(
        r"\b(?:iv|nonce)\s*=\s*(?:b|rb)?[\"'][^\"']*[\"']"
        r"|modes\.(?:CBC|CFB|OFB)\s*\(\s*(?:b)?[\"'][\"']\s*\)"
        r"|(?:MODE_CBC|MODE_CFB|MODE_OFB)[^#\n]*bytes\s*\(\s*16\s*\)",
        re.I,
    )),
    ("CRYPTO-007", re.compile(
        r"(?:AES\.new|Fernet|Cipher)\s*\(\s*(?:b|rb)?[\"'][^\"']{6,}[\"']"
        r"|\b(?:key|secret|api_key|private_key)\s*=\s*(?:b|rb)?[\"'][^\"']{6,}[\"']",
        re.I,
    )),
    ("CRYPTO-008", re.compile(
        r"\b(?:iv|key|token|salt|nonce|secret|password)\w*\s*=\s*random\.", re.I
    )),
    ("CRYPTO-009", re.compile(
        r"RSA\.generate\s*\(\s*(?:512|768|1024)\s*\)"
        r"|SECP192R1|SECP160R1|SECP112R1|SECT163",
        re.I,
    )),
    ("CRYPTO-010", re.compile(
        r"PROTOCOL_SSLv[23]|PROTOCOL_TLSv1(?:_1)?\b|_create_unverified_context"
        r"|CERT_NONE|verify\s*=\s*False",
        re.I,
    )),
    ("CRYPTO-011", re.compile(
        r"\.\s*(?:password|passwd|pwd)\s*=\s*(?!=)"
        r"|\bset_(?:password|passwd|pwd)\s*\(",
        re.I,
    )),
    ("CRYPTO-013", re.compile(
        r"\b\w*(?:password|passwd|pwd|token|secret|digest|hash|signature|mac)\w*"
        r"\s*(?:==|!=)\s*[A-Za-z_]",
        re.I,
    )),
]

_KDF_ITER_RE = re.compile(r"pbkdf2_hmac\s*\([^)]*?,\s*(\d{1,7})\s*[,)]", re.I)
_BCRYPT_RE = re.compile(r"bcrypt\.gensalt\s*\(\s*rounds\s*=\s*(\d+)\s*\)", re.I)
_SCRYPT_N_RE = re.compile(r"scrypt\s*\([^)]*?n\s*=\s*(\d+)", re.I)
_RSA_RE = re.compile(r"RSA\.generate\s*\(\s*(\d{3,5})\s*\)", re.I)


def run_patterns(sources: list[SourceFile]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for source_file in sources:
        for number, raw_line in enumerate(source_file.lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith(_COMMENT_PREFIXES):
                continue
            matched_rules: set[str] = set()
            for rule_id, pattern in _PATTERN_RULES:
                if pattern.search(raw_line):
                    matched_rules.add(rule_id)
            # value-dependent KDF checks
            match = _KDF_ITER_RE.search(raw_line)
            if match and int(match.group(1)) < 100_000:
                matched_rules.add("CRYPTO-012")
            match = _BCRYPT_RE.search(raw_line)
            if match and int(match.group(1)) < 12:
                matched_rules.add("CRYPTO-012")
            match = _SCRYPT_N_RE.search(raw_line)
            if match and int(match.group(1)) < 16384:
                matched_rules.add("CRYPTO-012")
            match = _RSA_RE.search(raw_line)
            if match and int(match.group(1)) < 2048:
                matched_rules.add("CRYPTO-009")
            for rule_id in matched_rules:
                meta = RULE_META.get(rule_id, {})
                out.append(
                    {
                        "rule_id": rule_id,
                        "title": meta.get("title", rule_id),
                        "title_en": meta.get("title_en", ""),
                        "category": meta.get("category", "其他"),
                        "message": meta.get("title", rule_id),
                        "severity": _coerce_severity(meta.get("severity")),
                        "cwe": _coerce_cwe(meta.get("cwe")),
                        "language": source_file.language,
                        "file": source_file.name,
                        "line": number,
                        "column": max(0, raw_line.find(line)),
                        "end_line": number,
                        "end_column": 0,
                        "snippet": line,
                        "fix_suggestion": "",
                        "engine": "pattern",
                    }
                )
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_sources(
    sources: list[SourceFile],
    target_dir: Path,
    rules_dir: Path,
    extended: bool = False,
) -> ScanOutput:
    source_lookup = {source.name: source for source in sources}
    findings: list[dict[str, Any]] = []
    engines: dict[str, Any] = {
        "semgrep": False,
        "ast": AuditScanner is not None,
        "pattern": True,
        "semgrep_detail": "",
    }

    if semgrep_path():
        raw, detail = run_semgrep(target_dir, rules_dir)
        engines["semgrep_detail"] = detail
        if detail == "ok":
            engines["semgrep"] = True
            findings.extend(_normalise_semgrep(raw, source_lookup))

    findings.extend(run_ast(sources, extended=extended))
    findings.extend(run_patterns(sources))

    # De-duplicate on rule + location; keep the highest-severity engine order.
    deduped: dict[tuple[str, str, int], dict[str, Any]] = {}
    for finding in findings:
        key = (finding["rule_id"], finding["file"], int(finding["line"] or 1))
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = finding
            continue
        if _SEVERITY_RANK.get(finding["severity"], 0) > _SEVERITY_RANK.get(existing["severity"], 0):
            deduped[key] = finding

    ordered = sorted(
        deduped.values(),
        key=lambda f: (
            _SEVERITY_RANK.get(f["severity"], 0),
            f["file"],
            int(f["line"] or 0),
        ),
        reverse=True,
    )
    for finding in ordered:
        attach_context(finding, source_lookup)
    engines["counts"] = {
        "semgrep": sum(1 for f in ordered if f["engine"] == "semgrep"),
        "ast": sum(1 for f in ordered if f["engine"] == "ast"),
        "pattern": sum(1 for f in ordered if f["engine"] == "pattern"),
    }
    return ScanOutput(findings=ordered, engines=engines)
