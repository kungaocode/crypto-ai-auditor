"""Bridge to the legacy security.audit AST scanner for Python source."""

from pathlib import Path
from typing import Any, Dict, List

from security.audit.scanner import AuditScanner
from security.audit.models import AuditConfig


def run_ast_scan(target: Path, config: AuditConfig | None = None) -> List[Dict[str, Any]]:
    """
    Run the AST-based security scanner on a file or directory.
    Returns findings as plain dicts compatible with Semgrep output.
    """
    scanner = AuditScanner(config=config or AuditConfig())
    result = scanner.scan(roots=[target])
    findings: List[Dict[str, Any]] = []
    for f in result.findings:
        # Only include crypto-relevant rules for this project
        crypto_prefixes = (
            "python-weak-hash",
            "python-hardcoded-secret",
            "python-no-tls-verify",
        )
        if not f.rule_id.startswith(crypto_prefixes):
            continue
        findings.append({
            "check_id": f.rule_id,
            "path": f.location.file,
            "start": {"line": f.location.line, "col": f.location.column},
            "end": {"line": f.location.line, "col": f.location.column},
            "extra": {
                "message": f.description,
                "metadata": {
                    "cwe": _infer_cwe(f.rule_id),
                    "severity": f.severity.value,
                },
                "lines": f.snippet,
            },
        })
    return findings


def _infer_cwe(rule_id: str) -> List[str]:
    mapping = {
        "python-weak-hash": ["CWE-327"],
        "python-hardcoded-secret": ["CWE-321"],
        "python-no-tls-verify": ["CWE-295"],
    }
    for prefix, cwes in mapping.items():
        if rule_id.startswith(prefix):
            return cwes
    return ["CWE-UNKNOWN"]
