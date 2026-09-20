"""AST context extraction around a Semgrep finding."""

import ast
from pathlib import Path
from typing import Any, Dict


def extract_context(finding: dict, lines_before: int = 5, lines_after: int = 10) -> Dict[str, Any]:
    """
    Extract surrounding code context for a Semgrep finding.
    Returns a dict with file, line range, and snippet.
    """
    path = Path(finding.get("path", ""))
    start = finding.get("start", {})
    line = start.get("line", 1)
    if not path.exists():
        return {"snippet": "", "function": "", "class": ""}
    try:
        source = path.read_text(encoding="utf-8")
    except Exception:
        return {"snippet": "", "function": "", "class": ""}
    lines = source.splitlines()
    lo = max(0, line - lines_before - 1)
    hi = min(len(lines), line + lines_after)
    snippet = "\n".join(lines[lo:hi])
    # TODO: AST-level function/class extraction
    return {"snippet": snippet, "function": "", "class": ""}
