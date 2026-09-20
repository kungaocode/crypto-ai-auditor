"""Wrapper around Semgrep CLI for JSON output."""

import json
import subprocess
from pathlib import Path
from typing import Any, List


def run_semgrep(target: Path, rules_dir: Path) -> List[dict]:
    """
    Run Semgrep with the given rules directory against target file/dir.
    Returns a list of finding dicts.
    """
    cmd = [
        "semgrep", "scan",
        "--config", str(rules_dir),
        "--json",
        "--quiet",
        str(target),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        # Semgrep returns 1 when findings exist, >1 on error
        raise RuntimeError(f"Semgrep failed: {result.stderr}")
    data = json.loads(result.stdout)
    return data.get("results", [])
