"""Convert verdicts to JSON or Markdown reports."""

import json
from pathlib import Path
from typing import Any, Dict, List


def generate_report(verdicts: List[Dict[str, Any]], out_dir: Path, fmt: str = "md") -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        path = out_dir / "report.json"
        path.write_text(json.dumps(verdicts, indent=2, ensure_ascii=False))
    else:
        path = out_dir / "report.md"
        lines = ["# Cryptographic Security Audit Report\n"]
        for v in verdicts:
            f = v["finding"]
            lines.append(f"## {f.get('check_id', 'N/A')}")
            lines.append(f"- **File**: {f.get('path', 'N/A')}")
            lines.append(f"- **Line**: {f.get('start', {}).get('line', 'N/A')}")
            lines.append(f"- **Verdict**: {v['verdict']} (confidence: {v['confidence']})")
            lines.append(f"- **CWE**: {v['cwe']}")
            lines.append(f"- **Severity**: {v['severity']}")
            lines.append(f"- **Explanation**: {v['explanation']}")
            lines.append("")
        path.write_text("\n".join(lines))
    print(f"[+] Report written to {path}")
