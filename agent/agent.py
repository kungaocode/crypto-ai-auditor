"""Security Agent: LLM + lightweight evidence step over static-analysis findings.

v0 scope (engineering milestone): single-step reasoning.
  - triage(finding, snippet):  code + Semgrep finding -> verdict Confirm/Reject
  - detect(code):              code -> {vulnerable, cwe, …} (benchmark "Base LLM")
Both delegate to a model backend from model/inference.py (mock | cloud). The ReAct
tool loop (semgrep / rule_db / cwe_db re-check) is the next stage (roadmap P4);
v0 keeps a cheap deterministic guard so fixture/test code is not auto-confirmed.
"""

import re
from pathlib import Path
from typing import Any, Dict, List

from model import inference as model_inf

VERDICT_MAP = {"confirm": "CONFIRMED", "reject": "REJECTED"}


class SecurityAgent:
    def __init__(self, config_path: Path | None = None, backend=None):
        self.config = self._load_config(config_path)
        self.backend = backend or model_inf.get_backend(config=self.config)
        # fixture guard toggle (rule of thumb: don't auto-confirm tests)
        self.guard = self.config.get("agent", {}).get("fixture_guard", True)

    def _load_config(self, path: Path | None) -> dict:
        if path is None:
            return {}
        import yaml
        return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}

    # ---- code helpers -------------------------------------------------

    @staticmethod
    def _finding_message(f: dict) -> str:
        extra = f.get("extra", {})
        msg = extra.get("message", "")
        return f"[{f.get('check_id', 'RULE')}] {msg}" if msg else f.get("check_id", "RULE")

    @staticmethod
    def _finding_code(f: dict) -> str:
        ctx = f.get("context") or {}
        if ctx.get("snippet"):
            return ctx["snippet"]
        path = Path(f.get("path", ""))
        start = f.get("start", {}) or {}
        line = start.get("line", 1)
        if path.exists():
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except Exception:
                lines = []
            return "\n".join(lines[max(0, line - 4):line + 8])
        return ""

    # ---- public API ----------------------------------------------------

    def detect(self, code: str) -> dict:
        """Code-only vulnerability detection (benchmark systems ②/⑤ detect mode)."""
        pred = self.backend.detect(code)
        return {
            "vulnerable": bool(pred.get("vulnerable")),
            "cwe": str(pred.get("cwe", "")),
            "severity": str(pred.get("severity", "")),
            "confidence": str(pred.get("confidence", "")),
            "explanation": str(pred.get("explanation", "")),
        }

    def triage(self, findings: List[dict]) -> List[Dict[str, Any]]:
        """Run triage over findings; returns report-compatible verdict dicts."""
        verdicts = []
        for f in findings:
            code = self._finding_code(f)
            finding_txt = self._finding_message(f)
            verdicts.append(self._triage_one(code, finding_txt, f))
        return verdicts

    def triage_one(self, code: str, finding_txt: str) -> dict:
        return self._triage_one(code, finding_txt, None)

    def _triage_one(self, code: str, finding_txt: str, raw_finding: dict | None) -> dict:
        pred = {}
        try:
            pred = self.backend.triage(code, finding_txt)
        except model_inf.LLMError as e:
            pred = {"verdict": "Reject", "confidence": "LOW",
                    "explanation": f"LLM unavailable ({e}); defaulted to Reject."}

        verdict_raw = str(pred.get("verdict", "")).strip().lower()
        verdict = VERDICT_MAP.get(verdict_raw, "UNCERTAIN")

        # evidence guard: model saying Confirm on test/fixture code is overruled only
        # when the guard is on AND the model is NOT the deterministic mock (which
        # already encodes the same rule). Keeps v0 honest about uncertainty.
        if (self.guard and self._is_fixture(code) and verdict_raw == "confirm"
                and type(self.backend).__name__ != "MockBackend"):
            verdict = "REJECTED"
            pred["explanation"] = (pred.get("explanation", "")
                                   + " [guard] finding in test/fixture scope.")

        fallback = raw_finding or {}
        return {
            "finding": raw_finding or {"code": code, "message": finding_txt},
            "verdict": verdict,
            "confidence": float(self._conf(pred.get("confidence"))),
            "cwe": pred.get("cwe") or fallback.get("extra", {}).get("metadata", {}).get("cwe", ["CWE-UNKNOWN"]),
            "severity": pred.get("severity") or fallback.get("extra", {}).get("metadata", {}).get("severity", "MEDIUM"),
            "explanation": pred.get("explanation", ""),
            "patch": pred.get("patch", ""),
        }

    @staticmethod
    def _conf(s) -> float:
        low = {"low": 0.3, "medium": 0.6, "high": 0.9}
        return low.get(str(s).strip().lower(), 0.5)

    @staticmethod
    def _is_fixture(code: str) -> bool:
        return bool(re.search(r"^\s*(async\s+)?def\s+test_", code[:600], re.MULTILINE))
