"""LLM backends: cloud (OpenAI-compatible) and deterministic local mock.

`get_backend(kind, config)` returns either:
  - CloudBackend : calls a hosted chat-completions API (DashScope/ModelScope/…)
  - MockBackend  : deterministic heuristics, used for CI / no-credential self-test.

Both expose `detect(code) -> dict` and `triage(code, finding) -> dict`
returning JSON-able label dicts (see model/prompts.py key sets).
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List

from model.prompts import build_messages_detect, build_messages_triage

DEFAULT_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"


class LLMError(RuntimeError):
    pass


def _extract_json(text: str) -> dict:
    """Best-effort JSON object extraction from an LLM response."""
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    # last-resort key extraction for common label fields
    out: Dict[str, Any] = {}
    for key in ("vulnerable", "verdict", "cwe", "severity", "confidence"):
        mm = re.search(rf'"{key}"\s*:\s*("?)([^",}}\n]+)\1', text)
        if mm:
            val = mm.group(2).strip()
            if key in {"vulnerable", "verdict"} and val.lower() in {"true", "confirm"}:
                out[key] = True if key == "vulnerable" else "Confirm"
            elif key == "vulnerable" and val.lower() in {"false", "reject"}:
                out[key] = False
            else:
                out[key] = val
    return out


class CloudBackend:
    """OpenAI-compatible chat-completions backend."""

    def __init__(self, model_id: str | None = None, api_key: str | None = None,
                 base_url: str | None = None, timeout: float = 60.0):
        import requests
        self._requests = requests
        self.model_id = model_id or os.getenv("LLM_MODEL_ID", "qwen3-4b")
        self.api_key = api_key if api_key is not None else os.getenv("LLM_API_KEY", "")
        self.base_url = (base_url or os.getenv("LLM_BASE_URL", "") or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        if not self.api_key:
            raise LLMError("CloudBackend requires LLM_API_KEY (or api_key=…). Use kind=mock for tests.")

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.1) -> str:
        # Qwen3-family models default to thinking mode, which is incompatible with
        # non-streaming requests: the API requires enable_thinking=false. We need
        # direct JSON answers (detect/triage), so disable it explicitly.
        payload = {"model": self.model_id, "messages": messages,
                   "temperature": temperature, "enable_thinking": False}
        try:
            resp = self._requests.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json=payload,
                timeout=self.timeout,
            )
        except Exception as e:  # network / timeout
            raise LLMError(f"Cloud request failed: {e}") from e
        if resp.status_code != 200:
            raise LLMError(f"Cloud API {resp.status_code}: {resp.text[:300]}")
        try:
            return resp.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as e:
            raise LLMError(f"Unexpected cloud response shape: {e}") from e

    def detect(self, code: str) -> dict:
        text = self.chat(build_messages_detect(code))
        return _extract_json(text)

    def triage(self, code: str, finding: str) -> dict:
        text = self.chat(build_messages_triage(code, finding))
        return _extract_json(text)


class MockBackend:
    """Deterministic stand-in for a base model (placeholder until FT model exists).

    detect : keyword signatures over the snippet -> {vulnerable, cwe, severity,
             confidence, explanation}. Deliberately narrow: general slice recall
             stays low so the real FT gain is visible later.
    triage : rejects findings that sit in test/fixture code, confirms otherwise.
    """

    # (regex, cwe, severity, note) — ordered, first match wins
    DETECT_SIGNALS = [
        (r"hashlib\.md5|hashlib\.new\(\s*[\"']md5", "CWE-327", "MEDIUM", "MD5 used"),
        (r"hashlib\.sha1|hashlib\.new\(\s*[\"']sha1", "CWE-327", "MEDIUM", "SHA-1 used"),
        (r"AES\.MODE_ECB|modes\.ECB", "CWE-327", "HIGH", "AES-ECB leaks patterns"),
        (r"AES\.new\([^)]*,\s*(b?\"\s*\"|bytes\(\s*16\s*\))|modes\.CBC\(\s*b?\"\"\)",
         "CWE-329", "HIGH", "predictable IV"),
        (r"AES\.new\(\s*b?[\"'][^\"']+[\"']", "CWE-321", "HIGH", "hard-coded key"),
        (r"(?:iv|salt|token|nonce|secret|password)\s*=\s*random\.", "CWE-338",
         "HIGH", "random module for secret"),
        (r"RSA\.generate\(\s*(?:512|768|1024)\s*\)", "CWE-326", "HIGH", "weak RSA key"),
        (r"PROTOCOL_(SSLv3|SSLv2|TLSv1\b|TLSv1_1)|_create_unverified_context|CERT_NONE|verify=False",
         "CWE-326", "HIGH", "insecure TLS"),
        (r"os\.system\(|subprocess\.(?:Popen|call|run)\([^)]*\+", "CWE-078",
         "HIGH", "command construction"),
        (r"pickle\.(?:loads?|load)\(", "CWE-502", "HIGH", "unsafe deserialization"),
        (r"yaml\.load\(", "CWE-502", "HIGH", "unsafe yaml.load"),
        (r"\beval\(|\bexec\(", "CWE-094", "HIGH", "dynamic code execution"),
        (r"cursor\.execute\([^)]*[+%]|\.execute\(\s*f[\"']", "CWE-089",
         "HIGH", "SQL built by concatenation"),
    ]

    def detect(self, code: str) -> dict:
        for rx, cwe, sev, note in self.DETECT_SIGNALS:
            if re.search(rx, code, re.IGNORECASE):
                return {
                    "vulnerable": True, "cwe": cwe, "severity": sev,
                    "confidence": "MEDIUM", "explanation": note,
                }
        return {"vulnerable": False, "cwe": "", "severity": "", "confidence": "HIGH",
                "explanation": "No known-misuse signature found."}

    def triage(self, code: str, finding: str) -> dict:
        # fixture/test code -> Reject; anything else -> Confirm.
        is_test = bool(re.search(r"^(async\s+)?def\s+test_", code, re.MULTILINE)) or "/test" in (code[:300].lower())
        if is_test:
            return {"verdict": "Reject", "cwe": "", "severity": "INFO", "confidence": "HIGH",
                    "explanation": "Finding sits in test/fixture code; not security-sensitive."}
        return {"verdict": "Confirm", "cwe": "", "severity": "HIGH", "confidence": "MEDIUM",
                "explanation": "Pattern matches real code path; keep candidate."}

    # chat() keeps the backend usable as a plain model drop-in if needed.
    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.1) -> str:
        user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        if "Task: triage" in user:
            code = user.split("Code:", 1)[1] if "Code:" in user else user
            return json.dumps(self.triage(code, ""))
        code = user.split("Code:", 1)[1] if "Code:" in user else user
        return json.dumps(self.detect(code))


def get_backend(kind: str | None = None, config: dict | None = None):
    """Factory. kind in {mock, cloud}; config/model env supply cloud params."""
    cfg = (config or {}).get("model", {}) if config else {}
    kind = (kind or cfg.get("kind") or
            ("cloud" if os.getenv("LLM_API_KEY") else "mock"))
    if kind == "cloud":
        return CloudBackend(
            model_id=cfg.get("model_id") or os.getenv("LLM_MODEL_ID"),
            api_key=cfg.get("api_key"),
            base_url=cfg.get("base_url"),
        )
    if kind == "mock":
        return MockBackend()
    raise LLMError(f"Unknown model kind {kind!r} (expected 'mock' or 'cloud')")
