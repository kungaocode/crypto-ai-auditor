"""Runtime configuration for the CryptoAudit web application.

The web app is a thin orchestration layer over the repository's existing
assets: Semgrep rules in ``rules/``, the AST scanner in ``security/audit`` and
the fine-tuned model backend in ``model/inference.py``.

Only environment variables (and an optional local ``api.txt``) are used for
credentials.  Secrets are never written to disk, logged or returned by the API.
"""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = PROJECT_ROOT / "webapp" / "frontend"
RULES_DIR = PROJECT_ROOT / "rules"
DEFAULT_FEEDBACK_DIR = PROJECT_ROOT / "data" / "webapp_feedback"

DEFAULT_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
DEFAULT_MODEL_ID = "qwen3-4b-instruct-2507-5f8261ad123d"

MODEL_MODES = ("auto", "cloud", "mock")


class ConfigError(RuntimeError):
    """Raised when the requested model mode cannot be satisfied."""


def _read_key_file(path: Path) -> str:
    """Return the first usable key from a local credentials file.

    ``api.txt`` in this repository stores one key per line.  Blank lines and
    comments are ignored.  Values are stripped and never echoed anywhere.
    """
    if not path.is_file():
        return ""
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            if value.lower().startswith(("api_key", "key", "token")):
                _, _, value = value.partition("=")
                value = value.strip()
            if value:
                return value
    except OSError:
        return ""
    return ""


def resolve_api_key() -> str:
    """Resolve the model API key without exposing it.

    Priority: ``LLM_API_KEY`` / ``DASHSCOPE_API_KEY`` environment variables,
    then ``LLM_API_KEY_FILE``, then the repository's ``api.txt`` when
    ``CRYPTOAUDIT_READ_API_FILE`` is not explicitly disabled.
    """
    for name in ("LLM_API_KEY", "DASHSCOPE_API_KEY"):
        value = os.getenv(name, "").strip()
        if value:
            return value

    explicit = os.getenv("LLM_API_KEY_FILE", "").strip()
    if explicit:
        return _read_key_file(Path(explicit).expanduser())

    if os.getenv("CRYPTOAUDIT_READ_API_FILE", "1").lower() in {"0", "false", "no"}:
        return ""
    return _read_key_file(PROJECT_ROOT / "api.txt")


def env_api_key() -> str:
    """API key supplied explicitly through the environment.

    ``auto`` mode only selects the cloud model when a key was provided
    explicitly.  A key discovered through ``api.txt`` is treated as an opt-in
    convenience for the manual "微调模型" mode and never silently overrides
    the deterministic offline engine.
    """
    for name in ("LLM_API_KEY", "DASHSCOPE_API_KEY"):
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def model_id() -> str:
    return os.getenv("LLM_MODEL_ID", "").strip() or DEFAULT_MODEL_ID


def base_url() -> str:
    return os.getenv("LLM_BASE_URL", "").strip() or DEFAULT_BASE_URL


def timeout_seconds() -> float:
    raw = os.getenv("LLM_TIMEOUT", "30").strip()
    try:
        return max(5.0, float(raw))
    except ValueError:
        return 30.0


def cloud_ready() -> bool:
    return bool(resolve_api_key())


def public_model_state() -> dict:
    """Non-sensitive model state safe to expose through ``/api/health``."""
    return {
        "cloud_configured": cloud_ready(),
        "model_id": model_id(),
        "base_url": base_url(),
        "workspace_configured": bool(os.getenv("LLM_WORKSPACE", "").strip()),
    }


def max_upload_bytes() -> int:
    raw = os.getenv("CRYPTOAUDIT_MAX_UPLOAD_MB", "16").strip()
    try:
        megabytes = max(1, int(raw))
    except ValueError:
        megabytes = 16
    return megabytes * 1024 * 1024


def feedback_enabled() -> bool:
    """Whether audited source files are retained for later retraining."""
    return os.getenv("CRYPTOAUDIT_FEEDBACK", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def feedback_dir() -> Path:
    """Directory for locally retained, review-pending audit samples."""
    raw = os.getenv("CRYPTOAUDIT_FEEDBACK_DIR", "").strip()
    if not raw:
        return DEFAULT_FEEDBACK_DIR
    path = Path(raw).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path
