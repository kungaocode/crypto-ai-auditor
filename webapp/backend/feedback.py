"""Persist audited source files as review-pending retraining candidates."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Iterable

from . import config

SCHEMA_VERSION = 1
DATASET_NAME = "submissions.jsonl"
_WRITE_LOCK = threading.Lock()
_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _relative_path(path: Path) -> str:
    try:
        return str(path.relative_to(config.PROJECT_ROOT))
    except ValueError:
        return str(path)


def _confidence(value: Any) -> float:
    try:
        return round(max(0.0, min(1.0, float(value))), 2)
    except (TypeError, ValueError):
        return 0.5


def _candidate_label(
    findings: list[dict[str, Any]],
    file_name: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    active = [
        finding
        for finding in findings
        if str(finding.get("verdict") or "UNCERTAIN").upper() != "REJECTED"
    ]
    detection = next(
        (
            item
            for item in result.get("summary", {}).get("model_detections", [])
            if item.get("file") == file_name
        ),
        None,
    )

    if active:
        top = max(
            active,
            key=lambda item: (
                _SEVERITY_RANK.get(str(item.get("severity") or "INFO").upper(), 0),
                _confidence(item.get("confidence")),
            ),
        )
        confirmed = sum(
            1
            for item in active
            if str(item.get("verdict") or "").upper() == "CONFIRMED"
        )
        return {
            "vulnerable": True,
            "cwe": top.get("cwe") or "CWE-UNKNOWN",
            "severity": str(top.get("severity") or "MEDIUM").upper(),
            "confidence": _confidence(top.get("confidence")),
            "explanation": str(
                top.get("explanation")
                or top.get("message")
                or "Web audit produced a review-pending finding."
            ),
            "candidate_verdict": "Confirm" if confirmed else "Review",
        }

    if detection and detection.get("vulnerable") is True:
        return {
            "vulnerable": True,
            "cwe": detection.get("cwe") or "CWE-UNKNOWN",
            "severity": str(detection.get("severity") or "MEDIUM").upper(),
            "confidence": _confidence(
                {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9}.get(
                    str(detection.get("confidence") or "").upper(),
                    0.5,
                )
            ),
            "explanation": str(
                detection.get("explanation")
                or "Whole-file model detection produced a review-pending candidate."
            ),
            "candidate_verdict": "Review",
        }

    return {
        "vulnerable": False,
        "cwe": "",
        "severity": "INFO",
        "confidence": 0.5,
        "explanation": "No static or model candidate was retained for this file.",
        "candidate_verdict": "Reject",
    }


def _finding_context(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keys = (
        "rule_id",
        "title",
        "category",
        "message",
        "severity",
        "cwe",
        "line",
        "verdict",
        "confidence",
        "explanation",
        "model_patch",
        "source",
    )
    return [
        {key: finding.get(key) for key in keys if finding.get(key) not in (None, "")}
        for finding in findings
    ]


def _record_for_source(
    source: Any,
    index: int,
    result: dict[str, Any],
    options: dict[str, Any],
) -> dict[str, Any]:
    findings = [
        finding
        for finding in result.get("findings", [])
        if finding.get("file") == source.name
    ]
    engine = result.get("engine", {})
    model = engine.get("model", {})
    code_sha256 = _sha256(source.source)
    return {
        "id": f"web-{result.get('audit_id', 'unknown')}-{index:03d}",
        "schema_version": SCHEMA_VERSION,
        "audit_id": result.get("audit_id"),
        "created_at": result.get("created_at"),
        "task": "triage" if findings else "detect",
        "language": source.language,
        "file": source.name,
        "code": source.source,
        "code_sha256": code_sha256,
        "bytes": len(source.source.encode("utf-8")),
        "lines": len(source.lines),
        "label": _candidate_label(findings, source.name, result),
        "findings": _finding_context(findings),
        "provenance": {
            "source": "webapp_user_submission",
            "label_origin": "static_and_model_assisted",
            "requested_model_mode": options.get("model_mode", "auto"),
            "effective_model_kind": model.get("kind", ""),
            "model_id": model.get("model_id", ""),
            "extended_scan": bool(options.get("extended", False)),
            "patches_requested": bool(options.get("generate_patches", True)),
        },
        "verified": False,
        "review_status": "pending",
        "training_ready": False,
    }


def public_state() -> dict[str, Any]:
    directory = config.feedback_dir()
    dataset = directory / DATASET_NAME
    return {
        "enabled": config.feedback_enabled(),
        "directory": _relative_path(directory),
        "dataset": _relative_path(dataset),
        "dataset_exists": dataset.is_file(),
    }


def record_audit(
    sources: Iterable[Any],
    result: dict[str, Any],
    options: dict[str, Any],
) -> dict[str, Any]:
    """Append one JSONL row per source file without failing the audit."""
    state = public_state()
    if not state["enabled"]:
        return {**state, "stored_samples": 0}

    records = [
        _record_for_source(source, index, result, options)
        for index, source in enumerate(sources, start=1)
    ]
    if not records:
        return {**state, "stored_samples": 0}

    directory = config.feedback_dir()
    dataset = directory / DATASET_NAME
    try:
        payload = "".join(
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
            for record in records
        )
        directory.mkdir(parents=True, exist_ok=True)
        with _WRITE_LOCK:
            with dataset.open("a", encoding="utf-8") as handle:
                handle.write(payload)
    except (OSError, TypeError, ValueError) as exc:
        return {
            **state,
            "stored_samples": 0,
            "error": f"回流数据写入失败：{exc}",
        }
    return {
        **state,
        "dataset_exists": True,
        "stored_samples": len(records),
    }
