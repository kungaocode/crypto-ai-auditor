"""Expose the Semgrep rule set as structured metadata for the UI."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from .scanners import RULE_META

try:
    import yaml
except Exception:  # pragma: no cover - PyYAML is an install requirement
    yaml = None  # type: ignore[assignment]


def _first(data: Any, key: str, default: Any = None) -> Any:
    if isinstance(data, dict):
        return data.get(key, default)
    return default


def _load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


@lru_cache(maxsize=1)
def load_catalog(rules_dir: Path) -> list[dict[str, Any]]:
    catalog: list[dict[str, Any]] = []
    if not rules_dir.is_dir():
        return catalog
    for rule_file in sorted(rules_dir.glob("*/rule.yaml")):
        data = _load_yaml(rule_file)
        rules = data.get("rules") or []
        rule = rules[0] if rules else {}
        rule_id = str(rule.get("id") or rule_file.parent.name).strip()
        metadata = rule.get("metadata") or {}
        fallback = RULE_META.get(rule_id, {})
        languages = rule.get("languages") or ["python"]
        catalog.append(
            {
                "id": rule_id,
                "title": fallback.get("title", rule_id),
                "title_en": fallback.get("title_en", ""),
                "category": fallback.get("category", "其他"),
                "severity": str(metadata.get("severity") or fallback.get("severity", "MEDIUM")).upper(),
                "cwe": str(metadata.get("cwe") or fallback.get("cwe", "CWE-UNKNOWN")),
                "message": rule.get("message", ""),
                "fix": rule.get("fix", ""),
                "languages": list(languages),
                "directory": rule_file.parent.name,
                "source": str(rule_file.relative_to(rules_dir.parent)),
            }
        )
    return catalog


def catalog_stats(catalog: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for rule in catalog:
        by_severity[rule["severity"]] = by_severity.get(rule["severity"], 0) + 1
        by_category[rule["category"]] = by_category.get(rule["category"], 0) + 1
    return {"total": len(catalog), "by_severity": by_severity, "by_category": by_category}
