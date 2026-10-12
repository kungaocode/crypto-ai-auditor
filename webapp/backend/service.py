"""Audit orchestration: static scan -> model triage -> remediation."""

from __future__ import annotations

import ast
import json
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.agent import SecurityAgent
from model import inference as model_inf

from . import config, patches
from .scanners import RULE_META, SourceFile, attach_context, scan_sources

SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 5, "INFO": 1}
_SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

DEFAULT_MAX_MODEL_FINDINGS = 24
MAX_DETECT_CHARS = 24_000


class AuditError(RuntimeError):
    """User-facing audit failure."""


# ---------------------------------------------------------------------------
# Model backend
# ---------------------------------------------------------------------------

def build_backend(requested_mode: str = "auto"):
    mode = (requested_mode or "auto").strip().lower()
    if mode not in config.MODEL_MODES:
        mode = "auto"

    api_key = config.resolve_api_key()
    if mode == "auto":
        effective = "cloud" if config.env_api_key() else "mock"
    else:
        effective = mode
    if effective == "cloud" and not api_key:
        raise config.ConfigError(
            "云模型模式需要 LLM_API_KEY（或项目根目录 api.txt 中的密钥）。"
        )

    cfg = {
        "model": {
            "kind": effective,
            "model_id": config.model_id(),
            "api_key": api_key,
            "base_url": config.base_url(),
        }
    }
    backend = model_inf.get_backend(kind=effective, config=cfg)
    if effective == "cloud":
        backend.timeout = config.timeout_seconds()

    meta = {
        "kind": effective,
        "requested_mode": mode,
        "model_id": config.model_id() if effective == "cloud" else "mock-deterministic",
        "cloud_configured": bool(api_key),
        "workspace_configured": bool(config.public_model_state()["workspace_configured"]),
        "label": "微调模型" if effective == "cloud" else "离线规则引擎",
    }
    return backend, meta


def _extract_json(text: str) -> dict[str, Any]:
    if not text:
        return {}
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            value = json.loads(match.group(0))
            return value if isinstance(value, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


PATCH_SYSTEM_PROMPT = (
    "You are a senior Python cryptographic security engineer. "
    "Return JSON only with keys: patched_code, explanation, changes. "
    "patched_code must be the complete corrected file, preserve public API and "
    "comments, and must keep the code syntactically valid. Apply the smallest "
    "safe change for each confirmed finding. Use standard-library primitives "
    "(secrets, os.urandom, hmac.compare_digest) and well-known crypto libraries."
)


def _is_valid_python(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def _model_patch(
    backend,
    source_file: SourceFile,
    findings: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if source_file.language != "python" or not findings or len(source_file.source) > MAX_DETECT_CHARS:
        return None
    finding_lines = "\n".join(
        f"- [{f['rule_id']}] line {f['line']}: {f['message']}" for f in findings
    )
    user_prompt = (
        f"Task: patch\nLanguage: python\n"
        f"Confirmed findings:\n{finding_lines}\n"
        f"Code:\n{source_file.source}"
    )
    try:
        text = backend.chat(
            [
                {"role": "system", "content": PATCH_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.0,
        )
    except Exception:
        return None
    data = _extract_json(text)
    patched = data.get("patched_code") or data.get("code")
    if not isinstance(patched, str) or len(patched.strip()) < 20:
        return None
    if not _is_valid_python(patched):
        return None
    return {
        "patched_code": patched,
        "explanation": str(data.get("explanation", "")).strip(),
        "changes": data.get("changes") if isinstance(data.get("changes"), list) else [],
    }


# ---------------------------------------------------------------------------
# Model triage
# ---------------------------------------------------------------------------

def _triage_finding(agent: SecurityAgent, finding: dict[str, Any]) -> dict[str, Any]:
    code = finding.get("context_snippet") or finding.get("snippet") or ""
    label = f"[{finding['rule_id']}] {finding.get('message', '')}"
    try:
        verdict = agent.triage_one(code, label)
    except Exception as exc:  # defensive: never fail the whole audit on one call
        return {
            "verdict": "UNCERTAIN",
            "confidence": 0.2,
            "explanation": f"模型研判调用失败：{exc}",
            "cwe": finding.get("cwe", "CWE-UNKNOWN"),
            "severity": finding.get("severity", "MEDIUM"),
            "patch": "",
        }
    explanation = str(verdict.get("explanation", ""))
    if "LLM unavailable" in explanation:
        verdict["verdict"] = "UNCERTAIN"
        verdict["confidence"] = 0.2
    return verdict


def _merge_verdict(finding: dict[str, Any], verdict: dict[str, Any]) -> None:
    model_cwe = verdict.get("cwe")
    if isinstance(model_cwe, (list, tuple)):
        model_cwe = model_cwe[0] if model_cwe else ""
    model_severity = str(verdict.get("severity") or "").upper()
    if model_severity not in SEVERITY_WEIGHT:
        model_severity = finding.get("severity", "MEDIUM")
    finding["verdict"] = str(verdict.get("verdict") or "UNCERTAIN").upper()
    finding["confidence"] = round(float(verdict.get("confidence") or 0.5), 2)
    finding["explanation"] = str(verdict.get("explanation") or "").strip()
    finding["model_patch"] = str(verdict.get("patch") or "").strip()
    finding["model"] = {
        "cwe": str(model_cwe or "").strip(),
        "severity": model_severity,
        "explanation": finding["explanation"],
    }
    finding["source"] = "static+model"
    finding["remediation"] = patches.fix_for(finding["rule_id"])


# ---------------------------------------------------------------------------
# Whole-file model detection
# ---------------------------------------------------------------------------

def _detect_sources(
    agent: SecurityAgent,
    sources: list[SourceFile],
    static_findings: list[dict[str, Any]],
    kind: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    detections: list[dict[str, Any]] = []
    synthetic: list[dict[str, Any]] = []
    files_with_static: dict[str, set[str]] = {}
    for finding in static_findings:
        files_with_static.setdefault(finding["file"], set()).add(finding["cwe"])

    for source_file in sources[:8]:
        if source_file.language != "python" or len(source_file.source) > MAX_DETECT_CHARS:
            continue
        try:
            result = agent.detect(source_file.source)
        except Exception as exc:
            detections.append(
                {
                    "file": source_file.name,
                    "vulnerable": None,
                    "cwe": "",
                    "severity": "",
                    "confidence": "",
                    "explanation": f"模型检测失败：{exc}",
                    "engine": kind,
                }
            )
            continue
        detection = {
            "file": source_file.name,
            "vulnerable": bool(result.get("vulnerable")),
            "cwe": str(result.get("cwe") or ""),
            "severity": str(result.get("severity") or "").upper(),
            "confidence": str(result.get("confidence") or ""),
            "explanation": str(result.get("explanation") or "").strip(),
            "engine": kind,
        }
        detections.append(detection)
        if detection["vulnerable"] and detection["cwe"] not in files_with_static.get(source_file.name, set()):
            severity = detection["severity"] if detection["severity"] in SEVERITY_WEIGHT else "MEDIUM"
            confidence = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9}.get(
                detection["confidence"].upper(), 0.5
            )
            synthetic.append(
                {
                    "rule_id": "MODEL-DETECT",
                    "title": "模型独立发现的漏洞",
                    "title_en": "Model-detected vulnerability",
                    "category": "模型研判",
                    "message": detection["explanation"] or "微调模型在该文件中发现了潜在密码学漏洞。",
                    "severity": severity,
                    "cwe": detection["cwe"] or "CWE-UNKNOWN",
                    "language": source_file.language,
                    "file": source_file.name,
                    "line": 0,
                    "column": 0,
                    "end_line": 0,
                    "end_column": 0,
                    "snippet": "",
                    "fix_suggestion": "",
                    "engine": "model",
                    "verdict": "CONFIRMED",
                    "confidence": confidence,
                    "explanation": detection["explanation"],
                    "model_patch": "",
                    "model": {
                        "cwe": detection["cwe"],
                        "severity": severity,
                        "explanation": detection["explanation"],
                    },
                    "source": "model",
                    "context_lines": [],
                    "context_snippet": source_file.source,
                    "fingerprint": f"MODEL-DETECT:{source_file.name}",
                    "remediation": patches.fix_for(detection["cwe"]),
                }
            )
    return detections, synthetic


# ---------------------------------------------------------------------------
# Risk scoring and insights
# ---------------------------------------------------------------------------

def risk_assessment(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = {level: 0 for level in _SEVERITY_ORDER}
    verdict_counts = {"CONFIRMED": 0, "REJECTED": 0, "UNCERTAIN": 0}
    score = 0.0
    for finding in findings:
        severity = str(finding.get("severity", "MEDIUM")).upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
        verdict = str(finding.get("verdict", "UNCERTAIN")).upper()
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        if verdict == "REJECTED":
            continue
        weight = SEVERITY_WEIGHT.get(severity, 8)
        confidence = float(finding.get("confidence") or 0.5)
        factor = confidence if verdict == "CONFIRMED" else confidence * 0.5
        score += weight * factor

    score = int(min(100, round(score)))
    if score >= 75:
        level, label = "CRITICAL", "严重"
    elif score >= 50:
        level, label = "HIGH", "高风险"
    elif score >= 20:
        level, label = "MEDIUM", "中风险"
    elif score > 0:
        level, label = "LOW", "低风险"
    else:
        level, label = "INFO", "未发现风险"

    return {
        "score": score,
        "level": level,
        "label": label,
        "severity_counts": severity_counts,
        "verdict_counts": verdict_counts,
    }


def build_insights(findings: list[dict[str, Any]]) -> dict[str, Any]:
    category_counts: dict[str, int] = {}
    cwe_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    files: dict[str, int] = {}
    for finding in findings:
        category_counts[finding.get("category", "其他")] = category_counts.get(finding.get("category", "其他"), 0) + 1
        cwe_counts[finding.get("cwe", "CWE-UNKNOWN")] = cwe_counts.get(finding.get("cwe", "CWE-UNKNOWN"), 0) + 1
        rule_counts[finding.get("rule_id", "UNKNOWN")] = rule_counts.get(finding.get("rule_id", "UNKNOWN"), 0) + 1
        files[finding.get("file", "")] = files.get(finding.get("file", ""), 0) + 1
    return {
        "by_category": category_counts,
        "by_cwe": cwe_counts,
        "by_rule": rule_counts,
        "by_file": files,
    }


def _narrative(risk: dict[str, Any], findings: list[dict[str, Any]], model_meta: dict[str, Any]) -> str:
    confirmed = risk["verdict_counts"].get("CONFIRMED", 0)
    total = len(findings)
    if total == 0:
        return f"{model_meta['label']}与静态规则均未发现密码学缺陷。"
    top = sorted(
        (f for f in findings if f.get("verdict") != "REJECTED"),
        key=lambda f: (SEVERITY_WEIGHT.get(f.get("severity", "MEDIUM"), 0), f.get("confidence", 0)),
        reverse=True,
    )[:3]
    focus = "、".join(f"{f['rule_id']} {f.get('title', '')}" for f in top)
    return (
        f"共检测到 {total} 条候选问题，其中 {confirmed} 条被模型确认，"
        f"综合风险 {risk['score']}/100（{risk['label']}）。优先处理：{focus}。"
    )


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

def build_remediation(
    sources: list[SourceFile],
    findings: list[dict[str, Any]],
    backend,
    model_meta: dict[str, Any],
    generate_patches: bool,
) -> dict[str, Any]:
    confirmed_by_file: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        if finding.get("verdict") == "CONFIRMED" and finding.get("line"):
            confirmed_by_file.setdefault(finding["file"], []).append(finding)

    files: list[dict[str, Any]] = []
    all_rule_ids: set[str] = set()
    for source_file in sources:
        confirmed = confirmed_by_file.get(source_file.name, [])
        if not confirmed:
            continue
        all_rule_ids.update(f["rule_id"] for f in confirmed)
        mechanical_code, mechanical_changes = patches.apply_mechanical_fixes(
            source_file.source, {f["rule_id"] for f in confirmed}
        )
        entry: dict[str, Any] = {
            "name": source_file.name,
            "language": source_file.language,
            "original": source_file.source,
            "fixed": mechanical_code,
            "changes": mechanical_changes,
            "diff": patches.unified_diff(source_file.source, mechanical_code, source_file.name),
            "source": "mechanical" if mechanical_changes else "guidance",
            "notes": [],
        }
        if (
            generate_patches
            and model_meta["kind"] == "cloud"
            and source_file.language == "python"
            and len(files) < 4
        ):
            model_result = _model_patch(backend, source_file, confirmed)
            if model_result:
                entry["fixed"] = model_result["patched_code"]
                entry["diff"] = patches.unified_diff(
                    source_file.source, model_result["patched_code"], source_file.name
                )
                entry["source"] = "model"
                entry["notes"] = [str(note) for note in model_result["changes"]][:12]
                if model_result["explanation"]:
                    entry["notes"].insert(0, model_result["explanation"])
        files.append(entry)

    return {
        "files": files,
        "suggestions": patches.suggestions_for(all_rule_ids),
        "has_changes": any(entry["diff"] for entry in files),
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_audit(
    sources: list[SourceFile],
    target_dir: Path,
    rules_dir: Path,
    *,
    model_mode: str = "auto",
    generate_patches: bool = True,
    extended: bool = False,
    max_model_findings: int = DEFAULT_MAX_MODEL_FINDINGS,
) -> dict[str, Any]:
    started = time.perf_counter()
    if not sources:
        raise AuditError("没有可审计的代码文件。")

    scan = scan_sources(sources, target_dir, rules_dir, extended=extended)
    findings = scan.findings

    # 1. Model triage over static candidates.
    backend, model_meta = build_backend(model_mode)
    agent = SecurityAgent(backend=backend)
    triaged = 0
    if findings:
        workers = 3 if model_meta["kind"] == "cloud" else 8
        capped = findings[:max_model_findings]
        with ThreadPoolExecutor(max_workers=min(workers, max(1, len(capped)))) as pool:
            verdicts = list(pool.map(lambda f: _triage_finding(agent, f), capped))
        for finding, verdict in zip(capped, verdicts):
            _merge_verdict(finding, verdict)
            triaged += 1
        for finding in findings[max_model_findings:]:
            finding["verdict"] = "UNCERTAIN"
            finding["confidence"] = 0.3
            finding["explanation"] = "超出本次模型研判上限，仅保留静态规则结论。"
            finding["model_patch"] = ""
            finding["model"] = {"cwe": "", "severity": finding["severity"], "explanation": finding["explanation"]}
            finding["source"] = "static"
            finding["remediation"] = patches.fix_for(finding["rule_id"])

    # 2. Whole-file model detection adds findings static rules may miss.
    detections, synthetic = _detect_sources(agent, sources, findings, model_meta["kind"])
    for finding in synthetic:
        finding["remediation"] = patches.fix_for(finding["rule_id"])
    findings.extend(synthetic)

    if not findings:
        pass

    # 3. Remediation artifacts.
    remediation = build_remediation(
        sources, findings, backend, model_meta, generate_patches
    )

    # 4. Aggregates.
    risk = risk_assessment(findings)
    insights = build_insights(findings)
    duration_ms = int((time.perf_counter() - started) * 1000)
    created_at = datetime.now(timezone.utc).isoformat()
    total_bytes = sum(len(source.source.encode("utf-8")) for source in sources)
    total_lines = sum(len(source.lines) for source in sources)

    model_detected = any(item.get("vulnerable") for item in detections)
    result = {
        "audit_id": uuid.uuid4().hex[:16],
        "created_at": created_at,
        "target": {
            "files": [
                {
                    "name": source.name,
                    "language": source.language,
                    "lines": len(source.lines),
                    "bytes": len(source.source.encode("utf-8")),
                }
                for source in sources
            ],
            "primary": sources[0].name,
            "file_count": len(sources),
            "line_count": total_lines,
            "byte_count": total_bytes,
        },
        "engine": {
            "static": scan.engines,
            "model": model_meta,
            "duration_ms": duration_ms,
            "triaged_findings": triaged,
            "extended": extended,
        },
        "summary": {
            "risk": risk,
            "total_findings": len(findings),
            "model_detected_vulnerable": model_detected,
            "model_detections": detections,
            "narrative": _narrative(risk, findings, model_meta),
        },
        "insights": insights,
        "findings": findings,
        "remediation": remediation,
    }
    return result


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def build_markdown_report(result: dict[str, Any]) -> str:
    target = result.get("target", {})
    summary = result.get("summary", {})
    risk = summary.get("risk", {})
    engine = result.get("engine", {})
    model = engine.get("model", {})
    lines = [
        "# 密码学代码安全审计报告",
        "",
        f"- 审计 ID：`{result.get('audit_id', '-')}`",
        f"- 生成时间：{result.get('created_at', '-')}",
        f"- 目标文件：{target.get('file_count', 0)} 个（{target.get('line_count', 0)} 行）",
        f"- 静态引擎：Semgrep={engine.get('static', {}).get('semgrep')} / AST={engine.get('static', {}).get('ast')} / Pattern=True",
        f"- 模型：{model.get('label', '-')}（{model.get('model_id', '-')}）",
        f"- 风险评分：{risk.get('score', 0)}/100（{risk.get('label', '-')}）",
        "",
        "## 结论",
        "",
        summary.get("narrative", ""),
        "",
        "## 漏洞清单",
        "",
        "| 规则 | 严重度 | CWE | 位置 | 模型结论 | 置信度 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for finding in result.get("findings", []):
        location = finding.get("file", "")
        if finding.get("line"):
            location += f":{finding['line']}"
        lines.append(
            f"| {finding.get('rule_id')} | {finding.get('severity')} | {finding.get('cwe')} | "
            f"{location} | {finding.get('verdict', '-')} | {finding.get('confidence', '-')} |"
        )

    lines += ["", "## 漏洞详情", ""]
    for finding in result.get("findings", []):
        lines.append(f"### {finding.get('rule_id')} · {finding.get('title')}")
        lines.append("")
        lines.append(f"- 严重度：{finding.get('severity')} / {finding.get('cwe')}")
        lines.append(f"- 位置：{finding.get('file')}" + (f":{finding['line']}" if finding.get("line") else ""))
        lines.append(f"- 规则说明：{finding.get('message', '')}")
        lines.append(f"- 模型研判：{finding.get('verdict')}（置信度 {finding.get('confidence')}）")
        if finding.get("explanation"):
            lines.append(f"- 分析：{finding['explanation']}")
        fix = patches.fix_for(finding.get("rule_id", ""))
        if fix:
            lines.append(f"- 修复建议：{fix.get('summary', '')}")
            lines.append("")
            lines.append("```python")
            lines.append(fix.get("good", ""))
            lines.append("```")
        lines.append("")

    remediation = result.get("remediation", {})
    if remediation.get("files"):
        lines += ["## 优化代码", ""]
        for entry in remediation["files"]:
            lines.append(f"### {entry['name']}（{entry['source']}）")
            lines.append("")
            lines.append("```diff")
            lines.extend(entry.get("diff", []))
            lines.append("```")
            lines.append("")
    return "\n".join(lines).strip() + "\n"
