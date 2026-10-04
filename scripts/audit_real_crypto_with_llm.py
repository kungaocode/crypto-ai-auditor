#!/usr/bin/env python3
"""Pre-audit real crypto candidates with a strong model.

The model is asked for a strict binary decision: ``confirmed`` or ``rejected``.
Model failures remain ``error`` rows and must never be imported as labels.
Successful verdicts may be imported by ``scripts/import_model_audit_verdicts.py``
with explicit model provenance.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_round6_final_dataset import RULE_CWE, TARGET_CWES  # noqa: E402


DEFAULT_CANDIDATES = [
    ROOT / "data/round6/candidates/real_crypto_candidates_enriched.jsonl",
    ROOT / "data/round6/candidates/real_crypto_candidates.jsonl",
]
DEFAULT_MODEL_OUT = ROOT / "data/round6/candidates/model_audit.jsonl"
DEFAULT_QUEUE_OUT = ROOT / "data/round6/candidates/real_crypto_candidates_uncertain.jsonl"
DEFAULT_COST_REPORT = ROOT / "reports/data_quality/model_audit_cost.json"
DEFAULT_ADVISORY_DIR = ROOT / "data/external/osv-pypi"
API_KEY_FILES = [ROOT / "api.txt", ROOT / "apitxt"]

DECISIONS = {"confirmed", "rejected"}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
CODE_PAIR_QUALITIES = {"complete", "partial", "missing", "not_applicable"}


class AuditTransportError(RuntimeError):
    """Raised when the model endpoint cannot be reached."""


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)

SYSTEM_PROMPT = """You are a senior Python application-security auditor specializing in cryptographic misuse.

Audit the supplied real-package advisory candidate independently. Treat the candidate CWE and
rule as hypotheses, not ground truth. Decide whether the vulnerable/fixed code pair demonstrates
a real security defect that belongs to this project's target taxonomy.

Rules:
1. Confirmed means the vulnerable code actually performs security-sensitive cryptographic
   misuse and the fixed code materially corrects it. Do not confirm library bugs, dependency
   upgrades, parser defects, test-only code, or unrelated code merely because the CVE mentions
   cryptography.
2. Rejected means the supplied evidence is sufficient to show the candidate is a false positive,
   not a real crypto-misuse fix, or outside the target taxonomy.
3. Make a binary decision. If the evidence is insufficient, contradicted, outside
   the target taxonomy, or the vulnerable/fixed pair is missing, choose rejected.
   Do not return uncertain or out_of_scope.
4. Do not invent missing code, versions, commits, licenses, or repository facts.
5. The model must never claim human verification. Output is a machine verdict.
6. Return exactly one JSON object and no Markdown or prose outside it.
"""

OUTPUT_SCHEMA = """{
  "decision": "confirmed | rejected",
  "rule_id": "CRYPTO-001..013 or null",
  "cwe": "one target CWE or null",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "confidence": 0.0,
  "license": "SPDX expression if explicitly supported by supplied evidence, otherwise null",
  "explanation": "concise reason for the decision",
  "finding": "one-line static-analysis style finding when confirmed; otherwise empty",
  "evidence_notes": "missing or contradictory evidence, if any",
  "code_pair_quality": "complete | partial | missing | not_applicable"
}"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    temp.write_text(text, encoding="utf-8")
    os.replace(temp, path)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    _atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{number}: invalid JSON ({exc})") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{number}: expected a JSON object")
        rows.append(row)
    if not rows:
        raise ValueError(f"candidate file is empty: {path}")
    return rows


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    _atomic_write_text(
        path,
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
    )


def _resolve_candidates(path: str | None) -> Path:
    if path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = ROOT / candidate
        if not candidate.exists():
            raise ValueError(f"candidate file not found: {candidate}")
        return candidate.resolve()
    for candidate in DEFAULT_CANDIDATES:
        if candidate.exists():
            return candidate
    raise ValueError(
        "no candidate file found; expected one of: "
        + ", ".join(str(path.relative_to(ROOT)) for path in DEFAULT_CANDIDATES)
    )


def resolve_api_key(api_key_file: Path | str | None = None) -> str:
    """Resolve the Moonshot key without ever printing its value."""
    for name in ("MOONSHOT_API_KEY", "KIMI_API_KEY"):
        value = os.environ.get(name, "").strip()
        if value:
            return value

    candidates = [Path(api_key_file)] if api_key_file else API_KEY_FILES
    path = next(
        (
            candidate if candidate.is_absolute() else ROOT / candidate
            for candidate in candidates
            if (candidate if candidate.is_absolute() else ROOT / candidate).exists()
        ),
        None,
    )
    if path is None:
        raise ValueError(
            "missing API key; set MOONSHOT_API_KEY or provide --api-key-file containing "
            "'kimi:' followed by the key"
        )

    lines = path.read_text(encoding="utf-8").splitlines()
    label_re = re.compile(
        r"^\s*(?:[-*]\s*)?(?:kimi|moonshot)"
        r"(?:[\s_-]*(?:api[\s_-]*)?(?:key|k[0-9][a-z0-9._-]*))?"
        r"\s*(?:[:：=]\s*(.*?))?\s*$",
        re.IGNORECASE,
    )
    for index, line in enumerate(lines):
        match = label_re.match(line)
        if not match:
            continue
        if match.group(1):
            return match.group(1).strip().strip("\"'")
        for following in lines[index + 1:]:
            value = following.strip().strip("\"'")
            if value and not value.startswith("#"):
                return value
    raise ValueError(f"could not find a non-empty 'kimi:' entry in {path}")


def estimate_tokens(text: str) -> int:
    """Conservative dependency-free token estimate for English code/prompt text."""
    ascii_chars = sum(1 for char in text if ord(char) < 128)
    non_ascii_chars = len(text) - ascii_chars
    return max(1, math.ceil(ascii_chars / 4 + non_ascii_chars / 1.5))


def _bounded_text(value: Any, limit: int) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated from {len(text)} characters]"


def _advisory_references(value: Any, limit: int = 20) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    if not isinstance(value, list):
        return references
    for item in value:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        references.append({
            "type": str(item.get("type") or "").strip(),
            "url": url,
        })
        if len(references) >= limit:
            break
    return references


def enrich_candidates_with_local_advisories(
    candidates: list[dict[str, Any]],
    *,
    advisory_dir: Path,
    max_advisory_chars: int,
) -> dict[str, int]:
    """Attach local OSV advisory text so the model can audit against the report."""
    counts = {"attached": 0, "missing": 0, "invalid": 0}
    for candidate in candidates:
        advisory_id = str(candidate.get("advisory_id") or "").strip()
        if not advisory_id:
            counts["missing"] += 1
            candidate["advisory_evidence"] = {}
            candidate["advisory_evidence_status"] = "missing advisory_id"
            continue
        path = advisory_dir / f"{advisory_id}.json"
        if not path.exists():
            counts["missing"] += 1
            candidate["advisory_evidence"] = {}
            candidate["advisory_evidence_status"] = "local advisory not found"
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            counts["invalid"] += 1
            candidate["advisory_evidence"] = {}
            candidate["advisory_evidence_status"] = "local advisory is invalid JSON"
            continue
        if not isinstance(payload, dict):
            counts["invalid"] += 1
            candidate["advisory_evidence"] = {}
            candidate["advisory_evidence_status"] = "local advisory is not an object"
            continue
        candidate["advisory_evidence"] = {
            "id": str(payload.get("id") or advisory_id),
            "summary": str(payload.get("summary") or ""),
            "details": _bounded_text(payload.get("details"), max_advisory_chars),
            "aliases": payload.get("aliases") or [],
            "published": str(payload.get("published") or ""),
            "modified": str(payload.get("modified") or ""),
            "severity": payload.get("severity") or [],
            "affected": payload.get("affected") or [],
            "references": _advisory_references(payload.get("references")),
        }
        candidate["advisory_evidence_status"] = "attached local OSV record"
        candidate["advisory_evidence_path"] = _display_path(path)
        counts["attached"] += 1
    return counts


def build_messages(candidate: dict[str, Any], *, max_code_chars: int) -> list[dict[str, str]]:
    code_vuln = _bounded_text(candidate.get("code_vuln"), max_code_chars)
    code_fixed = _bounded_text(candidate.get("code_fixed"), max_code_chars)
    evidence = {
        "candidate_id": candidate.get("candidate_id", ""),
        "source": candidate.get("source", ""),
        "package": candidate.get("package", ""),
        "advisory_id": candidate.get("advisory_id", ""),
        "cve_id": candidate.get("cve_id", ""),
        "repo_url": candidate.get("repo_url", ""),
        "file_path": candidate.get("file_path", ""),
        "function_name": candidate.get("function_name", ""),
        "cwe_hypothesis": candidate.get("cwe", ""),
        "rule_hypothesis": candidate.get("rule_id", ""),
        "vuln_commit": candidate.get("vuln_commit", ""),
        "fix_commit": candidate.get("fix_commit", ""),
        "affected_versions": candidate.get("affected_versions", ""),
        "fixed_version": candidate.get("fixed_version", ""),
        "notification_url": candidate.get("notification_url", ""),
        "patch_truncated": candidate.get("patch_truncated", False),
        "advisory_evidence": candidate.get("advisory_evidence") or {},
    }
    user_prompt = (
        "Audit this candidate.\n\n"
        f"Candidate metadata:\n{json.dumps(evidence, ensure_ascii=False, indent=2)}\n\n"
        "Vulnerable-side code:\n```python\n"
        f"{code_vuln}\n```\n\n"
        "Fixed-side code:\n```python\n"
        f"{code_fixed}\n```\n\n"
        "Target taxonomy:\n"
        f"{json.dumps({rule: sorted(cwes) for rule, cwes in RULE_CWE.items()}, sort_keys=True)}\n\n"
        "Return this JSON schema exactly:\n"
        f"{OUTPUT_SCHEMA}"
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]


def _extract_json_object(text: str) -> dict[str, Any]:
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end <= start:
            raise
        payload = json.loads(cleaned[start:end + 1])
    if not isinstance(payload, dict):
        raise ValueError("model response is not a JSON object")
    return payload


def _as_confidence(value: Any) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, confidence))


def normalize_model_result(
    candidate: dict[str, Any],
    parsed: dict[str, Any],
    *,
    model: str,
    reasoning_effort: str,
    usage: dict[str, Any],
    raw_response: str,
) -> dict[str, Any]:
    decision = str(parsed.get("decision") or "rejected").strip().lower()
    if decision in {"uncertain", "out_of_scope", "out-of-scope", "scope-out"}:
        decision = "rejected"
    if decision not in DECISIONS:
        decision = "rejected"

    reported_rule = str(parsed.get("rule_id") or "").strip()
    rule_id = reported_rule if reported_rule in RULE_CWE else ""
    cwe = str(parsed.get("cwe") or "").strip().upper()
    if cwe not in TARGET_CWES:
        cwe = ""

    severity = str(parsed.get("severity") or "").strip().upper()
    if severity not in SEVERITIES:
        severity = ""

    quality = str(parsed.get("code_pair_quality") or "").strip().lower()
    if quality not in CODE_PAIR_QUALITIES:
        quality = "missing" if not (candidate.get("code_vuln") and candidate.get("code_fixed")) else "partial"

    taxonomy_ok = True
    taxonomy_note = ""
    if rule_id and cwe and cwe not in RULE_CWE[rule_id]:
        taxonomy_ok = False
        taxonomy_note = f"reported cwe {cwe} does not match rule {rule_id}"
    if reported_rule and not rule_id:
        taxonomy_ok = False
        taxonomy_note = f"reported unknown rule {reported_rule!r}"

    return {
        "candidate_id": str(candidate.get("candidate_id", "")),
        "audited_at": _utc_now(),
        "model": model,
        "reasoning_effort": reasoning_effort,
        "verified": False,
        "review_status": "model_only",
        "decision": decision,
        "confidence": _as_confidence(parsed.get("confidence")),
        "rule_id": rule_id or None,
        "reported_rule_id": reported_rule or None,
        "cwe": cwe or None,
        "severity": severity or None,
        "license": str(parsed.get("license") or "").strip() or None,
        "explanation": str(parsed.get("explanation") or "").strip(),
        "finding": str(parsed.get("finding") or "").strip(),
        "evidence_notes": str(parsed.get("evidence_notes") or "").strip(),
        "code_pair_quality": quality,
        "taxonomy_ok": taxonomy_ok,
        "taxonomy_note": taxonomy_note,
        "usage": usage,
        "raw_response": raw_response,
        "error": "",
    }


def error_result(
    candidate: dict[str, Any],
    *,
    model: str,
    reasoning_effort: str,
    error: str,
    usage: dict[str, Any] | None = None,
    raw_response: str = "",
) -> dict[str, Any]:
    return {
        "candidate_id": str(candidate.get("candidate_id", "")),
        "audited_at": _utc_now(),
        "model": model,
        "reasoning_effort": reasoning_effort,
        "verified": False,
        "review_status": "model_only",
        "decision": "error",
        "confidence": 0.0,
        "rule_id": None,
        "reported_rule_id": None,
        "cwe": None,
        "severity": None,
        "license": None,
        "explanation": "",
        "finding": "",
        "evidence_notes": "",
        "code_pair_quality": "missing" if not (
            candidate.get("code_vuln") and candidate.get("code_fixed")
        ) else "partial",
        "taxonomy_ok": False,
        "taxonomy_note": "",
        "usage": usage or {},
        "raw_response": raw_response,
        "error": error,
    }


def _usage_dict(completion: Any) -> dict[str, Any]:
    usage = getattr(completion, "usage", None)
    if usage is None:
        return {}
    if hasattr(usage, "model_dump"):
        return usage.model_dump(exclude_none=True)
    if isinstance(usage, dict):
        return usage
    return {
        key: getattr(usage, key)
        for key in ("prompt_tokens", "completion_tokens", "total_tokens")
        if getattr(usage, key, None) is not None
    }


def _message_content(completion: Any) -> str:
    choices = getattr(completion, "choices", None) or []
    if not choices:
        raise ValueError("model returned no choices")
    message = getattr(choices[0], "message", None)
    content = getattr(message, "content", None) if message is not None else None
    if isinstance(content, list):
        return "".join(
            str(part.get("text", "")) if isinstance(part, dict) else str(part)
            for part in content
        )
    return str(content or "")


def call_model(
    client: Any,
    candidate: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    messages = build_messages(candidate, max_code_chars=args.max_code_chars)
    last_error: Exception | None = None
    for attempt in range(1, args.retries + 1):
        try:
            request: dict[str, Any] = {
                "model": args.model,
                "messages": messages,
                "reasoning_effort": args.reasoning_effort,
            }
            if args.max_output_tokens > 0:
                request["max_tokens"] = args.max_output_tokens
            completion = client.chat.completions.create(**request)
            raw = _message_content(completion)
            usage = _usage_dict(completion)
            try:
                parsed = _extract_json_object(raw)
                return normalize_model_result(
                    candidate,
                    parsed,
                    model=args.model,
                    reasoning_effort=args.reasoning_effort,
                    usage=usage,
                    raw_response=raw,
                )
            except (json.JSONDecodeError, ValueError) as exc:
                return error_result(
                    candidate,
                    model=args.model,
                    reasoning_effort=args.reasoning_effort,
                    error=f"JSON parse failure: {exc}",
                    usage=usage,
                    raw_response=raw,
                )
        except Exception as exc:  # API/client errors are retried below.
            if type(exc).__name__ in {"APIConnectionError", "APITimeoutError"}:
                raise AuditTransportError(f"{type(exc).__name__}: {exc}") from exc
            last_error = exc
            if attempt < args.retries:
                time.sleep(args.retry_delay * attempt)
    return error_result(
        candidate,
        model=args.model,
        reasoning_effort=args.reasoning_effort,
        error=f"{type(last_error).__name__}: {last_error}",
    )


def _stable_sample(candidate_id: str, sample_rate: float, seed: str) -> bool:
    if sample_rate <= 0:
        return False
    if sample_rate >= 1:
        return True
    digest = hashlib.sha256(f"{seed}:{candidate_id}".encode("utf-8")).digest()
    value = int.from_bytes(digest[:8], "big") / float(1 << 64)
    return value < sample_rate


def _evidence_complete(candidate: dict[str, Any]) -> bool:
    return bool(
        (candidate.get("advisory_id") or candidate.get("cve_id"))
        and candidate.get("repo_url")
        and (candidate.get("vuln_commit") or candidate.get("fix_commit"))
        and candidate.get("file_path")
    )


def queue_reasons(
    candidate: dict[str, Any],
    audit: dict[str, Any],
    *,
    min_confidence: float,
    sample_rate: float,
    sample_seed: str,
) -> list[str]:
    reasons: list[str] = []
    decision = str(audit.get("decision") or "error")
    confidence = _as_confidence(audit.get("confidence"))
    has_pair = bool(candidate.get("code_vuln") and candidate.get("code_fixed"))

    if audit.get("error"):
        reasons.append("model_error")
    if decision == "error":
        reasons.append("model_error")
    if confidence < min_confidence:
        reasons.append("low_confidence")
    if not has_pair:
        reasons.append("missing_code_pair")
    if not _evidence_complete(candidate):
        reasons.append("incomplete_evidence")
    if not audit.get("taxonomy_ok", False):
        reasons.append("taxonomy_review")

    high_confidence_complete = (
        decision in {"confirmed", "rejected"}
        and confidence >= min_confidence
        and has_pair
        and _evidence_complete(candidate)
        and audit.get("taxonomy_ok", False)
        and not audit.get("error")
    )
    if high_confidence_complete and _stable_sample(str(candidate["candidate_id"]), sample_rate, sample_seed):
        reasons.append("model_sample")
    return sorted(set(reasons))


def build_queue(
    candidates: list[dict[str, Any]],
    audits: dict[str, dict[str, Any]],
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    queue: list[dict[str, Any]] = []
    for candidate in candidates:
        candidate_id = str(candidate.get("candidate_id", ""))
        audit = audits.get(candidate_id)
        if not audit:
            continue
        reasons = queue_reasons(
            candidate,
            audit,
            min_confidence=args.min_confidence,
            sample_rate=args.sample_rate,
            sample_seed=args.sample_seed,
        )
        if not reasons:
            continue
        row = dict(candidate)
        row["model_audit"] = audit
        row["review_selection"] = {
            "reasons": reasons,
            "min_confidence": args.min_confidence,
            "sample_rate": args.sample_rate,
            "sample_seed": args.sample_seed,
        }
        queue.append(row)
    return queue


def _resolve_output(path: str | Path) -> Path:
    output = Path(path)
    return output if output.is_absolute() else ROOT / output


def _token_stats(candidates: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    prompt_tokens: list[int] = []
    for candidate in candidates:
        messages = build_messages(candidate, max_code_chars=args.max_code_chars)
        prompt_tokens.append(estimate_tokens("\n".join(message["content"] for message in messages)))

    total_input = sum(prompt_tokens)
    expected_output = args.assumed_output_tokens
    high_output = args.assumed_output_tokens + args.assumed_reasoning_tokens
    return {
        "candidate_count": len(candidates),
        "prompt_tokens": {
            "min": min(prompt_tokens) if prompt_tokens else 0,
            "max": max(prompt_tokens) if prompt_tokens else 0,
            "average": round(total_input / len(prompt_tokens), 2) if prompt_tokens else 0,
            "total": total_input,
        },
        "assumption": {
            "normal_output_tokens": expected_output,
            "reasoning_tokens_high": args.assumed_reasoning_tokens,
            "high_reasoning_output_tokens": high_output,
            "max_output_tokens_per_item": args.max_output_tokens,
        },
        "estimated_billable_tokens": {
            "normal_output_total": expected_output * len(candidates),
            "high_reasoning_output_total": high_output * len(candidates),
            "normal_total": total_input + expected_output * len(candidates),
            "high_reasoning_total": total_input + high_output * len(candidates),
        },
    }


def _cost_for_tokens(tokens: int, price_per_million: float) -> float | None:
    if price_per_million < 0:
        return None
    return round(tokens / 1_000_000 * price_per_million, 6)


def build_cost_report(candidates: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    stats = _token_stats(candidates, args)
    count = stats["candidate_count"]
    prices_supplied = args.price_input is not None and args.price_output is not None
    if not prices_supplied:
        return {
            "generated_at": _utc_now(),
            "status": "token_estimate_only_missing_prices",
            "model": args.model,
            "reasoning_effort": args.reasoning_effort,
            "candidate_path": _display_path(args.candidates_path),
            "token_stats": stats,
            "pricing": {
                "input_per_million": args.price_input,
                "output_per_million": args.price_output,
                "note": (
                    "No live Moonshot price was queried. Provide --price-input and "
                    "--price-output to calculate currency cost; the script does not guess prices."
                ),
            },
            "formula": {
                "input_cost": "input_tokens / 1e6 * input_price",
                "output_cost": (
                    "(final_output_tokens + reasoning_tokens) / 1e6 * output_price"
                ),
            },
        }

    normal_input_cost = _cost_for_tokens(stats["prompt_tokens"]["total"], args.price_input)
    high_input_cost = normal_input_cost
    normal_output_cost = _cost_for_tokens(
        stats["estimated_billable_tokens"]["normal_output_total"], args.price_output
    )
    high_output_cost = _cost_for_tokens(
        stats["estimated_billable_tokens"]["high_reasoning_output_total"], args.price_output
    )
    estimated_cost = {
        "normal": {
            "input": normal_input_cost,
            "output": normal_output_cost,
            "total": round((normal_input_cost or 0) + (normal_output_cost or 0), 6),
        },
        "high_reasoning": {
            "input": high_input_cost,
            "output": high_output_cost,
            "total": round((high_input_cost or 0) + (high_output_cost or 0), 6),
        },
    }
    return {
        "generated_at": _utc_now(),
        "status": "estimated",
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "candidate_path": _display_path(args.candidates_path),
        "token_stats": stats,
        "pricing": {
            "input_per_million": args.price_input,
            "output_per_million": args.price_output,
        },
        "estimated_cost": estimated_cost,
        "estimated_cost_scope": {
            "candidate_count": count,
            "note": (
                "Conservative no-cache estimate for the complete candidate batch. "
                "The runtime cost report replaces it with actual token usage when available."
            ),
        },
        "formula": {
            "input_cost": "input_tokens / 1e6 * input_price",
            "output_cost": "(final_output_tokens + reasoning_tokens) / 1e6 * output_price",
        },
    }


def _print_estimate(report: dict[str, Any], report_path: Path) -> None:
    stats = report["token_stats"]
    print("=" * 72)
    print("MODEL AUDIT ESTIMATE")
    print("=" * 72)
    print(f"candidate file : {report['candidate_path']}")
    print(f"candidates     : {stats['candidate_count']}")
    print(f"model          : {report['model']} ({report['reasoning_effort']})")
    print(
        "input tokens   : "
        f"total={stats['prompt_tokens']['total']} "
        f"avg={stats['prompt_tokens']['average']} "
        f"range={stats['prompt_tokens']['min']}..{stats['prompt_tokens']['max']}"
    )
    print(
        "output budget  : "
        f"normal={stats['assumption']['normal_output_tokens']} "
        f"high_reasoning={stats['assumption']['high_reasoning_output_tokens']} "
        "(per item)"
    )
    if report["status"] == "estimated":
        cost = report["estimated_cost"]
        print(
            "estimated cost : "
            f"batch_normal={cost['normal']['total']:.6f} "
            f"batch_high_reasoning={cost['high_reasoning']['total']:.6f}"
        )
    else:
        print("estimated cost : unavailable until official input/output prices are supplied")
    try:
        display_path = _display_path(report_path)
    except ValueError:
        display_path = report_path
    print(f"report         : {display_path}")


def _actual_usage(audits: dict[str, dict[str, Any]], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    prompt_tokens = 0
    completion_tokens = 0
    total_tokens = 0
    items_with_usage = 0
    for candidate in candidates:
        audit = audits.get(str(candidate.get("candidate_id", "")))
        usage = (audit or {}).get("usage") or {}
        if not usage:
            continue
        items_with_usage += 1
        prompt_tokens += int(usage.get("prompt_tokens") or 0)
        completion_tokens += int(usage.get("completion_tokens") or 0)
        total_tokens += int(usage.get("total_tokens") or 0)
    return {
        "items_with_usage": items_with_usage,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }


def _actual_cost(usage: dict[str, Any], args: argparse.Namespace) -> dict[str, Any] | None:
    if args.price_input is None or args.price_output is None:
        return None
    input_cost = _cost_for_tokens(int(usage.get("prompt_tokens") or 0), args.price_input)
    output_cost = _cost_for_tokens(int(usage.get("completion_tokens") or 0), args.price_output)
    return {
        "input": input_cost,
        "output": output_cost,
        "total": round((input_cost or 0) + (output_cost or 0), 6),
        "candidate_count": usage.get("items_with_usage", 0),
    }


def _load_existing_audits(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    audits: dict[str, dict[str, Any]] = {}
    for row in _load_jsonl(path):
        candidate_id = str(row.get("candidate_id") or "")
        if candidate_id:
            audits[candidate_id] = row
    return audits


def _create_client(args: argparse.Namespace) -> Any:
    try:
        from openai import OpenAI
        import httpx
    except ImportError as exc:
        raise ValueError(
            "openai and httpx are required; install them with 'pip install openai httpx'"
        ) from exc
    api_key = resolve_api_key(args.api_key_file)
    proxy = _resolve_proxy(getattr(args, "proxy", None))
    # trust_env=False so a stray ALL_PROXY (e.g. socks://) cannot break the client;
    # httpx cannot dial a socks:// proxy without the optional socks extra.
    http_client = httpx.Client(proxy=proxy or None, trust_env=False)
    return OpenAI(
        api_key=api_key,
        base_url=args.base_url,
        timeout=args.timeout,
        max_retries=0,
        http_client=http_client,
    )


def _resolve_proxy(explicit: str | None) -> str:
    """Pick an httpx-compatible proxy, skipping socks:// entries it cannot dial."""
    def usable(value: str) -> str:
        value = str(value or "").strip()
        scheme = value.split("://", 1)[0].lower()
        return value if scheme in ("http", "https") else ""

    if explicit:
        return usable(explicit)
    for name in (
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        candidate = usable(os.environ.get(name, ""))
        if candidate:
            return candidate
    return ""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pre-audit Round-6 real crypto candidates with Moonshot Kimi."
    )
    parser.add_argument("--candidates", default=None, help="input candidate JSONL")
    parser.add_argument("--model-out", default=str(DEFAULT_MODEL_OUT))
    parser.add_argument("--queue-out", default=str(DEFAULT_QUEUE_OUT))
    parser.add_argument("--cost-report-out", default=str(DEFAULT_COST_REPORT))
    parser.add_argument(
        "--api-key-file",
        default=None,
        help="optional key file; defaults to api.txt, then apitxt",
    )
    parser.add_argument("--base-url", default="https://api.moonshot.cn/v1")
    parser.add_argument("--model", default="kimi-k3")
    parser.add_argument(
        "--proxy",
        default=None,
        help=(
            "explicit HTTP(S) proxy, e.g. http://127.0.0.1:7897; "
            "defaults to HTTPS_PROXY/HTTP_PROXY/ALL_PROXY when set to an http(s) URL"
        ),
    )
    parser.add_argument(
        "--reasoning-effort",
        default="high",
        choices=("minimal", "low", "medium", "high", "max"),
    )
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--retry-delay", type=float, default=2.0)
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--max-output-tokens", type=int, default=6144)
    parser.add_argument("--max-code-chars", type=int, default=50000)
    parser.add_argument(
        "--advisory-dir",
        default=str(DEFAULT_ADVISORY_DIR),
        help="local OSV advisory directory used to attach report text",
    )
    parser.add_argument("--max-advisory-chars", type=int, default=12000)
    parser.add_argument("--limit", type=int, default=0, help="process only the first N candidates")
    parser.add_argument("--no-resume", action="store_true", help="re-audit IDs already present")
    parser.add_argument("--sample-rate", type=float, default=0.15)
    parser.add_argument("--min-confidence", type=float, default=0.80)
    parser.add_argument("--sample-seed", default="round6-kimi-audit-v1")
    parser.add_argument("--estimate-only", action="store_true")
    parser.add_argument("--assumed-output-tokens", type=int, default=800)
    parser.add_argument("--assumed-reasoning-tokens", type=int, default=4096)
    parser.add_argument(
        "--price-input",
        type=float,
        default=os.environ.get("MOONSHOT_PRICE_INPUT"),
        help="input price per million tokens in the currency you want reported",
    )
    parser.add_argument(
        "--price-output",
        type=float,
        default=os.environ.get("MOONSHOT_PRICE_OUTPUT"),
        help="output price per million tokens in the currency you want reported",
    )
    args = parser.parse_args(argv)

    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.retries < 1:
        parser.error("--retries must be at least 1")
    if not 0 <= args.sample_rate <= 1:
        parser.error("--sample-rate must be between 0 and 1")
    if not 0 <= args.min_confidence <= 1:
        parser.error("--min-confidence must be between 0 and 1")
    if args.max_output_tokens < 0:
        parser.error("--max-output-tokens must be non-negative")
    if args.max_code_chars < 1:
        parser.error("--max-code-chars must be positive")
    if args.max_advisory_chars < 1:
        parser.error("--max-advisory-chars must be positive")
    if (args.price_input is None) != (args.price_output is None):
        parser.error("--price-input and --price-output must be supplied together")
    if args.price_input is not None and (args.price_input < 0 or args.price_output < 0):
        parser.error("prices must be non-negative")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        args.candidates_path = _resolve_candidates(args.candidates)
        candidates = _load_jsonl(args.candidates_path)
    except (OSError, ValueError) as exc:
        print(f"[audit] {exc}", file=sys.stderr)
        return 1

    if args.limit > 0:
        candidates = candidates[:args.limit]

    advisory_dir = Path(args.advisory_dir)
    if not advisory_dir.is_absolute():
        advisory_dir = ROOT / advisory_dir
    advisory_counts = enrich_candidates_with_local_advisories(
        candidates,
        advisory_dir=advisory_dir,
        max_advisory_chars=args.max_advisory_chars,
    )
    print(
        "[audit] local advisory evidence: "
        f"attached={advisory_counts['attached']} "
        f"missing={advisory_counts['missing']} invalid={advisory_counts['invalid']}"
    )

    seen: set[str] = set()
    for candidate in candidates:
        candidate_id = str(candidate.get("candidate_id") or "")
        if not candidate_id:
            print("[audit] candidate is missing candidate_id", file=sys.stderr)
            return 1
        if candidate_id in seen:
            print(f"[audit] duplicate candidate_id: {candidate_id}", file=sys.stderr)
            return 1
        seen.add(candidate_id)

    cost_report = build_cost_report(candidates, args)
    cost_report_path = _resolve_output(args.cost_report_out)
    _atomic_write_json(cost_report_path, cost_report)
    _print_estimate(cost_report, cost_report_path)
    if args.estimate_only:
        return 0

    model_out = _resolve_output(args.model_out)
    queue_out = _resolve_output(args.queue_out)
    try:
        client = _create_client(args)
    except ValueError as exc:
        print(f"[audit] {exc}", file=sys.stderr)
        return 1
    used_proxy = _resolve_proxy(getattr(args, "proxy", None))
    print(
        f"[audit] base_url={args.base_url} proxy={used_proxy or 'direct (env proxies ignored)'}"
    )

    audits = {} if args.no_resume else _load_existing_audits(model_out)
    pending = [row for row in candidates if str(row["candidate_id"]) not in audits]
    print(
        f"[audit] resume={not args.no_resume} existing={len(audits)} "
        f"pending={len(pending)} workers={args.workers}"
    )

    if pending:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(call_model, client, row, args): row for row in pending}
            for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
                candidate = futures[future]
                candidate_id = str(candidate["candidate_id"])
                try:
                    audits[candidate_id] = future.result()
                except AuditTransportError as exc:
                    print(
                        f"[audit] model endpoint unreachable: {exc}",
                        file=sys.stderr,
                    )
                    return 1
                except Exception as exc:  # Defensive: call_model normally handles errors.
                    audits[candidate_id] = error_result(
                        candidate,
                        model=args.model,
                        reasoning_effort=args.reasoning_effort,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                decision = audits[candidate_id].get("decision", "error")
                confidence = audits[candidate_id].get("confidence", 0)
                print(
                    f"[audit] {index:>3}/{len(pending)} {candidate_id} "
                    f"{decision} confidence={confidence}"
                )
                _write_jsonl(model_out, [audits[str(row["candidate_id"])] for row in candidates if str(row["candidate_id"]) in audits])

    _write_jsonl(model_out, [audits[str(row["candidate_id"])] for row in candidates if str(row["candidate_id"]) in audits])
    queue = build_queue(candidates, audits, args)
    _write_jsonl(queue_out, queue)
    actual_usage = _actual_usage(audits, candidates)
    cost_report["actual_usage"] = actual_usage
    cost_report["actual_cost"] = _actual_cost(actual_usage, args)
    _atomic_write_json(cost_report_path, cost_report)

    decisions: dict[str, int] = {}
    for audit in audits.values():
        key = str(audit.get("decision") or "unknown")
        decisions[key] = decisions.get(key, 0) + 1
    summary = {
        "generated_at": _utc_now(),
        "candidate_path": _display_path(args.candidates_path),
        "model_out": _display_path(model_out),
        "queue_out": _display_path(queue_out),
        "audited": len(audits),
        "queued_for_human_review": len(queue),
        "model_verified_true": 0,
        "decisions": decisions,
        "cost_report": _display_path(_resolve_output(args.cost_report_out)),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("[audit] model results remain verified=false; only human review exports verified data")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
