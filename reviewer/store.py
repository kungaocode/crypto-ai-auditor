"""File-backed review storage for the R6 real-crypto candidate reviewer.

The reviewer reads advisory candidates (the enriched fix-commit file when it
exists, otherwise the raw candidate pool), records a human verdict for each
one, and rebuilds the ``real_verified_{detect,triage}.jsonl`` files that
``scripts/build_round6_final_dataset.py`` consumes.

Design mirrors the project-04 annotation bench: every confirmed verdict is
written to its own JSON file under a verdict directory (the source of truth),
and the JSONL index plus the verified-data exports are rebuilt after each
mutation so an interrupted session is fully recoverable.

The browser UI is deliberately binary: confirm or reject. Machine-generated
verdicts can be imported separately with explicit model provenance.
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_round6_final_dataset import RULE_CWE, TARGET_CWES  # noqa: E402


class ReviewStoreError(RuntimeError):
    """Raised when review state is invalid or cannot be persisted."""


VERDICTS = ("confirm", "reject")
EXPORTING_VERDICTS = ("confirm", "reject")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SAFE_REVIEWER_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

_DEFAULT_CANDIDATES = [
    "data/round6/candidates/real_crypto_candidates_uncertain.jsonl",
    "data/round6/candidates/real_crypto_candidates_functions.jsonl",
    "data/round6/candidates/real_crypto_candidates_enriched.jsonl",
    "data/round6/candidates/real_crypto_candidates.jsonl",
]

# Well-known upstream licenses, offered as an editable *hint* only. The reviewer
# still has to confirm it against the repository before it is exported.
LICENSE_HINTS = {
    "urllib3/urllib3": "MIT",
    "django/django": "BSD-3-Clause",
    "jpadilla/pyjwt": "MIT",
    "pyca/cryptography": "Apache-2.0 OR BSD-3-Clause",
    "paramiko/paramiko": "LGPL-2.1-or-later",
    "mpdavis/python-jose": "MIT",
    "authlib/authlib": "BSD-3-Clause",
    "sybrenstuvel/python-rsa": "Apache-2.0",
    "oauthlib/oauthlib": "BSD-3-Clause",
}

_GH_REPO_RE = re.compile(r"^https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+)")


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    temp.write_text(text, encoding="utf-8")
    os.replace(temp, path)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    _atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise ReviewStoreError(f"missing candidates file: {path}")
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ReviewStoreError(f"{path}:{number}: invalid JSON ({exc})") from exc
    if not rows:
        raise ReviewStoreError(f"candidates file is empty: {path}")
    return rows


def load_rule_catalog(root: Path) -> list[dict[str, str]]:
    """Read rule metadata from rules/*/rule.yaml without a YAML dependency."""
    catalog: dict[str, dict[str, str]] = {}
    for yaml_path in sorted((root / "rules").glob("*/rule.yaml")):
        text = yaml_path.read_text(encoding="utf-8")
        rid = re.search(r"id:\s*(CRYPTO-\d+)", text)
        if not rid:
            continue
        rule_id = rid.group(1)
        message = re.search(r'message:\s*"([^"]*)"', text)
        cwe = re.search(r'cwe:\s*"?(CWE-\d+)"?', text)
        # ``severity`` appears twice: the tool level (WARNING) and metadata.
        severities = re.findall(r"severity:\s*([A-Z]+)", text)
        catalog[rule_id] = {
            "id": rule_id,
            "title": message.group(1) if message else rule_id,
            "cwe": cwe.group(1) if cwe else "",
            "severity": severities[-1] if severities else "MEDIUM",
            "accepted_cwes": sorted(RULE_CWE.get(rule_id, set())),
        }
    for rule_id in RULE_CWE:
        catalog.setdefault(
            rule_id,
            {
                "id": rule_id,
                "title": rule_id,
                "cwe": "",
                "severity": "MEDIUM",
                "accepted_cwes": sorted(RULE_CWE[rule_id]),
            },
        )
    return [catalog[key] for key in sorted(catalog)]


def suggest_rule(cwe: str) -> str:
    """Best-effort rule suggestion; CWE-327/326 map to several rules, stay blank."""
    if cwe == "CWE-295":
        return "CRYPTO-010"
    matches = [rule for rule, cwes in RULE_CWE.items() if cwe in cwes and len(cwes) == 1]
    return matches[0] if len(matches) == 1 else ""


def suggest_license(repo_url: str) -> str:
    match = _GH_REPO_RE.match(repo_url or "")
    if not match:
        return ""
    return LICENSE_HINTS.get(f"{match.group(1)}/{match.group(2).removesuffix('.git')}", "")


class ReviewStore:
    """Load advisory candidates and persist one independent review per item."""

    verdicts: tuple[str, ...] = VERDICTS

    def __init__(
        self,
        root: Path | str,
        reviewer: str = "reviewer",
        *,
        candidates_path: Optional[Path | str] = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.reviewer = str(reviewer).strip()
        if not _SAFE_REVIEWER_RE.fullmatch(self.reviewer):
            raise ValueError(
                "reviewer must contain only letters, numbers, '_' or '-' and be at most 32 characters"
            )

        self.candidates_path = self._resolve_candidates(candidates_path)
        self.review_root = self.root / "data" / "round6" / "review"
        self.run_dir = self.review_root / "web" / self.reviewer
        self.verdicts_dir = self.run_dir / "labels"
        self.index_path = self.run_dir / "reviews.jsonl"
        self.detect_path = self.root / "data" / "round6" / "real_verified_detect.jsonl"
        self.triage_path = self.root / "data" / "round6" / "real_verified_triage.jsonl"
        self.rules = load_rule_catalog(self.root)
        self._lock = threading.RLock()

    # -- public API ---------------------------------------------------------

    def session(self) -> dict[str, Any]:
        with self._lock:
            candidates = self._load_candidates()
            reviews = self._scan_reviews_locked()
            items = [self._public_item(row, reviews.get(str(row["candidate_id"]))) for row in candidates]
            return {
                "reviewer": self.reviewer,
                "candidates_path": self._display_path(self.candidates_path),
                "total": len(items),
                "reviewed": sum(1 for item in items if item["verdict"]),
                "exportable": sum(1 for item in items if item["verdict"] in EXPORTING_VERDICTS),
                "counts": self._counts(items),
                "rules": self.rules,
                "items": items,
            }

    def review(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Record a verdict for one candidate and rebuild the exports."""
        if not isinstance(payload, dict):
            raise ReviewStoreError("request body must be a JSON object")
        item_id = self._safe_id(payload.get("id"))
        verdict = str(payload.get("verdict") or "").strip()
        if verdict not in self.verdicts:
            raise ReviewStoreError("verdict must be one of: " + ", ".join(self.verdicts))

        with self._lock:
            candidates = {str(row["candidate_id"]): row for row in self._load_candidates()}
            candidate = candidates.get(item_id)
            if candidate is None:
                raise ReviewStoreError(f"unknown candidate id: {item_id}")

            record = self._build_record(candidate, verdict, payload)
            reviews = self._scan_reviews_locked()
            previous = reviews.get(item_id)
            if previous and previous.get("verdict") != verdict:
                self._label_path(previous["verdict"], item_id).unlink(missing_ok=True)
            _atomic_write_json(self._label_path(verdict, item_id), record)
            reviews[item_id] = record
            self._rebuild_locked(reviews)
            return self._public_item(candidate, record)

    def clear(self, item_id: str | int) -> dict[str, Any]:
        with self._lock:
            candidates = {str(row["candidate_id"]): row for row in self._load_candidates()}
            row_id = self._safe_id(item_id)
            if row_id not in candidates:
                raise ReviewStoreError(f"unknown candidate id: {row_id}")
            reviews = self._scan_reviews_locked()
            previous = reviews.pop(row_id, None)
            if previous:
                self._label_path(previous["verdict"], row_id).unlink(missing_ok=True)
                self._rebuild_locked(reviews)
            return self._public_item(candidates[row_id], None)

    def export(self) -> dict[str, Any]:
        """Rebuild the verified JSONL files and report what was written."""
        with self._lock:
            reviews = self._scan_reviews_locked()
            self._rebuild_exports_locked(reviews)
            return {
                "detect": self._count_lines(self.detect_path),
                "triage": self._count_lines(self.triage_path),
                "detect_path": str(self.detect_path.relative_to(self.root)),
                "triage_path": str(self.triage_path.relative_to(self.root)),
            }

    # -- validation / record building --------------------------------------

    def _build_record(
        self,
        candidate: dict[str, Any],
        verdict: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        rule_id = str(payload.get("rule_id") or "").strip()
        if rule_id and rule_id not in RULE_CWE:
            raise ReviewStoreError(f"unknown rule_id {rule_id!r}; expected CRYPTO-001..013")

        license_ = str(
            payload.get("license")
            or candidate.get("license")
            or suggest_license(candidate.get("repo_url", ""))
            or "NOASSERTION"
        ).strip()
        severity = str(payload.get("severity") or "HIGH").strip().upper()
        if severity not in SEVERITIES:
            raise ReviewStoreError("severity must be one of: " + ", ".join(SEVERITIES))

        cwe = str(payload.get("cwe") or candidate.get("cwe") or "").strip().upper()
        if rule_id and cwe and cwe not in RULE_CWE[rule_id]:
            raise ReviewStoreError(
                f"cwe {cwe} does not match rule {rule_id} ({sorted(RULE_CWE[rule_id])})"
            )

        code_vuln = str(payload.get("code_vuln") or candidate.get("code_vuln") or "")
        code_fixed = str(payload.get("code_fixed") or candidate.get("code_fixed") or "")
        finding = str(payload.get("finding") or "").strip() or self._default_finding(candidate, rule_id)
        explanation = str(payload.get("explanation") or "").strip()
        note = str(payload.get("note") or "").strip()
        review_mode = str(payload.get("review_mode") or "manual").strip()
        if review_mode not in ("manual", "model"):
            raise ReviewStoreError("review_mode must be 'manual' or 'model'")
        model = str(payload.get("model") or "").strip()
        raw_confidence = payload.get("model_confidence")
        try:
            model_confidence = (
                None if raw_confidence in (None, "") else max(0.0, min(1.0, float(raw_confidence)))
            )
        except (TypeError, ValueError) as exc:
            raise ReviewStoreError("model_confidence must be a number between 0 and 1") from exc
        split = str(payload.get("split") or "train").strip()
        if split not in ("train", "val", "test"):
            raise ReviewStoreError("split must be one of train/val/test")

        if verdict == "confirm":
            if not code_vuln.strip() or not code_fixed.strip():
                raise ReviewStoreError(
                    "confirm needs both a vulnerable and a fixed snippet; paste them into the editors"
                )
            if not rule_id:
                raise ReviewStoreError("confirm needs a rule_id in CRYPTO-001..013")
            if not cwe:
                raise ReviewStoreError("confirm needs a cwe from the advisory")
            if not explanation:
                raise ReviewStoreError("confirm needs a short explanation of the crypto misuse")
            self._require_parses(code_vuln, "vulnerable")
            self._require_parses(code_fixed, "fixed")
        elif verdict == "reject":
            if not code_vuln.strip():
                raise ReviewStoreError("reject still needs the vulnerable snippet as the finding context")
            if not explanation:
                raise ReviewStoreError("reject needs a short explanation of why it is a false positive")

        return {
            "id": str(candidate["candidate_id"]),
            "candidate_id": str(candidate["candidate_id"]),
            "verdict": verdict,
            "reviewer": self.reviewer,
            "package": candidate.get("package", ""),
            "advisory_id": candidate.get("advisory_id", ""),
            "cve_id": candidate.get("cve_id", ""),
            "cwe": cwe,
            "rule_id": rule_id,
            "severity": severity,
            "license": license_,
            "repo_url": candidate.get("repo_url", ""),
            "vuln_commit": candidate.get("vuln_commit", ""),
            "fix_commit": candidate.get("fix_commit", ""),
            "file_path": candidate.get("file_path", ""),
            "code_vuln_url": candidate.get("code_vuln_url", ""),
            "code_fixed_url": candidate.get("code_fixed_url", ""),
            "code_vuln": code_vuln,
            "code_fixed": code_fixed,
            "finding": finding,
            "explanation": explanation,
            "note": note,
            "split": split,
            "review_mode": review_mode,
            "model": model,
            "model_confidence": model_confidence,
            "source_audit": str(payload.get("source_audit") or "").strip(),
            "reviewed_at": _utc_now(),
        }

    def _default_finding(self, candidate: dict[str, Any], rule_id: str) -> str:
        title = next((r["title"] for r in self.rules if r["id"] == rule_id), rule_id or "crypto misuse")
        cwe = candidate.get("cwe", "")
        location = candidate.get("file_path") or candidate.get("package", "")
        rule_label = rule_id or "CRYPTO-???"
        return f"[{rule_label}] {title} ({cwe}) at {location}.".replace("  ", " ")

    @staticmethod
    def _require_parses(code: str, which: str) -> None:
        try:
            ast.parse(code)
        except SyntaxError as exc:
            raise ReviewStoreError(
                f"{which} snippet is not valid Python ({exc.msg} at line {exc.lineno}); "
                "edit it in the code editor before confirming"
            ) from exc

    # -- persistence --------------------------------------------------------

    def _load_candidates(self) -> list[dict[str, Any]]:
        rows = _load_jsonl(self.candidates_path)
        seen: set[str] = set()
        for row in rows:
            row_id = self._safe_id(row.get("candidate_id"))
            if row_id in seen:
                raise ReviewStoreError(f"duplicate candidate_id in {self.candidates_path}: {row_id}")
            seen.add(row_id)
        return rows

    def _scan_reviews_locked(self) -> dict[str, dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        for verdict in self.verdicts:
            directory = self.verdicts_dir / verdict
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.json")):
                try:
                    record = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise ReviewStoreError(f"cannot read review {path}: {exc}") from exc
                row_id = self._safe_id(record.get("id", path.stem))
                if record.get("verdict") != verdict:
                    raise ReviewStoreError(
                        f"review {path} sits in {verdict}/ but records verdict={record.get('verdict')!r}"
                    )
                if row_id in found:
                    raise ReviewStoreError(f"id {row_id} has reviews in multiple verdict directories")
                found[row_id] = record
        return found

    def _rebuild_locked(self, reviews: dict[str, dict[str, Any]]) -> None:
        ordered = [reviews[key] for key in sorted(reviews)]
        _atomic_write_text(
            self.index_path,
            "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in ordered),
        )
        self._rebuild_exports_locked(reviews)

    def _rebuild_exports_locked(self, reviews: dict[str, dict[str, Any]]) -> None:
        detect: list[dict[str, Any]] = []
        triage: list[dict[str, Any]] = []
        for record in sorted(reviews.values(), key=lambda r: r["id"]):
            verdict = record.get("verdict")
            if verdict == "confirm":
                detect.append(self._detect_record(record))
                triage.append(self._triage_record(record, "Confirm"))
            elif verdict == "reject":
                triage.append(self._triage_record(record, "Reject"))
        _atomic_write_text(
            self.detect_path,
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in detect),
        )
        _atomic_write_text(
            self.triage_path,
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in triage),
        )

    def _evidence(self, record: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": "round6-real-ghsa-osv",
            "license": record["license"],
            "repo_url": record["repo_url"],
            "advisory_id": record["advisory_id"],
            "cve_id": record["cve_id"],
            "vuln_commit": record["vuln_commit"],
            "fix_commit": record["fix_commit"],
            "file": record["file_path"],
            "verified": True,
            "verified_by": record["reviewer"],
            "review_mode": record.get("review_mode", "manual"),
            "model": record.get("model", ""),
            "model_confidence": record.get("model_confidence"),
            "source_audit": record.get("source_audit", ""),
            "split": record["split"],
        }

    def _detect_record(self, record: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": f"r6-real-{record['id']}-detect",
            "language": "python",
            "task": "detect",
            "code": record["code_vuln"],
            "label": {
                "vulnerable": True,
                "cwe": record["cwe"],
                "severity": record["severity"],
                "confidence": "high",
                "explanation": record["explanation"],
            },
            "rule": record["rule_id"],
            **self._evidence(record),
        }

    def _triage_record(self, record: dict[str, Any], verdict: str) -> dict[str, Any]:
        label = {
            "cwe": record["cwe"],
            "severity": record["severity"],
            "verdict": verdict,
            "explanation": record["explanation"],
        }
        if verdict == "Confirm" and record.get("code_fixed"):
            label["patch"] = record["code_fixed"]
        return {
            "id": f"r6-real-{record['id']}-triage",
            "language": "python",
            "task": "triage",
            "code": record["code_vuln"],
            "finding": record["finding"],
            "label": label,
            "rule": record["rule_id"],
            **self._evidence(record),
        }

    # -- helpers ------------------------------------------------------------

    def _public_item(
        self,
        candidate: dict[str, Any],
        record: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        cwe = candidate.get("cwe", "")
        model_audit = candidate.get("model_audit") or {}
        model_rule = str(model_audit.get("rule_id") or "")
        model_cwe = str(model_audit.get("cwe") or "")
        if model_rule not in RULE_CWE or (
            model_cwe and model_cwe not in RULE_CWE.get(model_rule, set())
        ):
            model_rule = ""
        code_vuln = (record or {}).get("code_vuln") or candidate.get("code_vuln", "")
        code_fixed = (record or {}).get("code_fixed") or candidate.get("code_fixed", "")
        license_ = (
            (record or {}).get("license")
            or candidate.get("license")
            or suggest_license(candidate.get("repo_url", ""))
            or "NOASSERTION"
        )
        return {
            "id": str(candidate["candidate_id"]),
            "package": candidate.get("package", ""),
            "cwe": cwe,
            "advisory_id": candidate.get("advisory_id", ""),
            "cve_id": candidate.get("cve_id", ""),
            "repo_url": candidate.get("repo_url", ""),
            "vuln_commit": candidate.get("vuln_commit", ""),
            "fix_commit": candidate.get("fix_commit", ""),
            "file_path": candidate.get("file_path", ""),
            "code_vuln_url": candidate.get("code_vuln_url", ""),
            "code_fixed_url": candidate.get("code_fixed_url", ""),
            "code_vuln": code_vuln,
            "code_fixed": code_fixed,
            "has_code": bool(str(code_vuln).strip()) and bool(str(code_fixed).strip()),
            "rule_hint": candidate.get("rule_id") or suggest_rule(cwe),
            "notification_url": candidate.get("notification_url", ""),
            "verdict": record.get("verdict") if record else None,
            "rule_id": record.get("rule_id") if record else "",
            "severity": record.get("severity") if record else "",
            "license": license_,
            "finding": record.get("finding") if record else "",
            "explanation": record.get("explanation") if record else "",
            "note": record.get("note") if record else "",
            "split": record.get("split") if record else "train",
            "reviewed_at": record.get("reviewed_at") if record else None,
            "model_decision": model_audit.get("decision", ""),
            "model_confidence": model_audit.get("confidence"),
            "model_rule_id": model_rule,
            "model_cwe": model_cwe,
            "model_severity": model_audit.get("severity", ""),
            "model_license": model_audit.get("license", ""),
            "model_explanation": model_audit.get("explanation", ""),
            "model_finding": model_audit.get("finding", ""),
            "model_evidence_notes": model_audit.get("evidence_notes", ""),
            "model_error": model_audit.get("error", ""),
            "model_review_status": model_audit.get("review_status", ""),
            "review_selection": candidate.get("review_selection") or {},
        }

    def _label_path(self, verdict: str, item_id: str) -> Path:
        if verdict not in self.verdicts:
            raise ReviewStoreError(f"unsupported verdict directory: {verdict!r}")
        return self.verdicts_dir / verdict / f"{self._safe_id(item_id)}.json"

    def _resolve_candidates(self, override: Optional[Path | str]) -> Path:
        if override is not None:
            path = Path(override)
            path = path if path.is_absolute() else self.root / path
            if not path.exists():
                raise ReviewStoreError(f"candidates file not found: {path}")
            return path
        for relative in _DEFAULT_CANDIDATES:
            candidate = self.root / relative
            if candidate.exists():
                return candidate
        raise ReviewStoreError(
            "no candidate file found; run scripts/harvest_real_crypto_candidates.py first "
            "(looked for " + ", ".join(_DEFAULT_CANDIDATES) + ")"
        )

    @staticmethod
    def _safe_id(value: Any) -> str:
        row_id = str(value).strip()
        if not row_id or not _SAFE_ID_RE.fullmatch(row_id):
            raise ReviewStoreError(f"unsafe or empty id: {value!r}")
        return row_id

    @staticmethod
    def _counts(items: list[dict[str, Any]]) -> dict[str, int]:
        counts = {verdict: 0 for verdict in VERDICTS}
        for item in items:
            verdict = item.get("verdict")
            if verdict in counts:
                counts[verdict] += 1
        return counts

    @staticmethod
    def _count_lines(path: Path) -> int:
        if not path.exists():
            return 0
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())

    def _display_path(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)
