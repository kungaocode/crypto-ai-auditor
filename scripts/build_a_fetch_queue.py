#!/usr/bin/env python3
"""Build a small, high-precision fetch queue for A-class evidence.

The advisory mirrors are already drained. The remaining bottleneck is turning
advisory rows that have a GitHub repository and fix commit into complete
vulnerable/fixed code pairs. Fetching all 548 candidates is wasteful because
most are broad watchlist matches without a target crypto CWE.

This script does not promote anything to A-class. It only ranks and selects
the most plausible candidates for the network fetch and human review:

1. target CWE is the strongest signal;
2. crypto keywords and core crypto packages add confidence;
3. GitHub repo plus a concrete fix commit are mandatory;
4. duplicate advisory, repository+commit and code provenance is removed.

Usage:
    python3 scripts/build_a_fetch_queue.py --self-test
    python3 scripts/build_a_fetch_queue.py --emit
    python3 scripts/build_a_fetch_queue.py --scope keyword --limit 100 --emit
"""
import argparse
import csv
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.build_round6_final_dataset import RULE_CWE  # noqa: E402

CAND_DIR = ROOT / "data" / "round6" / "candidates"
DEFAULT_IN = CAND_DIR / "real_crypto_candidates_need_code.jsonl"
DEFAULT_OUT = CAND_DIR / "real_crypto_candidates_a_fetch_queue.jsonl"
DEFAULT_REVIEW_OUT = CAND_DIR / "real_crypto_candidates_a_review.tsv"
DEFAULT_STATS_OUT = ROOT / "reports" / "data_quality" / "a_fetch_queue_stats.json"

TARGET_CWES = set().union(*RULE_CWE.values())
GITHUB_REPO = re.compile(
    r"^https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+?)(?:/|$)"
)
GITHUB_COMMIT = re.compile(
    r"^https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+?)/(?:-/)?commit/"
    r"([0-9a-fA-F]{7,40})(?:[/?#]|$)"
)

CORE_PACKAGES = {
    "authlib", "bcrypt", "cryptography", "ecdsa", "itsdangerous", "josepy",
    "jwt", "keyring", "m2crypto", "nacl", "oauthlib", "oscrypto",
    "paramiko", "passlib", "pycryptodome", "pycryptodomex", "pyjwt",
    "pynacl", "pyopenssl", "python-jose", "python-rsa", "rsa", "scrypt",
    "simple-crypt", "tornado", "webauthn", "xmlsec",
}
SECONDARY_PACKAGES = {
    "aiohttp", "asyncssh", "certifi", "django", "fastapi", "flask",
    "httplib2", "httpx", "paramiko", "pycurl", "requests", "starlette",
    "twisted", "urllib3", "werkzeug",
}

RULE_HINT = {
    "CWE-329": "CRYPTO-006",
    "CWE-321": "CRYPTO-007",
    "CWE-338": "CRYPTO-008",
    "CWE-326": "CRYPTO-009",
    "CWE-295": "CRYPTO-010",
    "CWE-256": "CRYPTO-011",
    "CWE-916": "CRYPTO-012",
    "CWE-208": "CRYPTO-013",
}


def as_list(value):
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if value in (None, ""):
        return []
    return [str(value)]


def norm_cwe(value):
    text = str(value or "").strip().upper()
    match = re.search(r"(?:CWE[-_ ]?)?(\d{1,4})", text)
    return f"CWE-{int(match.group(1)):03d}" if match else ""


def record_cwes(record):
    values = []
    for value in as_list(record.get("cwe")) + as_list(record.get("cwe_all")):
        normalized = norm_cwe(value)
        if normalized and normalized not in values:
            values.append(normalized)
    return values


def match_reasons(record):
    return [str(value) for value in as_list(record.get("match_reasons"))]


def commit_hint(record):
    """Prefer a full same-repository SHA over an abbreviated advisory SHA."""
    repo_match = GITHUB_REPO.match(str(record.get("repo_url") or ""))
    primary = str(record.get("fix_commit") or "").strip()
    candidates = [primary] if primary else []
    if repo_match:
        owner, name = repo_match.group(1).lower(), repo_match.group(2).removesuffix(".git").lower()
        for reference in record.get("cross_references") or []:
            url = reference.get("url", "") if isinstance(reference, dict) else str(reference)
            match = GITHUB_COMMIT.match(url or "")
            if not match:
                continue
            ref_owner, ref_name, sha = match.groups()
            if ref_owner.lower() == owner and ref_name.removesuffix(".git").lower() == name:
                candidates.append(sha)
    seen = set()
    candidates = [value for value in candidates if value and not (value in seen or seen.add(value))]
    return sorted(candidates, key=len, reverse=True)[0] if candidates else ""


def repo_commit_url(record, commit=""):
    repo = str(record.get("repo_url") or "").rstrip("/")
    commit = commit or commit_hint(record)
    if not repo or not commit:
        return ""
    return f"{repo}/commit/{commit}"


def suggested_rule(cwes, text):
    for cwe in cwes:
        if cwe in RULE_HINT:
            return RULE_HINT[cwe]
    if "CWE-327" not in cwes:
        return ""
    lowered = (text or "").lower()
    if re.search(r"\bmd5\b", lowered):
        return "CRYPTO-001"
    if re.search(r"\bsha-?1\b", lowered):
        return "CRYPTO-002"
    if re.search(r"\b(?:3des|des)\b", lowered):
        return "CRYPTO-003"
    if re.search(r"\brc4\b", lowered):
        return "CRYPTO-004"
    if re.search(r"\becb\b", lowered):
        return "CRYPTO-005"
    return ""


def rank_record(record):
    """Return (score, tier, reasons, target_hit, advisory_text)."""
    cwes = record_cwes(record)
    target_hit = sorted(set(cwes) & TARGET_CWES)
    reasons = match_reasons(record)
    text = " ".join([
        str(record.get("package") or ""),
        str(record.get("advisory_id") or ""),
        " ".join(reasons),
    ])
    lowered_text = text.lower()
    package = str(record.get("package") or "").strip().lower()
    repo = str(record.get("repo_url") or "")
    commit = str(record.get("fix_commit") or "").strip()
    has_keyword = any(reason.startswith("keyword:") for reason in reasons)
    has_watchlist = any(reason.startswith("watchlist:") for reason in reasons)

    score = 0
    score_reasons = []
    if target_hit:
        score += 100
        score_reasons.append("target-cwe:" + ",".join(target_hit))
        if len(target_hit) > 1:
            score += 10
            score_reasons.append("multi-target-cwe")
    if has_keyword:
        score += 30
        score_reasons.append("crypto-keyword")
    if package in CORE_PACKAGES:
        score += 40
        score_reasons.append("core-crypto-package")
    elif package in SECONDARY_PACKAGES:
        score += 15
        score_reasons.append("security-sensitive-package")
    if has_watchlist:
        score += 5
        score_reasons.append("watchlist")
    if GITHUB_REPO.match(repo):
        score += 15
        score_reasons.append("github-repo")
    if len(commit) >= 7:
        score += 10
        score_reasons.append("fix-commit")
    if not target_hit and not has_keyword:
        score -= 50
        score_reasons.append("watchlist-only")
    if target_hit and has_keyword:
        tier = "P0"
    elif target_hit:
        tier = "P1"
    elif has_keyword and package in CORE_PACKAGES:
        tier = "P2"
    else:
        tier = "P3"
    return score, tier, score_reasons, target_hit, lowered_text


def load_jsonl(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def build_queue(records, scope):
    ranked = []
    for record in records:
        if not (GITHUB_REPO.match(str(record.get("repo_url") or ""))
                and str(record.get("fix_commit") or "").strip()):
            continue
        score, tier, reasons, target_hit, text = rank_record(record)
        if scope == "target" and not target_hit:
            continue
        if scope == "keyword" and not (
            target_hit
            or any(reason.startswith("keyword:") for reason in match_reasons(record))
        ):
            continue
        row = dict(record)
        row["a_fetch_priority"] = tier
        row["a_fetch_score"] = score
        row["a_fetch_reasons"] = reasons
        row["a_fetch_target_cwes"] = target_hit
        row["a_fetch_suggested_rule"] = suggested_rule(target_hit, text)
        row["a_fetch_commit_hint"] = commit_hint(row)
        row["a_fetch_commit_url"] = repo_commit_url(row, row["a_fetch_commit_hint"])
        ranked.append(row)

    ranked.sort(key=lambda row: (
        -int(row["a_fetch_score"]),
        row["a_fetch_priority"],
        row.get("package") or "",
        row.get("candidate_id") or "",
    ))
    selected = []
    seen = {"advisory": set(), "commit": set()}
    for row in ranked:
        advisory = str(row.get("advisory_id") or row.get("cve_id") or "")
        repo = str(row.get("repo_url") or "")
        commit = str(row.get("fix_commit") or "")
        commit_key = (repo, commit)
        if advisory and advisory in seen["advisory"]:
            continue
        if commit_key in seen["commit"]:
            continue
        if advisory:
            seen["advisory"].add(advisory)
        seen["commit"].add(commit_key)
        selected.append(row)
    return selected


def write_review_tsv(path, rows):
    columns = [
        "rank", "priority", "score", "candidate_id", "package", "cwe",
        "suggested_rule", "source", "repo_url", "fix_commit",
        "advisory_url", "commit_url", "reasons",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, delimiter="\t")
        writer.writeheader()
        for rank, row in enumerate(rows, 1):
            writer.writerow({
                "rank": rank,
                "priority": row.get("a_fetch_priority", ""),
                "score": row.get("a_fetch_score", ""),
                "candidate_id": row.get("candidate_id", ""),
                "package": row.get("package", ""),
                "cwe": row.get("cwe", ""),
                "suggested_rule": row.get("a_fetch_suggested_rule", ""),
                "source": row.get("source", ""),
                "repo_url": row.get("repo_url", ""),
                "fix_commit": row.get("a_fetch_commit_hint") or row.get("fix_commit", ""),
                "advisory_url": row.get("notification_url", ""),
                "commit_url": row.get("a_fetch_commit_url", ""),
                "reasons": ",".join(row.get("a_fetch_reasons") or []),
            })


def self_test():
    target = {
        "candidate_id": "x",
        "package": "pyjwt",
        "repo_url": "https://github.com/jpadilla/pyjwt",
        "fix_commit": "a" * 12,
        "cwe": "CWE-327",
        "match_reasons": ["cwe:CWE-327", "keyword:md5"],
    }
    score, tier, reasons, hit, text = rank_record(target)
    assert score >= 180 and tier == "P0", (score, tier, reasons)
    assert hit == ["CWE-327"] and suggested_rule(hit, text) == "CRYPTO-001"
    target["cross_references"] = [
        {"type": "FIX", "url": "https://github.com/jpadilla/pyjwt/commit/" + "c" * 40}
    ]
    assert commit_hint(target) == "c" * 40
    assert repo_commit_url(target).endswith("c" * 40)

    broad = {
        "candidate_id": "y",
        "package": "Django",
        "repo_url": "https://github.com/django/django",
        "fix_commit": "b" * 40,
        "cwe": "",
        "match_reasons": ["watchlist:Django"],
    }
    _, tier, reasons, hit, _ = rank_record(broad)
    assert tier == "P3" and not hit and "watchlist-only" in reasons

    selected = build_queue([target, broad], "target")
    assert len(selected) == 1 and selected[0]["candidate_id"] == "x"
    assert selected[0]["a_fetch_commit_hint"] == "c" * 40
    print("[self-test] A fetch queue ranking OK")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="infile", type=Path, default=DEFAULT_IN)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--review-out", type=Path, default=DEFAULT_REVIEW_OUT)
    parser.add_argument("--stats-out", type=Path, default=DEFAULT_STATS_OUT)
    parser.add_argument("--scope", choices=("target", "keyword", "all"),
                        default="target",
                        help="target=CWE only (default), keyword=+crypto keywords, all=all fetchable")
    parser.add_argument("--limit", type=int, default=0,
                        help="Maximum rows after ranking; 0 keeps all selected rows")
    parser.add_argument("--emit", action="store_true",
                        help="Write the queue, review TSV and stats JSON")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    infile = args.infile if args.infile.is_absolute() else ROOT / args.infile
    if not infile.exists():
        print(f"[FAIL] input not found: {infile}")
        return 1
    records = load_jsonl(infile)
    queue = build_queue(records, args.scope)
    if args.limit:
        queue = queue[:args.limit]

    stats = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": str(infile),
        "scope": args.scope,
        "input_rows": len(records),
        "selected_rows": len(queue),
        "selected_advisories": len({
            r.get("advisory_id") or r.get("cve_id") for r in queue
            if r.get("advisory_id") or r.get("cve_id")
        }),
        "selected_repos": len({r.get("repo_url") for r in queue if r.get("repo_url")}),
        "by_priority": dict(Counter(r["a_fetch_priority"] for r in queue)),
        "by_cwe": dict(Counter(
            cwe for row in queue for cwe in row.get("a_fetch_target_cwes") or []
        ).most_common()),
        "by_package": dict(Counter(
            row.get("package") or "?" for row in queue
        ).most_common(30)),
        "by_suggested_rule": dict(Counter(
            row.get("a_fetch_suggested_rule") or "?" for row in queue
        ).most_common()),
        "note": "A-fetch queue only; rows remain preliminary_class=B and verified=false.",
    }

    print(f"Input candidates : {len(records)}")
    print(f"Scope            : {args.scope}")
    print(f"Selected for A fetch: {len(queue)}")
    print("By priority      :", stats["by_priority"])
    print("By target CWE    :", stats["by_cwe"])
    print("By suggested rule:", stats["by_suggested_rule"])
    for rank, row in enumerate(queue[:20], 1):
        print(f"  {rank:2d}. {row['a_fetch_priority']} "
              f"{row.get('package',''):24s} {row.get('cwe',''):9s} "
              f"{row.get('a_fetch_suggested_rule') or '?':10s} "
              f"{row.get('candidate_id','')}")

    if not args.emit:
        print("\n[dry-run] no files written; add --emit")
        return 0

    out = args.out if args.out.is_absolute() else ROOT / args.out
    review_out = args.review_out if args.review_out.is_absolute() else ROOT / args.review_out
    stats_out = args.stats_out if args.stats_out.is_absolute() else ROOT / args.stats_out
    for path in (out, review_out, stats_out):
        path.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in queue) + "\n",
        encoding="utf-8",
    )
    write_review_tsv(review_out, queue)
    stats_out.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
                         encoding="utf-8")
    print(f"\n[+] wrote {out}")
    print(f"[+] wrote {review_out}")
    print(f"[+] wrote {stats_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
