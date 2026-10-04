#!/usr/bin/env python3
"""Turn advisory candidates into real vulnerable/fixed code pairs (needs network).

Reads the candidate JSONL produced by ``harvest_real_crypto_candidates.py`` and,
for every candidate that has a GitHub repo and a fix commit, downloads the fix
commit through the GitHub REST API, keeps the changed ``.py`` files, and splits
each unified diff into the vulnerable ("before") and fixed ("after") snippets.

This script only *collects evidence*. It never sets ``verified=true`` and never
writes training data; a human still has to read each pair and fill the
``real_verified_{detect,triage}.jsonl`` files described in
``data/round6/candidates/SCHEMA.md``.

Network is required for the real run, so it cannot execute inside the offline
sandbox. Run ``--self-test`` to check the diff parser without network, and
``--dry-run`` to see what would be fetched.

Usage:
    # offline sanity check of the diff parser
    python3 scripts/fetch_fix_code.py --self-test

    # see which candidates would be fetched (no requests)
    python3 scripts/fetch_fix_code.py --dry-run

    # real run (set a token to lift the 60 req/hour anonymous limit)
    GITHUB_TOKEN=ghp_xxx python3 scripts/fetch_fix_code.py
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.build_round6_final_dataset import RULE_CWE  # noqa: E402

DEFAULT_IN = ROOT / "data" / "round6" / "candidates" / "real_crypto_candidates.jsonl"
DEFAULT_OUT = ROOT / "data" / "round6" / "candidates" / "real_crypto_candidates_enriched.jsonl"
API = "https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
LICENSE_API = "https://api.github.com/repos/{owner}/{repo}/license"
RATE_LIMIT_API = "https://api.github.com/rate_limit"

GITHUB_REPO = re.compile(
    r"^https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+?)(?:/|$)"
)
GITHUB_COMMIT = re.compile(
    r"^https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+?)/(?:-/)?commit/"
    r"([0-9a-fA-F]{7,40})(?:[/?#]|$)"
)

# Coarse CWE -> rule hint. Only used to *suggest* a rule; the human confirms it.
# CWE-327/326 map to several rules, so they stay empty on purpose.
CWE_RULE_HINT = {
    "CWE-329": "CRYPTO-006",
    "CWE-321": "CRYPTO-007",
    "CWE-338": "CRYPTO-008",
    "CWE-256": "CRYPTO-011",
    "CWE-916": "CRYPTO-012",
    "CWE-208": "CRYPTO-013",
    "CWE-295": "CRYPTO-010",
}

NON_IMPLEMENTATION_SEGMENTS = {
    "benchmark", "benchmarks", "doc", "docs", "example", "examples",
    "fixture", "fixtures", "integration_test", "integration_tests",
    "test", "tests", "unit_test", "unit_tests",
}
CRYPTO_PATH_TERMS = {
    "auth", "cert", "cipher", "crypto", "hash", "hmac", "jwt", "key",
    "password", "random", "secret", "security", "sign", "ssl", "token",
    "tls", "verify",
}
CWE_PATCH_TERMS = {
    "CWE-208": {
        "compare_digest", "constant_time", "hmac", "secrets",
    },
    "CWE-256": {
        "decrypt", "encrypt", "key", "password", "secret",
    },
    "CWE-295": {
        "cert", "check_hostname", "context", "ssl", "tls", "verify",
    },
    "CWE-321": {
        "api_key", "key", "password", "secret", "token",
    },
    "CWE-326": {
        "aes", "cipher", "key_size", "rsa", "sha", "tls",
    },
    "CWE-327": {
        "des", "ecb", "hashlib", "md5", "rc4", "sha1",
    },
    "CWE-329": {
        "iv", "nonce", "random", "secrets",
    },
    "CWE-338": {
        "random", "randint", "secrets", "urandom",
    },
    "CWE-916": {
        "hash", "hashlib", "pbkdf2", "scrypt", "sha",
    },
}


def parse_patch(patch: str):
    """Split a unified diff into (vulnerable, fixed) source blocks.

    Context lines (leading space) appear in both blocks; removed lines go only
    into the vulnerable block and added lines only into the fixed block. This
    reconstructs the before/after view of the changed hunks without a checkout.
    """
    vuln, fixed = [], []
    for line in (patch or "").splitlines():
        if not line:
            continue
        if line.startswith("@@"):
            continue
        marker, body = line[0], line[1:]
        if marker == " ":
            vuln.append(body)
            fixed.append(body)
        elif marker == "-":
            vuln.append(body)
        elif marker == "+":
            fixed.append(body)
        elif marker == "\\":  # "\ No newline at end of file"
            continue
    return "\n".join(vuln), "\n".join(fixed)


def rule_hint(cwe: str) -> str:
    return CWE_RULE_HINT.get((cwe or "").strip(), "")


def github_repo(repo_url: str):
    match = GITHUB_REPO.match((repo_url or "").strip())
    if not match:
        return None
    return match.group(1), match.group(2).removesuffix(".git")


def is_nonimplementation_path(filename: str):
    """Reject test/example/doc paths before ranking implementation files."""
    path = str(filename or "").replace("\\", "/").strip().lower()
    if not path:
        return True, "empty filename"
    parts = [part for part in path.split("/") if part]
    leaf = parts[-1] if parts else ""
    for part in parts[:-1]:
        if part in NON_IMPLEMENTATION_SEGMENTS:
            return True, f"non-implementation directory: {part}"
    if leaf.startswith("test_") or leaf.endswith("_test.py") or leaf == "conftest.py":
        return True, "test filename"
    if any(term in leaf for term in ("fixture", "example", "benchmark")):
        return True, "fixture/example/benchmark filename"
    return False, ""


def changed_patch_lines(patch: str):
    return sum(
        1
        for line in (patch or "").splitlines()
        if line.startswith(("+", "-"))
        and not line.startswith(("+++", "---"))
    )


def score_python_file(filename: str, patch: str, record: dict):
    """Score one changed .py file for implementation-level evidence quality."""
    excluded, reason = is_nonimplementation_path(filename)
    if excluded:
        return -10_000, [reason]

    path = str(filename or "").replace("\\", "/").lower()
    leaf = path.rsplit("/", 1)[-1]
    patch_lower = (patch or "").lower()
    package = re.sub(r"[^a-z0-9]+", "", str(record.get("package") or "").lower())
    compact_path = re.sub(r"[^a-z0-9]+", "", path)
    reasons = []
    score = 0

    if package and len(package) >= 3 and package in compact_path:
        score += 8
        reasons.append("package-name-in-path")
    if re.search(r"(?:^|/)(?:src|lib|libs)/", path):
        score += 4
        reasons.append("src/lib-path")
    if path.startswith(("src/", "lib/", "libs/")):
        score += 2
        reasons.append("top-level-source-path")

    path_hits = sorted(term for term in CRYPTO_PATH_TERMS if term in leaf)
    if path_hits:
        score += 4 + min(len(path_hits), 3)
        reasons.append("crypto-path:" + ",".join(path_hits))

    cwe = str(record.get("cwe") or "").strip().upper()
    patch_terms = CWE_PATCH_TERMS.get(cwe, set())
    patch_hits = sorted(term for term in patch_terms if term in patch_lower)
    if patch_hits:
        score += 6 + min(len(patch_hits), 3)
        reasons.append("cwe-patch:" + ",".join(patch_hits))
    elif any(term in patch_lower for term in CRYPTO_PATH_TERMS):
        score += 2
        reasons.append("generic-crypto-patch")

    changed = changed_patch_lines(patch)
    score += min(changed // 10, 4)
    reasons.append(f"changed-lines:{changed}")
    if len(path) <= 80:
        score += 1
        reasons.append("focused-path")
    return score, reasons


def choose_primary_python_file(files, record: dict):
    """Return (file, selection_reason, candidate_scores).

    Implementation files are strongly preferred over tests, fixtures, examples,
    and documentation even when those files have a much larger patch.
    """
    ranked = []
    for file in files or []:
        filename = str(file.get("filename") or "")
        patch = str(file.get("patch") or "")
        score, reasons = score_python_file(filename, patch, record)
        ranked.append({
            "filename": filename,
            "score": score,
            "patch_lines": changed_patch_lines(patch),
            "patch_available": file.get("patch") is not None,
            "reasons": reasons,
        })
    ranked.sort(
        key=lambda item: (
            -item["score"],
            -item["patch_lines"],
            len(item["filename"]),
            item["filename"],
        )
    )
    implementation = [item for item in ranked if item["score"] > -10_000]
    if not implementation:
        return None, "no implementation .py file after excluding tests/examples/docs", ranked[:5]
    usable = [item for item in implementation if item["patch_available"]]
    selected = usable[0] if usable else implementation[0]
    reason = (
        f"selected {selected['filename']} "
        f"(score={selected['score']}; " + ", ".join(selected["reasons"])
        + ("; patch truncated" if not selected["patch_available"] else "") + ")"
    )
    return selected["filename"], reason, ranked[:5]


def api_get(url: str, token: str, timeout: int = 30):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "aie-crypto-auditor-fetchfix",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read())


def candidate_commits(record: dict, owner: str, name: str):
    """Return the primary fix SHA plus same-repository cross-reference SHAs."""
    values = [str(record.get("fix_commit") or "").strip()]
    for reference in record.get("cross_references") or []:
        url = reference.get("url", "") if isinstance(reference, dict) else str(reference)
        match = GITHUB_COMMIT.match(url or "")
        if not match:
            continue
        ref_owner, ref_name, sha = match.groups()
        if ref_owner.lower() == owner.lower() and ref_name.removesuffix(".git").lower() == name.lower():
            values.append(sha)
    seen = set()
    values = [value for value in values if value and not (value in seen or seen.add(value))]
    return sorted(values, key=len, reverse=True)


def repository_license(data: dict):
    """Extract a concrete SPDX license from a repo/license API response."""
    repository = data.get("repository") or {}
    license_obj = data.get("license") or repository.get("license") or {}
    spdx = str(license_obj.get("spdx_id") or "").strip()
    name = str(license_obj.get("name") or "").strip()
    if spdx and spdx.upper() not in {"NOASSERTION", "NONE", "UNKNOWN"}:
        return spdx, name, data.get("html_url") or ""
    return "", name, data.get("html_url") or ""


def fetch_repository_license(owner: str, name: str, token: str, cache: dict):
    """Fetch and cache a repository SPDX license, returning (spdx, name, url, status)."""
    key = (owner.lower(), name.lower())
    if key in cache:
        return cache[key]
    try:
        data = api_get(LICENSE_API.format(owner=owner, repo=name), token)
        spdx, license_name, license_url = repository_license(data)
        result = (spdx, license_name, license_url, "ok" if spdx else "not declared")
    except urllib.error.HTTPError as exc:
        result = ("", "", "", f"HTTP {exc.code}")
    except Exception as exc:  # noqa: BLE001 - do not lose the code evidence
        result = ("", "", "", f"{type(exc).__name__}: {exc}")
    cache[key] = result
    return result


def enrich_candidate(record: dict, token: str, license_cache: dict):
    """Return (updated_record, status) where status is 'ok'|'skip'|'error: ...'."""
    repo = github_repo(record.get("repo_url", ""))
    if not repo:
        return record, "skip: repo_url is not a github repo"
    if not record.get("fix_commit"):
        return record, "skip: no fix_commit"
    owner, name = repo
    data = None
    resolved_sha = ""
    last_error = ""
    for sha in candidate_commits(record, owner, name):
        url = API.format(owner=owner, repo=name, sha=sha)
        try:
            data = api_get(url, token)
            resolved_sha = sha
            break
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
            if exc.code == 404:
                continue
            return record, f"error: {last_error}"
        except Exception as exc:  # noqa: BLE001 - surface any transport failure
            return record, f"error: {type(exc).__name__}: {exc}"
    if data is None:
        return record, "skip: fix commit not found via API"

    parents = data.get("parents") or []
    parent_sha = parents[0].get("sha") if parents else ""
    full_sha = str(data.get("sha") or resolved_sha)
    files = data.get("files") or []
    py_files = [f for f in files if str(f.get("filename", "")).endswith(".py")]
    if not py_files:
        return record, "skip: no .py changes in fix commit"

    filename, selection_reason, candidate_scores = choose_primary_python_file(py_files, record)
    if not filename:
        return record, f"skip: {selection_reason}"
    primary = next((file for file in py_files if file.get("filename") == filename), None)
    if primary is None:
        return record, "error: selected file disappeared from commit response"
    patch = primary.get("patch") or ""
    vuln_code, fixed_code = parse_patch(patch)
    if not vuln_code.strip() or not fixed_code.strip():
        return record, "skip: patch has no removable/added python lines"

    record = dict(record)
    record["file_path"] = primary.get("filename", "")
    record["code_vuln"] = vuln_code
    record["code_fixed"] = fixed_code
    record["fix_commit_original"] = str(record.get("fix_commit") or "")
    record["fix_commit"] = full_sha
    record["fix_commit_full"] = full_sha
    record["parent_sha"] = parent_sha
    record["fix_patch"] = patch
    record["fix_patch_file"] = primary.get("filename", "")
    record["code_vuln_url"] = (
        f"https://github.com/{owner}/{name}/blob/{parent_sha}/{primary.get('filename','')}"
        if parent_sha else ""
    )
    record["code_fixed_url"] = (
        f"https://github.com/{owner}/{name}/blob/{full_sha}/{primary.get('filename','')}"
    )
    record["a_fetch_commit_url"] = f"https://github.com/{owner}/{name}/commit/{full_sha}"
    record["selected_file_reason"] = selection_reason
    record["py_file_candidates"] = candidate_scores
    if not record.get("vuln_commit"):
        record["vuln_commit"] = parent_sha
    record["changed_py_files"] = [f.get("filename", "") for f in py_files]
    license_spdx, license_name, license_url, license_status = fetch_repository_license(
        owner, name, token, license_cache
    )
    if not license_spdx:
        fallback_spdx, fallback_name, fallback_url = repository_license(data)
        license_spdx = license_spdx or fallback_spdx
        license_name = license_name or fallback_name
        license_url = license_url or fallback_url
        if fallback_spdx:
            license_status = "commit-api fallback"
    if license_spdx:
        record["license"] = license_spdx
    if license_name:
        record["license_name"] = license_name
    if license_url:
        record["license_url"] = license_url
    record["license_fetch_status"] = license_status
    # The REST API omits ``patch`` for very large files; note that for review.
    record["patch_truncated"] = primary.get("patch") is None
    if not record.get("rule_id"):
        record["rule_id"] = rule_hint(record.get("cwe", ""))
    record["fetched_at"] = datetime.now(timezone.utc).isoformat()
    record["verified"] = False
    return record, "ok"


def self_test():
    patch = (
        "@@ -1,4 +1,5 @@\n"
        " import hashlib\n"
        " def sign(msg, key):\n"
        "-    return hashlib.md5(msg).hexdigest()\n"
        "+    return hashlib.sha256(msg).hexdigest()\n"
        " \n"
    )
    vuln, fixed = parse_patch(patch)
    assert "hashlib.md5" in vuln and "hashlib.sha256" not in vuln, vuln
    assert "hashlib.sha256" in fixed and "hashlib.md5" not in fixed, fixed
    assert "def sign" in vuln and "def sign" in fixed
    assert rule_hint("CWE-329") == "CRYPTO-006"
    assert rule_hint("CWE-327") == ""  # ambiguous, human decides
    assert github_repo("https://github.com/pyca/cryptography") == ("pyca", "cryptography")
    assert github_repo("https://gitlab.com/x/y") is None
    selection_record = {"package": "pyjwt", "cwe": "CWE-327"}
    files = [
        {
            "filename": "tests/test_jwt.py",
            "patch": "@@ -1 +1 @@\n-hashlib.md5(x)\n+hashlib.sha256(x)\n" * 20,
        },
        {
            "filename": "jwt/algorithms.py",
            "patch": "@@ -1 +1 @@\n-hashlib.md5(x)\n+hashlib.sha256(x)\n",
        },
    ]
    filename, reason, _ = choose_primary_python_file(files, selection_record)
    assert filename == "jwt/algorithms.py", (filename, reason)
    only_tests, only_reason, _ = choose_primary_python_file(files[:1], selection_record)
    assert only_tests is None and "no implementation" in only_reason
    assert repository_license(
        {"license": {"spdx_id": "Apache-2.0", "name": "Apache License 2.0"}}
    )[0] == "Apache-2.0"
    commit_record = {
        "fix_commit": "abc1234",
        "cross_references": [
            {"type": "FIX", "url": "https://github.com/pyca/cryptography/commit/" + "d" * 40}
        ],
    }
    assert candidate_commits(commit_record, "pyca", "cryptography") == ["d" * 40, "abc1234"]
    for rule, cwes in RULE_CWE.items():
        assert rule.startswith("CRYPTO-")
    print("[self-test] fetch_fix_code parser OK")


def preflight(token: str, needed: int):
    """Check that GitHub API access works and report the remaining core quota."""
    try:
        data = api_get(RATE_LIMIT_API, token)
    except urllib.error.HTTPError as exc:
        print(f"[FAIL] GitHub API preflight returned HTTP {exc.code}; refresh GITHUB_TOKEN")
        return False
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] GitHub API preflight failed: {type(exc).__name__}: {exc}")
        return False
    core = (data.get("resources") or {}).get("core") or {}
    remaining = core.get("remaining")
    limit = core.get("limit")
    print(f"[preflight] GitHub core quota: {remaining}/{limit}")
    if isinstance(remaining, int) and remaining < needed:
        print(f"[FAIL] {remaining} GitHub API calls remain but this run needs about "
              f"{needed} (commit + repository-license requests); wait or use a fresh token")
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch fix-commit diffs for candidates")
    ap.add_argument("--in", dest="infile", type=Path, default=DEFAULT_IN)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""),
                    help="GitHub token (or set GITHUB_TOKEN); raises the rate limit")
    ap.add_argument("--limit", type=int, default=0, help="Stop after N candidates")
    ap.add_argument("--sleep", type=float, default=1.0,
                    help="Seconds between API calls (be polite)")
    ap.add_argument("--dry-run", action="store_true",
                    help="List fetchable candidates without calling the API")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return 0

    infile = args.infile if args.infile.is_absolute() else ROOT / args.infile
    if not infile.exists():
        print(f"[FAIL] candidate file not found: {infile}")
        return 1
    records = [json.loads(l) for l in infile.read_text(encoding="utf-8").splitlines() if l.strip()]

    fetchable = [r for r in records if github_repo(r.get("repo_url", "")) and r.get("fix_commit")]
    print(f"Candidates: {len(records)}  fetchable (github+commit): {len(fetchable)}")

    if args.dry_run:
        for r in fetchable:
            owner, name = github_repo(r["repo_url"])
            print(f"  {r.get('package',''):14} {r.get('cwe',''):9} "
                  f"{owner}/{name}@{r['fix_commit'][:12]}")
        print("\n[dry-run] no requests made")
        return 0

    out = args.out if args.out.is_absolute() else ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    selected_for_fetch = fetchable[:args.limit] if args.limit else fetchable
    selected_repos = {
        tuple(part.lower() for part in github_repo(record.get("repo_url", "")))
        for record in selected_for_fetch
    }
    needed = len(selected_for_fetch) + len(selected_repos)
    if not preflight(args.token, needed):
        return 1

    enriched, statuses = [], {}
    license_cache = {}
    fetched = 0
    for record in records:
        if args.limit and fetched >= args.limit:
            enriched.append(record)
            continue
        if not (github_repo(record.get("repo_url", "")) and record.get("fix_commit")):
            updated = dict(record)
            updated["fetch_status"] = "skip: repo_url is not github or no fix_commit"
            statuses[updated.get("candidate_id", "?")] = updated["fetch_status"]
            enriched.append(updated)
            continue
        if fetched:
            time.sleep(max(args.sleep, 0))
        updated, status = enrich_candidate(record, args.token, license_cache)
        updated = dict(updated)
        updated["fetch_status"] = status
        fetched += 1
        statuses[updated.get("candidate_id", "?")] = status
        enriched.append(updated)
        print(f"  [{status:12}] {updated.get('package','')}: {updated.get('cve_id','')}")

    out.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in enriched) + "\n",
        encoding="utf-8")

    ok = sum(1 for s in statuses.values() if s == "ok")
    print(f"\n[+] {out}: {len(enriched)} row(s), {ok} enriched with code pairs")
    if ok:
        print("Next: read each pair, fill human_verdict and rule_id, then write "
              "data/round6/real_verified_{detect,triage}.jsonl (see SCHEMA.md)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
