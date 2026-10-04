#!/usr/bin/env python3
"""Rebuild candidate code pairs at function level (needs network for the real run).

``fetch_fix_code.py`` reconstructs only the changed diff hunks. Those fragments
are useful evidence but they do not parse as Python, so they cannot be used as
detect/triage training samples. This script closes that gap:

1. For every candidate with a GitHub repo, a fix commit and a changed .py file,
   fetch the file at the fix commit and at its parent through
   ``raw.githubusercontent.com``.
2. Parse both revisions with ``ast``, map the patch's changed lines to the
   innermost enclosing function, and extract that **complete** function.
3. Write an enriched pool where ``code_vuln``/``code_fixed`` parse on their own
   and ``code_quality`` is ``function`` instead of ``diff_fragment``.

Like every other collector it only gathers evidence: ``verified`` stays false and
``human_verdict`` is untouched. A human still confirms each pair.

Usage:
    python3 scripts/rebuild_candidate_functions.py --self-test   # offline
    python3 scripts/rebuild_candidate_functions.py --dry-run     # no requests
    GITHUB_TOKEN=ghp_xxx python3 scripts/rebuild_candidate_functions.py
"""
import argparse
import ast
import json
import os
import re
import sys
import textwrap
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CAND_DIR = ROOT / "data" / "round6" / "candidates"
DEFAULT_IN = CAND_DIR / "real_crypto_candidates_screened.jsonl"
DEFAULT_OUT = CAND_DIR / "real_crypto_candidates_functions.jsonl"

RAW = "https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}"
COMMITS_API = "https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
GITHUB_REPO = re.compile(
    r"^https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+?)(?:/|$)"
)
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", re.MULTILINE)


def get(record, *keys):
    for key in keys:
        value = record.get(key)
        if value:
            return value
    return ""


def github_repo(repo_url):
    match = GITHUB_REPO.match((repo_url or "").strip())
    if not match:
        return None
    return match.group(1), match.group(2).removesuffix(".git")


def first_added_line(patch: str) -> int:
    """1-based line number in the *fixed* file of the first added line."""
    fixed_line = None
    for line in (patch or "").splitlines():
        header = HUNK.match(line)
        if header:
            fixed_line = int(header.group(1))
            continue
        if fixed_line is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            return fixed_line
        if not line.startswith("-"):
            fixed_line += 1
    return 0


def first_removed_line(patch: str) -> int:
    """1-based line number in the *parent* file of the first removed line."""
    old_line = None
    for line in (patch or "").splitlines():
        header = re.match(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@", line)
        if header:
            old_line = int(header.group(1))
            continue
        if old_line is None:
            continue
        if line.startswith("-") and not line.startswith("---"):
            return old_line
        if not line.startswith("+"):
            old_line += 1
    return 0


def changed_lines(patch: str, side: str):
    """Return all changed 1-based line numbers for ``old`` or ``new`` side."""
    if side not in {"old", "new"}:
        raise ValueError(side)
    line_number = None
    values = []
    for line in (patch or "").splitlines():
        header = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if header:
            line_number = int(header.group(1 if side == "old" else 2))
            continue
        if line_number is None:
            continue
        if side == "old" and line.startswith("-") and not line.startswith("---"):
            values.append(line_number)
            line_number += 1
        elif side == "new" and line.startswith("+") and not line.startswith("+++"):
            values.append(line_number)
            line_number += 1
        elif not line.startswith(("+", "-")):
            line_number += 1
    return values


def context_lines(patch: str, side: str):
    """Return unchanged hunk line numbers; used when a patch only adds/deletes."""
    line_number = None
    values = []
    for line in (patch or "").splitlines():
        header = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if header:
            line_number = int(header.group(1 if side == "old" else 2))
            continue
        if line_number is None:
            continue
        if line.startswith(" "):
            values.append(line_number)
            line_number += 1
        elif side == "old" and line.startswith("-") and not line.startswith("---"):
            line_number += 1
        elif side == "new" and line.startswith("+") and not line.startswith("+++"):
            line_number += 1
    return values


def function_for_changes(source: str, patch: str, side: str):
    """Find the first changed line that belongs to a parseable function."""
    lines = changed_lines(patch, side)
    if not lines:
        lines = context_lines(patch, side)
    for line in lines:
        block, name = enclosing_function(source, line)
        if block:
            return block, name, line
    return None, "", 0



def enclosing_function(source: str, line: int):
    """Return the source of the innermost function containing ``line``.

    ``line`` is 1-based. The outermost function on the path is returned so the
    extracted block is a complete, independently parseable function/method.
    """
    if not source or line <= 0:
        return None, ""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None, ""
    lines = source.splitlines(keepends=True)
    best = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = min([node.lineno] + [d.lineno for d in node.decorator_list])
        if start <= line <= node.end_lineno:
            if best is None or start < best[0]:
                best = (start, node.end_lineno, node.name)
    if not best:
        return None, ""
    start, end, name = best
    block = textwrap.dedent("".join(lines[start - 1:end]).rstrip()) + "\n"
    try:
        ast.parse(block)
    except (SyntaxError, ValueError):
        return None, name
    return block, name


def fetch_text(url: str, token: str, timeout: int = 30):
    headers = {"User-Agent": "aie-crypto-auditor-rebuild"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def fetch_commit_files(owner: str, repo: str, sha: str, token: str):
    """Return {filename: patch} for the commit's .py changes."""
    url = COMMITS_API.format(owner=owner, repo=repo, sha=sha)
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "aie-crypto-auditor-rebuild",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.loads(response.read())
    parents = data.get("parents") or []
    parent_sha = parents[0].get("sha") if parents else ""
    patches = {
        f.get("filename"): f.get("patch") or ""
        for f in data.get("files") or []
        if str(f.get("filename", "")).endswith(".py")
    }
    return parent_sha, patches


def rebuild(record: dict, token: str):
    """Return (updated_record, status). Status starts with ok:/skip:/error:."""
    repo = github_repo(record.get("repo_url", ""))
    sha = str(get(record, "fix_commit_full", "fix_commit")).strip()
    file_path = get(record, "file_path")
    if not repo:
        return record, "skip: not a github repo"
    if not sha:
        return record, "skip: no fix_commit"
    if not file_path.endswith(".py"):
        return record, "skip: no .py file_path"
    owner, name = repo
    parent_sha = str(get(record, "parent_sha", "vuln_commit")).strip()
    stored_patch = get(record, "fix_patch")
    stored_file = get(record, "fix_patch_file")
    if parent_sha and stored_patch and (not stored_file or stored_file == file_path):
        patches = {file_path: stored_patch}
    else:
        try:
            parent_sha, patches = fetch_commit_files(owner, name, sha, token)
        except urllib.error.HTTPError as exc:
            return record, f"error: commit HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001
            return record, f"error: {type(exc).__name__}: {exc}"
    if not parent_sha:
        return record, "skip: no parent commit"
    patch = patches.get(file_path, "")
    if not patch:
        # The file may have been renamed in the commit; fall back to record code.
        return record, "skip: no patch for file_path in commit"

    try:
        old_src = fetch_text(RAW.format(owner=owner, repo=name, sha=parent_sha, path=file_path), token)
        new_src = fetch_text(RAW.format(owner=owner, repo=name, sha=sha, path=file_path), token)
    except urllib.error.HTTPError as exc:
        return record, f"error: raw HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return record, f"error: {type(exc).__name__}: {exc}"

    vuln_code, vuln_name, old_line = function_for_changes(old_src, patch, "old")
    fixed_code, fixed_name, new_line = function_for_changes(new_src, patch, "new")
    if not vuln_code or not fixed_code:
        return record, "skip: changed line is not inside a function"

    record = dict(record)
    record.update({
        "fix_commit": sha,
        "fix_commit_full": sha,
        "vuln_commit": parent_sha,
        "parent_sha": parent_sha,
        "file_path": file_path,
        "function_name": fixed_name or vuln_name,
        "code_vuln": vuln_code,
        "code_fixed": fixed_code,
        "code_vuln_url": f"https://github.com/{owner}/{name}/blob/{parent_sha}/{file_path}",
        "code_fixed_url": f"https://github.com/{owner}/{name}/blob/{sha}/{file_path}",
        "code_quality": "function",
        "function_source_lines": {
            "vulnerable": old_line,
            "fixed": new_line,
        },
        "rebuilt_at": datetime.now(timezone.utc).isoformat(),
        "verified": False,
    })
    return record, "ok: function extracted"


def self_test():
    source = (
        "import hashlib\n"
        "\n"
        "def outer(data):\n"
        "    def inner(blob):\n"
        "        return hashlib.md5(blob).hexdigest()\n"
        "    return inner(data)\n"
        "\n"
        "def other():\n"
        "    return 1\n"
    )
    block, name = enclosing_function(source, 5)
    assert block and name == "outer", (block, name)
    assert "def inner" in block and "def other" not in block
    class_source = (
        "import hmac\n"
        "\n"
        "class Verifier:\n"
        "    def verify(self, left, right):\n"
        "        return left == right\n"
    )
    class_block, class_name = enclosing_function(class_source, 5)
    assert class_block and class_name == "verify", (class_block, class_name)
    assert class_block.startswith("def verify"), class_block
    ast.parse(class_block)
    patch = (
        "@@ -1,7 +1,8 @@\n"
        " import hashlib\n"
        " \n"
        " def sign(msg, key):\n"
        "-    return hashlib.md5(msg).hexdigest()\n"
        "+    return hashlib.sha256(msg).hexdigest()\n"
    )
    assert first_removed_line(patch) == 4, first_removed_line(patch)
    assert first_added_line(patch) == 4, first_added_line(patch)
    assert changed_lines(patch, "old") == [4], changed_lines(patch, "old")
    assert changed_lines(patch, "new") == [4], changed_lines(patch, "new")
    addition_only = "@@ -4,0 +5,1 @@\n+        check_certificate()\n"
    assert changed_lines(addition_only, "old") == [], changed_lines(addition_only, "old")
    assert context_lines(addition_only, "old") == [], context_lines(addition_only, "old")
    print("[self-test] function rebuild locator OK")


def main() -> int:
    ap = argparse.ArgumentParser(description="Rebuild candidate functions at commit level")
    ap.add_argument("--in", dest="infile", type=Path, default=DEFAULT_IN)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sleep", type=float, default=1.0)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return 0

    infile = args.infile if args.infile.is_absolute() else ROOT / args.infile
    if not infile.exists():
        print(f"[FAIL] input not found: {infile}")
        return 1
    records = [json.loads(l) for l in infile.read_text(encoding="utf-8").splitlines() if l.strip()]
    todo = [r for r in records if github_repo(r.get("repo_url", "")) and r.get("fix_commit")]
    print(f"Candidates: {len(records)}  ms-level rebuildable: {len(todo)}")

    if args.dry_run:
        for r in todo[:50]:
            owner, name = github_repo(r["repo_url"])
            print(f"  {r.get('package',''):18} {r.get('cwe',''):9} "
                  f"{owner}/{name}@{str(get(r, 'fix_commit_full', 'fix_commit'))[:12]} "
                  f"{get(r, 'file_path')}")
        print("\n[dry-run] no requests made")
        return 0

    out = args.out if args.out.is_absolute() else ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    enriched, ok, processed = [], 0, 0
    for record in records:
        if args.limit and processed >= args.limit:
            enriched.append(record)
            continue
        if not (github_repo(record.get("repo_url", "")) and record.get("fix_commit")):
            updated = dict(record)
            updated["rebuild_status"] = "skip: not a github repo or no fix_commit"
            enriched.append(updated)
            continue
        if processed:
            time.sleep(max(args.sleep, 0))
        updated, status = rebuild(record, args.token)
        updated = dict(updated)
        updated["rebuild_status"] = status
        processed += 1
        if status.startswith("ok"):
            ok += 1
        enriched.append(updated)
        print(f"  [{status:28}] {updated.get('package','')}: {updated.get('cve_id','')}")

    out.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in enriched) + "\n",
        encoding="utf-8")
    print(f"\n[+] {out}: {len(enriched)} row(s), {ok} function-level pair(s)")
    print("Next: re-run screen_real_crypto_candidates.py on this file, then the model audit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
