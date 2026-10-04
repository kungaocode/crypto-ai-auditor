#!/usr/bin/env python3
"""Harvest real Python-crypto advisory candidates into the R6 candidate pool.

Reads advisory records that follow the OSV schema (a local clone of
github/advisory-database, an OSV export, the PyPA YAML mirror, or an OSV API
response) and keeps the PyPI advisories that are plausibly about Python crypto
misuse. Three independent signals widen the pool:

  * target/extra CWE membership (authoritative when present),
  * the PyPI package watchlist,
  * --keyword-recall over the advisory text (for PYSEC/YAML records that carry
    no CWE tag at all).

Matching is a *recall* step: it emits candidate skeleton rows for human review.

It is intentionally conservative: every emitted row is ``preliminary_class``
"B" with ``verified=false``. A machine cannot promote a candidate to A-class;
that requires a human reading the advisory, the fix commit and the code.

Sources (choose one or more):
    --advisories DIR|FILE   local JSON/JSONL/YAML advisory records (dirs walked)
    --fetch-osv             query api.osv.dev for each package (needs network)

Examples:
    # PyPA YAML mirror, where advisories have no CWE tag.
    python3 scripts/harvest_real_crypto_candidates.py \
        --advisories data/external/pypa-advisory-database/vulns \
        --keyword-recall --source-label PyPA --id-prefix pypa \
        --out data/round6/candidates/real_crypto_candidates_pypa.jsonl

    # OSV PyPI export with extra adjacent CWEs.
    python3 scripts/harvest_real_crypto_candidates.py \
        --advisories data/external/osv-pypi --all-packages --keyword-recall \
        --extra-cwes CWE-347,CWE-798,CWE-319,CWE-330,CWE-311,CWE-328

Output:
    data/round6/candidates/real_crypto_candidates.jsonl

Then:
    python3 scripts/validate_real_crypto_candidates.py \
        data/round6/candidates/real_crypto_candidates.jsonl --min-a 20
    # fill evidence, assign A/B/C/D, write real_verified_{detect,triage}.jsonl
    python3 scripts/build_round6_final_dataset.py --emit
"""
import argparse
import json
import re
import sys
import tempfile
import urllib.request
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:  # PyYAML is only needed for the PyPA .yaml advisory mirror.
    yaml = None

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.build_round6_final_dataset import TARGET_CWES  # noqa: E402

DEFAULT_OUT = ROOT / "data" / "round6" / "candidates" / "real_crypto_candidates.jsonl"
OSV_QUERY = "https://api.osv.dev/v1/query"

# Packages worth watching for crypto-misuse fixes. --all-packages disables this.
DEFAULT_PACKAGES = [
    # Core crypto / TLS libraries
    "cryptography", "pycryptodome", "pycryptodomex", "pycrypto", "pyopenssl",
    "python-rsa", "rsa", "ecdsa", "pynacl", "nacl", "m2crypto", "gmpy2",
    "pyca", "cryptography-vectors", "openssl", "oscrypto", "asn1crypto",
    # Password / KDF / randomness
    "passlib", "bcrypt", "argon2-cffi", "scrypt", "pyscrypt", "pbkdf2",
    "simple-crypt", "cryptography-fernet",
    # JWT / JOSE / OAuth / SSO
    "pyjwt", "python-jose", "jose", "josepy", "authlib", "oauthlib",
    "django-allauth", "fido2", "webauthn", "python3-saml",
    # Web / HTTP / TLS clients
    "requests", "urllib3", "httpx", "aiohttp", "tornado", "certifi",
    "flask", "werkzeug", "django", "starlette", "fastapi", "itsdangerous",
    "paramiko", "asyncssh", "fabric", "twisted", "pycurl", "httplib2",
    # Misc crypto-touching
    "xmlsec", "pyotp", "onetimepass", "keyring", "secretstorage", "cryptolyzer",
]

COMMIT_URL = re.compile(
    r"https?://(?:www\.)?(?:github|gitlab)\.com/[^/]+/[^/]+/(?:commit|-/commit)/[0-9a-fA-F]{7,40}"
)

# Malware advisories (OSV "MAL-*", GHSA "MAL-*") describe malicious packages,
# not crypto misuse, so they are dropped from the candidate pool by default.
MALICIOUS_ID = re.compile(r"\bMAL-\d{4}-\d+\b", re.IGNORECASE)

# Crypto-misuse recall net for --keyword-recall. PyPA/PYSEC records usually carry
# no CWE, so the advisory text is the only local signal. Matching here only
# widens the pool for human/model review: it never assigns a CWE and never sets
# verified=true. Every emitted row stays preliminary_class "B".
CRYPTO_KEYWORD = re.compile(
    r"\b(?:hashlib|hmac|md5|sha-?1\b|sha-?256|weak\s+(?:hash|cipher|algorithm|"
    r"prng|random|entropy)|ecb\b|rc4\b|hard-?coded\s+(?:key|secret|password|"
    r"credential|token)|getrandbits|urandom|constant[- ]time|timing\s+(?:attack|"
    r"side)|iv\s+reuse|nonce\s+reuse|salt\b|jwt\b|signature\s+verification|"
    r"verify\s*=\s*false|check_hostname|certificate\s+validation|"
    r"password\s+hashing|key\s+derivation|kdf\b|pkcs7|cipher\s+suite)\b",
    re.IGNORECASE,
)


ADVISORY_SUFFIXES = (".json", ".jsonl", ".yaml", ".yml")
# OSV-shaped containers seen in local mirrors and API responses.
CONTAINER_KEYS = ("vulns", "advisories", "results", "records", "data")


def load_records(path: Path):
    """Yield advisory dicts from a JSON/JSONL/YAML file or a directory tree.

    Handles the shapes actually present under data/external: one advisory per
    ``GHSA-*.json`` file (github/advisory-database), one advisory per
    ``PYSEC-*.yaml`` file (pypa/advisory-database) and OSV API exports that wrap
    a list under ``vulns``/``advisories``/``results``. Unreadable files are
    skipped rather than aborting the whole scan.
    """
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file() and child.suffix.lower() in ADVISORY_SUFFIXES:
                yield from load_records(child)
        return
    if path.suffix.lower() not in ADVISORY_SUFFIXES:
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    stripped = text.lstrip()
    if not stripped:
        return
    is_yaml = path.suffix.lower() in (".yaml", ".yml")
    if is_yaml and yaml is None:
        raise RuntimeError(
            "PyYAML is required to read .yaml advisories; pip install pyyaml")
    try:
        if is_yaml:
            obj = yaml.safe_load(text)
        elif path.suffix.lower() == ".jsonl":
            for line in text.splitlines():
                if line.strip():
                    item = json.loads(line)
                    if isinstance(item, dict):
                        yield item
            return
        else:
            obj = json.loads(text)
    except json.JSONDecodeError:
        return
    except Exception:  # yaml.YAMLError and any other malformed-record failure
        return
    yield from _iter_advisories(obj)


def _iter_advisories(obj):
    """Flatten a loaded JSON/YAML object into advisory dicts."""
    if isinstance(obj, list):
        for item in obj:
            yield from _iter_advisories(item)
        return
    if not isinstance(obj, dict):
        return
    for key in CONTAINER_KEYS:
        container = obj.get(key)
        if isinstance(container, list):
            for item in container:
                yield from _iter_advisories(item)
            return
    # A dict that looks like a single advisory (has an id and affected/refs).
    if obj.get("id") or obj.get("ghsa_id") or obj.get("affected"):
        yield obj


def advisory_text(adv: dict) -> str:
    """Joined free text used by --keyword-recall (summary + details + id)."""
    return "\n".join(
        str(adv.get(key) or "") for key in ("id", "ghsa_id", "summary", "details")
    )


def advisory_cwes(adv: dict):
    cwes = set()
    db = adv.get("database_specific") or {}
    for value in db.get("cwe_ids") or []:
        cwes.add(str(value))
    for value in adv.get("cwe_ids") or []:
        cwes.add(str(value))
    # Some GHSA exports nest CWE under a top-level "cwe" list.
    for value in adv.get("cwe") or []:
        cwes.add(str(value))
    return cwes


def advisory_packages(adv: dict):
    names = []
    for affected in adv.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem = str(package.get("ecosystem") or "").lower()
        name = package.get("name")
        if name and ecosystem in ("pypi", "pip"):
            names.append(name)
    return names


def ref_urls(adv: dict):
    urls = []
    for ref in adv.get("references") or []:
        url = ref.get("url") if isinstance(ref, dict) else ref
        if url:
            urls.append(str(url))
    return urls


def fixed_versions(adv: dict):
    versions = []
    for affected in adv.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    versions.append(str(event["fixed"]))
    return versions


def cve_from(adv: dict):
    for alias in adv.get("aliases") or []:
        if str(alias).startswith("CVE-"):
            return str(alias)
    for key in ("cve", "cve_id"):
        if adv.get(key):
            return str(adv[key])
    return ""


def advisory_match(adv, *, target_cwes, watch, keyword_recall, all_packages,
                   cwe_only, include_malicious):
    """Decide whether an advisory is in scope and record *why* it matched.

    Returns a match dict, or the sentinel strings "malicious"/"withdrawn" so the
    caller can report those skips separately, or ``None`` when out of scope.

    CWE matching stays authoritative. The package watchlist and the
    --keyword-recall net only widen the pool for later human/model review; they
    never assign a CWE, a rule, or verified=true.
    """
    advisory_id = str(adv.get("id") or adv.get("ghsa_id") or "")
    if not advisory_id:
        return None
    if not include_malicious and MALICIOUS_ID.search(advisory_id):
        return "malicious"
    if adv.get("withdrawn"):
        return "withdrawn"
    packages = advisory_packages(adv)
    if not packages:  # Python-only pool: ignore non-PyPI advisories.
        return None
    cwes_all = sorted(advisory_cwes(adv))
    hit = sorted(set(cwes_all) & target_cwes)
    reasons = []
    if hit:
        reasons.append("cwe:" + ",".join(hit))
    if not all_packages:
        watched = sorted({p for p in packages if p.lower() in watch})
        if watched:
            reasons.append("watchlist:" + ",".join(watched))
    if keyword_recall:
        found = CRYPTO_KEYWORD.search(advisory_text(adv))
        if found:
            reasons.append("keyword:" + re.sub(r"\s+", "_", found.group(0).lower()))
    if cwe_only and not hit:
        return None
    if not reasons:
        return None
    return {
        "advisory_id": advisory_id,
        "packages": packages,
        "cwes_all": cwes_all,
        "hit": hit,
        "reasons": reasons,
    }


def build_candidate(adv: dict, match: dict, *, source_label: str = "GHSA/OSV",
                    id_prefix: str = "osv"):
    """Turn one in-scope advisory into a single candidate row.

    The row points at the primary fix commit; any additional fix commits are
    listed in ``cross_references`` so a later fetcher can try them too. Emitted
    rows are always ``preliminary_class`` "B" with ``verified=false``: a machine
    may narrow the pool but may not promote a candidate to A-class.
    """
    commits = []
    for url in ref_urls(adv):
        found = COMMIT_URL.search(url)
        if found and found.group(0) not in commits:
            commits.append(found.group(0))
    advisory_id = match["advisory_id"]
    packages = match["packages"]
    hit_cwes = match["hit"]

    def make(commit: str, index: int):
        repo_url = ""
        if commit:
            repo_url = re.sub(r"/(?:-/)?commit/[0-9a-fA-F]{7,40}$", "", commit)
        suffix = "" if len(commits) <= 1 else f"-{index + 1}"
        return {
            "candidate_id": f"{id_prefix}-{advisory_id}{suffix}",
            "source": source_label,
            "advisory_id": str(advisory_id),
            "cve_id": cve_from(adv),
            "package": packages[0],
            "repo_url": repo_url,
            "vuln_commit": "",
            "fix_commit": commit.rsplit("/", 1)[-1] if commit else "",
            "affected_versions": "",
            "fixed_version": ", ".join(sorted(set(fixed_versions(adv)))) or "",
            "file_path": "",
            "function_name": "",
            "cwe": hit_cwes[0] if hit_cwes else "",
            "cwe_all": match["cwes_all"],
            "match_reasons": match["reasons"],
            "rule_id": "",
            "code_vuln_url": "",
            "code_fixed_url": commit,
            "notification_url": f"https://osv.dev/vulnerability/{advisory_id}",
            "code_vuln": "",
            "static_finding": "",
            "preliminary_class": "B",
            "human_verdict": "",
            "verified": False,
            "verified_by": "",
            "license": "",
            "collected_at": date.today().isoformat(),
            "split": "",
        }

    if not commits:
        return [make("", 0)]
    primary = make(commits[0], 0)
    if len(commits) > 1:
        primary["cross_references"] = [
            {"type": "FIX", "url": commit} for commit in commits[1:]
        ]
    return [primary]


def fetch_osv(packages):
    """Query api.osv.dev for each package; yields OSV vuln dicts. Needs network."""
    for name in packages:
        payload = json.dumps({"package": {"name": name, "ecosystem": "PyPI"}}).encode()
        req = urllib.request.Request(
            OSV_QUERY, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as response:
            body = json.loads(response.read())
        for vuln in body.get("vulns", []):
            vuln.setdefault("database_specific", {})
            yield vuln


def self_test():
    watch = {"example-pkg"}
    sample = {
        "id": "GHSA-0000-0000-0000",
        "aliases": ["CVE-2020-00000"],
        "database_specific": {"cwe_ids": ["CWE-327"]},
        "affected": [{"package": {"ecosystem": "PyPI", "name": "example-pkg"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}],
        "references": [{"type": "FIX",
                        "url": "https://github.com/owner/repo/commit/0123456789abcdef0123456789abcdef01234567"}],
    }
    match = advisory_match(sample, target_cwes=TARGET_CWES, watch=watch,
                           keyword_recall=False, all_packages=False,
                           cwe_only=False, include_malicious=False)
    assert isinstance(match, dict) and match["hit"] == ["CWE-327"], match
    candidates = build_candidate(sample, match)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["advisory_id"] == "GHSA-0000-0000-0000"
    assert candidate["cve_id"] == "CVE-2020-00000"
    assert candidate["package"] == "example-pkg"
    assert candidate["cwe"] == "CWE-327"
    assert candidate["fix_commit"] == "0123456789abcdef0123456789abcdef01234567"
    assert candidate["preliminary_class"] == "B" and candidate["verified"] is False
    assert candidate["cwe_all"] == ["CWE-327"]
    assert candidate["match_reasons"] and candidate["match_reasons"][0].startswith("cwe:")

    # A non-target CWE that is not on the watchlist is out of scope.
    off_target = {"id": "GHSA-9999-9999-9999",
                  "database_specific": {"cwe_ids": ["CWE-787"]},
                  "affected": [{"package": {"ecosystem": "PyPI", "name": "other"}}]}
    assert advisory_match(off_target, target_cwes=TARGET_CWES, watch=watch,
                          keyword_recall=False, all_packages=False,
                          cwe_only=False, include_malicious=False) is None

    # --keyword-recall catches a crypto advisory that carries no CWE (PyPA style).
    pypa_style = {
        "id": "PYSEC-2020-0001",
        "details": "The library used a weak hash (md5) to compare signatures.",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "some-pkg"}}],
    }
    kw_match = advisory_match(pypa_style, target_cwes=TARGET_CWES, watch=watch,
                              keyword_recall=True, all_packages=False,
                              cwe_only=False, include_malicious=False)
    assert isinstance(kw_match, dict) and kw_match["hit"] == [], kw_match
    assert any(r.startswith("keyword:") for r in kw_match["reasons"])
    assert advisory_match(pypa_style, target_cwes=TARGET_CWES, watch=watch,
                          keyword_recall=False, all_packages=False,
                          cwe_only=False, include_malicious=False) is None

    # Malicious "MAL-*" advisories are dropped unless explicitly requested.
    malware = {"id": "MAL-2023-1234",
               "database_specific": {"cwe_ids": ["CWE-327"]},
               "affected": [{"package": {"ecosystem": "PyPI", "name": "evil"}}]}
    assert advisory_match(malware, target_cwes=TARGET_CWES, watch=watch,
                          keyword_recall=True, all_packages=True,
                          cwe_only=False, include_malicious=False) == "malicious"
    assert isinstance(advisory_match(malware, target_cwes=TARGET_CWES, watch=watch,
                                     keyword_recall=True, all_packages=True,
                                     cwe_only=False, include_malicious=True), dict)

    # Multiple fix commits collapse to one primary row plus cross_references.
    multi = {
        "id": "GHSA-1111-1111-1111",
        "database_specific": {"cwe_ids": ["CWE-327"]},
        "affected": [{"package": {"ecosystem": "PyPI", "name": "pkg"}}],
        "references": [
            {"type": "FIX", "url": "https://github.com/o/r/commit/" + "a" * 40},
            {"type": "FIX", "url": "https://github.com/o/r/commit/" + "b" * 40},
        ],
    }
    multi_match = advisory_match(multi, target_cwes=TARGET_CWES, watch=watch,
                                 keyword_recall=False, all_packages=True,
                                 cwe_only=False, include_malicious=False)
    multi_rows = build_candidate(multi, multi_match)
    assert len(multi_rows) == 1, multi_rows
    assert multi_rows[0]["fix_commit"] == "a" * 40
    assert multi_rows[0]["candidate_id"] == "osv-GHSA-1111-1111-1111-1"
    cross = multi_rows[0].get("cross_references") or []
    assert len(cross) == 1 and cross[0]["url"].endswith("b" * 40), cross

    # YAML loading must handle the PyPA/PYSEC shape (bare advisory dicts).
    with tempfile.TemporaryDirectory() as tmp:
        ypath = Path(tmp) / "PYSEC-2099-1.yaml"
        ypath.write_text(
            "id: PYSEC-2099-1\ndetails: uses md5\n"
            "affected:\n- package:\n    ecosystem: PyPI\n    name: demo\n",
            encoding="utf-8")
        loaded = list(load_records(ypath))
    assert loaded and loaded[0]["id"] == "PYSEC-2099-1", loaded

    print("[self-test] harvest parser OK")
    print(json.dumps(candidates, indent=2, ensure_ascii=False))


def main() -> int:
    ap = argparse.ArgumentParser(description="Harvest real crypto advisory candidates")
    ap.add_argument("--advisories", nargs="*", type=Path, default=None,
                    help="Local advisory files/directories (JSON, JSONL, YAML)")
    ap.add_argument("--fetch-osv", action="store_true",
                    help="Query api.osv.dev per package (needs network)")
    ap.add_argument("--packages", default=",".join(DEFAULT_PACKAGES),
                    help="Comma-separated PyPI package watchlist")
    ap.add_argument("--packages-file", type=Path,
                    help="Extra watchlist packages, one per line")
    ap.add_argument("--all-packages", action="store_true",
                    help="Ignore the watchlist (CWE/keyword matching only)")
    ap.add_argument("--extra-cwes", default="",
                    help="Comma-separated extra CWEs to treat as in-scope")
    ap.add_argument("--cwe-only", action="store_true",
                    help="Strict mode: require a target/extra CWE match")
    ap.add_argument("--keyword-recall", action="store_true",
                    help="Also match crypto keywords in advisory text (no CWE needed)")
    ap.add_argument("--include-malicious", action="store_true",
                    help="Keep MAL-* malware advisories (dropped by default)")
    ap.add_argument("--source-label", default="GHSA/OSV",
                    help="Value written to each row's `source` field")
    ap.add_argument("--id-prefix", default="osv",
                    help="candidate_id prefix, keeps source pools from colliding")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--stats-out", type=Path, default=None,
                    help="Optional JSON report of the scan")
    ap.add_argument("--limit", type=int, default=0, help="Stop after N candidates")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return 0

    watch = {p.strip().lower() for p in args.packages.split(",") if p.strip()}
    if args.packages_file:
        pfile = args.packages_file if args.packages_file.is_absolute() else ROOT / args.packages_file
        watch |= {
            line.strip().lower()
            for line in pfile.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    target_cwes = set(TARGET_CWES)
    for raw in args.extra_cwes.split(","):
        raw = raw.strip().upper()
        if raw:
            target_cwes.add(raw if raw.startswith("CWE-") else f"CWE-{raw}")

    if args.fetch_osv:
        source = fetch_osv(sorted(watch))
    elif args.advisories:
        paths = [p if p.is_absolute() else ROOT / p for p in args.advisories]
        missing = [str(p) for p in paths if not p.exists()]
        if missing:
            print(f"[FAIL] advisories path not found: {', '.join(missing)}")
            return 1

        def _iter(paths):
            for path in paths:
                yield from load_records(path)

        source = _iter(paths)
    else:
        print("[FAIL] provide --advisories DIR|FILE, or --fetch-osv (network)")
        return 1

    seen = set()
    candidates = []
    by_reason = Counter()
    by_cwe = Counter()
    scanned = skipped_malicious = skipped_withdrawn = not_matched = 0
    for adv in source:
        scanned += 1
        match = advisory_match(
            adv, target_cwes=target_cwes, watch=watch,
            keyword_recall=args.keyword_recall, all_packages=args.all_packages,
            cwe_only=args.cwe_only, include_malicious=args.include_malicious)
        if match == "malicious":
            skipped_malicious += 1
            continue
        if match == "withdrawn":
            skipped_withdrawn += 1
            continue
        if not isinstance(match, dict):
            not_matched += 1
            continue
        rows = build_candidate(adv, match, source_label=args.source_label,
                               id_prefix=args.id_prefix)
        for candidate in rows:
            if candidate["candidate_id"] in seen:
                continue
            seen.add(candidate["candidate_id"])
            candidates.append(candidate)
            for reason in match["reasons"]:
                by_reason[reason.split(":", 1)[0]] += 1
            if candidate["cwe"]:
                by_cwe[candidate["cwe"]] += 1
            elif match["cwes_all"]:
                by_cwe["untargeted:" + ",".join(match["cwes_all"])] += 1
            else:
                by_cwe["<none>"] += 1
        if args.limit and len(candidates) >= args.limit:
            break

    out = args.out if args.out.is_absolute() else ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "\n".join(json.dumps(c, ensure_ascii=False) for c in candidates) + "\n",
        encoding="utf-8")

    with_commit = sum(1 for c in candidates if c["fix_commit"])
    stats = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_label": args.source_label,
        "inputs": [str(p) for p in (args.advisories or [])],
        "target_cwes": sorted(target_cwes),
        "keyword_recall": args.keyword_recall,
        "cwe_only": args.cwe_only,
        "all_packages": args.all_packages,
        "scanned": scanned,
        "skipped_withdrawn": skipped_withdrawn,
        "skipped_malicious": skipped_malicious,
        "not_matched": not_matched,
        "emitted": len(candidates),
        "with_commit": with_commit,
        "by_cwe": dict(by_cwe.most_common()),
        "by_match_reason": dict(by_reason.most_common()),
    }
    if args.stats_out:
        stats_path = args.stats_out if args.stats_out.is_absolute() else ROOT / args.stats_out
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
                              encoding="utf-8")

    print(f"Scanned advisories: {scanned}  (withdrawn {skipped_withdrawn}, "
          f"malicious {skipped_malicious}, out-of-scope {not_matched})")
    print(f"[+] {out}: {len(candidates)} candidate(s) "
          f"({with_commit} with fix commit) (preliminary_class=B, verified=false)")
    print("by CWE         :", dict(by_cwe.most_common(12)))
    print("by match reason:", dict(by_reason.most_common()))
    print("Next: human-review each advisory, fix commit and code; then write "
          "data/round6/real_verified_{detect,triage}.jsonl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
