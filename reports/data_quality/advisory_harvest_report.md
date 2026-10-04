# Advisory Harvest Report (R6 Finalization)

Scope: local clone of `github/advisory-database`, scanned by
`scripts/harvest_real_crypto_candidates.py` with the project's target CWE set
(`CRYPTO-001..013`: CWE-321/326/327/329/338/916/208/256/295).

## Inputs

| Item | Value |
|---|---|
| Source | `data/external/advisory-database/advisories` |
| Advisory records scanned | 380,127 |
| Target CWEs | CWE-321, 326, 327, 329, 338, 916, 208, 256, 295 |

## Outputs

| File | Filter | Candidates | With fix commit |
|---|---|---|---|
| `data/round6/candidates/real_crypto_candidates.jsonl` | watchlist packages | 22 | 15 |
| `data/round6/candidates/real_crypto_candidates_broad.jsonl` | any PyPI package | 140 | 75 |

Every emitted row is `preliminary_class=B` and `verified=false`; the harvester
cannot promote a candidate to A-class.

## CWE distribution (broad pool, n=140)

| CWE | Count |
|---|---|
| CWE-295 | 67 |
| CWE-208 | 25 |
| CWE-327 | 20 |
| CWE-326 | 13 |
| CWE-256 | 6 |
| CWE-321 | 4 |
| CWE-338 | 3 |
| CWE-916 | 1 |
| CWE-329 | 1 |

## Watchlist pool (n=22)

CWE: CWE-295 x8, CWE-327 x7, CWE-208 x7.

Packages: cryptography x5, urllib3 x4, Django x3, rsa x2, python-jose x2,
authlib x2, pyjwt x1, ecdsa x1, paramiko x1, oauthlib x1.

Candidates without a captured fix commit (e.g. `ecdsa` CVE-2024-23342) are
mostly fix-less by design: the advisory documents a limitation the maintainers
could not patch in place, so they cannot become vulnerable/fixed training pairs.

## Honest status

- No record has been human-verified yet, so `real_verified_*.jsonl` do not exist
  and `build_round6_final_dataset.py --emit` still reproduces the 322-record
  curated/rule-fixture baseline with `verified_real_total=0`.
- Extracting the actual code pairs needs network
  (`scripts/fetch_fix_code.py`); the sandbox has no egress.
- License, repository ownership and the "is this crypto misuse vs library
  defect" judgement are all still human-review items.

## Next step

Run `scripts/fetch_fix_code.py` with network access, then review each enriched
pair and write `data/round6/real_verified_{detect,triage}.jsonl` per
`data/round6/candidates/SCHEMA.md`. Only after that does the real-crypto
positive bottleneck start to close.
