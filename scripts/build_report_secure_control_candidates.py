#!/usr/bin/env python3
"""Build auditable candidates from the fixed-commit secure-control report.

This script does not create training rows. It extracts only the source nodes
that were actually downloaded under data/round6/sources/secure_controls and
records, for every report item, whether the report claim matches the pinned
source.

Outputs:
  data/round6/candidates/report_secure_controls.jsonl
  reports/data_quality/report_secure_controls_stats.json

Every output row is a candidate with verified=false and review_status=unreviewed.
Rows that recommend secure_reference must still be reviewed before they can be
used to write supplements. No row is registered in R6_SOURCE_FILES.
"""
import argparse
import ast
import hashlib
import json
import textwrap
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCE_ROOT = ROOT / "data" / "round6" / "sources" / "secure_controls"
OUT = ROOT / "data" / "round6" / "candidates" / "report_secure_controls.jsonl"
STATS_OUT = ROOT / "reports" / "data_quality" / "report_secure_controls_stats.json"

CRYPTOGRAPHY_COMMIT = "d02de9f26e9a2353e89427c1cea8b9ed2bae969e"
PYJWT_29FB_COMMIT = "29fbfc3641b65e2b4f620ed77202b8a0df5a54f8"
PYJWT_4ADCD_COMMIT = "4adcd02722f5011c60079d3978dfc167b9a8eaa5"
DJANGO_COMMIT = "ffcf24c9ce781a7c194ed8c42a59a60e922e374e"


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def github_url(repo_url, commit, file_path):
    return f"{repo_url}/blob/{commit}/{file_path}"


REPORT_ITEMS = [
    {
        "candidate_id": "C-001",
        "package": "pyca/cryptography",
        "repo_url": "https://github.com/pyca/cryptography",
        "reported_commit": CRYPTOGRAPHY_COMMIT,
        "reported_file_path": (
            "src/cryptography/hazmat/primitives/_modes.py"
        ),
        "reported_function_name": "_check_aes_key_length",
        "reported_source_url": github_url(
            "https://github.com/pyca/cryptography",
            CRYPTOGRAPHY_COMMIT,
            "src/cryptography/hazmat/primitives/_modes.py",
        ),
        "actual_file_path": (
            "src/cryptography/hazmat/primitives/ciphers/modes.py"
        ),
        "reported_cwes": ["CWE-326"],
        "license": "Apache-2.0 OR BSD-3-Clause",
        "source_class": "implementation",
        "report_claim": (
            "The helper is claimed to whitelist only 128, 192, and 256 bit "
            "AES keys and to reject all weak or malformed key lengths."
        ),
        "actual_behavior": (
            "The extracted helper only rejects AES key sizes greater than 256 "
            "for non-XTS modes. It does not validate lower bounds or other "
            "algorithms. AES.key_sizes and _verify_key_size hold the actual "
            "key whitelist, while 512 is intentionally included there for "
            "AES-256-XTS."
        ),
        "claim_validation": "report_mismatch",
        "decision": "context_dependent",
        "confidence": 0.98,
        "extract": [
            {
                "role": "primary",
                "kind": "function",
                "source_file": "cryptography/modes.py",
                "qualname": "_check_aes_key_length",
            },
            {
                "role": "supporting",
                "kind": "function",
                "source_file": "cryptography/algorithms.py",
                "qualname": "_verify_key_size",
            },
            {
                "role": "supporting",
                "kind": "class",
                "source_file": "cryptography/algorithms.py",
                "qualname": "AES",
            },
        ],
        "rule_mapping": {
            "reported_rule": "CRYPTO-009",
            "reported_cwe": "CWE-326",
            "coverage_status": "partial_requires_algorithm_key_sizes",
            "safe_negative_eligible": False,
        },
        "safe_controls": [
            "AES.key_sizes",
            "_verify_key_size",
            "rejects AES modes above 256 bits",
        ],
        "missing_evidence": [
            "No advisory is attached.",
            "The reported _modes.py path does not exist at this commit.",
        ],
        "recommended_dataset_role": "secure_reference",
        "r6_merge_status": "blocked_report_mismatch",
        "reviewer_questions": [
            "Should the complete AES plus _verify_key_size context be retained "
            "as a non-training secure reference?"
        ],
    },
    {
        "candidate_id": "C-002",
        "package": "pyca/cryptography",
        "repo_url": "https://github.com/pyca/cryptography",
        "reported_commit": CRYPTOGRAPHY_COMMIT,
        "reported_file_path": (
            "src/cryptography/hazmat/primitives/ciphers/modes.py"
        ),
        "reported_function_name": "XTS.__init__",
        "reported_source_url": github_url(
            "https://github.com/pyca/cryptography",
            CRYPTOGRAPHY_COMMIT,
            "src/cryptography/hazmat/primitives/ciphers/modes.py",
        ),
        "actual_file_path": (
            "src/cryptography/hazmat/primitives/ciphers/modes.py"
        ),
        "reported_cwes": ["CWE-326"],
        "license": "Apache-2.0 OR BSD-3-Clause",
        "source_class": "implementation",
        "report_claim": (
            "XTS.__init__ is claimed to enforce the 256-bit or 512-bit key "
            "material required by AES-XTS."
        ),
        "actual_behavior": (
            "XTS.__init__ only checks that tweak is exactly 16 bytes. The key "
            "size check is in validate_for_algorithm and accepts exactly 256 "
            "or 512 bits, after rejecting AES128 and AES256 wrapper classes."
        ),
        "claim_validation": "partial",
        "decision": "safe_control",
        "confidence": 0.99,
        "extract": [
            {
                "role": "primary",
                "kind": "class",
                "source_file": "cryptography/modes.py",
                "qualname": "XTS",
            }
        ],
        "rule_mapping": {
            "reported_rule": "CRYPTO-009",
            "reported_cwe": "CWE-326",
            "coverage_status": "control_outside_rule_pattern",
            "safe_negative_eligible": False,
        },
        "safe_controls": [
            "tweak length must be 16 bytes",
            "key_size must be 256 or 512 bits",
            "AES128 and AES256 wrappers are rejected for XTS",
        ],
        "missing_evidence": [
            "No advisory is attached.",
            "The reported function name points to __init__, but the key-size "
            "control is in validate_for_algorithm.",
        ],
        "recommended_dataset_role": "secure_reference",
        "r6_merge_status": "review_required_secure_reference",
        "reviewer_questions": [
            "Is the complete XTS class useful as a secure reference even "
            "though CRYPTO-009 does not fire on XTS key-size validation?"
        ],
    },
    {
        "candidate_id": "C-003",
        "package": "pyca/cryptography",
        "repo_url": "https://github.com/pyca/cryptography",
        "reported_commit": CRYPTOGRAPHY_COMMIT,
        "reported_file_path": (
            "src/cryptography/hazmat/primitives/ciphers/modes.py"
        ),
        "reported_function_name": "ECB.__init__",
        "reported_source_url": github_url(
            "https://github.com/pyca/cryptography",
            CRYPTOGRAPHY_COMMIT,
            "src/cryptography/hazmat/primitives/ciphers/modes.py",
        ),
        "actual_file_path": (
            "src/cryptography/hazmat/primitives/ciphers/modes.py"
        ),
        "reported_cwes": ["CWE-329"],
        "license": "Apache-2.0 OR BSD-3-Clause",
        "source_class": "implementation",
        "report_claim": (
            "ECB.__init__ is claimed to validate an IV between 8 and 128 "
            "bytes, which is presented as protection against predictable IVs."
        ),
        "actual_behavior": (
            "ECB has no __init__ and no IV. It only aliases "
            "validate_for_algorithm to _check_aes_key_length. The reported "
            "8-to-128-byte IV check is GCM.__init__, and a length check does "
            "not establish IV randomness or non-reuse."
        ),
        "claim_validation": "report_mismatch",
        "decision": "out_of_scope",
        "confidence": 0.99,
        "extract": [
            {
                "role": "primary",
                "kind": "class",
                "source_file": "cryptography/modes.py",
                "qualname": "GCM",
            },
            {
                "role": "supporting",
                "kind": "class",
                "source_file": "cryptography/modes.py",
                "qualname": "ECB",
            },
        ],
        "rule_mapping": {
            "reported_rule": "CRYPTO-006",
            "reported_cwe": "CWE-329",
            "coverage_status": "report_mismatch_no_coverage",
            "safe_negative_eligible": False,
        },
        "safe_controls": [
            "GCM enforces a 64-to-1024-bit IV length",
            "GCM enforces a minimum authentication tag length",
        ],
        "missing_evidence": [
            "No advisory is attached.",
            "IV randomness and non-reuse are not visible in the extracted code.",
        ],
        "recommended_dataset_role": "exclude",
        "r6_merge_status": "blocked_out_of_scope",
        "reviewer_questions": [],
    },
    {
        "candidate_id": "C-004",
        "package": "pyca/cryptography",
        "repo_url": "https://github.com/pyca/cryptography",
        "reported_commit": CRYPTOGRAPHY_COMMIT,
        "reported_file_path": (
            "src/cryptography/hazmat/primitives/ciphers/algorithms.py"
        ),
        "reported_function_name": "TripleDES",
        "reported_source_url": github_url(
            "https://github.com/pyca/cryptography",
            CRYPTOGRAPHY_COMMIT,
            "src/cryptography/hazmat/primitives/ciphers/algorithms.py",
        ),
        "actual_file_path": (
            "src/cryptography/hazmat/primitives/ciphers/algorithms.py"
        ),
        "reported_cwes": ["CWE-327"],
        "license": "Apache-2.0 OR BSD-3-Clause",
        "source_class": "protocol-compat",
        "report_claim": (
            "TripleDES is claimed to carry a DeprecatedIn43 marker and to be "
            "a compatibility-only implementation."
        ),
        "actual_behavior": (
            "The pinned class exposes the 3DES primitive, expands 8-byte and "
            "16-byte keys, and has no DeprecatedIn43 marker in this file. The "
            "class is a dangerous primitive compatibility path, not a safe "
            "control."
        ),
        "claim_validation": "partial",
        "decision": "out_of_scope",
        "confidence": 0.98,
        "extract": [
            {
                "role": "primary",
                "kind": "class",
                "source_file": "cryptography/algorithms.py",
                "qualname": "TripleDES",
            }
        ],
        "rule_mapping": {
            "reported_rule": "CRYPTO-003",
            "reported_cwe": "CWE-327",
            "coverage_status": "risk_primitive_not_safe_control",
            "safe_negative_eligible": False,
        },
        "safe_controls": [],
        "missing_evidence": [
            "No advisory is attached.",
            "No DeprecatedIn43 marker is present at the pinned commit.",
        ],
        "recommended_dataset_role": "exclude",
        "r6_merge_status": "blocked_unsafe_primitive_compat",
        "reviewer_questions": [],
    },
    {
        "candidate_id": "C-005",
        "package": "pyca/cryptography",
        "repo_url": "https://github.com/pyca/cryptography",
        "reported_commit": CRYPTOGRAPHY_COMMIT,
        "reported_file_path": (
            "src/cryptography/hazmat/primitives/ciphers/algorithms.py"
        ),
        "reported_function_name": "ARC4",
        "reported_source_url": github_url(
            "https://github.com/pyca/cryptography",
            CRYPTOGRAPHY_COMMIT,
            "src/cryptography/hazmat/primitives/ciphers/algorithms.py",
        ),
        "actual_file_path": (
            "src/cryptography/hazmat/primitives/ciphers/algorithms.py"
        ),
        "reported_cwes": ["CWE-327"],
        "license": "Apache-2.0 OR BSD-3-Clause",
        "source_class": "wrapper",
        "report_claim": (
            "ARC4 is claimed to carry a DeprecatedIn43 marker and to be kept "
            "only for backward compatibility."
        ),
        "actual_behavior": (
            "The pinned class validates only that key is bytes-like. It does "
            "not add a cryptographic safety control and has no DeprecatedIn43 "
            "marker in this file. RC4 must not enter a safe-negative set."
        ),
        "claim_validation": "partial",
        "decision": "out_of_scope",
        "confidence": 0.99,
        "extract": [
            {
                "role": "primary",
                "kind": "class",
                "source_file": "cryptography/algorithms.py",
                "qualname": "ARC4",
            }
        ],
        "rule_mapping": {
            "reported_rule": "CRYPTO-004",
            "reported_cwe": "CWE-327",
            "coverage_status": "risk_primitive_not_safe_control",
            "safe_negative_eligible": False,
        },
        "safe_controls": [],
        "missing_evidence": [
            "No advisory is attached.",
            "No DeprecatedIn43 marker is present at the pinned commit.",
        ],
        "recommended_dataset_role": "exclude",
        "r6_merge_status": "blocked_unsafe_primitive_compat",
        "reviewer_questions": [],
    },
    {
        "candidate_id": "C-006",
        "package": "pyca/cryptography",
        "repo_url": "https://github.com/pyca/cryptography",
        "reported_commit": CRYPTOGRAPHY_COMMIT,
        "reported_file_path": (
            "src/cryptography/hazmat/primitives/_serialization.py"
        ),
        "reported_function_name": "BestAvailableEncryption.__init__",
        "reported_source_url": github_url(
            "https://github.com/pyca/cryptography",
            CRYPTOGRAPHY_COMMIT,
            "src/cryptography/hazmat/primitives/_serialization.py",
        ),
        "actual_file_path": (
            "src/cryptography/hazmat/primitives/_serialization.py"
        ),
        "reported_cwes": ["CWE-287"],
        "license": "Apache-2.0 OR BSD-3-Clause",
        "source_class": "implementation",
        "report_claim": (
            "The constructor is claimed to reject an empty password and "
            "therefore provide an authentication control."
        ),
        "actual_behavior": (
            "The constructor rejects non-bytes and empty bytes. It prevents a "
            "clearly invalid password input, but it does not authenticate a "
            "user and does not enforce password entropy or KDF strength."
        ),
        "claim_validation": "partial",
        "decision": "out_of_scope",
        "confidence": 0.99,
        "extract": [
            {
                "role": "primary",
                "kind": "class",
                "source_file": "cryptography/_serialization.py",
                "qualname": "BestAvailableEncryption",
            }
        ],
        "rule_mapping": {
            "reported_rule": None,
            "reported_cwe": "CWE-287",
            "coverage_status": "non_target_cwe",
            "safe_negative_eligible": False,
        },
        "safe_controls": [
            "password must be bytes",
            "password must be non-empty",
        ],
        "missing_evidence": [
            "No advisory is attached.",
            "CWE-287 is outside CRYPTO-001 through CRYPTO-013.",
        ],
        "recommended_dataset_role": "secure_reference",
        "r6_merge_status": "blocked_non_target_cwe",
        "reviewer_questions": [],
    },
    {
        "candidate_id": "C-007",
        "package": "pyca/cryptography",
        "repo_url": "https://github.com/pyca/cryptography",
        "reported_commit": CRYPTOGRAPHY_COMMIT,
        "reported_file_path": (
            "src/cryptography/hazmat/primitives/_serialization.py"
        ),
        "reported_function_name": "kdf_rounds",
        "reported_source_url": github_url(
            "https://github.com/pyca/cryptography",
            CRYPTOGRAPHY_COMMIT,
            "src/cryptography/hazmat/primitives/_serialization.py",
        ),
        "actual_file_path": (
            "src/cryptography/hazmat/primitives/_serialization.py"
        ),
        "reported_cwes": ["CWE-916"],
        "license": "Apache-2.0 OR BSD-3-Clause",
        "source_class": "implementation",
        "report_claim": (
            "kdf_rounds is claimed to prevent KDF degradation to no work by "
            "requiring a positive integer and preventing duplicate setup."
        ),
        "actual_behavior": (
            "kdf_rounds rejects duplicate setup and accepts any integer >= 1. "
            "It has no minimum security threshold, so values such as one are "
            "still accepted and CRYPTO-012 does not fire on this method."
        ),
        "claim_validation": "context_dependent",
        "decision": "context_dependent",
        "confidence": 0.99,
        "extract": [
            {
                "role": "primary",
                "kind": "method",
                "source_file": "cryptography/_serialization.py",
                "qualname": "KeySerializationEncryptionBuilder.kdf_rounds",
            }
        ],
        "rule_mapping": {
            "reported_rule": "CRYPTO-012",
            "reported_cwe": "CWE-916",
            "coverage_status": "validation_only_no_strength_floor",
            "safe_negative_eligible": False,
        },
        "safe_controls": [
            "rounds must be an integer",
            "rounds must be at least one",
            "kdf_rounds cannot be set twice",
        ],
        "missing_evidence": [
            "No advisory is attached.",
            "No minimum KDF work factor is enforced by this method.",
        ],
        "recommended_dataset_role": "secure_reference",
        "r6_merge_status": "blocked_context_dependent",
        "reviewer_questions": [
            "Is this useful as a secure reference for input validation, but "
            "not as a CRYPTO-012 negative?"
        ],
    },
    {
        "candidate_id": "C-008",
        "package": "pyca/cryptography",
        "repo_url": "https://github.com/pyca/cryptography",
        "reported_commit": CRYPTOGRAPHY_COMMIT,
        "reported_file_path": (
            "src/cryptography/hazmat/primitives/kdf/scrypt.py"
        ),
        "reported_function_name": "Scrypt (Module Level Configuration)",
        "reported_source_url": github_url(
            "https://github.com/pyca/cryptography",
            CRYPTOGRAPHY_COMMIT,
            "src/cryptography/hazmat/primitives/kdf/scrypt.py",
        ),
        "actual_file_path": (
            "src/cryptography/hazmat/primitives/kdf/scrypt.py"
        ),
        "reported_cwes": ["CWE-770"],
        "license": "Apache-2.0 OR BSD-3-Clause",
        "source_class": "implementation",
        "report_claim": (
            "Scrypt and _MEM_LIMIT are claimed to cap resource use and to be "
            "safe KDF parameters for CRYPTO-012."
        ),
        "actual_behavior": (
            "Scrypt validates structural constraints: n is a power of two and "
            "at least two, r and p are at least one, instances are single-use, "
            "and verification uses constant-time comparison. It does not "
            "enforce a secure n value such as 2**14, so n=2 is accepted."
        ),
        "claim_validation": "context_dependent",
        "decision": "context_dependent",
        "confidence": 0.99,
        "extract": [
            {
                "role": "primary",
                "kind": "class",
                "source_file": "cryptography/scrypt.py",
                "qualname": "Scrypt",
            },
            {
                "role": "supporting",
                "kind": "assignment",
                "source_file": "cryptography/scrypt.py",
                "qualname": "_MEM_LIMIT",
            },
        ],
        "rule_mapping": {
            "reported_rule": "CRYPTO-012",
            "reported_cwe": "CWE-916",
            "coverage_status": "parameter_floor_below_rule_threshold",
            "safe_negative_eligible": False,
        },
        "safe_controls": [
            "n must be a power of two and at least two",
            "r and p must be at least one",
            "single-use instances",
            "constant-time verification",
            "_MEM_LIMIT bounds the OpenSSL memory request",
        ],
        "missing_evidence": [
            "No advisory is attached.",
            "n=2 is accepted, while CRYPTO-012 treats scrypt n below 16384 "
            "as weak.",
        ],
        "recommended_dataset_role": "secure_reference",
        "r6_merge_status": "blocked_weak_parameter_floor",
        "reviewer_questions": [
            "Should the class remain a secure reference for lifecycle and "
            "constant-time handling while its parameter floor is documented "
            "as insufficient?"
        ],
    },
    {
        "candidate_id": "C-009",
        "package": "django/django",
        "repo_url": "https://github.com/django/django",
        "reported_commit": DJANGO_COMMIT,
        "reported_file_path": "django/core/signing.py",
        "reported_function_name": "dumps",
        "reported_source_url": github_url(
            "https://github.com/django/django",
            DJANGO_COMMIT,
            "django/core/signing.py",
        ),
        "actual_file_path": "django/core/signing.py",
        "reported_cwes": ["CWE-310"],
        "license": "BSD-3-Clause",
        "source_class": "implementation",
        "report_claim": (
            "dumps is claimed to sign the compression marker and payload "
            "together with HMAC-SHA-256."
        ),
        "actual_behavior": "",
        "claim_validation": "not_evaluable",
        "decision": "insufficient_evidence",
        "confidence": 1.0,
        "extract": [],
        "rule_mapping": {
            "reported_rule": None,
            "reported_cwe": "CWE-310",
            "coverage_status": "source_missing",
            "safe_negative_eligible": False,
        },
        "safe_controls": [],
        "missing_evidence": [
            "The fixed-commit source file was not downloaded.",
            "No code or hash can be recorded without reconstructing from "
            "another version.",
        ],
        "recommended_dataset_role": "exclude",
        "r6_merge_status": "blocked_missing_source",
        "reviewer_questions": [],
    },
    {
        "candidate_id": "C-010",
        "package": "django/django",
        "repo_url": "https://github.com/django/django",
        "reported_commit": DJANGO_COMMIT,
        "reported_file_path": "django/core/signing.py",
        "reported_function_name": "loads",
        "reported_source_url": github_url(
            "https://github.com/django/django",
            DJANGO_COMMIT,
            "django/core/signing.py",
        ),
        "actual_file_path": "django/core/signing.py",
        "reported_cwes": ["CWE-409", "CWE-208"],
        "license": "BSD-3-Clause",
        "source_class": "implementation",
        "report_claim": (
            "loads is claimed to verify the signature with constant-time "
            "comparison before decompression or JSON parsing."
        ),
        "actual_behavior": "",
        "claim_validation": "not_evaluable",
        "decision": "insufficient_evidence",
        "confidence": 1.0,
        "extract": [],
        "rule_mapping": {
            "reported_rule": "CRYPTO-013",
            "reported_cwe": "CWE-208",
            "coverage_status": "source_missing",
            "safe_negative_eligible": False,
        },
        "safe_controls": [],
        "missing_evidence": [
            "The fixed-commit source file was not downloaded.",
            "The Zlib ordering and constant-time comparison cannot be verified "
            "from the report alone.",
        ],
        "recommended_dataset_role": "exclude",
        "r6_merge_status": "blocked_missing_source",
        "reviewer_questions": [],
    },
    {
        "candidate_id": "C-011",
        "package": "jpadilla/pyjwt",
        "repo_url": "https://github.com/jpadilla/pyjwt",
        "reported_commit": PYJWT_29FB_COMMIT,
        "reported_file_path": "jwt/api_jwt.py",
        "reported_function_name": "_merge_options",
        "reported_source_url": github_url(
            "https://github.com/jpadilla/pyjwt",
            PYJWT_29FB_COMMIT,
            "jwt/api_jwt.py",
        ),
        "actual_file_path": "jwt/api_jwt.py",
        "reported_cwes": ["CWE-287"],
        "license": "MIT",
        "source_class": "implementation",
        "report_claim": (
            "_merge_options is claimed to mutate a caller-owned options dict "
            "because a shallow copy is missing, creating a verification "
            "downgrade."
        ),
        "actual_behavior": (
            "The file available locally is commit 4adcd027, not the reported "
            "29fbfc364. At 4adcd027, _merge_options copies options with "
            "dict(options), so this local file must not be presented as the "
            "reported vulnerable revision."
        ),
        "claim_validation": "not_evaluable",
        "decision": "insufficient_evidence",
        "confidence": 1.0,
        "extract": [
            {
                "role": "primary",
                "kind": "method",
                "source_file": "pyjwt/api_jwt_4adcd.py",
                "qualname": "PyJWT._merge_options",
            }
        ],
        "rule_mapping": {
            "reported_rule": None,
            "reported_cwe": "CWE-287",
            "coverage_status": "report_target_missing_local_revision_differs",
            "safe_negative_eligible": False,
        },
        "safe_controls": [
            "dict(options) creates a shallow copy before merging defaults",
        ],
        "missing_evidence": [
            "The reported 29fbfc364 revision was not downloaded.",
            "The advisory GHSA-gvp8-978c-rx2q was not independently checked.",
        ],
        "recommended_dataset_role": "secure_reference",
        "r6_merge_status": "blocked_report_target_missing",
        "reviewer_questions": [
            "Can the 29fbfc364 file be downloaded separately if this old "
            "revision is still needed?"
        ],
    },
    {
        "candidate_id": "C-012",
        "package": "jpadilla/pyjwt",
        "repo_url": "https://github.com/jpadilla/pyjwt",
        "reported_commit": PYJWT_4ADCD_COMMIT,
        "reported_file_path": "jwt/api_jwt.py",
        "reported_function_name": "_decode_payload",
        "reported_source_url": github_url(
            "https://github.com/jpadilla/pyjwt",
            PYJWT_4ADCD_COMMIT,
            "jwt/api_jwt.py",
        ),
        "actual_file_path": "jwt/api_jwt.py",
        "reported_cwes": ["CWE-674", "CWE-400"],
        "license": "MIT",
        "source_class": "implementation",
        "report_claim": (
            "_decode_payload is claimed to catch only ValueError and therefore "
            "to let RecursionError escape for deeply nested JSON."
        ),
        "actual_behavior": (
            "The pinned source catches only ValueError around json.loads. "
            "RecursionError is not converted to DecodeError. This is a real "
            "resource-exhaustion defect, but CWE-674 and CWE-400 are outside "
            "the shipped crypto taxonomy."
        ),
        "claim_validation": "confirmed",
        "decision": "out_of_scope",
        "confidence": 0.99,
        "extract": [
            {
                "role": "primary",
                "kind": "method",
                "source_file": "pyjwt/api_jwt_4adcd.py",
                "qualname": "PyJWT._decode_payload",
            }
        ],
        "rule_mapping": {
            "reported_rule": None,
            "reported_cwe": "CWE-674",
            "coverage_status": "non_target_cwe",
            "safe_negative_eligible": False,
        },
        "safe_controls": [],
        "missing_evidence": [
            "The advisory GHSA-42vr-xj54-vc7v was not independently checked.",
        ],
        "recommended_dataset_role": "exclude",
        "r6_merge_status": "blocked_non_target_cwe",
        "reviewer_questions": [],
    },
    {
        "candidate_id": "C-013",
        "package": "jpadilla/pyjwt",
        "repo_url": "https://github.com/jpadilla/pyjwt",
        "reported_commit": PYJWT_4ADCD_COMMIT,
        "reported_file_path": "jwt/api_jws.py",
        "reported_function_name": "_load",
        "reported_source_url": github_url(
            "https://github.com/jpadilla/pyjwt",
            PYJWT_4ADCD_COMMIT,
            "jwt/api_jws.py",
        ),
        "actual_file_path": "jwt/api_jws.py",
        "reported_cwes": ["CWE-674"],
        "license": "MIT",
        "source_class": "implementation",
        "report_claim": (
            "_load correctly catches RecursionError and converts malformed "
            "JSON headers into DecodeError."
        ),
        "actual_behavior": (
            "_load catches (ValueError, RecursionError) around json.loads and "
            "also rejects a non-empty payload segment when b64 is false. The "
            "control is real, but CWE-674 is outside the shipped taxonomy."
        ),
        "claim_validation": "confirmed",
        "decision": "safe_control",
        "confidence": 0.99,
        "extract": [
            {
                "role": "primary",
                "kind": "method",
                "source_file": "pyjwt/api_jws_4adcd.py",
                "qualname": "PyJWS._load",
            }
        ],
        "rule_mapping": {
            "reported_rule": None,
            "reported_cwe": "CWE-674",
            "coverage_status": "non_target_cwe",
            "safe_negative_eligible": False,
        },
        "safe_controls": [
            "json.loads reports are caught as ValueError and RecursionError",
            "DecodeError wraps malformed headers",
            "detached payload input is rejected before unused decoding",
        ],
        "missing_evidence": [
            "No advisory is attached.",
            "CWE-674 is outside CRYPTO-001 through CRYPTO-013.",
        ],
        "recommended_dataset_role": "secure_reference",
        "r6_merge_status": "blocked_non_target_cwe",
        "reviewer_questions": [],
    },
    {
        "candidate_id": "C-014",
        "package": "django/django",
        "repo_url": "https://github.com/django/django",
        "reported_commit": DJANGO_COMMIT,
        "reported_file_path": "django/core/management/utils.py",
        "reported_function_name": "get_random_secret_key",
        "reported_source_url": github_url(
            "https://github.com/django/django",
            DJANGO_COMMIT,
            "django/core/management/utils.py",
        ),
        "actual_file_path": "django/core/management/utils.py",
        "reported_cwes": ["CWE-330"],
        "license": "BSD-3-Clause",
        "source_class": "implementation",
        "report_claim": (
            "get_random_secret_key is claimed to generate a 50-character "
            "secret using django.utils.crypto.get_random_string."
        ),
        "actual_behavior": "",
        "claim_validation": "not_evaluable",
        "decision": "insufficient_evidence",
        "confidence": 1.0,
        "extract": [],
        "rule_mapping": {
            "reported_rule": None,
            "reported_cwe": "CWE-330",
            "coverage_status": "source_missing",
            "safe_negative_eligible": False,
        },
        "safe_controls": [],
        "missing_evidence": [
            "The fixed-commit source file was not downloaded.",
            "The report maps CWE-330, while the shipped weak-random rule is "
            "CWE-338.",
        ],
        "recommended_dataset_role": "exclude",
        "r6_merge_status": "blocked_missing_source",
        "reviewer_questions": [],
    },
    {
        "candidate_id": "C-015",
        "package": "django/django",
        "repo_url": "https://github.com/django/django",
        "reported_commit": DJANGO_COMMIT,
        "reported_file_path": "django/utils/crypto.py",
        "reported_function_name": "get_random_string",
        "reported_source_url": github_url(
            "https://github.com/django/django",
            DJANGO_COMMIT,
            "django/utils/crypto.py",
        ),
        "actual_file_path": "django/utils/crypto.py",
        "reported_cwes": ["CWE-338"],
        "license": "BSD-3-Clause",
        "source_class": "implementation",
        "report_claim": (
            "get_random_string is claimed to use secrets.choice to provide a "
            "CSPRNG-backed string generator."
        ),
        "actual_behavior": "",
        "claim_validation": "not_evaluable",
        "decision": "insufficient_evidence",
        "confidence": 1.0,
        "extract": [],
        "rule_mapping": {
            "reported_rule": "CRYPTO-008",
            "reported_cwe": "CWE-338",
            "coverage_status": "source_missing",
            "safe_negative_eligible": False,
        },
        "safe_controls": [],
        "missing_evidence": [
            "The fixed-commit source file was not downloaded.",
            "The claimed secrets.choice implementation cannot be verified "
            "from the report alone.",
        ],
        "recommended_dataset_role": "exclude",
        "r6_merge_status": "blocked_missing_source",
        "reviewer_questions": [],
    },
]


def matching_node(tree, kind, qualname):
    """Return the exact module-level node named by an extraction request."""
    if kind in {"function", "method"}:
        expected_type = (ast.FunctionDef, ast.AsyncFunctionDef)
    elif kind == "class":
        expected_type = (ast.ClassDef,)
    elif kind == "assignment":
        expected_type = (ast.Assign, ast.AnnAssign)
    else:
        raise ValueError(f"unsupported extraction kind: {kind}")

    parts = qualname.split(".")
    if len(parts) == 1:
        for node in tree.body:
            if not isinstance(node, expected_type):
                continue
            if kind == "assignment":
                if isinstance(node, ast.Assign):
                    names = [
                        target.id
                        for target in node.targets
                        if isinstance(target, ast.Name)
                    ]
                else:
                    names = [node.target.id] if isinstance(node.target, ast.Name) else []
                if qualname in names:
                    return node
            elif getattr(node, "name", None) == qualname:
                return node
        return None

    if kind != "method":
        raise ValueError(f"qualified extraction requires a method: {qualname}")

    class_name, method_name = parts
    for class_node in tree.body:
        if not isinstance(class_node, ast.ClassDef) or class_node.name != class_name:
            continue
        for node in class_node.body:
            if isinstance(node, expected_type) and node.name == method_name:
                return node
    return None


def extract_node(source, path, spec):
    parse_tree = ast.parse(source)
    node = matching_node(parse_tree, spec["kind"], spec["qualname"])
    if node is None:
        return {
            "role": spec["role"],
            "kind": spec["kind"],
            "qualname": spec["qualname"],
            "source_file": spec["source_file"],
            "line_start": None,
            "line_end": None,
            "code": "",
            "code_sha256": "",
            "parseable": False,
            "extraction_status": "node_not_found",
        }

    segment = ast.get_source_segment(source, node)
    if not segment:
        lines = source.splitlines()
        segment = "\n".join(lines[node.lineno - 1:node.end_lineno])
    code = textwrap.dedent(segment).strip() + "\n"
    parseable = True
    try:
        ast.parse(code)
    except SyntaxError:
        parseable = False

    return {
        "role": spec["role"],
        "kind": spec["kind"],
        "qualname": spec["qualname"],
        "source_file": path,
        "line_start": node.lineno,
        "line_end": node.end_lineno,
        "code": code,
        "code_sha256": sha256_text(code),
        "parseable": parseable,
        "extraction_status": "ok",
    }


def source_record(rel_path):
    path = SOURCE_ROOT / rel_path
    if not path.is_file():
        return {
            "path": rel_path,
            "exists": False,
            "sha256": "",
            "bytes": 0,
        }
    data = path.read_bytes()
    return {
        "path": rel_path,
        "exists": True,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def build_record(item):
    source_files = []
    for spec in item["extract"]:
        if spec["source_file"] not in source_files:
            source_files.append(spec["source_file"])

    sources = [source_record(path) for path in source_files]
    source_by_path = {record["path"]: record for record in sources}
    extracted_nodes = []
    extraction_errors = []

    for spec in item["extract"]:
        source = source_by_path[spec["source_file"]]
        if not source["exists"]:
            extraction_errors.append(
                f"{spec['source_file']}: source file is missing"
            )
            continue
        source_text = (SOURCE_ROOT / spec["source_file"]).read_text(
            encoding="utf-8"
        )
        node = extract_node(source_text, spec["source_file"], spec)
        if node["extraction_status"] != "ok":
            extraction_errors.append(
                f"{spec['source_file']}: {spec['qualname']} not found"
            )
        extracted_nodes.append(node)

    primary = next(
        (node for node in extracted_nodes if node["role"] == "primary"),
        None,
    )
    source_status = "verified_source"
    if not item["extract"] or any(not source["exists"] for source in sources):
        source_status = "source_missing"
    elif item["candidate_id"] == "C-011":
        source_status = "report_target_missing"
    elif extraction_errors:
        source_status = "extraction_failed"

    primary_source = source_by_path.get(primary["source_file"]) if primary else None
    if primary:
        commit = item["reported_commit"]
        if item["candidate_id"] == "C-011":
            commit = PYJWT_4ADCD_COMMIT
        source_url = github_url(
            item["repo_url"], commit, item["actual_file_path"]
        )
    else:
        commit = item["reported_commit"]
        source_url = item["reported_source_url"]

    return {
        "candidate_id": item["candidate_id"],
        "package": item["package"],
        "repo_url": item["repo_url"],
        "commit": commit,
        "reported_commit": item["reported_commit"],
        "file_path": item["actual_file_path"],
        "reported_file_path": item["reported_file_path"],
        "function_name": primary["qualname"] if primary else item["reported_function_name"],
        "reported_function_name": item["reported_function_name"],
        "source_url": source_url,
        "reported_source_url": item["reported_source_url"],
        "license": item["license"],
        "source_class": item["source_class"],
        "report_claim": item["report_claim"],
        "actual_behavior": item["actual_behavior"],
        "claim_validation": item["claim_validation"],
        "source_status": source_status,
        "decision": item["decision"],
        "confidence": item["confidence"],
        "rule_mapping": item["rule_mapping"],
        "reported_cwes": item["reported_cwes"],
        "safe_controls": item["safe_controls"],
        "missing_evidence": item["missing_evidence"],
        "recommended_dataset_role": item["recommended_dataset_role"],
        "r6_merge_status": item["r6_merge_status"],
        "reviewer_questions": item["reviewer_questions"],
        "source_files": sources,
        "source_sha256": (
            primary_source["sha256"] if primary_source else ""
        ),
        "code_sha256": primary["code_sha256"] if primary else "",
        "code": primary["code"] if primary else "",
        "extracted_nodes": extracted_nodes,
        "extraction_errors": extraction_errors,
        "verified": False,
        "review_status": "unreviewed",
        "not_training_eligible": True,
    }


def sorted_counter(counter):
    return dict(sorted(counter.items()))


def build_stats(records):
    source_paths = Counter()
    for record in records:
        for source in record["source_files"]:
            source_paths[source["path"]] += 1

    node_count = sum(len(record["extracted_nodes"]) for record in records)
    parseable_nodes = sum(
        1
        for record in records
        for node in record["extracted_nodes"]
        if node["parseable"]
    )
    return {
        "schema_version": 1,
        "report_items": len(records),
        "source_status": sorted_counter(
            Counter(record["source_status"] for record in records)
        ),
        "claim_validation": sorted_counter(
            Counter(record["claim_validation"] for record in records)
        ),
        "decision": sorted_counter(
            Counter(record["decision"] for record in records)
        ),
        "recommended_dataset_role": sorted_counter(
            Counter(record["recommended_dataset_role"] for record in records)
        ),
        "r6_merge_status": sorted_counter(
            Counter(record["r6_merge_status"] for record in records)
        ),
        "extracted_nodes": {
            "total": node_count,
            "parseable": parseable_nodes,
            "failed": node_count - parseable_nodes,
        },
        "source_files": sorted_counter(source_paths),
        "verified_true_count": sum(
            1 for record in records if record["verified"] is True
        ),
        "training_eligible_count": sum(
            1
            for record in records
            if record["not_training_eligible"] is False
        ),
        "records": [
            {
                "candidate_id": record["candidate_id"],
                "package": record["package"],
                "source_status": record["source_status"],
                "claim_validation": record["claim_validation"],
                "decision": record["decision"],
                "recommended_dataset_role": record["recommended_dataset_role"],
                "r6_merge_status": record["r6_merge_status"],
                "function_name": record["function_name"],
                "source_sha256": record["source_sha256"],
                "code_sha256": record["code_sha256"],
                "extraction_errors": record["extraction_errors"],
            }
            for record in records
        ],
    }


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True))
            handle.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--emit",
        action="store_true",
        help="write the candidate JSONL and statistics report",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the statistics report to stdout",
    )
    args = parser.parse_args()

    records = [build_record(item) for item in REPORT_ITEMS]
    stats = build_stats(records)

    failures = [
        record["candidate_id"]
        for record in records
        if record["verified"] is True
        or not record["not_training_eligible"]
        or any(not node["parseable"] for node in record["extracted_nodes"])
    ]
    if failures:
        raise SystemExit(
            "[FAIL] candidate invariants violated for: " + ", ".join(failures)
        )

    print(
        f"[+] report items: {stats['report_items']} "
        f"(nodes: {stats['extracted_nodes']['total']}, "
        f"parseable: {stats['extracted_nodes']['parseable']})"
    )
    print(f"[+] source status: {stats['source_status']}")
    print(f"[+] decisions: {stats['decision']}")
    print(f"[+] dataset roles: {stats['recommended_dataset_role']}")

    if args.json:
        print(json.dumps(stats, ensure_ascii=True, indent=2, sort_keys=True))

    if args.emit:
        write_jsonl(OUT, records)
        STATS_OUT.parent.mkdir(parents=True, exist_ok=True)
        STATS_OUT.write_text(
            json.dumps(stats, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"[+] wrote {OUT}")
        print(f"[+] wrote {STATS_OUT}")
    else:
        print("[i] dry run only; pass --emit to write outputs")


if __name__ == "__main__":
    main()
