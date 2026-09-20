"""Shared prompt templates for SFT (training) and inference (evaluation).

Single source of truth so the model sees the SAME message distribution at
fine-tune time and at eval time (roadmap §7: fixed seed/format; D2).
The builders below reproduce exactly what `scripts/prepare_sft_data.py`
emits for its training pairs.
"""
from typing import Dict, List

SYS_PROMPT = (
    "You are a Python code vulnerability auditor. Respond in JSON only. "
    "For task 'detect', report whether the code is vulnerable and its CWE. "
    "For task 'triage', decide whether the given static-analysis finding is a "
    "real vulnerability (Confirm/Reject) and give a fix."
)

# Assistant JSON key sets the model is asked to fill at inference time.
DETECT_OUTPUT_KEYS = ("vulnerable", "cwe", "severity", "confidence", "explanation")
TRIAGE_OUTPUT_KEYS = ("cwe", "severity", "verdict", "confidence", "explanation", "patch")


def build_detect_user(code: str, language: str = "python") -> str:
    return f"Task: detect\nLanguage: {language}\nCode:\n{code}"


# Purpose-guidance suffix appended to the triage user message (round-3 acceptance).
# Empirical: on the 18 grounded probes it lifts fpr 0.500 -> 0.000 with zero
# confirm_recall regression (confirm_recall stays 1.000). Added in build_triage_user
# so inference (CloudBackend.triage) AND future SFT generation (prepare_sft_data ->
# build_messages) share one source of truth: train what we deploy, deploy what we train.
TRIAGE_PURPOSE_GUIDE = (
    "\n\nBefore your verdict, reason about what the flagged call's output actually does: "
    "does it protect a credential, token, key, signature, nonce, or real secret "
    "(a security purpose -> Confirm), or is it only change detection, caching, "
    "sharding, dedup, ETag, tracing, load distribution, or test scaffolding "
    "(a non-security purpose -> Reject)?"
)


def build_triage_user(code: str, finding: str, language: str = "python") -> str:
    return (
        f"Task: triage\nLanguage: {language}\n"
        f"Static Finding: {finding}\n"
        f"Code:\n{code}"
        f"{TRIAGE_PURPOSE_GUIDE}"
    )


def build_messages_detect(code: str) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": SYS_PROMPT},
        {"role": "user", "content": build_detect_user(code)},
    ]


def build_messages_triage(code: str, finding: str) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": SYS_PROMPT},
        {"role": "user", "content": build_triage_user(code, finding)},
    ]
