#!/usr/bin/env python3
"""
Convert internal dataset (v2 unified schema) into cloud-platform SFT JSONL.

v2 records: {id, language, task: detect|triage, code, finding?, label{...},
             source, license, repo_url, commit, verified, split}

Dual-task message templates (roadmap 3.3):
  - detect : user = 仅代码        -> assistant = {vulnerable, cwe, severity, confidence?, explanation}
  - triage : user = 代码+static finding -> assistant = {cwe, severity, verdict, explanation, patch?}

The task is made explicit in the user prompt so one model learns both input->output forms
without confusing them. `finding` is required for triage, omitted for detect.
Platform schema may vary; adjust messages structure per provider docs.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

# allow `python scripts/<tool>.py` to import the `model` package at repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from model.prompts import (  # noqa: E402
    SYS_PROMPT,
    build_detect_user,
    build_triage_user,
)

# Label keys to emit per task, in stable order (subset of record['label']).
LABEL_KEYS = {
    "detect": ["vulnerable", "cwe", "severity", "confidence", "explanation"],
    "triage": ["cwe", "severity", "verdict", "explanation", "patch"],
}
# Fields every sample of a task must carry (the task's core output).
REQUIRED_KEYS = {"detect": ["vulnerable"], "triage": ["verdict"]}


def build_messages(record: dict) -> List[Dict[str, str]]:
    """Build chat-format messages from a single v2 dataset record."""
    task = record.get("task", "detect")
    if task not in LABEL_KEYS:
        raise ValueError(f"unknown task {task!r} in record {record.get('id')}")

    language = record.get("language", "python")
    code = record.get("code", "")
    label = record.get("label") or {}

    if task == "detect":
        # Only code is shown; no static finding (public datasets give none).
        user_content = build_detect_user(code, language)
    else:
        finding = record.get("finding")
        if not finding:
            raise ValueError(f"triage record {record.get('id')} missing 'finding'")
        user_content = build_triage_user(code, finding, language)

    keys = [k for k in LABEL_KEYS[task] if k in label]
    missing_core = [k for k in REQUIRED_KEYS[task] if k not in label]
    if missing_core:
        raise ValueError(
            f"record {record.get('id')} label missing required field(s) "
            f"for task {task!r}: {missing_core}"
        )
    if not keys:
        raise ValueError(f"record {record.get('id')} label has no fields for task {task!r}")
    assistant_content = json.dumps(
        {k: label[k] for k in keys}, ensure_ascii=False, sort_keys=False
    )
    return [
        {"role": "system", "content": SYS_PROMPT},
        {"role": "user", "content": user_content},
        {"role": "assistant", "content": assistant_content},
    ]


def convert(input_path: Path, output_path: Path) -> None:
    records = [json.loads(line) for line in input_path.read_text().splitlines() if line.strip()]
    ok = skip = 0
    with open(output_path, "w", encoding="utf-8") as fh:
        for r in records:
            try:
                msg = {"messages": build_messages(r)}
            except (ValueError, KeyError) as e:
                print(f"[!] skip {r.get('id', '?')}: {e}")
                skip += 1
                continue
            fh.write(json.dumps(msg, ensure_ascii=False) + "\n")
            ok += 1
    print(f"[+] Converted {ok} records -> {output_path} (skipped {skip})")
    if skip:
        print(f"[!] {skip} records skipped; fix them in the source dataset, not here.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare v2 SFT data (dual task detect/triage) for cloud fine-tuning"
    )
    parser.add_argument("--input", "-i", type=Path, required=True)
    parser.add_argument("--output", "-o", type=Path, required=True)
    args = parser.parse_args()
    convert(args.input, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
