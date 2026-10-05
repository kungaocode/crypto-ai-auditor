# Benchmark Report

Config: `configs/benchmark_round5.yaml` — model backend: `CloudBackend` (`qwen3-4b-instruct-2507-7421554c67e6`).

> Round context and known regressions: see `docs/experiment.md`. Do not compare numbers across rounds. `confirm_recall` is low-power on eval slices with few GT-Confirm rows; always read it with the positive count.

> **Status:** this is a degraded Round-5 run, retained as regression evidence.
> Round 6 has since been trained and evaluated separately against the frozen
> slices and 18 probes; see `data/round6/eval/RESULTS.md`. The R5 numbers here
> must not be mixed with the R6 results. A same-config Round-5 cloud rerun
> produced detect `0/2/3/8` and triage FPR `0.368`; a previous run on the same
> deployment produced detect `0/1/3/9` and FPR `0.289`.

## Detect slice (n=13)

| system | recall | precision | f1 | accuracy | cwe_acc |
|---|---|---|---|---|---|
| llm | 0.000 | 0.000 | 0.000 | 0.615 | None |

## Domain slice (triage, n=41, GT-Confirm=3)

| system | confirm_recall | fpr | accuracy | n |
|---|---|---|---|---|
| llm | 1.000 | 0.368 | 0.658 | 41 |
