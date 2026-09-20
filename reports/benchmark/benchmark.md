# Benchmark Report

## Detect slice

| system | recall | precision | f1 | accuracy | cwe_acc |
|---|---|---|---|---|---|
| static | 0.112 | 1.000 | 0.201 | 0.524 | 0.3235 |
| llm | 0.984 | 0.536 | 0.694 | 0.534 | 0.8967 |

## Domain slice (triage)

| system | confirm_recall | fpr | accuracy | n |
|---|---|---|---|---|
| static | 1.000 | 1.000 | 0.483 | 29 |
| llm | 0.929 | 0.067 | 0.931 | 29 |
| agent | 0.929 | 0.067 | 0.931 | 29 |
