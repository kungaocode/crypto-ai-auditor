# Benchmark Report

## Detect slice

| system | recall | precision | f1 | accuracy | cwe_acc |
|---|---|---|---|---|---|
| llm | 0.990 | 0.537 | 0.697 | 0.538 | 0.9205 |

## Domain slice (triage)

| system | confirm_recall | fpr | accuracy | n |
|---|---|---|---|---|
| llm | 0.929 | 0.067 | 0.931 | 29 |
| agent | 0.857 | 0.067 | 0.897 | 29 |
