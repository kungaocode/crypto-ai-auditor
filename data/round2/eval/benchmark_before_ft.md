# Benchmark Report

## Detect slice

| system | recall | precision | f1 | accuracy | cwe_acc |
|---|---|---|---|---|---|
| llm | 0.836 | 0.540 | 0.656 | 0.531 | 0.7961 |

## Domain slice (triage)

| system | confirm_recall | fpr | accuracy | n |
|---|---|---|---|---|
| llm | 0.357 | 0.000 | 0.690 | 29 |
| agent | 0.357 | 0.067 | 0.655 | 29 |
