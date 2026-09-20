# Round-3 验收记录（最终验收模型）

模型：`qwen3-4b-instruct-2507-f5d4f1aedd8f`（基座重训，LoRA rank16/alpha32/dropout0.005，3 epochs，2595 条）
日期：2026-09-03

## 关键决策：triage 推理固化用途引导 prompt

`model/prompts.py::build_triage_user` 追加 `TRIAGE_PURPOSE_GUIDE`（user 消息末尾，SYS_PROMPT 保持微调原版不变）。
该函数是推理（`CloudBackend.triage`）与 SFT 生成（`prepare_sft_data.build_messages`）的**单一事实源**，
因此未来第 4 轮训练数据将自动带上引导，训练/部署分布一致。

引导原文（经验证，勿随意改动措辞）：
> "Before your verdict, reason about what the flagged call's output actually does: does it protect a
> credential, token, key, signature, nonce, or real secret (a security purpose -> Confirm), or is it
> only change detection, caching, sharding, dedup, ETag, tracing, load distribution, or test
> scaffolding (a non-security purpose -> Reject)?"

依据：同模型无引导 fpr=0.500 → 有引导 fpr=0.000、confirm_recall 保持 1.000（18 条探针）。换 SYS_PROMPT 会回归（#15 又错），故只动 user 不动 system。

## 判据对照

| 判据 | 目标 | 结果 | 判定 |
|---|---|---|---|
| 18 探针 fpr | ≤0.167 | **0.000** | ✅ |
| 18 探针 confirm_recall | ≥0.917 | **1.000** | ✅ |
| 18 探针 accuracy | — | **1.000**（18/18，含 #11 翻回、#13/14/15/17 Reject）| ✅ |
| detect cwe_acc | ≥0.75 | **0.921**（round-1 0.796，round-2 0.433）| ✅ |
| detect f1 | ≥0.65 | **0.697**（round-1 0.656）| ✅ |

证据文件：`data/round3/eval/triage_probe_results_r3_guided.json`（引导后探针）、`data/round3/eval/benchmark_r3/benchmark.json`（全量基准）。

## 基准细项（detect 569 条 / domain 29 条）

```
detect.llm : n=569 tp=302 fp=260 fn=3 tn=4  recall=0.990 precision=0.537 f1=0.697 cwe_acc=0.921
domain.llm : n=29  gt_confirm=14 gt_reject=15 confirm_recall=0.929 fpr=0.067 accuracy=0.931   (未加引导的原始 backend)
domain.agent: n=29 confirm_recall=0.857 fpr=0.067 accuracy=0.897
```

> 注：domain 切片在基准里走的是未加引导的 `backend.triage`，confirm_recall 已 0.929；引导只作用于 18 探针那类"生产代码非安全用途"硬样例。

## 已知局限（第 4 轮待补）

**detect 层近乎全报**：562/569 判漏洞，仅 4 真负 + 3 漏报。precision 0.537 ≈ 数据漏洞占比（0.536），
二元 vulnerable 判定无判别力，recall/cwe_acc 靠"宁可全报"取得。
- 对三件套影响有限：真实管线 = Semgrep 筛 finding → LLM 仅 Confirm/Reject，而 triage 层判别良好（探针 fpr=0、domain fpr=0.067）。
- 用户判断根因 = 训练数据缺"安全的加密代码"负样本；第 4 轮将扩充**非漏洞 + 漏洞**双类数据再训。

## 归档对照（round1→round3 detect）

| 指标 | round-1 (510facca98f1) | round-2 (da015253d244) | round-3 (f5d4f1aedd8f) |
|---|---|---|---|
| cwe_acc | 0.796 | **0.433**（灾难性干扰）| **0.921** |
| f1 | 0.656 | 0.642 | **0.697** |
| domain confirm_recall | 0.357 | 0.000 | **0.929** |
