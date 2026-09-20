# 第三轮 —— 全量合并重训（基座起点）

## 为什么要做第三轮

第二轮续训模型 `qwen3-4b-instruct-2507-da015253d244` 验证结果：

- ✅ **探针达标**：fpr 0.667 → 0.000，confirm_recall 保持 0.917，accuracy 0.722 → 0.944（训前 5 条错判翻正 5 条）
- ❌ **detect 任务 CWE 崩坏**：cwe_acc 0.796 → 0.433。343/569 条预测 CWE 偏移，全部偏向第二轮数据里的加密类 CWE（CWE-321/338 在 GT 为 0 的情况下被预测出 25/23 条；CWE-330/605 归零）
- ❌ domain 集 confirm_recall 0.357 → 0.000（全 Reject，过度纠偏倾向）

**结论**：只喂 triage 增量样本的续训造成灾难性干扰。第三轮改为**从基座 `qwen3-4b-instruct-2507` 用全量合并数据重训**，一次性保住 detect + 修复后的 triage。

## 数据（全部在 `data/round3/upload/`，chatml 格式，与历次上传同构）

| 文件 | 条数 | 内容 |
|---|---|---|
| `train.jsonl` | **2595** | detect 2406 + triage 第一轮 132 + round2 修补 54 + 签名/认证 Confirm 修补 3 |
| `val.jsonl` | **130** | detect 100（从 PyCode-Vul detect_val 抽样）+ triage 30（10 规则 × 3 条，15C+15R）|
| `test.jsonl` | **130** | detect 100（从 PyCode-Vul detect_test 抽样）+ triage 30（10 规则 × 3 条，15C+15R）|

验证/测试集从 12 条扩充到 130 条（≈train 的 5%），混合 detect + triage 任务。triage 部分覆盖全部 10 条 CRYPTO 规则，每规则 3 条样本（2C+1R 或 1C+2R），全部通过 Semgrep 回测，无交叉触发。

新增的 3 条修补样本（`data/round3/signature_fix_source.jsonl`，Semgrep 回测 3/3）针对第二轮后唯一残留错判（探针 #11：MD5/SHA-1 手写签名被误判 Reject），覆盖"弱算法用于**认证/签名** → Confirm"：API 令牌签名、webhook 验签、升级包校验。

## 网页端训练（百炼，华北2·北京）

新建"模型微调"任务，**基础模型选 `qwen3-4b-instruct-2507`**（不是第二轮模型），上传 `data/round3/upload/` 下三个文件。最终超参：

| 参数 | 值 | 说明 |
|---|---|---|
| 训练方式 | LoRA | |
| batch_size | 16 | 2595/16 ≈ 162 步/epoch |
| learning_rate | 1e-4 | |
| **n_epochs** | **3** | triage 仅 7.4%，用更多 epoch 补偿 rank=16 的容量 |
| eval_steps | 50 | ~3 evals/epoch |
| **lora_rank** | **16** | 🔒 锁定 |
| **lora_alpha** | **32** | 🔒 锁定（alpha=2×rank，scale=2 标准强度）|
| **lora_dropout** | **0.005** | 🔒 锁定（几乎不丢弃）|
| lr_scheduler_type | cosine | |
| max_length | 2048 | detect 有长样本 |

**参数组合特性**：rank=16 + dropout=0.005 = **容量偏小、几乎无正则**。基座重训 2595 条足以支撑（第一轮 rank=8 即达 cwe_acc 0.796），但 triage 学习更依赖 epoch 数补偿，故取 3。

## 训后验证（判据）

```bash
export LLM_API_KEY="$(sed -n '2p' api.txt)"
export LLM_MODEL_ID="qwen3-4b-instruct-2507-<新后缀>"

# 18 条探针（同一脚本、同一探针，与训前/第二轮可比）
python scripts/run_triage_probes.py \
    --out data/round3/eval/triage_probe_results_r3.json \
    --compare data/round2/eval/triage_probe_results_before.json

# 全量基准
sed "s|qwen3-4b-instruct-2507-510facca98f1|$LLM_MODEL_ID|" \
    data/round2/eval/benchmark_config_template.yaml > /tmp/benchmark.ft3.yaml
python main.py --benchmark --config /tmp/benchmark.ft3.yaml
```

**全部通过才算成功**：
- fpr ≤ 0.167（最多错 1 条）且 #13/#14/#15/#17 保持 Reject、#11 翻回 Confirm
- confirm_recall ≥ 0.917
- detect：cwe_acc ≥ 0.75（恢复到 0.796 附近）、f1 ≥ 0.65
- domain 切片仅供参考

基线存档：`data/round2/eval/benchmark_before_ft.json`（第一轮模型）、`reports/benchmark/benchmark.json`（第二轮模型，已被本轮基准覆盖）。
