# 第二轮续训 —— 数据与操作指引

针对第一轮微调模型 `qwen3-4b-instruct-2507-510facca98f1` 在 **triage（Confirm/Reject）** 上实测出的弱点，制作了一份**只喂新增样本**的增量训练集。本文件 = 数据卡 + 网页续训步骤 + 训后验证命令。

> 相关决定：只产出数据与网页操作指引（不通过 API 触发训练）；增量续训只喂新增样本；允许用真实模型调用先定位弱点、训后验证。

---

## 1. 训前弱点定位（为什么要做这份数据）

对真实微调模型跑了 18 条**带完整可触发代码的探针**（Semgrep 一定能在代码里命中，消除 domain 集“代码看不到被标记调用”的干扰）。训前基线：

| 指标 | 值 | 含义 |
|---|---|---|
| confirm_recall | **0.917** (11/12) | 真正的安全误用基本能保留 |
| fpr | **0.667** (4/6) | GT=Reject 却被 Confirm 的比例，**主要短板** |
| accuracy | 0.722 | 18 条中错 5 条 |

训前判错明细（`data/round2/eval/triage_probe_results_before.json`）：

- **#13 #14**：生产代码用 MD5 做文件变更检测 / 内容寻址缓存键（非安全用途）→ 被误判 Confirm。模型只学会了“test/fixture 才 Reject”，没学会“非安全用途也 Reject”。
- **#15**：SHA-1 一致性哈希分片 → 误判 Confirm（同理）。
- **#17**：random 抖动做退避 → 误判 Confirm。
- **#10**：RC4 加密一段数据（代码像“示例”）→ 误判 Reject（反向：把真加密当玩具）。

第 2 轮数据就按这 4 个非安全 Reject 场景 + 各家族测试夹具 + 各类真安全 Confirm 铺开。

---

## 2. 产出文件（本轮数据）

| 文件 | 说明 |
|---|---|
| `data/round2/triage_fix_source.jsonl` | **训练数据源**（v2 schema，54 条：28 Confirm / 26 Reject），GT 齐全 |
| `data/round2/val_source.jsonl` / `test_source.jsonl` | **验证/测试数据源**（各 12 条：6 Confirm / 6 Reject，全新代码，v2 schema）|
| **`data/round2/upload/train.jsonl`** | ⬆️ **平台上传用：训练集**（54 条，与第一轮成功上传的 chatml 格式完全一致）|
| **`data/round2/upload/val.jsonl`** | ⬆️ **平台上传用：验证集**（12 条）|
| **`data/round2/upload/test.jsonl`** | ⬆️ **平台上传用：测试集**（12 条）|

> ⚠️ `data/round2/*_source.jsonl` 是源数据（含 id/label 等字段），**不能直接上传平台**；可上传的只有 `data/round2/upload/` 下的三个文件。重新生成：`python scripts/build_round2_eval_sets.py`（会同步刷新 upload/ 目录）。`data/sft/` 下留有同内容的规范副本。
| `data/round2/eval/triage_probes.json` | 18 条训后验证探针（GT + code + finding）|
| `data/round2/eval/triage_probe_results_before.json` | 探针训前结果（上面基线）|
| `data/round2/eval/benchmark_before_ft.json/.md` | 训前全量基准快照（detect + domain）|
| `data/round2/eval/benchmark_config_template.yaml` | 训后跑全量基准的配置文件模板 |
| `scripts/run_triage_probes.py` | 可复用探针评测脚本（跑/汇总/对比）|

### 数据卡
- 规模：54 条增量样本 = 28 Confirm + 26 Reject；**只含 triage 任务**（detect 无需补）。
- 规则覆盖：10 条 CRYPTO 规则全覆盖（见下表）。Confirm 侧重”用于安全目的的真误用”（登录/口令散列、签名、加密、令牌、弱曲线、不校验证书）；Reject 侧重非安全 MD5/SHA-1 用法 + 各类真实测试夹具 + 真会触发规则的随机数测试夹具。
- **补充样本（4 条）**：针对探针 #17（`jitter_delay` 退避抖动误判 Confirm）补了 2 条**生产代码非安全随机数** Reject（退避抖动 `backoff_salt`、负载均衡 `shard_key`，变量名真实触发规则但用途非安全）；另为 Reject 空缺的 CRYPTO-006 / CRYPTO-009 各补 1 条测试夹具 Reject。
- **独立验证/测试集（各 12 条）**：全部新写代码，6 Confirm / 6 Reject，覆盖 10 条规则；其中 7 条是"生产代码非安全用途随机数/哈希"的 Reject（泛化试金石）。与训练集、18 条探针零重叠，每条均 Semgrep 回测命中预期规则。
- **忠实性校验**：每条样本都跑了 Semgrep 回测，**54/54 命中其预期规则且无串规则**（含对原有 `round2-CRYPTO-007-3-Reject` 的修复：ECB→CBC，消除 CRYPTO-005 串扰）；finding 字符串、CWE、severity 全部直接取自 `rules/crypto-*/rule.yaml`，与产品端一致。Confirm 全部带可用的安全修复 `patch`，Reject 说明逐条手写（无模板套话）。
- 格式：assistant 输出键 `[cwe, severity, verdict, explanation, patch]`，与第一轮一致，方便在平台里合并/续训。

按规则分布（Confirm/Reject）：

```
CRYPTO-001 MD5        5/8      CRYPTO-006 IV         2/1
CRYPTO-002 SHA-1      4/5      CRYPTO-007 硬编码密钥  2/2
CRYPTO-003 DES        2/1      CRYPTO-008 弱随机      3/4
CRYPTO-004 RC4        2/1      CRYPTO-009 弱密钥长度  2/1
CRYPTO-005 AES-ECB    2/1      CRYPTO-010 TLS        4/2
```

---

## 3. 网页端继续微调（阿里云百炼，华北2·北京 cn-beijing）

1. 打开百炼控制台 <https://bailian.console.aliyun.com/cn-beijing>，左侧进入 **模型中心 / 我的模型**，找到第一轮模型 `qwen3-4b-instruct-2507-510facca98f1`。
2. 进入**继续训练/再次微调**入口（若该模型卡片没有此入口：新建一个“模型微调”任务，把**基础模型**直接选成 `qwen3-4b-instruct-2507-510facca98f1` —— 即“微调再微调”，等于在现权重上续训）。
3. 训练数据：新建/选择**数据集** → 上传本地文件，三个文件都在 `data/round2/upload/` 下（与第一轮成功上传的文件完全同构）：
   - 训练集：`data/round2/upload/train.jsonl`（54 条）
   - 验证集：`data/round2/upload/val.jsonl`（12 条）
   - 测试集：`data/round2/upload/test.jsonl`（12 条）

   上传后在数据集里点”**校验/生效**”，确认三个文件全部通过、无 JSON/字段报错。
4. 任务设置（增量续训推荐超参，按 54 条小样本 + LoRA 续训场景选定）：

   | 参数 | 推荐值 | 一句话理由 |
   |---|---|---|
   | 训练方式 | **LoRA/QLoRA** | 续训防遗忘，比全参稳（若被迫用全参则 lr 降到 ~1e-5）|
   | batch_size | **8** | 小批量 → 每 epoch ~7 步、3 轮共 ~21 步，优化步数够 |
   | learning_rate | **1e-4** | LoRA 标准区间下限，续训不伤第一轮能力；勿超 2e-4 |
   | n_epochs | **3** | fpr 仍高可试 4–5；>6 易过拟合到这 54 条 |
   | eval_steps | **5** | ~21 步里取 4 个点看 val loss，防过拟合 |
   | lora_rank | **16** | 纠偏任务容量适中；8 偏小、32+ 易过拟合 |
   | lora_alpha | **32** | alpha=2×rank，scale=2 标准强度 |
   | lora_dropout | **0.05** | 小数据加一点正则 |
   | lr_scheduler_type | **cosine** | 末期平滑收敛；linear 亦可，避免 constant |
   | max_length | **1024** | 最长样本 ~500 token；设 <512 会截断 patch 教坏模型 |

   **验证集策略**：验证/测试集已单独制作并上传（各 12 条全新样本，覆盖 10 条规则与"生产代码非安全用途随机数"弱点模式，Semgrep 回测通过、与训练集/探针零重叠），因此训练集无需再切分，`split` 相关选项若仍出现设 **1.0**。平台的 val/test loss 只用来盯过拟合（从最低点明显回升才值得警惕）；最终判据仍是训后 18 条探针（针对性修复）+ 全量基准（防回退）。`warmup_ratio` 等其余参数保持平台默认。
5. 启动训练，等待完成；在训练任务/模型页复制**新模型 ID**（形如 `qwen3-4b-instruct-2507-<新的十六进制后缀>`）。
6. 用它做第 4 节“训后验证”。

> **回退方案（仅当平台不允许以微调模型为基座）**：若只能以基座 `qwen3-4b-instruct-2507` 为起点，则需要把第一轮 triage 数据与新增数据合并后一起上传：
> ```bash
> cat data/sft/triage_train_chatml.jsonl data/sft/triage_fix_chatml.jsonl \
>     > data/sft/triage_continue_chatml.jsonl     # 132 + 54 = 186 条
> ```
> 其余步骤不变，只是不再能“只喂新增样本”。

---

## 4. 训后验证（拿到新模型 ID 后执行）

在项目根目录运行。先注入凭证（api.txt 第 2 行，不回显）：

```bash
export LLM_API_KEY="$(sed -n '2p' api.txt)"
export LLM_MODEL_ID="qwen3-4b-instruct-2507-<新的十六进制后缀>"   # 换成第 3 节拿到的新 ID
```

**4a. 18 条探针（推荐优先，能直接对照弱点）：**

```bash
# 跑新模型并保存结果
python scripts/run_triage_probes.py \
    --out data/round2/eval/triage_probe_results_after.json

# 与训前基线对比（应看到 fpr 0.667 -> 明显下降，confirm_recall 不掉）
python scripts/run_triage_probes.py \
    --results data/round2/eval/triage_probe_results_after.json \
    --compare  data/round2/eval/triage_probe_results_before.json
```

**4b. 全量基准（detect 应基本不变；domain 集因上下文错位仅供参考）：**

```bash
# 把模板里的 model_id 换成新 ID（或直接用上面环境变量方式在模板中留空即可被环境变量接管）
sed "s|qwen3-4b-instruct-2507-510facca98f1|$LLM_MODEL_ID|" \
    data/round2/eval/benchmark_config_template.yaml > /tmp/benchmark.ft2.yaml
python main.py --benchmark --config /tmp/benchmark.ft2.yaml
```

注意：全量基准会**覆盖** `reports/benchmark/`；训前快照已存在 `data/round2/eval/benchmark_before_ft.json/.md`，跑完后与它比较即可。

**判据（对齐本轮弱点）**：
- `fpr`（探针）从 0.667 **显著下降**（最好 <0.2）——第 2 轮主攻点；
- `confirm_recall` 保持在 0.9+（别为降 fpr 把真 Confirm 也砍了）；
- 具体到条：#13/#14/#15/#17 应翻成 Reject；#10 应翻回 Confirm。
- 基准 detect slice 数值不应回退（本轮数据不含 detect，预期持平）。
