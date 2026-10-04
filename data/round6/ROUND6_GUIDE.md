# Round-6 指南：全规则覆盖 + 安全库对冲 + 全量基座重训

> 本指南已按仓库实际产物校正（2026-10）。凡是不能由脚本复现的说法都已删除。

## 一、R5 回归诊断（本轮修复目标）

| R5 问题 | 指标 | R3值 | R5值 | R6对策 |
|---|---|---|---|---|
| triage Confirm 召回下滑 | 18-probe confirm_recall | 1.000 | 0.667 | 新增 Confirm 样本 |
| 领域FPR翻倍 | domain fpr | 0.067 | 0.289 | 扩增 Reject 样本 + 安全库对冲 |
| triage样本比例失衡 | Confirm:Reject | 122:100 | — | R6 新增 Confirm:Reject = 83:53 |
| detect 全规则族覆盖 | 部分规则缺训练样本 | 5/10 | 5/10 | 补齐至 13/13 规则族 |

## 二、数据构成（全量合并重训）

**R6 基线新增 322 条**，来自 8 个必需源文件（`scripts/build_round6_final_dataset.py`
的 `R6_SOURCE_FILES` 是唯一事实来源）。R6 最终化又追加了 79 条 advisory 支撑的
真实记录（见第七节），**最终 R6 新增 401 条**：

| 源文件 | 条数 |
|---|---|
| new_detect.jsonl | 33 |
| new_triage.jsonl | 21 |
| supplement_detect.jsonl | 28 |
| supplement_triage.jsonl | 5 |
| supplement_v2_detect.jsonl | 21 |
| supplement_v2_triage.jsonl | 6 |
| rule_fixture_detect.jsonl | 104 |
| rule_fixture_triage.jsonl | 104 |
| **合计** | **322** |

| 类别 | 数量 | 说明 |
|---|---|---|
| detect pos（漏洞） | 100 | 覆盖全部 CRYPTO-001~013 规则族 |
| detect aneg（安全库） | 17 | 安全库的正规用法 |
| detect bneg（弱原语×安全） | 20 | 库工具 / legacy 格式 / 完整性用途 |
| detect neg（规则夹具） | 37 | 规则库 `ok:`/good 对照（含明确的安全替代写法） |
| detect safe（其余） | 12 | new_detect 中的安全样本 |
| triage Confirm | 83 | R5 回归修复 + 硬编码密钥/SSLv3/RSA-1024 + 规则夹具正例 |
| triage Reject | 53 | PEM/PKCS8 + passlib + itsdangerous + JWT + 规则夹具对照 |
| **合计** | **322** | detect=186 (pos 100 / neg 86), triage=136 (Confirm 83 / Reject 53) |

### 规则夹具（rule_fixture_*.jsonl）来源与限制

由 `scripts/convert_rule_fixtures_to_round6.py --emit` 从本地外部规则库生成：

| 上游 | 路径 | 许可 | 用途 |
|---|---|---|---|
| Semgrep 官方规则夹具 | `data/external/semgrep-rules/python/**`（`# ruleid:` / `# ok:` 标注） | Semgrep Rules License v1.0 | detect 正/负例 + triage Confirm/Reject（不携带未经复核的 fix patch） |
| Bandit 示例程序 | `data/external/bandit/examples/` | Apache-2.0 | CRYPTO-001/002/008/009/010 的 detect 正/负例 |

只映射语义与已发布 CRYPTO-001~013 完全一致的规则；上游更宽的规则
（blowfish / RC2 / IDEA / XOR / MD2 / MD4 / JWT / sha224 等）一律跳过。
正例必须命中对应 CRYPTO 规则的 scope，负例必须含有明确的安全替代写法
（如 `sha256` / `AES` / GCM / `os.urandom` / `create_default_context`），
避免把"检测器没覆盖的坏代码"误标成安全。全部 208 条 `verified=false`。

> **用途边界**：规则夹具是工具回归数据，用来补 negative/Reject 和 finding
> 覆盖，**不是**真实漏洞正例。Semgrep 来源的行带 Semgrep Rules License v1.0，
> 若对外再分发数据集需按该许可处理（Bandit 来源为 Apache-2.0）。

**最终合并**（322 条基线 + 79 条真实记录 = 401 条新增）：

| 来源层 | 条数 | verified |
|---|---|---|
| R6 基线新增（curated/规则夹具） | 322 | 全部 `false` |
| `real_verified_detect.jsonl` | 30（全为漏洞正例） | `true`（23 K3 + 7 人工） |
| `real_verified_triage.jsonl` | 49（30 Confirm / 19 Reject） | `true`（37 K3 + 12 人工） |
| **R6 新增合计** | **401** | detect 216 (pos 130 / neg 86), triage 185 (Confirm 113 / Reject 72) |

**合并R5基座**（`data/round5/final/upload/full`，已剥离 TRIAGE_PURPOSE_GUIDE）：

```
train = 3115   val = 347   test = 660   total = 4122
```

重新生成：

```bash
python3 scripts/build_round6_final_dataset.py --emit
```

> **重要数据质量限制**：R6 基线新增 322/322 都是 `verified=false`，属于人工/模型
> 辅助构造而非独立复核过的真实漏洞。另有 79 条 `verified=true` 真实记录，但
> 真实 crypto 正例仍只有 30 条（低于 50-100 门槛）。统计时必须分层，且不得
> 把基线样本当作已验证真值。详见 `reports/data_quality/r6_final_feasibility.md`。

## 三、新增库覆盖（对比R5）

| 库 | 样本数 | 类型 |
|---|---|---|
| cryptography | 9 | aneg |
| PyNaCl | 3 | aneg |
| itsdangerous | 4 | aneg(2) + bneg(2) |
| PyJWT | 3 | aneg(2) + bneg(1) |
| PyCryptoDome | 4 | aneg(2) + bneg(2) |
| passlib | 5 | trej |
| **argon2-cffi** | 2 | aneg（NEW） |
| **ecdsa** | 2 | aneg（NEW） |
| **google-auth** | 1 | aneg（NEW） |
| **oscrypto** | 1 | aneg（NEW） |

## 四、关键设计决策

1. **TRIAGE_PURPOSE_GUIDE 从训练数据剥离**：`model/prompts.py` 新增
   `training=False` 参数；训练时由 `prepare_sft_data.py --training` 控制。
   训练数据中不再包含引导文本，推理时仍追加。
   R5 的 `data/round5/upload/full`（tracked，含引导句）是**旧制品**；
   训练必须使用 `data/round5/final/upload/full`（已剥离）。

2. **Legacy 格式兼容类型 bneg**：新增「库实现 legacy 原语 = 非漏洞」类 detect bneg，
   直击 R4/R5 passlib 问题的根因——教模型区分「库的格式兼容实现」与「真正的密码误用」。

3. **全规则族覆盖**：13/13 CRYPTO 规则族在 R6 新增数据中都有 detect pos 样本。

4. **分层留出（val/test）**：按规则族和样本类型分层抽取。
   **注意**：R6 的 val/test 是训练留出集，不是干净的外部评测集；
   评测必须使用 `data/round6/validation_frozen/`。

## 五、评测集冻结（重要）

历史 `data/round6/validation/{detect,triage}_eval.jsonl` 与训练集存在泄漏：

| 评测集 | 与优化可见集重叠（exact） | 与优化可见集重叠（AST） |
|---|---|---|
| r6 triage_eval (42) | 4 条 | 2 条 |
| r6 detect_eval (19) | 0 条 | 0 条 |

已由 `scripts/audit_dataset_leakage.py --write-frozen` 生成去泄漏版本：

```
data/round6/validation_frozen/detect_eval.jsonl   n=19  (pos=7, neg=12)
data/round6/validation_frozen/triage_eval.jsonl   n=36  (Confirm=4, Reject=32)
data/round6/validation_frozen/manifest.json
```

`configs/benchmark_round6.yaml` 已指向冻结集。

> **统计功效警告**：冻结 triage 只有 4 条 Confirm。`confirm_recall` 在 n=4 上没有
> 统计意义，只能报计数与置信区间，不能作为验收门槛。

## 六、训练参数

```
基座: qwen3-4b-instruct-2507（新鲜基座，与R3同起点）
全量合并重训（严禁增量续训）
QLoRA: rank=16, alpha=32, dropout=0.005
学习率: 1e-4, cosine decay
batch: 16, epochs: 3
max_length: 2048
验证步数: 50
```

## 七、真实数据合并（R6 最终化，取代独立第七轮）

R6 的基座新增 322 条 curated/synthetic/规则夹具样本，不解决真实 crypto 正例
缺口；随后合并了 79 条 advisory 支撑的真实记录（最终 401 条新增）。正式训练前
允许继续补强，但不再新建 R7：真实记录直接合并进 R6。

### 7.1 固定 commit 安全参考层

`result.txt` 对应的 15 条固定 commit 审计候选已完成源码核验。项目负责人确认
将其中 7 条 `secure_reference` 合并为独立的非训练参考层：

```bash
python3 scripts/build_report_secure_references.py --emit
```

输出：

- `data/round6/references/report_secure_references.jsonl`
- `reports/data_quality/report_secure_references_stats.json`

这 7 条只用于修复建议、安全写法比较和后续人工晋级，全部保持
`verified=false`、`training_eligible=false`，不进入训练集，也不改变
`r6_manifest.json`。另外 8 条 `exclude` 不合并。

| 文件 | 作用 | 必需？ |
|---|---|---|
| `data/round6/candidates/real_crypto_candidates.jsonl` | 联网/本地 advisory 采集的候选池 | 可选 |
| `data/round6/candidates/real_crypto_candidates_broad.jsonl` | 不限包名的更大候选池 | 可选 |
| `data/round6/candidates/real_crypto_candidates_enriched.jsonl` | 抓回 fix diff 后的 vulnerable/fixed 代码对 | 可选 |
| `data/round6/candidates/real_crypto_candidates_functions.jsonl` | 按 fix commit 重建的函数级 vulnerable/fixed 代码对 | 可选 |
| `data/round6/candidates/real_crypto_candidates_local.jsonl` | 通过通用适配器从本地兼容 JSON/JSONL 中筛出的候选（当前 242 条） | 可选 |
| `data/round6/candidates/real_crypto_candidates_screened.jsonl` | 二次筛选后的候选（含 `_screen` 评分与 P1/P2/P3 分层） | 可选 |
| `data/round6/candidates/real_crypto_candidates_{ghsa,osv_pypi,pypa,pycode_vul}.jsonl` | 各来源 harvester 输出（GHSA/OSV/PyPA advisory + PyCode-Vul CSV） | 可选 |
| `data/round6/candidates/real_crypto_candidates_review_queue.jsonl` | P1+P2 优先人工复核队列（当前 7 条） | 可选 |
| `data/round6/candidates/real_crypto_candidates_need_code.jsonl` | 有 fix commit、待补代码的队列（当前 549 条） | 可选 |
| `data/round6/candidates/real_crypto_candidates_no_commit.jsonl` | 有公告但无 commit/repo 的队列（当前 703 条） | 可选 |
| `data/round6/candidates/real_crypto_candidates_predicted_cve.jsonl` | 包名/CWE 预测出 CVE id、待核对的记录（当前 2 条） | 可选 |
| `data/round6/candidates/real_crypto_candidates_volume.jsonl` | B 类训练量：无 advisory 但成对可解析生产代码（当前 331 条） | 可选 |
| `data/round6/candidates/real_crypto_candidates_uncertain.jsonl` | 模型预审后进入人工复核的队列（不确定 + 抽样） | 可选 |
| `data/round6/real_verified_detect.jsonl` | 人工确认的 Detect 正/负例 | 可选 |
| `data/round6/real_verified_triage.jsonl` | 人工确认的 Triage Confirm/Reject | 可选 |
| `data/round6/final/r6_manifest.json` | 逐来源与制品的 SHA-256 冻结记录 | `--emit` 自动生成 |

处理流程：

```bash
# 1) 采集候选（本地 advisory-database 克隆，或 --fetch-osv 联网）
python3 scripts/harvest_real_crypto_candidates.py \
    --advisories /path/to/advisory-database/advisories

# 1b) 需要更大候选池时，去掉包名白名单
python3 scripts/harvest_real_crypto_candidates.py \
    --advisories /path/to/advisory-database/advisories --all-packages \
    --out data/round6/candidates/real_crypto_candidates_broad.jsonl

# 1c) 各来源单独采集（本地已 clone / 已下载，harvester 支持 json/jsonl/yaml/yml）
#     GHSA / OSV-PyPI / PyPA：
#     python3 scripts/harvest_real_crypto_candidates.py \
#         --advisories data/external/advisory-database/advisories \
#         --out data/round6/candidates/real_crypto_candidates_ghsa.jsonl
#     PyCode-Vul（本地 CSV，vulnerable/patched 函数对，永远 B 类）：
python3 scripts/harvest_pycode_vul_candidates.py --emit

# 2) 二次筛选：合并默认池 + data/ 下兼容 JSON/JSONL，去重并打 P1/P2/P3
#    只写 _screen 元数据，永不改动 verified。用 --no-local-json 可复现旧口径
python3 scripts/screen_real_crypto_candidates.py --emit

# 3) 补代码：两条路线二选一或都做
#    3a) 抓 fix commit 的 .py diff 片段（快，但可能仍是片段）
python3 scripts/fetch_fix_code.py --dry-run
GITHUB_TOKEN=ghp_xxx python3 scripts/fetch_fix_code.py
#    3b) 按 commit 抓回完整文件，用 AST 定位最内层函数（更慢，但可 parse）
python3 scripts/rebuild_candidate_functions.py --dry-run
GITHUB_TOKEN=ghp_xxx python3 scripts/rebuild_candidate_functions.py

# 3c) 把函数级产物再筛一轮（默认池已含全部来源 + functions）
python3 scripts/screen_real_crypto_candidates.py --emit

# 4) 结构校验 + A 类门槛
python3 scripts/validate_real_crypto_candidates.py \
    data/round6/candidates/real_crypto_candidates_screened.jsonl --min-a 20

# 5) 强模型预审（花钱，先 --estimate-only 估价；输出永远 verified=false）
python3 scripts/audit_real_crypto_with_llm.py --estimate-only
python3 scripts/audit_real_crypto_with_llm.py \
    --candidates data/round6/candidates/real_crypto_candidates_review_queue.jsonl \
    --reasoning-effort high --workers 3

# 6) 浏览器人工复核不确定 + 抽样队列；每次结论自动重建 real_verified_{detect,triage}.jsonl
python3 scripts/annotate_real_crypto.py \
    --candidates data/round6/candidates/real_crypto_candidates_uncertain.jsonl \
    --reviewer reviewer-kimi --open
#    复核说明见 reviewer/README.md，schema 见
#    data/round6/candidates/SCHEMA.md

# 7) 合并 + 冻结哈希
python3 scripts/build_round6_final_dataset.py --emit
python3 scripts/audit_dataset_leakage.py --write-frozen
python3 scripts/build_dataset_metadata.py
```

完整的分步命令、外部数据源扩展清单和估价见
`data/round6/REAL_DATA_RUNBOOK.md`。

已实测（本地全量数据，可复现）：三个 advisory 源（GHSA 38 万条 JSON、OSV-PyPI
2.6 万条 JSON、PyPA 7721 条 YAML）加 PyCode-Vul CSV，各源 harvester 输出
GHSA 534 / OSV-PyPI 843 / PyPA 706 / PyCode-Vul 389，默认池合并后 2476 条。
通用本地 JSON/JSONL 适配器再补 242 条（当前全部来自
`data/round4/real_findings.jsonl`），合并 2718 条、去重后 1861 条候选，全部
`verified=false`；来源分布 OSV-PyPI 549 / GHSA 399 / pycode-vul 387 /
PyPA 231 / round4-real-findings 209 / GHSA-OSV 86。二次筛选后
P1/P2/P3 = 5/2/1854，只有 7 条进人工复核队列。400 条已带代码对（366 条两边
可 `ast.parse`，主要来自 PyCode-Vul 和函数重建），549 条只有 fix commit 待补代码
（`..._need_code.jsonl`），703 条既无 commit 也无 repo（`..._no_commit.jsonl`）。
全量 P3 估价 k3(high) ¥975.18 / k2.7-code(high) ¥267.01 超预算，实际只审
331 条 B 类训练量（`..._volume.jsonl`）。

约束：

- 真实文件缺失时，builder 原样复现 322 条 / 4043 条基线；文件存在时（当前
  状态）最终产出 401 条新增 / 4122 条总量。
- 真实文件存在时，builder 强制 `verified=true`、完整证据链（advisory/CVE、
  repo、commit、file）、规则与 CWE 一致、无重复、无仓库跨 split，任一不满足
  即失败退出。
- 训练前必须核对 `data/round6/final/r6_manifest.json` 的哈希；冻结后不得再改
  `train/val/test`。
- 评测仍使用 `data/round6/validation_frozen/`，训练期间不可见。
- 真实 crypto 正例达到 50-100 条之前，不得把 R6 结果写成真实 crypto 漏洞
  泛化能力；当前为 30 条。
