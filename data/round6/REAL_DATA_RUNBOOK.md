# R6 真实数据补强 Runbook（候选池 -> 函数重建 -> 模型预审 -> 人工复核 -> 合并）

> 本文是 `data/round6/ROUND6_GUIDE.md` 第七节和
> `docs/dataset_source_strategy.md` 的可执行版。命令按顺序执行；每一步都只写
> `verified=false`，只有人工 Confirm/Reject 才会写入
> `data/round6/real_verified_{detect,triage}.jsonl`。
>
> 沙箱内没有出网能力：`git clone`、GitHub API、OSV 和 Moonshot/Kimi 调用都必须在
> 本机执行。离线部分（筛选、统计、估价）已经跑完，结果见下面的快照。

## 0. 当前快照（2026-10-03，离线复现）

| 指标 | 值 |
|---|---|
| 已落盘外部数据源 | `data/external/advisory-database`（38 万条 GHSA JSON）、`data/external/osv-pypi`（2.6 万条 OSV JSON）、`data/external/pypa-advisory-database`（7721 条 YAML）、`data/external/bandit`、`data/external/semgrep-rules`、`data/external/trailofbits-semgrep-rules` |
| 新增本地数据源 | `data/raw/pycode-vul`（CSV，14248 条 train 记录，含 vulnerable/patched 函数对） |
| 各源 harvester 输出 | GHSA 534（402 带 commit）/ OSV-PyPI 843（408）/ PyPA 706（296）/ PyCode-Vul 389 |
| 默认池合并 | 2476（8 个显式池，经 `candidate_id` 合并后） |
| 通用本地 JSON/JSONL 适配 | 扫描 13 个文件、608 条记录，适配 242 条（当前全部来自 `data/round4/real_findings.jsonl`） |
| 合并候选（默认池 + 本地适配） | 2718（去重丢弃 857） |
| 去重后入选候选 | 1861 |
| 来源分布 | OSV-PyPI 549 / GHSA 399 / pycode-vul 387 / PyPA 231 / round4-real-findings 209 / GHSA-OSV 86 |
| P1 / P2 / P3 | 5 / 2 / 1854 |
| P3 细分 | `p3_volume` 331（可解析的真实生产代码对，B 类训练量）/ `p3_stock` 1523 |
| 已带代码对 | 400（两边都可 `ast.parse` 的 366） |
| 代码路径分类（全候选） | production 415 / test+fixture 194；其余路径未知 |
| 待补代码（有 fix_commit、无代码） | 549（`real_crypto_candidates_need_code.jsonl`） |
| 无 commit（需先补 advisory/版本溯源） | 703，且 703 条全部 `repo_url` 为空（`real_crypto_candidates_no_commit.jsonl`） |
| 模型预测 id（需核对 NVD/GHSA） | 2（`real_crypto_candidates_predicted_cve.jsonl`） |
| B 类训练量（无 advisory、成对代码） | 331（`real_crypto_candidates_volume.jsonl`） |
| 模型预审估价（P1） | k3(high) ¥2.56 / k2.7-code(high) ¥0.70 |
| 模型预审估价（P2） | k3(high) ¥1.10 / k2.7-code(high) ¥0.30 |
| 模型预审估价（全量 P3） | k3(high) ¥975.18 / k2.7-code(high) ¥267.01（超预算，不可全量） |
| 模型预审估价（331 条 volume） | k2.6 / k2.7-code：normal ¥17.18 / high ¥53.79 |
| 规则夹具转 R6（已完成） | 208 条（detect 104 / triage 104） |
| advisory 扩源净增真实正例 | 0：GHSA/OSV/PyPA 三个 advisory 源已抽干 |

结论：三个 advisory JSON/YAML 源（GHSA / OSV-PyPI / PyPA）已全部吃透，重复过滤后
没有新增 A 类正例。通用本地 JSON/JSONL 适配器又补了 242 条真实 finding 候选，但
它们没有 advisory/CVE、fix commit 或代码对，去重后只保留 209 条，全部是
`p3_stock`，只能作为 Reject/finding 库存，不能升 A。真正的 B 类训练量仍来自
PyCode-Vul CSV 的 331 条可解析成对生产代码，另有 703 条只有公告、没有 commit、
也没有 repo 的待溯源记录。A 类瓶颈仍未解除：需要本机联网跑
`rebuild_candidate_functions.py` / `fetch_fix_code.py` 补代码，再人工复核。

分类法缺口（提升前必须处理）：PyCode-Vul 的 crypto 预测标签里，`CWE-330`（220 条）
以及 `CWE-328/347/798/319/311` 都不在 R6 的 `RULE_CWE`（CRYPTO-001..013 只覆盖
327/329/321/338/326/295/256/916/208）。这些行只能做 B 类训练量，不能直接进
`real_verified_*`。若要提升，需要先决定是扩展 `CRYPTO-0xx` 规则，还是把
CWE-330/CWE-328 等映射到现有规则，并在 pending 规则文件中写明。

复现命令（全部离线，沙箱内即可跑）：

```bash
# GHSA（本地 clone，watchlist 命中；534 条，402 带 commit）
python3 scripts/harvest_real_crypto_candidates.py \
  --advisories data/external/advisory-database/advisories \
  --source-label GHSA --id-prefix ghsa \
  --out data/round6/candidates/real_crypto_candidates_ghsa.jsonl \
  --stats-out reports/data_quality/harvest_ghsa_stats.json

# OSV-PyPI（all-packages + keyword-recall + adjacent CWEs；843 条，408 带 commit）
python3 scripts/harvest_real_crypto_candidates.py \
  --advisories data/external/osv-pypi --all-packages --keyword-recall \
  --extra-cwes CWE-347,CWE-798,CWE-319,CWE-330,CWE-311,CWE-328 \
  --source-label OSV/PyPI --id-prefix osv \
  --out data/round6/candidates/real_crypto_candidates_osv_pypi.jsonl \
  --stats-out reports/data_quality/harvest_osv_pypi_stats.json

# PyPA YAML（watchlist + keyword-recall；706 条，296 带 commit）
python3 scripts/harvest_real_crypto_candidates.py \
  --advisories data/external/pypa-advisory-database/vulns --keyword-recall \
  --source-label PyPA --id-prefix pypa \
  --out data/round6/candidates/real_crypto_candidates_pypa.jsonl \
  --stats-out reports/data_quality/harvest_pypa_stats.json

# PyCode-Vul CSV（389 条，永远 B 类）
python3 scripts/harvest_pycode_vul_candidates.py --emit

# 二次筛选 + 全部队列（默认含通用本地 JSON/JSONL 适配，1861 条入选）
python3 scripts/screen_real_crypto_candidates.py --emit

# 旧口径（不扫描 data/ 下的通用 JSON/JSONL）：去重后 1652 条
python3 scripts/screen_real_crypto_candidates.py --no-local-json --emit
```

## 1. 继续扩 `data/external/`（本机联网执行）

先建目录，全部走 `.gitignore` 已忽略的 `data/external/`，不要提交大文件：

```bash
mkdir -p data/external
```

### 1.1 直接可用（OSV schema，harvester 可直接吃）

```bash
# PyPA 官方 advisory-database（PYSEC 源）。本地 github/advisory-database 全部是
# GHSA-* id（实测 380127/380127），PyPA 库能补进 GHSA 里没有的 PYSEC 记录
git clone --depth 1 https://github.com/pypa/advisory-database.git \
  data/external/pypa-advisory-database
# PyPA 库实际是 YAML；harvester 已支持 *.json / *.jsonl / *.yaml / *.yml
find data/external/pypa-advisory-database -name 'PYSEC-*' | head

# OSV PyPI 生态全量导出（zip，每个 advisory 一个 JSON）
# 数量级：几十 MB，比 clone advisory-database 小得多
# 聚合 GHSA + PYSEC，与已有 GHSA 库重叠，增量主要是 PYSEC 来源的记录
curl -L -o data/external/osv-PyPI-all.zip \
  https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
mkdir -p data/external/osv-pypi && \
  unzip -o data/external/osv-PyPI-all.zip -d data/external/osv-pypi

# 之后可直接： python3 scripts/harvest_real_crypto_candidates.py \
#   --advisories data/external/osv-pypi --all-packages \
#   --out data/round6/candidates/real_crypto_candidates_osv.jsonl
```

注意：相当一部分 PYSEC 记录没有 `cwe_ids` 字段，harvester 的 CWE 过滤会直接跳过，
所以这一路的新增目标 CWE 候选可能不多。先跑一遍看增量，再决定是否继续投入。

> 数据源索引见 https://google.github.io/osv.dev/data/ 。若上面的 bucket 路径变化，
> 以该页给出的当前下载地址为准。

### 1.2 需要先核验页面再下载（真实漏洞修复对）

| 数据 | 落盘位置 | 命令 / 来源 | 先核验什么 |
|---|---|---|---|
| CVEfixes | `data/external/CVEfixes/` | Zenodo record 5842818（搜索确认） | 版本、Python 占比、许可证、实际大小 |
| MoreFixes | `data/external/MoreFixes/` | Zenodo record 13983082（搜索确认） | 版本、下载文件、许可证；**不要**相信“8.8 TB”未核验说法 |
| PyVul | `data/external/PyVul/` | arXiv 2509.04260 关联仓库 | 仓库是否发布、许可、Python 子集 |
| ReposVul | `data/external/ReposVul/` | 论文配套仓库 / Zenodo | 下载地址、许可、Python × 目标 CWE 子集 |
| CrossVul | `data/external/CrossVul/` | `git clone https://github.com/vulnerability-dataset/cross-vul.git` | 仓库是否仍在线、Python 子集、许可 |

这些数据**不能**直接变成 `verified=true`；它们只扩大候选池和用于交叉验证。
下载后按目标 CWE 过滤，先只统计 Python × 目标 CWE × 有 paired 代码的数量。

### 1.3 只能补 Reject / finding（不要当正例）

```bash
# Bandit 测试用例：纯 Python，覆盖 CWE-327/328/330/295，适合做 Reject 和规则回归
git clone --depth 1 https://github.com/PyCQA/bandit.git data/external/bandit

# Semgrep 规则（Trail of Bits + 官方）：提供 finding 输入模板和正/负测试桩
git clone --depth 1 https://github.com/trailofbits/semgrep-rules.git \
  data/external/trailofbits-semgrep-rules
git clone --depth 1 https://github.com/semgrep/semgrep-rules.git \
  data/external/semgrep-rules

# CodeQL Python 安全查询（稀疏检出，只拉 Security 目录）
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/github/codeql.git data/external/codeql
cd data/external/codeql && \
  git sparse-checkout set python/ql/src/Security && cd -
```

这些是**规则和测试桩**，不是真实漏洞正例。用于生成 finding、构造 Reject、
回归 CRYPTO-001..013 规则。不要把它们写进 `real_verified_*`。

### 1.4 本地非 advisory 数据（离线，脚本已支持多种文件类型）

harvester 除 advisory JSON/YAML 外，还读取本地 CSV。`data/raw/pycode-vul` 的
train/test CSV 每行都是真实仓库函数，带
`vulnerable_function_source` / `patched_function_source` 和模型预测的
`predicted_cwe_ids`。它没有 advisory/CVE，所以永远只能进 B 类训练量：

```bash
# PyCode-Vul CSV -> 候选 JSONL（默认跳过 test split，避免泄漏 domain_eval）
python3 scripts/harvest_pycode_vul_candidates.py --emit
# 产物：data/round6/candidates/real_crypto_candidates_pycode_vul.jsonl
```

所有行 `verified=false`、`preliminary_class="B"`，`match_reasons` 里写明
`pycode-vul:predicted-cwe`（模型预测，非真值）和
`pycode-vul:sha-semantics-unconfirmed`。要冲 A 类仍需 advisory/CVE 溯源。

`screen_real_crypto_candidates.py` 另外默认扫描 `data/` 下兼容的
`.json`/`.jsonl`。适配器会识别常见代码对、repo、file、commit、CWE/CVE 和 rule
字段名，把本地记录规范成候选格式并写入
`real_crypto_candidates_local.jsonl`。当前扫描 13 个文件/608 条记录，适配 242 条，
全部来自 `data/round4/real_findings.jsonl`，最终去重保留 209 条。它们是
`verified=false`、`preliminary_class="B"`、`p3_stock`，没有 advisory/CVE、
fix commit 或代码对，不能进入 A 类。需要检查适配口径时用：

```bash
# 只看本地数据覆盖和当前池行数
python3 scripts/screen_real_crypto_candidates.py --coverage --emit

# 复现旧口径（关闭通用本地 JSON/JSONL 适配）
python3 scripts/screen_real_crypto_candidates.py --no-local-json
```

## 2. 把候选补成函数级代码对（本机联网）

当前 1861 条候选里，400 条已带代码对，其中 366 条两边都能 `ast.parse`（主要来自
PyCode-Vul 和函数重建）；仍有 549 条只有 fix commit、没有代码
（`..._need_code.jsonl`）。
`rebuild_candidate_functions.py` 会按 fix commit 抓回修复前/后完整文件，再用 AST
定位最内层函数。需要 GitHub token：

```bash
# 先看会抓哪些
python3 scripts/rebuild_candidate_functions.py --dry-run

# 真正抓取；token 可显著提高限流上限
GITHUB_TOKEN=ghp_xxx python3 scripts/rebuild_candidate_functions.py \
  --in data/round6/candidates/real_crypto_candidates_screened.jsonl \
  --out data/round6/candidates/real_crypto_candidates_functions.jsonl
```

输出仍是 `verified=false`，只是把代码证据补成可解析的函数。

另有 703 条 advisory 有公告但**既无 commit、也无 repo_url**
（`..._no_commit.jsonl`）：缺的是包名 -> 仓库的映射。要先把上游包的 GitHub 地址
查出来（PyPI JSON API `https://pypi.org/pypi/<pkg>/json` 的 `project_urls`），
才能定位 fixed_version 前后两个版本做差异。这一路是下一步扩量的主要缺口。

## 3. 重新筛选 + 估价（离线）

```bash
# 默认池已包含 watchlist/broad/ghsa/osv/pypa/pycode-vul/enriched/functions 八个池；
# 脚本还会扫描 data/ 下的兼容 JSON/JSONL。去重后按证据强度分 P1/P2/P3，
# 并产出 review_queue / need_code / no_commit / predicted_cve / volume 五个队列。
# 用 --no-local-json 可关闭本地 JSON 适配，复现旧的 1652 条口径。
python3 scripts/screen_real_crypto_candidates.py --emit

# 估价：先用 P1（便宜），确认流程后再上全量
python3 scripts/audit_real_crypto_with_llm.py \
  --candidates data/round6/candidates/real_crypto_candidates_review_queue.jsonl \
  --estimate-only --model kimi-k3 --reasoning-effort high \
  --price-input 20 --price-output 100
```

价格口径（Moonshot 官方，单位 ¥/1M tokens）：k3 输入 20、输出 100；
k2.7-code 输入 6.5、输出 27。估价公式见 `reports/data_quality/`。

## 4. 模型预审（本机联网，花钱）

先用 P1+P2 冒烟（`..._review_queue.jsonl`，共 7 条），确认输出格式和
`verified=false`：

```bash
# P1 五条，k3 ≈ ¥2.56（high），正常推理 ≈ ¥0.51
python3 scripts/audit_real_crypto_with_llm.py \
  --candidates data/round6/candidates/real_crypto_candidates_review_queue.jsonl \
  --reasoning-effort high --workers 3 \
  --sample-rate 0.15 --price-input 20 --price-output 100
```

确认无误后再决定全量策略（预算约 ¥50，勿超三位数）。注意：1854 条全量 P3 估价
k3(high) ¥975.18 / k2.7-code(high) ¥267.01，**远超预算，不要全量跑**。实际可选：

```bash
# 选项 A（推荐）：只审 331 条 B 类训练量（成对生产代码、无 advisory），
#   k2.7-code(high) ≈ ¥53.79，正常推理 ≈ ¥17.18；kimi-k2.6 同价
python3 scripts/audit_real_crypto_with_llm.py \
  --candidates data/round6/candidates/real_crypto_candidates_volume.jsonl \
  --model kimi-k2.7-code --reasoning-effort high --workers 4 \
  --price-input 6.5 --price-output 27

# 选项 B：只审 P1+P2（7 条），k3(high) ≈ ¥3.66，最省；其余留待人工
python3 scripts/audit_real_crypto_with_llm.py \
  --candidates data/round6/candidates/real_crypto_candidates_review_queue.jsonl \
  --model kimi-k3 --reasoning-effort high --workers 3 \
  --price-input 20 --price-output 100
```

输出：

```text
data/round6/candidates/model_audit.jsonl
data/round6/candidates/real_crypto_candidates_uncertain.jsonl   # 进人工队列
reports/data_quality/model_audit_cost.json
```

`model_audit.jsonl` 本身是机器证据（`verified=false`）。若把模型裁决作为最终
标签，必须通过导入脚本写入 `real_verified_*`，并保留
`review_mode="model"` / `model="kimi-k3"` 的来源标记：

```bash
python3 scripts/import_model_audit_verdicts.py \
  --audit data/round6/candidates/model_audit_k3_binary.jsonl \
  --reviewer reviewer-kimi
```

导入后的记录 `verified=true`，但报告时必须和 `review_mode="manual"` 的记录分开
统计，不得改写成人工标签。

## 5. 人工复核（本机浏览器）

只审不确定 + 抽样那部分，减少工作量：

```bash
python3 scripts/annotate_real_crypto.py \
  --candidates data/round6/candidates/real_crypto_candidates_uncertain.jsonl \
  --reviewer reviewer-kimi --open
```

结论只有 `confirm` / `reject` 会落到：

```text
data/round6/real_verified_detect.jsonl
data/round6/real_verified_triage.jsonl
```

`confirm` 要求：目标规则、明确许可证、解释、两段能 `ast.parse` 的 Python 片段。

## 6. 合并成最终版 R6（离线）

```bash
# 先 QA，不落盘
python3 scripts/build_round6_final_dataset.py --dry-run

# 达标后再落盘，重建 train/val/test 与 r6_manifest.json
python3 scripts/build_round6_final_dataset.py --emit

# 合并后重新冻结哈希
python3 scripts/build_dataset_metadata.py
```

约束（builder 强制、失败即退出）：

- `real_verified_*` 必须 `verified=true`，且证据链完整（advisory/CVE、repo、commit、file）。
- 规则与 CWE 必须一致，无重复，同一仓库不跨 split。
- 训练前核对 `data/round6/final/r6_manifest.json` 的哈希；冻结后不得再改 train/val/test。
- 评测仍用 `data/round6/validation_frozen/`，训练期间不可见。
- 真实 crypto 正例 < 50 条时，R6 结果不得写成真实 crypto 漏洞泛化能力
  （当前 30 条，目标 50-100 条）。

## 7. 验收门槛提醒

| gate | criterion |
|---|---|
| A 类真实正例 | 目标 50-100 条（当前 30） |
| 不同 advisory/CVE | ≥ 10 |
| 不同仓库 | ≥ 10 |
| 目标规则族 | ≥ 4 |
| Triage Confirm-able | ≥ 10 |
| 可验证 Reject | ≥ 10 |

停止条件：单来源 40 条候选里 A 类 < 10，停该来源；两个工作日后 A 类仍不足
50-100 条门槛时，先按分层口径诚实报告当前 30 条真实正例的结果。
