# 真实 Python Crypto 数据源评估与 R6 最终化采集计划

> 本文整合三轮联网模型结果，并只保留能由公开证据、脚本或人工复核闭环
> 支撑的结论。未被直接核验的版本号、记录数、许可证和下载地址均标为
> **待核验**，不能写成项目事实。

> **决策（不再开 R7）**：本轮不单独构建第七轮。真实的 advisory 驱动样本在
> 正式训练前合并进 Round 6，形成 R6 最终化制品；训练开始时冻结 `train/val/test`
> 与来源哈希（`data/round6/final/r6_manifest.json`），之后不得再改。R6 是本项目
> 的最终训练轮次，这样既保留了“先补强再训练”的质量目标，也不制造一个与 R6
> 共存、口径重复的新轮次。

## 1. 决策摘要

当前项目的核心问题不是继续增加同类合成样本，而是缺少：

1. 真实 Python crypto 漏洞正例。
2. 带 advisory、repo、commit、file、function 的修复前后代码对。
3. 能独立于现有训练分布的外部测试集。

R6 最终制品为 4122 条训练/验证/测试记录（3115/347/660）和 19 detect /
36 triage 的冻结评测集。R6 新增 401 条 = 322 条 curated/规则夹具
（`verified=false`）加 79 条 advisory 支撑的 `verified=true` 真实记录
（30 detect + 49 triage，其中 60 条 K3 复核、19 条人工复核）。冻结 triage
仍只有 4 条 Confirm。评测集（`data/round6/validation_frozen/`）必须保持
不变；继续在同一模板上扩样不会解决真实正例缺口。可行性评估见
`reports/data_quality/r6_final_feasibility.md`。

最现实的优先路线是：

```
GitHub Advisory / OSV 类公告
  -> 定位 fix commit / patch reference
  -> 回溯仓库中的 vulnerable 与 fixed 代码
  -> 映射到 CRYPTO-001..013
  -> Semgrep 生成 finding
  -> 人工标记 A/B/C/D
  -> 形成经过验证的 Detect 正例与 Triage Confirm 样本
```

CVEfixes、MoreFixes、ReposVul、CrossVul 用于扩大候选池和交叉验证，
不能替代上述证据链。

## 2. 三份外部结果的整合

### 2.1 第一份结果

主要价值：

- 覆盖面广，列出了 Advisory、CVEfixes、CrossVul、Bandit、Semgrep、
  CodeQL、Juliet、Snyk 等来源。
- 提到了从真实 advisory 和 patch commit 构建正例的方向。

不能直接采用的部分：

- 把 Bandit/Semgrep/CodeQL 测试样例当成可训练的真实漏洞正例。
- 混入了大量非 Python、非 crypto 或非漏洞任务的数据。
- 多个 URL、CVE、版本号和数据量属于未核验推测。

结论：只能作为候选来源清单，不能作为采集事实来源。

### 2.2 第二份结果

主要价值：

- 按“真实漏洞 + 修复链”而不是“数据集名称”分层。
- 正确把 Advisory/OSV 放到最高优先级。
- 明确提出按 CWE、repo、commit 和人工 Confirm/Reject 处理。
- 明确排除 Big-Vul、PrimeVul、DiverseVul 原始 C/C++ 数据与 PyPIBugs。

需要保留的不确定项：

- ReposVul、CrossVul、CleanVul、Patchwork-CVE 的记录数、Python/目标 CWE
  子集和许可证均需逐项核验。
- 公告中的漏洞不一定属于本项目定义的“代码误用”；协议实现缺陷、库内部
  解析器缺陷和依赖漏洞不能自动计入 Confirm。

结论：这是三份结果中最适合作为项目决策基线的一份。

### 2.3 第三份结果

主要价值：

- 给出了“Advisory 文本 + 真实 patch + Semgrep finding”的三元组思路。
- 提到 MoreFixes、PyVul、CrossCommitVuln-Bench 等第二批候选。
- 强调时间切分、仓库切分和外部盲测。

必须降级处理的说法：

| 说法 | 当前处理 |
|---|---|
| MoreFixes 为 CVEfixes 的全面升级、规模最大 | 可作为候选假设，待官方页面和论文核验 |
| MoreFixes 解压后达 8.8 TB | 明显需要重新核验单位、版本和下载文件，暂不采信 |
| PyVul 已发布且含 1157 commit / 2082 函数 | 需核验论文、仓库、数据许可和实际下载文件 |
| CrossCommitVuln-Bench 已可作为外部基准 | 需核验会议、版本、下载地址和任务定义；在此之前不纳入计划 |
| PyPA Advisory 提供完整 workaround/专家解释 | OSV 类记录的字段并不总是包含 workaround，必须逐条检查 |
| Semgrep/AutoGrep 规则可直接生成真值 | 只能生成 finding，不能替代人工 Confirm |
| AutoGrep 的 645 条规则质量可靠 | 自动生成规则需要抽样评测，不能未经核验直接使用 |
| Kaggle OSV 文本适合代码级训练 | 只适合辅助 NLP，不提供足够的代码级 vulnerable/fixed 证据 |
| MoreFixes 默认数据库口令 | 属于部署细节，不写入项目文档，也不作为可复现依据 |

结论：第三份报告的方向正确，但事实密度低于其文字量。只采纳其
MoreFixes、PyVul 候选和三元组流水线，所有量化声明先进入“待核验”表。

## 3. 来源分级与用途

### P0：优先采集

| 来源 | 角色 | 进入项目的条件 |
|---|---|---|
| GitHub Advisory Database / OSV / PyPI 相关公告体系 | 发现真实 Python 包漏洞与修复链接 | 能解析 GitHub/OSV 标识、CWE、包名、受影响版本和 fix reference |
| 对应上游仓库与 fix commit | 生成 vulnerable/fixed 代码对 | 能取得修复前后文件或函数，且来源可固定到 commit |
| CVEfixes / MoreFixes | 扩大真实 CVE 修复候选池 | 实际取得数据库或补丁文件，确认 Python/目标 CWE 字段和许可证 |

要求：公告、commit 和代码三方都能互相证明。仅有 advisory 文本时只能算
B 类候选，不能算已确认正例。

### P0 下载落盘清单

把外部原始数据统一放在仓库的 `data/external/` 下；该目录已在 `.gitignore`
中忽略，避免把大文件或可再分发材料提交进 Git。

| 优先级 | 数据 | 建议落盘位置 | 用途 |
|---|---|---|---|
| 1 | GitHub Advisory Database（官方仓库） | `data/external/advisory-database/` | 本地离线筛选 PyPI advisory、CWE、fix reference |
| 2 | OSV API 导出或按包查询结果 | `data/round6/candidates/osv/` | 补充 advisory 与修复引用 |
| 3 | MoreFixes / CVEfixes 发布制品 | `data/external/MoreFixes/` 或 `data/external/CVEfixes/` | 扩大真实 CVE 修复候选池与交叉验证 |
| 4 | PyVul / ReposVul / CrossVul（核验后） | `data/external/PyVul/` 等 | 候选池、覆盖统计、外部验证 |

最小可执行路径：

```bash
mkdir -p data/external
# 注意：写成单行，不要用行尾反斜杠续行，否则 git 会报 "Too many arguments"
git clone --depth 1 https://github.com/github/advisory-database.git data/external/advisory-database

# 只做结构解析，不会自动把候选写成 verified=true
# 默认按项目关注包清单筛选，输出到 data/round6/candidates/real_crypto_candidates.jsonl
python3 scripts/harvest_real_crypto_candidates.py \
    --advisories data/external/advisory-database/advisories

# 需要更大候选池时（不限包名）：
python3 scripts/harvest_real_crypto_candidates.py \
    --advisories data/external/advisory-database/advisories --all-packages \
    --out data/round6/candidates/real_crypto_candidates_broad.jsonl

# 用 GitHub REST API 取回每个 fix commit 的 .py diff，拆成 vulnerable/fixed 代码对
# 这一步需要联网（沙箱内不可运行），建议先 --dry-run 看会抓哪些
GITHUB_TOKEN=ghp_xxx python3 scripts/fetch_fix_code.py --dry-run
GITHUB_TOKEN=ghp_xxx python3 scripts/fetch_fix_code.py

# 二次筛选：合并 watchlist + broad + enriched，去重并按证据强度分 P1/P2/P3
# 只写 _screen 元数据，永不改动 verified
python3 scripts/screen_real_crypto_candidates.py --emit

# 把 fix commit 抓回完整文件，按 AST 定位最内层函数（比 diff 片段更可用）
GITHUB_TOKEN=ghp_xxx python3 scripts/rebuild_candidate_functions.py --dry-run
GITHUB_TOKEN=ghp_xxx python3 scripts/rebuild_candidate_functions.py

# 补充外部来源（联网）：OSV PyPI 生态全量导出，OSV schema，harvester 可直接读
curl -L -o data/external/osv-PyPI-all.zip \
    https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
mkdir -p data/external/osv-pypi && \
    unzip -o data/external/osv-PyPI-all.zip -d data/external/osv-pypi
```

已实测（可复现）：GHSA advisory-database 38 万条 JSON、OSV-PyPI 2.6 万条 JSON、
PyPA 7721 条 YAML，加 PyCode-Vul CSV，各源 harvester 输出 GHSA 534 / OSV-PyPI
843 / PyPA 706 / PyCode-Vul 389，默认池合并后 2476 条。二次筛选默认还会扫描
`data/` 下兼容的 JSON/JSONL，再适配 242 条本地记录（当前全部来自
`data/round4/real_findings.jsonl`），合并 2718 条、去重后共 1861 条候选，
`verified=false`。来源分布 OSV-PyPI 549 / GHSA 399 / pycode-vul 387 /
PyPA 231 / round4-real-findings 209 / GHSA-OSV 86。需要复现旧的池-only 口径时
加 `--no-local-json`。
`fetch_fix_code.py` / `rebuild_candidate_functions.py` 把 fix commit 拆成
vulnerable/fixed 代码对，仍然只写 `verified=false`，人工复核后才进
`data/round6/real_verified_{detect,triage}.jsonl`。

二次筛选后 P1/P2/P3 = 5/2/1854，人工复核队列只有 7 条。400 条已带代码对、其中
366 条可 `ast.parse`；549 条只有 fix commit 待补代码，703 条既无 commit 也无 repo。
全量 P3 估价 k3(high) ¥975.18 / k2.7-code(high) ¥267.01 超预算，实际只审 331 条
B 类训练量（`..._volume.jsonl`，k2.7-code(high) ≈ ¥53.79，正常 ≈ ¥17.18）；
P1+P2 七条 k3(high) ≈ ¥3.66。完整分步命令见 `data/round6/REAL_DATA_RUNBOOK.md`。

MoreFixes、PyVul、ReposVul、CrossVul 的官方页面、版本、许可证和实际下载大小
在下载前重新打开来源核验；不要依据模型生成的记录数或链接直接采购/下载。

### P1：条件使用

| 来源 | 角色 | 限制 |
|---|---|---|
| ReposVul / CrossVul | Python 与 CWE 候选池 | 先统计 Python × 目标 CWE × paired 代码，再做抽样人工复核 |
| PyVul | 潜在 Python 包漏洞基准 | 仅在论文、仓库、下载和许可核验通过后进入评估 |
| CleanVul / Patchwork-CVE | 候选或 triage 辅助 | 标签来源不是项目的人工真值，不能直接作为 Confirm |
| Bandit / Semgrep / CodeQL 测试夹具 | Reject、规则回归、finding 生成 | 可提供安全写法和告警触发，不提供真实漏洞正例 |
| Snyk / NVD | 元数据补充 | 不作为代码级 vulnerable/fixed 的主要来源 |

### P2：只做外部评估

只有在来源、任务定义和 Python crypto 子集都核验后，才考虑：

- CrossCommitVuln-Bench。
- 其他 2025-2026 新发布的真实漏洞基准。

外部基准必须完全隔离，不允许参与训练、模型选择或提示词调优。

### 排除或仅做 sanity check

| 来源 | 原因 |
|---|---|
| Big-Vul / Devign / PrimeVul 原始版 | C/C++ 为主，不能直接衡量 Python crypto misuse |
| DiverseVul 原始版 | C/C++ 为主，语言错配 |
| PyPIBugs | 真实 Python bug，但不是目标 crypto security vulnerability |
| CyberSecEval / SecurityEval | 任务是模型安全对齐或规则示例，不是真实工程漏洞检测 |
| Juliet / SARD | 合成模式高度规律，只可做管线回归，不能作为真实性能证据 |
| 纯模板合成 crypto 样本 | 现有瓶颈不是数量，继续扩样会加深模板过拟合 |

## 4. 统一判定标准

每个候选先标为 A/B/C/D，再决定能否进入数据文件。

| 等级 | 定义 | 用途 |
|---|---|---|
| A | 真实安全边界受影响，命中目标 CWE/规则，至少有一个公开 advisory 和一个可信 fix commit；人工确认 vulnerable 与 fixed 语义 | 可进入真实 Detect 正例和 Triage Confirm |
| B | 与 crypto 缺陷相关，但安全边界、规则映射、修复语义或代码上下文仍需人工判断 | 进入 triage 候选池，不计入已验证正例 |
| C | 库兼容实现、协议实现、测试向量、依赖版本漏洞、纯解析器/内存缺陷或非安全用途弱原语 | 多数应标 Reject、范围外或排除 |
| D | 语言、任务、CWE 或技术栈不匹配 | 不进入项目 |

A 类必须同时满足：

1. 弱原语或弱参数的输出保护凭据、令牌、密钥、签名、nonce 或真实秘密。
2. 漏洞代码与修复代码可追溯到同一仓库的修复前/后状态。
3. 修复不是单纯升级依赖、增加日志、关闭功能或更新文档。
4. 能映射到 `CRYPTO-001..013` 中的至少一个规则；不能映射时记为范围外。
5. 记录包含人工判定、证据链接和许可证状态。

## 5. 候选记录规范

联网搜索模型只输出候选人，不直接生成最终训练标签。每条候选至少保存：

```json
{
  "candidate_id": "",
  "source": "",
  "advisory_id": "",
  "cve_id": "",
  "package": "",
  "repo_url": "",
  "vuln_commit": "",
  "fix_commit": "",
  "affected_versions": "",
  "fixed_version": "",
  "file_path": "",
  "function_name": "",
  "cwe": "",
  "rule_id": "",
  "code_vuln_url": "",
  "code_fixed_url": "",
  "static_finding": "",
  "preliminary_class": "A",
  "human_verdict": "",
  "verified": false,
  "verified_by": "",
  "license": "",
  "collected_at": "",
  "split": ""
}
```

`code_vuln` 和 `code_fixed` 在核验后再提取，不要接受搜索模型凭记忆重写的
代码。最终数据文件使用项目现有的精选记录 schema，并保留 advisory 与
commit 证据。

## 6. 去重与切分

### 去重键

按以下顺序去重：

1. `advisory_id` / `cve_id`。
2. `repo_url + fix_commit`。
3. `repo_url + file_path + function_name`。
4. vulnerable/fixed 代码的归一化文本 SHA-256。

同一漏洞同时出现在 GHSA、OSV 和 CVEfixes 时只保留一条主记录，其他来源放
在 `cross_references`，不能重复计入样本数。

### 切分

- 先按仓库切分，再按时间切分，不能只随机切 row。
- 同一仓库的多个 CVE 必须进入同一 split。
- 外部测试使用训练截止时间之后的 advisory 和 fix commit。
- 外部测试不得参与阈值选择、few-shot 示例或提示词调优。
- 旧数据集与新采集记录有重叠时，以可追溯的 commit 证据为准。

## 7. 两阶段收尾方案

### 方案 A：快速收尾

适用于无法完成真实数据核验的情况：

1. 不宣称解决了真实 crypto 正例缺口。
2. 保留 R6 全量重训，但把 R6 指标写成内部 curated holdout。
3. 在限制章节明确：322 条基线新增未独立验证，真实正例仅 30 条，
   冻结 triage 仅 4 条 Confirm。
4. 不把 R6 结果包装成真实仓库泛化能力。

这是诚实收尾，但不能满足“真实外部验证”的质量目标。

### 方案 B：1 到 2 天数据补强后统一训练（合并进 R6）

推荐方案。不新建 R7：把人工确认的真实记录写入
`data/round6/real_verified_{detect,triage}.jsonl`，由
`scripts/build_round6_final_dataset.py --emit` 合并进 R6 最终制品，并重新生成
`r6_manifest.json`。冻结评测集 `data/round6/validation_frozen/` 不动，口径与
已有实验保持一致。

#### 第 1 步：采集最多 40 条候选

配额：

| 来源 | 上限 |
|---|---|
| GHSA/OSV/PyPI 类 advisory + fix commit | 20 |
| CVEfixes / MoreFixes | 10 |
| ReposVul / CrossVul | 10 |

不足就写“可用记录不足”，禁止凑数。每条必须有可点击的一手证据。

#### 第 2 步：自动核验

自动检查：

- URL 和 commit 是否存在。
- vulnerable 与 fixed 文件是否来自同一仓库。
- CWE、包名、受影响版本与修复版本是否可由公告或仓库证明。
- 代码能否解析，或能否定位到明确函数。
- 是否存在重复 advisory、重复 commit 或近重复代码。
- 许可证是否允许研究使用，是否能只保存片段而不重新分发大段源码。

自动检查只能把候选标为 `machine_validated=true`，不能自动标为人工
`verified=true`。

#### 第 3 步：人工 A/B/C/D

人工重点判断：

- 漏洞是否属于代码中的 crypto misuse，而不是算法协议或库内部实现缺陷。
- fix 是否真正改变安全属性。
- Semgrep 是否能产生与人工结论一致的 finding。
- 修复前后代码是否仍有可比的函数级上下文。

#### 第 4 步：数据门槛

R6 最终化（进入训练前）至少满足：

- A 类真实正例不少于 20 条。
- 至少来自 10 个不同 advisory/CVE。
- 至少覆盖 10 个不同仓库；仓库多样性不足时不得做仓库级泛化声明。
- 至少覆盖 4 个目标规则族；稀有 CWE 缺失时如实报告，不强制凑数。
- A 类中至少 10 条能在 vulnerable 代码上触发对应 CRYPTO 规则，用于
  Triage Confirm。
- 新增可验证 Reject 不少于 10 条，优先来自真实安全库写法和 C 类。

#### 第 5 步：停止条件

- 一个来源提供 40 条候选后 A 类少于 10 条：停止继续投入该来源。
- 两个工作日后总 A 类少于 20 条：停止数据冲刺，转方案 A 诚实收尾。
- 只有 advisory 文本、没有 fix commit 或代码证据：不能计入 A 类。
- 只能通过搜索模型记忆复述代码：不能计入任何已验证类别。

#### 第 6 步：训练与评测

达到门槛后：

1. 运行 `python3 scripts/build_round6_final_dataset.py --emit`，生成 R6
   train/val/test 与 `r6_manifest.json`（含逐来源与制品 SHA-256）。
2. 从 fresh base 全量训练，禁止增量续训。
3. 冻结评测仍用 `data/round6/validation_frozen/`，它用于观察回归，不是外部测试。
4. 新增的真实 crypto 评测切片在训练期间完全不可见，单独报告。
5. 继续报告 real-library Reject slice、18-probe、detect 和 triage 指标。
6. 在报告中分别写“内部 curated holdout”和“外部真实漏洞评测”。

## 八、R6 最终化验收门槛

现有护栏保持不变：

| gate | criterion |
|---|---|
| detect precision | 不低于 R3/R4 基线 0.54 |
| domain FPR | 不高于 0.06 |
| 18-probe | 至少 17/18 |
| real-library FPR | 不差于 R3/R4 |

R6 新增的真实数据还需单独报告：

| gate | report |
|---|---|
| 真实 Detect 正例召回 | 正确数 / A 类正例数 |
| 真实 Detect 精度 | 正确数 / 所有正预测数 |
| 真实 Triage Confirm recall | 正确 Confirm 数 / 可触发规则的 A 类数 |
| 真实 Triage FPR | 错误 Confirm 数 / 真实 Reject 数 |
| 来源覆盖率 | advisory、repo、CWE/rule 分布 |

样本数低于 20 时，所有比例必须同时给出分子/分母，不能只写百分比。

## 九、联网搜索提示词（用于 R6 补强）

把下面内容直接发给联网搜索模型。目标不是让它推荐“十大数据集”，而是让它
返回可以逐条核验的真实候选。

```text
你是 Python 加密代码漏洞修复证据核验员，不是数据集推荐员。

背景：项目只做 Python 代码中的已知 crypto misuse，目标 CWE 为
321、326、327、329、338、916、208，次要 256、295。需要真实
vulnerable/fixed 代码对，不接受纯 synthetic、规则示例或仅有 CVSS 的公告。

请最多返回 40 条候选，配额是：
- GHSA/OSV/PyPI 类 advisory + fix commit：最多 20 条
- CVEfixes/MoreFixes：最多 10 条
- ReposVul/CrossVul：最多 10 条

不足就写“可用记录不足”，严禁凑数。每条必须给出：
source、advisory_id、CVE、Python 包名、repo_url、vuln_commit、
fix_commit、file_path、function_name、CWE、目标规则、
affected_versions、fixed_version、许可证、一手证据 URL。

同时给出 preliminary_class：
A = 真实代码 crypto misuse，安全边界受影响，修复改变安全属性，证据链完整
B = 相关但语义、规则映射或 patch 仍待人工判断
C = 库兼容实现、协议/解析器缺陷、测试向量、依赖漏洞或非安全用途
D = 语言、任务或 CWE 不匹配

硬性要求：
1. 每条必须有可点击的一手证据；无法核验的字段写 unknown。
2. 不得根据记忆生成代码，只给代码所在文件和 commit 链接。
3. 不得用同一 CVE 的 GHSA/OSV/CVEfixes 记录重复计数。
4. 必须区分“应用代码误用”和“库实现内部缺陷”。
5. 必须说明 fix 是否只是版本升级、文档修改或功能关闭；若是，降为 C。
6. 不确定发布日期、记录数、许可证时明确写“未核验”。
7. 最后给出 A/B/C/D 计数，并列出每个目标 CWE 的候选数。
```

## 十、立即执行清单

```bash
# 1) 采集候选：三个 advisory 源 + PyCode-Vul CSV；二次筛选默认再扫 data/ 下 JSON/JSONL
#    （各源精确命令与可复现数量见 runbook 的"复现命令"块）
python3 scripts/harvest_real_crypto_candidates.py \
    --advisories /path/to/advisory-database/advisories
python3 scripts/harvest_pycode_vul_candidates.py --emit
python3 scripts/screen_real_crypto_candidates.py --emit
#    只复现旧池口径时加 --no-local-json

# 2) 结构校验 + A 类门槛（20 条）
python3 scripts/validate_real_crypto_candidates.py \
    data/round6/candidates/real_crypto_candidates_screened.jsonl --min-a 20

# 3) 浏览器人工逐条复核；confirm/reject 自动写入已验证记录
python3 scripts/annotate_real_crypto.py --open
#    data/round6/real_verified_detect.jsonl
#    data/round6/real_verified_triage.jsonl

# 4) 合并进 R6 并冻结来源/制品哈希
python3 scripts/build_round6_final_dataset.py --emit
python3 scripts/audit_dataset_leakage.py --write-frozen
python3 scripts/build_dataset_metadata.py
```

- [ ] 用第 9 节提示词或 `harvest_real_crypto_candidates.py` 获取最多 40 条候选。
- [ ] 原样保存搜索输出，不把模型复述当作代码证据。
- [ ] 打开每条 advisory 和 commit，提取真实 vulnerable/fixed 片段。
- [ ] 逐条标 A/B/C/D，记录 unknown 和许可证状态。
- [ ] 统计不同 advisory、repo、CWE/rule 数量。
- [ ] A 类达到 20 条后再冻结 R6 并训练；否则停止扩样并转快速收尾。
- [ ] R6 从 fresh base 全量训练，禁止继续在 R5/R6 上增量续训。
- [ ] 训练前核对 `data/round6/final/r6_manifest.json` 的哈希。
- [ ] 同时报告内部冻结集与外部真实漏洞集，不混成一张表。
