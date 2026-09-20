# LLM 辅助漏洞审计系统 —— 推进计划 v2（半扩 · 7 天 · 云微调 · CV/PS 导向）

> 基于 v1（密码专项）+ 你的两个决定：**① 范围半扩：产品保留密码骨架，微调实验的数据主体改用现有 Python 漏洞数据集，另留 ~150 条密码样本做领域对照；② 微调走云 API。**
>
> - `[决策]` = 需要你拍板处，均已给推荐默认值。
> - 本文档是 v2；「附」一节有 v1 → v2 的改动对照。

---

## 0. 一句话定位（v2）

> 一个 **Semgrep（密码规则）+ 云微调 Qwen3-4B + Agent** 的 Python 代码漏洞审计 Pipeline：先在**公共 Python 漏洞数据**（SeCodePLT / CVEfixes 子集）上做 QLoRA 领域适配，验证微调对**通用漏洞检测与 CWE 分流**的提升；再在**密码误用领域切片**上验证迁移与 Agent 误报过滤，端到端产出结构化安全报告。

**为什么半扩而不是全扩**：全扩需要重写整套通用规则和产品，7 天风险高；维持密码专项则微调数据只能手造、规模小。半扩让你**复用现有代码 + 拿到千级干净数据 + 讲"模型×领域工具×工作流"的完整故事**。

---

## 1. 研究问题与可验证假设（v2）

核心问题不变，评估改为**双切片**（通用检测 / 领域分流，见 §7）：

| 编号 | 假设 | 切片 | 判定标准 |
|---|---|---|---|
| H1 | QLoRA 提升 CWE/严重度判断 | 通用 + 领域 | 测试集 CWE Acc 提升 >5 点 |
| H2 | Agent 降低误报且不损检出 | 领域（Semgrep 候选） | FPR 降 ≥20%，Recall 降 <5% |
| H3 | 静态信息提升 LLM 理解 | 领域 | 有 static finding 时解释质量更高 |
| **H4** | **公共数据微调迁移到密码领域** | 领域 vs 通用 | 领域切片相对 base 有增益（微调不是只对训练域有效） |

> v1 的 H4（合成→真实）仍在真实项目验证中保留，但主角换成「公共→领域」的迁移问题。

---

## 2. 系统架构（v2，仅标注变化）

```
用户提交 Python 代码
   │
   ▼
Semgrep（自有 10 条密码规则 + 可选社区安全规则包）
   │  Candidate Findings（仅领域切片存在；通用切片上≈空）
   ▼
LLM Agent（云 API：Base / Fine-tuned）
   │  · 通用切片：函数级「是否漏洞 + CWE + 严重度」
   │  · 领域切片：finding 级分流（Confirm/Reject）+ 修复
   ▼
结构化 JSON → Markdown 报告
```

- **Semgrep 的双重角色**：产品里是密码候选生成器；通用切片上它几乎不命中（如实记录，作近零基线）。
- **可选增强**：给通用切片加一条 `Semgrep 社区安全包（p/python / p/owasp-top-ten）` 作为 Static baseline，**零新增规则开发量**，[决策] D19。
- Agent / parser / report 等模块 v1 不变，继续沿用。

---

## 3. 数据策略 v2

### 3.1 KernJC 判定（一句话）
不采用。[KernJC](https://arxiv.org/abs/2404.11107) 是 **Linux 内核漏洞环境生成工具**（C、内核级、带 Kconfig/PoC），不是代码级训练数据；方向贴近利用复现，与防御性审计边界不符。

### 3.2 三层数据

| 层 | 来源 | 数量 | 用途 | 许可 |
|---|---|---|---|---|
| **L1 公共数据（微调主料）** | [SeCodePLT](https://arxiv.org/abs/2410.11096)（NeurIPS'25，Python 子集）为主；时间富余再自筛 CVEfixes Python 子集 | 数千级（训练取 Python 子集） | QLoRA 训练 + 通用切片评估 | **SeCodePLT CC-BY-4.0**（干净可分发）；CVEfixes 逐 repo 核对 |
| **L2 密码领域对照** | 手写底样 + LLM 辅助 + 模板变换，**经自有规则回测** | ~100-150 | 领域切片（产品演示 + Agent 评估） | 自产，无顾虑 |
| **L3 真实项目** | 3~5 个 Python 密码项目（MIT/Apache），固定 commit | 每条可溯源 | 端到端验证 | 记录 license |

### 3.3 标签形态对齐（关键工程点）
公共数据集给的是「函数是否含漏洞 + CWE」，**没有 finding 文本/修复建议**，和现有 `prepare_sft_data` 的 `finding` 字段不匹配。改动：

- **通用切片训练对**：`user: 仅代码` → `assistant: {vulnerable, cwe, severity, confidence, explanation}`，无 static finding。
- **领域切片训练对**：`user: 代码 + static finding` → `assistant: {cwe, severity, verdict, explanation, patch}`（v1 格式）。
- 一个模型同时学两种输入→输出，Prompt 里显式区分任务类型（`task: detect` / `task: triage`）。

### 3.4 统一 schema（v2）

```json
{
  "id": "seccodeplt-00341",
  "language": "python",
  "task": "detect | triage",
  "code": "……",
  "finding": "（triage 必填；detect 省略）",
  "label": {
    "vulnerable": true,
    "cwe": "CWE-079",
    "severity": "HIGH",
    "explanation": "……",
    "recommendation": "……",
    "patch": "……"
  },
  "source": "seccodeplt | cvefixes | synthetic",
  "license": "CC-BY-4.0 | repo-license",
  "repo_url": "…", "commit": "…",
  "verified": false, "split": ""
}
```

### 3.5 防泄漏
- 按规范化哈希去重；同一 repo/来源归入同一 split；公共数据集优先用其**官方划分**。
- 领域样本单独成 slice，不与公共训练数据混在同一评测里（避免概念混淆）。

---

## 4. 里程碑总览（7 天）

| 天 | 阶段 | 目标 | 关键产出 |
|---|---|---|---|
| D1 | P0 + 数据底座 | 仓库环境、**下载并核验 SeCodePLT Python 子集**、CWE 库 | repo、`data/raw/seccodeplt/`、schema |
| D2 | P1a 公共数据处理 | 抽取→去重→平衡→转换 detect 格式；**改造 prepare_sft_data 支持 task 两种格式** | `train/val/test.jsonl`（detect） |
| D3 | P1b 领域对照 | ~120 条密码样本 + 规则回测 + triage 格式 | 领域 slice（`domain_eval.jsonl`） |
| D4 | 云微调启动 + 全链路 | **上午提交微调任务**（detect 数据为主，含少量领域）；下午接 Base 推理 | 训练任务后台跑；pipeline 通 |
| D5 | Base baseline | Base LLM 在双切片上出 baseline | benchmark 框架 + 首张指标表 |
| D6 | Agent + 切换微调模型 | Agent 分流 + 反谄媚；**切 FT 模型**重跑 | Base vs FT 对比表 |
| D7 | 真实验证 + 打包 | 3~5 仓库端到端；五系统对比；README/Demo/报告 | 对比表 + CV 材料 |

> 7 天=全职；非全职顺延到 10-14 天。微调 D4 提交后**后台跑**，不阻塞主线。

---

## 5. 分阶段任务清单（v2，数据相关为重写，其余沿用 v1）

### P0 · 工程骨架（D1 上午）
- [ ] Git 仓库（私有）+ 目录 + `requirements.txt` + `main.py` 已有骨架核对
- [ ] **下载 SeCodePLT**（HF 或官方源），核验 Python 子集字段结构、条数、许可文件
- [ ] CWE 库补齐 9 个重点 + 按公共数据实际 CWE 分布扩展（用 `cwe_lookup()` 服务 prompt/RAG）
- [ ] 若选 CVEfixes 备胎：D1 先确认其 Python 子集数据量再定是否纳入（[决策] D16）

### P1a · 公共数据处理（D2）
- [ ] `scripts/import_public_dataset.py`：下载/读取 → 过滤 Python → 抽样平衡（vulnerable 少，做下采样/保留全部 vulnerable）
- [ ] 去重（AST 归一化哈希）→ 统一 schema（v2）→ 转换 detect 训练对
- [ ] `scripts/validate_dataset.py`：schema 校验 + 重复检测 + 标签一致性抽查
- [ ] 划分：优先用官方 split；否则按 repo 分组切
- [ ] **改造 `prepare_sft_data.py`**：支持 `task` 两种消息模板，`finding` 可选

### P1b · 密码领域对照（D3）
- [ ] 复用 v1 计划：每类密码误用 vulnerable/secure 对 + 修复建议
- [ ] **全部经自有 Semgrep 规则回测**（vulnerable 必命中 / secure 必不命中）
- [ ] 人工抽检标签与修复（MD5→Argon2id 之类不能机械替换）
- [ ] 汇总 ~120 条 → `domain_eval.jsonl`（不用于训练主体，[决策] 是否少量混入训练留你定）

### P2 · 全链路 + Base baseline（D4 下~D5）
- [ ] semgrep_runner / parser / report_generator 沿用 v1
- [ ] `inference.py` 接云 API，支持 `detect`/`triage` 两种调用
- [ ] `benchmark.py`：双切片指标表（§7）
- [ ] 跑 Base LLM 在双切片上的 baseline

### P3 · 云微调（D4 启动）
- [ ] 数据：detect 主料（公共数据）+ 少量领域 triage 样本混入（比例 [决策] D18，默认 ≤20%）
- [ ] 平台：阿里云百炼 / 魔搭（D1 验证 Qwen3-4B 可用性；无则走 v1 的 D14 兜底链）
- [ ] 记录：数据集构成 / token 数 / 超参 / loss / 成本 / 耗时 → 技术报告数据点
- [ ] 训练完成后部署，D6 切换对比

### P4 · Agent（D6）
- [ ] ReAct + 工具（semgrep / AST / rule_db / cwe_db / patch）
- [ ] 反谄媚 Prompt（要求证据、倾向 Reject 测试/mock/非敏感）
- [ ] triage 指标（GT-FP 正确拒绝率 / GT-TP 保留率）
- [ ] **注意**：detect 模式下 Agent 用于"二次复核 + 补 CWE"；triage 模式下用于误报过滤——两种模式指标分开记

### P5 · 真实项目（D7）
- [ ] 3~5 个 Python 密码项目端到端；TP/FP/FN/CWE Acc；对照 H4（公共→领域迁移 + 真实泛化）

### P6 · 打包（D7 下）
- [ ] docs / reports 归档 / README / Demo 视频 / 技术报告 / CV 描述（实验后填数字）

---

## 6. 决策日志（v2，新增/变更标 ⭐）

| 编号 | 决策项 | 决定/默认 | 备注 |
|---|---|---|---|
| ⭐D16 | 公共数据源 | **PyCode-Vul（Python，经自有 Semgrep 规则回测自证）**（主）；CVEfixes Python（备，视时间/数据量） | SeCodePLT 官方 Python 子集已核验损坏（实为 C/C++ 行），弃用 |
| ⭐D17 | 评估切片 | **双切片**：通用（公共测试集）+ 领域（密码 domain_eval） | 指标分开报 |
| ⭐D18 | 领域样本入训练比例 | ≤20% | 太高会稀释公共泛化 |
| ⭐D19 | 通用切片 Static baseline | Semgrep 社区安全包（p/python 等） | 零规则开发量，可选 |
| D1 | 基础模型 | Qwen3-4B（平台缺则走 D14） | |
| D2 | 思考模式 | 结构化输出关 thinking | JSON 可解析 |
| D3 | 推理 | 云 API | 本地无 GPU |
| D4 | Agent | 手写 ReAct | |
| D6 | v1 语言 | 仅 Python | |
| D11 | 节奏 | 7 天（全职） | |
| D14 | 平台无 Qwen3-4B | 换平台→同族模型→租 GPU | |
| ⭐D20 | 规则工程形态 | 10 条 CRYPTO 规则**逐条自测（semgrep --test 10/10 通过）** + demo 文件端到端出报告 | 学习用：只保证流程跑通 + 小测试，不做工业级 precision |
| ⭐D21 | T1 标签语义 | **verified=True = "自有规则命中"（semgrep 证据），非人工确认** | 语义措辞必须诚实，不冒充 ground truth |
| ⭐D22 | 规则命中×代码场景 | 生产代码命中→正样本/triage Confirm；**test/夹具代码命中→triage Reject 对照**，排除出 detect 正样本 | test 里 md5/sha1 多为夹具算 hash，非安全缺陷 |
| ⭐D23 | Agent 分期 | v0=单步推理+fixture guard；ReAct 工具环放 FT 模型就位后的 P4 对比阶段 | 工程线先跑通可测，模型线再上复杂度 |

---

## 6.1 数据产出快照（PyCode-Vul 导入，D2 落地）

源：HuggingFace `S-AIR-L/PyCode-Vul`（cc-by-4.0，Zenodo DOI 19746552），官方 train/test 两个 CSV 天然分集。`cwe_ids/cve_ids` 全 UNKNOWN → 只能靠规则回测自证 + predicted（noisy）分层。产出于 `data/splits/`（`validate_dataset.py` 全绿、跨集零泄漏）：

| 文件 | 条数 | 说明 |
|---|---|---|
| `detect_train.jsonl` | 2406 | 1413 vuln / 993 secure（15 仓库，官方 train 集） |
| `detect_val.jsonl` | 272 | 按 repo 分层切 10%（seed 0） |
| `detect_test.jsonl` | 569 | 305 vuln / 264 secure（官方 test 集，已剔除与 train 重复文本） |
| `triage_train.jsonl` | 132 | 61 Confirm（生产误用）+ 71 Reject（test/夹具 FP），真实代码+真实规则 finding |
| `domain_eval.jsonl` | 29 | 14 Confirm / 15 Reject —— 非泄漏领域控制切片（held-out） |

通用切片主要 CWE：CWE-89 / CWE-327 / CWE-79 / CWE-330 / CWE-259。微调主料仍待：CWE 描述增强、detect 负样本补平衡（可选）、QA/格式对齐（`prepare_sft_data.py` 已改造并 4 文件零错转换）。

## 6.2 工程线落地快照（Agent / inference / benchmark）

- `model/prompts.py`：detect/triage 模板**单一来源**，`prepare_sft_data.py` 与 inference 共用 → 微调与评估分布一致（改造后 SFT 输出逐字节不变已核验）。
- `model/inference.py`：`get_backend(kind)` 工厂 → `CloudBackend`（OpenAI 兼容 HTTP，无 key 构造即报错）｜`MockBackend`（确定性启发式，CI/无凭证自测）。
- `agent/agent.py`：`SecurityAgent` v0 = 单步推理 + fixture guard（不自动 Confirm test/夹具代码）；ReAct 工具环（semgrep/rule_db/cwe_db/patch）留待 P4 下一阶段（[决策] D23）。产品路径 `main.py -i <file>` 现产出真实 verdict（CONFIRMED/REJECTED）。
- `evaluation/benchmark.py` + `configs/benchmark.yaml`：双切片×系统（static/llm/agent）runner。`python main.py --benchmark --config configs/benchmark.yaml` 自测基线：

| detect (n=569) | recall | precision | f1 | cwe_acc |
|---|---|---|---|---|
| static(规则) | 0.112 | 1.000 | 0.201 | 0.324 |
| llm(mock) | 0.364 | 0.561 | 0.441 | 0.288 |

| domain (n=29) | confirm_recall | fpr | acc |
|---|---|---|---|
| static(全收) | 1.000 | 1.000 | 0.483 |
| llm(mock) | 1.000 | 0.067 | 0.966 |
| agent(mock) | 1.000 | 0.067 | 0.966 |

> mock 领域切片表现"过好"是因为 mock 的 test/非 test 判定与构造 GT 用的信号同源 —— 属占位性质，真实结论以 FT 模型上线后为准（届时只改 `configs/benchmark.yaml` 的 `model.kind/model_id`）。

---

## 7. 评估协议 v2（双切片）

**切片定义**
- **通用切片**：公共数据官方测试集（函数级），GT = vulnerable? + CWE。指标：Detection Recall / Precision / F1 / CWE Acc（macro）。
- **领域切片**：`domain_eval.jsonl`（密码误用，Semgrep 候选级）。指标：Semgrep 候选经 Agent 后的 FP Triage、报告解释质量盲评（表见 v1 §6.3）。

**五系统 × 双切片**

| 系统 | 通用（Detection/F1） | 通用 CWE Acc | 领域 Recall | 领域 FPR | 领域 CWE Acc |
|---|---|---|---|---|---|
| ① Static only | | | | | |
| ② Base LLM | | | | | |
| ③ Static + Base | | | | | |
| ④ Static + FT | | | | | |
| ⑤ 全 Agent | | | | | |

> 领域切片上 ① 是所有密码样本都该命中（回测保证），意义在对比 ③④⑤ 相对 ①② 的增益。通用切片上 ① 接近空，如实呈现。

**其余沿用 v1**：盲评 0/1/2 表、防泄漏（仓库分组+哈希）、seed/解码参数固定。

---

## 8. 风险登记（v2 增补）

| 风险 | 影响 | 缓解 |
|---|---|---|
| **SeCodePLT Python 子集量或粒度不符预期** | 中 | D1 先核验；量不足则启用 CVEfixes 备胎；粒度是文件级就加函数切分 |
| **公共数据标签噪声（检测基准常见问题）** | 中 | 用质量最高的官方划分；抽检 5% 人工核对 |
| **许可/再分发** | 中 | SeCodePLT CC-BY 安全；CVEfixes/BigVul 只本地训练，repo 不 commit 代码，只记来源 |
| **detect/triage 双格式混训令 4B 学乱** | 中 | prompt 显式 `task` 标记；必要时分两轮微调对比（先 detect 后 triage） |
| 云平台缺模型/任务失败/成本 | 中高 | 沿用 v1 兜底链 + 上限 |
| Agent 谄媚 | 高 | 沿用反谄媚 + 已知 FP 测试 |
| 防泄漏不到位 | 高 | 沿用仓库分组 + 哈希；公共数据用官方 split |
| 7 天排满 | 中 | 裁剪优先级：P1a > P2 > P4 > P3 > P5 |

---

## 9. 环境与复现

- 沿用 v1（`python 3.10+`、固定版本、seed、`.gitignore` 不跟踪代码数据，只跟踪脚本+metadata）。
- 新增：`scripts/import_public_dataset.py` 一键下载+筛选（记录版本/日期/哈希）；SeCodePLT 许可文件入库 `data/raw/seccodeplt/LICENSE`。

---

## 10. 产出与 CV/PS 材料包（v2）

**工程产出**
- [ ] 双切片 benchmark 表（五系统）
- [ ] Base vs FT 对比（云端微调记录：配置/loss/成本）
- [ ] 公共数据导入脚本 + 数据卡（`docs/dataset.md`：来源/许可/构成/防泄漏）
- [ ] 全链路报告 + 3~5 份真实项目报告 + Demo

**CV 描述模板（实验后填数字）**
> LLM-Assisted Python Vulnerability Auditor
> - Fine-tuned Qwen3-4B (QLoRA) on {N} Python vulnerability samples from {dataset} + curated crypto-misuse set; built a Semgrep + LLM-agent pipeline for detection, CWE classification, and false-positive triage.
> - Achieved {X}% detection F1 / CWE accuracy on a public test split; agent reduced false positives by {Y}% on crypto-misuse candidates.

**PS 叙事**：传统审计依赖人工专家 → 追问 LLM 能否分担 → 用公共漏洞数据做领域适配 + 工具增强 → 结论：价值在「模型×领域工具×真实工作流」结合。

---

## 11. 现在就开始的 5 件事（D1）

1. 核实现有 `main.py`/rules/agent 骨架与 v2 目标差异（agent/inference/benchmark 仍是桩，先不阻塞数据）。
2. **下载并核验 SeCodePLT Python 子集**（字段、条数、许可、粒度）。
3. 写 `import_public_dataset.py`（读取→过滤→平衡→去重）。
4. 改造 `prepare_sft_data.py` 支持 detect/triage 双任务。
5. 决定 CVEfixes 备胎是否启用（核 Python 数据量后）。

> 数据链路 D1-D2 先跑通 = 项目的最大不确定性和最大工作量，优先攻坚。

---

## 附：v1 → v2 改动对照

| 项 | v1 | v2 |
|---|---|---|
| 范围 | 密码专项 | 半扩：密码产品 + 公共数据微调 + 领域对照 |
| 微调数据 | 手造密码合成 300+ | 公共 Python 漏洞数据为主（SeCodePLT 等）+ ≤20% 领域 |
| 训练格式 | 单任务（代码+finding→报告） | 双任务 detect/triage，`finding` 可选 |
| 评估 | 单一切片 | 双切片（通用检测 / 领域分流） |
| 研究重点 | 领域适配 vs base | + 公共→领域的迁移性（H4） |
| 数据许可 | 自产无忧 | SeCodePLT CC-BY-4.0；他源只记来源不分发 |
