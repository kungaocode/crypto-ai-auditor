# 第四轮 —— 负样本微调（安全/不安全决策边界）+ 真实项目验证集

## 为什么要做第四轮

第三轮模型 `qwen3-4b-instruct-2507-f5d4f1aedd8f` 的 detect 层「近乎全报」（见 `data/round3/eval/ACCEPTANCE.md`）：

```
detect.llm : n=569 tp=302 fp=260 fn=3 tn=4  recall=0.990 precision=0.537 f1=0.697
```

二元 `vulnerable` 判定无判别力：562/569 判漏洞，仅 4 真负。根因 = detect 训练负样本全是**非加密的通用 Django 代码**（`cwe: None`），模型从未见过「**安全的加密代码**」。真实管线靠 triage 层兜底（探针 fpr=0、domain fpr=0.067），但 detect 本身没有学出「密码代码里什么是安全的」。

**第四轮目标**：补「非漏洞」负样本，让模型在**加密代码**上学会安全/不安全的决策边界；并用**真实密码实现项目**做留出验证。

---

## 一、负样本（`data/round4/`，detect 任务，vulnerable=false）

两类（判据见 `docs/crypto_vuln_taxonomy.md`）：

| 类 | 定义 | 数量 |
|---|---|---|
| **A 类（安全现代密码）** | 用了正确原语：scrypt/argon2/bcrypt/pbkdf2、AES-GCM+随机 nonce、ChaCha20-Poly1305、SHA-3、HKDF、ECDH、`secrets`/`os.urandom`、RSA-2048、Ed25519、`ssl.create_default_context` | **42** |
| **B 类（弱原语 × 非安全目的）** | MD5/SHA-1/`random` 用在缓存键、去重、分片、变更检测、退避抖动、A/B 分桶、测试夹具、benchmark | **35** |

B 类再细分（回测 `data/round4/backtest_report.jsonl`）：

- **strong-B（31 条）**：规则会命中，模型必须「看穿规则命中 → 非安全目的 → Reject」（如 `backoff_salt = random.uniform(...)` 触发 CRYPTO-008，但只是退避抖动）。
- **weak-B（4 条）**：规则不命中（`random` 无安全命名变量），平凡安全。

### 回测纪律（`python scripts/build_round4_negatives.py --backtest`）

```
77 samples: A-class-rule-hit=0 (must be 0), B-class-no-hit=4 (informational)
  strong-B (rule fires, model must override): 31
  weak-B   (no rule, trivially safe):       4
```

**A 类必须 0 命中**（证明「安全现代密码」不触发任何规则）；**strong-B 命中预期规则**（证明判别器必须越过规则命中去看用途上下文）。

### 知识来源（负样本标注依据）

- `crypto_and_security/*.jsonl`（NIST/FIPS 标准文本，用户新增）—— 抽取了 4 处规范性结论并落地到样本解释与 A 类选型：
  - 口令存储：SP 800-63B「approved salted KDF, preferably a keyed hash」
  - 认证加密：AES-256-GCM 或 **ChaCha20-Poly1305**（→ A036）
  - nonce：AEAD nonce 必须每次加密唯一，但**无需不可预测**（SP 800-77）
  - 会话 id：CSPRNG ≥128 bits（→ A041 `secrets.token_hex(32)`）
  - 哈希：SHA-3 为现行 NIST 标准（→ A037 `sha3_256`）
  - 密钥派生：HKDF / ECDH（→ A038/A039）
- `docs/crypto_vuln_taxonomy.md`（第 0 节：NIST SP 800-131A、SHAttered、Sweet32、Wang 2004、Pearce S&P'22、To Fix or Not to Fix 的「effective false positive」）。

### 比例现状（决定先不扩量）

| | vulnerable | secure | 比例 |
|---|---|---|---|
| 原 detect_train | 1413 | 993 | 59 : 41 |
| **加 77 负样本后** | 1413 | 1070 | **57 : 43** |

用户定调「40:60 或 50:50、真实分布里漏洞反而少」。换算：50:50 需 ~420 负样本，40:60 需 ~1127。**本轮先不追量**——优先 77 条高质量负样本（每条经 Semgrep 回测 + NIST 依据），训后看结果再决定扩/删（见第五节决策点）。

---

## 二、真实项目验证集（`data/round4/real_validation/`）

留出集（`split=test`、`verified=True`），由 5 个真实 Python 密码库 shallow clone（固定 commit）构建：

| 项目 | commit | 许可证 | Semgrep 命中 |
|---|---|---|---|
| itsdangerous | `672971d66a2ef9f85151e53283113f33d642dabd` | BSD-3-Clause | 1（HMAC-SHA1 默认摘要）|
| passlib | `f5f66f567b6bc90397800dae22c14a9423389d12` | BSD-3-Clause | 19（legacy 哈希方案）|
| PyJWT | `30b7ca1afc9013ab9396c890ea98726a7a8311c7` | MIT | 0 |
| python-rsa | `42b0e14ffbeeb9d99d1037e6440a2cc61780e4ea` | Apache-2.0 | 0 |
| pycryptodome | `a1e52c70302a51077e9d6a20a6abc6a04da1b5e6` | BSD-2-Clause | 222（DES/RC4/弱密钥长度）|

> PyJWT、python-rsa 规则命中为 0 —— 本身写得好，只在 detect 子集里贡献安全函数样本。

构建脚本：`python scripts/build_round4_validation.py`（从 `data/round4/real_findings.jsonl` 提取，函数级用 AST 取完整函数体，模块级取 ±12 行上下文窗口，按 (repo,file,function) 去重）。

### 2.1 triage 子集（35 条，全部 verdict=Reject）

**核心论点**：密码库「实现」弱原语（DES/RC4/MD5/SHA-1）不是误用——库必须提供这些原语、密码哈希库必须能验证 legacy 格式。规则命中但应 **Reject**，即「effective false positive」的真实版。

| 类别 | 数量 | 含义 |
|---|---|---|
| legacy-hash-scheme | 11 | passlib 实现 md5_crypt/sha1_crypt/phpass/mysql/oracle/postgres/django 等 legacy 口令格式 |
| test-vector | 18 | pycryptodome SelfTest 复现已知向量 |
| legacy-format | 4 | PBES1/PEM 用 DES/3DES 读 legacy 加密密钥 |
| benchmark | 1 | pct-speedtest 吞吐测试 |
| hmac-legacy-digest | 1 | itsdangerous 默认 HMAC-SHA1（HMAC 不需要抗碰撞）|

规则覆盖：CRYPTO-001(7) / 002(5) / 003(16) / 004(1) / 009(6)。其余 5 条规则（AES-ECB / IV / 硬编码密钥 / 弱随机 / TLS）在这 5 个库里不触发 —— 预期，不是缺口。

### 2.2 detect 子集（7 条，全部 vulnerable=false）

从同 5 个库手工挑的**无争议安全**函数：HMAC `compare_digest` 校验、PBKDF2-HMAC、bcrypt、RSA-OAEP、JWS HMAC 签名、scrypt、AES-GCM。

---

## 三、上传集（`data/round4/upload/`，chatml，与历次同构）

| 文件 | 条数 | 内容 | 用途 |
|---|---|---|---|
| `incr/train.jsonl` | **77** | 仅新增负样本（42 A + 35 B）| **续训**（第三轮模型继续训练做对比）|
| `incr/{val,test}.jsonl` | 0 | —（val 沿用第三轮 `data/round3/upload/val.jsonl`）| |
| `full/train.jsonl` | **2672** | detect 2483（原 2406 + 77 负样本）**+ triage 189**（132+54+3）| **基座重训**（双任务都保留）|
| `full/val.jsonl` | 302 | detect 272 + triage 30 | |
| `full/test.jsonl` | 599 | detect 569 + triage 30 | |

> ⚠️ 全量集必须含 triage（189 条）——若只喂 detect 数据从基座重训，会**遗忘 triage 任务**（第二轮教训的变体）。`--emit` 已保证双任务都在。

生成：`python scripts/build_round4_negatives.py --emit`。

---

## 四、网页端训练（百炼，华北2·北京）

两条都跑、对比（LoRA 三参数 🔒 锁定，其余沿用第三轮）：

| 路线 | 基础模型 | 上传 | 训练方式 |
|---|---|---|---|
| 续训（对比）| `qwen3-4b-instruct-2507-f5d4f1aedd8f`（第三轮）| `incr/train.jsonl`（77 条）| LoRA 续训 |
| 基座重训（主）| `qwen3-4b-instruct-2507` | `expanded/upload/full/{train,val,test}.jsonl`（3315 条）| LoRA 重训 |

### 4.1 锁定项（与第三轮一致，不再动）

| 参数 | 值 |
|---|---|
| 训练方式 | LoRA（QLoRA，4bit 量化）|
| rank / alpha / dropout | 16 / 32 / 0.005 |
| max_length | 2048 |

### 4.2 路线 A：基座重训（主路线，3315 条）

| 参数 | 值 | 理由 |
|---|---|---|
| lr | **1e-4** | 与第三轮一致，便于直接对比「50:50 vs 77」|
| batch_size | 16 | 3315 / 16 ≈ 207 step/epoch |
| epochs | **3** | 3 轮 ≈ 620 step，与第三轮同量级（数据仅 +28%，不加轮）|
| scheduler | cosine | 沿用 |
| warmup | ~5%（平台可设则用，否则默认）| ≈ 31 step 预热 |

> ⚠️ 这一版 detect 正/负里合成样本占 456/643。若训后真实项目 eval 出现「背模板」迹象（对未见代码 FPR 反弹），往回收：降 **2 epoch** 或 **lr 5e-5**。

### 4.3 路线 B：续训（对比路线，77 条）

数据量极小，防遗忘优先，参数刻意「轻」：

| 参数 | 值 | 理由 |
|---|---|---|
| lr | **5e-5**（减半）| 77 条新分布样本用满 lr 会把模型带偏成「一律安全」|
| batch_size | 16（或 8，若平台允许）| 77 / 16 ≈ 5 step/epoch |
| epochs | **2** | ≈ 10 step，一次「轻触」：够验证方向、不至于崩 detect |
| scheduler | cosine | 沿用 |
| max_length | 2048 | 沿用 |

> 续训风险：第二轮证明「只喂增量样本会灾难性遗忘」。本轮负样本是 detect 格式且含大量「安全加密代码」，与第三轮数据分布差异大，续训路线需重点看 detect 是否崩（cwe_acc / f1 回退）。这也是「两条都跑」的原因。

---

## 五、训后验证（判据）与决策点

```bash
export LLM_API_KEY="$(sed -n '2p' api.txt)"
export LLM_MODEL_ID="qwen3-4b-instruct-2507-<新后缀>"
```

**新增：真实项目验证**（本轮核心，测 detect/triage 在真实密码库上的 FPR）

```bash
# 42 条留出集（35 triage 全 Reject + 7 detect 全安全），已配好 config
# 全部 GT 为 Reject/安全，核心指标 = domain fpr -> 0、domain accuracy -> 1.0
sed "s|qwen3-4b$|$LLM_MODEL_ID|" configs/benchmark_real_projects.yaml > /tmp/benchmark.real.yaml
python main.py --benchmark --config /tmp/benchmark.real.yaml
```

**回归：三件套**

```bash
python scripts/run_triage_probes.py --out data/round4/eval/triage_probe_results_r4.json \
    --compare data/round3/eval/triage_probe_results_r3_guided.json   # 18 探针
python main.py --benchmark --config /tmp/benchmark.ft4.yaml           # 569 detect + 29 domain
```

**判据**：

| 判据 | 目标 |
|---|---|
| 真实项目 triage fpr（35 条全 Reject）| **fpr → 0**（≤0.06，最多错 2 条）|
| 真实项目 detect 准确（7 条全安全）| 7/7 vulnerable=false |
| 18 探针 fpr | ≤ 0.167，confirm_recall ≥ 0.917（不回归）|
| detect f1 / cwe_acc | ≥ 0.65 / ≥ 0.75（不回归）|

**决策点（看结果再动）**：

- 若真实项目 fpr 达标且 569 detect 不回归 → 负样本质量够，**不扩量**；可把 triage 层同一「purpose 引导」结论推广。
- 若 detect 仍偏「全报」→ 说明 77 条不够覆盖决策边界 → **扩量到 ~420（50:50）**，优先补 B 类 strong-B（规则命中却非安全的硬样例）。
- 若 detect 反向塌（cwe_acc/f1 掉）→ 是续训遗忘，改用基座重训结果。
- 待补（可选）：detect 任务的「**加密代码漏洞正样本**」（vulnerable=true，如 MD5 口令、AES-ECB 加密真实数据）——本轮先聚焦负样本，正样本是否补留待训后。

---

## 六、50:50 扩量（`scripts/expand_round4_samples.py`）

用户定调「50:50 先跑通」，随后「约减半」。扩量把 detect_train 从 57:43 拉到 **50:50（1563:1563）**：

| 轴 | 原有 | 本次新增 | 合计 |
|---|---|---|---|
| vulnerable（正） | 1413 | **+150 加密正样本** | **1563** |
| secure（负） | 1070（含 77 手写负样本） | **+493 负样本** | **1563** |

> 正样本数由 `--positives` 控制（默认 150，减半后的选择）；负样本数自动推导到 50:50。`--positives 300` 可回到之前的全量扩量（1713:1713）。

### 6.1 加密正样本（+150，vulnerable=true）

组合生成：10 条规则 × 3 模板 × 5 命名 = 150（每规则取前 3 个模板，10 条规则全覆盖）。每条都是真实弱模式用法，**回测必须命中自己的规则**（`positives-not-firing=0`）。CWE 分布：CWE-327(75)/326(30)/329(15)/321(15)/338(15)，severity 沿用既有加密正样本约定 `WARNING`、`confidence=HIGH`、`explanation` = 规则 message。

### 6.2 负样本（+493，vulnerable=false）

| 来源 | 数量 | 说明 |
|---|---|---|
| B 类 strong-B（组合） | 240 | 弱原语 × 非安全目的：md5/sha1(144) + weak-random(48) + des/rc4/ecb benchmark/testvec/obfuscate(48)，全部命中规则、模型须越过 |
| A 类（真实仓库深挖） | 187 | AST 从 5 个 pinned 仓库提取的**真实安全密码函数**（passlib 91 / pycryptodome 90 / itsdangerous 2 / pyjwt 2 / python-rsa 2），弱模式 token 过滤 + 与 held-out 验证集去重 |
| A 类（组合模板） | 66 | 手写 A-pool 前 66 条（scrypt/pbkdf2/aesgcm/chacha20/rsa-oaep/secrets/os.urandom…），必须 0 命中 |

### 6.3 回测纪律（`--backtest`）

```
positives-not-firing = 0   （正样本必须命中自己的规则）
A-class-rule-hit     = 0   （安全样本必须零命中）
strong-B             = 240  （规则命中但安全，模型须越过）
弱-B                 = 0
```

去重：643 条（150 正 + 493 负）id 唯一、code 无完全重复、无模板占位符泄漏。

### 6.4 输出（`data/round4/expanded/`）

| 文件 | 条数 | 内容 |
|---|---|---|
| `positive_source.jsonl` / `negative_source.jsonl` | 150 / 493 | v2 schema 源数据 |
| `backtest_report.jsonl` | 643 | 逐条 Semgrep 命中 |
| `upload/full/train.jsonl` | **3315** | detect 3126（原 2406 + 77 + 150 + 493）**+ triage 189**，基座重训 |
| `upload/full/{val,test}.jsonl` | 302 / 599 | 沿用（detect + triage，未动）|

> 这是 50:50 的**基座重训**上传集，取代第五节「77 负样本」的 `upload/full/train.jsonl`（2672）。续训路线（incr）仍用 77 条做对比，不扩量。
>
> ⚠️ 扩量仍是**合成占多**（150 正 + 306 合成负 vs 187 真实负）。训后若发现「背模板」迹象（detect 对未见过的真实代码 FPR 反弹），优先回退到「77 条高质量」或只保留 187 真实深挖 + 手写。对比实验见下。
