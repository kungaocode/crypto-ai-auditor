# Round-6 最终评测报告（Final Test Set + Model Capability）

> 日期：2026-10-05
> 部署模型：`qwen3-4b-instruct-2507-5f8261ad123d`（百炼「第六轮密码微调结果」，状态 RUNNING）
> 评测命令：`scripts/run_round6_eval.py`、`scripts/run_round6_test_split.py`、`scripts/run_round6_capability.py`

---

## 一、被测模型

| 项 | 值 |
|---|---|
| 部署模型 ID | `qwen3-4b-instruct-2507-5f8261ad123d` |
| 微调任务 | `ft-202610051556-cc87`（第六轮密码微调） |
| 微调输出模型 | `qwen3-4b-instruct-2507-ft-202610051556-cc87` |
| 基座 | `qwen3-4b-instruct-2507`（新鲜基座，全量合并重训） |
| 工作空间 | `ws-avxkjb2tq5lq1gwm` |
| 训练超参（平台回报） | LoRA rank=16 / alpha=32 / dropout=0.005；lr=1e-4；epochs=3；batch=128；max_len=4096；cosine |

> 数据集：R5 基座 + R6 新增 401 条全量合并重训（`train=3115 / val=347 / test=660`，
> 共 4122 条），其中 `verified=true` 真实记录 79 条、真实 crypto 正例 30 条。
> 推理路径与部署一致（triage 追加 `TRIAGE_PURPOSE_GUIDE`）。

---

## 二、总览（四套评测）

| 套件 | 样本量 | 关键结果 |
|---|---|---|
| ① 冻结留出集 detect | 19（漏洞 7 / 安全 12） | recall 0.714 / precision 0.500 / f1 0.588 / cwe_acc 0.400 |
| ① 冻结留出集 triage | 36（Confirm 4 / Reject 32） | confirm_recall 1.000 / **fpr 0.125** / acc 0.889 |
| ② 18 条真实探针 | 18（Confirm 12 / Reject 6） | **accuracy 0.667** / confirm_recall 0.500 / fpr 0.000 |
| ③ 第六轮设计测试集 test.jsonl detect | 602（漏洞 325 / 安全 277） | recall 0.859 / precision 0.550 / f1 0.671 / cwe_acc 0.724 |
| ③ 第六轮设计测试集 test.jsonl triage | 58（Confirm 28 / Reject 30） | **confirm_recall 0.571** / **fpr 0.200** / acc 0.690 |
| ④ 能力矩阵（13 规则） | 26（13 漏洞 + 13 安全） | 漏洞检出 11/13 / CWE 正确 6/13 / 安全不误报 10/13 |
| ④ 安全库抗误报 | 10 | 不误报 8/10（**fpr 0.20**） |

---

## 三、① 冻结留出集（`validation_frozen/`，去泄漏的干净评测）

### 3.1 Detect 切片（n=19，漏洞 7 / 安全 12）

| 系统 | recall | precision | f1 | accuracy | cwe_acc | tp/fp/fn/tn |
|---|---|---|---|---|---|---|
| llm（R6 微调） | 0.714 | 0.500 | 0.588 | 0.632 | 0.400 | 5/5/2/7 |
| static（Semgrep） | 0.000 | 0.000 | 0.000 | 0.526 | — | 0/2/7/10 |

| # | 样本 | GT | Pred | CWE(Pred) | 判定 |
|---|---|---|---|---|---|
| 1 | `round4-real-detect-itsdangerous-SigningAlgorithm_verify_signature` | 安全 | 安全 | — | ✓ |
| 2 | `round4-real-detect-passlib-Pbkdf2DigestHandler__calc_checksum` | 安全 | 安全 | — | ✓ |
| 3 | `round4-real-detect-passlib-_BcryptBackend__calc_checksum` | 安全 | 安全 | — | ✓ |
| 4 | `round4-real-detect-python-rsa-encrypt` | 安全 | 漏洞 | CWE-327 | ✗ |
| 5 | `round4-real-detect-pyjwt-HMACAlgorithm_sign` | 安全 | 安全 | — | ✓ |
| 6 | `round4-real-detect-pycryptodome-scrypt` | 安全 | 漏洞 | CWE-327 | ✗ |
| 7 | `round4-real-detect-pycryptodome-GcmMode_encrypt` | 安全 | 漏洞 | CWE-327 | ✗ |
| 8 | `r5v-011-pos` | 漏洞 (CWE-256) | 漏洞 | CWE-259 | ✓(CWE✗) |
| 9 | `r5v-012-pos` | 漏洞 (CWE-916) | 安全 | — | ✗ |
| 10 | `r5v-013-pos` | 漏洞 (CWE-208) | 漏洞 | CWE-208 | ✓ |
| 11 | `r5v-011-aneg` | 安全 | 漏洞 | CWE-259 | ✗ |
| 12 | `r5v-012-aneg` | 安全 | 安全 | — | ✓ |
| 13 | `r5v-013-aneg` | 安全 | 安全 | — | ✓ |
| 14 | `r6-pos-static-iv-cbc` | 漏洞 (CWE-329) | 漏洞 | CWE-329 | ✓ |
| 15 | `r6-pos-nonce-reuse-gcm` | 漏洞 (CWE-329) | 漏洞 | CWE-327 | ✓(CWE✗) |
| 16 | `r6-pos-hardcoded-aes-key` | 漏洞 (CWE-321) | 漏洞 | CWE-327 | ✓(CWE✗) |
| 17 | `r6-pos-weak-random-session` | 漏洞 (CWE-338) | 安全 | — | ✗ |
| 18 | `r6-ecdsa-sign` | 安全 | 安全 | — | ✓ |
| 19 | `r6-bneg-rc4-legacy-protocol-handler` | 安全 | 漏洞 | CWE-327 | ✗ |

> 说明：static（Semgrep）在本切片的 7 个正例上全部漏报（`tp=0`），因为这些手写最小片段
> 不匹配自定义规则的 pattern scope；这不是本报告重点，仅作参照。

### 3.2 Triage（domain）切片（n=36，Confirm 4 / Reject 32）

| 系统 | confirm_recall | fpr | accuracy |
|---|---|---|---|
| llm（R6 微调） | 1.000 | 0.125 | 0.889 |
| static（accept-all，系统①） | 1.000 | 1.000 | — |

误报 4 条（GT-Reject → Confirm）：
`Crypto_IO__PBES__PBES2_encrypt`、`passlib_cisco_pix`、`passlib_sun_md5_crypt`、`r5v-011-tneg`。
4 条 GT-Confirm 全部命中。

> `confirm_recall` 仅基于 4 条 GT-Confirm，**只有计数意义，不做统计验收**。

---

## 四、② 模型能力测试（18 条真实探针）

| 指标 | 值 |
|---|---|
| n | 18（GT-Confirm 12 / GT-Reject 6） |
| confirm_recall | 0.500 |
| fpr | 0.000 |
| accuracy | 0.667 |

| # | GT | Pred | 样本首行 | 判定 |
|---|---|---|---|---|
| 0 | Confirm | Confirm | `def register(username, password):` | ✓ |
| 1 | Confirm | Confirm | `def set_password(user, raw):` | ✓ |
| 2 | Confirm | Reject | `def login(user, pw):`（MD5 口令比对） | ✗ |
| 3 | Confirm | Confirm | `from Crypto.Cipher import AES`（ECB） | ✓ |
| 4 | Confirm | Reject | `from Crypto.Cipher import AES`（CBC 零 IV） | ✗ |
| 5 | Confirm | Confirm | `from Crypto.Cipher import AES` | ✓ |
| 6 | Confirm | Confirm | `import requests`（verify=False） | ✓ |
| 7 | Confirm | Confirm | `from Crypto.PublicKey import RSA`（1024） | ✓ |
| 8 | Confirm | Reject | `import random, string`（弱随机 token） | ✗ |
| 9 | Confirm | Reject | `from Crypto.Cipher import DES` | ✗ |
| 10 | Confirm | Reject | `from Crypto.Cipher import ARC4` | ✗ |
| 11 | Confirm | Reject | `def make_api_signature(secret, body):`（MD5 签名） | ✗ |
| 12–17 | Reject | Reject | 测试夹具 / 变更检测 / 缓存 / 分片 / jitter | ✓（6/6） |

**关键发现（错分的 6 条 Confirm）：**

1. **裁决与解释自相矛盾（3 条）**：#2、#8、#11 的 `explanation` 推理结论是
   `-> Confirm`（"protects a credential / real secret / a security purpose"），
   但 `verdict` 字段输出 `Reject`。原始输出示例（#2）：
   ```json
   {"cwe":"CWE-327","severity":"WARNING","verdict":"Reject",
    "explanation":"...the stored hash is used to authenticate the user, so this protects a credential -> Confirm."}
   ```
2. **幻觉出不存在的不安全语境（3 条）**：#4、#9、#10 把纯加密函数解释成
   "encrypts a cache key / test fixture generates an ETag / cache coherence"，
   而代码里根本没有缓存或测试语境 —— 模型把 Reject 类的目的推理模板错误套到真实漏洞上。

---

## 五、③ 第六轮设计测试集（`final/upload/full/test.jsonl`，n=660）

### 5.1 Detect（n=602，漏洞 325 / 安全 277）

| 指标 | 值 |
|---|---|
| recall | 0.859（279/325） |
| precision | 0.550（279/507） |
| f1 | 0.671 |
| accuracy | 0.545 |
| cwe_acc | 0.724 |
| tp / fp / fn / tn | 279 / 228 / 46 / 49 |

### 5.2 Triage（n=58，Confirm 28 / Reject 30）

| 指标 | 值 |
|---|---|
| confirm_recall | 0.571（16/28） |
| fpr | 0.200（6/30） |
| accuracy | 0.690 |

> 逐条预测见 `test_split_r6.json`（`detect_rows` / `triage_rows`）。
> 注意：该测试集是训练留出 split，与训练分布同源；其中 detect 的 GT 标签含
> 较多 PyCode-Vul 模型预测噪声（例如非加密 Django 函数被标 `CWE-326` 漏洞），
> 因此 detect 的二元/ CWE 指标只能作为相对参照，不能当作真实 crypto 泛化能力。

---

## 六、④ 额外能力测试（手写确定性探针）

### 6.1 13 规则 detect 矩阵（每规则 1 漏洞 + 1 安全）

| 指标 | 值 |
|---|---|
| 漏洞检出 | 11 / 13 |
| CWE 正确 | 6 / 13 |
| 安全不误报 | 10 / 13 |

| 规则 | 期望 CWE | 漏洞检出 | Pred CWE | 安全不误报 |
|---|---|---|---|---|
| CRYPTO-001 MD5 | CWE-327 | ✓ | CWE-327 | ✓ |
| CRYPTO-002 SHA-1 | CWE-327 | ✗（漏报） | — | ✓ |
| CRYPTO-003 DES | CWE-327 | ✓ | CWE-327 | ✓ |
| CRYPTO-004 RC4 | CWE-327 | ✓ | CWE-327 | ✓ |
| CRYPTO-005 AES-ECB | CWE-327 | ✓ | CWE-327 | ✓ |
| CRYPTO-006 可预测 IV | CWE-329 | ✓ | CWE-327（CWE✗） | ✓ |
| CRYPTO-007 硬编码密钥 | CWE-321 | ✓ | CWE-327（CWE✗） | ✗（安全写法被误报） |
| CRYPTO-008 弱随机 | CWE-338 | ✗（漏报） | — | ✓ |
| CRYPTO-009 弱密钥长度 | CWE-326 | ✓ | CWE-326 | ✓ |
| CRYPTO-010 不安全 TLS | CWE-326 | ✓ | CWE-326 | ✓ |
| CRYPTO-011 明文密码 | CWE-256 | ✓ | CWE-259（CWE✗） | ✗（`make_password` 被误报） |
| CRYPTO-012 弱 KDF 参数 | CWE-916 | ✓ | CWE-798（CWE✗） | ✗（60 万迭代被误报） |
| CRYPTO-013 时序不安全比较 | CWE-208 | ✓ | CWE-259（CWE✗） | ✓ |

### 6.2 安全库抗误报（10 条安全写法，期望全部 `vulnerable=false`）

| 结果 | 值 |
|---|---|
| 不误报 | 8 / 10（fpr 0.20） |

误报 2 条：
- `cryptography.hazmat...AESGCM(key).encrypt(os.urandom(12), ...)` → 判漏洞 CWE-327
- `nacl.secret.SecretBox(key).encrypt(msg)` → 判漏洞 CWE-327

---

## 七、验收门槛对照

| 门槛 | 目标 | 实测 | 判定 |
|---|---|---|---|
| detect precision | > 0.54（R3/R4 基线） | 冻结 0.500 / 测试集 0.550 | ⚠️ 临界（冻结集不达标） |
| domain fpr | ≤ 0.06（R5 目标） | 冻结 0.125 / 测试集 0.200 | ❌ |
| 18 探针 accuracy | ≥ 0.95 | 0.667 | ❌ |
| domain confirm_recall | 仅报告（n=4，无统计意义） | 冻结 1.000 / 测试集 0.571 | — |

---

## 八、结论与局限

### 结论

1. **detect 从 R5 崩溃中恢复，但未回到 R3/R4 水平。** R5 同配置云跑 detect 曾为
   recall 0.000；R6 冻结集 recall 0.714、测试集 recall 0.859，precision ≈ 0.50–0.55
   与 R3/R4 相当，但 recall 从 ~0.99 降到 ~0.86（不再是"宁可全报"）。f1 0.588（冻结）
   / 0.671（测试集）。
2. **CWE 分类是明显短板。** cwe_acc 冻结 0.400 / 测试集 0.724 / 矩阵 6/13，
   大量正例被折叠成 `CWE-327`、`CWE-259`、`CWE-798`（其中 259/798 不在 R6 规则族
   CWE 集合内），CWE-256/329/321/338/916 常常分错。
3. **triage Confirm 召回是本轮最严重回归。** 18 探针 confirm_recall 0.500、测试集
   0.571（R3 曾为 1.000）；伴随两类病态行为——(a) 解释与 `verdict` 字段自相矛盾
   （3/18），(b) 幻觉出"cache key / ETag / test fixture"等不存在的不安全语境（3/18）。
   fpr 仍高于 0.06 目标（冻结 0.125 / 测试集 0.200 / 安全库 0.20）。
4. **对安全密码库仍会误报。** 冻结 detect 把 python-rsa / scrypt / GCM / RC4-legacy
   等安全用法判为漏洞；安全库探针把 `AESGCM`、`nacl.SecretBox` 判为 CWE-327。

### 可能的根因（假设，未做消融验证）

- R6 数据大量注入 Reject / bneg / neg 样本（库 legacy 格式、测试夹具、缓存/去重/ETag），
  使模型把「非安全用途 → Reject」过度泛化到真实漏洞。
- 训练数据剥离了 `TRIAGE_PURPOSE_GUIDE`，但推理时仍追加；该引导以
  `(a non-security purpose -> Reject)?` 结尾，可能把 `verdict` 字段拉向 Reject，
  造成"解释正确、裁决相反"的自相矛盾。
- detect 负样本覆盖的真实安全库代码仍不足，安全库抗误报（fpr 0.20）未达目标。

### 统计与数据局限

- 冻结集样本很小（detect n=19 / triage n=36），domain 仅 4 条 Confirm，
  `confirm_recall` 无统计意义，只能报计数。
- 真实 crypto 正例当前 30 条（< 50–100 门槛），**本报告不构成对真实 crypto 漏洞
  泛化能力的证据**。
- test.jsonl detect 的 GT 标签含 PyCode-Vul 模型预测噪声，仅作相对参照。

### 证据文件

- `data/round6/eval/benchmark_r6.json` — 冻结集 detect+domain 逐条预测与 static 基线
- `data/round6/eval/triage_probe_results_r6.json` — 18 探针逐条（含 explanation）
- `data/round6/eval/test_split_r6.json` — 660 条测试集逐条预测
- `data/round6/eval/capability_r6.json` — 13 规则矩阵 + 安全库抗误报
- 脚本：`scripts/run_round6_eval.py` / `run_round6_test_split.py` / `run_round6_capability.py`
