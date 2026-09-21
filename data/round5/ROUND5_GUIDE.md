# Round-5 指南：已知口令漏洞形式微调数据（全量合并重训）

> 本轮**只搭建数据与验证切片，不训练**。范围界定：**只学已知漏洞形式 → 已知修复**；
> 「未知形式/组合形式」的泛化识别留作下一个课题（见 §七）。
> 结论先行：`pos-missing=0 / aneg-hit=0 / bneg-no-fire=0`，83 条新样本回测纪律全绿，
> 可与基座 `data/round4/upload/full/` 合并后进入下一轮全量重训。

## 一、R4 遗留硬伤（R5 要治的）

| R4 问题 | 数据 | 数字 | R5 对策 |
|---|---|---|---|
| 三族新规则零训练支撑 | detect 训练集无 CWE-256/916/208 正样本 | 训练后仍按 011/012/013 全不识别 | 新增 20 条正样本（6+7+6 训练 + 1 val），每条必须命中对应规则 |
| 密码库 legacy 全误报 | passlib 11 条 legacy-hash 库实现 | R4 两模型 11/11 全判 Confirm | 11 条移入训练（8 train / 1 val / 2 test），教「库复现 legacy 格式 = 非漏洞」 |
| CRYPTO-011 全报警 | `.password = <任意值>` 都命中 | 连 `=hash_password(pw)` 也报警 | A/B 类负样本 + tneg 教「看语义、不背闹钟」 |
| 合成扩量背题（R4 50:50 判失败） | 456 合成 vs 187 真实 | 全量与三轮持平 | **R5 新样本全部手工 curated，零模板组合扩量** |

## 二、训练策略铁律（不变）

- **全量合并重训**：基座 = `data/round4/upload/full/{train,val,test}.jsonl`（2672 = detect 2483 + triage 189）。
- **严禁增量续训**：R2 / R4-微量 两次灾难性遗忘（recall 0.990→0.584）已证死路。
- 上传集只写 `data/round5/upload/full/`（chatml），基座记录按原样搬运、**不再二次 to_chatml**（已是 chatml，双包装会 KeyError——已在 `emit_upload_sets` 修复）。

## 三、新样本组成（全部手工 curated）

**detect（52 = 46 train + 3 val + 3 test）**

| 类 | 条数 | 定义 | 静态规则预期 |
|---|---|---|---|
| pos | 20（19 train + 1 val） | vulnerable=true，已知弱形式（明文口令 / 弱 KDF / 时序比较） | 命中且只命中自家规则 |
| aneg（A 类） | 16 train | vulnerable=false，现代安全写法（scrypt/argon2/bcrypt-12/PBKDF2-310k/compare_digest…） | 0 命中 |
| bneg（B 类） | 11 train + 3 test | vulnerable=false，弱形式×非安全用途（测试夹具 / 基准 / legacy-verify / 缓存去重 / 分片寻址） | **规则命中但判安全**（教模型透过报警看用途） |

**triage（31 = 25 train + 1 val + 5 test）**

| 类 | 条数 | 说明 |
|---|---|---|
| tneg Reject | 11 train + 3 test | 011 良性赋值/测试夹具、012 测试向量/基准/legacy-verify、013 缓存去重/测试断言 |
| tpos Confirm（带 patch） | 6 train | 同一弱形式但保护真实凭据/密钥 |
| passlib legacy Reject | 11（8 train / 1 val / 2 test） | 真实库代码，legacy 格式例外；2 条留 test 作为 R5 验收的**真正留出证据** |

**合并后上传集**：train 2743 / val 306 / test 607（基座 2672/302/599 + 新增 71/4/8）。
新样本 train 内 triage Reject:Confirm = 19:6，合并基座 189 条后约 100:122，仍偏 Confirm，不会把模型带进「一律 Reject」。

## 四、回测纪律与结果（semgrep 全规则目录）

`python scripts/build_round5_known_forms.py --backtest --emit`（semgrep 需网络/可写 settings，见 REPO README 的提权说明）

```
83 samples | pos-missing=0 aneg-hit=0 multi-rule-pos=0
            bneg-no-fire=0 bneg-other-rule=0 triage-finding-miss=10(全部 passlib，信息性)
```

- triage finding-miss 的 10 条 passlib 是**信息性**的：真实库代码不写字面 `pbkdf2_hmac(…)` 弱调用，
  静态规则本就打不中；triage 训练喂的是 finding 文本，不依赖 snippet 再命中。
- 本轮顺带修的规则缺陷：
  - CRYPTO-012 扩展 bcrypt/scrypt 弱参数时，`pattern-and` 不能嵌在 `pattern-either` 里
    （InvalidRuleSchemaError 会**静默使全部规则失效**，R5 首次回测全 0 命中的根因）；
    合法写法是 `pattern-either: [patterns: [pattern:…, metavariable-comparison:…], …]`。
  - scrypt 关键字参数必须带尾随 `...`：`hashlib.scrypt(..., n=$N, ...)`，
    否则 semgrep 匹配不到 `scrypt(pw, salt=salt, n=1024, …)`（`…, n=$N` 无尾随不命中）。

## 五、验收门槛（训练完成后按此判过/不过）

1. **真实项目 domain fpr ≤ 0.06**：`configs/benchmark_round5.yaml` 跑 `data/round5/validation/triage_eval.jsonl`
   （35 条 R4 真实回归 Reject + 6 条新族探针），GT-Reject→Confirm 比例 ≤ 6%。
2. **passlib legacy 不再全 Confirm**：35 条真实回归中 11 条 passlib——
   R4 是 11/11 Confirm（坏），R5 目标 ≥ 10/11 Reject；其中 2 条在 test 切片是硬留出证据。
3. **CRYPTO-011 良性赋值 Reject**：`r5v-011-tneg`（`user.password = KDF摘要`）必须 Reject；
   配套 011 Confirm（真实明文存储）必须 Confirm。
4. **detect 精度提升**：`detect_eval.jsonl`（7 真实安全函数 + 3 新族 pos + 3 新族 aneg）
   在 011/012/013 上 tp≥2/3、aneg 0 误报；主基准整体 precision > 0.537（R3/R4 持平值）。
5. **18 探针回归**：`python scripts/run_triage_probes.py --results … --compare data/round2/eval/triage_probes.json`
   保持 18/18（Confirm 方向不因新增 Reject 样本而崩）。

## 六、验证切片与跑法

- `scripts/build_round5_validation.py [--backtest]` 产出：
  `data/round5/validation/{detect_eval.jsonl, triage_eval.jsonl, manifest.json}` + `configs/benchmark_round5.yaml`。
- 12 条新族探针与训练集**零代码重叠**（脚本内泄漏检查），回测 12/12 纪律通过。
- 评估：`python main.py --benchmark --config configs/benchmark_round5.yaml`（填 LLM_MODEL_ID / LLM_API_KEY）。
- 数据校验：`python scripts/validate_dataset.py --files data/round5/known_forms_detect.jsonl data/round5/known_forms_triage.jsonl
  data/round5/validation/detect_eval.jsonl data/round5/validation/triage_eval.jsonl`——本轮全部 OK。
  注意：验证器只认 v2 schema，`upload/full/*.jsonl` 是 chatml，不能喂给它。

## 七、下一课题思路（真实口令漏洞识别的进阶，本轮不做）

已知形式学完后，把「已知→未知」的泛化作为下一轮目标，候选方向（按性价比排序）：

1. **形式组合爆破**：把 011/012/013 与既有 CWE-327/328（弱算法）交叉——例如「明文存 + MD5」、
   「比较== + 弱摘要」这类现实世界最常见的复合写法；用手工枚举状态矩阵而非模板扩量。
2. **语义负样本深化**：口令库/框架的「必须复现 legacy」是 R4 最大漏网，R5 只做了 passlib；
   可扩展到 PyJWT / itsdangerous / pycryptodome 的 PBES/签名字段，逐库建立「库职责白名单」。
3. **context-aware detect**：把「无权读取的规则命中」从「规则命中」中剥离——给模型补
   「赋值语句的 RHS 数据流」监督信号（KDF 摘要 / 常量 / 用户输入溯源），把 CRYPTO-011 从全报警收敛到真漏洞。
4. **可解释补丁生成**：tpos 已带 patch；进阶为「多候选修法 + 理由」的偏好排序（DPO 式），
   让 Confirm 输出不再只是标签。
5. **未知形式探测集**：为下一课题预埋「近邻变异」测试集（换参数风格、换 API 名、跨库等价物），
   训练后用它度量泛化，而不是等到上线才发现。
