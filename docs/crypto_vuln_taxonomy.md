# 密码学漏洞分类参考（Round-4 负样本 & 真实项目标注口径）

> 用途：为第四轮负样本的 `explanation` 措辞、以及真实密码项目验证集的**人工标注判据**提供权威依据。
> 每条给出「弱模式 → 真实攻击/依据 → 安全对照写法」三要素；标注时按此口径判断。

## 0. 权威依据速览（联网核验，2026-09）

| 来源 | 关键结论 |
|---|---|
| [NIST SP 800-131A Rev.2/Rev.3](https://www.nist.gov/news-events/news/2019/03/transitioning-use-cryptographic-algorithms-and-key-lengths-nist-sp-800-131a) | MD5、SHA-1（签名生成）、2-key 3DES、RC4、RSA/DH <112-bit（含 1024）、非 SP800-90A 的 RNG 均已 **Disallowed**；Rev.3 进一步 Disallow **AES-ECB 加密**，2030 年起 128-bit 为最低强度 |
| [Wang et al. 2004 / Flame 2012](https://safeguard.sh/resources/blog/insecure-hash-algorithm-usage-in-application-code) | MD5 2004 被构造碰撞；2012 Flame 用 MD5 碰撞伪造 Microsoft 签名的证书 |
| [SHAttered 2017](https://safeguard.sh/resources/blog/weakbroken-cryptography-vulnerabilities-explained) | SHA-1 2017 由 Google/CWI 撞破（两 PDF 同 SHA-1）；Git 至今仍主要依赖 SHA-1 做对象哈希 |
| [Pearce et al., Asleep at the Keyboard, S&P'22](https://people.cs.vt.edu/nm8247/publications/TSE3150302-2.pdf#5#1) | Copilot 生成代码 ~40% 含漏洞，CWE-327 是其最差类别之一 |
| [Fu et al., TOSEM'25](https://people.cs.vt.edu/nm8247/publications/TSE3150302-2.pdf#5#1) | 真实合入 Copilot 代码中最常见的弱点是 **CWE-330（随机值不足）** |
| [To Fix or Not to Fix: Crypto-misuses in the Wild](https://ar5iv.labs.arxiv.org/html/2209.11103) | 明确记录「**effective false positive**」= 弱原语用在**非安全上下文**（如 MD5 做缓存），不应修 → 本项目 B 类负样本的文献依据 |

## 1. 规则 ↔ CWE ↔ 安全对照

| 规则 | CWE | 弱模式（Confirm / vulnerable=true） | 安全对照（Reject / vulnerable=false） |
|---|---|---|---|
| CRYPTO-001 MD5 | CWE-327 | 口令散列、令牌派生、完整性校验、签名 | `sha256`/`hmac-sha256`/`scrypt`/`argon2`；MD5 仅做 cache/dedup/etag/内容寻址 |
| CRYPTO-002 SHA-1 | CWE-327 | 签名、证书指纹、凭证散列、会话 id | `sha256`；SHA-1 仅做分片/日志索引/非安全指纹 |
| CRYPTO-003 DES/3DES | CWE-327 | 加密真实数据（Sweet32：64-bit 块生日攻击） | `AES-GCM`/`AES-CBC+随机IV`；DES 仅 benchmark/测试夹具 |
| CRYPTO-004 RC4 | CWE-327 | 加密真实数据（keystream 偏置、无认证） | `AES-GCM`；RC4 仅测试向量复现 |
| CRYPTO-005 AES-ECB | CWE-327 | 加密真实数据（块模式泄漏明文结构，Adobe 2013） | `AES-GCM`/`AES-CBC+随机IV` |
| CRYPTO-006 可预测 IV | CWE-329 | 固定/全零 IV（CBC/CFB 前缀泄漏、明文链接） | 每次加密 `os.urandom(16)`/`secrets.token_bytes(16)` 新 IV |
| CRYPTO-007 硬编码密钥 | CWE-321 | 密钥/口令写死在源码 | `os.environ` / secrets manager / KDF |
| CRYPTO-008 弱随机 | CWE-338 | `random.*` 生成令牌/口令/盐/nonce（Mersenne Twister 可预测；Debian CVE-2008-0166） | `secrets.*` / `os.urandom` |
| CRYPTO-009 弱密钥长度 | CWE-326 | RSA/DH <2048（1024 可被分解） | RSA-2048+ / `SECP256R1`+ |
| CRYPTO-010 不安全 TLS | CWE-326/295 | `verify=False`、`PROTOCOL_TLSv1`、`_create_unverified_context` | `requests` 默认校验、`ssl.create_default_context()`、`TLSv1_2+` |

## 2. 判别口径（detect 负样本 & 真实项目标注时遵循）

**判 vulnerable=true 的必要条件：弱原语/弱参数的输出，其安全性影响到了某个「安全目的」。**
安全目的 = 保护 **凭据、令牌、密钥、签名、nonce、真实秘密** 的机密性/完整性/认证。

**判 vulnerable=false 的两类**：
- **A 类（安全现代密码）**：用了正确原语（scrypt/argon2/bcrypt/pbkdf2、AES-GCM+随机 nonce、`secrets`/`os.urandom`、`sha256`+HMAC、RSA-2048、TLS 校验开启）。
- **B 类（弱原语 × 非安全目的）**：MD5/SHA-1/`random` 用在缓存键、去重、内容寻址、变更检测（etag/fingerprint）、分片/负载均衡、日志索引、退避抖动、A/B 分桶、模拟/测试夹具——**无任何安全属性依赖该输出**。

> 文献对齐：B 类即 [To Fix or Not to Fix](https://ar5iv.labs.arxiv.org/html/2209.11103) 的「effective false positive」，真实世界中不应报告。
