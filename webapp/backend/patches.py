"""Deterministic remediation helpers and an optional model-assisted fixer.

The static rule set already carries a ``fix`` field for every rule.  This
module turns that guidance into a concrete, reviewable artifact:

* a conservative line-by-line rewrite for mechanical substitutions
  (MD5 -> SHA-256, 1024 -> 3072, disabled TLS verification -> enabled);
* a safe code snippet for defects that require a structural change
  (ECB -> GCM, plaintext passwords -> a KDF, comparisons -> compare_digest);
* a unified diff so the UI can show exactly what changed.
"""

from __future__ import annotations

import difflib
import re
from typing import Any, Callable


RULE_FIXES: dict[str, dict[str, Any]] = {
    "CRYPTO-001": {
        "summary": "将 MD5 替换为 SHA-256；口令场景请改用 scrypt/argon2/bcrypt。",
        "bad": 'hashlib.md5(data).hexdigest()',
        "good": 'hashlib.sha256(data).hexdigest()',
    },
    "CRYPTO-002": {
        "summary": "将 SHA-1 替换为 SHA-256；口令场景请改用专用 KDF。",
        "bad": 'hashlib.sha1(data).hexdigest()',
        "good": 'hashlib.sha256(data).hexdigest()',
    },
    "CRYPTO-003": {
        "summary": "DES/3DES 已不安全，改用 AES-256-GCM 或 ChaCha20-Poly1305。",
        "bad": "DES3.new(key, DES3.MODE_CBC, iv)",
        "good": (
            "nonce = secrets.token_bytes(12)\n"
            "cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)\n"
            "ciphertext, tag = cipher.encrypt_and_digest(plaintext)"
        ),
    },
    "CRYPTO-004": {
        "summary": "RC4 存在统计偏差，改用 AES-256-GCM 或 ChaCha20-Poly1305。",
        "bad": "ARC4.new(key).encrypt(plaintext)",
        "good": (
            "nonce = secrets.token_bytes(12)\n"
            "cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)\n"
            "ciphertext, tag = cipher.encrypt_and_digest(plaintext)"
        ),
    },
    "CRYPTO-005": {
        "summary": "ECB 会泄露明文结构，改用带唯一 nonce 的 AES-GCM。",
        "bad": "AES.new(key, AES.MODE_ECB)",
        "good": (
            "nonce = secrets.token_bytes(12)  # 每次加密都必须唯一\n"
            "cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)\n"
            "ciphertext, tag = cipher.encrypt_and_digest(plaintext)"
        ),
    },
    "CRYPTO-006": {
        "summary": "每次加密生成独立随机 IV/nonce，并通过密码学安全随机源获取。",
        "bad": 'iv = b""',
        "good": "iv = secrets.token_bytes(16)  # 或 os.urandom(16)",
    },
    "CRYPTO-007": {
        "summary": "密钥改从环境变量或密钥管理服务读取，不要写进源码。",
        "bad": 'key = b"0123456789abcdef"',
        "good": 'key = os.environ["APP_AES_KEY"].encode("utf-8")',
    },
    "CRYPTO-008": {
        "summary": "安全敏感值改用 secrets 或 os.urandom，不要使用 random 模块。",
        "bad": "token = random.getrandbits(256)",
        "good": "token = secrets.token_bytes(32)",
    },
    "CRYPTO-009": {
        "summary": "RSA 至少 2048 位（推荐 3072），或改用 P-256/P-384 曲线。",
        "bad": "key = RSA.generate(1024)",
        "good": "key = RSA.generate(3072)",
    },
    "CRYPTO-010": {
        "summary": "启用证书校验与 TLS 1.2+，不要关闭 verify 或使用旧协议。",
        "bad": 'requests.get(url, verify=False)\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)',
        "good": (
            "ctx = ssl.create_default_context()\n"
            "ctx.minimum_version = ssl.TLSVersion.TLSv1_2\n"
            "requests.get(url, verify=True, timeout=10)"
        ),
    },
    "CRYPTO-011": {
        "summary": "只保存加盐 KDF 摘要，不要存储或传递明文口令。",
        "bad": "user.password = password",
        "good": (
            "salt = secrets.token_bytes(16)\n"
            "digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)\n"
            "user.password_hash = digest"
        ),
    },
    "CRYPTO-012": {
        "summary": "提高 KDF 成本：PBKDF2-SHA256 >= 600k，bcrypt cost >= 12，scrypt n >= 2**14。",
        "bad": 'hashlib.pbkdf2_hmac("sha256", password, salt, 1000)',
        "good": 'hashlib.pbkdf2_hmac("sha256", password, salt, 600_000)',
    },
    "CRYPTO-013": {
        "summary": "使用 hmac.compare_digest 进行恒定时间比较。",
        "bad": "if stored_token == provided_token:",
        "good": "if hmac.compare_digest(stored_token, provided_token):",
    },
}


def fix_for(rule_id: str) -> dict[str, Any]:
    return RULE_FIXES.get(rule_id, {})


def _replace(patterns: list[tuple[re.Pattern[str], Callable[[re.Match[str]], str]]]) -> Callable[[str], tuple[str, list[str]]]:
    def apply(line: str) -> tuple[str, list[str]]:
        notes: list[str] = []
        for pattern, replacement in patterns:
            line, count = pattern.subn(replacement, line)
            if count:
                notes.append(pattern.pattern)
        return line, notes

    return apply


def _literal(old: str, new: str) -> Callable[[re.Match[str]], str]:
    return lambda _match: new


def _bump_number(threshold: int, replacement: int) -> Callable[[re.Match[str]], str]:
    def repl(match: re.Match[str]) -> str:
        value = int(match.group(1))
        return match.group(0).replace(match.group(1), str(replacement), 1) if value < threshold else match.group(0)

    return repl


_MECHANICAL: dict[str, list[tuple[re.Pattern[str], Callable[[re.Match[str]], str]]]] = {
    "CRYPTO-001": [
        (re.compile(r"hashlib\.md5\s*\("), _literal("", "hashlib.sha256(")),
        (re.compile(r"(hashlib\.new\s*\(\s*)([\"'])md5([\"'])", re.I), lambda m: f"{m.group(1)}{m.group(2)}sha256{m.group(3)}"),
    ],
    "CRYPTO-002": [
        (re.compile(r"hashlib\.sha1\s*\("), _literal("", "hashlib.sha256(")),
        (re.compile(r"(hashlib\.new\s*\(\s*)([\"'])sha-?1([\"'])", re.I), lambda m: f"{m.group(1)}{m.group(2)}sha256{m.group(3)}"),
    ],
    "CRYPTO-009": [
        (re.compile(r"RSA\.generate\s*\(\s*(?:512|768|1024)\s*\)"), _literal("", "RSA.generate(3072)")),
    ],
    "CRYPTO-010": [
        (re.compile(r"verify\s*=\s*False"), _literal("", "verify=True")),
        (re.compile(r"ssl\.SSLContext\s*\(\s*ssl\.PROTOCOL_(?:SSLv[23]|TLSv1(?:_1)?)\s*\)"), _literal("", "ssl.create_default_context()")),
    ],
    "CRYPTO-012": [
        (re.compile(r"(pbkdf2_hmac\s*\([^)]*?,\s*)(\d{1,6})(\s*[,)])"), lambda m: f"{m.group(1)}600000{m.group(3)}"),
        (re.compile(r"(bcrypt\.gensalt\s*\(\s*rounds\s*=\s*)(\d+)(\s*\))"), lambda m: f"{m.group(1)}12{m.group(3)}"),
        (re.compile(r"(scrypt\s*\([^)]*?n\s*=\s*)(\d+)(\s*)"), lambda m: f"{m.group(1)}16384{m.group(3)}"),
    ],
}


def apply_mechanical_fixes(source: str, rule_ids: set[str]) -> tuple[str, list[dict[str, Any]]]:
    """Apply conservative substitutions and return the new source + change log."""
    lines = source.splitlines()
    changes: list[dict[str, Any]] = []
    for index, original_line in enumerate(lines):
        line = original_line
        for rule_id in sorted(rule_ids):
            for pattern, replacement in _MECHANICAL.get(rule_id, []):
                updated, count = pattern.subn(replacement, line)
                if count and updated != line:
                    changes.append(
                        {
                            "rule_id": rule_id,
                            "line": index + 1,
                            "before": line.rstrip(),
                            "after": updated.rstrip(),
                        }
                    )
                    line = updated
        lines[index] = line
    fixed = "\n".join(lines)
    if source.endswith("\n") and not fixed.endswith("\n"):
        fixed += "\n"
    return fixed, changes


def unified_diff(original: str, fixed: str, filename: str = "snippet.py") -> list[str]:
    return list(
        difflib.unified_diff(
            original.splitlines(),
            fixed.splitlines(),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="",
        )
    )


def suggestions_for(rule_ids: set[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rule_id in sorted(rule_ids):
        fix = RULE_FIXES.get(rule_id)
        if not fix:
            continue
        out.append({"rule_id": rule_id, **fix})
    return out
