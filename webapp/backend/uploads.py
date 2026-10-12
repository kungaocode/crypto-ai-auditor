"""Safe staging for pasted snippets and uploaded files/archives.

Uploaded code is never executed.  Files are written into a fresh temporary
directory, scanned in place, and the directory is removed by the caller.
Archive extraction rejects absolute paths and ``..`` traversal.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .scanners import SourceFile, guess_language, is_supported

MAX_FILES = 60
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 400
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._\-\u4e00-\u9fff]+")


class UploadError(RuntimeError):
    """User-facing upload validation failure."""


def sanitize_name(name: str, fallback: str = "snippet.py") -> str:
    candidate = Path(name or "").name.strip()
    candidate = _SAFE_NAME.sub("_", candidate).strip("._")
    return candidate or fallback


@dataclass
class StagedAudit:
    root: Path
    sources: list[SourceFile] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def _new_root() -> Path:
    return Path(tempfile.mkdtemp(prefix="cryptoaudit-"))


def _read_source(path: Path, name: str) -> SourceFile:
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise UploadError(f"{name} 超过单文件大小上限（2 MB）。")
    if b"\x00" in raw[:4096]:
        raise UploadError(f"{name} 看起来是二进制文件，已拒绝。")
    source = raw.decode("utf-8", errors="replace")
    return SourceFile(name=name, path=path, language=guess_language(name), source=source)


def stage_code(code: str, filename: str = "snippet.py") -> StagedAudit:
    if not code or not code.strip():
        raise UploadError("代码内容为空。")
    if len(code.encode("utf-8")) > MAX_FILE_BYTES:
        raise UploadError("代码超过单文件大小上限（2 MB）。")
    root = _new_root()
    name = sanitize_name(filename or "snippet.py")
    if not is_supported(name):
        name = "snippet.py"
    path = root / name
    path.write_text(code, encoding="utf-8")
    staged = StagedAudit(root=root)
    staged.sources.append(_read_source(path, name))
    return staged


def _unique_path(root: Path, name: str, used: set[str]) -> Path:
    candidate = name
    stem, suffix = Path(name).stem, Path(name).suffix
    index = 1
    while candidate in used:
        candidate = f"{stem}_{index}{suffix}"
        index += 1
    used.add(candidate)
    return root / candidate


def _extract_archive(archive, root: Path, staged: StagedAudit, used: set[str]) -> None:
    try:
        payload = archive.read()
    except Exception as exc:
        raise UploadError(f"无法读取压缩包：{exc}") from exc
    if not payload:
        raise UploadError("压缩包为空。")
    if not zipfile.is_zipfile(__import__("io").BytesIO(payload)):
        raise UploadError("仅支持 ZIP 压缩包。")
    total = 0
    with zipfile.ZipFile(__import__("io").BytesIO(payload)) as zf:
        entries = [i for i in zf.infolist() if not i.is_dir()]
        if len(entries) > MAX_ARCHIVE_ENTRIES:
            raise UploadError(f"压缩包条目过多（>{MAX_ARCHIVE_ENTRIES}）。")
        for info in entries:
            if len(staged.sources) >= MAX_FILES:
                staged.skipped.append({"name": info.filename, "reason": "文件数量超限"})
                continue
            raw_name = info.filename.replace("\\", "/")
            if raw_name.startswith("/") or ".." in Path(raw_name).parts:
                staged.skipped.append({"name": info.filename, "reason": "非法路径"})
                continue
            name = sanitize_name(raw_name)
            if not is_supported(name):
                continue
            if info.file_size > MAX_FILE_BYTES:
                staged.skipped.append({"name": raw_name, "reason": "文件过大"})
                continue
            total += info.file_size
            if total > MAX_FILE_BYTES * 12:
                raise UploadError("压缩包解压后体积过大。")
            target = _unique_path(root, name, used)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=64 * 1024)
            try:
                staged.sources.append(_read_source(target, target.name))
            except UploadError as exc:
                staged.skipped.append({"name": raw_name, "reason": str(exc)})


def stage_uploads(files: Iterable, archive=None) -> StagedAudit:
    root = _new_root()
    staged = StagedAudit(root=root)
    used: set[str] = set()
    archives = []

    for storage in files:
        original = getattr(storage, "filename", "") or ""
        if not original:
            continue
        name = sanitize_name(original)
        if Path(name).suffix.lower() == ".zip":
            archives.append(storage)
            continue
        if not is_supported(name):
            staged.skipped.append({"name": original, "reason": "不支持的扩展名"})
            continue
        if len(staged.sources) >= MAX_FILES:
            staged.skipped.append({"name": original, "reason": "文件数量超限"})
            continue
        target = _unique_path(root, name, used)
        try:
            storage.save(target)
            staged.sources.append(_read_source(target, target.name))
        except UploadError as exc:
            staged.skipped.append({"name": original, "reason": str(exc)})
        except Exception as exc:
            staged.skipped.append({"name": original, "reason": f"保存失败：{exc}"})

    if archive is not None and getattr(archive, "filename", ""):
        archives.append(archive)

    for stored_archive in archives:
        if len(staged.sources) >= MAX_FILES:
            name = getattr(stored_archive, "filename", "") or "archive.zip"
            staged.skipped.append({"name": name, "reason": "文件数量超限"})
            continue
        _extract_archive(stored_archive, root, staged, used)

    if not staged.sources:
        staged.cleanup()
        reason = "；".join(sorted({item["reason"] for item in staged.skipped})) or "没有找到受支持的文件"
        raise UploadError(f"未接收到可审计代码：{reason}")
    return staged
