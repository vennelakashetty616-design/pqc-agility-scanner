from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    "reports",
    ".mypy_cache",
    ".eggs",
}

MANIFEST_NAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "package.json",
    "go.mod",
    "pom.xml",
    "cargo.toml",
    "build.gradle",
    "build.gradle.kts",
    "pipfile",
    "composer.json",
    "gemfile",
    "package-lock.json",
}

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der"}
MAX_BYTES = 1_000_000


@dataclass
class SourceFile:
    path: Path
    relative: str
    text: str
    data: bytes
    category: str


def _category(path: Path, text: str) -> str:
    name = path.name.lower()
    if name in MANIFEST_NAMES:
        return "manifest"
    if path.suffix.lower() in CERT_EXTENSIONS or "-----BEGIN CERTIFICATE-----" in text:
        return "certificate"
    if "-----BEGIN" in text and "PRIVATE KEY-----" in text:
        return "certificate"
    config_suffixes = {
        ".conf",
        ".cnf",
        ".cfg",
        ".ini",
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".xml",
        ".properties",
    }
    config_names = {"ssh_config", "dockerfile", "nginx.conf"}
    if path.suffix.lower() in config_suffixes or name in config_names:
        return "config"
    return "code"


def _binary(data: bytes) -> bool:
    return b"\x00" in data[:1024]


def discover(root: Path) -> tuple[list[SourceFile], int]:
    files: list[SourceFile] = []
    skipped = 0
    root = root.resolve()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            skipped += 1
            continue
        try:
            size = path.stat().st_size
        except OSError:
            skipped += 1
            continue
        if size > MAX_BYTES:
            skipped += 1
            continue
        try:
            data = path.read_bytes()
        except OSError:
            skipped += 1
            continue
        suffix = path.suffix.lower()
        if _binary(data) and suffix not in CERT_EXTENSIONS:
            skipped += 1
            continue
        text = data.decode("utf-8", errors="replace")
        if suffix in CERT_EXTENSIONS or b"-----BEGIN CERTIFICATE-----" in data:
            category = "certificate"
        else:
            category = _category(path, text)
        relative = path.relative_to(root).as_posix()
        files.append(SourceFile(path=path, relative=relative, text=text, data=data, category=category))
    files.sort(key=lambda item: item.relative)
    return files, skipped
