"""Accept a folder path and uploaded text or PDF files for one scan."""

from __future__ import annotations

import base64
import binascii
import re
import tempfile
import zlib
from pathlib import Path

from pqcscan.analysis import ScanRequestError, build_analysis
from pqcscan.engine import scan_path
from pqcscan.models import ScanResult
from pqcscan.plan import (
    build_checklist,
    build_graph,
    build_hybrid_options,
    compatibility_risks,
    limitations,
    testing_steps,
)
from pqcscan.inventory import build_inventory
from pqcscan.disclaimer import DISCLAIMER

_ALLOWED = {".txt", ".text", ".md", ".pdf"}
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
_MAX_FILES = 8
_MAX_FILE_BYTES = 1_500_000


def scan_inputs(path: str, files: list | None) -> dict:
    """Scan a folder, uploaded files, or both, and return one analysis."""
    uploads = _decode_uploads(files or [])
    folder = path.strip()
    results: list[ScanResult] = []
    label_parts: list[str] = []
    if folder:
        try:
            root = Path(folder).expanduser().resolve()
        except OSError as exc:
            raise ScanRequestError(f"Cannot read that path: {exc}") from exc
        if root == Path(root.anchor):
            raise ScanRequestError("Choose a project folder, not the whole disk.")
        if not root.is_dir():
            raise ScanRequestError(f"Not a folder: {root}")
        results.append(scan_path(root))
        label_parts.append(str(root))
    if uploads:
        with tempfile.TemporaryDirectory(prefix="pqcscan-upload-") as temp:
            folder_path = Path(temp)
            for name, data in uploads:
                target = folder_path / name
                if name.lower().endswith(".pdf"):
                    text = pdf_text(data)
                    if not text.strip():
                        raise ScanRequestError(f"Could not read text from {name}.")
                    target = folder_path / f"{Path(name).stem}.txt"
                    target.write_text(f"Source PDF: {name}\n{text}\n", encoding="utf-8")
                else:
                    target.write_bytes(data)
            results.append(scan_path(folder_path))
        label_parts.append("uploaded files")
    if not results:
        raise ScanRequestError("Enter a folder path or upload a text or PDF file.")
    merged = results[0] if len(results) == 1 else _merge(results)
    merged.root = " + ".join(label_parts)
    return build_analysis(merged)


def _decode_uploads(files: list) -> list[tuple[str, bytes]]:
    if not isinstance(files, list):
        raise ScanRequestError("Send uploaded files as a list.")
    if len(files) > _MAX_FILES:
        raise ScanRequestError(f"Upload at most {_MAX_FILES} files.")
    decoded: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            raise ScanRequestError("Each upload needs a name and data.")
        name = _safe_name(str(item.get("name", "")))
        if name in seen:
            raise ScanRequestError(f"Two files share the name {name}.")
        seen.add(name)
        raw = item.get("data", "")
        if not isinstance(raw, str) or not raw.strip():
            raise ScanRequestError(f"{name} is empty.")
        try:
            data = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ScanRequestError(f"{name} is not valid file data.") from exc
        if len(data) > _MAX_FILE_BYTES:
            raise ScanRequestError(f"{name} is larger than 1.5 MB.")
        if not data:
            raise ScanRequestError(f"{name} is empty.")
        decoded.append((name, data))
    return decoded


def _safe_name(name: str) -> str:
    base = Path(name).name
    if not _NAME.fullmatch(base):
        raise ScanRequestError("Use a simple file name with letters, numbers, dots, or dashes.")
    if Path(base).suffix.lower() not in _ALLOWED:
        raise ScanRequestError("Upload .txt, .md, or .pdf files only.")
    return base


def pdf_text(data: bytes) -> str:
    """Pull visible text out of a simple PDF so the scanner can read it."""
    pieces: list[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        raw = match.group(1)
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            pass
        pieces.extend(_pdf_strings(raw))
    if not pieces:
        pieces.extend(_pdf_strings(data))
    return "\n".join(piece for piece in pieces if piece.strip())


def _pdf_strings(raw: bytes) -> list[str]:
    found = []
    for match in re.finditer(rb"\((?:\\.|[^\\)])*\)", raw):
        found.append(_unescape_pdf(match.group(0)[1:-1]))
    return found


def _unescape_pdf(raw: bytes) -> str:
    text = raw.replace(b"\\n", b"\n").replace(b"\\r", b"\r").replace(b"\\t", b"\t")
    text = text.replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
    return text.decode("utf-8", errors="replace")


def _merge(results: list[ScanResult]) -> ScanResult:
    findings = []
    for result in results:
        findings.extend(result.findings)
    for index, finding in enumerate(findings, start=1):
        finding.finding_id = f"F-{index:03d}"
    files_scanned = sum(result.files_scanned for result in results)
    files_skipped = sum(result.files_skipped for result in results)
    inventory = build_inventory(findings)
    return ScanResult(
        root="",
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        findings=findings,
        inventory=inventory,
        checklist=build_checklist(findings),
        hybrid_options=build_hybrid_options(findings),
        migration_graph=build_graph(inventory),
        limitations=limitations(files_scanned, files_skipped),
        compatibility_risks=compatibility_risks(findings),
        testing_steps=testing_steps(),
        disclaimer=DISCLAIMER,
    )
