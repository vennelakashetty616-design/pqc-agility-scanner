from __future__ import annotations

import json
from pathlib import Path

from pqcscan.disclaimer import DISCLAIMER
from pqcscan.models import Finding, ScanResult

SCHEMA = 1


def fingerprint(finding: Finding) -> str | None:
    if finding.confidence != "confirmed":
        return None
    if finding.kind not in {"algorithm", "library", "protocol", "certificate", "key_size", "secret_material"}:
        return None
    path = finding.evidence[0].path if finding.evidence else finding.component
    return f"{finding.kind}|{finding.name}|{path}"


def baseline_document(result: ScanResult) -> dict:
    fingerprints = sorted({item for item in (fingerprint(finding) for finding in result.findings) if item})
    return {
        "schema": SCHEMA,
        "disclaimer": DISCLAIMER,
        "fingerprints": fingerprints,
    }


def write_baseline(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline_document(result), indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA or not isinstance(data.get("fingerprints"), list):
        raise ValueError("Baseline schema is not recognized. Expected schema 1 with a fingerprints list.")
    return data


def compare_baseline(result: ScanResult, document: dict) -> tuple[list[str], list[str]]:
    current = {item for item in (fingerprint(finding) for finding in result.findings) if item}
    previous = set(document["fingerprints"])
    return sorted(current - previous), sorted(previous - current)
