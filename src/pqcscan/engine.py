from __future__ import annotations

from pathlib import Path

from pqcscan.baseline import fingerprint
from pqcscan.certs import scan_certificate
from pqcscan.disclaimer import DISCLAIMER
from pqcscan.discover import discover
from pqcscan.imports import build_import_edges, infer_indirect
from pqcscan.inventory import build_inventory
from pqcscan.manifests import scan_manifest
from pqcscan.matchers import scan_text
from pqcscan.models import Finding, ScanResult
from pqcscan.plan import (
    build_checklist,
    build_graph,
    build_hybrid_options,
    compatibility_risks,
    limitations,
    testing_steps,
)

_CONCERN_RANK = {"urgent": 0, "plan": 1, "monitor": 2, "informational": 3}
_CONFIDENCE_RANK = {"confirmed": 0, "uncertain": 1}


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    ordered: list[Finding] = []
    for finding in findings:
        evidence = finding.evidence[0] if finding.evidence else None
        key = (
            finding.confidence,
            finding.name,
            finding.kind,
            finding.usage,
            evidence.path if evidence else finding.component,
            evidence.line if evidence else None,
            finding.via,
        )
        if key in seen:
            continue
        seen.add(key)
        ordered.append(finding)
    return ordered


def _sort(findings: list[Finding]) -> list[Finding]:
    def key(finding: Finding) -> tuple:
        evidence = finding.evidence[0] if finding.evidence else None
        return (
            _CONFIDENCE_RANK.get(finding.confidence, 9),
            _CONCERN_RANK.get(finding.concern, 9),
            evidence.path if evidence else finding.component,
            evidence.line if evidence else 0,
            finding.name,
            finding.usage,
        )

    return sorted(findings, key=key)


def scan_path(root: Path) -> ScanResult:
    root = root.resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Scan path is not a directory: {root}")
    files, skipped = discover(root)
    findings: list[Finding] = []
    for source in files:
        if source.category == "certificate":
            findings.extend(scan_certificate(source))
            continue
        if source.category == "manifest":
            findings.extend(scan_manifest(source))
            continue
        findings.extend(scan_text(source))
    edges = build_import_edges(files)
    line_map = {source.relative: source.text.splitlines() for source in files}
    findings.extend(infer_indirect(findings, edges, line_map))
    findings = _sort(_dedupe(findings))
    for index, finding in enumerate(findings, start=1):
        finding.finding_id = f"F-{index:03d}"
    inventory = build_inventory(findings)
    return ScanResult(
        root=str(root),
        files_scanned=len(files),
        files_skipped=skipped,
        findings=findings,
        inventory=inventory,
        checklist=build_checklist(findings),
        hybrid_options=build_hybrid_options(findings),
        migration_graph=build_graph(inventory),
        limitations=limitations(len(files), skipped),
        compatibility_risks=compatibility_risks(findings),
        testing_steps=testing_steps(),
        disclaimer=DISCLAIMER,
    )


def confirmed_fingerprints(result: ScanResult) -> list[str]:
    return sorted({item for item in (fingerprint(finding) for finding in result.findings) if item})
