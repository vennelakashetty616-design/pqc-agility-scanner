"""Turn a scan into the figures and plain-language reading the dashboard shows.

The text is assembled from the inventory. It is not a live model, and it does
not decide that a system is quantum-safe.
"""

from __future__ import annotations

from pathlib import Path

from pqcscan.dashboard import _plain
from pqcscan.engine import scan_path
from pqcscan.models import InventoryEntry, ScanResult

_CONCERN_ORDER = ("urgent", "plan", "monitor", "informational")

_CONCERN_LABEL = {
    "urgent": "Retire now",
    "plan": "Plan a migration",
    "monitor": "Keep, with an owner",
    "informational": "Library or name only",
}

_GUIDANCE = {
    "urgent": (
        "Published guidance already treats these as obsolete for new use: broken hashes, "
        "retired ciphers, TLS 1.0 and 1.1, and RSA keys under 2048 bits. Retire them with a "
        "vetted library. That cleanup does not make the system post-quantum."
    ),
    "plan": (
        "RSA and elliptic-curve public keys still work at modern sizes. NIST FIPS 203, 204, and "
        "205 name ML-KEM, ML-DSA, and SLH-DSA for a later migration. A larger RSA key is not a "
        "post-quantum fix. This tool does not implement those algorithms."
    ),
    "monitor": (
        "SHA-256, SHA-384, and AES-256 remain ordinary classical choices. AES-128 has a smaller "
        "long-term margin and is a later decision than public-key migration. Give each one an owner."
    ),
    "informational": (
        "A library or algorithm name records a dependency. It does not say which call is active, "
        "and it does not show that a deployment is quantum-safe."
    ),
}

_USAGE_LABEL = {
    "hash": "Hashing",
    "signature": "Signatures",
    "keygen": "Key generation",
    "key_agreement": "Key agreement",
    "bulk_encryption": "Encryption",
    "mac": "Message authentication",
    "password_hashing": "Password hashing",
    "transport": "Transport security",
    "library": "Libraries",
    "certificate": "Certificates",
    "declared_dependency": "Declared packages",
    "indirect": "Through a wrapper",
    "unknown": "Name only",
}


class ScanRequestError(ValueError):
    """The folder the dashboard was asked to scan cannot be read."""


def _active(entry: InventoryEntry) -> bool:
    return bool(entry.direct_components or entry.indirect_components or entry.declared_dependencies)


def _spots(findings, name: str | None = None, concern: str | None = None, limit: int = 8) -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple] = set()
    for finding in findings:
        if name is not None and finding.name != name:
            continue
        if concern is not None and finding.concern != concern:
            continue
        if not finding.evidence:
            continue
        evidence = finding.evidence[0]
        key = (evidence.path, evidence.line, evidence.snippet)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"path": evidence.path, "line": evidence.line, "snippet": evidence.snippet})
        if len(rows) >= limit:
            break
    return rows


def _where(paths: list[str], limit: int = 2) -> str:
    shown = paths[:limit]
    text = ", ".join(shown)
    extra = len(paths) - len(shown)
    if extra > 0:
        text += f", and {extra} more"
    return text


def _headline(urgent: int, plan: int, confirmed: int) -> str:
    if confirmed == 0:
        return "No confirmed cryptographic use was found in this folder."
    if urgent and plan:
        return (
            f"{urgent} practices should be retired, and {plan} still need a migration plan."
        )
    if urgent:
        return f"{urgent} practices should be retired. No separate migration-plan group was confirmed."
    if plan:
        return f"Nothing obsolete was confirmed. {plan} practices still need a migration plan."
    return "Confirmed cryptography is present. Give each item an owner before treating the scan as finished."


def _narrative(result: ScanResult, urgent_names: list[str], plan_names: list[str], uncertain: int) -> str:
    file_word = "file" if result.files_scanned == 1 else "files"
    sentences = [
        f"The scanner read {result.files_scanned} {file_word} in {result.root}. "
        "It looked at source, configuration, certificates, and dependency files. It did not run the program."
    ]
    if urgent_names:
        shown = ", ".join(urgent_names[:6])
        more = len(urgent_names) - min(len(urgent_names), 6)
        extra = f", plus {more} more" if more else ""
        sentences.append(
            f"Confirmed obsolete practice includes {shown}{extra}. "
            "Those are already a problem on ordinary computers. Replacing them does not make the system post-quantum."
        )
    else:
        sentences.append("No obsolete mechanism was confirmed in this tree.")
    if plan_names:
        shown = ", ".join(plan_names[:5])
        sentences.append(
            f"Practices that still work today but need a plan include {shown}. "
            "Public-key algorithms in that list rely on math a future quantum computer would threaten. "
            "Hashes and AES are usually a later decision than that public-key plan."
        )
    if uncertain:
        sentences.append(
            f"{uncertain} matches are comments or bare names. Do not schedule a migration from those rows."
        )
    sentences.append(
        "This page lines the inventory up with widely published guidance. "
        "It is not a certification, and it does not prove the system is quantum-safe."
    )
    return " ".join(sentences)


def build_analysis(result: ScanResult) -> dict:
    confirmed = [item for item in result.findings if item.confidence == "confirmed"]
    uncertain = [item for item in result.findings if item.confidence != "confirmed"]
    direct = [item for item in confirmed if item.usage != "indirect"]

    by_concern: dict[str, list[InventoryEntry]] = {key: [] for key in _CONCERN_ORDER}
    for entry in result.inventory:
        if _active(entry) and entry.concern in by_concern:
            by_concern[entry.concern].append(entry)

    concern_counts = {key: 0 for key in _CONCERN_ORDER}
    for finding in direct:
        concern_counts[finding.concern] = concern_counts.get(finding.concern, 0) + 1

    usage_counts: dict[str, int] = {}
    for finding in direct:
        usage_counts[finding.underlying_usage] = usage_counts.get(finding.underlying_usage, 0) + 1

    file_counts: dict[str, int] = {}
    for finding in direct:
        path = finding.evidence[0].path if finding.evidence else finding.component
        file_counts[path] = file_counts.get(path, 0) + 1

    standards = []
    for key in _CONCERN_ORDER:
        items = []
        for entry in by_concern[key]:
            paths = entry.direct_components + entry.indirect_components + entry.declared_dependencies
            hits = sum(1 for finding in direct if finding.name == entry.mechanism and finding.concern == key)
            spots = _spots(confirmed, entry.mechanism, key)
            items.append(
                {
                    "name": entry.mechanism,
                    "plain": _plain(entry.mechanism, entry.concern),
                    "where": _where(paths),
                    "count": hits or len(paths),
                    "locations": spots,
                }
            )
        standards.append(
            {
                "key": key,
                "title": _CONCERN_LABEL[key],
                "guidance": _GUIDANCE[key],
                "items": items,
            }
        )

    updates = []
    for item in result.checklist:
        if item.confidence != "confirmed":
            continue
        if item.concern not in {"urgent", "plan"}:
            continue
        where = ""
        snippet = ""
        line = None
        path = ""
        if item.evidence:
            evidence = item.evidence[0]
            path = evidence.path
            line = evidence.line
            snippet = evidence.snippet
            where = f"{evidence.path}:{evidence.line}" if evidence.line else evidence.path
        updates.append(
            {
                "priority": item.priority,
                "title": item.name,
                "kind": item.kind,
                "concern": item.concern,
                "why": item.why,
                "action": item.actions[0] if item.actions else "",
                "gate": item.validation_gate,
                "where": where,
                "path": path,
                "line": line,
                "snippet": snippet,
                "count": item.finding_count,
            }
        )
        if len(updates) >= 12:
            break

    hidden = []
    for entry in result.inventory:
        for path in entry.indirect_components:
            origin = next(
                (
                    finding.via
                    for finding in result.findings
                    if finding.usage == "indirect"
                    and finding.name == entry.mechanism
                    and finding.component == path
                    and finding.via
                ),
                "another file",
            )
            hidden.append({"caller": path, "origin": origin or "another file", "mechanism": entry.mechanism})
            if len(hidden) >= 12:
                break
        if len(hidden) >= 12:
            break

    findings = []
    for finding in result.findings:
        evidence = finding.evidence[0] if finding.evidence else None
        path = evidence.path if evidence else finding.component
        line = evidence.line if evidence else None
        snippet = evidence.snippet if evidence else ""
        where = f"{path}:{line}" if line else path
        findings.append(
            {
                "name": finding.name,
                "concern": finding.concern,
                "confidence": finding.confidence,
                "usage": _USAGE_LABEL.get(finding.underlying_usage, finding.underlying_usage),
                "where": where,
                "path": path,
                "line": line,
                "snippet": snippet,
                "summary": finding.summary,
                "hint": finding.migration_hint,
                "plain": _plain(finding.name, finding.concern),
            }
        )
        if len(findings) >= 400:
            break

    urgent_names = [entry.mechanism for entry in by_concern["urgent"]]
    plan_names = [entry.mechanism for entry in by_concern["plan"]]
    return {
        "root": result.root,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "disclaimer": result.disclaimer,
        "headline": _headline(len(urgent_names), len(plan_names), len(confirmed)),
        "narrative": _narrative(result, urgent_names, plan_names, len(uncertain)),
        "counts": {
            "confirmed": len(confirmed),
            "uncertain": len(uncertain),
            "files": result.files_scanned,
            "retire": len(urgent_names),
            "plan": len(plan_names),
            "keep": len(by_concern["monitor"]),
            "libraries": len(by_concern["informational"]),
        },
        "charts": {
            "concern": [
                {"key": key, "label": _CONCERN_LABEL[key], "count": concern_counts.get(key, 0)}
                for key in _CONCERN_ORDER
                if concern_counts.get(key, 0)
            ],
            "usage": [
                {"key": key, "label": _USAGE_LABEL.get(key, key), "count": count}
                for key, count in sorted(usage_counts.items(), key=lambda pair: (-pair[1], pair[0]))
            ],
            "files": [
                {"label": path, "count": count}
                for path, count in sorted(file_counts.items(), key=lambda pair: (-pair[1], pair[0]))[:8]
            ],
        },
        "standards": standards,
        "updates": updates,
        "hidden": hidden,
        "risks": list(result.compatibility_risks)[:6],
        "checks": list(result.testing_steps)[:6],
        "limitations": list(result.limitations)[:8],
        "findings": findings,
        "findings_truncated": len(result.findings) > len(findings),
    }


def analyze_directory(raw: str) -> dict:
    try:
        path = Path(raw).expanduser().resolve()
    except OSError as exc:
        raise ScanRequestError(f"Cannot read that path: {exc}") from exc
    if path == Path(path.anchor):
        raise ScanRequestError("Choose a project folder, not the whole disk.")
    if not path.is_dir():
        raise ScanRequestError(f"Not a folder: {path}")
    return build_analysis(scan_path(path))
