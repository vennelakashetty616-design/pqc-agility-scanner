from __future__ import annotations

from pqcscan.models import InventoryEntry, Finding

_CONCERN_RANK = {"urgent": 0, "plan": 1, "monitor": 2, "informational": 3}


def _worse(current: str, new: str) -> str:
    if _CONCERN_RANK.get(new, 9) < _CONCERN_RANK.get(current, 9):
        return new
    return current


def _add(bucket: list[str], value: str) -> None:
    if value not in bucket:
        bucket.append(value)


def build_inventory(findings: list[Finding]) -> list[InventoryEntry]:
    grouped: dict[tuple[str, str], InventoryEntry] = {}
    for finding in findings:
        key = (finding.name, finding.kind)
        entry = grouped.get(key)
        if entry is None:
            entry = InventoryEntry(mechanism=finding.name, kind=finding.kind, concern=finding.concern)
            grouped[key] = entry
        entry.concern = _worse(entry.concern, finding.concern)
        path = finding.component
        if finding.confidence == "uncertain":
            _add(entry.uncertain_components, path)
        elif finding.usage == "indirect":
            _add(entry.indirect_components, path)
        elif finding.usage == "declared_dependency":
            _add(entry.declared_dependencies, path)
        else:
            _add(entry.direct_components, path)
    entries = list(grouped.values())
    entries.sort(key=lambda item: (_CONCERN_RANK.get(item.concern, 9), item.kind, item.mechanism))
    return entries
