from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Evidence:
    path: str
    line: int | None
    snippet: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    rule_id: str
    name: str
    kind: str
    usage: str
    underlying_usage: str
    concern: str
    confidence: str
    summary: str
    migration_hint: str
    quantum_relevance: str
    component: str
    evidence: list[Evidence] = field(default_factory=list)
    via: str | None = None
    finding_id: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        return data


@dataclass
class InventoryEntry:
    mechanism: str
    kind: str
    concern: str
    direct_components: list[str] = field(default_factory=list)
    indirect_components: list[str] = field(default_factory=list)
    declared_dependencies: list[str] = field(default_factory=list)
    uncertain_components: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ChecklistItem:
    priority: int
    title: str
    name: str
    kind: str
    concern: str
    confidence: str
    why: str
    actions: list[str]
    validation_gate: str
    evidence: list[Evidence] = field(default_factory=list)
    finding_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HybridOption:
    option_id: str
    title: str
    pattern: str
    status: str
    applies_because: str
    interoperability: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    files_scanned: int
    files_skipped: int
    findings: list[Finding]
    inventory: list[InventoryEntry]
    checklist: list[ChecklistItem]
    hybrid_options: list[HybridOption]
    migration_graph: str
    limitations: list[str]
    compatibility_risks: list[str]
    testing_steps: list[str]
    disclaimer: str

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "disclaimer": self.disclaimer,
            "findings": [item.to_dict() for item in self.findings],
            "inventory": [item.to_dict() for item in self.inventory],
            "checklist": [item.to_dict() for item in self.checklist],
            "hybrid_options": [item.to_dict() for item in self.hybrid_options],
            "migration_graph": self.migration_graph,
            "limitations": list(self.limitations),
            "compatibility_risks": list(self.compatibility_risks),
            "testing_steps": list(self.testing_steps),
        }
