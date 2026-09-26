from __future__ import annotations

import json

from pqcscan.models import ScanResult


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _counts(result: ScanResult) -> dict[str, int]:
    counts = {
        "confirmed": 0,
        "uncertain": 0,
        "urgent": 0,
        "plan": 0,
        "monitor": 0,
        "informational": 0,
    }
    for finding in result.findings:
        counts[finding.confidence] = counts.get(finding.confidence, 0) + 1
        counts[finding.concern] = counts.get(finding.concern, 0) + 1
    return counts


def render_markdown(result: ScanResult) -> str:
    counts = _counts(result)
    lines = [
        "# Post-quantum cryptography migration inventory",
        "",
        f"> {result.disclaimer}",
        "",
        "## Scope",
        "",
        f"- Root: `{result.root}`",
        f"- Files scanned: {result.files_scanned}",
        f"- Files skipped: {result.files_skipped}",
        f"- Confirmed findings: {counts['confirmed']}",
        f"- Uncertain matches: {counts['uncertain']}",
        f"- Concern mix: urgent {counts['urgent']}, plan {counts['plan']}, monitor {counts['monitor']}, informational {counts['informational']}",
        "",
        "Confirmed findings have an API, a parsed certificate, a known dependency, or a specific protocol token. Uncertain matches are names or comments and stay in their own list.",
        "",
        "## Dependency inventory",
        "",
        "| Mechanism | Kind | Concern | Direct | Indirect | Declared | Uncertain |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    if not result.inventory:
        lines.append("| none |  |  |  |  |  |  |")
    for entry in result.inventory:
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(entry.mechanism),
                    _cell(entry.kind),
                    entry.concern,
                    str(len(entry.direct_components)),
                    str(len(entry.indirect_components)),
                    str(len(entry.declared_dependencies)),
                    str(len(entry.uncertain_components)),
                ]
            )
            + " |"
        )
    lines.extend(["", "Components below are file paths in the scanned tree.", ""])
    for entry in result.inventory:
        lines.append(f"### {entry.mechanism} ({entry.kind})")
        lines.append("")
        if entry.direct_components:
            lines.append("Direct: " + ", ".join(f"`{path}`" for path in entry.direct_components))
        if entry.indirect_components:
            lines.append("Indirect: " + ", ".join(f"`{path}`" for path in entry.indirect_components))
        if entry.declared_dependencies:
            lines.append("Declared dependencies: " + ", ".join(f"`{path}`" for path in entry.declared_dependencies))
        if entry.uncertain_components:
            lines.append("Uncertain: " + ", ".join(f"`{path}`" for path in entry.uncertain_components))
        lines.append("")

    uncertain = [item for item in result.checklist if item.confidence != "confirmed"]
    lines.extend(
        [
            "## Migration checklist",
            "",
            "Items are ordered by concern. Confirmed entries come before uncertain entries at the same concern. An uncertain entry is a review item, not a confirmed defect.",
            "",
        ]
    )
    lines.extend(_checklist_section(result.checklist))
    lines.extend(["## Uncertain matches", ""])
    if not uncertain:
        lines.extend(["None.", ""])
    else:
        lines.append("Review these before scheduling work. The same items appear in the checklist above.")
        lines.append("")
        for item in uncertain:
            evidence = item.evidence[0] if item.evidence else None
            where = f"`{evidence.path}:{evidence.line}`" if evidence and evidence.line else ""
            lines.append(f"- {item.priority}. {item.title} {where}".rstrip())
        lines.append("")

    lines.extend(["## Hybrid deployment options", ""])
    lines.append("These options are high-level planning models. They identify interoperability concerns. They are not code to deploy.")
    lines.append("")
    for option in result.hybrid_options:
        lines.append(f"### {option.title}")
        lines.append("")
        lines.append(option.pattern)
        lines.append("")
        lines.append(f"Status: {option.status}")
        lines.append("")
        lines.append(f"Why it appears: {option.applies_because}")
        lines.append("")
        for note in option.interoperability:
            lines.append(f"- {note}")
        lines.append("")

    lines.extend(
        [
            "## Migration graph",
            "",
            "The first diagram is the suggested review order and its validation gates. The second diagram links inventoried files to mechanisms. Neither diagram proves a safe cutover.",
            "",
            "```mermaid",
            result.migration_graph,
            "```",
            "",
            "## Limitations",
            "",
        ]
    )
    for item in result.limitations:
        lines.append(f"- {item}")
    lines.extend(["", "## Compatibility risks", ""])
    for item in result.compatibility_risks:
        lines.append(f"- {item}")
    lines.extend(["", "## Testing steps", ""])
    for index, item in enumerate(result.testing_steps, start=1):
        lines.append(f"{index}. {item}")
    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("No cryptographic mechanisms were detected in this tree. That is not a quantum-safety attestation.")
    for finding in result.findings:
        location = finding.evidence[0] if finding.evidence else None
        where = f"{location.path}:{location.line}" if location and location.line else finding.component
        via = f" via `{finding.via}`" if finding.via else ""
        lines.append(
            f"- `{finding.finding_id}` {finding.confidence} {finding.concern} **{finding.name}** "
            f"({finding.kind}, {finding.usage}) at `{where}`{via}"
        )
        lines.append(f"  - {finding.summary}")
    lines.extend(["", result.disclaimer, ""])
    return "\n".join(lines)


def _checklist_section(items: list) -> list[str]:
    if not items:
        return ["None.", ""]
    lines: list[str] = []
    for item in items:
        lines.append(f"### {item.priority}. {item.title}")
        lines.append("")
        lines.append(f"Concern: {item.concern}. Confidence: {item.confidence}. Findings: {item.finding_count}.")
        lines.append("")
        lines.append(item.why)
        lines.append("")
        lines.append("Actions:")
        for action in item.actions:
            lines.append(f"- {action}")
        lines.append("")
        lines.append(f"Validation: {item.validation_gate}")
        lines.append("")
        if item.evidence:
            lines.append("Evidence:")
            for evidence in item.evidence[:6]:
                line = f":{evidence.line}" if evidence.line else ""
                lines.append(f"- `{evidence.path}{line}` {_cell(evidence.snippet)}")
            if len(item.evidence) > 6 or item.finding_count > len(item.evidence):
                lines.append("- Further evidence is in report.json.")
            lines.append("")
    return lines


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2) + "\n"
