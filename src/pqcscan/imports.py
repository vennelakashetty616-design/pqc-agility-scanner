from __future__ import annotations

import re
from collections import defaultdict, deque

from pqcscan.discover import SourceFile
from pqcscan.models import Evidence, Finding


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _module_paths(parts: list[str], available: set[str]) -> list[str]:
    if not parts:
        return []
    rel_py = "/".join(parts) + ".py"
    rel_init = "/".join(parts) + "/__init__.py"
    found = []
    if rel_py in available:
        found.append(rel_py)
    if rel_init in available:
        found.append(rel_init)
    return found


def _resolve_python(relative: str, module: str, level: int, available: set[str]) -> list[str]:
    parts = [part for part in module.split(".") if part] if module else []
    parent = relative.rsplit("/", 1)[0] if "/" in relative else ""
    parent_parts = parent.split("/") if parent else []
    if level:
        up = level - 1
        base = parent_parts[: len(parent_parts) - up] if up else parent_parts
        if up > len(parent_parts):
            base = []
        return _module_paths(base + parts, available)
    for index in range(len(parent_parts), -1, -1):
        found = _module_paths(parent_parts[:index] + parts, available)
        if found:
            return found
    if not parts:
        return []
    suffix = "/".join(parts) + ".py"
    init_suffix = "/".join(parts) + "/__init__.py"
    return _unique([rel for rel in available if rel.endswith(suffix) or rel.endswith(init_suffix)])


def _python_edges(source: SourceFile, available: set[str]) -> list[tuple[int, str]]:
    edges: list[tuple[int, str]] = []
    for number, line in enumerate(source.text.splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        relative_import = re.match(r"from\s+(\.+)([\w.]*)\s+import\s+(.+)", stripped)
        if relative_import:
            dots, module, _names = relative_import.groups()
            for target in _resolve_python(source.relative, module, len(dots), available):
                edges.append((number, target))
            continue
        plain_from = re.match(r"from\s+([\w.]+)\s+import\s+(.+)", stripped)
        if plain_from:
            for target in _resolve_python(source.relative, plain_from.group(1), 0, available):
                edges.append((number, target))
            continue
        plain_import = re.match(r"import\s+([\w.]+(?:\s*,\s*[\w.]+)*)", stripped)
        if plain_import:
            for part in re.split(r"\s*,\s*", plain_import.group(1)):
                name = part.split(" as ")[0].strip()
                for target in _resolve_python(source.relative, name, 0, available):
                    edges.append((number, target))
    return edges


def _js_edges(source: SourceFile, available: set[str]) -> list[tuple[int, str]]:
    pattern = re.compile(
        r"""(?:require\(\s*['\"](\.[^'\"]+)['\"]|import\s+(?:[\w*\s{},]+from\s+)?['\"](\.[^'\"]+)['\"])"""
    )
    edges: list[tuple[int, str]] = []
    parent = source.relative.rsplit("/", 1)[0] if "/" in source.relative else ""
    for number, line in enumerate(source.text.splitlines(), start=1):
        for match in pattern.finditer(line):
            raw = match.group(1) or match.group(2)
            edges.extend((number, target) for target in _resolve_relative_script(parent, raw, available))
    return edges


def _resolve_relative_script(parent: str, raw: str, available: set[str]) -> list[str]:
    pieces = [] if not parent else parent.split("/")
    for part in raw.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if pieces:
                pieces.pop()
            continue
        pieces.append(part)
    base = "/".join(pieces)
    candidates = [
        base,
        base + ".js",
        base + ".mjs",
        base + ".ts",
        base + ".tsx",
        base + "/index.js",
        base + "/index.ts",
    ]
    return [item for item in candidates if item in available]


def _go_imports(text: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    in_block = False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("import ("):
            in_block = True
            continue
        if in_block:
            if stripped.startswith(")"):
                in_block = False
                continue
            if stripped.startswith("//"):
                continue
            match = re.search(r'"([^"]+)"', stripped)
            if match:
                found.append((number, match.group(1)))
            continue
        match = re.match(r'import\s+(?:\w+\s+)?"([^"]+)"', stripped)
        if match:
            found.append((number, match.group(1)))
    return found


def _go_edges(source: SourceFile, files: list[SourceFile]) -> list[tuple[int, str]]:
    directories: dict[str, list[str]] = defaultdict(list)
    for item in files:
        if item.path.suffix.lower() != ".go":
            continue
        parent = item.relative.rsplit("/", 1)[0] if "/" in item.relative else ""
        directories[parent].append(item.relative)
    edges: list[tuple[int, str]] = []
    for number, import_path in _go_imports(source.text):
        for directory in _match_go_directory(import_path, directories):
            for relative in directories[directory]:
                if relative != source.relative:
                    edges.append((number, relative))
    return edges


def _match_go_directory(import_path: str, directories: dict[str, list[str]]) -> list[str]:
    parts = [part for part in import_path.split("/") if part]
    for index in range(len(parts)):
        suffix = "/".join(parts[index:])
        if suffix in directories:
            return [suffix]
    return []


def build_import_edges(files: list[SourceFile]) -> dict[str, list[tuple[int, str]]]:
    available = {item.relative for item in files}
    edges: dict[str, list[tuple[int, str]]] = {}
    for source in files:
        suffix = source.path.suffix.lower()
        if suffix == ".py":
            found = _python_edges(source, available)
        elif suffix in {".js", ".mjs", ".ts", ".tsx"}:
            found = _js_edges(source, available)
        elif suffix == ".go":
            found = _go_edges(source, files)
        else:
            found = []
        if found:
            edges[source.relative] = found
    return edges


def infer_indirect(
    findings: list[Finding],
    edges: dict[str, list[tuple[int, str]]],
    line_map: dict[str, list[str]],
) -> list[Finding]:
    direct: dict[str, list[Finding]] = defaultdict(list)
    direct_names: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for finding in findings:
        if finding.confidence != "confirmed" or finding.usage in {"indirect", "declared_dependency"}:
            continue
        if finding.kind in {"certificate", "secret_material"}:
            continue
        if not finding.evidence:
            continue
        path = finding.evidence[0].path
        direct[path].append(finding)
        direct_names[path].add((finding.name, finding.kind))

    reverse: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for importer, deps in edges.items():
        for line, imported in deps:
            reverse[imported].append((importer, line))

    indirect: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for origin, origin_findings in direct.items():
        queue: deque[tuple[str, int]] = deque([(origin, 0)])
        visited = {origin}
        while queue:
            current, depth = queue.popleft()
            if depth >= 5:
                continue
            for importer, line in reverse.get(current, []):
                if importer in visited:
                    continue
                visited.add(importer)
                queue.append((importer, depth + 1))
                snippet = ""
                rows = line_map.get(importer, [])
                if 1 <= line <= len(rows):
                    snippet = " ".join(rows[line - 1].strip().split())[:180]
                for finding in origin_findings:
                    if (finding.name, finding.kind) in direct_names.get(importer, set()):
                        continue
                    key = (importer, finding.name, finding.kind, origin)
                    if key in seen:
                        continue
                    seen.add(key)
                    indirect.append(
                        Finding(
                            rule_id=f"{finding.rule_id}-indirect",
                            name=finding.name,
                            kind=finding.kind,
                            usage="indirect",
                            underlying_usage=finding.underlying_usage,
                            concern=finding.concern,
                            confidence="confirmed",
                            summary=(
                                f"Indirect {finding.name} via {origin}. "
                                "The direct call or configuration is in that file. This file depends on it."
                            ),
                            migration_hint=finding.migration_hint,
                            quantum_relevance=finding.quantum_relevance,
                            component=importer,
                            evidence=[Evidence(importer, line, snippet or f"import dependency on {origin}")]
                            + list(finding.evidence),
                            via=origin,
                        )
                    )
    return indirect
