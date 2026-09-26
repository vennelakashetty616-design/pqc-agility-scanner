from __future__ import annotations

import re
from dataclasses import dataclass

from pqcscan.catalog import Rule, rules
from pqcscan.discover import SourceFile
from pqcscan.models import Evidence, Finding


@dataclass
class Region:
    line: int
    text: str
    kind: str


def _split_hash_comment(line: str) -> tuple[str, str]:
    in_single = False
    in_double = False
    escape = False
    for index, char in enumerate(line):
        if escape:
            escape = False
            continue
        if char == "\\" and (in_single or in_double):
            escape = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if char == "#" and not in_single and not in_double:
            return line[:index], line[index:]
    return line, ""


def _split_slash_comment(line: str, in_block: bool) -> tuple[str, str, bool]:
    if in_block:
        end = line.find("*/")
        if end == -1:
            return "", line, True
        comment = line[: end + 2]
        code_rest, comment_rest, still = _split_slash_comment(line[end + 2 :], False)
        return code_rest, comment + comment_rest, still
    code_chars: list[str] = []
    comment_chars: list[str] = []
    in_single = False
    in_double = False
    escape = False
    index = 0
    while index < len(line):
        char = line[index]
        nxt = line[index + 1] if index + 1 < len(line) else ""
        if escape:
            code_chars.append(char)
            escape = False
            index += 1
            continue
        if char == "\\" and (in_single or in_double):
            code_chars.append(char)
            escape = True
            index += 1
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            code_chars.append(char)
            index += 1
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            code_chars.append(char)
            index += 1
            continue
        if not in_single and not in_double and char == "/" and nxt == "/":
            comment_chars.append(line[index:])
            break
        if not in_single and not in_double and char == "/" and nxt == "*":
            end = line.find("*/", index + 2)
            if end == -1:
                comment_chars.append(line[index:])
                return "".join(code_chars), "".join(comment_chars), True
            comment_chars.append(line[index : end + 2])
            index = end + 2
            continue
        code_chars.append(char)
        index += 1
    return "".join(code_chars), "".join(comment_chars), False


def iter_regions(source: SourceFile) -> list[Region]:
    suffix = source.path.suffix.lower()
    name = source.path.name.lower()
    regions: list[Region] = []
    if suffix in {".js", ".mjs", ".ts", ".tsx", ".java", ".go", ".c", ".h", ".cs"}:
        in_block = False
        for number, line in enumerate(source.text.splitlines(), start=1):
            code, comment, in_block = _split_slash_comment(line, in_block)
            if code.strip():
                regions.append(Region(number, code, "code"))
            if comment.strip():
                regions.append(Region(number, comment, "comment"))
        return regions
    hash_comments = suffix in {
        ".py",
        ".yaml",
        ".yml",
        ".conf",
        ".cnf",
        ".cfg",
        ".ini",
        ".env",
        ".toml",
        ".rb",
        ".sh",
    } or name in {"ssh_config", "dockerfile"}
    if hash_comments:
        for number, line in enumerate(source.text.splitlines(), start=1):
            code, comment = _split_hash_comment(line)
            kind = "config" if source.category == "config" else "code"
            if code.strip():
                regions.append(Region(number, code, kind))
            if comment.strip():
                regions.append(Region(number, comment, "comment"))
        return regions
    kind = "config" if source.category == "config" else "code"
    for number, line in enumerate(source.text.splitlines(), start=1):
        if line.strip():
            regions.append(Region(number, line, kind))
    return regions


def _snippet(line: str) -> str:
    compact = " ".join(line.strip().split())
    if len(compact) > 180:
        return compact[:177] + "..."
    return compact


def _concern_for_key_size(name: str, default: str, match: re.Match[str], text: str) -> tuple[str, str, str]:
    if name != "RSA-key-size":
        return name, default, ""
    size = next((group for group in match.groups() if group), None)
    if size is None:
        found = re.search(r"\b(1024|2048|3072|4096)\b", text)
        size = found.group(1) if found else None
    if size is None:
        return name, default, ""
    concern = "urgent" if int(size) < 2048 else "plan"
    return f"RSA-{size}", concern, f" Explicit size {size} bits."


def _compile(rule_list: list[Rule]) -> list[tuple[Rule, re.Pattern[str]]]:
    compiled = []
    for rule in rule_list:
        compiled.append((rule, re.compile(rule.pattern)))
    return compiled


_COMPILED = _compile(rules())


def _covered(weak_name: str, strong: list[Finding]) -> bool:
    needle = weak_name.casefold()
    for finding in strong:
        blob = f"{finding.name} {finding.evidence[0].snippet if finding.evidence else ''}".casefold()
        if needle in blob:
            return True
    return False


def scan_text(source: SourceFile) -> list[Finding]:
    if source.category in {"manifest", "certificate"}:
        return []
    by_line_strong: dict[int, list[Finding]] = {}
    by_line_weak: dict[int, list[Finding]] = {}
    seen: set[tuple[str, int, str]] = set()
    for region in iter_regions(source):
        for rule, pattern in _COMPILED:
            if rule.tier == "strong" and region.kind == "comment":
                continue
            if rule.tier == "weak" and region.kind == "comment":
                pass
            match = pattern.search(region.text)
            if not match:
                continue
            key = (rule.rule_id, region.line, rule.tier)
            if key in seen:
                continue
            seen.add(key)
            name, concern, extra = _concern_for_key_size(rule.name, rule.concern, match, region.text)
            confidence = "confirmed" if rule.tier == "strong" else "uncertain"
            summary = rule.summary + extra
            if rule.tier == "weak" and region.kind == "config" and rule.rule_id in {
                "weak-mlkem",
                "weak-mldsa",
                "weak-slh",
            }:
                confidence = "confirmed"
                summary = (
                    f"{name} is set in configuration. Confirm a vetted implementation and peer support. "
                    "A configured name does not prove quantum safety."
                )
            elif rule.tier == "weak":
                summary = (
                    rule.summary
                    + " Uncertain match. Confirm real cryptographic use before scheduling migration work."
                )
            finding = Finding(
                rule_id=rule.rule_id,
                name=name,
                kind=rule.kind,
                usage=rule.usage,
                underlying_usage=rule.usage,
                concern=concern,
                confidence=confidence,
                summary=summary,
                migration_hint=rule.migration_hint,
                quantum_relevance=rule.quantum_relevance,
                component=source.relative,
                evidence=[Evidence(source.relative, region.line, _snippet(region.text))],
            )
            bucket = by_line_strong if rule.tier == "strong" else by_line_weak
            bucket.setdefault(region.line, []).append(finding)
    findings: list[Finding] = []
    lines = set(by_line_strong) | set(by_line_weak)
    for line in sorted(lines):
        strong = by_line_strong.get(line, [])
        findings.extend(strong)
        for finding in by_line_weak.get(line, []):
            if strong and _covered(finding.name, strong):
                continue
            if any(item.name.casefold() == finding.name.casefold() and item.confidence == "confirmed" for item in strong):
                continue
            findings.append(finding)
    return findings
