from __future__ import annotations

import json
import re

from pqcscan.catalog import Q_LIBRARY
from pqcscan.discover import SourceFile
from pqcscan.models import Evidence, Finding

# Normalized package names. These are inventory labels, not an allow-list of safe libraries.
_PACKAGES: dict[str, tuple[str, str, str]] = {
    "pycrypto": (
        "PyCrypto",
        "urgent",
        "PyCrypto is unmaintained. Plan a move to a maintained vetted library. Do not copy ciphers into application code.",
    ),
    "pycryptodome": (
        "PyCryptodome",
        "plan",
        "PyCryptodome is a classical crypto dependency. Inventory the algorithms the application asks it to run.",
    ),
    "cryptography": (
        "cryptography",
        "informational",
        "The Python cryptography package is a vetted OpenSSL binding. Record which algorithms it is used for. The dependency does not prove quantum safety.",
    ),
    "pyjwt": (
        "PyJWT",
        "plan",
        "JWT library. The alg values in use matter more than the package name.",
    ),
    "python-jose": (
        "python-jose",
        "plan",
        "JOSE library. Inventory signature and encryption algorithms separately.",
    ),
    "pyopenssl": (
        "pyOpenSSL",
        "plan",
        "pyOpenSSL binding. Inventory the protocol versions and cipher configuration it applies.",
    ),
    "m2crypto": (
        "M2Crypto",
        "plan",
        "M2Crypto OpenSSL binding. Confirm it is still maintained for this platform before keeping it.",
    ),
    "ecdsa": (
        "python-ecdsa",
        "plan",
        "Python ECDSA implementation dependency. Inventory curves and verifiers.",
    ),
    "jsonwebtoken": (
        "jsonwebtoken",
        "plan",
        "Node JWT library. Verifiers often allow-list alg identifiers.",
    ),
    "node-forge": (
        "node-forge",
        "plan",
        "JavaScript cryptography implementation. Inventory call sites and prefer a vetted platform library for new work.",
    ),
    "crypto-js": (
        "crypto-js",
        "plan",
        "crypto-js dependency. Mode and key length are call-site facts, not package-name facts.",
    ),
    "node-rsa": (
        "node-rsa",
        "plan",
        "node-rsa dependency. RSA key handling is a post-quantum migration candidate.",
    ),
    "elliptic": (
        "elliptic",
        "plan",
        "elliptic JavaScript dependency. It may arrive transitively. Inventory why it is in the tree.",
    ),
    "jose": (
        "jose",
        "plan",
        "JOSE library dependency. Inventory alg and enc values.",
    ),
    "jws": (
        "jws",
        "plan",
        "jws is commonly pulled in by JWT libraries. Confirm whether application code depends on it directly.",
    ),
    "jwa": (
        "jwa",
        "plan",
        "jwa is commonly pulled in by JWT libraries. Inventory the algorithms it is asked to run.",
    ),
    "golang.org/x/crypto": (
        "golang.org/x/crypto",
        "informational",
        "Go supplementary crypto module. The import path does not identify which subpackages production uses.",
    ),
    "ring": (
        "ring",
        "informational",
        "Rust ring crate. Inventory the algorithms the crate is asked to run.",
    ),
    "rustls": (
        "rustls",
        "informational",
        "rustls TLS library. Protocol version and cipher suites still need an inventory.",
    ),
    "openssl": (
        "openssl-crate",
        "plan",
        "Rust openssl crate binding. Inventory the OpenSSL version and the algorithms it is configured to use.",
    ),
    "sha1": (
        "sha1-crate",
        "urgent",
        "Rust sha1 crate. Retire SHA-1 where collision resistance matters.",
    ),
    "md-5": (
        "md-5-crate",
        "urgent",
        "Rust md-5 crate. Retire MD5 where collision resistance matters.",
    ),
    "des": (
        "des-crate",
        "urgent",
        "Rust des crate. DES is a deprecated classical cipher.",
    ),
    "bouncycastle": (
        "Bouncy Castle",
        "plan",
        "Bouncy Castle dependency. Inventory the algorithms and providers the application requests.",
    ),
    "bcprov-jdk15on": (
        "Bouncy Castle",
        "plan",
        "Bouncy Castle provider artifact. Inventory requested algorithms.",
    ),
}

_NAME_HINTS = ("crypto", "cipher", "openssl", "bouncycastle", "jose", "jwt", "nacl", "sodium", "tls")


def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _finding(source: SourceFile, line: int, package: str, display: str, concern: str, hint: str, summary: str) -> Finding:
    return Finding(
        rule_id=f"manifest-{_normalize(display)}",
        name=display,
        kind="library",
        usage="declared_dependency",
        underlying_usage="library",
        concern=concern,
        confidence="confirmed",
        summary=summary,
        migration_hint=hint,
        quantum_relevance=Q_LIBRARY,
        component=source.relative,
        evidence=[Evidence(source.relative, line, _snippet(package))],
    )


def _snippet(text: str) -> str:
    compact = " ".join(text.strip().split())
    return compact[:180]


def _from_known(source: SourceFile, line: int, raw_name: str) -> Finding | None:
    normalized = _normalize(raw_name)
    leaf = normalized.split("/")[-1]
    info = _PACKAGES.get(normalized) or _PACKAGES.get(leaf)
    if info is None and "bouncycastle" in normalized:
        info = _PACKAGES["bouncycastle"]
    if info is None and normalized.startswith("golang.org/x/crypto"):
        info = _PACKAGES["golang.org/x/crypto"]
    if info is None:
        if any(hint in normalized for hint in _NAME_HINTS):
            return Finding(
                rule_id="manifest-unknown-crypto-name",
                name=raw_name,
                kind="library",
                usage="declared_dependency",
                underlying_usage="library",
                concern="plan",
                confidence="uncertain",
                summary=f"Dependency name {raw_name} looks cryptographic, but it is not in the known package list.",
                migration_hint="Confirm the package and the algorithms it provides before adding it to the migration plan.",
                quantum_relevance=Q_LIBRARY,
                component=source.relative,
                evidence=[Evidence(source.relative, line, _snippet(raw_name))],
            )
        return None
    display, concern, hint = info
    return _finding(
        source,
        line,
        raw_name,
        display,
        concern,
        hint,
        f"Declared dependency {raw_name}.",
    )


def _scan_requirements(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")
    for number, line in enumerate(source.text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = pattern.match(stripped)
        if not match:
            continue
        found = _from_known(source, number, match.group(1))
        if found:
            findings.append(found)
    return findings


def _scan_package_json(source: SourceFile) -> list[Finding]:
    try:
        data = json.loads(source.text)
    except json.JSONDecodeError:
        return [
            Finding(
                rule_id="manifest-unparsed-json",
                name="Unparsed package.json",
                kind="library",
                usage="declared_dependency",
                underlying_usage="library",
                concern="plan",
                confidence="uncertain",
                summary="package.json could not be parsed, so dependencies may be missing from the inventory.",
                migration_hint="Fix the JSON and re-scan. Do not assume an empty inventory.",
                quantum_relevance=Q_LIBRARY,
                component=source.relative,
                evidence=[Evidence(source.relative, 1, "package.json")],
            )
        ]
    findings: list[Finding] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name in block:
            line = _line_of(source.text, name)
            found = _from_known(source, line, name)
            if found:
                findings.append(found)
    return findings


def _scan_package_lock(source: SourceFile) -> list[Finding]:
    try:
        data = json.loads(source.text)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue
            name = path.split("node_modules/")[-1]
            if not name or name == path and "node_modules" not in path:
                continue
            line = _line_of(source.text, name)
            found = _from_known(source, line, name)
            if found:
                found.summary = f"Lockfile dependency {name}. It may be direct or transitive."
                findings.append(found)
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        for name in dependencies:
            line = _line_of(source.text, name)
            found = _from_known(source, line, name)
            if found:
                found.summary = f"Lockfile dependency {name}. It may be direct or transitive."
                findings.append(found)
    return findings


def _scan_go_mod(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"([A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+)\s+v\d")
    for number, line in enumerate(source.text.splitlines(), start=1):
        if line.strip().startswith("//"):
            continue
        for match in pattern.finditer(line):
            found = _from_known(source, number, match.group(1))
            if found:
                findings.append(found)
    return findings


def _scan_cargo(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*=\s*"')
    for number, line in enumerate(source.text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("["):
            continue
        match = pattern.match(line)
        if not match:
            continue
        found = _from_known(source, number, match.group(1))
        if found:
            findings.append(found)
    return findings


def _scan_xml_or_gradle(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for number, line in enumerate(source.text.splitlines(), start=1):
        if "bouncycastle" in line.lower() or "bcprov" in line.lower():
            found = _from_known(source, number, "bouncycastle")
            if found and found.name not in seen:
                seen.add(found.name)
                findings.append(found)
    return findings


def _scan_pyproject(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(source.text.splitlines(), start=1):
        if line.strip().startswith("#"):
            continue
        for name in _PACKAGES:
            if re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", line.lower()):
                found = _from_known(source, number, name)
                if found:
                    findings.append(found)
    return findings


def _line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    return 1


def scan_manifest(source: SourceFile) -> list[Finding]:
    name = source.path.name.lower()
    if name in {"requirements.txt", "requirements-dev.txt"}:
        return _scan_requirements(source)
    if name == "package.json":
        return _scan_package_json(source)
    if name == "package-lock.json":
        return _scan_package_lock(source)
    if name == "go.mod":
        return _scan_go_mod(source)
    if name == "cargo.toml":
        return _scan_cargo(source)
    if name in {"pom.xml", "build.gradle", "build.gradle.kts"}:
        return _scan_xml_or_gradle(source)
    if name == "pyproject.toml":
        return _scan_pyproject(source)
    return _scan_requirements(source)
