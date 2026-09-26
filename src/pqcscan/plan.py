from __future__ import annotations

from pqcscan.disclaimer import DISCLAIMER
from pqcscan.models import ChecklistItem, Evidence, Finding, HybridOption, InventoryEntry

_CONCERN_RANK = {"urgent": 0, "plan": 1, "monitor": 2, "informational": 3}
_CONFIDENCE_RANK = {"confirmed": 0, "uncertain": 1}


def _gate(concern: str, confidence: str) -> str:
    if confidence == "uncertain":
        return "Gate: a reviewer confirms or dismisses this match. Do not schedule a cutover from an uncertain string match."
    if concern == "urgent":
        return "Gate: staging configuration and tests show the deprecated mechanism is absent, and the oldest supported client still works."
    if concern == "plan":
        return "Gate: an owner, a confidentiality lifetime, and an interoperability note are recorded before any algorithm change."
    if concern == "monitor":
        return "Gate: the mechanism has an owner and a written reason it remains."
    return "Gate: confirm whether the name is an active dependency or only a mention."


def build_checklist(findings: list[Finding]) -> list[ChecklistItem]:
    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for finding in findings:
        groups.setdefault((finding.name, finding.kind, finding.confidence), []).append(finding)
    items: list[ChecklistItem] = []
    for (name, kind, confidence), group in groups.items():
        concern = min(group, key=lambda item: _CONCERN_RANK.get(item.concern, 9)).concern
        evidence: list[Evidence] = []
        for finding in group:
            for item in finding.evidence:
                if len(evidence) >= 12:
                    break
                evidence.append(item)
        hint = group[0].migration_hint
        why = group[0].quantum_relevance
        actions = [
            hint,
            "Keep confirmed findings and uncertain matches in separate review queues.",
            "Re-scan after the change. Update the CI baseline only when the difference is intentional.",
        ]
        items.append(
            ChecklistItem(
                priority=0,
                title=f"{name} ({kind})",
                name=name,
                kind=kind,
                concern=concern,
                confidence=confidence,
                why=why,
                actions=actions,
                validation_gate=_gate(concern, confidence),
                evidence=evidence,
                finding_count=len(group),
            )
        )
    items.sort(key=lambda item: (_CONCERN_RANK.get(item.concern, 9), _CONFIDENCE_RANK.get(item.confidence, 9), item.title))
    for index, item in enumerate(items, start=1):
        item.priority = index
    return items


def build_hybrid_options(findings: list[Finding]) -> list[HybridOption]:
    confirmed = [item for item in findings if item.confidence == "confirmed"]
    public_key = [
        item
        for item in confirmed
        if item.underlying_usage in {"key_agreement", "keygen", "signature", "certificate"}
        or item.kind in {"certificate", "key_size"}
        or item.name.startswith("TLS")
        or "RSA" in item.name
        or "ECD" in item.name
    ]
    symmetric = [
        item
        for item in confirmed
        if item.underlying_usage in {"bulk_encryption", "mac", "hash"} or item.name.startswith("AES") or item.name.startswith("SHA")
    ]
    options: list[HybridOption] = []
    if public_key:
        options.append(
            HybridOption(
                option_id="hybrid-key-establishment",
                title="Hybrid classical and post-quantum key establishment",
                pattern=(
                    "Combine a classical key agreement such as X25519 or ECDH with a post-quantum KEM "
                    "such as ML-KEM, so the session secret depends on both results."
                ),
                status="Planning model only. This tool does not implement the combiner or any post-quantum algorithm.",
                applies_because="The inventory has confirmed public-key, certificate, TLS, or key-generation use.",
                interoperability=[
                    "Both peers must agree on one named hybrid group or combiner.",
                    "A silent fallback to classical-only key establishment is a downgrade path.",
                    "Older TLS stacks and middleboxes may reject unknown groups.",
                    "Post-quantum keys and ciphertexts are larger. Check handshake and token limits.",
                    "Use a vetted implementation such as a current OpenSSL or liboqs build. Do not write a KEM for this plan.",
                ],
            )
        )
        options.append(
            HybridOption(
                option_id="hybrid-signatures",
                title="Hybrid or composite signatures and certificates",
                pattern=(
                    "Carry a classical signature and a post-quantum signature such as ML-DSA or SLH-DSA "
                    "during a transition, either as a composite object or as parallel chains."
                ),
                status="Planning model only. This tool does not build composite certificates.",
                applies_because="The inventory has confirmed signatures, certificate keys, or public-key generation.",
                interoperability=[
                    "Verifiers that understand only the classical algorithm need a transition path.",
                    "Certificate authorities, HSMs, and transparency logs may not accept the new object.",
                    "Composite certificates and parallel chains are different deployments. Pick one and test it.",
                    "Signature size grows. Confirm protocol message limits before a cutover.",
                ],
            )
        )
    if symmetric:
        options.append(
            HybridOption(
                option_id="symmetric-inventory",
                title="Symmetric algorithms stay on a separate track",
                pattern=(
                    "Keep AES-256-GCM and a current hash on the inventory while public-key migration is planned. "
                    "AES-128 has a smaller margin and should be listed with the peers that require it."
                ),
                status="Planning note. This is not a claim that any symmetric algorithm is quantum-safe.",
                applies_because="The inventory has confirmed symmetric encryption, MACs, or hashes.",
                interoperability=[
                    "Changing a hash or cipher identifier breaks stored tokens and peers until every consumer is updated.",
                    "A symmetric change does not replace a quantum-vulnerable key-establishment step.",
                ],
            )
        )
    if not options:
        options.append(
            HybridOption(
                option_id="no-confirmed-public-key",
                title="No hybrid option was selected from confirmed findings",
                pattern="The scan did not confirm a public-key or symmetric mechanism to attach a hybrid plan to.",
                status="This absence is not a quantum-safety result.",
                applies_because="No confirmed cryptographic mechanism matched the hybrid selectors.",
                interoperability=["Re-run the scan when runtime configuration, HSMs, or private repositories are in scope."],
            )
        )
    return options


def _node(label: str) -> str:
    total = 0
    for char in label:
        total = (total * 131 + ord(char)) & 0xFFFFFFFF
    return f"n{total:08x}"


def build_graph(inventory: list[InventoryEntry]) -> str:
    phases = """flowchart TD
  owners["1. Assign an owner to each confirmed inventory row"]
  gateOwners["Gate: every confirmed item has an owner and a confidentiality lifetime"]
  retire["2. Retire deprecated hashes, ciphers, and protocol versions"]
  gateRetire["Gate: staging shows the deprecated mechanism is absent and clients still connect"]
  libraries["3. Replace unmaintained cryptographic libraries with vetted ones"]
  gateLibs["Gate: dependency review and application tests pass"]
  classify["4. Classify data by how long confidentiality must hold"]
  gateClass["Gate: long-lived secrets are listed separately from short-lived sessions"]
  hybrid["5. Plan a lab trial of hybrid key establishment using a vetted implementation"]
  gateHybrid["Gate: lab notes say the trial is not production and name the library used"]
  certs["6. Plan certificate and signature migration with verifier support"]
  gateCerts["Gate: interoperability matrix covers clients, HSMs, and object size"]
  rescan["7. Re-scan and compare the CI baseline"]
  gateScan["Gate: baseline changes are reviewed and the report still says a scan is not quantum-safe"]
  owners --> gateOwners --> retire --> gateRetire --> libraries --> gateLibs --> classify --> gateClass --> hybrid --> gateHybrid --> certs --> gateCerts --> rescan --> gateScan"""
    lines = [
        "flowchart LR",
        "  %% Dependency edges from the inventory. This order is a review aid, not a proof.",
    ]
    count = 0
    for entry in inventory:
        if entry.concern == "informational" and not entry.direct_components and not entry.indirect_components:
            continue
        mechanism = _node(entry.mechanism + "|" + entry.kind)
        label = entry.mechanism.replace('"', "'")
        lines.append(f'  {mechanism}["{label}"]')
        components = entry.direct_components + entry.indirect_components + entry.declared_dependencies
        for component in components:
            if count >= 40:
                lines.append('  truncated["Further edges are in report.json"]')
                return phases + "\n\n" + "\n".join(lines)
            component_id = _node("component|" + component + entry.mechanism)
            component_label = component.replace('"', "'")
            lines.append(f'  {component_id}["{component_label}"]')
            lines.append(f"  {component_id} --> {mechanism}")
            count += 1
    if count == 0:
        lines.append('  none["No confirmed dependency edges"]')
    return phases + "\n\n" + "\n".join(lines)


def limitations(files_scanned: int, files_skipped: int) -> list[str]:
    return [
        DISCLAIMER,
        f"This run read {files_scanned} file{'' if files_scanned == 1 else 's'} and skipped {files_skipped} binary, oversized, or unreadable paths.",
        "The scan is static. It does not execute the target, attach to a process, or read HSMs, KMS consoles, or network endpoints.",
        "Matches are rules and parsers. Reflection, dynamic imports, generated code, and closed-source binaries are out of scope.",
        "Confirmed means the rule saw an API, a parsed certificate, a known dependency, or a specific protocol token. Uncertain means a name or comment still needs a person.",
        "Python, JavaScript, and Go imports are followed inside the tree so wrappers can be tied back to call sites. Java imports are not followed. Lockfiles are only expanded for known package names.",
        "Transitive system packages, container base images, and managed cloud TLS settings are invisible unless their configuration is in the scanned tree.",
        "The sandbox uses the vetted Python cryptography package for classical profiles only. It refuses post-quantum profile ids instead of simulating them.",
        "Hybrid options in this report are deployment sketches. They are not an implementation and they are not interoperability approval.",
    ]


def compatibility_risks(findings: list[Finding]) -> list[str]:
    risks = [
        "Algorithm identifiers in TLS, SSH, JOSE, X.509, and application tokens are not interchangeable.",
        "Peers, HSMs, and middleboxes may reject an unknown group or a larger certificate even when both cryptographic designs are sound.",
        "Fallback from a hybrid handshake to a classical handshake can become a downgrade if it is automatic.",
        "Re-encrypting stored data is a data migration. It is separate from changing a protocol default.",
        "Certificate lifetimes can outlast the migration window. Record not-after dates with the inventory.",
    ]
    if any(item.kind == "certificate" and item.confidence == "confirmed" for item in findings):
        risks.append(
            "Parsed certificates in this tree need a verifier plan. A post-quantum or composite certificate is not a drop-in for the current key."
        )
    if any(item.name.startswith("TLS") and item.confidence == "confirmed" for item in findings):
        risks.append(
            "Raising the minimum TLS version can disconnect older clients. Test that matrix and keep a rollback."
        )
    if any(item.name in {"RS256", "HMAC-SHA-256", "ES256", "jsonwebtoken", "PyJWT"} for item in findings):
        risks.append(
            "JWT consumers that allow-list alg will reject a new identifier. Update verifiers before issuers."
        )
    return risks


def testing_steps() -> list[str]:
    return [
        "Re-run this scanner in CI against the committed baseline. Investigate added fingerprints before merging.",
        "For each confirmed urgent item, add a staging check that the deprecated protocol, hash, or cipher no longer appears.",
        "Exercise the oldest supported client after any TLS or SSH change, and record the rollback.",
        "For wrapper findings, test the public function and the module it calls. An indirect hit is still a dependency.",
        "If a hybrid lab trial is approved, run it with a vetted post-quantum library in a non-production environment and write down peer failures.",
        "Confirm an owner for each inventory row. A scan cannot assign operational responsibility.",
        "After fixes, scan again. A smaller finding list is progress on the inventory. It is not proof of quantum safety.",
    ]
