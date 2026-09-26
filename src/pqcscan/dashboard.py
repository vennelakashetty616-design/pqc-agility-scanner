from __future__ import annotations

import html

from pqcscan.models import InventoryEntry, ScanResult

# Short explanations for the mechanisms this scanner knows well.
# Unknown names fall back to a generic sentence so a new scan still reads clearly.
_PLAIN: dict[str, str] = {
    "TLS 1.0": "Connections are still allowed to use a very old version of TLS. Turn it off after checking that old clients can connect. That cleanup does not make the connection post-quantum.",
    "TLS 1.1": "TLS 1.1 is also retired. Removing it is ordinary hardening, not post-quantum protection.",
    "TLS 1.2": "TLS 1.2 is current enough to keep during a transition. It still uses today's public-key math unless both sides negotiate a hybrid or post-quantum group.",
    "TLS 1.3": "TLS 1.3 is the current classical protocol. It is not post-quantum unless a hybrid group is actually configured and both peers support it.",
    "OpenSSL security level 0": "This setting lets very weak cryptography through. Raise it. That does not add post-quantum protection.",
    "RC4": "RC4 is an old cipher that should no longer be offered.",
    "DES": "DES uses a short key and is obsolete. Replace it with a vetted library. Do not write a new cipher.",
    "3DES": "3DES is a retired cipher. Replace the call with a current authenticated cipher from a vetted library.",
    "MD5": "MD5 is a hash that can be forged. Stop using it where integrity matters. Replacing it does not make the system post-quantum.",
    "SHA-1": "SHA-1 is a hash that can be forged. Retire it where a collision would matter.",
    "PBKDF2-SHA-1": "Passwords are being stretched with SHA-1. Move password storage to a current password hash from a vetted library.",
    "SHA-256": "SHA-256 is a normal modern hash. Keep an owner for it. It is not the first thing to migrate.",
    "HMAC-SHA-256": "A shared secret is used to sign tokens. Protect and rotate that secret. This is separate from post-quantum signatures.",
    "ssh-rsa": "SSH is still using an old signature name tied to SHA-1. Move hosts and clients to a current SSH algorithm and test existing keys.",
    "SSH Diffie-Hellman SHA-1": "SSH key agreement is using an old SHA-1 group. Remove it after checking clients. Classical Diffie-Hellman is also a later post-quantum planning item.",
    "RSA-1024": "This RSA key is too small for today's computers, and it is also a post-quantum migration concern. Replace it.",
    "RSA-2048": "RSA-2048 is common today. It still needs a migration plan because a future quantum computer would threaten RSA. A larger RSA key is not a post-quantum fix.",
    "RSA": "RSA is used to create or use keys. It works with today's computers at modern sizes, and it needs a migration plan for signatures and key agreement.",
    "RSA key transport": "TLS is using an old way to send the session secret with RSA. Prefer ephemeral key agreement, then plan hybrid key establishment separately for data that must stay secret for a long time.",
    "RSA-PSS": "RSA-PSS is a modern RSA signature style. It is still RSA, so verifiers need a plan before any new algorithm name is introduced.",
    "RS256": "JSON tokens are signed with RSA. Every checker must allow the algorithm name. A post-quantum signature will need a new name and updated checkers.",
    "ES256": "JSON tokens are signed with elliptic-curve P-256. That is classical cryptography and needs a verifier plan before it changes.",
    "ECDSA": "Elliptic-curve signatures are in use. Inventory the curve and who verifies it.",
    "ECDSA-P-256": "P-256 signatures or key agreement. Classical, and a migration candidate.",
    "ECDSA-P-384": "P-384 signatures or key agreement. Classical, and a migration candidate.",
    "ECDHE-RSA": "The connection makes a fresh elliptic-curve secret and authenticates it with an RSA certificate. Good classical practice, and still a planning item for long-lived secrecy.",
    "AES": "AES is in use, but this hit does not show the key length or mode. Open the call before changing it.",
    "AES-128-GCM": "AES-128-GCM is a current cipher with a smaller margin than AES-256. List the peers that require it before changing it.",
    "AES-256-GCM": "AES-256-GCM is a common long-term cipher. Confirm both sides actually negotiate it.",
    "AES-128-CBC-HMAC-SHA-256": "A token format uses AES-128 plus HMAC. Check every reader before changing the name.",
    "TLS AES128-SHA": "An old TLS suite mixes AES-128 with SHA-1. Drop it when clients allow a current suite.",
    "PyCrypto": "PyCrypto is an abandoned Python library. Move callers to a maintained vetted library. Do not copy cipher code into the app.",
    "crypto/md5": "Go code imports the MD5 package. Retire the call, then drop the import.",
    "sha1-crate": "A Rust package exists specifically for SHA-1. Retire that use if a collision would matter.",
    "cryptography": "The Python cryptography package is a vetted OpenSSL binding. The dependency itself is not evidence of quantum safety. Record which algorithms it is asked to run.",
    "golang.org/x/crypto": "A Go crypto module is declared. The module name does not say which algorithms production uses.",
    "PyJWT": "A JWT library is declared or imported. The algorithm name in the token matters more than the package name.",
    "jsonwebtoken": "A Node JWT library is present. Checkers often only allow specific algorithm names.",
    "node-forge": "JavaScript cryptography code is present. Inventory what it is asked to do.",
    "crypto-js": "crypto-js is present. The package name does not tell you the mode or key length.",
    "elliptic": "The elliptic package is in the tree, often pulled in by something else. Find out why it is there.",
    "jws": "A JWT helper library is present, often as a dependency of another JWT package.",
    "Bouncy Castle": "The Java Bouncy Castle library is declared. Inventory which algorithms the app requests.",
    "ring": "The Rust ring crate is declared. Inventory which algorithms the app requests.",
    "ML-KEM": "A post-quantum key-agreement name appears. A name in a file is not a working quantum-safe deployment.",
    "ML-DSA": "A post-quantum signature name appears. A name is not proof that certificates and verifiers support it.",
    "SLH-DSA": "A post-quantum signature name appears. Confirm size limits and verifier support with a vetted library.",
    "Private key material": "A private key file is in the tree. Remove it, rotate the key, and do not copy the key into this report.",
    "JWT none": "Tokens can be accepted with no signature. Reject that. This is a present authentication bug.",
}


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _plain(name: str, concern: str) -> str:
    known = _PLAIN.get(name)
    if known:
        return known
    if concern == "urgent":
        return (
            f"{name} is on the outdated list. Confirm the file, then retire it with a vetted library. "
            "That cleanup does not by itself make the system post-quantum."
        )
    if concern == "plan":
        return (
            f"{name} still needs an owner and a migration note. It may be fine today. "
            "Changing it can break peers until every reader is updated."
        )
    if concern == "monitor":
        return f"{name} is worth keeping on the inventory. Give it an owner and a reason it stays."
    return f"{name} was recorded. A name or a library does not prove the system is quantum-safe."


def _counts(result: ScanResult) -> dict[str, int]:
    counts = {"confirmed": 0, "uncertain": 0, "urgent": 0, "plan": 0, "monitor": 0, "informational": 0}
    for finding in result.findings:
        counts[finding.confidence] = counts.get(finding.confidence, 0) + 1
        if finding.confidence == "confirmed":
            counts[finding.concern] = counts.get(finding.concern, 0) + 1
    return counts


def _entries(result: ScanResult, concern: str, confidence_uncertain: bool = False) -> list[InventoryEntry]:
    if confidence_uncertain:
        return [item for item in result.inventory if item.uncertain_components and not item.direct_components and not item.indirect_components and not item.declared_dependencies]
    return [item for item in result.inventory if item.concern == concern and (item.direct_components or item.indirect_components or item.declared_dependencies)]


def _where(entry: InventoryEntry) -> str:
    paths = entry.direct_components + entry.indirect_components + entry.declared_dependencies + entry.uncertain_components
    shown = paths[:3]
    extra = len(paths) - len(shown)
    text = ", ".join(shown)
    if extra > 0:
        text += f", and {extra} more"
    return text or "see the JSON report"


def _hidden_rows(result: ScanResult) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for entry in result.inventory:
        if not entry.indirect_components:
            continue
        if entry.concern == "informational" and entry.mechanism == "cryptography":
            continue
        for path in entry.indirect_components[:4]:
            origin = next((item.via for item in result.findings if item.usage == "indirect" and item.name == entry.mechanism and item.component == path and item.via), "another file")
            rows.append((path, origin, entry.mechanism))
    return rows[:12]


def _steps(result: ScanResult) -> list[str]:
    steps = [
        "Give each confirmed item an owner. The scanner cannot decide who should fix it.",
        "Retire the outdated list first: old TLS, old hashes, old ciphers, and abandoned libraries. Test the oldest client you still support.",
        "Replace unmaintained libraries with a vetted one. Do not paste cipher code into the application.",
        "Write down which data must stay secret for many years. That list drives the public-key migration, not the hash cleanup.",
        "If a hybrid trial is approved, run it in a lab with a vetted post-quantum library such as a current OpenSSL or liboqs build. This tool will not invent that cryptography.",
        "Scan again and update the CI baseline only when the difference was intentional. Fewer findings means the inventory moved. It does not prove quantum safety.",
    ]
    if not any(item.concern == "urgent" and item.confidence == "confirmed" for item in result.findings):
        steps[1] = "No outdated mechanism was confirmed in this tree. Still assign owners before treating the scan as finished."
    return steps


def render_dashboard(result: ScanResult) -> str:
    counts = _counts(result)
    urgent = _entries(result, "urgent")
    plan = _entries(result, "plan")
    watch = _entries(result, "monitor")
    hidden = _hidden_rows(result)
    uncertain = [item for item in result.findings if item.confidence == "uncertain"]
    parts = [
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "<meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "<title>Cryptography status</title>",
        "<style>",
        ":root { color-scheme: light; --ink:#1c1917; --muted:#57534e; --line:#e7e5e4; --paper:#fafaf9; --urgent:#9f1239; --plan:#9a3412; --ok:#365314; }",
        "body { margin:0; font:16px/1.5 Georgia, 'Iowan Old Style', Palatino, serif; color:var(--ink); background:var(--paper); }",
        "main { max-width:920px; margin:0 auto; padding:40px 20px 64px; }",
        "h1 { font-size:32px; line-height:1.2; margin:0 0 8px; font-weight:600; }",
        "h2 { font-size:22px; margin:36px 0 8px; font-weight:600; }",
        "p, li { color:var(--ink); }",
        ".muted { color:var(--muted); }",
        ".banner { border:1px solid var(--line); padding:12px 14px; margin:20px 0 28px; }",
        ".stats { display:grid; grid-template-columns:repeat(4, minmax(0,1fr)); gap:12px; }",
        ".stat { border-top:3px solid var(--ink); padding-top:8px; }",
        ".stat b { display:block; font-size:28px; line-height:1.1; }",
        ".stat.urgent { border-color:var(--urgent); }",
        ".stat.plan { border-color:var(--plan); }",
        ".stat.ok { border-color:var(--ok); }",
        "table { width:100%; border-collapse:collapse; margin-top:8px; }",
        "th, td { text-align:left; vertical-align:top; padding:8px 10px 8px 0; border-bottom:1px solid var(--line); }",
        "th { font-size:13px; letter-spacing:0.04em; text-transform:uppercase; color:var(--muted); font-weight:600; }",
        "code { font-family:Consolas, ui-monospace, monospace; font-size:0.92em; }",
        "ol { padding-left:1.2em; }",
        "@media (max-width:700px) { .stats { grid-template-columns:1fr 1fr; } h1 { font-size:26px; } }",
        "</style>",
        "</head>",
        "<body>",
        "<main>",
        "<p class=\"muted\">Cryptography status dashboard</p>",
        "<h1>What this scan found, in plain language</h1>",
        f"<p>The scanner read <b>{result.files_scanned}</b> files under <code>{_esc(result.root)}</code>. "
        "It lists cryptography the code and configuration still depend on, including uses hidden behind a wrapper. "
        "It does not run the program, and it does not decide that the system is safe.</p>",
        f"<div class=\"banner\"><b>Read this first.</b> {_esc(result.disclaimer)}</div>",
        "<section class=\"stats\">",
        f"<div class=\"stat urgent\"><b>{len(urgent)}</b><span>outdated items to retire first</span></div>",
        f"<div class=\"stat plan\"><b>{len(plan)}</b><span>items that need a migration plan</span></div>",
        f"<div class=\"stat\"><b>{counts['confirmed']}</b><span>confirmed hits, including repeats across files</span></div>",
        f"<div class=\"stat ok\"><b>{len(uncertain)}</b><span>comments or names that are not confirmed use</span></div>",
        "</section>",
        "<h2>Fix these first</h2>",
        "<p>These are already outdated on ordinary computers. Cleaning them up is the first job. Doing so does not make the system post-quantum.</p>",
        _table(urgent),
        "<h2>Plan these, without treating them as broken today</h2>",
        "<p>Public-key algorithms such as RSA and elliptic curves still work at modern sizes. A future quantum computer is why they need a plan. Hashes and AES are a separate, usually later, decision.</p>",
        _table(plan),
        "<h2>Keep, and give someone ownership</h2>",
        _table(watch) if watch else "<p>No confirmed item was in the keep-and-own group.</p>",
        "<h2>Hidden behind another file</h2>",
        "<p>Some files never name an algorithm. They call another file that does. The row below is the caller, then the file that actually uses the cryptography.</p>",
        _hidden_table(hidden),
        "<h2>Mentioned, but not confirmed</h2>",
        "<p>These are comments or bare names. Do not schedule a migration from a comment.</p>",
        _uncertain_table(uncertain),
        "<h2>What to do next</h2>",
        "<ol>",
        "".join(f"<li>{_esc(step)}</li>" for step in _steps(result)),
        "</ol>",
        "<h2>What this page is not</h2>",
        "<p>This is not an AI judgment, a penetration test, or a quantum-safety certificate. "
        "The wording is a plain-language view of the same static inventory. "
        "Closed-source programs, HSMs, and cloud consoles are invisible unless their settings are in the scanned folder.</p>",
        f"<p class=\"muted\">{_esc(result.disclaimer)}</p>",
        "</main>",
        "</body>",
        "</html>",
    ]
    return "\n".join(parts) + "\n"


def _table(entries: list[InventoryEntry]) -> str:
    if not entries:
        return "<p>None in this group.</p>"
    rows = []
    for entry in entries:
        rows.append(
            "<tr>"
            f"<td><b>{_esc(entry.mechanism)}</b></td>"
            f"<td>{_esc(_plain(entry.mechanism, entry.concern))}</td>"
            f"<td><code>{_esc(_where(entry))}</code></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>What</th><th>In plain terms</th><th>Where</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _hidden_table(rows: list[tuple[str, str, str]]) -> str:
    if not rows:
        return "<p>No confirmed use was reached only through another file.</p>"
    body = []
    for caller, origin, mechanism in rows:
        body.append(
            "<tr>"
            f"<td><code>{_esc(caller)}</code></td>"
            f"<td><code>{_esc(origin)}</code></td>"
            f"<td>{_esc(mechanism)}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>File that depends on it</th><th>File that actually uses it</th><th>Mechanism</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table>"
    )


def _uncertain_table(findings: list) -> str:
    if not findings:
        return "<p>No uncertain matches.</p>"
    body = []
    for finding in findings:
        evidence = finding.evidence[0] if finding.evidence else None
        where = f"{evidence.path}:{evidence.line}" if evidence and evidence.line else finding.component
        body.append(
            "<tr>"
            f"<td><b>{_esc(finding.name)}</b></td>"
            f"<td><code>{_esc(where)}</code></td>"
            f"<td>{_esc(finding.summary)}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Name</th><th>Where</th><th>Why it is uncertain</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table>"
    )
