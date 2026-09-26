from __future__ import annotations

from pathlib import Path

import pytest

from pqcscan.dashboard import render_dashboard
from pqcscan.engine import scan_path
from pqcscan.report import render_markdown

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "legacy-billing"


@pytest.fixture(scope="module")
def sample_result():
    return scan_path(SAMPLE)


def _match(result, name: str, path_part: str, confidence: str | None = None, usage: str | None = None):
    found = []
    for finding in result.findings:
        if finding.name != name:
            continue
        if confidence and finding.confidence != confidence:
            continue
        if usage and finding.usage != usage:
            continue
        if any(
            evidence.path == path_part or evidence.path.endswith("/" + path_part)
            for evidence in finding.evidence
        ):
            found.append(finding)
    return found


def test_confirmed_call_sites_and_protocols(sample_result):
    assert _match(sample_result, "MD5", "app/security/wrappers.py", "confirmed")
    assert _match(sample_result, "DES", "app/security/wrappers.py", "confirmed")
    assert _match(sample_result, "PyCrypto", "requirements.txt", "confirmed", "declared_dependency")
    assert _match(sample_result, "TLS 1.0", "config/nginx.conf", "confirmed")
    assert _match(sample_result, "TLS 1.1", "config/nginx.conf", "confirmed")
    assert _match(sample_result, "TLS 1.2", "config/nginx.conf", "confirmed")
    assert _match(sample_result, "TLS 1.0", "app/tls_client.py", "confirmed")
    assert _match(sample_result, "RC4", "config/nginx.conf", "confirmed")
    assert _match(sample_result, "RSA key transport", "config/service.yaml", "confirmed")
    assert _match(sample_result, "OpenSSL security level 0", "config/openssl.cnf", "confirmed")
    assert _match(sample_result, "ssh-rsa", "config/ssh_config", "confirmed")
    assert _match(sample_result, "SHA-1", "src/main/java/com/example/LegacyCipher.java", "confirmed")
    assert _match(sample_result, "3DES", "src/main/java/com/example/LegacyCipher.java", "confirmed")
    assert _match(sample_result, "RSA-1024", "internal/token.go", "confirmed")
    assert _match(sample_result, "PBKDF2-SHA-1", "app/passwords.py", "confirmed")
    assert _match(sample_result, "SHA-256", "app/hashing.py", "confirmed")
    assert _match(sample_result, "HMAC-SHA-256", "app/security/tokens.py", "confirmed")
    assert _match(sample_result, "RS256", "web/session.js", "confirmed")
    assert _match(sample_result, "elliptic", "package-lock.json", "confirmed", "declared_dependency")
    assert _match(sample_result, "Bouncy Castle", "pom.xml", "confirmed", "declared_dependency")
    assert _match(sample_result, "sha1-crate", "Cargo.toml", "confirmed", "declared_dependency")
    assert _match(sample_result, "golang.org/x/crypto", "go.mod", "confirmed", "declared_dependency")


def test_wrappers_and_lockfile_are_visible(sample_result):
    for path in ("app/security/facade.py", "app/billing.py", "app/api.py"):
        hits = _match(sample_result, "MD5", path, "confirmed", "indirect")
        assert hits, path
        assert hits[0].via == "app/security/wrappers.py"
    checkout = _match(sample_result, "SHA-1", "web/checkout.js", "confirmed", "indirect")
    assert checkout and checkout[0].via == "web/session.js"
    go_hits = _match(sample_result, "MD5", "cmd/charge.go", "confirmed", "indirect")
    assert go_hits and go_hits[0].via == "internal/token.go"
    elliptic = _match(sample_result, "elliptic", "package.json")
    assert elliptic == []
    flask = [item for item in sample_result.findings if item.name.lower() == "flask"]
    express = [item for item in sample_result.findings if item.name.lower() == "express"]
    assert flask == [] and express == []


def test_uncertain_notes_stay_separate_from_confirmed_config(sample_result):
    notes = [item for item in sample_result.findings if item.component == "app/notes.py"]
    assert {item.name for item in notes} >= {"RSA", "AES", "ML-KEM"}
    assert all(item.confidence == "uncertain" for item in notes)
    configured = _match(sample_result, "ML-KEM", "config/crypto-policy.json", "confirmed")
    assert configured
    confirmed_titles = {item.title for item in sample_result.checklist if item.confidence == "confirmed"}
    uncertain_titles = {item.title for item in sample_result.checklist if item.confidence == "uncertain"}
    assert "MD5 (algorithm)" in confirmed_titles
    assert "RSA (algorithm)" in uncertain_titles
    rsa_rows = [item for item in sample_result.checklist if item.name == "RSA" and item.kind == "algorithm"]
    assert {item.confidence for item in rsa_rows} == {"confirmed", "uncertain"}


def test_certificate_inventory(sample_result):
    certs = [
        item
        for item in sample_result.findings
        if item.kind == "certificate" and item.component == "certs/billing.crt"
    ]
    assert certs, "Generate the sample certificate with scripts/generate_sample_cert.py"
    assert any(item.name == "RSA-2048" and item.confidence == "confirmed" for item in certs)
    assert all("PRIVATE KEY" not in item.summary for item in sample_result.findings)


def test_inventory_links_mechanism_to_components(sample_result):
    md5 = next(item for item in sample_result.inventory if item.mechanism == "MD5" and item.kind == "algorithm")
    assert "app/security/wrappers.py" in md5.direct_components
    assert "app/billing.py" in md5.indirect_components
    assert "app/api.py" in md5.indirect_components


def test_plan_graph_and_hybrid_options(sample_result):
    assert any(item.option_id == "hybrid-key-establishment" for item in sample_result.hybrid_options)
    hybrid = next(item for item in sample_result.hybrid_options if item.option_id == "hybrid-key-establishment")
    assert hybrid.interoperability
    assert "not implement" in hybrid.status.lower() or "does not implement" in hybrid.status.lower()
    assert "flowchart TD" in sample_result.migration_graph
    assert "Gate:" in sample_result.migration_graph
    assert sample_result.checklist[0].confidence == "confirmed"
    assert sample_result.checklist[0].concern == "urgent"
    assert sample_result.limitations
    assert sample_result.compatibility_risks
    assert sample_result.testing_steps


def test_report_does_not_claim_quantum_safety(sample_result):
    markdown = render_markdown(sample_result)
    assert "does not prove" in markdown
    assert "quantum-safe" in markdown
    for line in markdown.splitlines():
        if "quantum-safe" in line.lower():
            lowered = line.lower()
            assert "not" in lowered
    assert "Uncertain matches" in markdown
    assert "Compatibility risks" in markdown
    assert "Testing steps" in markdown


def test_tls12_is_not_recorded_as_tls10(tmp_path: Path):
    (tmp_path / "nginx.conf").write_text("ssl_protocols TLSv1.2 TLSv1.3;\n", encoding="utf-8")
    (tmp_path / "openssl.cnf").write_text(
        "MinProtocol = TLSv1.2\nCipherString = DEFAULT@SECLEVEL=2\n",
        encoding="utf-8",
    )
    result = scan_path(tmp_path)
    names = {item.name for item in result.findings if item.confidence == "confirmed"}
    assert "TLS 1.2" in names
    assert "TLS 1.3" in names
    assert "TLS 1.0" not in names
    assert "TLS 1.1" not in names
    assert "OpenSSL security level 0" not in names


def test_dashboard_explains_the_scan_in_plain_language(sample_result):
    page = render_dashboard(sample_result)
    assert "What this scan found, in plain language" in page
    assert "Fix these first" in page
    assert "does not prove" in page
    assert "quantum-safe" in page
    assert "MD5" in page
    assert "app/api.py" in page
    assert "app/security/wrappers.py" in page
    for line in page.splitlines():
        if "quantum-safe" in line.lower():
            assert "not" in line.lower()


def test_empty_tree_still_disclaims(tmp_path: Path):
    result = scan_path(tmp_path)
    markdown = render_markdown(result)
    assert result.findings == []
    assert "does not prove" in markdown
    assert "quantum-safe" in markdown
