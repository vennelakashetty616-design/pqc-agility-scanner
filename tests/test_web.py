from pathlib import Path

import base64

from pqcscan.analysis import ScanRequestError, analyze_directory, build_analysis
from pqcscan.chat import answer_question
from pqcscan.engine import scan_path
from pqcscan.intake import scan_inputs
from pqcscan.web import render_platform, sandbox_message

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "legacy-billing"


def test_dashboard_page_can_scan_any_folder():
    page = render_platform(str(SAMPLE))
    assert "What cryptography this code is using" in page
    assert "Download report" in page
    assert "High priority" in page
    assert 'type="file"' in page
    assert "How the confirmed hits split" in page
    assert "Ask about this scan" in page
    assert "File and line" in page
    assert "code-hit" in page
    assert "does not prove" in page
    assert str(SAMPLE) in page
    for line in page.splitlines():
        if "quantum-safe" in line.lower():
            assert "not" in line.lower()


def test_analysis_explains_sample_practices_and_updates():
    analysis = build_analysis(scan_path(SAMPLE))
    assert analysis["counts"]["retire"] > 0
    assert analysis["counts"]["plan"] > 0
    assert analysis["charts"]["concern"]
    assert analysis["charts"]["usage"]
    names = [item["name"] for group in analysis["standards"] for item in group["items"]]
    assert "MD5" in names
    assert "RSA-2048" in names or "RSA" in names
    assert "obsolete" in analysis["narrative"].lower() or "retire" in analysis["headline"].lower()
    assert "does not prove the system is quantum-safe" in analysis["narrative"]
    assert analysis["updates"]
    assert analysis["updates"][0]["concern"] == "urgent"
    located = next(item for item in analysis["findings"] if item["name"] == "MD5" and item["line"])
    assert ":" in located["where"]
    assert located["snippet"]
    md5_group = next(item for group in analysis["standards"] if group["key"] == "urgent" for item in group["items"] if item["name"] == "MD5")
    assert md5_group["locations"]
    assert md5_group["locations"][0]["line"]
    bands = {band["key"]: band for band in analysis["priorities"]}
    assert set(bands) == {"high", "medium", "low"}
    high_names = [item["name"] for item in bands["high"]["items"]]
    assert "MD5" in high_names
    md5 = next(item for item in bands["high"]["items"] if item["name"] == "MD5")
    assert md5["reason"]
    assert md5["action"]
    assert md5["locations"]
    joined = analysis["narrative"] + analysis["disclaimer"]
    assert "not" in joined.lower()


def test_chat_answers_from_the_scan_without_a_safety_claim():
    analysis = build_analysis(scan_path(SAMPLE))
    safe = answer_question(analysis, "Does this prove we are quantum-safe?")
    assert "does not prove" in safe.lower()
    assert "quantum-safe" in safe.lower()
    md5 = answer_question(analysis, "Where is MD5?")
    assert "MD5" in md5
    assert "hash" in md5.lower()
    colors = answer_question(analysis, "What do the colors mean?")
    assert "Red means retire" in colors
    first = answer_question(analysis, "What should we fix first?")
    assert "Retire" in first
    assert answer_question(None, "Hello").startswith("Scan a folder")


def test_text_and_pdf_uploads_are_scanned_with_the_folder():
    note = b"digest = hashlib.md5(payload).digest()\n"
    pdf = b"""%PDF-1.1
1 0 obj<</Length 48>>stream
BT (token = DES.new(key)) Tj ET
endstream
endobj
trailer<</Root 1 0 R>>
%%EOF
"""
    analysis = scan_inputs(
        str(SAMPLE),
        [
            {"name": "extra-note.txt", "data": base64.b64encode(note).decode()},
            {"name": "policy.pdf", "data": base64.b64encode(pdf).decode()},
        ],
    )
    names = [item["name"] for item in analysis["findings"]]
    assert "MD5" in names
    assert "DES" in names
    assert "uploaded files" in analysis["root"]
    high = next(band for band in analysis["priorities"] if band["key"] == "high")
    assert any(item["name"] == "DES" for item in high["items"])
    try:
        scan_inputs("", [{"name": "notes.exe", "data": base64.b64encode(b"x").decode()}])
    except ScanRequestError as exc:
        assert "pdf" in str(exc).lower() or ".txt" in str(exc)
    else:
        raise AssertionError("unsupported upload should be rejected")


def test_missing_folder_is_rejected():
    try:
        analyze_directory(str(SAMPLE / "does-not-exist"))
    except ScanRequestError as exc:
        assert "Not a folder" in str(exc)
    else:
        raise AssertionError("missing folder should be rejected")


def test_sandbox_endpoint_verifies_and_refuses_post_quantum():
    ok = sandbox_message("ecdsa-p256")
    assert "cryptography" in ok
    assert "True" in ok
    assert "does not make any system quantum-safe" in ok
    refused = sandbox_message("ml-kem-768").lower()
    assert "refused" in refused
    assert "custom cryptography" in refused
