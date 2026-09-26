from pathlib import Path

from pqcscan.analysis import ScanRequestError, analyze_directory, build_analysis
from pqcscan.chat import answer_question
from pqcscan.engine import scan_path
from pqcscan.web import render_platform, sandbox_message

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "legacy-billing"


def test_dashboard_page_can_scan_any_folder():
    page = render_platform(str(SAMPLE))
    assert "What cryptography this code is using" in page
    assert "Scan folder" in page
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
