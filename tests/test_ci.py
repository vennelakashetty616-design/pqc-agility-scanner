import shutil
from pathlib import Path

from pqcscan.baseline import baseline_document, compare_baseline, load_baseline
from pqcscan.cli import main
from pqcscan.engine import scan_path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "legacy-billing"
BASELINE = ROOT / "baselines" / "legacy-billing.json"


def test_new_library_fails_ci_and_a_comment_does_not(tmp_path: Path):
    original = baseline_document(scan_path(SAMPLE))
    copied = tmp_path / "tree"
    shutil.copytree(SAMPLE, copied)
    requirements = copied / "requirements.txt"
    requirements.write_text(requirements.read_text(encoding="utf-8") + "pycryptodome==3.20.0\n", encoding="utf-8")
    added, _removed = compare_baseline(scan_path(copied), original)
    assert any("PyCryptodome" in item for item in added)

    comment_only = tmp_path / "notes"
    shutil.copytree(SAMPLE, comment_only)
    (comment_only / "app" / "extra_note.py").write_text(
        "# RSA might be discussed later\n",
        encoding="utf-8",
    )
    added, _removed = compare_baseline(scan_path(comment_only), original)
    assert added == []


def test_committed_baseline_matches_the_sample():
    document = load_baseline(BASELINE)
    added, removed = compare_baseline(scan_path(SAMPLE), document)
    assert added == []
    assert removed == []


def test_cli_ci_exit_code(tmp_path: Path):
    baseline = tmp_path / "baseline.json"
    assert main(["baseline", "--path", str(SAMPLE), "--out", str(baseline)]) == 0
    assert main(["ci", "--path", str(SAMPLE), "--baseline", str(baseline)]) == 0
    copied = tmp_path / "tree"
    shutil.copytree(SAMPLE, copied)
    target = copied / "app" / "new_hash.py"
    target.write_text("import hashlib\n\n\ndef tag(data: bytes) -> bytes:\n    return hashlib.md5(data).digest()\n", encoding="utf-8")
    assert main(["ci", "--path", str(copied), "--baseline", str(baseline)]) == 3
