import json
import platform
import sys
from pathlib import Path

import pytest

from cwe_witness.compiler import clean_environment
from cwe_witness.engine import verify
from cwe_witness.runner import execute

pytestmark = pytest.mark.skipif(platform.system() != "Linux", reason="Linux runner")


def test_timeout(tmp_path):
    result = execute(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        tmp_path,
        b"",
        clean_environment(),
        0.1,
        4096,
    )
    assert result["timeout"]
    assert result["duration_seconds"] < 5


def test_output_limit(tmp_path):
    result = execute(
        [sys.executable, "-c", "print('A' * 1000000)"], tmp_path, b"", clean_environment(), 3, 4096
    )
    assert result["output_limited"]
    assert (tmp_path / "stdout.txt").stat().st_size <= 4096


def test_environment_not_inherited(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_API_TOKEN", "synthetic-secret")
    result = execute(
        [sys.executable, "-c", "import os; print(os.getenv('FAKE_API_TOKEN'))"],
        tmp_path,
        b"",
        clean_environment(),
        3,
        4096,
    )
    assert result["exit_code"] == 0
    assert (tmp_path / "stdout.txt").read_text().strip() == "None"


def test_fixture_and_build_error(tmp_path):
    source = tmp_path / "fixture.c"
    source.write_text(
        '#include <stdio.h>\nint main(void) { FILE *f=fopen("data/input.txt", "r");'
        "if (!f) return 2; int c=fgetc(f); fclose(f); putchar(c); return 0; }"
    )
    fixture = tmp_path / "synthetic.txt"
    fixture.write_text("SYNTHETIC")
    manifest = {
        "sample_id": "fixture",
        "sources": [str(source)],
        "claimed_cwe": "CWE-125",
        "profile": "c.oob-read@1.0.0",
        "fixtures": [{"source": str(fixture), "destination": "data/input.txt"}],
    }
    path = tmp_path / "sample.yaml"
    path.write_text(json.dumps(manifest))
    result = verify(path, tmp_path / "results", tmp_path / "missing.csv")
    assert result.decision.status == "NOT_CONFIRMED"
    assert Path(result.runs[0].stdout).read_text() == "S"
    assert result.fixture_hashes
    result.manifest.entry.stdin = "tampered"
    with pytest.raises(ValueError, match="stdin hash changed"):
        verify(path, tmp_path / "results", tmp_path / "missing.csv", previous=result)
    source.write_text("this does not compile")
    result = verify(path, tmp_path / "results", tmp_path / "missing.csv")
    assert result.decision.status == "ERROR"
    assert result.decision.reason_code == "BUILD_FAILED"


def test_output_limit_ignores_preexisting_files(tmp_path):
    # A fixture larger than the limit is the caller's data, not child output.
    (tmp_path / "fixture.bin").write_bytes(b"F" * 8192)
    result = execute(
        [sys.executable, "-c", "print('ok')"], tmp_path, b"", clean_environment(), 3, 4096
    )
    assert result["exit_code"] == 0
    assert not result["output_limited"]
