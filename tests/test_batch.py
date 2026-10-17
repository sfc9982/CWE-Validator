import platform
import shutil
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from cwe_witness.batch import build_manifest
from cwe_witness.cli import app
from cwe_witness.manifest import discover_batch_sources, load_batch_manifest


def write_batch(tmp_path: Path) -> Path:
    sources = tmp_path / "incoming"
    sources.mkdir()
    (sources / "CWE125_safe_a.c").write_text(
        '#include <stdio.h>\nint main(void) { puts("a"); return 0; }\n'
    )
    (sources / "CWE-125_safe_b.c").write_text(
        '#include <stdio.h>\nint main(void) { puts("b"); return 0; }\n'
    )
    (sources / "CWE-787_other.c").write_text("int main(void) { return 0; }\n")
    path = tmp_path / "batch.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "batch_id": "cwe125-test",
                "source_directory": "incoming",
                "claimed_cwe": "CWE-125",
                "entry": {"stdin": "5\n"},
                "overrides": {"CWE125_safe_a.c": {"entry": {"stdin": "2\n"}}},
            },
            sort_keys=False,
        )
    )
    return path


def test_discovery_and_override_expansion(tmp_path):
    path = write_batch(tmp_path)
    batch = load_batch_manifest(path)
    sources = discover_batch_sources(path, batch)
    assert [name for name, _ in sources] == ["CWE-125_safe_b.c", "CWE125_safe_a.c"]
    manifest = build_manifest(path, batch, sources[1][0], sources[1][1])
    assert len(manifest.sources) == 1
    assert manifest.entry.stdin == "2\n"


def test_discovery_accepts_stable_numeric_prefix(tmp_path):
    path = write_batch(tmp_path)
    numbered = tmp_path / "incoming" / "001_CWE125_generated.c"
    numbered.write_text("int main(void) { return 0; }\n")
    misleading = tmp_path / "incoming" / "prefix_CWE125_generated.c"
    misleading.write_text("int main(void) { return 0; }\n")

    names = [name for name, _ in discover_batch_sources(path, load_batch_manifest(path))]

    assert "001_CWE125_generated.c" in names
    assert "prefix_CWE125_generated.c" not in names


def test_stdin_file_override_replaces_shared_stdin(tmp_path):
    sources = tmp_path / "incoming"
    sources.mkdir()
    (sources / "CWE369_S001_F007_VUL.c").write_text("int main(void) { return 0; }\n")
    fixture = tmp_path / "S007.stdin"
    fixture.write_text("records\n0\n")
    path = tmp_path / "batch.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "batch_id": "cwe369-test",
                "source_directory": "incoming",
                "claimed_cwe": "CWE-369",
                "entry": {"stdin": "0\n0\n"},
                "overrides": {"CWE369_S001_F007_VUL.c": {"entry": {"stdin_file": "S007.stdin"}}},
            },
            sort_keys=False,
        )
    )
    batch = load_batch_manifest(path)
    source = discover_batch_sources(path, batch)[0]
    manifest = build_manifest(path, batch, source[0], source[1])
    assert manifest.entry.stdin == ""
    assert manifest.entry.stdin_file == "S007.stdin"


def test_unknown_override_is_rejected(tmp_path):
    path = write_batch(tmp_path)
    value = yaml.safe_load(path.read_text())
    value["overrides"]["CWE125_missing.c"] = {}
    path.write_text(yaml.safe_dump(value, sort_keys=False))
    runner = CliRunner()
    result = runner.invoke(app, ["batch-sources", str(path), "--output", str(tmp_path / "out")])
    assert result.exit_code == 2
    assert "override source was not discovered" in result.output


def test_duplicate_sample_id_is_rejected(tmp_path):
    path = write_batch(tmp_path)
    value = yaml.safe_load(path.read_text())
    value["overrides"]["CWE125_safe_a.c"]["sample_id"] = "same"
    value["overrides"]["CWE-125_safe_b.c"] = {"sample_id": "same"}
    path.write_text(yaml.safe_dump(value, sort_keys=False))
    result = CliRunner().invoke(
        app, ["batch-sources", str(path), "--output", str(tmp_path / "out")]
    )
    assert result.exit_code == 2
    assert "duplicate sample_id" in result.output


def test_override_path_traversal_is_rejected(tmp_path):
    path = write_batch(tmp_path)
    value = yaml.safe_load(path.read_text())
    value["overrides"] = {"../escape.c": {}}
    path.write_text(yaml.safe_dump(value, sort_keys=False))
    with pytest.raises(ValueError, match="relative POSIX path"):
        load_batch_manifest(path)


def test_recursive_discovery_is_explicit(tmp_path):
    path = write_batch(tmp_path)
    nested = tmp_path / "incoming" / "nested"
    nested.mkdir()
    (nested / "CWE125_nested.c").write_text("int main(void) { return 0; }\n")
    batch = load_batch_manifest(path)
    assert [name for name, _ in discover_batch_sources(path, batch)] == [
        "CWE-125_safe_b.c",
        "CWE125_safe_a.c",
    ]
    value = yaml.safe_load(path.read_text())
    value["recursive"] = True
    path.write_text(yaml.safe_dump(value, sort_keys=False))
    batch = load_batch_manifest(path)
    assert [name for name, _ in discover_batch_sources(path, batch)] == [
        "CWE-125_safe_b.c",
        "CWE125_safe_a.c",
        "nested/CWE125_nested.c",
    ]


@pytest.mark.skipif(
    platform.system() != "Linux" or not shutil.which("clang"),
    reason="Linux and Clang required for independent-program batch execution",
)
def test_batch_compiles_each_main_independently(tmp_path):
    path = write_batch(tmp_path)
    result = CliRunner().invoke(
        app, ["batch-sources", str(path), "--output", str(tmp_path / "out")]
    )
    assert result.exit_code == 0, result.output
    summaries = list((tmp_path / "out").glob("*/summary.json"))
    assert len(summaries) == 1
    summary = yaml.safe_load(summaries[0].read_text())
    assert [row["source"] for row in summary["rows"]] == [
        "CWE-125_safe_b.c",
        "CWE125_safe_a.c",
    ]
    assert all(row["status"] == "NOT_CONFIRMED" for row in summary["rows"])


def test_batch_records_unexpected_worker_errors(tmp_path, monkeypatch):
    import cwe_witness.engine as engine
    from cwe_witness.batch import run_batch

    def explode(*args, **kwargs):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(engine, "verify", explode)
    path = write_batch(tmp_path)
    directory, rows = run_batch(path, tmp_path / "out", tmp_path / "missing.csv", jobs=2)
    assert [row["status"] for row in rows] == ["ERROR", "ERROR"]
    assert all("synthetic failure" in row["reason"] for row in rows)
    assert (directory / "summary.json").is_file()
    assert (directory / "summary.md").is_file()


def test_override_stdin_file_must_be_relative(tmp_path):
    from pydantic import ValidationError

    path = write_batch(tmp_path)
    config = yaml.safe_load(path.read_text())
    config["overrides"] = {"CWE125_safe_a.c": {"entry": {"stdin_file": "/etc/passwd"}}}
    path.write_text(yaml.safe_dump(config, sort_keys=False))
    batch = load_batch_manifest(path)
    sources = dict(discover_batch_sources(path, batch))
    with pytest.raises(ValidationError, match="relative path"):
        build_manifest(path, batch, "CWE125_safe_a.c", sources["CWE125_safe_a.c"])
