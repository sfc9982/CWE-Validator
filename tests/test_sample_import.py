from pathlib import Path

import pytest
import yaml

from cwe_witness.cli import app
from cwe_witness.manifest import load_manifest
from typer.testing import CliRunner


def _write_case(root: Path, *, approved: bool = True) -> tuple[Path, Path, Path]:
    source = root / "target.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    fixture = root / "input.txt"
    fixture.write_text("fixed test fixture\n", encoding="utf-8")
    base = root / "base.yaml"
    base.write_text(
        yaml.safe_dump(
            {
                "sample_id": "base",
                "sources": ["target.c"],
                "claimed_cwe": "CWE-125",
                "profile": "c.oob-read@1.0.0",
                "entry": {"stdin": "base input"},
                "path_policy": {"allowed_root": "/work"},
            }
        ),
        encoding="utf-8",
    )
    spec = root / "case.yaml"
    spec.write_text(
        yaml.safe_dump(
            {
                "source_tool": "PoCGen",
                "upstream_version": "v4",
                "case_id": "fixed-01",
                "review_status": "approved" if approved else "pending",
                "review_note": "Manually checked as a fixed regression sample.",
                "upstream_success_claim": True,
                "entry": {"stdin": "5", "argv": ["sample"]},
                "fixtures": [{"source": "input.txt", "destination": "input.txt"}],
            }
        ),
        encoding="utf-8",
    )
    return base, spec, fixture


def test_import_case_preserves_verifier_policy_and_records_hashes(tmp_path):
    base, spec, fixture = _write_case(tmp_path)
    output = tmp_path / "imported.yaml"
    result = CliRunner().invoke(app, ["import-case", str(base), str(spec), str(output)])
    assert result.exit_code == 0, result.output

    imported = load_manifest(output)
    original = load_manifest(base)
    assert imported.claimed_cwe == original.claimed_cwe
    assert imported.profile == original.profile
    assert imported.path_policy == original.path_policy
    assert imported.entry.stdin == "5"
    assert imported.entry.argv == ["sample"]
    assert imported.imported_case.source_tool == "PoCGen"
    assert imported.imported_case.upstream_success_claim is True
    assert imported.imported_case.input_sha256
    assert imported.imported_case.fixture_sha256["input.txt"]
    assert fixture.is_file()


@pytest.mark.parametrize("changed", ["input", "source", "fixture"])
def test_imported_manifest_rejects_changed_hashes(tmp_path, changed):
    base, spec, fixture = _write_case(tmp_path)
    output = tmp_path / "imported.yaml"
    assert CliRunner().invoke(app, ["import-case", str(base), str(spec), str(output)]).exit_code == 0
    imported = yaml.safe_load(output.read_text(encoding="utf-8"))
    if changed == "input":
        imported["entry"]["stdin"] = "changed"
        output.write_text(yaml.safe_dump(imported), encoding="utf-8")
        expected = "input hash changed"
    elif changed == "source":
        (tmp_path / "target.c").write_text("int main(void) { return 1; }\n", encoding="utf-8")
        expected = "source hash changed"
    else:
        fixture.write_text("modified fixture\n", encoding="utf-8")
        expected = "fixture hash changed"
    with pytest.raises(ValueError, match=expected):
        load_manifest(output)


def test_import_rejects_unreviewed_case_and_cannot_override_cwe(tmp_path):
    base, spec, _ = _write_case(tmp_path, approved=False)
    result = CliRunner().invoke(app, ["import-case", str(base), str(spec), str(tmp_path / "out.yaml")])
    assert result.exit_code == 2
    assert not (tmp_path / "out.yaml").exists()

    spec.write_text(spec.read_text(encoding="utf-8") + "claimed_cwe: CWE-22\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["import-case", str(base), str(spec), str(tmp_path / "out.yaml")])
    assert result.exit_code == 2
    assert not (tmp_path / "out.yaml").exists()
