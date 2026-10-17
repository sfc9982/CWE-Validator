from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from cwe_witness.cli import app, resolve_catalog
from cwe_witness.cli import batch as batch_command
from cwe_witness.manifest import catalog_entry, load_manifest
from cwe_witness.models import AllocationFailure, Fixture, Manifest, Result
from cwe_witness.profiles import load_profile

ROOT = Path(__file__).resolve().parents[1]


def test_batch_defaults_to_calibration_directory():
    import inspect

    assert inspect.signature(batch_command).parameters["directory"].default == Path(
        "manifests/calibration"
    )


def test_calibration_manifests():
    manifests = list((ROOT / "manifests/calibration").glob("*.yaml"))
    assert len(manifests) == 18
    for path in manifests:
        manifest = load_manifest(path)
        profile = load_profile(manifest.profile)
        if profile:
            assert profile.cwe_id == manifest.claimed_cwe


@pytest.mark.parametrize("destination", ["../secret", "/etc/passwd", "C:/secret", "a/../../b", "."])
def test_fixture_path_rejected(destination):
    with pytest.raises(ValidationError):
        Fixture(source="x", destination=destination)


def test_unknown_fields_rejected():
    with pytest.raises(ValidationError):
        Manifest(
            sample_id="sample",
            sources=["a.c"],
            claimed_cwe="CWE-125",
            profile="c.oob-read@1.0.0",
            unexpected=True,
        )


def test_allocation_failure_schema():
    config = AllocationFailure(function="calloc", call_index=2)
    assert config.function == "calloc"
    assert config.call_index == 2
    with pytest.raises(ValidationError):
        AllocationFailure(function="realloc", call_index=1)
    with pytest.raises(ValidationError):
        AllocationFailure(function="malloc", call_index=0)


def test_catalog_missing_is_explicit():
    assert (
        catalog_entry(ROOT / "tests/fixtures/catalog.csv", "CWE-125")["name"]
        == "Out-of-bounds Read"
    )
    assert (
        catalog_entry(ROOT / "tests/fixtures/catalog.csv", "CWE-416")["status"]
        == "NOT_IN_PROVIDED_CATALOG"
    )


def test_catalog_default_does_not_fall_back_to_parent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert resolve_catalog(None) == Path("699.csv")
    assert catalog_entry(resolve_catalog(None), "CWE-125")["status"] == "CATALOG_NOT_FOUND"
    (tmp_path / "699.csv").write_text("CWE-ID,Name,Description\n125,Read,x\n")
    assert catalog_entry(resolve_catalog(None), "CWE-125")["name"] == "Read"


def test_catalog_explicit_override(tmp_path):
    catalog = tmp_path / "external.csv"
    catalog.write_text("CWE-ID,Name,Description\n125,External,x\n")
    assert resolve_catalog(catalog) == catalog
    assert catalog_entry(resolve_catalog(catalog), "CWE-125")["name"] == "External"


def test_unsupported_is_success(tmp_path):
    import json

    manifest = json.loads((ROOT / "manifests/calibration/cwe125-normal.yaml").read_text())
    manifest["sources"] = [str(ROOT / "tests/calibration/memory.c")]
    manifest["profile"] = "unsupported@1.0.0"
    path = tmp_path / "unsupported.yaml"
    path.write_text(json.dumps(manifest))
    result = CliRunner().invoke(app, ["run", str(path), "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output
    saved = Result.model_validate_json(next(tmp_path.rglob("result.json")).read_text())
    assert saved.decision.status == "UNSUPPORTED"
    assert saved.runs == []


def test_invalid_manifest_nonzero(tmp_path):
    path = tmp_path / "invalid.yaml"
    path.write_text("unknown: true")
    assert CliRunner().invoke(app, ["validate", str(path)]).exit_code != 0


def test_init_uses_filename_only_for_claim(tmp_path):
    target = tmp_path / "claim.yaml"
    runner = CliRunner()
    source = tmp_path / "CWE125_sample.c"
    source.write_text("int main(void) { return 0; }\n")
    args = ["init", str(source), str(target), "--stdin", "5"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    manifest = load_manifest(target)
    assert manifest.claimed_cwe == "CWE-125"
    assert manifest.profile == "c.oob-read@1.0.0"
    assert manifest.entry.stdin == "5"
    assert runner.invoke(app, args).exit_code != 0


def test_function_failure_requires_null_contract():
    from cwe_witness.models import FunctionFailure

    with pytest.raises(ValidationError, match="configured together"):
        Manifest(
            sample_id="sample",
            sources=["a.c"],
            claimed_cwe="CWE-476",
            profile="c.null-pointer-dereference@1.0.0",
            function_failure=FunctionFailure(function="fopen"),
        )


@pytest.mark.parametrize("source", ["../secret", "/etc", "C:/secret", "a\\b", ""])
def test_path_mount_source_rejected(source):
    from cwe_witness.models import PathMount

    with pytest.raises(ValidationError):
        PathMount(source=source, destination="/var/data")


@pytest.mark.parametrize("manifest", sorted((ROOT / "manifests/calibration").glob("*.yaml")))
def test_all_bundled_manifests_validate_through_cli(manifest):
    result = CliRunner().invoke(app, ["validate", str(manifest)])
    assert result.exit_code == 0, result.output
    assert "profile=supported" in result.output
