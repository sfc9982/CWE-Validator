import shutil
from pathlib import Path

import pytest
import yaml

from cwe_witness.engine import verify
from cwe_witness.models import BuildConfig
from cwe_witness.profiles import load_profile
from cwe_witness.sample_import import import_case

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    not shutil.which("clang"), reason="Clang is required to run C calibration samples"
)


CASES = [
    ("CWE-125", "c.oob-read", "bounds.c", ["read", "2"]),
    ("CWE-787", "c.oob-write", "bounds.c", ["write", "2"]),
    ("CWE-190", "c.integer-overflow", "arithmetic.c", ["overflow"]),
    ("CWE-191", "c.integer-underflow", "arithmetic.c", ["underflow"]),
    ("CWE-369", "c.divide-by-zero", "arithmetic.c", ["divide"]),
    ("CWE-416", "c.heap-uaf", "lifetime.c", ["use-after-free"]),
    ("CWE-415", "c.heap-double-free", "lifetime.c", ["double-free"]),
    ("CWE-476", "c.null-pointer-dereference", "lifetime.c", ["null-dereference"]),
]


@pytest.mark.parametrize("cwe,profile_id,source_name,argv", CASES)
def test_reviewed_imported_c_case_confirms_claim(tmp_path, cwe, profile_id, source_name, argv):
    profile = load_profile(f"{profile_id}@1.0.0")
    source = ROOT / "tests" / "calibration" / "extended" / source_name
    base_manifest = tmp_path / "base.yaml"
    base_manifest.write_text(
        yaml.safe_dump(
            {
                "sample_id": f"extended-{cwe.lower()}-base",
                "sources": [str(source)],
                "claimed_cwe": cwe,
                "profile": f"{profile_id}@1.0.0",
                "build": BuildConfig(preset=profile.build_preset).model_dump(),
                "replay": {"count": 1},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    case_spec = tmp_path / "case.yaml"
    case_spec.write_text(
        yaml.safe_dump(
            {
                "source_tool": "handwritten-c-regression",
                "upstream_version": "local-1",
                "case_id": cwe.lower(),
                "review_status": "approved",
                "review_note": "Reviewed C sample and input are paired with this CWE profile.",
                "entry": {"argv": argv},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    imported_manifest = tmp_path / "imported.yaml"
    import_case(base_manifest, case_spec, imported_manifest)

    result = verify(
        imported_manifest,
        tmp_path / "results",
        ROOT / "tests" / "fixtures" / "catalog.csv",
    )
    assert result.decision.status == "CONFIRMED", result.model_dump_json(indent=2)
    assert result.manifest.imported_case is not None
    assert result.manifest.imported_case.case_id == cwe.lower()
