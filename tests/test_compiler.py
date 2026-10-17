import platform
import shutil
from pathlib import Path

import pytest

from cwe_witness.adapters.copy_observer import parse_copy_observer
from cwe_witness.compiler import compile_sources, required_link_flags
from cwe_witness.judging import judge
from cwe_witness.models import AllocationFailure, BuildConfig, Entry, Manifest
from cwe_witness.profiles import load_profile
from cwe_witness.runner import run_binary


def test_openssl_sources_request_libcrypto(tmp_path: Path) -> None:
    source = tmp_path / "openssl.c"
    source.write_text("#include <openssl/evp.h>\nint main(void) { return 0; }\n")

    assert required_link_flags([source]) == ["-lcrypto"]


def test_regular_c_sources_keep_default_link_flags(tmp_path: Path) -> None:
    source = tmp_path / "plain.c"
    source.write_text("#include <stdio.h>\nint main(void) { return 0; }\n")

    assert required_link_flags([source]) == []


@pytest.mark.skipif(
    platform.system() != "Linux" or not shutil.which("clang"),
    reason="Linux and Clang required for allocation-failure compilation",
)
def test_allocation_failure_build_records_shim_and_commands(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text(
        "#include <stdlib.h>\n"
        "struct record { int value; };\n"
        "int main(void) { struct record *p = malloc(sizeof(*p)); return p->value; }\n"
    )
    result = compile_sources(
        [source],
        tmp_path / "build",
        "injected",
        "clang-ubsan-debug",
        allocation_failure=AllocationFailure(function="malloc"),
    )
    assert result.exit_code == 0
    assert result.binary_hash
    assert len(result.commands) == 3
    shim = next(
        Path(path) for path in result.source_hashes if path.endswith("allocation-failure-shim.c")
    )
    assert 'getenv("CWE_WITNESS_ALLOCATION_FAILURE_LOG")' in shim.read_text()
    assert "inject|malloc|1" in shim.read_text()


@pytest.mark.skipif(
    platform.system() != "Linux" or not shutil.which("clang"),
    reason="Linux and Clang required for copy-observer compilation",
)
def test_copy_observer_confirms_struct_field_overflow(tmp_path: Path) -> None:
    source = tmp_path / "field.c"
    source.write_text(
        "#include <string.h>\n"
        "struct record { char citation[4]; int year; };\n"
        'int main(void) { struct record r; strcpy(r.citation, "123456"); return 0; }\n'
    )
    build = compile_sources([source], tmp_path / "build", "copy", "clang-asan-copy-debug")
    assert build.exit_code == 0
    manifest = Manifest(
        sample_id="copy-test",
        sources=[str(source)],
        claimed_cwe="CWE-120",
        profile="c.classic-buffer-overflow",
        entry=Entry(),
        build=BuildConfig(preset="clang-asan-copy-debug"),
    )
    run = run_binary(build, manifest, tmp_path / "run", [], "run-1", observer="asan")
    observations = parse_copy_observer(run, [str(source)])
    decision = judge(load_profile("c.classic-buffer-overflow@1.0.0"), run, observations)
    assert decision.status == "CONFIRMED"
    assert observations[0].target_capacity == 4
    assert observations[0].actual_write_size == 7
