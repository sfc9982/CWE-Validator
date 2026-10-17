import hashlib
import json
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from cwe_witness.adapters.asan import parse_asan
from cwe_witness.compiler import compile_sources
from cwe_witness.engine import verify
from cwe_witness.judging import judge
from cwe_witness.models import AllocationFailure, Entry, Manifest, Result, Run
from cwe_witness.profiles import load_profile
from cwe_witness.runner import run_binary

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    platform.system() != "Linux" or not shutil.which("clang"),
    reason="Linux and Clang ASan required",
)


def test_parse_asan_recognizes_llvm18_global_boundary_wording(tmp_path: Path) -> None:
    source = "/evidence/CWE125_S001_F001_VUL.c"
    log = tmp_path / "asan.42"
    log.write_text(
        "\n".join(
            [
                "==42==ERROR: AddressSanitizer: global-buffer-overflow on address 0x1000",
                "READ of size 8 at 0x1000 thread T0",
                f"    #0 0x1 in read_vital_sign {source}:13:12",
                f"0x1000 is located 0 bytes after global variable 'vital_signs' defined in '{source}:3' (0x0) of size 192",
                f"SUMMARY: AddressSanitizer: global-buffer-overflow {source}:13:12 in read_vital_sign",
                "==42==ABORTING",
            ]
        ),
        encoding="utf-8",
    )
    run = Run(
        run_id="run-1",
        build_id="build",
        argv=[],
        cwd=str(tmp_path),
        environment={},
        stdin_hash="",
        binary_hash="",
        pid=42,
        exit_code=86,
        signal=None,
        timeout=False,
        output_limited=False,
        duration_seconds=0.0,
        stdout="",
        stderr="",
        sanitizer_log=str(log),
    )

    observations = parse_asan(run, [source])

    assert len(observations) == 1
    assert observations[0].bounds_associated
    assert observations[0].complete


@pytest.fixture(scope="module")
def build(tmp_path_factory):
    directory = tmp_path_factory.mktemp("calibration")
    result = compile_sources([ROOT / "tests/calibration/memory.c"], directory, "calibration")
    assert result.exit_code == 0, Path(result.stderr).read_text()
    return result


@pytest.mark.parametrize(
    "profile,mode,index,expected",
    [
        ("c.heap-uaf", "uaf", "0", "CONFIRMED"),
        ("c.heap-uaf", "no-access", "0", "NOT_CONFIRMED"),
        ("c.heap-uaf", "null", "0", "NOT_CONFIRMED"),
        ("c.heap-uaf", "double", "0", "NOT_CONFIRMED"),
        ("c.heap-double-free", "double", "0", "CONFIRMED"),
        ("c.heap-double-free", "free-null", "0", "NOT_CONFIRMED"),
        ("c.heap-double-free", "distinct", "0", "NOT_CONFIRMED"),
        ("c.heap-double-free", "reuse", "0", "NOT_CONFIRMED"),
        ("c.heap-double-free", "uaf", "0", "NOT_CONFIRMED"),
    ]
    + [
        (profile, mode, index, expected)
        for profile, mode in [("c.oob-read", "read"), ("c.oob-write", "write")]
        for index, expected in [
            ("0", "NOT_CONFIRMED"),
            ("4", "NOT_CONFIRMED"),
            ("5", "CONFIRMED"),
            ("-1", "CONFIRMED"),
        ]
    ]
    + [
        ("c.oob-read", "write", "5", "NOT_CONFIRMED"),
        ("c.oob-write", "read", "5", "NOT_CONFIRMED"),
    ]
    + [
        (profile, mode, "0", "NOT_CONFIRMED")
        for profile in ["c.heap-uaf", "c.heap-double-free", "c.oob-read", "c.oob-write"]
        for mode in ["fake", "unreachable"]
    ],
)
def test_calibration(build, tmp_path, profile, mode, index, expected):
    selected = load_profile(profile + "@1.0.0")
    manifest = Manifest(
        sample_id="calibration",
        sources=list(build.source_hashes),
        claimed_cwe=selected.cwe_id,
        profile=profile + "@1.0.0",
        entry=Entry(argv=[mode, index]),
    )
    run = run_binary(build, manifest, tmp_path / "run", [], "calibration")
    observations = parse_asan(run, manifest.sources)
    decision = judge(selected, run, observations)
    assert decision.status == expected, (observations, Path(run.stderr).read_text())


@pytest.mark.parametrize(
    "name,expected",
    [
        ("cwe120-trigger", "CONFIRMED"),
        ("cwe190-trigger", "CONFIRMED"),
        ("cwe191-trigger", "CONFIRMED"),
        ("cwe369-trigger", "CONFIRMED"),
        ("cwe476-trigger", "CONFIRMED"),
        ("cwe416-trigger", "CONFIRMED"),
        ("cwe415-trigger", "CONFIRMED"),
        ("cwe125-normal", "NOT_CONFIRMED"),
        ("cwe125-lower-valid", "NOT_CONFIRMED"),
        ("cwe125-upper-valid", "NOT_CONFIRMED"),
        ("cwe125-right-boundary", "CONFIRMED"),
        ("cwe125-left-boundary", "CONFIRMED"),
        ("cwe787-normal", "NOT_CONFIRMED"),
        ("cwe787-upper-valid", "NOT_CONFIRMED"),
        ("cwe787-right-boundary", "CONFIRMED"),
        ("cwe787-left-read", "NOT_CONFIRMED"),
        pytest.param(
            "cwe772-trigger",
            "CONFIRMED",
            marks=pytest.mark.skipif(not shutil.which("valgrind"), reason="Valgrind required"),
        ),
    ],
)
def test_calibration_manifest(tmp_path, name, expected):
    result = verify(
        ROOT / f"manifests/calibration/{name}.yaml", tmp_path, ROOT / "tests/fixtures/catalog.csv"
    )
    assert result.decision.status == expected, result.model_dump_json(indent=2)
    assert result.replay_consistent
    saved = Path(result.artifact_dir) / "result.json"
    assert Result.model_validate_json(saved.read_text()) == result
    if name in {"cwe416-trigger", "cwe772-trigger"}:
        assert result.control_result.startswith("PASS")
    if name == "cwe416-trigger":
        replayed = verify(saved, tmp_path, ROOT / "tests/fixtures/catalog.csv", previous=result)
        assert replayed.decision.status == "CONFIRMED"
        assert replayed.builds[0].binary_hash == result.builds[0].binary_hash
        Path(result.builds[0].binary).write_bytes(b"changed")
        with pytest.raises(ValueError, match="hash changed"):
            verify(saved, tmp_path, ROOT / "tests/fixtures/catalog.csv", previous=result)


def test_control_can_be_omitted(tmp_path):
    manifest = {
        "sample_id": "uaf",
        "sources": [str(ROOT / "tests/calibration/memory.c")],
        "claimed_cwe": "CWE-416",
        "profile": "c.heap-uaf@1.0.0",
        "entry": {"scope": "program", "argv": ["uaf", "0"], "stdin": ""},
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    result = verify(path, tmp_path / "results", ROOT / "tests/fixtures/catalog.csv")
    assert result.decision.status == "CONFIRMED"
    assert result.control_result == "Optional control not configured."


def test_allocation_failure_injection_confirms_null_dereference(tmp_path):
    source = tmp_path / "null_alloc.c"
    source.write_text(
        "#include <stdlib.h>\n"
        "struct record { int value; };\n"
        "int main(void) { struct record *p = malloc(sizeof(*p)); return p->value; }\n"
    )
    manifest = Manifest(
        sample_id="injected-null",
        sources=[str(source)],
        claimed_cwe="CWE-476",
        profile="c.null-pointer-dereference@1.0.0",
        build={"preset": "clang-ubsan-debug"},
        allocation_failure=AllocationFailure(function="malloc"),
    )
    path = tmp_path / "manifest.json"
    path.write_text(manifest.model_dump_json())
    result = verify(path, tmp_path / "results", ROOT / "tests/fixtures/catalog.csv")
    assert result.decision.status == "CONFIRMED", result.model_dump_json(indent=2)
    assert result.observations[0].kind == "null_pointer_dereference"
    assert result.observations[0].location
    assert result.replay_consistent

    saved = Path(result.artifact_dir) / "result.json"
    replayed = verify(
        saved, tmp_path / "replays", ROOT / "tests/fixtures/catalog.csv", previous=result
    )
    assert replayed.decision.status == "CONFIRMED"


def _verify_generated_cwe787(tmp_path: Path, source_text: str) -> Result:
    source = tmp_path / "generated.c"
    source.write_text(source_text, encoding="utf-8")
    manifest = Manifest(
        sample_id="generated-cwe787",
        sources=[str(source)],
        claimed_cwe="CWE-787",
        profile="c.oob-write@1.0.0",
        entry=Entry(),
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json(), encoding="utf-8")
    return verify(manifest_path, tmp_path / "results", ROOT / "tests/fixtures/catalog.csv")


def test_compound_assignment_read_is_confirmed_by_asan_column(tmp_path):
    result = _verify_generated_cwe787(
        tmp_path,
        (
            "#include <stdio.h>\n"
            "int main(void) {\n"
            "    int values[1] = {0};\n"
            "    int i = 0;\n"
            "    values[i + 1] += 1;\n"
            "    return 0;\n"
            "}\n"
        ),
    )

    assert result.decision.status == "CONFIRMED", result.model_dump_json(indent=2)
    assert result.observations[0].operation == "write"
    assert result.observations[0].static_operation == "compound_assignment"


def test_unrelated_increment_does_not_confirm_oob_read_as_write(tmp_path):
    result = _verify_generated_cwe787(
        tmp_path,
        (
            "#include <stdio.h>\n"
            "int main(void) {\n"
            "    int values[1] = {7};\n"
            "    int i = 0;\n"
            '    printf("%d ", values[-1]); i++;\n'
            "    return 0;\n"
            "}\n"
        ),
    )

    assert result.decision.status == "NOT_CONFIRMED"
    assert result.decision.reason_code == "OTHER_ERROR_TRIGGERED_FIRST"
    assert result.observations[0].operation == "read"


def test_incomplete_report_and_unattributed(build, tmp_path):
    manifest = Manifest(
        sample_id="uaf",
        sources=list(build.source_hashes),
        claimed_cwe="CWE-416",
        profile="c.heap-uaf@1.0.0",
        entry=Entry(argv=["uaf"]),
    )
    run = run_binary(build, manifest, tmp_path / "run", [], "run")
    profile = load_profile(manifest.profile)
    observations = parse_asan(run, ["/unrelated/source.c"])
    assert judge(profile, run, observations).status == "NOT_CONFIRMED"
    log = Path(run.sanitizer_log)
    log.write_text(log.read_text().replace(f"=={run.pid}==ABORTING", ""))
    observations = parse_asan(run, manifest.sources)
    assert judge(profile, run, observations).status == "NOT_CONFIRMED"


def test_stdin_file_with_control_and_crlf_replays(tmp_path):
    # Regression: the control run must receive the artifact-relative stdin
    # root, and CRLF stdin bytes must hash identically on verify and replay.
    source = tmp_path / "reader.c"
    source.write_text(
        "#include <stdio.h>\n"
        "int main(void) {\n"
        "    int values[4] = {1, 2, 3, 4};\n"
        "    int index = 0;\n"
        '    if (scanf("%d", &index) != 1) return 2;\n'
        '    printf("%d\\n", values[index]);\n'
        "    return 0;\n"
        "}\n"
    )
    control = tmp_path / "reader_fixed.c"
    control.write_text(
        "#include <stdio.h>\n"
        "int main(void) {\n"
        "    int values[4] = {1, 2, 3, 4};\n"
        "    int index = 0;\n"
        '    if (scanf("%d", &index) != 1) return 2;\n'
        '    if (index < 0 || index >= 4) { puts("rejected"); return 0; }\n'
        '    printf("%d\\n", values[index]);\n'
        "    return 0;\n"
        "}\n"
    )
    (tmp_path / "input.txt").write_bytes(b"4\r\n")
    manifest = Manifest(
        sample_id="stdin-control",
        sources=[str(source)],
        claimed_cwe="CWE-125",
        profile="c.oob-read@1.0.0",
        entry=Entry(stdin_file="input.txt"),
        control={
            "sources": [control.name],
            "review_note": "The control rejects out-of-range indexes before reading.",
            "expected_stdout": "rejected\n",
        },
    )
    path = tmp_path / "manifest.json"
    path.write_text(manifest.model_dump_json())

    result = verify(path, tmp_path / "results", ROOT / "tests/fixtures/catalog.csv")

    assert result.decision.status == "CONFIRMED", result.model_dump_json(indent=2)
    assert result.control_result.startswith("PASS"), result.control_result
    assert result.runs[0].stdin_hash == hashlib.sha256(b"4\r\n").hexdigest()
    saved = Path(result.artifact_dir) / "result.json"
    replayed = verify(
        saved, tmp_path / "replays", ROOT / "tests/fixtures/catalog.csv", previous=result
    )
    assert replayed.decision.status == "CONFIRMED"


def test_network_fixture_replays_with_ephemeral_port(tmp_path):
    # Regression: the substituted loopback port must not trip the replay
    # argv check.
    source = tmp_path / "client.c"
    source.write_text(
        "#include <arpa/inet.h>\n"
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <sys/socket.h>\n"
        "#include <unistd.h>\n"
        "int main(int argc, char **argv) {\n"
        "    if (argc < 3) return 2;\n"
        "    int fd = socket(AF_INET, SOCK_STREAM, 0);\n"
        "    struct sockaddr_in addr = {0};\n"
        "    addr.sin_family = AF_INET;\n"
        "    addr.sin_port = htons((unsigned short)atoi(argv[2]));\n"
        "    inet_pton(AF_INET, argv[1], &addr.sin_addr);\n"
        "    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) return 3;\n"
        '    send(fd, "GET\\n", 4, 0);\n'
        "    char buffer[64] = {0};\n"
        "    ssize_t got = recv(fd, buffer, sizeof buffer - 1, 0);\n"
        "    if (got > 0) fputs(buffer, stdout);\n"
        "    close(fd);\n"
        "    return 0;\n"
        "}\n"
    )
    manifest = Manifest(
        sample_id="network-client",
        sources=[str(source)],
        claimed_cwe="CWE-125",
        profile="c.oob-read@1.0.0",
        entry=Entry(argv=["{network_host}", "{network_port}"]),
        network_fixture={"response": "HELLO\n"},
    )
    path = tmp_path / "manifest.json"
    path.write_text(manifest.model_dump_json())

    result = verify(path, tmp_path / "results", ROOT / "tests/fixtures/catalog.csv")

    assert result.decision.status == "NOT_CONFIRMED", result.model_dump_json(indent=2)
    assert Path(result.runs[0].stdout).read_text() == "HELLO\n"
    saved = Path(result.artifact_dir) / "result.json"
    replayed = verify(
        saved, tmp_path / "replays", ROOT / "tests/fixtures/catalog.csv", previous=result
    )
    assert replayed.decision.status == "NOT_CONFIRMED"


@pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("bwrap", "strace")),
    reason="Bubblewrap and strace required",
)
def test_path_calibration_manifest(tmp_path):
    probe = subprocess.run(
        ["bwrap", "--die-with-parent", "--ro-bind", "/", "/", "--unshare-net", "--", "/bin/true"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    if probe.returncode:
        pytest.skip("Bubblewrap namespace operations denied by host policy")
    result = verify(
        ROOT / "manifests/calibration/cwe22-trigger.yaml",
        tmp_path,
        ROOT / "tests/fixtures/catalog.csv",
    )
    assert result.decision.status == "CONFIRMED", result.model_dump_json(indent=2)
    assert result.replay_consistent
    assert all(run.exit_code == 0 for run in result.runs)
