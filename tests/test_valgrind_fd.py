import platform
import shutil
from pathlib import Path

import pytest

from cwe_witness.adapters.valgrind_fd import parse_valgrind_fd
from cwe_witness.compiler import compile_sources
from cwe_witness.judging import judge
from cwe_witness.models import BuildConfig, Entry, Manifest, Run
from cwe_witness.profiles import load_profile
from cwe_witness.runner import run_binary

ROOT = Path(__file__).resolve().parents[1]


def recorded_run(tmp_path: Path, text: str, *, exit_code: int = 0) -> Run:
    log = tmp_path / "valgrind-fd.log"
    log.write_text(text)
    empty = tmp_path / "empty"
    empty.write_text("")
    return Run(
        run_id="run-1",
        build_id="build",
        argv=["valgrind", "sample"],
        cwd=str(tmp_path),
        environment={},
        stdin_hash="0" * 64,
        binary_hash="1" * 64,
        pid=123,
        exit_code=exit_code,
        signal=None,
        timeout=False,
        output_limited=False,
        duration_seconds=0.1,
        stdout=str(empty),
        stderr=str(empty),
        sanitizer_log="",
        observer="valgrind-fd",
        evidence_log=str(log),
    )


@pytest.mark.parametrize(
    "header,stack_hint,expected",
    [
        ("Open file descriptor 3: /tmp/data", "open", "file"),
        ("Open AF_UNIX socket 4: <unknown>", "socketpair", "socket"),
        ("Open file descriptor 5:", "pipe", "pipe"),
    ],
)
def test_parse_fd_resource_types(tmp_path, header, stack_hint, expected):
    source = "/workspace/fd_resources.c"
    text = (
        "==123== FILE DESCRIPTORS: 4 open (3 std) at exit.\n"
        f"==123== {header}\n"
        f"==123==    at 0x1: {stack_hint} (syscall.c:1)\n"
        f"==123==    by 0x2: main ({source}:12)\n"
        "==123== \n"
    )
    observations = parse_valgrind_fd(recorded_run(tmp_path, text), [source])
    assert len(observations) == 1
    assert observations[0].resource_type == expected
    assert observations[0].complete
    assert observations[0].location.line == 12


def test_incomplete_unattributed_and_wrong_pid_are_ignored(tmp_path):
    source = "/workspace/fd_resources.c"
    text = (
        "==999== FILE DESCRIPTORS: 4 open (3 std) at exit.\n"
        "==999== Open file descriptor 3: /tmp/data\n"
        f"==999==    by 0x2: main ({source}:12)\n"
        "==123== Open file descriptor 4: /tmp/other\n"
        "==123==    by 0x2: runtime (runtime.c:4)\n"
    )
    assert parse_valgrind_fd(recorded_run(tmp_path, text), [source]) == []


@pytest.mark.skipif(
    platform.system() != "Linux" or not shutil.which("clang") or not shutil.which("valgrind"),
    reason="Linux, Clang and Valgrind required",
)
@pytest.mark.parametrize(
    "mode,expected",
    [
        ("file-leak", "CONFIRMED"),
        ("file-closed", "NOT_CONFIRMED"),
        ("socket-leak", "CONFIRMED"),
        ("socket-closed", "NOT_CONFIRMED"),
        ("pipe-leak", "CONFIRMED"),
        ("pipe-closed", "NOT_CONFIRMED"),
    ],
)
def test_fd_calibration(tmp_path, mode, expected):
    source = ROOT / "tests/calibration/fd_resources.c"
    build = compile_sources([source], tmp_path / "build", "fd", "clang-debug")
    assert build.exit_code == 0
    manifest = Manifest(
        sample_id="fd-calibration",
        sources=[str(source)],
        claimed_cwe="CWE-772",
        profile="c.posix-resource-release@1.0.0",
        build=BuildConfig(preset="clang-debug"),
        entry=Entry(argv=[mode]),
    )
    run = run_binary(build, manifest, tmp_path / "run", [], "run-1", observer="valgrind-fd")
    observations = parse_valgrind_fd(run, manifest.sources)
    decision = judge(load_profile(manifest.profile), run, observations)
    assert decision.status == expected, Path(run.evidence_log).read_text()
