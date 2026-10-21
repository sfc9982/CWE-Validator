from pathlib import Path

from cwe_witness.adapters.path_trace import parse_path_trace
from cwe_witness.models import PathPolicy, Run


def _run(log: Path) -> Run:
    return Run(
        run_id="run-1",
        build_id="build",
        argv=[],
        cwd="/work",
        environment={},
        stdin_hash="",
        binary_hash="",
        pid=1,
        exit_code=1,
        signal=None,
        timeout=False,
        output_limited=False,
        duration_seconds=0,
        stdout="",
        stderr="",
        sanitizer_log="",
        observer="path-trace",
        evidence_log=str(log),
        program_argv=["/work/sample"],
    )


def test_path_trace_confirms_successful_escape(tmp_path: Path) -> None:
    log = tmp_path / "path-trace.log"
    log.write_text(
        'openat(AT_FDCWD, "allowed/../outside/marker.txt", O_RDONLY) = 3\n'
        " > /work/sample(CWE22_S011_F001_VUL+0x1) [0x1234]\n"
        "+++ exited with 1 +++\n",
        encoding="utf-8",
    )
    observations = parse_path_trace(
        _run(log),
        ["/work/CWE22_S011_F001_VUL.c"],
        PathPolicy(allowed_root="allowed", outside_target="outside/marker.txt"),
    )
    assert len(observations) == 1
    assert observations[0].path_outside_allowed
    assert observations[0].path_access_succeeded
    assert observations[0].complete
    # A symbol name that merely resembles a source filename is not attribution.
    # Without an address-to-line mapping this event remains useful evidence but
    # cannot independently satisfy target_code_attributed.
    assert observations[0].location is None


def test_path_trace_ignores_failed_escape(tmp_path: Path) -> None:
    log = tmp_path / "path-trace.log"
    log.write_text(
        'openat(AT_FDCWD, "allowed/../outside/marker.txt", O_RDONLY) = -1 ENOENT (No such file)\n'
        "+++ exited with 1 +++\n",
        encoding="utf-8",
    )
    assert not parse_path_trace(
        _run(log),
        ["/work/CWE22_S011_F001_VUL.c"],
        PathPolicy(allowed_root="allowed", outside_target="outside/marker.txt"),
    )


def test_path_trace_checks_rename_destination(tmp_path: Path) -> None:
    log = tmp_path / "path-trace.log"
    log.write_text(
        'rename("allowed/report.txt", "allowed/../outside/marker.txt") = 0\n'
        " > /work/sample(CWE22_S011_F001_VUL+0x1) [0x1234]\n"
        "+++ exited with 0 +++\n",
        encoding="utf-8",
    )
    observations = parse_path_trace(
        _run(log),
        ["/work/CWE22_S011_F001_VUL.c"],
        PathPolicy(allowed_root="allowed", outside_target="outside/marker.txt", operation="write"),
    )
    assert len(observations) == 1
    assert observations[0].path_resolved == "/work/outside/marker.txt"
    assert observations[0].path_operation == "write"


def test_path_trace_resolves_relative_paths_against_decorated_dirfd(tmp_path: Path) -> None:
    log = tmp_path / "path-trace.log"
    log.write_text(
        'openat(5</work/allowed>, "data.txt", O_RDONLY) = 6</work/allowed/data.txt>\n'
        'openat(7</tmp>, "../etc/marker.txt", O_RDONLY) = 8\n'
        " > /work/sample(CWE22_S011_F001_VUL+0x1) [0x1234]\n"
        "+++ exited with 0 +++\n",
        encoding="utf-8",
    )
    observations = parse_path_trace(
        _run(log),
        ["/work/CWE22_S011_F001_VUL.c"],
        PathPolicy(allowed_root="allowed"),
    )
    # The first open stays inside the allowed root once the dirfd is honoured;
    # only the second escapes.
    assert [item.path_resolved for item in observations] == ["/etc/marker.txt"]


def test_path_trace_tracks_cwd_changes(tmp_path: Path) -> None:
    log = tmp_path / "path-trace.log"
    log.write_text(
        'chdir("/tmp") = 0\n'
        'openat(AT_FDCWD, "outside.txt", O_RDONLY) = 3\n'
        " > /work/sample(CWE22_S011_F001_VUL+0x1) [0x1234]\n"
        "+++ exited with 0 +++\n",
        encoding="utf-8",
    )

    observations = parse_path_trace(_run(log), ["/work/sample.c"], PathPolicy(allowed_root="/work"))

    assert [item.path_resolved for item in observations] == ["/tmp/outside.txt"]
