from pathlib import Path

from cwe_witness.engine import promote_compound_write
from cwe_witness.models import Location, Observation


def _read(source: Path, line: int, column: int | None) -> Observation:
    return Observation(
        observation_id="obs-1",
        run_id="run-1",
        kind="out_of_bounds",
        operation="read",
        location=Location(file=str(source), line=line, column=column),
        raw_artifact="",
        line_start=1,
        line_end=1,
    )


def test_compound_assignment_read_is_promoted(tmp_path: Path) -> None:
    source = tmp_path / "compound.c"
    source.write_text("    monthly_totals[month_index] += hours;\n")
    line = source.read_text().splitlines()[0]
    column = line.index("+=") + 1

    result = promote_compound_write([_read(source, 1, column)])

    assert result[0].operation == "write"
    assert result[0].static_operation == "compound_assignment"


def test_unrelated_increment_on_same_line_does_not_promote(tmp_path: Path) -> None:
    source = tmp_path / "ordinary_read.c"
    source.write_text('    printf("%d ", values[-1]); i++;\n')
    line = source.read_text().splitlines()[0]
    # ASan reports an ordinary array access at the start of the expression,
    # not at the later unrelated ``i++``.
    column = line.index("values") + 1

    result = promote_compound_write([_read(source, 1, column)])

    assert result[0].operation == "read"
    assert result[0].static_operation is None


def test_missing_asan_column_is_conservative(tmp_path: Path) -> None:
    source = tmp_path / "unknown.c"
    source.write_text("    values[-1] += 1;\n")

    result = promote_compound_write([_read(source, 1, None)])

    assert result[0].operation == "read"


def test_replay_environment_ignores_artifact_paths() -> None:
    from cwe_witness.runner import _stable_environment

    first = {
        "PATH": "/usr/bin",
        "ASAN_OPTIONS": "detect_leaks=0:log_path=/run/a/asan",
        "UBSAN_OPTIONS": "halt_on_error=1:log_path=/run/a/ubsan.log",
        "CWE_WITNESS_COPY_LOG": "/run/a/copy-observer.log",
        "CWE_WITNESS_NULL_CONTRACT_LOG": "/run/a/null-contract.log",
    }
    second = {
        "PATH": "/usr/bin",
        "ASAN_OPTIONS": "detect_leaks=0:log_path=/run/b/asan",
        "UBSAN_OPTIONS": "halt_on_error=1:log_path=/run/b/ubsan.log",
        "CWE_WITNESS_COPY_LOG": "/run/b/copy-observer.log",
        "CWE_WITNESS_NULL_CONTRACT_LOG": "/run/b/null-contract.log",
    }

    assert _stable_environment(first) == _stable_environment(second)


def test_replay_argv_matches_network_placeholders() -> None:
    from cwe_witness.engine import _argv_matches_entry

    template = ["--url", "http://{network_host}:{network_port}/x", "GET"]
    actual = ["--url", "http://127.0.0.1:43121/x", "GET"]

    assert _argv_matches_entry(actual, template, True)
    assert _argv_matches_entry(["a"], ["a"], False)
    # Without a network fixture the argv must match literally.
    assert not _argv_matches_entry(actual, template, False)
    assert not _argv_matches_entry(["--url", "http://10.0.0.1:43121/x", "GET"], template, True)
    assert not _argv_matches_entry(actual[:-1], template, True)
