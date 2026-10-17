from pathlib import Path

from cwe_witness.adapters.ubsan import parse_ubsan_bounds
from cwe_witness.models import Run


def _run(source: Path, log: Path) -> Run:
    return Run(
        run_id="run-1",
        build_id="build-1",
        argv=["sample"],
        cwd=str(source.parent),
        environment={},
        stdin_hash="",
        binary_hash="hash",
        pid=10,
        exit_code=1,
        signal=None,
        timeout=False,
        output_limited=False,
        duration_seconds=0.01,
        stdout="",
        stderr="",
        sanitizer_log="",
        observer="asan-bounds",
        auxiliary_logs={"ubsan_bounds": str(log)},
    )


def test_ubsan_bounds_accepts_complete_array_read(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { int values[3]; return values[index]; }\n")
    log = tmp_path / "ubsan-bounds.10"
    log.write_text(
        f"{source}:1:48: runtime error: index 3 out of bounds for type 'int[3]'\n"
        f"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior {source}:1:48\n"
    )

    observations = parse_ubsan_bounds(_run(source, log), [str(source)])

    assert len(observations) == 1
    assert observations[0].operation == "read"
    assert observations[0].bounds_associated
    assert observations[0].complete


def test_ubsan_bounds_rejects_direct_array_write(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { int values[3]; values[index] = 4; return 0; }\n")
    log = tmp_path / "ubsan-bounds.10"
    log.write_text(
        f"{source}:1:40: runtime error: index 3 out of bounds for type 'int[3]'\n"
        f"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior {source}:1:40\n"
    )

    assert parse_ubsan_bounds(_run(source, log), [str(source)]) == []


def test_ubsan_bounds_requires_complete_summary_and_exact_source(tmp_path: Path) -> None:
    source = tmp_path / "snapshot" / "sample.c"
    source.parent.mkdir()
    source.write_text("int main(void) { int values[3]; return values[index]; }\n")
    other = tmp_path / "external" / "sample.c"
    other.parent.mkdir()
    other.write_text(source.read_text())
    log = tmp_path / "ubsan-bounds.10"
    log.write_text(f"{other}:1:48: runtime error: index 3 out of bounds for type 'int[3]'\n")

    assert parse_ubsan_bounds(_run(source, log), [str(source)]) == []

    log.write_text(f"{source}:1:48: runtime error: index 3 out of bounds for type 'int[3]'\n")
    incomplete = parse_ubsan_bounds(_run(source, log), [str(source)])
    assert len(incomplete) == 1
    assert not incomplete[0].complete


def test_ubsan_bounds_reads_combined_sanitizer_log(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { int values[3]; return values[index]; }\n")
    asan_log = tmp_path / "asan.10"
    asan_log.write_text(
        f"{source}:1:48: runtime error: index 3 out of bounds for type 'int[3]'\n"
        f"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior {source}:1:48\n"
    )
    run = _run(source, tmp_path / "stderr.txt").model_copy(update={"sanitizer_log": str(asan_log)})

    observations = parse_ubsan_bounds(run, [str(source)])

    assert len(observations) == 1
    assert observations[0].raw_artifact == str(asan_log)
