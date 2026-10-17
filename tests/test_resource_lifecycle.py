from pathlib import Path

from cwe_witness.adapters.resource_lifecycle import parse_resource_lifecycle, report_complete
from cwe_witness.models import ResourceLifecycle, Run


def _run(log: Path) -> Run:
    return Run(
        run_id="run-1",
        build_id="build-1",
        argv=["sample"],
        cwd=str(log.parent),
        environment={},
        stdin_hash="",
        binary_hash="hash",
        pid=10,
        exit_code=0,
        signal=None,
        timeout=False,
        output_limited=False,
        duration_seconds=0.01,
        stdout="",
        stderr="",
        sanitizer_log=str(log),
        observer="resource-lifecycle",
        evidence_log=str(log),
    )


def _complete_log(source: Path | str) -> str:
    return (
        "==10== 32 bytes in 1 blocks are still reachable in loss record 1 of 1\n"
        "==10==    at 0x1000: malloc (vg_replace_malloc.c:381)\n"
        f"==10==    by 0x2000: open_connection ({source}:19)\n"
        "==10== HEAP SUMMARY:\n"
        "==10==     in use at exit: 32 bytes in 1 blocks\n"
        "==10== LEAK SUMMARY:\n"
        "==10==    still reachable: 32 bytes in 1 blocks\n"
        "==10== ERROR SUMMARY: 0 errors from 0 contexts\n"
    )


def test_lifecycle_requires_allocator_and_exact_acquisition_frame(tmp_path: Path) -> None:
    source = tmp_path / "snapshot" / "sample.c"
    source.parent.mkdir()
    source.write_text("int main(void) { return 0; }\n")
    log = tmp_path / "memcheck.log"
    log.write_text(_complete_log(source))
    run = _run(log)
    lifecycle = ResourceLifecycle(
        resource_type="database_connection",
        acquire_functions=["open_connection"],
        allocators=["malloc"],
    )

    observations = parse_resource_lifecycle(run, [str(source)], lifecycle)

    assert report_complete(run)
    assert len(observations) == 1
    assert observations[0].resource_type == "database_connection"
    assert observations[0].resource_count == 1
    assert observations[0].size_bytes == 32


def test_lifecycle_rejects_same_basename_and_missing_full_summary(tmp_path: Path) -> None:
    source = tmp_path / "snapshot" / "sample.c"
    source.parent.mkdir()
    source.write_text("int main(void) { return 0; }\n")
    external = tmp_path / "external" / "sample.c"
    external.parent.mkdir()
    external.write_text(source.read_text())
    log = tmp_path / "memcheck.log"
    log.write_text(_complete_log(external))
    lifecycle = ResourceLifecycle(
        resource_type="database_connection",
        acquire_functions=["open_connection"],
        allocators=["malloc"],
    )
    run = _run(log)

    assert parse_resource_lifecycle(run, [str(source)], lifecycle) == []
    log.write_text(_complete_log(source).replace("ERROR SUMMARY:", "INCOMPLETE SUMMARY:"))
    assert not report_complete(run)
    assert parse_resource_lifecycle(run, [str(source)], lifecycle)[0].complete is False


def test_lifecycle_resolves_relative_dwarf_path_inside_snapshot_only(tmp_path: Path) -> None:
    result = tmp_path / "result"
    source = result / "sources" / "sample.c"
    source.parent.mkdir(parents=True)
    source.write_text("int main(void) { return 0; }\n")
    run_dir = result / "run-1"
    run_dir.mkdir()
    log = run_dir / "lifecycle.log"
    log.write_text(_complete_log("sources/sample.c"))
    run = Run(
        **_run(log).model_dump(exclude={"cwd"}),
        cwd=str(run_dir / "work"),
    )
    lifecycle = ResourceLifecycle(
        resource_type="database_connection",
        acquire_functions=["open_connection"],
        allocators=["malloc"],
    )

    observations = parse_resource_lifecycle(run, [str(source)], lifecycle)

    assert len(observations) == 1
    assert observations[0].location is not None
    assert observations[0].location.file == str(source)
