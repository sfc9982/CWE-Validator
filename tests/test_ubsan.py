from pathlib import Path

from cwe_witness.adapters.ubsan import parse_ubsan
from cwe_witness.models import AllocationFailure, Run


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
        exit_code=1,
        signal=None,
        timeout=False,
        output_limited=False,
        duration_seconds=0.01,
        stdout="",
        stderr="",
        sanitizer_log=str(log),
        observer="ubsan",
    )


def test_ubsan_classifies_subtraction_overflow_by_math(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { return 0; }\n")
    log = tmp_path / "ubsan.log"
    log.write_text(
        f"{source}:4:9: runtime error: signed integer overflow: 2147483647 - -1 cannot be represented in type 'int'\n"
        f"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior {source}:4:9\n"
    )

    observations = parse_ubsan(_run(log), [str(source)])

    assert [(item.kind, item.arithmetic_operator, item.operand_value) for item in observations] == [
        ("integer_overflow", "-", "2147483648")
    ]
    assert observations[0].complete


def test_ubsan_classifies_addition_underflow_by_math(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { return 0; }\n")
    log = tmp_path / "ubsan.log"
    log.write_text(
        f"{source}:4:9: runtime error: signed integer overflow: -2147483648 + -1 cannot be represented in type 'int'\n"
    )

    assert parse_ubsan(_run(log), [str(source)])[0].kind == "integer_underflow"


def test_ubsan_rejects_same_basename_outside_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "snapshot" / "sample.c"
    source.parent.mkdir()
    source.write_text("int main(void) { return 0; }\n")
    impostor = tmp_path / "external" / "sample.c"
    impostor.parent.mkdir()
    impostor.write_text("int main(void) { return 0; }\n")
    log = tmp_path / "ubsan.log"
    log.write_text(f"{impostor}:4:9: runtime error: division by zero\n")

    observation = parse_ubsan(_run(log), [str(source)])[0]
    assert observation.location is None
    assert not observation.complete


def test_ubsan_does_not_treat_plain_null_word_as_dereference(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { return 0; }\n")
    log = tmp_path / "ubsan.log"
    log.write_text(f"{source}:4:9: runtime error: null pointer passed to argument 1\n")

    assert parse_ubsan(_run(log), [str(source)]) == []


def test_ubsan_null_member_offset_requires_controlled_allocation_failure(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("records = calloc(1, sizeof(*records));\nrecords[0].field = 1;\n")
    log = tmp_path / "ubsan.log"
    log.write_text(
        f"{source}:2:8: runtime error: applying zero offset to null pointer\n"
        f"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior {source}:2:8\n"
    )
    run = _run(log).model_copy(update={"signal": 6, "exit_code": -6})

    assert parse_ubsan(run, [str(source)]) == []
    observations = parse_ubsan(
        run,
        [str(source)],
        AllocationFailure(function="calloc", call_index=1),
    )
    assert observations == []

    injection_log = tmp_path / "allocation-failure.log"
    injection_log.write_text("inject|calloc|1\n")
    run = run.model_copy(update={"auxiliary_logs": {"allocation_failure": str(injection_log)}})
    observations = parse_ubsan(
        run,
        [str(source)],
        AllocationFailure(function="calloc", call_index=1),
    )
    assert len(observations) == 1
    assert observations[0].kind == "null_pointer_dereference"
    assert observations[0].operation == "member"
    assert observations[0].complete
