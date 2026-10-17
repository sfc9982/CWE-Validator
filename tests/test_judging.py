from pathlib import Path

from cwe_witness.judging import judge
from cwe_witness.models import Location, Observation, Profile, Run


def make_run(
    tmp_path: Path, *, exit_code: int, signal: int | None = None, observer: str = "asan"
) -> Run:
    return Run(
        run_id="run-1",
        build_id="build-1",
        argv=["sample"],
        cwd=str(tmp_path),
        environment={},
        stdin_hash="",
        binary_hash="hash",
        pid=10,
        exit_code=exit_code,
        signal=signal,
        timeout=False,
        output_limited=False,
        duration_seconds=0.01,
        stdout=str(tmp_path / "stdout"),
        stderr=str(tmp_path / "stderr"),
        sanitizer_log=str(tmp_path / "missing.log"),
        observer=observer,
    )


def profile() -> Profile:
    return Profile(
        profile_id="test",
        cwe_id="CWE-125",
        mechanism="out_of_bounds",
        operation="read",
        required_predicates=[
            "valid_program_execution",
            "complete_runtime_report",
            "target_mechanism_observed",
            "target_code_attributed",
        ],
    )


def test_active_nonzero_exit_is_not_unexpected(tmp_path: Path) -> None:
    decision = judge(profile(), make_run(tmp_path, exit_code=2), [])

    assert decision.status == "NOT_CONFIRMED"
    assert decision.reason_code == "NO_RUNTIME_EVIDENCE"


def test_signal_without_evidence_is_process_crash(tmp_path: Path) -> None:
    decision = judge(profile(), make_run(tmp_path, exit_code=-11, signal=11), [])

    assert decision.status == "ERROR"
    assert decision.reason_code == "PROCESS_CRASH"


def test_signal_with_complete_ubsan_evidence_is_judged(tmp_path: Path) -> None:
    run = make_run(tmp_path, exit_code=-6, signal=6, observer="ubsan")
    observation = Observation(
        observation_id="obs-1",
        run_id=run.run_id,
        kind="out_of_bounds",
        location=Location(file="sample.c", line=4),
        complete=True,
        bounds_associated=True,
        raw_artifact="ubsan.log",
        line_start=1,
        line_end=3,
    )

    decision = judge(profile(), run, [observation])

    assert decision.status == "CONFIRMED"
