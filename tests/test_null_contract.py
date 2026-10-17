from pathlib import Path

from cwe_witness.adapters.null_contract import parse_null_contract
from cwe_witness.models import Run


def _run(log: Path) -> Run:
    return Run(
        run_id="run-1",
        build_id="build-1",
        argv=[],
        cwd=str(log.parent),
        environment={},
        stdin_hash="",
        binary_hash="",
        pid=1,
        exit_code=-6,
        signal=6,
        timeout=False,
        output_limited=False,
        duration_seconds=0,
        stdout="",
        stderr="",
        sanitizer_log="",
        auxiliary_logs={"null_contract": str(log)},
    )


def test_null_contract_allows_one_failure_to_reach_later_sink(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { return 0; }\n")
    log = tmp_path / "contract.log"
    log.write_text(f"failure|{source}|14\nnull_sink|{source}|22\n")

    observation = parse_null_contract(_run(log), [str(source)])[0]

    assert observation.location and observation.location.line == 22
    assert observation.failure_source == "fopen:14"


def test_null_contract_rejects_ambiguous_failure_sources(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { return 0; }\n")
    log = tmp_path / "contract.log"
    log.write_text(f"failure|{source}|14\nfailure|{source}|16\nnull_sink|{source}|22\n")

    assert parse_null_contract(_run(log), [str(source)]) == []
