from pathlib import Path

from ..models import Location, Observation, Run


def parse_null_contract(run: Run, sources: list[str]) -> list[Observation]:
    path = Path(run.auxiliary_logs.get("null_contract", ""))
    if not path.is_file() or run.timeout or run.output_limited:
        return []
    events = [
        line.split("|", 2)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
    ]
    failures = {(item[1], item[2]) for item in events if len(item) == 3 and item[0] == "failure"}
    # The shim records call sites rather than pointer identities.  A sink on
    # another line may still receive the injected NULL through a simple local
    # forwarding path, but only a single unambiguous failure source is safe to
    # associate without a full data-flow engine.
    unambiguous_failure = next(iter(failures)) if len(failures) == 1 else None
    findings: list[Observation] = []
    for item in events:
        if len(item) != 3 or item[0] != "null_sink" or unambiguous_failure is None:
            continue
        failure_file, failure_line = unambiguous_failure
        if item[1] != failure_file:
            continue
        source = next(
            (
                value
                for value in sources
                if Path(value).resolve(strict=False) == Path(item[1]).resolve(strict=False)
            ),
            None,
        )
        if source is None:
            continue
        findings.append(
            Observation(
                observation_id=f"{run.run_id}-contract-{len(findings) + 1}",
                run_id=run.run_id,
                kind="null_pointer_dereference",
                producer="target-null-contract@1.0.0",
                operation="call",
                location=Location(file=source, line=int(item[2])),
                complete=True,
                raw_artifact=str(path),
                line_start=1,
                line_end=len(events),
                failure_source=f"fopen:{failure_line}",
            )
        )
    return findings
