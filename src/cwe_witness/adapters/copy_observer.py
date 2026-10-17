import struct
from pathlib import Path

from ..models import Location, Observation, Run


def parse_copy_observer(run: Run, sources: list[str]) -> list[Observation]:
    path = Path(run.auxiliary_logs.get("copy_observer", ""))
    if not path.is_file():
        return []
    source_set = {str(Path(source).resolve()) for source in sources}
    observations: list[Observation] = []
    for index, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        fields = raw.split("|", 4)
        if len(fields) != 5:
            continue
        operation, filename, line_text, capacity_text, actual_text = fields
        try:
            line = int(line_text)
            capacity = int(capacity_text)
            actual = int(actual_text)
        except ValueError:
            continue
        resolved = str(Path(filename).resolve())
        if resolved not in source_set or line < 1 or capacity < 0 or actual < 0:
            continue
        known_capacity = None if capacity == (1 << (8 * struct.calcsize("P"))) - 1 else capacity
        overflow = known_capacity is not None and actual > known_capacity
        observations.append(
            Observation(
                observation_id=f"{run.run_id}-copy-{index}",
                run_id=run.run_id,
                kind="out_of_bounds" if overflow else "copy_operation",
                producer="copy-wrapper@1.0.0",
                operation="write",
                location=Location(file=filename, line=line),
                copy_operation=operation,
                target_capacity=known_capacity,
                actual_write_size=actual,
                bounds_associated=overflow,
                complete=not run.timeout and not run.output_limited,
                raw_artifact=str(path),
                line_start=index,
                line_end=index,
            )
        )
    return observations


def attach_copy_evidence(
    observations: list[Observation], copy_observations: list[Observation]
) -> list[Observation]:
    """Attach a copy record to the ASan report at the same source location."""
    result: list[Observation] = []
    for observation in observations:
        matches = [
            item
            for item in copy_observations
            if item.location
            and observation.location
            and Path(item.location.file).name == Path(observation.location.file).name
            and item.location.line == observation.location.line
        ]
        if matches:
            item = matches[0]
            result.append(
                observation.model_copy(
                    update={
                        "copy_operation": item.copy_operation,
                        "target_capacity": item.target_capacity,
                        "actual_write_size": item.actual_write_size,
                        "bounds_associated": observation.bounds_associated
                        or item.bounds_associated,
                        "related_evidence_ids": [item.observation_id],
                    }
                )
            )
        else:
            result.append(observation)
    return result
