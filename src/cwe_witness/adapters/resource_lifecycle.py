import re
from pathlib import Path

from ..models import Location, Observation, ResourceLifecycle, Run


def _usable_log(run: Run) -> Path | None:
    path = Path(run.evidence_log)
    if not path.is_file() or run.timeout or run.output_limited or run.signal is not None:
        return None
    return path


def report_complete(run: Run) -> bool:
    """True when memcheck ran to its heap summary under normal termination."""
    path = _usable_log(run)
    if path is None:
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return "HEAP SUMMARY:" in text and "LEAK SUMMARY:" in text and "ERROR SUMMARY:" in text


def _attribute_frame_path(raw_path: str, run: Run, sources: list[str]) -> str | None:
    """Map an exact DWARF source path to this run's immutable source snapshot."""
    candidate = Path(raw_path)
    candidates = [candidate.resolve(strict=False)] if candidate.is_absolute() else []
    # Valgrind may print the source path relative to its recorded compilation
    # directory. Resolve that path only beneath this run's snapshot directory.
    result_root = Path(run.cwd).parent.parent
    snapshot_root = result_root / "sources"
    if not candidate.is_absolute():
        candidates.extend(
            [
                (result_root / candidate).resolve(strict=False),
                (snapshot_root / candidate).resolve(strict=False),
            ]
        )
    for source in sources:
        source_path = Path(source).resolve(strict=False)
        if source_path in candidates:
            return source
    return None


def parse_resource_lifecycle(
    run: Run, sources: list[str], lifecycle: ResourceLifecycle | None
) -> list[Observation]:
    if lifecycle is None:
        return []
    path = _usable_log(run)
    if path is None:
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    complete = report_complete(run)
    observations: list[Observation] = []
    record_indexes = [
        index
        for index, line in enumerate(lines)
        if re.search(r"\d+ bytes in \d+ blocks are .* in loss record \d+ of \d+", line)
    ]
    for record_position, index in enumerate(record_indexes):
        record = re.search(
            r"(?P<bytes>\d+) bytes in (?P<blocks>\d+) blocks are (?P<state>.*?) in loss record \d+ of \d+",
            lines[index],
        )
        if not record:
            continue
        end = (
            record_indexes[record_position + 1]
            if record_position + 1 < len(record_indexes)
            else next(
                (stop for stop in range(index + 1, len(lines)) if "HEAP SUMMARY:" in lines[stop]),
                len(lines),
            )
        )
        block = lines[index:end]
        block_text = "\n".join(block)
        if not re.search(
            r"(?:at|by) 0x[0-9A-Fa-f]+: (?:"
            + "|".join(re.escape(item) for item in lifecycle.allocators)
            + r")\b",
            block_text,
        ):
            continue
        for frame in block:
            match = re.search(r"(?:at|by) 0x[0-9A-Fa-f]+: ([^ (]+) \((.+):(\d+)\)", frame)
            if not match or match[1] not in lifecycle.acquire_functions:
                continue
            source = _attribute_frame_path(match[2], run, sources)
            if source is None:
                continue
            observations.append(
                Observation(
                    observation_id=f"{run.run_id}-obs-{len(observations) + 1}",
                    run_id=run.run_id,
                    kind="custom_resource_leak",
                    producer="valgrind-memcheck-resource@1.1.0",
                    operation="acquire",
                    location=Location(file=source, line=int(match[3]), function=match[1]),
                    complete=complete,
                    raw_artifact=str(path),
                    line_start=index + 1,
                    line_end=end,
                    resource_type=lifecycle.resource_type,
                    resource_name=match[1],
                    size_bytes=int(record["bytes"]),
                    resource_count=int(record["blocks"]),
                )
            )
            break
    return observations
