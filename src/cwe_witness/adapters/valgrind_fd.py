import re
from pathlib import Path

from ..models import Location, Observation, Run

PREFIX = re.compile(r"^==(?P<pid>\d+)==\s?(?P<body>.*)$")
FD_HEADER = re.compile(r"^Open file descriptor (?P<fd>\d+):\s*(?P<name>.*)$")
SOCKET_HEADER = re.compile(r"^Open (?P<family>AF_[A-Z0-9_]+) socket (?P<fd>\d+):\s*(?P<name>.*)$")


def _target_location(lines: list[str], sources: list[str]) -> Location | None:
    for line in lines:
        for source in sources:
            source_path = Path(source)
            match = re.search(
                rf"\b(?P<function>[^ ()]+) \([^()\s]*{re.escape(source_path.name)}:"
                rf"(?P<line>\d+)\)",
                line,
            )
            if match:
                return Location(
                    file=source,
                    line=int(match["line"]),
                    function=match["function"],
                )
    return None


def report_complete(run: Run) -> bool:
    path = Path(run.evidence_log)
    if not path.is_file() or run.timeout or run.output_limited:
        return False
    if run.signal is not None and not run.controlled_termination:
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return bool(re.search(r"^==\d+== FILE DESCRIPTORS:\s+\d+ open .* at exit\.$", text, re.M))


def parse_valgrind_fd(run: Run, sources: list[str]) -> list[Observation]:
    path = Path(run.evidence_log)
    if not path.is_file():
        return []
    raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    summary_pid = next(
        (
            int(match.group("pid"))
            for raw in raw_lines
            if (match := re.match(r"^==(?P<pid>\d+)==\s+FILE DESCRIPTORS:", raw))
        ),
        None,
    )
    if summary_pid is None:
        return []
    parent_pid = next(
        (
            int(match.group("parent"))
            for raw in raw_lines
            if (match := re.match(rf"^=={summary_pid}== Parent PID: (?P<parent>\d+)$", raw))
        ),
        None,
    )
    if parent_pid is None and summary_pid != run.pid:
        return []
    lines: list[tuple[int, str]] = []
    for number, raw in enumerate(raw_lines, 1):
        match = PREFIX.match(raw)
        if match and int(match["pid"]) == summary_pid:
            lines.append((number, match["body"]))
    # Same completeness rule as report_complete(), evaluated on the lines we
    # already read instead of re-reading the evidence log from disk.
    complete = (
        not run.timeout
        and not run.output_limited
        and (run.signal is None or run.controlled_termination)
        and any(
            re.match(r"^==\d+== FILE DESCRIPTORS:\s+\d+ open .* at exit\.$", raw)
            for raw in raw_lines
        )
    )
    observations: list[Observation] = []
    index = 0
    while index < len(lines):
        line_number, body = lines[index]
        fd_match = FD_HEADER.match(body)
        socket_match = SOCKET_HEADER.match(body)
        if not fd_match and not socket_match:
            index += 1
            continue
        end = index + 1
        block = [body]
        while end < len(lines):
            next_body = lines[end][1]
            if FD_HEADER.match(next_body) or SOCKET_HEADER.match(next_body):
                break
            if next_body.startswith("FILE DESCRIPTORS:"):
                break
            block.append(next_body)
            end += 1
        location = _target_location(block, sources)
        if location:
            header_match = socket_match or fd_match
            assert header_match is not None
            descriptor = int(header_match["fd"])
            name = header_match["name"].strip() or None
            joined = "\n".join(block).lower()
            resource_type = "socket" if socket_match else "pipe" if "pipe" in joined else "file"
            observations.append(
                Observation(
                    observation_id=f"{run.run_id}-obs-{len(observations) + 1}",
                    run_id=run.run_id,
                    kind="posix_fd_leak",
                    producer="valgrind-fd-text@1.0.0",
                    operation="open",
                    location=location,
                    complete=complete,
                    raw_artifact=str(path),
                    line_start=line_number,
                    line_end=lines[end - 1][0],
                    descriptor=descriptor,
                    resource_type=resource_type,
                    resource_name=name,
                )
            )
        index = end
    return observations
