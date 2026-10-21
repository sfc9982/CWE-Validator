import posixpath
import re
import shutil
import subprocess
from pathlib import Path

from ..models import Location, Observation, PathPolicy, Run

_SYSCALL = re.compile(
    r"^\s*(?:(?P<pid>\d+)\s+)?(?P<name>openat2?|open|creat|rename|renameat2?|unlink|unlinkat|truncate|chdir|fchdir)\((?P<args>.*)\)\s+=\s+(?P<ret>-?\d+)"
)
_FRAME = re.compile(
    r"^\s*>\s+(?P<obj>[^\s(]+)(?:\((?P<symbol>[^)]*)\))?\s+\[0x(?P<addr>[0-9a-fA-F]+)\]"
)
# A quoted path argument, optionally preceded by the dirfd of an *at() call.
# strace -yy decorates numeric descriptors with their path: ``5</work/sub>``.
_PATH_ARGUMENT = re.compile(
    r'(?:(?P<dirfd>AT_FDCWD|\d+)(?:<(?P<dirpath>[^>]*)>)?,\s*)?"(?P<path>(?:\\.|[^"\\])*)"'
)
_EXIT = re.compile(r"\+\+\+ (?:exited with|killed by)")


def _decode(value: str) -> str:
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return value


def _resolve(raw: str, cwd: str) -> str:
    if raw.startswith("/"):
        return posixpath.normpath(raw)
    return posixpath.normpath(posixpath.join(cwd, raw))


def _path_arguments(args: str, cwd: str) -> list[tuple[str, str]]:
    """Return ``(raw, resolved)`` for every path argument of one syscall.

    Relative paths resolve against the decorated dirfd when strace printed
    one, and against the process cwd otherwise.
    """
    found: list[tuple[str, str]] = []
    for match in _PATH_ARGUMENT.finditer(args):
        raw = _decode(match.group("path"))
        base = cwd
        if match.group("dirpath") and match.group("dirfd") != "AT_FDCWD":
            base = match.group("dirpath")
        found.append((raw, _resolve(raw, base)))
    return found


def trace_complete(run: Run) -> bool:
    """True when strace recorded the program's own exit under normal termination."""
    path = Path(run.evidence_log)
    if not path.is_file() or run.timeout or run.output_limited or run.signal is not None:
        return False
    return any(
        _EXIT.search(line)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
    )


def _policy_path(value: str | None, cwd: str) -> str | None:
    return _resolve(value, cwd) if value else None


def _outside(path: str, allowed: str) -> bool:
    try:
        return posixpath.commonpath([path, allowed]) != allowed
    except ValueError:
        return True


def _addr2line(addr2line: str, binary: str, address: str, cache: dict[str, list[str]]) -> list[str]:
    """Resolve one address, caching per binary so repeated frames (common when
    the same code path performs several syscalls) do not respawn addr2line."""
    key = f"{binary}{address}"
    if key not in cache:
        try:
            cache[key] = subprocess.run(
                [addr2line, "-e", binary, "-f", "-C", "-i", f"0x{address}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
                shell=False,
            ).stdout.splitlines()
        except (OSError, subprocess.SubprocessError):
            cache[key] = []
    return cache[key]


def _attribute(
    frames: list[str], run: Run, sources: list[str], cache: dict[str, list[str]]
) -> Location | None:
    binary = run.symbol_binary or (run.program_argv[0] if run.program_argv else "")
    # Frame addresses are offsets within their own object; only frames from
    # the target program can be resolved against the target binary.
    target_objects = {value for value in (run.symbol_binary, *run.program_argv[:1]) if value}
    addr2line = shutil.which("addr2line")
    for frame in frames:
        match = _FRAME.match(frame)
        if not match:
            continue
        if addr2line and binary and match.group("obj") in target_objects:
            output = _addr2line(addr2line, binary, match.group("addr"), cache)
            for line in output:
                location = re.match(r"(.+):(\d+)$", line)
                if not location or location.group(1) in {"??", "??:0"}:
                    continue
                candidate = Path(location.group(1))
                try:
                    resolved_candidate = candidate.resolve(strict=False)
                except OSError:
                    continue
                source = next(
                    (s for s in sources if Path(s).resolve(strict=False) == resolved_candidate),
                    None,
                )
                if source:
                    return Location(
                        file=source,
                        line=int(location.group(2)),
                        function=output[0] if output else match.group("symbol"),
                    )
    return None


def parse_path_trace(
    run: Run, sources: list[str], policy: PathPolicy | None = None
) -> list[Observation]:
    path = Path(run.evidence_log)
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    complete = any(_EXIT.search(line) for line in lines)
    cwd = run.cwd
    process_cwd: dict[str, str] = {}
    allowed = _policy_path(policy.allowed_root, cwd) if policy else None
    target = _policy_path(policy.outside_target, cwd) if policy else None
    if not allowed:
        return []
    observations: list[Observation] = []
    addr_cache: dict[str, list[str]] = {}
    index = 0
    while index < len(lines):
        match = _SYSCALL.match(lines[index])
        if not match:
            index += 1
            continue
        frames: list[str] = []
        next_index = index + 1
        while next_index < len(lines) and not _SYSCALL.match(lines[next_index]):
            if lines[next_index].lstrip().startswith(">"):
                frames.append(lines[next_index])
            next_index += 1
        name = match.group("name")
        args = match.group("args")
        pid = match.group("pid") or "main"
        process_cwd.setdefault(pid, cwd)
        current_cwd = process_cwd[pid]
        paths = _path_arguments(args, current_cwd)
        result = int(match.group("ret"))
        if result == 0 and name == "chdir" and paths:
            process_cwd[pid] = paths[0][1]
            index = next_index
            continue
        if result == 0 and name == "fchdir":
            descriptor_path = re.search(r"\d+<([^>]+)>", args)
            if descriptor_path:
                process_cwd[pid] = descriptor_path.group(1)
            index = next_index
            continue
        if name in {"chdir", "fchdir"}:
            index = next_index
            continue
        if not paths:
            index = next_index
            continue
        if name.startswith("rename"):
            # The destination is the path being written; check it first so an
            # escaping rename is recorded against the file it created.
            paths.reverse()
        succeeded = result >= 0
        operation = (
            "write"
            if name.startswith(("rename", "unlink", "truncate"))
            or re.search(r"O_(?:WRONLY|RDWR|CREAT|TRUNC)", args)
            else "read"
        )
        operation_match = not policy or policy.operation == "any" or operation == policy.operation
        escaped = next(
            (
                (raw, resolved)
                for raw, resolved in paths
                if _outside(resolved, allowed) and (target is None or resolved == target)
            ),
            None,
        )
        if succeeded and escaped and operation_match:
            raw, resolved = escaped
            location = _attribute(frames, run, sources, addr_cache)
            observations.append(
                Observation(
                    observation_id=f"{run.run_id}-obs-{len(observations) + 1}",
                    run_id=run.run_id,
                    kind="path_traversal",
                    producer="strace-path@1.1.0",
                    location=location,
                    operation=operation,
                    path_operation=operation,
                    path_access_succeeded=True,
                    path_outside_allowed=True,
                    path_raw=raw,
                    path_resolved=resolved,
                    path_allowed_root=allowed,
                    path_boundary_source=policy.boundary_source if policy else None,
                    path_syscall=name,
                    path_syscall_return=result,
                    complete=complete
                    and run.signal is None
                    and not run.timeout
                    and not run.output_limited,
                    raw_artifact=str(path),
                    line_start=index + 1,
                    line_end=next_index,
                    resource_name=resolved,
                )
            )
        index = next_index
    return observations
