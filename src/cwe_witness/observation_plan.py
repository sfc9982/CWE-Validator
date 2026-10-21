"""Static hints used only to select additional runtime observers."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .models import ObservationCandidate, ObservationPlan, Profile

_CALLS = {
    "strcpy": "copy",
    "strncpy": "copy",
    "strcat": "copy",
    "strncat": "copy",
    "memcpy": "copy",
    "memmove": "copy",
    "sprintf": "copy",
    "snprintf": "copy",
    "gets": "copy",
    "free": "release",
    "malloc": "allocation",
    "calloc": "allocation",
    "realloc": "allocation",
    "fopen": "file_access",
    "open": "file_access",
    "openat": "file_access",
    "unlink": "file_access",
    "unlinkat": "file_access",
    "rename": "file_access",
    "renameat": "file_access",
    "creat": "file_access",
    "truncate": "file_access",
    "chdir": "file_access",
    "fchdir": "file_access",
    "symlink": "file_access",
    "readlink": "file_access",
    "realpath": "file_access",
    "close": "resource_release",
    "fclose": "resource_release",
    "socket": "resource_acquire",
    "accept": "resource_acquire",
    "pipe": "resource_acquire",
    "dup": "resource_acquire",
    "dup2": "resource_acquire",
}


def _node_location(node: dict[str, object], fallback: str) -> tuple[str, int | None]:
    location = node.get("loc") or node.get("range", {})
    if isinstance(location, dict):
        location = location.get("expansionLoc") or location.get("spellingLoc") or location
    if isinstance(location, dict) and "begin" in location:
        location = location.get("begin")
        if isinstance(location, dict):
            location = location.get("expansionLoc") or location.get("spellingLoc") or location
    if not isinstance(location, dict):
        return fallback, None
    file = location.get("file")
    line = location.get("line")
    return str(file or fallback), int(line) if isinstance(line, int) else None


def _callee(node: dict[str, object]) -> str | None:
    for child in node.get("inner", []) if isinstance(node.get("inner"), list) else []:
        if not isinstance(child, dict):
            continue
        if child.get("kind") == "ImplicitCastExpr":
            for nested in child.get("inner", []):
                if isinstance(nested, dict) and nested.get("kind") == "DeclRefExpr":
                    declaration = nested.get("referencedDecl", {})
                    if isinstance(declaration, dict):
                        name = declaration.get("name")
                        return str(name) if name else None
    return None


def _walk(node: dict[str, object], source: str, found: list[ObservationCandidate]) -> None:
    kind = str(node.get("kind", ""))
    detail = ""
    if kind == "CallExpr":
        callee = _callee(node)
        if callee in _CALLS:
            detail = f"call to {callee}"
            candidate_kind = _CALLS[callee]
        else:
            candidate_kind = ""
    elif kind == "ArraySubscriptExpr":
        candidate_kind, detail = "array_access", "array or pointer subscript"
    elif kind == "BinaryOperator" and node.get("opcode") in {"+", "-", "*", "/", "%"}:
        candidate_kind = "arithmetic"
        type_info = node.get("type", {})
        qtype = type_info.get("qualType", "unknown") if isinstance(type_info, dict) else "unknown"
        detail = f"operator {node.get('opcode')} with type {qtype}"
    elif kind == "UnaryOperator" and node.get("opcode") == "*":
        candidate_kind, detail = "pointer_access", "pointer dereference"
    else:
        candidate_kind = ""
    if candidate_kind:
        file, line = _node_location(node, source)
        if Path(file).resolve(strict=False) == Path(source).resolve(strict=False):
            found.append(
                ObservationCandidate(kind=candidate_kind, file=file, line=line, detail=detail)
            )
    children = node.get("inner", [])
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict):
                _walk(child, source, found)


def _candidate_observers(candidates: list[ObservationCandidate]) -> list[str]:
    mapped = {
        "copy": "asan",
        "array_access": "asan-bounds",
        "arithmetic": "ubsan",
        "pointer_access": "asan",
        "release": "asan",
        "allocation": "asan",
        "file_access": "path-trace",
        "resource_acquire": "resource-lifecycle",
        "resource_release": "resource-lifecycle",
    }
    result: list[str] = []
    for candidate in candidates:
        observer = mapped.get(candidate.kind)
        if observer and observer not in result:
            result.append(observer)
    return result


def build_observation_plan(
    sources: list[str], profile: Profile, mode: str, max_supplemental_runs: int
) -> ObservationPlan:
    candidates: list[ObservationCandidate] = []
    gaps: list[str] = [
        "AST candidates are not a proven data-flow map from stdin, argv, or fixtures."
    ]
    if profile.cwe_id == "CWE-772":
        gaps.append(
            "Custom resource acquisition/release contracts cannot be inferred reliably from C names alone."
        )
    clang = shutil.which("clang")
    if not clang:
        gaps.append("clang unavailable: source-site discovery was not run")
    else:
        for source in sources:
            try:
                completed = subprocess.run(
                    [
                        clang,
                        "-std=c11",
                        "-D_DEFAULT_SOURCE",
                        "-Xclang",
                        "-ast-dump=json",
                        "-fsyntax-only",
                        source,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=True,
                    shell=False,
                )
                _walk(json.loads(completed.stdout), source, candidates)
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
                gaps.append(f"AST unavailable for {Path(source).name}: {type(error).__name__}")
    deduped = {
        (item.kind, str(Path(item.file).resolve(strict=False)), item.line, item.detail): item
        for item in candidates
    }
    candidates = list(deduped.values())
    options = _candidate_observers(candidates)
    observers = [profile.observer]
    if mode == "adaptive":
        observers.extend(observer for observer in options if observer != profile.observer)
    candidate_monitor = {
        "copy": "asan",
        "array_access": "asan-bounds",
        "arithmetic": "ubsan",
        "pointer_access": "asan",
        "release": "asan",
        "allocation": "asan",
        "file_access": "path-trace",
        "resource_acquire": "resource-lifecycle",
        "resource_release": "resource-lifecycle",
    }
    for candidate in candidates:
        candidate_observer = candidate_monitor.get(candidate.kind)
        candidate.monitor_status = (
            "planned"
            if candidate_observer == profile.observer
            else "planned"
            if candidate_observer in observers
            else "unavailable"
        )
    if len(options) > max_supplemental_runs + (1 if profile.observer in options else 0):
        gaps.append("Supplemental observer limit leaves some candidate classes unobserved.")
    tools_by_observer = {
        "asan": ("clang",),
        "asan-bounds": ("clang",),
        "ubsan": ("clang",),
        "path-trace": ("strace", "bwrap"),
        "valgrind-fd": ("valgrind",),
        "resource-lifecycle": ("valgrind",),
    }
    tool_versions: dict[str, str] = {}
    for observer in observers:
        for tool in tools_by_observer.get(observer, ()):
            executable = shutil.which(tool)
            if not executable:
                continue
            try:
                version = subprocess.run(
                    [executable, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                    shell=False,
                )
                output = (version.stdout or version.stderr).splitlines()
                if output:
                    tool_versions[tool] = output[0]
            except (OSError, subprocess.SubprocessError):
                gaps.append(f"Could not record {tool} version for observer {observer}.")
    observers = observers[: max_supplemental_runs + 1]
    return ObservationPlan(
        mode=mode,
        primary_observer=profile.observer,
        planned_observers=observers,
        max_supplemental_runs=max_supplemental_runs,
        candidates=candidates,
        gaps=gaps,
        tool_versions=tool_versions,
    )
