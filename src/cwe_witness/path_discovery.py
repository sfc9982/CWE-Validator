"""Conservative source hints for choosing a CWE-22 test boundary."""

from __future__ import annotations

import re
from pathlib import Path

from .models import PathPolicy

_C_STRING = re.compile(r'"((?:\\.|[^"\\])*)"')
_DEFINE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+(\"(?:\\.|[^\"\\])*\")", re.MULTILINE)
_FILE_CALL = re.compile(
    r"\b(?:fopen|open|openat|creat|freopen|rename|renameat|unlink|unlinkat)\s*\(([^;]*)",
    re.DOTALL,
)


def infer_path_policy(sources: list[str]) -> tuple[PathPolicy, str, list[str]]:
    """Infer one obvious directory prefix; otherwise use the documented /work boundary."""
    candidates: set[str] = set()
    evidence: list[str] = []
    for source in sources:
        try:
            text = Path(source).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        macros = {
            name: bytes(raw[1:-1], "utf-8").decode("unicode_escape")
            for name, raw in _DEFINE.findall(text)
        }
        # Include direct constants and simple macros, but only constants in file
        # operation arguments are considered evidence for an access boundary.
        for call in _FILE_CALL.finditer(text):
            args = call.group(1)
            for name, value in macros.items():
                args = re.sub(rf"\b{re.escape(name)}\b", f'"{value}"', args)
            for literal in _C_STRING.finditer(args):
                value = bytes(literal.group(1), "utf-8").decode("unicode_escape")
                if not value or value.startswith("%"):
                    continue
                parent = value.rsplit("/", 1)[0] if "/" in value else ""
                if (
                    parent
                    and parent not in {".", ".."}
                    and (parent.startswith("/") or ".." not in parent.split("/"))
                ):
                    candidates.add(parent)
                    evidence.append(f"{Path(source).name}: file-operation path prefix {parent!r}")
    if len(candidates) == 1:
        root = next(iter(candidates))
        return (
            PathPolicy(allowed_root=root, boundary_source="source_inference"),
            "source_inference",
            evidence,
        )
    return (
        PathPolicy(allowed_root="/work", boundary_source="working_directory_assumption"),
        "working_directory_assumption",
        ["No unique fixed file-operation directory was found; using /work."],
    )
