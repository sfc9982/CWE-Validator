import re
from pathlib import Path

from ..models import AllocationFailure, Location, Observation, Run

_DIAGNOSTIC = re.compile(
    r"(?P<file>(?:[A-Za-z]:)?[^\n:]+\.c):(?P<line>\d+):(?P<column>\d+):\s*"
    r"runtime error:\s*(?P<message>[^\n]+)",
    re.IGNORECASE,
)
_BOUNDS = re.compile(
    r"index\s+(?P<index>-?\d+)\s+out of bounds for type\s+['‘](?P<type>[^'’]+)['’]",
    re.IGNORECASE,
)
_ARITHMETIC = re.compile(
    r"(?P<left>-?\d+)\s*(?P<operator>\+|-|\*|/)\s*(?P<right>-?\d+)"
    r".*?type ['‘](?P<type>[^'’]+)['’]",
    re.IGNORECASE,
)
_TYPE_RANGES = {
    "signed char": (-128, 127),
    "char": (-128, 127),
    "short": (-32768, 32767),
    "short int": (-32768, 32767),
    "int": (-(2**31), 2**31 - 1),
    "long": (-(2**63), 2**63 - 1),
    "long int": (-(2**63), 2**63 - 1),
    "long long": (-(2**63), 2**63 - 1),
    "long long int": (-(2**63), 2**63 - 1),
    "unsigned char": (0, 2**8 - 1),
    "unsigned short": (0, 2**16 - 1),
    "unsigned short int": (0, 2**16 - 1),
    "unsigned int": (0, 2**32 - 1),
    "unsigned long": (0, 2**64 - 1),
    "unsigned long int": (0, 2**64 - 1),
    "unsigned long long": (0, 2**64 - 1),
}


def _location(match: re.Match[str], sources: list[str]) -> Location | None:
    """Attribute only an exact canonical source path; never a basename."""
    try:
        candidate = Path(match["file"]).resolve(strict=False)
    except OSError:
        return None
    source = next(
        (value for value in sources if Path(value).resolve(strict=False) == candidate), None
    )
    if source is None:
        return None
    return Location(file=source, line=int(match["line"]), column=int(match["column"]))


def _arithmetic(message: str) -> tuple[str, str, str, str] | None:
    match = _ARITHMETIC.search(message)
    if not match:
        return None
    operand_type = " ".join(match["type"].lower().split())
    limits = _TYPE_RANGES.get(operand_type)
    if limits is None:
        return None
    left, right, operator = int(match["left"]), int(match["right"]), match["operator"]
    if operator == "+":
        value = left + right
    elif operator == "-":
        value = left - right
    elif operator == "*":
        value = left * right
    elif right:
        # C integer division truncates toward zero; avoid float conversion so
        # very large operands remain exact while classifying the diagnostic.
        value = (abs(left) // abs(right)) * (-1 if (left < 0) != (right < 0) else 1)
    else:
        return None
    if value > limits[1]:
        return "integer_overflow", operator, operand_type, str(value)
    if value < limits[0]:
        return "integer_underflow", operator, operand_type, str(value)
    return None


def parse_ubsan(
    run: Run, sources: list[str], allocation_failure: AllocationFailure | None = None
) -> list[Observation]:
    path = Path(run.sanitizer_log)
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    observations: list[Observation] = []
    injected_failure = False
    injection_log = Path(run.auxiliary_logs.get("allocation_failure", ""))
    if allocation_failure and injection_log.is_file():
        injected_failure = (
            f"inject|{allocation_failure.function}|{allocation_failure.call_index}"
            in injection_log.read_text(encoding="utf-8", errors="replace").splitlines()
        )
    diagnostics = list(_DIAGNOSTIC.finditer(text))
    for index, diagnostic in enumerate(diagnostics):
        message, lowered = diagnostic["message"], diagnostic["message"].lower()
        block_end = diagnostics[index + 1].start() if index + 1 < len(diagnostics) else len(text)
        report_block = text[diagnostic.start() : block_end]
        arithmetic = _arithmetic(message)
        kind: str | None = None
        operation: str | None = None
        operator: str | None = None
        operand_type: str | None = None
        operand_value: str | None = None
        if arithmetic:
            kind, operator, operand_type, operand_value = arithmetic
        elif re.search(r"(?:division|remainder|float division) by zero", lowered):
            kind, operation = "divide_by_zero", "divide"
        elif re.search(r"\b(load|store|member access).*null pointer", lowered):
            kind = "null_pointer_dereference"
            operation = "read" if "load" in lowered else "write" if "store" in lowered else "member"
        elif injected_failure and "applying zero offset to null pointer" in lowered:
            location = _location(diagnostic, sources)
            if location:
                try:
                    source_line = (
                        Path(location.file)
                        .read_text(encoding="utf-8", errors="replace")
                        .splitlines()[location.line - 1]
                    )
                except (OSError, IndexError):
                    source_line = ""
                # Clang reports the null base expression for constructs such
                # as records[i].field. Accept this as a dereference only when
                # the run is explicitly configured to fail an allocation and
                # the diagnosed source expression is visibly a member access.
                if re.search(r"\b[A-Za-z_]\w*\s*\[[^]]+\]\s*(?:\.|->)", source_line):
                    kind, operation = "null_pointer_dereference", "member"
        if kind is None:
            continue
        location = _location(diagnostic, sources)
        line_start = text.count("\n", 0, diagnostic.start()) + 1
        observations.append(
            Observation(
                observation_id=f"{run.run_id}-obs-{len(observations) + 1}",
                run_id=run.run_id,
                kind=kind,
                producer="ubsan-text@1.1.0",
                operation=operation,
                location=location,
                complete=(
                    bool(location)
                    and "SUMMARY: UndefinedBehaviorSanitizer:" in report_block
                    and not run.timeout
                    and not run.output_limited
                ),
                raw_artifact=str(path),
                line_start=line_start,
                line_end=line_start,
                arithmetic_operator=operator,
                operand_type=operand_type,
                operand_value=operand_value,
            )
        )
    return observations


def _subscript_is_read(source: str, line_number: int, column: int) -> bool | None:
    """Classify one diagnosed subscript conservatively from its source line.

    UBSan points at the subscript expression. If a line has several subscripts,
    the diagnostic column must identify exactly one; a direct assignment to
    that lvalue is a write, while a compound assignment remains a read.
    """
    lines = source.splitlines()
    if not 1 <= line_number <= len(lines):
        return None
    line = lines[line_number - 1]
    if not 1 <= column <= len(line):
        return None
    pairs: list[tuple[int, int, int]] = []
    stack: list[int] = []
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "[":
            stack.append(index)
        elif char == "]" and stack:
            bracket = stack.pop()
            expression_start = bracket
            while expression_start > 0 and re.match(
                r"[A-Za-z0-9_.*>\-]", line[expression_start - 1]
            ):
                expression_start -= 1
            pairs.append((expression_start, bracket, index))
    candidates = [item for item in pairs if item[0] <= column - 1 <= item[2]]
    if len(candidates) != 1:
        return None
    expression_start, _, end = candidates[0]
    tail = line[end + 1 :]
    # A member selection can follow the array access before its assignment.
    tail = re.sub(r"^(?:\s*(?:\.|->)\s*[A-Za-z_]\w*)+", "", tail)
    tail = tail.lstrip()
    if re.match(r"=(?!=|>)", tail):
        return False
    if re.match(r"(?:\+\+|--)", tail):
        return True
    if re.match(r"(?:\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=)", tail):
        return True
    prefix = line[:expression_start].rstrip()
    if prefix.endswith("&"):
        return None
    if re.search(r"(?:\+\+|--)\s*$", prefix):
        return True
    return True


def parse_ubsan_bounds(run: Run, sources: list[str]) -> list[Observation]:
    """Parse complete Clang UBSan array-bound reports as corroborating reads."""
    observations: list[Observation] = []
    path_texts = [run.auxiliary_logs.get("ubsan_bounds", ""), run.sanitizer_log]
    paths = list(dict.fromkeys(Path(item) for item in path_texts if item))
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        complete_report = "SUMMARY: UndefinedBehaviorSanitizer:" in text
        diagnostics = list(_DIAGNOSTIC.finditer(text))
        for diagnostic_index, diagnostic in enumerate(diagnostics):
            bound = _BOUNDS.search(diagnostic["message"])
            if not bound:
                continue
            location = _location(diagnostic, sources)
            if not location:
                continue
            try:
                source_text = Path(location.file).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            is_read = _subscript_is_read(source_text, location.line, location.column or 0)
            if is_read is not True:
                continue
            type_extent = re.search(r"\[(\d+)\]$", bound["type"].strip())
            if not type_extent:
                continue
            index_value, extent = int(bound["index"]), int(type_extent[1])
            if 0 <= index_value < extent:
                continue
            block_end = (
                diagnostics[diagnostic_index + 1].start()
                if diagnostic_index + 1 < len(diagnostics)
                else len(text)
            )
            report_block = text[diagnostic.start() : block_end]
            complete = "SUMMARY: UndefinedBehaviorSanitizer:" in report_block
            line_start = text.count("\n", 0, diagnostic.start()) + 1
            observations.append(
                Observation(
                    observation_id=f"{run.run_id}-bounds-{len(observations) + 1}",
                    run_id=run.run_id,
                    kind="out_of_bounds",
                    producer="ubsan-bounds-read@1.0.0",
                    operation="read",
                    location=location,
                    bounds_associated=True,
                    static_operation="array_subscript_read",
                    complete=(
                        complete_report and complete and not run.timeout and not run.output_limited
                    ),
                    raw_artifact=str(path),
                    line_start=line_start,
                    line_end=line_start,
                    operand_type=bound["type"],
                    operand_value=f"index={index_value};extent={extent}",
                )
            )
    return observations
