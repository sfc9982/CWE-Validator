import re
from pathlib import Path

from ..models import Location, Observation, Run


def location(text: str, sources: list[str]) -> Location | None:
    for line in text.splitlines():
        if not re.match(r"\s*#\d+\s", line):
            continue
        for source in sources:
            match = re.search(re.escape(source) + r":(\d+)(?::(\d+))?", line)
            if match:
                function = re.search(r"\bin (\S+)", line)
                return Location(
                    file=source,
                    line=int(match[1]),
                    function=function[1] if function else None,
                    column=int(match[2]) if match[2] else None,
                )
    return None


def _parse_report(run: Run, text: str, sources: list[str], header: re.Match[str]) -> Observation:
    category = header[1]
    kind = (
        "heap_use_after_free"
        if category == "heap-use-after-free"
        else "heap_double_free"
        if category == "attempting double-free"
        else "out_of_bounds"
    )
    access = re.search(r"^(READ|WRITE) of size (\d+) at (0x[0-9a-f]+)", text, re.M)
    released = re.search(r"freed by thread .*? here:\n(.*?)(?=\n\n)", text, re.S)
    allocated = re.search(
        r"(?:previously )?allocated by thread .*? here:\n(.*?)(?=\n\n)", text, re.S
    )
    region = re.search(
        r"(0x[0-9a-f]+) is located (\d+) bytes inside of (\d+)-byte region \[(0x[0-9a-f]+),(0x[0-9a-f]+)\)",
        text,
    )
    address = (
        re.search(r"attempting double-free on (0x[0-9a-f]+)", text)
        if kind == "heap_double_free"
        else access
    )
    associated = False
    if region and address and released and allocated:
        actual = int(address[1] if kind == "heap_double_free" else address[3], 16)
        low, high = int(region[4], 16), int(region[5], 16)
        associated = (
            actual == int(region[1], 16) == low + int(region[2])
            and high - low == int(region[3])
            and low <= actual < high
        )
    # ``header`` is matched against the full log while ``text`` is the
    # report slice, so header offsets cannot be applied here.  Keep the
    # primary stack (before the allocation/free details) for source
    # attribution.  This is especially important for recovered ASan runs
    # where a later double-free report follows an earlier UAF report.
    first_stack = text
    for marker in ("\n0x", "\nfreed by thread", "\npreviously allocated by thread"):
        first_stack = first_stack.split(marker, 1)[0]
    stack_boundary = re.search(
        r"\[(\d+), (\d+)\) '[^']+'[^\n]*<== Memory access at offset (\d+) (?:overflows|underflows|partially overflows|partially underflows) this variable",
        text,
    )
    bounds_associated = False
    if access and stack_boundary:
        low_offset, high_offset, offset = map(int, stack_boundary.groups())
        bounds_associated = low_offset < high_offset and (
            offset < low_offset or offset + int(access[2]) > high_offset
        )
    heap_boundary = re.search(
        r"(0x[0-9a-f]+) is located (\d+) bytes (to the right|to the left) of (\d+)-byte region \[(0x[0-9a-f]+),(0x[0-9a-f]+)\)",
        text,
    )
    if access and heap_boundary:
        pointer, distance, side, size, low_hex, high_hex = heap_boundary.groups()
        low_address, high_address = int(low_hex, 16), int(high_hex, 16)
        actual_address = int(access[3], 16)
        bounds_associated = (
            actual_address == int(pointer, 16)
            and high_address - low_address == int(size)
            and (
                actual_address == high_address + int(distance)
                if side == "to the right"
                else actual_address == low_address - int(distance)
            )
        )
    # LLVM 14 reported global overflows as "to the right/left of global
    # variable", while LLVM 18 uses "after/before global variable".  Both
    # forms explicitly identify an address outside the named global object.
    global_boundary = re.search(
        r"(0x[0-9a-f]+) is located (\d+) bytes "
        r"(?:to the right of|to the left of|after|before) global variable "
        r"'[^']+' .*? of size (\d+)",
        text,
        re.S,
    )
    if access and global_boundary:
        pointer, distance, size = global_boundary.groups()
        actual_address = int(access[3], 16)
        bounds_associated = (
            actual_address == int(pointer, 16) and int(distance) >= 0 and int(size) > 0
        )
    recover = "halt_on_error=0" in run.environment.get("ASAN_OPTIONS", "")
    complete = (
        not run.timeout
        and not run.output_limited
        and "SUMMARY: AddressSanitizer:" in text
        and (
            (recover and (run.exit_code in (0, 86) or run.signal is not None))
            or (not recover and run.exit_code == 86 and f"=={run.pid}==ABORTING" in text)
        )
    )
    return Observation(
        observation_id="",
        run_id=run.run_id,
        kind=kind,
        producer="asan-text@1.0.0",
        operation="free" if kind == "heap_double_free" else access[1].lower() if access else None,
        size_bytes=int(access[2]) if access else None,
        location=location(first_stack, sources),
        release_location=location(released[1], sources) if released else None,
        allocation_location=location(allocated[1], sources) if allocated else None,
        object_associated=associated,
        bounds_associated=bounds_associated,
        complete=complete,
        raw_artifact="",
        line_start=0,
        line_end=len(text.splitlines()),
    )


def parse_asan(run: Run, sources: list[str]) -> list[Observation]:
    path = Path(run.sanitizer_log)
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    headers = list(
        re.finditer(
            rf"^=={run.pid}==ERROR: AddressSanitizer: (heap-use-after-free|attempting double-free|(?:heap|stack|global)-buffer-(?:overflow|underflow))\b",
            text,
            re.M,
        )
    )
    observations: list[Observation] = []
    line_number = 1
    previous_offset = 0
    for index, header in enumerate(headers, start=1):
        # Count newlines only in the slice since the previous header instead
        # of rescanning the whole prefix for every report.
        line_number += text.count("\n", previous_offset, header.start())
        previous_offset = header.start()
        end = headers[index].start() if index < len(headers) else len(text)
        observation = _parse_report(run, text[header.start() : end], sources, header)
        observations.append(
            observation.model_copy(
                update={
                    "observation_id": f"{run.run_id}-obs-{index}",
                    "raw_artifact": str(path),
                    "line_start": line_number,
                }
            )
        )
    return observations
