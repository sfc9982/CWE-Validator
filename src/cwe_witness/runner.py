import hashlib
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Literal

from .compiler import clean_environment
from .manifest import digest
from .models import Build, Manifest, Run


def _start_tcp_fixture(
    response: bytes, max_connections: int
) -> tuple[socket.socket, threading.Thread, threading.Event]:
    import threading

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    stop = threading.Event()

    def serve() -> None:
        served = 0
        while not stop.is_set() and served < max_connections:
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                # The runner closes the listener to stop the fixture thread.
                # Treat that deliberate shutdown as normal cleanup.
                if stop.is_set():
                    break
                raise
            with conn:
                # A client that only reads would otherwise block the fixture
                # in recv() until the run's wall-clock timeout; bound the wait
                # and still deliver the response.
                conn.settimeout(1.0)
                try:
                    conn.recv(4096)
                except OSError:
                    pass
                try:
                    conn.sendall(response)
                except OSError:
                    pass
            served += 1

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return listener, thread, stop


def _file_sizes(root: Path) -> dict[Path, int]:
    return {p: p.stat().st_size for p in root.rglob("*") if p.is_file()}


def execute(
    argv: list[str],
    cwd: Path,
    stdin: bytes,
    environment: dict[str, str],
    timeout: float,
    limit: int,
    termination: str = "normal",
    termination_grace_seconds: float = 1.0,
) -> dict[str, Any]:
    """Bound disk output and kill the process group, including surviving descendants."""
    start = time.monotonic()
    launch_argv = [
        sys.executable,
        "-I",
        "-S",
        str(Path(__file__).with_name("_limit_exec.py")),
        str(limit),
        str(int(timeout)),
        *argv,
    ]
    input_path = cwd / "stdin.txt"
    input_path.write_bytes(stdin)
    # Only files the child created or grew count towards the output limit;
    # a large fixture copied in before the run is the caller's data.
    sizes_before = _file_sizes(cwd)
    timed_out = False
    controlled_termination = False
    with (
        input_path.open("rb") as inp,
        (cwd / "stdout.txt").open("wb") as out,
        (cwd / "stderr.txt").open("wb") as err,
    ):
        process = subprocess.Popen(
            launch_argv,
            cwd=cwd,
            env=environment,
            stdin=inp,
            stdout=out,
            stderr=err,
            start_new_session=True,
            shell=False,
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if termination == "graceful-window":
                controlled_termination = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=termination_grace_seconds)
                except subprocess.TimeoutExpired:
                    timed_out = True
            else:
                timed_out = True
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    return {
        "pid": process.pid,
        "exit_code": process.returncode,
        "launch_argv": launch_argv,
        "timeout": timed_out,
        "controlled_termination": controlled_termination,
        "duration_seconds": time.monotonic() - start,
        "output_limited": any(
            size >= limit and sizes_before.get(path) != size
            for path, size in _file_sizes(cwd).items()
        ),
    }


_VOLATILE_ARTIFACT_ENVIRONMENT = {
    "CWE_WITNESS_COPY_LOG": "<artifact>",
    "CWE_WITNESS_NULL_CONTRACT_LOG": "<artifact>",
    "CWE_WITNESS_ALLOCATION_FAILURE_LOG": "<artifact>",
}


def _stable_environment(environment: dict[str, str]) -> dict[str, str]:
    """Remove run-specific artifact paths before replay comparison."""
    stable: dict[str, str] = {}
    for key, value in environment.items():
        if key in _VOLATILE_ARTIFACT_ENVIRONMENT:
            stable[key] = _VOLATILE_ARTIFACT_ENVIRONMENT[key]
            continue
        if key in {"ASAN_OPTIONS", "UBSAN_OPTIONS"}:
            options = [
                "log_path=<artifact>" if option.startswith("log_path=") else option
                for option in value.split(":")
            ]
            stable[key] = ":".join(options)
            continue
        stable[key] = value
    return stable


def run_binary(
    build: Build,
    manifest: Manifest,
    directory: Path,
    fixtures: list[tuple[Path, str]],
    run_id: str,
    observer: Literal[
        "asan", "asan-bounds", "valgrind-fd", "ubsan", "path-trace", "resource-lifecycle"
    ] = "asan",
    expected_environment: dict[str, str] | None = None,
    stdin_root: Path | None = None,
    purpose: str = "primary",
    supplemental_reason: str | None = None,
) -> Run:
    directory.mkdir(parents=True)
    work = directory / "work"
    work.mkdir()
    for source, destination in fixtures:
        target = work / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    env = clean_environment()
    network_listener = None
    network_thread = None
    network_stop = None
    argv_values = list(manifest.entry.argv)
    if manifest.network_fixture:
        network_listener, network_thread, network_stop = _start_tcp_fixture(
            manifest.network_fixture.response.encode(), manifest.network_fixture.max_connections
        )
        port = network_listener.getsockname()[1]
        argv_values = [
            value.replace("{network_host}", "127.0.0.1").replace("{network_port}", str(port))
            for value in argv_values
        ]
    evidence_log = (
        work / "path-trace.log"
        if observer == "path-trace"
        else directory
        / (
            "asan"
            if observer in ("asan", "asan-bounds")
            else "ubsan.log"
            if observer == "ubsan"
            else "lifecycle.log"
            if observer == "resource-lifecycle"
            else "valgrind-fd.log"
        )
    )
    if observer in ("asan", "asan-bounds"):
        recover = manifest.build.preset == "clang-asan-recover-debug"
        env["ASAN_OPTIONS"] = (
            f"detect_leaks=0:halt_on_error={'0' if recover else '1'}:abort_on_error=0:exitcode=86:"
            f"symbolize=1:log_path={evidence_log}"
        )
        symbolizer = shutil.which("llvm-symbolizer")
        if symbolizer:
            env["ASAN_SYMBOLIZER_PATH"] = str(Path(symbolizer).resolve())
        if manifest.build.preset == "clang-asan-copy-debug":
            env["CWE_WITNESS_COPY_LOG"] = str(directory / "copy-observer.log")
        if observer == "asan-bounds":
            env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
    elif observer == "ubsan":
        env["UBSAN_OPTIONS"] = (
            f"print_stacktrace=1:halt_on_error=1:abort_on_error=1:log_path={evidence_log}"
        )
    if manifest.null_contract:
        env["CWE_WITNESS_NULL_CONTRACT_LOG"] = str(directory / "null-contract.log")
    if manifest.allocation_failure:
        env["CWE_WITNESS_ALLOCATION_FAILURE_LOG"] = str(directory / "allocation-failure.log")
    if expected_environment is not None and _stable_environment(env) != _stable_environment(
        expected_environment
    ):
        raise ValueError("runtime environment changed since original verification")
    # Keep stdin as raw bytes: text decoding would normalise CRLF and reject
    # non-UTF-8 fixtures, and the replay check hashes the file's bytes.
    stdin = manifest.entry.stdin.encode()
    if manifest.entry.stdin_file:
        stdin_path = (stdin_root or Path.cwd()) / manifest.entry.stdin_file
        if not stdin_path.is_file():
            raise FileNotFoundError(f"stdin fixture is missing: {manifest.entry.stdin_file}")
        stdin = stdin_path.read_bytes()
    program_argv = [build.binary, *argv_values]
    if observer in ("valgrind-fd", "resource-lifecycle"):
        valgrind = shutil.which("valgrind")
        if not valgrind:
            raise FileNotFoundError("valgrind is not available")
        valgrind_args = (
            [
                "--tool=memcheck",
                "--leak-check=full",
                "--show-leak-kinds=all",
                "--errors-for-leak-kinds=all",
            ]
            if observer == "resource-lifecycle"
            else ["--tool=none", "--track-fds=yes"]
        )
        argv = [
            str(Path(valgrind).resolve()),
            *valgrind_args,
            "--trace-children=no",
            "--num-callers=32",
            f"--log-file={evidence_log}",
            *program_argv,
        ]
        if manifest.path_policy and observer == "valgrind-fd":
            evidence_log = work / "valgrind-fd.log"
            bwrap = shutil.which("bwrap")
            if not bwrap:
                raise FileNotFoundError("bubblewrap is required for path_policy mounts")
            argv = [
                str(Path(bwrap).resolve()),
                "--die-with-parent",
                "--tmpfs",
                "/",
                "--tmpfs",
                "/tmp",
                "--dir",
                "/usr",
                "--ro-bind",
                "/usr",
                "/usr",
                "--dir",
                "/bin",
                "--ro-bind",
                "/bin",
                "/bin",
                "--dir",
                "/lib",
                "--ro-bind",
                "/lib",
                "/lib",
                "--dir",
                "/lib64",
                "--ro-bind",
                "/lib64",
                "/lib64",
                "--dir",
                "/etc",
                "--ro-bind",
                "/etc",
                "/etc",
                "--bind",
                str(work.resolve()),
                "/work",
                "--ro-bind",
                str(Path(build.binary).resolve()),
                "/work/target-program",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--unshare-net",
                "--chdir",
                "/work",
            ]
            for mount in manifest.path_policy.mounts:
                source = (work / mount.source).resolve()
                source.mkdir(parents=True, exist_ok=True)
                parents = list(Path(mount.destination).parents)
                for parent in reversed(parents[:-1]):
                    if str(parent) != "/":
                        argv.extend(["--dir", str(parent)])
                argv.extend(["--dir", mount.destination, "--bind", str(source), mount.destination])
            argv.extend(
                [
                    "--",
                    str(Path(valgrind).resolve()),
                    "--tool=none",
                    "--track-fds=yes",
                    "--trace-children=no",
                    "--num-callers=32",
                    "--log-file=/work/valgrind-fd.log",
                    "/work/target-program",
                    *argv_values,
                ]
            )
    elif observer == "ubsan":
        argv = program_argv
    elif observer == "path-trace":
        strace = shutil.which("strace")
        bwrap = shutil.which("bwrap")
        if not strace or not bwrap:
            raise FileNotFoundError("strace and bubblewrap are required")
        program_argv = ["/work/target-program", *manifest.entry.argv]
        argv = [
            str(Path(bwrap).resolve()),
            "--die-with-parent",
            "--tmpfs",
            "/",
            "--dir",
            "/usr",
            "--ro-bind",
            "/usr",
            "/usr",
            "--dir",
            "/bin",
            "--ro-bind",
            "/bin",
            "/bin",
            "--dir",
            "/lib",
            "--ro-bind",
            "/lib",
            "/lib",
            "--dir",
            "/lib64",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--dir",
            "/etc",
            "--ro-bind",
            "/etc",
            "/etc",
            "--bind",
            str(work.resolve()),
            "/work",
            "--ro-bind",
            str(Path(build.binary).resolve()),
            "/work/target-program",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--unshare-net",
            "--chdir",
            "/work",
        ]
        if manifest.path_policy:
            for mount in manifest.path_policy.mounts:
                source = (work / mount.source).resolve()
                source.mkdir(parents=True, exist_ok=True)
                for parent in reversed(list(Path(mount.destination).parents)[:-1]):
                    if str(parent) != "/":
                        argv.extend(["--dir", str(parent)])
                argv.extend(["--dir", mount.destination, "--bind", str(source), mount.destination])
        argv.extend(
            [
                "--",
                str(Path(strace).resolve()),
                "-f",
                "-k",
                "-yy",
                "-e",
                "trace=%file",
                "-o/work/path-trace.log",
                *program_argv,
            ]
        )
    elif observer not in ("asan", "asan-bounds"):
        raise ValueError(f"unsupported observer: {observer}")
    else:
        argv = program_argv
    data = execute(
        argv,
        work,
        stdin,
        env,
        manifest.run.timeout_seconds,
        manifest.run.output_limit_bytes,
        manifest.run.termination,
        manifest.run.termination_grace_seconds,
    )
    if network_stop is not None:
        network_stop.set()  # type: ignore[union-attr]
        if network_listener is not None:
            network_listener.close()
        if network_thread is not None:
            network_thread.join(timeout=1)
    report = (
        directory / f"asan.{data['pid']}" if observer in ("asan", "asan-bounds") else evidence_log
    )
    if observer == "ubsan" and not report.is_file():
        candidates = sorted(directory.glob("ubsan.*"))
        if candidates:
            report = candidates[0]
    if report.is_file() and report.stat().st_size >= manifest.run.output_limit_bytes:
        data["output_limited"] = True
    bounds_log = work / "stderr.txt"
    if bounds_log.is_file() and bounds_log.stat().st_size >= manifest.run.output_limit_bytes:
        data["output_limited"] = True
    return Run(
        run_id=run_id,
        build_id=build.build_id,
        argv=argv,
        cwd="/work" if observer == "path-trace" else str(work),
        environment=env,
        stdin_hash=hashlib.sha256(stdin).hexdigest(),
        binary_hash=digest(Path(build.binary)),
        signal=-data["exit_code"] if data["exit_code"] < 0 else None,
        stdout=str(work / "stdout.txt"),
        stderr=str(work / "stderr.txt"),
        sanitizer_log=str(report) if observer in ("asan", "asan-bounds", "ubsan") else "",
        observer=observer,
        purpose=purpose,
        supplemental_reason=supplemental_reason,
        evidence_log=str(report),
        program_argv=program_argv,
        symbol_binary=str(Path(build.binary).resolve()),
        auxiliary_logs={
            **(
                {"null_contract": str(directory / "null-contract.log")}
                if manifest.null_contract
                else {}
            ),
            **(
                {"allocation_failure": str(directory / "allocation-failure.log")}
                if manifest.allocation_failure
                else {}
            ),
            **(
                {"copy_observer": str(directory / "copy-observer.log")}
                if observer == "asan" and manifest.build.preset == "clang-asan-copy-debug"
                else {}
            ),
            **({"ubsan_bounds": str(work / "stderr.txt")} if observer == "asan-bounds" else {}),
        },
        **data,
    )
