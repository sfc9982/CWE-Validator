import hashlib
import json
import platform
import re
import shutil
import uuid
from pathlib import Path

from .adapters.asan import parse_asan
from .adapters.copy_observer import attach_copy_evidence, parse_copy_observer
from .adapters.null_contract import parse_null_contract
from .adapters.path_trace import parse_path_trace, trace_complete
from .adapters.resource_lifecycle import parse_resource_lifecycle
from .adapters.resource_lifecycle import report_complete as lifecycle_complete
from .adapters.ubsan import parse_ubsan, parse_ubsan_bounds
from .adapters.valgrind_fd import parse_valgrind_fd, report_complete
from .compiler import compile_sources
from .judging import judge
from .manifest import catalog_entry, digest, load_manifest
from .models import Build, Decision, DerivedFact, Finding, Manifest, Observation, Result, Run
from .profiles import load_profile
from .reporting import save
from .runner import run_binary


def signature(observations: list[Observation]) -> str:
    facts = sorted(
        [
            {
                "kind": o.kind,
                "operation": o.operation,
                "file": Path(o.location.file).name if o.location else None,
                "line": o.location.line if o.location else None,
                "object_associated": o.object_associated,
                "bounds_associated": o.bounds_associated,
                "allocation": (Path(o.allocation_location.file).name, o.allocation_location.line)
                if o.allocation_location
                else None,
                "release": (Path(o.release_location.file).name, o.release_location.line)
                if o.release_location
                else None,
                "complete": o.complete,
                "resource_type": o.resource_type,
                "resource_count": o.resource_count,
                "resource_name": (
                    "tcp:loopback"
                    if o.resource_type == "socket" and o.resource_name
                    else Path(o.resource_name).name
                    if o.resource_name
                    else None
                ),
                "arithmetic_operator": o.arithmetic_operator,
                "operand_type": o.operand_type,
                "operand_value": o.operand_value,
                "copy_operation": o.copy_operation,
                "static_operation": o.static_operation,
                "target_capacity": o.target_capacity,
                "actual_write_size": o.actual_write_size,
                "path_operation": o.path_operation,
                "path_outside_allowed": o.path_outside_allowed,
                "path_raw": o.path_raw,
                "path_resolved": o.path_resolved,
                "path_allowed_root": o.path_allowed_root,
                "path_syscall": o.path_syscall,
            }
            for o in observations
        ],
        key=lambda value: json.dumps(value, sort_keys=True),
    )
    return hashlib.sha256(json.dumps(facts, sort_keys=True).encode()).hexdigest()


_COMPOUND_ASSIGNMENT_OPERATORS = (
    "<<=",
    ">>=",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "&=",
    "|=",
    "^=",
    "++",
    "--",
)


def _compound_assignment_operator_at(line: str, column: int | None) -> str | None:
    """Return the compound-assignment operator starting at an ASan column.

    ASan reports a compound-assignment read at the operator itself (for
    example ``monthly_totals[month_index] += hours`` points at ``+=``), not at
    the array expression.  Requiring the operator at that exact column avoids
    treating unrelated ``++``/``--`` tokens elsewhere on the same line as a
    write.  Logs without a column are handled conservatively: no promotion.
    """
    if column is None or column < 1:
        return None
    index = column - 1
    if index >= len(line):
        return None
    return next(
        (
            operator
            for operator in _COMPOUND_ASSIGNMENT_OPERATORS
            if line.startswith(operator, index)
        ),
        None,
    )


def promote_compound_write(observations: list[Observation]) -> list[Observation]:
    """Promote only ASan reads that are provably compound-assignment reads."""
    promoted: list[Observation] = []
    source_lines: dict[str, list[str]] = {}
    for observation in observations:
        if (
            observation.kind != "out_of_bounds"
            or observation.operation != "read"
            or not observation.location
        ):
            promoted.append(observation)
            continue
        try:
            lines = source_lines.get(observation.location.file)
            if lines is None:
                lines = (
                    Path(observation.location.file)
                    .read_text(encoding="utf-8", errors="replace")
                    .splitlines()
                )
                source_lines[observation.location.file] = lines
            line = lines[observation.location.line - 1]
        except (OSError, IndexError):
            promoted.append(observation)
            continue
        if _compound_assignment_operator_at(line, observation.location.column):
            promoted.append(
                observation.model_copy(
                    update={
                        "operation": "write",
                        "producer": "asan+source-operation@1.0.0",
                        "static_operation": "compound_assignment",
                        "related_evidence_ids": [observation.observation_id],
                    }
                )
            )
        else:
            promoted.append(observation)
    return promoted


_NETWORK_PLACEHOLDERS = {
    "{network_host}": r"127\.0\.0\.1",
    "{network_port}": r"\d{1,5}",
}


def _argv_matches_entry(actual: list[str], template: list[str], network: bool) -> bool:
    """Compare a recorded argv with the manifest's argv template.

    With a network fixture the runner substitutes an ephemeral loopback port
    into the program arguments, so those positions are matched structurally
    instead of literally.
    """
    if len(actual) != len(template):
        return False
    for value, expected in zip(actual, template, strict=True):
        if value == expected:
            continue
        if not network:
            return False
        pattern = re.escape(expected)
        for placeholder, replacement in _NETWORK_PLACEHOLDERS.items():
            pattern = pattern.replace(re.escape(placeholder), replacement)
        if not re.fullmatch(pattern, value):
            return False
    return True


def _parse_observations(
    run: Run, sources: list[str], manifest: Manifest, observer: str
) -> list[Observation]:
    """Parse one run's evidence log with the adapter for its observer."""
    if observer in ("asan", "asan-bounds"):
        observations = parse_asan(run, sources)
        if manifest.build.preset == "clang-asan-copy-debug":
            copy_observations = parse_copy_observer(run, sources)
            observations = attach_copy_evidence(observations, copy_observations)
            seen = {
                (Path(o.location.file).name, o.location.line) for o in observations if o.location
            }
            for item in copy_observations:
                if item.kind != "out_of_bounds" or not item.location:
                    continue
                key = (Path(item.location.file).name, item.location.line)
                if key in seen:
                    continue
                seen.add(key)
                observations.append(item)
        if observer == "asan-bounds":
            observations.extend(parse_ubsan_bounds(run, sources))
        return observations
    if observer == "valgrind-fd":
        return parse_valgrind_fd(run, sources)
    if observer == "ubsan":
        return [
            *parse_ubsan(run, sources, manifest.allocation_failure),
            *parse_null_contract(run, sources),
        ]
    if observer == "path-trace":
        return parse_path_trace(run, sources, manifest.path_policy)
    if observer == "resource-lifecycle":
        return parse_resource_lifecycle(run, sources, manifest.resource_lifecycle)
    return []


def _control_observer_ok(observer: str, run: Run) -> bool:
    """True when the observer produced a clean, complete report for the control."""
    if observer == "asan-bounds":
        stderr = Path(run.auxiliary_logs.get("ubsan_bounds", ""))
        return not Path(run.sanitizer_log).exists() and (
            not stderr.is_file()
            or "runtime error:" not in stderr.read_text(encoding="utf-8", errors="replace")
        )
    if observer in ("asan", "ubsan"):
        return not Path(run.sanitizer_log).exists()
    if observer == "valgrind-fd":
        return report_complete(run)
    if observer == "path-trace":
        return trace_complete(run)
    if observer == "resource-lifecycle":
        return lifecycle_complete(run)
    return False


def snapshot(sources: list[str], base: Path, destination: Path) -> list[str]:
    destination.mkdir(parents=True)
    names = [Path(s).name for s in sources]
    if len(names) != len(set(names)):
        raise ValueError("source basenames must be unique")
    for source, name in zip(sources, names, strict=True):
        shutil.copyfile(base / source, destination / name)
    return [str(destination / name) for name in names]


def verify(path: Path, output: Path, catalog: Path, previous: Result | None = None) -> Result:
    directory = (output / uuid.uuid4().hex).resolve()
    directory.mkdir(parents=True)
    manifest = previous.manifest.model_copy(deep=True) if previous else load_manifest(path)
    profile = load_profile(manifest.profile)
    if profile and profile.cwe_id != manifest.claimed_cwe:
        raise ValueError("profile CWE does not match claimed_cwe")
    result = Result(
        manifest=manifest,
        profile=profile,
        artifact_dir=str(directory),
        catalog=previous.catalog if previous else catalog_entry(catalog, manifest.claimed_cwe),
        runtime_platform={
            "system": platform.system(),
            "machine": platform.machine(),
            "release": platform.release(),
            "libc": " ".join(platform.libc_ver()),
        },
        decision=Decision(status="UNSUPPORTED", reason_code="UNSUPPORTED_PROFILE"),
    )
    if not profile:
        save(result)
        return result
    if (
        manifest.build.preset != profile.build_preset
        and manifest.build.preset not in profile.compatible_build_presets
    ):
        result.decision = Decision(status="ERROR", reason_code="BUILD_PRESET_MISMATCH")
        save(result)
        return result
    if platform.system() != "Linux":
        result.decision.reason_code = "UNSUPPORTED_PLATFORM"
        save(result)
        return result
    required_tools = {
        "valgrind-fd": ("valgrind", "bwrap") if manifest.path_policy else ("valgrind",),
        "resource-lifecycle": ("valgrind",),
        "path-trace": ("strace", "bwrap"),
    }.get(profile.observer, ())
    if any(not shutil.which(tool) for tool in required_tools):
        result.decision.reason_code = "OBSERVER_UNAVAILABLE"
        save(result)
        return result
    if previous:
        if previous.runtime_platform != result.runtime_platform:
            raise ValueError("runtime platform changed since original verification")
        if previous.profile != profile:
            raise ValueError("profile changed since original verification")
        if previous.manifest.allocation_failure != manifest.allocation_failure:
            raise ValueError("allocation failure injection changed")
        if (
            previous.manifest.function_failure != manifest.function_failure
            or previous.manifest.null_contract != manifest.null_contract
        ):
            raise ValueError("NULL contract injection changed")
        expected_stdin = hashlib.sha256(
            (
                (path.resolve().parent / manifest.entry.stdin_file).read_bytes()
                if manifest.entry.stdin_file
                else manifest.entry.stdin.encode()
            )
        ).hexdigest()
        if any(run.stdin_hash != expected_stdin for run in previous.runs):
            raise ValueError("stdin hash changed")
        if any(
            not _argv_matches_entry(
                run.program_argv[1:] if run.program_argv else run.argv[1:],
                manifest.entry.argv,
                manifest.network_fixture is not None,
            )
            for run in previous.runs
        ):
            raise ValueError("argv changed")
        for build in previous.builds:
            for source, expected in build.source_hashes.items():
                if digest(Path(source)) != expected:
                    raise ValueError(f"source hash changed: {source}")
            if not build.binary_hash or digest(Path(build.binary)) != build.binary_hash:
                raise ValueError("binary missing or hash changed")
        for fixture_path, expected in previous.fixture_hashes.items():
            if digest(Path(fixture_path)) != expected:
                raise ValueError("fixture hash changed")
        result.builds = previous.builds
        result.fixture_hashes = previous.fixture_hashes
    else:
        shutil.copyfile(path, directory / "input-manifest.yaml")
        manifest.sources = snapshot(manifest.sources, path.resolve().parent, directory / "sources")
        if manifest.control:
            manifest.control.sources = snapshot(
                manifest.control.sources, path.resolve().parent, directory / "control-sources"
            )
        for index, fixture in enumerate(manifest.fixtures):
            target = directory / "fixtures" / str(index)
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(path.resolve().parent / fixture.source, target)
            fixture.source = str(target)
            result.fixture_hashes[str(target)] = digest(target)
        result.builds.append(
            compile_sources(
                [Path(s) for s in manifest.sources],
                directory / "build",
                "target-build",
                manifest.build.preset,
                allocation_failure=manifest.allocation_failure,
                function_failure=manifest.function_failure,
                null_contract=manifest.null_contract,
                copy_observer=manifest.build.preset == "clang-asan-copy-debug",
            )
        )
    if manifest.entry.stdin_file:
        stdin_source = (path.resolve().parent / manifest.entry.stdin_file).resolve()
        if not stdin_source.is_file():
            raise FileNotFoundError(f"stdin fixture is missing: {manifest.entry.stdin_file}")
        stdin_target = directory / "stdin" / Path(manifest.entry.stdin_file).name
        stdin_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(stdin_source, stdin_target)
        manifest.entry = manifest.entry.model_copy(
            update={"stdin_file": str(Path("stdin") / stdin_target.name)}
        )
    build = result.builds[0]
    if build.exit_code != 0 or not build.binary_hash:
        result.decision = Decision(status="ERROR", reason_code="BUILD_FAILED")
        save(result)
        return result
    fixtures = [(Path(f.source), f.destination) for f in manifest.fixtures]
    decisions = []
    for index in range(manifest.replay.count):
        run = run_binary(
            build,
            manifest,
            directory / f"run-{index + 1}",
            fixtures,
            f"run-{index + 1}",
            observer=profile.observer,
            expected_environment=previous.runs[0].environment if previous else None,
            stdin_root=directory,
        )
        result.runs.append(run)
        observations = _parse_observations(run, manifest.sources, manifest, profile.observer)
        if manifest.claimed_cwe == "CWE-787":
            observations = promote_compound_write(observations)
        result.observations.extend(observations)
        decisions.append(judge(profile, run, observations))
        result.run_decisions[run.run_id] = decisions[-1]
        result.replay_signatures.append(signature(observations))
    result.decision = next(
        (decision for decision in decisions if decision.status == "ERROR"), decisions[0]
    )
    # A witness is reproducible only if every configured replay independently
    # meets the Profile. One successful run cannot mask a failed replay.
    if all(decision.status == "CONFIRMED" for decision in decisions):
        result.decision = decisions[0]
    elif result.decision.status != "ERROR":
        result.decision = next(
            (decision for decision in decisions if decision.status != "CONFIRMED"), decisions[0]
        )
    result.replay_consistent = len(set(result.replay_signatures)) == 1
    if previous:
        result.replay_consistent = (
            result.replay_consistent
            and bool(previous.replay_signatures)
            and result.replay_signatures[0] == previous.replay_signatures[0]
        )
    if result.decision.status == "CONFIRMED" and not result.replay_consistent:
        result.decision = Decision(
            status="NOT_CONFIRMED",
            reason_code="REPLAY_DIVERGED",
            predicates=result.decision.predicates,
        )
    if manifest.control:
        control_build: Build
        if previous and len(previous.builds) > 1:
            control_build = previous.builds[1]
        else:
            control_build = compile_sources(
                [Path(s) for s in manifest.control.sources],
                directory / "control-build",
                "control-build",
                manifest.build.preset,
                copy_observer=False,
            )
            result.builds.append(control_build)
        passed = False
        control_status = "FAIL: control build failed. "
        if control_build.exit_code == 0 and control_build.binary_hash:
            control_run = run_binary(
                control_build,
                manifest,
                directory / "control",
                fixtures,
                "control-run",
                observer=profile.observer,
                stdin_root=directory,
            )
            result.runs.append(control_run)
            control_observations = _parse_observations(
                control_run, manifest.control.sources, manifest, profile.observer
            )
            observer_ok = _control_observer_ok(profile.observer, control_run)
            passed = (
                control_run.exit_code == 0
                and not control_run.timeout
                and not control_run.output_limited
                and observer_ok
                and not control_observations
                and Path(control_run.stdout).read_bytes()
                == manifest.control.expected_stdout.encode()
            )
            if passed:
                control_status = "PASS: target error removed; reviewed functional output retained. "
            elif control_run.timeout or control_run.output_limited:
                control_status = "FAIL: optional control exceeded a runtime limit. "
            else:
                control_status = "FAIL: optional control run/output check failed. "
        result.control_result = control_status
        result.control_result += manifest.control.review_note
    result.findings = [
        Finding(mechanism=o.kind, observation_id=o.observation_id, location=o.location)
        for o in result.observations
    ]
    result.derived_facts = [
        DerivedFact(fact_id=f"fact-{i}", predicate=p.predicate, evidence_ids=p.evidence_ids)
        for i, p in enumerate(result.decision.predicates)
        if p.status == "SATISFIED"
    ]
    save(result)
    return result
