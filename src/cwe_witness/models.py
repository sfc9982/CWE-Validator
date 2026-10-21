from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Entry(Model):
    scope: Literal["program"] = "program"
    stdin: str = ""
    stdin_file: str | None = None
    argv: list[str] = Field(default_factory=list)

    @field_validator("stdin_file")
    @classmethod
    def safe_stdin_file(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from pathlib import PurePosixPath, PureWindowsPath

        path = PurePosixPath(value)
        if not value or path.is_absolute() or PureWindowsPath(value).drive or "\\" in value:
            raise ValueError("stdin_file must be a relative path")
        return value

    @model_validator(mode="after")
    def exclusive_stdin_source(self) -> "Entry":
        if self.stdin_file is not None and self.stdin:
            raise ValueError("stdin and stdin_file are mutually exclusive")
        return self


class BuildConfig(Model):
    language: Literal["c"] = "c"
    standard: Literal["c11"] = "c11"
    preset: Literal[
        "clang-asan-debug",
        "clang-debug",
        "clang-ubsan-debug",
        "clang-ubsan-float-debug",
        "clang-asan-ubsan-debug",
        "clang-asan-recover-debug",
        "clang-asan-copy-debug",
        "clang-asan-bounds-debug",
    ] = "clang-asan-debug"


class RunConfig(Model):
    timeout_seconds: float = Field(default=5, gt=0, le=60)
    output_limit_bytes: int = Field(default=1048576, ge=1024, le=16777216)
    termination: Literal["normal", "graceful-window"] = "normal"
    termination_grace_seconds: float = Field(default=1, gt=0, le=10)


class ReplayConfig(Model):
    count: int = Field(default=2, ge=1, le=10)


class AllocationFailure(Model):
    function: Literal["malloc", "calloc"]
    call_index: int = Field(default=1, ge=1)


class FunctionFailure(Model):
    function: Literal["fopen"]
    call_index: int = Field(default=1, ge=1)


class NullContract(Model):
    function: Literal["fprintf", "fread"]
    argument_index: Literal[1, 4] = 1

    @model_validator(mode="after")
    def known_nonnull_argument(self) -> "NullContract":
        expected = {"fprintf": 1, "fread": 4}[self.function]
        if self.argument_index != expected:
            raise ValueError(f"{self.function} requires non-NULL argument {expected}")
        return self


def _default_allocators() -> list[Literal["malloc", "calloc"]]:
    return ["malloc", "calloc"]


class ResourceLifecycle(Model):
    resource_type: str = Field(min_length=1, pattern=r"^[a-zA-Z0-9_.-]+$")
    acquire_functions: list[str] = Field(min_length=1)
    allocators: list[Literal["malloc", "calloc"]] = Field(default_factory=_default_allocators)


class NetworkFixture(Model):
    protocol: Literal["tcp"] = "tcp"
    response: str = "OK\n"
    max_connections: int = Field(default=1, ge=1, le=1000)


class Fixture(Model):
    source: str
    destination: str

    @field_validator("destination")
    @classmethod
    def safe_destination(cls, value: str) -> str:
        from pathlib import PurePosixPath, PureWindowsPath

        if (
            not value
            or PurePosixPath(value).is_absolute()
            or PureWindowsPath(value).drive
            or "\\" in value
            or ".." in PurePosixPath(value).parts
            or value == "."
            or value in {"stdin.txt", "stdout.txt", "stderr.txt"}
        ):
            raise ValueError("fixture destination must be a relative path without traversal")
        return value


class Control(Model):
    sources: list[str] = Field(min_length=1)
    review_note: str = Field(min_length=10)
    expected_stdout: str


class PathMount(Model):
    source: str
    destination: str

    @field_validator("source")
    @classmethod
    def safe_source(cls, value: str) -> str:
        from pathlib import PurePosixPath, PureWindowsPath

        if (
            not value
            or PurePosixPath(value).is_absolute()
            or PureWindowsPath(value).drive
            or "\\" in value
            or ".." in PurePosixPath(value).parts
        ):
            raise ValueError("path mount source must be a relative path without traversal")
        return value

    @field_validator("destination")
    @classmethod
    def absolute_destination(cls, value: str) -> str:
        from pathlib import PurePosixPath

        if not PurePosixPath(value).is_absolute() or ".." in PurePosixPath(value).parts:
            raise ValueError("path mount destination must be an absolute path without traversal")
        return value


class PathPolicy(Model):
    allowed_root: str
    boundary_source: Literal["explicit", "source_inference", "working_directory_assumption"] = "explicit"
    inference_evidence: list[str] = Field(default_factory=list)
    outside_target: str | None = None
    marker: str | None = None
    operation: Literal["read", "write", "any"] = "any"
    mounts: list[PathMount] = Field(default_factory=list)


class ObservationCandidate(Model):
    kind: str
    file: str
    line: int | None = None
    detail: str
    execution_status: Literal["unknown", "executed", "not_observed"] = "unknown"
    monitor_status: Literal["planned", "observer_enabled", "unavailable", "unknown"] = "planned"


class ObservationPlan(Model):
    mode: Literal["adaptive", "explicit"] = "adaptive"
    primary_observer: str
    planned_observers: list[str] = Field(default_factory=list)
    max_supplemental_runs: int = 3
    candidates: list[ObservationCandidate] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    tool_versions: dict[str, str] = Field(default_factory=dict)


class EntryOverride(Model):
    stdin: str | None = None
    stdin_file: str | None = None
    argv: list[str] | None = None


class RunOverride(Model):
    timeout_seconds: float | None = Field(default=None, gt=0, le=60)
    output_limit_bytes: int | None = Field(default=None, ge=1024, le=16777216)
    termination: Literal["normal", "graceful-window"] | None = None
    termination_grace_seconds: float | None = Field(default=None, gt=0, le=10)


class ReplayOverride(Model):
    count: int | None = Field(default=None, ge=1, le=10)


class BatchOverride(Model):
    sample_id: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.-]+$")
    entry: EntryOverride | None = None
    run: RunOverride | None = None
    replay: ReplayOverride | None = None
    fixtures: list[Fixture] | None = None
    control: Control | None = None
    path_policy: PathPolicy | None = None
    observation_mode: Literal["adaptive", "explicit"] | None = None
    max_supplemental_runs: int | None = Field(default=None, ge=0, le=3)
    allocation_failure: AllocationFailure | None = None
    network_fixture: NetworkFixture | None = None
    profile: str | None = None
    build: BuildConfig | None = None
    function_failure: FunctionFailure | None = None
    null_contract: NullContract | None = None
    resource_lifecycle: ResourceLifecycle | None = None


class BatchManifest(Model):
    schema_version: Literal["1.0"] = "1.0"
    batch_id: str = Field(pattern=r"^[a-zA-Z0-9_.-]+$")
    source_directory: str
    claimed_cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    profile: str | None = None
    recursive: bool = False
    entry: Entry = Field(default_factory=Entry)
    build: BuildConfig | None = None
    run: RunConfig = Field(default_factory=RunConfig)
    replay: ReplayConfig = Field(default_factory=ReplayConfig)
    fixtures: list[Fixture] = Field(default_factory=list)
    path_policy: PathPolicy | None = None
    observation_mode: Literal["adaptive", "explicit"] = "adaptive"
    max_supplemental_runs: int = Field(default=3, ge=0, le=3)
    allocation_failure: AllocationFailure | None = None
    network_fixture: NetworkFixture | None = None
    function_failure: FunctionFailure | None = None
    null_contract: NullContract | None = None
    resource_lifecycle: ResourceLifecycle | None = None
    overrides: dict[str, BatchOverride] = Field(default_factory=dict)


class Manifest(Model):
    schema_version: Literal["1.0"] = "1.0"
    sample_id: str = Field(pattern=r"^[a-zA-Z0-9_.-]+$")
    sources: list[str] = Field(min_length=1)
    claimed_cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    profile: str
    entry: Entry = Field(default_factory=Entry)
    build: BuildConfig = Field(default_factory=BuildConfig)
    run: RunConfig = Field(default_factory=RunConfig)
    replay: ReplayConfig = Field(default_factory=ReplayConfig)
    fixtures: list[Fixture] = Field(default_factory=list)
    control: Control | None = None
    path_policy: PathPolicy | None = None
    observation_mode: Literal["adaptive", "explicit"] = "adaptive"
    max_supplemental_runs: int = Field(default=3, ge=0, le=3)
    allocation_failure: AllocationFailure | None = None
    network_fixture: NetworkFixture | None = None
    function_failure: FunctionFailure | None = None
    null_contract: NullContract | None = None
    resource_lifecycle: ResourceLifecycle | None = None

    @model_validator(mode="after")
    def paired_null_contract_injection(self) -> "Manifest":
        # The fopen failure shim and the fprintf NULL-sink contract are one
        # mechanism; the compiler cannot build either half on its own.
        if (self.function_failure is None) != (self.null_contract is None):
            raise ValueError("function_failure and null_contract must be configured together")
        return self


class Profile(Model):
    schema_version: Literal["1.0"] = "1.0"
    profile_id: str
    version: str = "1.0.0"
    cwe_id: str
    mechanism: str
    operation: str | None = None
    observer: Literal[
        "asan", "asan-bounds", "valgrind-fd", "ubsan", "path-trace", "resource-lifecycle"
    ] = "asan"
    build_preset: Literal[
        "clang-asan-debug",
        "clang-debug",
        "clang-ubsan-debug",
        "clang-ubsan-float-debug",
        "clang-asan-ubsan-debug",
        "clang-asan-recover-debug",
        "clang-asan-copy-debug",
        "clang-asan-bounds-debug",
    ] = "clang-asan-debug"
    compatible_build_presets: list[str] = Field(default_factory=list)
    # Retained only so historical Profile/result JSON remains readable.
    # The engine treats every control as optional regardless of this value.
    control_required: bool = False
    required_predicates: list[str]


class Build(Model):
    build_id: str
    argv: list[str]
    commands: list[list[str]] = Field(default_factory=list)
    launch_argv: list[str] = Field(default_factory=list)
    compiler_version: str
    source_hashes: dict[str, str]
    binary: str
    binary_hash: str | None = None
    exit_code: int
    stdout: str
    stderr: str


class Run(Model):
    run_id: str
    build_id: str
    argv: list[str]
    launch_argv: list[str] = Field(default_factory=list)
    cwd: str
    environment: dict[str, str]
    stdin_hash: str
    binary_hash: str
    pid: int
    exit_code: int
    signal: int | None
    timeout: bool
    output_limited: bool
    controlled_termination: bool = False
    duration_seconds: float
    stdout: str
    stderr: str
    sanitizer_log: str
    observer: Literal[
        "asan", "asan-bounds", "valgrind-fd", "ubsan", "path-trace", "resource-lifecycle"
    ] = "asan"
    purpose: str = "primary"
    supplemental_reason: str | None = None
    evidence_log: str = ""
    program_argv: list[str] = Field(default_factory=list)
    symbol_binary: str = ""
    auxiliary_logs: dict[str, str] = Field(default_factory=dict)


class Location(Model):
    file: str
    line: int
    function: str | None = None
    # Column is needed internally to distinguish compound-assignment reads from
    # ordinary out-of-bounds reads.  It is intentionally omitted from the
    # serialized schema so historical result JSON remains compatible.
    column: int | None = Field(default=None, exclude=True)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Location):
            return NotImplemented
        return (self.file, self.line, self.function) == (
            other.file,
            other.line,
            other.function,
        )


class Observation(Model):
    observation_id: str
    run_id: str
    kind: str
    producer: str = "asan-text@1.0.0"
    operation: str | None = None
    size_bytes: int | None = None
    location: Location | None = None
    release_location: Location | None = None
    allocation_location: Location | None = None
    object_associated: bool = False
    bounds_associated: bool = False
    complete: bool = False
    raw_artifact: str
    line_start: int
    line_end: int
    descriptor: int | None = None
    resource_type: str | None = None
    resource_name: str | None = None
    resource_count: int | None = None
    arithmetic_operator: str | None = None
    operand_type: str | None = None
    operand_value: str | None = None
    copy_operation: str | None = None
    static_operation: str | None = None
    target_capacity: int | None = None
    actual_write_size: int | None = None
    related_evidence_ids: list[str] = Field(default_factory=list)
    failure_source: str | None = None
    path_operation: str | None = None
    path_outside_allowed: bool = False
    path_access_succeeded: bool = False
    path_raw: str | None = None
    path_resolved: str | None = None
    path_allowed_root: str | None = None
    path_boundary_source: str | None = None
    path_syscall: str | None = None
    path_syscall_return: int | None = None


class PredicateResult(Model):
    predicate: str
    status: Literal["SATISFIED", "CONTRADICTED", "UNKNOWN"]
    evidence_ids: list[str] = Field(default_factory=list)
    missing_requirements: list[str] = Field(default_factory=list)
    reason_code: str
    predicate_version: str = "1.0.0"


class DerivedFact(Model):
    fact_id: str
    predicate: str
    evidence_ids: list[str]


class Finding(Model):
    mechanism: str
    observation_id: str
    location: Location | None


class Decision(Model):
    status: Literal["CONFIRMED", "NOT_CONFIRMED", "UNSUPPORTED", "ERROR"]
    reason_code: str
    predicates: list[PredicateResult] = Field(default_factory=list)


class Result(Model):
    schema_version: Literal["1.0"] = "1.0"
    manifest: Manifest
    profile: Profile | None = None
    catalog: dict[str, str] = Field(default_factory=dict)
    fixture_hashes: dict[str, str] = Field(default_factory=dict)
    runtime_platform: dict[str, str] = Field(default_factory=dict)
    builds: list[Build] = Field(default_factory=list)
    runs: list[Run] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    derived_facts: list[DerivedFact] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    decision: Decision
    replay_signatures: list[str] = Field(default_factory=list)
    replay_consistent: bool | None = None
    run_decisions: dict[str, Decision] = Field(default_factory=dict)
    observation_plan: ObservationPlan | None = None
    monitoring_gaps: list[str] = Field(default_factory=list)
    supplemental_replay_consistent: dict[str, bool] = Field(default_factory=dict)
    supplemental_signatures: dict[str, list[str]] = Field(default_factory=dict)
    control_result: str = "Optional control not configured."
    artifact_dir: str
