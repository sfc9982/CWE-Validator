import json
import os
import re
import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from .manifest import discover_batch_sources, load_batch_manifest
from .models import (
    BatchManifest,
    BuildConfig,
    Control,
    Entry,
    Fixture,
    Manifest,
    NetworkFixture,
    Profile,
)
from .profiles import available_profiles


def _profile_for(batch: BatchManifest) -> tuple[str, Profile | None]:
    if batch.profile:
        profile_id = batch.profile
        profile = next(
            (
                item
                for item in available_profiles()
                if f"{item.profile_id}@{item.version}" == profile_id
            ),
            None,
        )
        return profile_id, profile
    profiles = [item for item in available_profiles() if item.cwe_id == batch.claimed_cwe]
    profile = next(
        (item for item in profiles if item.profile_id == "c.posix-resource-release"), None
    )
    profile = profile or (profiles[0] if profiles else None)
    return (
        f"{profile.profile_id}@{profile.version}" if profile else "unsupported@1.0.0",
        profile,
    )


def _sample_id(batch_id: str, relative_source: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", relative_source).strip("-")
    return f"{batch_id}-{slug}"


def _resolved_fixture(config_path: Path, fixture: Fixture) -> Fixture:
    return fixture.model_copy(
        update={"source": str((config_path.parent / fixture.source).resolve())},
    )


def build_manifest(
    config_path: Path,
    batch: BatchManifest,
    relative_source: str,
    source_path: Path,
) -> Manifest:
    """Expand one discovered source into the normal verification Manifest."""
    override = batch.overrides.get(relative_source)
    profile_id, profile = _profile_for(batch)
    if override and override.profile:
        profile_id = override.profile
        profile = next(
            (
                item
                for item in available_profiles()
                if f"{item.profile_id}@{item.version}" == profile_id
            ),
            None,
        )

    entry = batch.entry
    if override and override.entry:
        entry_update = override.entry.model_dump(exclude_none=True)
        if "stdin_file" in entry_update:
            entry_update["stdin"] = ""
        elif "stdin" in entry_update:
            entry_update["stdin_file"] = None
        # Re-validate rather than model_copy(update=...) so the stdin_file
        # path rules apply to override values too.
        entry = Entry.model_validate({**entry.model_dump(), **entry_update})
    run = batch.run
    if override and override.run:
        run = run.model_copy(
            update={
                key: value for key, value in override.run.model_dump(exclude_none=True).items()
            },
        )
    replay = batch.replay
    if override and override.replay:
        replay = replay.model_copy(
            update={
                key: value for key, value in override.replay.model_dump(exclude_none=True).items()
            },
        )
    fixture_values = (
        override.fixtures if override and override.fixtures is not None else batch.fixtures
    )
    fixtures = [_resolved_fixture(config_path, fixture) for fixture in fixture_values]

    control: Control | None = None
    if override and override.control:
        control = override.control.model_copy(
            update={
                "sources": [
                    str((config_path.parent / source).resolve())
                    for source in override.control.sources
                ],
            },
        )
    build = override.build if override and override.build else batch.build
    if build is None:
        build = BuildConfig(preset=profile.build_preset if profile else "clang-asan-debug")
    path_policy = batch.path_policy
    if override and override.path_policy:
        if path_policy:
            path_policy = path_policy.model_copy(
                update=override.path_policy.model_dump(exclude_unset=True)
            )
        else:
            path_policy = override.path_policy
    allocation_failure = batch.allocation_failure
    if override and override.allocation_failure is not None:
        allocation_failure = override.allocation_failure
    network_fixture: NetworkFixture | None = batch.network_fixture
    if override and override.network_fixture is not None:
        network_fixture = override.network_fixture
    function_failure = batch.function_failure
    if override and override.function_failure is not None:
        function_failure = override.function_failure
    null_contract = batch.null_contract
    if override and override.null_contract is not None:
        null_contract = override.null_contract
    resource_lifecycle = batch.resource_lifecycle
    if override and override.resource_lifecycle is not None:
        resource_lifecycle = override.resource_lifecycle
    return Manifest(
        sample_id=(
            override.sample_id
            if override and override.sample_id
            else _sample_id(batch.batch_id, relative_source)
        ),
        sources=[str(source_path.resolve())],
        claimed_cwe=batch.claimed_cwe,
        profile=profile_id,
        entry=entry,
        build=build,
        run=run,
        replay=replay,
        fixtures=fixtures,
        control=control,
        path_policy=path_policy,
        allocation_failure=allocation_failure,
        network_fixture=network_fixture,
        function_failure=function_failure,
        null_contract=null_contract,
        resource_lifecycle=resource_lifecycle,
    )


def _report_path(report: str, batch_directory: Path) -> str:
    if not report:
        return ""
    return Path(report).resolve().relative_to(batch_directory.resolve()).as_posix()


def run_batch(
    config_path: Path,
    output: Path,
    catalog: Path,
    jobs: int = 1,
) -> tuple[Path, list[dict[str, object]]]:
    """Run all discovered programs and write a batch summary.

    Manifest expansion stays serial so source ordering and duplicate
    detection are deterministic; the per-sample ``verify`` calls run in a
    thread pool when ``jobs`` > 1. Every verification writes to its own
    uuid-keyed artifact directory, so workers share no mutable state.
    """
    from .engine import verify

    batch = load_batch_manifest(config_path)
    sources = discover_batch_sources(config_path, batch)
    if not sources:
        raise ValueError(f"no {batch.claimed_cwe} .c files found in {batch.source_directory}")
    unknown_overrides = sorted(set(batch.overrides) - {name for name, _ in sources})
    if unknown_overrides:
        raise ValueError(f"override source was not discovered: {unknown_overrides[0]}")

    batch_directory = (output / f"{batch.batch_id}-{uuid.uuid4().hex}").resolve()
    manifest_directory = batch_directory / "manifests"
    result_directory = batch_directory / "results"
    manifest_directory.mkdir(parents=True)
    prepared: list[tuple[str, Manifest, Path]] = []
    sample_ids: set[str] = set()
    for index, (relative_source, source_path) in enumerate(sources, start=1):
        manifest = build_manifest(config_path, batch, relative_source, source_path)
        if manifest.sample_id in sample_ids:
            raise ValueError(f"duplicate sample_id in batch: {manifest.sample_id}")
        sample_ids.add(manifest.sample_id)
        generated_path = manifest_directory / f"{index:04d}-{manifest.sample_id}.yaml"
        if manifest.entry.stdin_file:
            source_stdin = (config_path.parent / manifest.entry.stdin_file).resolve()
            if not source_stdin.is_file():
                raise ValueError(f"stdin fixture is missing: {manifest.entry.stdin_file}")
            stdin_target = manifest_directory / "stdin" / f"{index:04d}-{source_stdin.name}"
            stdin_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_stdin, stdin_target)
            manifest.entry = manifest.entry.model_copy(
                update={"stdin_file": str(Path("stdin") / stdin_target.name)}
            )
        generated_path.write_text(
            yaml.safe_dump(
                manifest.model_dump(exclude_none=True), allow_unicode=True, sort_keys=False
            ),
            encoding="utf-8",
        )
        prepared.append((relative_source, manifest, generated_path))

    def worker(item: tuple[str, Manifest, Path]) -> dict[str, object]:
        relative_source, manifest, generated_path = item
        try:
            result = verify(generated_path, result_directory, catalog)
            return {
                "source": relative_source,
                "sample": result.manifest.sample_id,
                "cwe": result.manifest.claimed_cwe,
                "status": result.decision.status,
                "reason": result.decision.reason_code,
                "report": _report_path(
                    str(Path(result.artifact_dir) / "report.md"), batch_directory
                ),
            }
        except Exception as exc:  # noqa: BLE001 - one bad sample must not lose the batch summary
            return {
                "source": relative_source,
                "sample": manifest.sample_id,
                "cwe": manifest.claimed_cwe,
                "status": "ERROR",
                "reason": str(exc),
                "report": "",
            }

    workers = jobs if jobs > 0 else (os.cpu_count() or 1)
    if workers > 1 and len(prepared) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            # map() preserves input order, so rows stay in stable source order.
            rows = list(pool.map(worker, prepared))
    else:
        rows = [worker(item) for item in prepared]

    counts = {
        status: sum(row["status"] == status for row in rows)
        for status in ("CONFIRMED", "NOT_CONFIRMED", "UNSUPPORTED", "ERROR")
    }
    summary = {"batch_id": batch.batch_id, "rows": rows, "counts": counts}
    (batch_directory / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    lines = [
        f"# Batch verification: {batch.batch_id}",
        "",
        f"CWE: `{batch.claimed_cwe}`",
        "",
        "| Source | Sample | Status | Reason | Report |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        report = f"[report]({row['report']})" if row["report"] else ""
        lines.append(
            f"| `{row['source']}` | {row['sample']} | {row['status']} | "
            f"{row['reason']} | {report} |"
        )
    lines.extend(
        [
            "",
            "| Status | Count |",
            "|---|---:|",
            *[f"| {status} | {count} |" for status, count in counts.items()],
        ]
    )
    (batch_directory / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return batch_directory, rows
