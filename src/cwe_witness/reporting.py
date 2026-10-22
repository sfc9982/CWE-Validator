import json
import shlex
from pathlib import Path

from .models import Result


def markdown(result: Result) -> str:
    lines = [
        "# CWE Witness",
        "",
        "## Summary",
        "",
        f"Sample: {result.manifest.sample_id}",
        f"Target: {result.manifest.claimed_cwe}",
        f"Result: **{result.decision.status}** ({result.decision.reason_code})",
        "Scope: C / program / Linux",
        "",
        f"Catalog: {result.catalog.get('status')} — {result.catalog.get('name', '')}",
        "",
        "## Allocation failure injection",
        "",
        (
            f"Configured: `{result.manifest.allocation_failure.function}` call "
            f"`{result.manifest.allocation_failure.call_index}` returns NULL."
            if result.manifest.allocation_failure
            else "Not configured."
        ),
        "",
        "## What was observed",
        "",
    ]
    if result.manifest.imported_case:
        imported = result.manifest.imported_case
        lines[lines.index("## What was observed")] = "## Imported regression case"
        lines.extend(
            [
                f"Source: `{imported.source_tool}` version `{imported.upstream_version}`, "
                f"case `{imported.case_id}`; review status `{imported.review_status}`.",
                f"Reviewer note: {imported.review_note}",
                f"Upstream success claim (informational only): `{imported.upstream_success_claim}`.",
                f"Input SHA-256: `{imported.input_sha256}`",
                *[
                    f"- Source `{source}` SHA-256: `{value}`"
                    for source, value in imported.source_sha256.items()
                ],
                *[
                    f"- Fixture `{destination}` SHA-256: `{value}`"
                    for destination, value in imported.fixture_sha256.items()
                ],
                "",
                "## What was observed",
                "",
            ]
        )
    if result.manifest.path_policy:
        policy = result.manifest.path_policy
        lines[lines.index("## What was observed")] = "## Path boundary evidence"
        lines.extend(
            [
                f"Allowed root: `{policy.allowed_root}` ({policy.boundary_source}).",
                *[f"- Evidence: {item}" for item in policy.inference_evidence],
                "",
                "## What was observed",
                "",
            ]
        )
    if result.observation_plan:
        plan = result.observation_plan
        lines.extend(
            [
                "## Observation plan",
                "",
                f"Mode: `{plan.mode}`; primary observer: `{plan.primary_observer}`; "
                f"planned observers: {', '.join(plan.planned_observers)}.",
                f"Source candidates: {len(plan.candidates)}; supplemental run limit: "
                f"{plan.max_supplemental_runs}.",
                "Observer enabled does not prove that a source site executed or that every "
                "operation at that site was monitored; exact site-level coverage remains unknown.",
                *[f"- Tool `{tool}`: {version}" for tool, version in plan.tool_versions.items()],
                *[
                    f"- {site.file}:{site.line or '?'} `{site.kind}` ({site.monitor_status}); "
                    f"execution={site.execution_status}: {site.detail}"
                    for site in plan.candidates
                ],
                *[f"- Coverage gap: {gap}" for gap in result.monitoring_gaps],
                *[
                    f"- Supplemental `{observer}` replay consistent: {consistent}."
                    for observer, consistent in result.supplemental_replay_consistent.items()
                ],
                "",
            ]
        )
    for observation in result.observations:
        evidence_kind = "derived" if "+source-operation" in observation.producer else "direct"
        lines.append(
            f"- {observation.observation_id} ({evidence_kind}): {observation.kind}, "
            f"{observation.operation}, location={observation.location}; "
            f"allocation={observation.allocation_location}; "
            f"release={observation.release_location}; "
            f"object associated={observation.object_associated}; "
            f"resource={observation.resource_type}:{observation.resource_name}; "
            f"resource_count={observation.resource_count}; "
            f"descriptor={observation.descriptor}; "
            f"path_raw={observation.path_raw}; path_resolved={observation.path_resolved}; "
            f"allowed_root={observation.path_allowed_root}; "
            f"boundary_source={observation.path_boundary_source}; "
            f"syscall={observation.path_syscall}; return={observation.path_syscall_return}"
            f"; copy={observation.copy_operation}; target_capacity={observation.target_capacity}; "
            f"actual_write_size={observation.actual_write_size}; "
            f"producer={observation.producer}; complete={observation.complete}; "
            f"arithmetic={observation.operand_value} ({observation.operand_type})"
        )
    lines += [
        "",
        "## Why this supports the target",
        "",
        "| Predicate | Result | Evidence | Missing |",
        "|---|---|---|---|",
    ]
    for predicate in result.decision.predicates:
        lines.append(
            f"| {predicate.predicate} | {predicate.status} | "
            f"{', '.join(predicate.evidence_ids)} | "
            f"{', '.join(predicate.missing_requirements)} |"
        )
    lines += [
        "",
        "## What is not claimed",
        "",
        "NOT_CONFIRMED does not mean safe. No claim of exploitability, code execution, "
        "all-input coverage, or portability to other compilers/environments.",
        "",
        "## Reproduction",
        "",
    ]
    for build in result.builds:
        lines += [
            f"### {build.build_id}",
            "",
            "```text",
            *[shlex.join(command) for command in (build.commands or [build.argv])],
            build.compiler_version.strip(),
            "```",
            "",
            f"Binary SHA-256: `{build.binary_hash}`",
            "",
            "```json",
            json.dumps(build.source_hashes, indent=2),
            "```",
            "",
        ]
    for run in result.runs:
        lines += [
            f"### {run.run_id}",
            "",
            "```text",
            shlex.join(run.argv),
            "```",
            "",
            f"cwd: `{run.cwd}`; stdin SHA-256: `{run.stdin_hash}`; "
            f"exit: {run.exit_code}; signal: {run.signal}; timeout: {run.timeout}; "
            f"duration: {run.duration_seconds:.3f}s",
            "",
            "```json",
            json.dumps(run.environment, indent=2),
            "```",
            "",
        ]
    lines += [
        "Input (UTF-8):",
        "",
        "```json",
        json.dumps(result.manifest.entry.model_dump(), ensure_ascii=False, indent=2),
        "```",
        "",
        "## Replay / Control",
        "",
        f"Semantic signatures: {result.replay_signatures}",
        f"Replay consistent: {result.replay_consistent}",
        result.control_result,
        "",
        "## Raw evidence",
        "",
        "- [Manifest](manifest.json)",
        "- [Result JSON](result.json)",
    ]
    root = Path(result.artifact_dir)
    for run in result.runs:
        for label, value in [
            ("stdout", run.stdout),
            ("stderr", run.stderr),
            ("evidence", run.evidence_log or run.sanitizer_log),
        ]:
            path = Path(value)
            if path.is_file():
                relative = path.relative_to(root).as_posix()
                lines.append(f"- [{run.run_id} {label}]({relative})")
        for label, value in run.auxiliary_logs.items():
            path = Path(value)
            if path.is_file():
                relative = path.relative_to(root).as_posix()
                lines.append(f"- [{run.run_id} {label}]({relative})")
    return "\n".join(lines) + "\n"


def save(result: Result) -> None:
    directory = Path(result.artifact_dir)
    (directory / "result.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
    (directory / "manifest.json").write_text(
        result.manifest.model_dump_json(indent=2), encoding="utf-8"
    )
    (directory / "report.md").write_text(markdown(result), encoding="utf-8")
