import json
import os
import platform
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import typer
import yaml

from .batch import run_batch
from .engine import verify
from .manifest import load_manifest
from .models import BuildConfig, Entry, Manifest, Result
from .profiles import available_profiles, load_profile
from .reporting import markdown
from .sample_import import import_case

app = typer.Typer(no_args_is_help=True, help="Verify C CWE claims using runtime evidence.")


def resolve_catalog(catalog: Path | None) -> Path:
    if catalog is not None:
        return catalog
    # The project root is the sole implicit catalog location.  Callers that
    # intentionally keep the catalog elsewhere must pass --catalog.
    return Path("699.csv")


@app.command("init")
def init_manifest(source: Path, output: Path, stdin: str = "") -> None:
    """Create a manifest with its claimed CWE derived from the C filename."""
    match = re.match(r"^CWE-?(\d+)(?:[_.-]|$)", source.name, re.IGNORECASE)
    if not match or not source.is_file() or source.suffix.lower() != ".c":
        typer.echo("Expected an existing CWE<number>.c or CWE-<number>_name.c", err=True)
        raise typer.Exit(2)
    cwe = f"CWE-{int(match[1])}"
    profile = next((p for p in available_profiles() if p.cwe_id == cwe), None)
    try:
        source_path = os.path.relpath(source.resolve(), output.resolve().parent)
    except ValueError:
        source_path = str(source.resolve())
    manifest = Manifest(
        sample_id=f"sample-cwe{int(match[1])}",
        sources=[source_path],
        claimed_cwe=cwe,
        entry=Entry(stdin=stdin),
        profile=f"{profile.profile_id}@{profile.version}" if profile else "unsupported@1.0.0",
        build=BuildConfig(preset=profile.build_preset if profile else "clang-asan-debug"),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x", encoding="utf-8") as handle:
            yaml.safe_dump(
                manifest.model_dump(exclude_none=True), handle, allow_unicode=True, sort_keys=False
            )
    except FileExistsError as exc:
        typer.echo(f"Manifest already exists: {output}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"Created {output}; claimed CWE={cwe}; review input before running.")


@app.command()
def doctor() -> None:
    """Check the supported OS, compiler, ASan runtime and symbolizer."""
    import tempfile

    from .compiler import compile_sources
    from .models import Manifest
    from .runner import run_binary

    info = {
        "platform": platform.system(),
        "python": platform.python_version(),
        "clang": shutil.which("clang"),
        "symbolizer": shutil.which("llvm-symbolizer"),
        "asan_smoke": "not run",
        "valgrind": shutil.which("valgrind"),
        "fd_tracking_smoke": "not run",
    }
    if platform.system() == "Linux" and info["clang"]:
        with tempfile.TemporaryDirectory(prefix="cwe-doctor-") as tmp:
            root = Path(tmp)
            source = root / "check.c"
            source.write_text("int main(void) { return 0; }\n")
            build = compile_sources([source], root / "build", "doctor")
            if build.exit_code == 0:
                manifest = Manifest(
                    sample_id="doctor",
                    sources=[str(source)],
                    claimed_cwe="CWE-125",
                    profile="c.oob-read@1.0.0",
                )
                run = run_binary(build, manifest, root / "run", [], "doctor")
                info["asan_smoke"] = "PASS" if run.exit_code == 0 else "FAIL"
            else:
                info["asan_smoke"] = "FAIL: " + Path(build.stderr).read_text()
            if info["valgrind"]:
                fd_source = root / "fd-check.c"
                fd_source.write_text(
                    '#include <fcntl.h>\nint main(void) { return open("/dev/null", O_RDONLY) < 0; }\n'
                )
                fd_build = compile_sources(
                    [fd_source], root / "fd-build", "fd-doctor", "clang-debug"
                )
                if fd_build.exit_code == 0:
                    fd_manifest = Manifest(
                        sample_id="fd-doctor",
                        sources=[str(fd_source)],
                        claimed_cwe="CWE-772",
                        profile="c.posix-resource-release@1.0.0",
                        build=BuildConfig(preset="clang-debug"),
                    )
                    fd_run = run_binary(
                        fd_build,
                        fd_manifest,
                        root / "fd-run",
                        [],
                        "fd-doctor",
                        observer="valgrind-fd",
                    )
                    from .adapters.valgrind_fd import parse_valgrind_fd

                    info["fd_tracking_smoke"] = (
                        "PASS" if parse_valgrind_fd(fd_run, [str(fd_source)]) else "FAIL"
                    )
    typer.echo(json.dumps(info, indent=2))
    if platform.system() == "Linux" and (
        not info["clang"] or info["asan_smoke"] != "PASS" or info["fd_tracking_smoke"] != "PASS"
    ):
        raise typer.Exit(1)


@app.command()
def validate(manifest: Path) -> None:
    """Validate manifest schema, sources, fixtures and the profile/claim relation."""
    try:
        value = load_manifest(manifest)
        profile = load_profile(value.profile)
        if profile and profile.cwe_id != value.claimed_cwe:
            raise ValueError("profile CWE does not match claimed_cwe")
        if (
            profile
            and profile.build_preset != value.build.preset
            and value.build.preset not in profile.compatible_build_presets
        ):
            raise ValueError("build preset does not match profile")
        typer.echo(f"VALID: {value.sample_id}; profile={'supported' if profile else 'UNSUPPORTED'}")
    except (ValueError, OSError, yaml.YAMLError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc


@app.command("import-case")
def import_reviewed_case(base_manifest: Path, case_spec: Path, output_manifest: Path) -> None:
    """Import one approved fixed regression case without changing its verifier policy."""
    try:
        output = import_case(base_manifest, case_spec, output_manifest)
        typer.echo(f"Imported reviewed case: {output}")
        typer.echo("Run cweverify validate on the generated manifest before execution.")
    except (ValueError, OSError, yaml.YAMLError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(2) from exc


def display(result: Result) -> None:
    typer.echo(
        f"{result.manifest.sample_id}: {result.manifest.claimed_cwe} "
        f"{result.decision.status} ({result.decision.reason_code})\n"
        f"Report: {result.artifact_dir}/report.md\n"
        f"JSON: {result.artifact_dir}/result.json"
    )
    if result.decision.status == "ERROR":
        raise typer.Exit(1)


@app.command()
def run(
    manifest: Path, output: Path = Path(".cwe-witness/runs"), catalog: Path | None = None
) -> None:
    """Compile and verify a manifest, preserving evidence and source snapshots."""
    try:
        display(verify(manifest, output, resolve_catalog(catalog)))
    except (ValueError, OSError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc


@app.command()
def explain(result: Path) -> None:
    """Render a stored, schema-validated result."""
    typer.echo(markdown(Result.model_validate_json(result.read_text(encoding="utf-8"))))


@app.command()
def batch(
    directory: Path = Path("manifests/calibration"),
    output: Path = Path(".cwe-witness/runs"),
    catalog: Path | None = None,
    jobs: int = typer.Option(
        0, "--jobs", help="Parallel workers; 0 uses the machine's CPU core count."
    ),
) -> None:
    """Verify prepared manifests (in parallel) and retain a summary of every outcome."""
    paths = sorted(directory.glob("*.yaml"))
    if not paths:
        typer.echo("No YAML manifests found", err=True)
        raise typer.Exit(2)

    def worker(path: Path) -> dict[str, str]:
        try:
            result = verify(path, output, resolve_catalog(catalog))
            return {
                "manifest": str(path),
                "sample": result.manifest.sample_id,
                "cwe": result.manifest.claimed_cwe,
                "status": result.decision.status,
                "reason": result.decision.reason_code,
                "report": str(Path(result.artifact_dir) / "report.md"),
            }
        except Exception as exc:  # noqa: BLE001 - one bad manifest must not lose the summary
            return {
                "manifest": str(path),
                "sample": path.stem,
                "cwe": "unknown",
                "status": "ERROR",
                "reason": str(exc),
                "report": "",
            }

    workers = jobs if jobs > 0 else (os.cpu_count() or 1)
    if workers > 1 and len(paths) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            # map() preserves input order, so rows match the sorted manifest order.
            rows = list(pool.map(worker, paths))
    else:
        rows = [worker(path) for path in paths]
    failed = False
    for row in rows:
        failed |= row["status"] == "ERROR"
        typer.echo(f"{row['sample']}: {row['status']} ({row['reason']})")
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    lines = [
        "# Repository verification",
        "",
        "| Sample | CWE | Result | Report |",
        "|---|---|---|---|",
    ]
    for row in rows:
        report_link = (
            Path(row["report"]).relative_to(output.resolve()).as_posix() if row["report"] else ""
        )
        lines.append(
            f"| {row['sample']} | {row['cwe']} | {row['status']} | [report]({report_link}) |"
        )
    (output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    typer.echo(f"Summary: {output / 'summary.md'}")
    if failed:
        raise typer.Exit(1)


@app.command("batch-sources")
def batch_sources(
    manifest: Path,
    output: Path = Path(".cwe-witness/batches"),
    catalog: Path | None = None,
    jobs: int = typer.Option(
        0, "--jobs", help="Parallel workers; 0 uses the machine's CPU core count."
    ),
) -> None:
    """Discover and independently verify multiple programs for one CWE."""
    try:
        directory, rows = run_batch(manifest, output, resolve_catalog(catalog), jobs=jobs)
    except (ValueError, OSError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(2) from exc
    for row in rows:
        typer.echo(f"{row['source']}: {row['status']} ({row['reason']})")
    counts = {
        status: sum(row["status"] == status for row in rows)
        for status in ("CONFIRMED", "NOT_CONFIRMED", "UNSUPPORTED", "ERROR")
    }
    typer.echo("Counts: " + ", ".join(f"{status}={count}" for status, count in counts.items()))
    typer.echo(f"Summary: {directory / 'summary.md'}")
    if any(row["status"] == "ERROR" for row in rows):
        raise typer.Exit(1)


@app.command()
def replay(result: Path, output: Path = Path(".cwe-witness/runs")) -> None:
    """Check artifact hashes and replay the original binary and frozen inputs."""
    try:
        previous = Result.model_validate_json(result.read_text(encoding="utf-8"))
        if not previous.builds or not previous.runs:
            raise ValueError("result has no executable witness to replay")
        display(verify(result, output, resolve_catalog(None), previous=previous))
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc


if __name__ == "__main__":
    app()
