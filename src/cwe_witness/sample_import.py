"""Import reviewed, fixed regression cases without changing verifier policy."""

import hashlib
import json
import os
from pathlib import Path

import yaml

from .manifest import digest, load_manifest
from .models import Entry, ImportedCaseProvenance, ImportedCaseSpec, Manifest


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry_digest(entry: Entry) -> str:
    payload = json.dumps(
        entry.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return _sha256_bytes(payload)


def validate_imported_case(manifest: Manifest, manifest_path: Path) -> None:
    """Verify the imported inputs still match their recorded provenance hashes."""
    imported = manifest.imported_case
    if imported is None:
        return
    for source, expected in imported.source_sha256.items():
        path = Path(source)
        if not path.is_absolute():
            path = manifest_path.parent / path
        if not path.is_file() or digest(path) != expected:
            raise ValueError(f"imported case source hash changed or source missing: {source}")
    if entry_digest(manifest.entry) != imported.input_sha256:
        raise ValueError("imported case input hash changed")
    fixture_by_destination = {fixture.destination: fixture for fixture in manifest.fixtures}
    for destination, expected in imported.fixture_sha256.items():
        fixture = fixture_by_destination.get(destination)
        if fixture is None:
            raise ValueError(f"imported case fixture is missing: {destination}")
        fixture_path = Path(fixture.source)
        if not fixture_path.is_absolute():
            fixture_path = manifest_path.parent / fixture_path
        if not fixture_path.is_file() or digest(fixture_path) != expected:
            raise ValueError(f"imported case fixture hash changed: {destination}")


def _reference(path: Path, base: Path) -> str:
    try:
        return Path(os.path.relpath(path, base)).as_posix()
    except ValueError:
        return str(path)


def import_case(base_manifest_path: Path, case_spec_path: Path, output_manifest_path: Path) -> Path:
    """Create a manifest for a reviewed fixed case, preserving verifier policy."""
    base_path = base_manifest_path.resolve()
    case_path = case_spec_path.resolve()
    output_path = output_manifest_path.resolve()
    base = load_manifest(base_path)
    spec = ImportedCaseSpec.model_validate(yaml.safe_load(case_path.read_text(encoding="utf-8")))
    if base.imported_case is not None:
        raise ValueError("base manifest is already an imported case; use an original base manifest")

    case_root = case_path.parent
    imported_fixtures = []
    fixture_hashes: dict[str, str] = {}
    destinations = {fixture.destination for fixture in base.fixtures}
    for fixture in spec.fixtures:
        source = (case_root / fixture.source).resolve()
        try:
            source.relative_to(case_root)
        except ValueError as exc:
            raise ValueError(f"imported fixture escapes case directory: {fixture.source}") from exc
        if not source.is_file():
            raise ValueError(f"imported fixture does not exist: {fixture.source}")
        if fixture.destination in destinations:
            raise ValueError(f"imported fixture destination already exists: {fixture.destination}")
        destinations.add(fixture.destination)
        imported_fixtures.append(
            {"source": _reference(source, output_path.parent), "destination": fixture.destination}
        )
        fixture_hashes[fixture.destination] = digest(source)

    # Resolve all references before moving the derived manifest so its relative
    # paths continue to identify the same source and fixture files.
    source_hashes: dict[str, str] = {}
    for source in base.sources + (base.control.sources if base.control else []):
        resolved = (base_path.parent / source).resolve()
        if not resolved.is_file():
            raise ValueError(f"C source does not exist: {resolved}")
        source_hashes[_reference(resolved, output_path.parent)] = digest(resolved)
    for fixture in base.fixtures:
        resolved = (base_path.parent / fixture.source).resolve()
        fixture_hashes.setdefault(fixture.destination, digest(resolved))
        fixture.source = _reference(resolved, output_path.parent)

    entry = Entry(stdin=spec.entry.stdin, argv=spec.entry.argv)
    provenance = ImportedCaseProvenance(
        source_tool=spec.source_tool,
        upstream_version=spec.upstream_version,
        case_id=spec.case_id,
        review_status=spec.review_status,
        review_note=spec.review_note,
        upstream_success_claim=spec.upstream_success_claim,
        source_sha256=source_hashes,
        input_sha256=entry_digest(entry),
        fixture_sha256=fixture_hashes,
    )
    sample_id = f"{base.sample_id}-{spec.case_id}"
    values = base.model_dump(mode="python", exclude_none=True)
    values.update(
        sample_id=sample_id,
        sources=[_reference((base_path.parent / source).resolve(), output_path.parent) for source in base.sources],
        entry=entry.model_dump(mode="python"),
        fixtures=[fixture.model_dump(mode="python") for fixture in base.fixtures]
        + imported_fixtures,
        imported_case=provenance.model_dump(mode="python"),
    )
    if base.control:
        values["control"]["sources"] = [
            _reference((base_path.parent / source).resolve(), output_path.parent)
            for source in base.control.sources
        ]
    derived = Manifest.model_validate(values)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        raise FileExistsError(f"output manifest already exists: {output_path}")
    # Run the same checks that later validate/replay operations will enforce.
    validate_imported_case(derived, output_path)
    with output_path.open("x", encoding="utf-8") as handle:
        handle.write(
            yaml.safe_dump(
                derived.model_dump(mode="json", exclude_none=True),
                allow_unicode=True,
                sort_keys=False,
            )
        )
    return output_path
