import csv
import hashlib
import re
from functools import lru_cache
from pathlib import Path, PurePosixPath, PureWindowsPath

import yaml

from .models import BatchManifest, Manifest


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_manifest(path: Path) -> Manifest:
    manifest = Manifest.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    for source in manifest.sources + (manifest.control.sources if manifest.control else []):
        resolved = (path.parent / source).resolve()
        if not resolved.is_file() or resolved.suffix.lower() != ".c":
            raise ValueError(f"C source does not exist: {resolved}")
    destinations = [f.destination for f in manifest.fixtures]
    if len(destinations) != len(set(destinations)):
        raise ValueError("duplicate fixture destination")
    for fixture in manifest.fixtures:
        if not (path.parent / fixture.source).is_file():
            raise ValueError(f"fixture does not exist: {fixture.source}")
    return manifest


def load_batch_manifest(path: Path) -> BatchManifest:
    """Load and validate a directory batch specification."""
    manifest = BatchManifest.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    source_path = Path(manifest.source_directory)
    if (
        not manifest.source_directory
        or PurePosixPath(manifest.source_directory).is_absolute()
        or PureWindowsPath(manifest.source_directory).is_absolute()
        or PureWindowsPath(manifest.source_directory).drive
    ):
        raise ValueError("batch source_directory must be a relative path")
    source_directory = (path.parent / source_path).resolve()
    if not source_directory.is_dir():
        raise ValueError(f"batch source directory does not exist: {source_directory}")
    for key in manifest.overrides:
        candidate = Path(key)
        if (
            not key
            or PurePosixPath(key).is_absolute()
            or PureWindowsPath(key).is_absolute()
            or PureWindowsPath(key).drive
            or candidate == Path(".")
            or ".." in candidate.parts
            or "\\" in key
        ):
            raise ValueError(f"batch override key must be a relative POSIX path: {key!r}")
    return manifest


def discover_batch_sources(path: Path, manifest: BatchManifest) -> list[tuple[str, Path]]:
    """Return matching source files as (POSIX relative name, resolved path)."""
    source_directory = (path.parent / manifest.source_directory).resolve()
    candidates = source_directory.rglob("*") if manifest.recursive else source_directory.glob("*")
    number = int(manifest.claimed_cwe.removeprefix("CWE-"))
    # Imported corpora often prefix filenames with a stable sequence number,
    # for example ``001_CWE120_case.c``.  The prefix is metadata; the CWE
    # declaration must still immediately follow it.
    prefix = re.compile(rf"^(?:\d+_)?CWE-?0*{number}(?:[_.-]|$)", re.IGNORECASE)
    found: list[tuple[str, Path]] = []
    for candidate in candidates:
        # Cheap name checks first; stat/resolve only the files that qualify.
        if (
            candidate.suffix.lower() != ".c"
            or not prefix.match(candidate.name)
            or not candidate.is_file()
        ):
            continue
        relative = candidate.relative_to(source_directory)
        resolved = candidate.resolve()
        try:
            resolved.relative_to(source_directory)
        except ValueError as exc:
            raise ValueError(f"batch source escapes source directory: {candidate}") from exc
        found.append((relative.as_posix(), resolved))
    found.sort(key=lambda item: item[0].casefold())
    return found


@lru_cache(maxsize=None)
def _catalog_entry_cached(resolved: str, mtime_ns: int, cwe: str) -> dict[str, str]:
    # The mtime in the key invalidates entries when the catalog file changes.
    path = Path(resolved)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["CWE-ID"] == cwe.removeprefix("CWE-"):
                return {
                    "status": "FOUND",
                    "path": resolved,
                    "sha256": digest(path),
                    "name": row["Name"],
                    "description": row["Description"],
                }
    return {
        "status": "NOT_IN_PROVIDED_CATALOG",
        "path": resolved,
        "sha256": digest(path),
    }


def catalog_entry(path: Path, cwe: str) -> dict[str, str]:
    if not path.is_file():
        return {"status": "CATALOG_NOT_FOUND", "path": str(path)}
    resolved = str(path.resolve())
    return _catalog_entry_cached(resolved, Path(resolved).stat().st_mtime_ns, cwe)
