# CWE Witness

CWE Witness (`cweverify`) checks whether runtime evidence supports a claimed Common Weakness Enumeration (CWE) weakness in a C program. It builds the sample, runs it with the configured observer, and records the evidence and decision so another person can inspect or replay the result.

A filename, comment, printed error message, or crash does not establish a CWE. `CONFIRMED` means the configured evidence rules matched in the recorded run. `NOT_CONFIRMED` means they did not; it does not prove the program is safe. `UNSUPPORTED` means the requested profile or execution environment is unavailable. `ERROR` means verification could not complete.

This project is for reproducible security research and education. Its calibration programs intentionally contain bugs. Run only code you trust: the runner adds process limits and Linux isolation where available, but it is not a security boundary for actively malicious programs.

## Quick start

On Linux, detect your distribution and install the system tools and Python package:

```bash
bash scripts/setup.sh --dry-run
bash scripts/setup.sh --yes
source .venv/bin/activate
cweverify doctor
```

The installer maps Ubuntu/Debian, Fedora/Enterprise Linux, and Arch/Manjaro packages. See [environment setup](SETUP.md) for versions, mirrors, existing Python environments and Docker.

For Docker:

```bash
bash scripts/docker.sh build
bash scripts/docker.sh run doctor
bash scripts/docker.sh run run manifests/calibration/cwe416-trigger.yaml
```

Then validate and run a bundled calibration case:

```bash
cweverify validate manifests/calibration/cwe416-trigger.yaml
cweverify run manifests/calibration/cwe416-trigger.yaml
cweverify batch
```

For Python-only development:

```bash
uv sync --all-groups
uv run cweverify --help
uv run pytest -q
```

The tool requires Python 3.11 or newer. Sample execution is supported on Linux. Windows users can run it in WSL2; native Windows supports manifest and report operations only. macOS execution is not supported.

## Supported profiles

The bundled profiles cover CWE-120, CWE-125, CWE-190, CWE-191, CWE-369, CWE-415, CWE-416, CWE-476, CWE-772, CWE-787, and CWE-22. Each profile declares the observer and evidence predicates used to support its result. CWE-772 includes POSIX file descriptor and custom resource checks. CWE-22 uses Bubblewrap and strace. See [Analysis method](ANALYSIS_METHOD.md) for evidence limits and the [Chinese user guide](README.zh-CN.md) for installation and usage details.

The default batch directory is `manifests/calibration`. You can pass another directory with `cweverify batch --directory PATH`. Verification artifacts are written under `.cwe-witness/` and are ignored by Git.

## Optional catalog metadata

Runtime findings do not require a CWE catalog. You may supply your own CSV with `CWE-ID`, `Name` and `Description` columns using `--catalog /path/to/catalog.csv` on run/batch commands. By default the CLI looks for `699.csv` in the working directory; if absent, results record `CATALOG_NOT_FOUND` and verification proceeds. The small CSV under `tests/fixtures/` is synthetic test data, not a CWE catalog distribution.

## Development

Install development dependencies with `uv sync --all-groups`, then run:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv run pytest -q
uv build
```

The latest executed checks and remaining environment limits are recorded in [VALIDATION.md](VALIDATION.md).

Contributions and security reports are described in [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). The project code and synthetic test fixtures are licensed under MIT. No research corpus or third-party CWE catalog is bundled.
