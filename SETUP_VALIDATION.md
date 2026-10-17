# Setup validation — 2026-10-17

The four setup/Docker scripts passed Bash syntax checks and ShellCheck. Seven focused bootstrap tests passed as part of this clean repository's full suite: **154 tests and 11 subtests passed, with no skips**. Checks cover nine distribution/derivative package plans, side-effect-free help/dry-run, argument errors, directory preservation, checkpoints and Docker mounts/permission opt-in.

The independently isolated source tree also passed Ruff, formatting, mypy, all 18 manifest validations, real CLI doctor and calibration/batch checks, and packaging/installed-wheel smoke checks. The optional external catalog is not bundled or required for runtime verification; the sole catalog test fixture is a synthetic record.

These results do not establish successful installation on every distribution. Actual native package installation on the five-distribution matrix and Docker image build/run remain pending CI. No Docker daemon is available locally. The host's Python lacks its matching venv/ensurepip package; a previous prerequisite probe correctly stopped rather than performing system installation under `--skip-system`. Dependencies for application validation were prepared independently without changing system packages.

Image construction uses `--skip-verify`; a successful image build alone is not a runtime observer check. The path calibration was separately confirmed with real strace inside nested Bubblewrap. The Docker-specific permission mode has not been executed locally. Full scope and results are in [VALIDATION.md](VALIDATION.md).
