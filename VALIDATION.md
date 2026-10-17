# Clean release validation — 2026-10-17

This standalone repository contains tool source, profiles, synthetic calibration fixtures and unit tests, setup/Docker/CI configuration, the dependency lockfile, licensing and maintained documentation. It was initialized independently; no previous Git objects, commits, refs, remotes, research inputs or historical reports were imported.

## Reproduce

On Linux with the required system tools:

```bash
bash scripts/setup.sh --yes --use-uv
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv run pytest -q
uv run cweverify doctor
for manifest in manifests/calibration/*.yaml; do
  uv run cweverify validate "$manifest"
done
uv run cweverify run manifests/calibration/cwe416-trigger.yaml
uv run cweverify run manifests/calibration/cwe125-normal.yaml
uv run cweverify batch --jobs 1
uv build
```

For shell changes, run Bash syntax checks and ShellCheck on the four scripts in `scripts/`. Docker and distribution requirements are described in [SETUP.md](SETUP.md).

## Executed checks

The clean source tree was mounted read-only in Bubblewrap with separately prepared Python dependencies and real Linux observer tools. The original workspace and home directories were hidden. External networking was disabled while synthetic loopback communication remained available. Builds and evidence were written to a dedicated temporary directory. No system packages were installed.

Environment: Ubuntu 26.04/x86_64/WSL2, Python 3.14.4, Clang/LLVM 21.1.8, Valgrind 3.26.0, strace 6.19, Bubblewrap 0.11.1, pytest 9.1.1, Ruff 0.16.8, mypy 2.3.1 and Hatchling 1.32.4.

| Check | Result |
| --- | --- |
| Full tests in the independent tree | **154 passed, 11 subtests passed; no skips** |
| Ruff lint/format, mypy, Bash syntax, ShellCheck | Pass |
| All bundled manifests | 18 valid with supported profiles |
| Doctor | ASan and file-descriptor tracking both PASS |
| Positive / negative calibration | CONFIRMED / NOT_CONFIRMED; replay consistent |
| Nested path observer | Synthetic traversal CONFIRMED with strace inside Bubblewrap |
| Default batch | 12 CONFIRMED, 6 NOT_CONFIRMED; no ERROR or UNSUPPORTED |
| No optional catalog supplied | CATALOG_NOT_FOUND is recorded; runtime verification still succeeds |
| Synthetic catalog explicitly supplied | Lookup succeeds without importing an external catalog |
| Wheel and source distribution | Build and content inspection passed; all 12 profiles included |
| Installed CLI outside source directory | Help, doctor, validation and positive calibration passed |
| Repository contents | 95 curated files, including 9 synthetic C fixtures and one synthetic CSV record |
| Git isolation | Fresh main branch; no imported commits, object alternates or remotes |

Boundary accesses, direction mismatches, optional controls, replay consistency, raw stdin and tampered binaries are covered by the tests. Deliberate vulnerabilities remain in the synthetic calibration fixtures.

## Publication scope

The repository does not contain original demo programs, imported source corpora, input matrices, source repair patches, research documents, office exports, archives, a third-party CWE catalog, old validation artifacts or earlier Git history. The only bundled CSV is an original one-record fixture for catalog lookup tests. Optional real catalogs remain external and have their own applicable redistribution terms.

Candidate files were checked for known credential patterns, private-key blocks, credential-bearing URLs, machine-account paths, symlinks and oversized artifacts. Local documentation links and CI YAML/shell syntax were also checked. Targeted scans do not guarantee detection of every possible private fact or credential format.

The source repository and its original history, configuration, staging choices and working files were preserved. The clean export was verified before its initial publication commit. Publication starts with a new root commit in a separate repository; the original repository and its visibility are preserved. Validation evidence and built distributions are local ignored artifacts.

## Not executed locally

Docker image build/run and the five-distribution installation matrix still require their corresponding environments. CI defines those checks with read-only repository permissions; their hosted results are reported separately by GitHub Actions. The native host also lacks matching venv/ensurepip support, so a fresh native installer run was not represented as successful. Application verification used independently prepared dependencies. See [SETUP_VALIDATION.md](SETUP_VALIDATION.md).
