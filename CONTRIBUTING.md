# Contributing

Thanks for helping improve CWE Witness. Before opening a pull request, check that your change preserves the evidence-based decision model: file names, comments, printed text, and crashes alone must not confirm a CWE.

For code changes, install the development dependencies with `uv sync --all-groups` and run:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv run pytest -q
uv build
```

Changes to runtime observation should include focused tests for both matching evidence and a plausible non-target case. Linux-only execution checks should state which external tools they require. Use synthetic data in examples and fixtures; do not add private records, credentials, generated run output, binaries, or third-party corpora without their redistribution terms and attribution.

Use a concise imperative pull request title. Describe the behavior changed, the relevant CWE profiles, and the checks you ran.

For shell changes, run Bash syntax checks and ShellCheck on the setup scripts and Docker helper. Keep calibration manifests standalone and exercise both supported build presets and any compatible alternatives.
