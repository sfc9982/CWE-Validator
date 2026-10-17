# Linux and Docker setup

Run all commands from the standalone CWE-Validator project directory. Installation needs repository/PyPI network access. The script never changes kernel settings, enables third-party OS repositories, or starts Docker for you.

## Native Linux

| Distribution family | Package manager | Python/package notes |
| --- | --- | --- |
| Ubuntu 24.04+ / Debian 12+ and compatible derivatives | apt | `python3-venv`, Clang/LLVM, `libclang-rt-dev`, Valgrind, Bubblewrap, strace |
| Fedora | dnf | Distribution Python 3, `compiler-rt`, Valgrind, Bubblewrap, strace |
| RHEL / Rocky / AlmaLinux / CentOS Stream 9+ | dnf (yum compatibility) | Uses separate `python3.11` and `python3.11-pip`; RHEL 9 requires 9.2+ repositories. Repository entitlements/package availability remain the administrator's responsibility. |
| Arch Linux / Manjaro | pacman | Includes `compiler-rt`; uses `pacman -Syu` to avoid unsupported partial upgrades. Review normal system upgrade implications. |

These are package mappings, not a claim that every distribution/version has been tested. Unsupported distributions can use `--skip-system` after manually installing tools, or the Debian-based Docker image. Alpine/musl is not supported by the provided native toolchain. Older Ubuntu/Debian releases require an existing Python 3.11+ and matching venv support; the script does not add a PPA or replace system Python. Native macOS/Windows execution remains unsupported; use Linux containers or WSL2.

```bash
bash scripts/setup.sh --dry-run
bash scripts/setup.sh --yes
source .venv/bin/activate
cweverify doctor
cweverify validate manifests/calibration/cwe416-trigger.yaml
cweverify run manifests/calibration/cwe416-trigger.yaml
```

`setup-ubuntu.sh` forwards to the same installer for compatibility. Scripts require Bash. On WSL, use a separate Linux venv (for example `--venv-dir .venv-linux`) rather than an existing Windows venv. Run as your normal user with sudo available for OS packages; do not run the whole installer through sudo unless installing a root-owned environment intentionally.

Useful options:

```bash
# Existing system tools: no sudo or system package operations.
bash scripts/setup.sh --skip-system --python-bin python3.12 --venv-dir .venv-custom

# Runtime only, or reproducible Python dependency installation via uv.lock.
bash scripts/setup.sh --no-dev
bash scripts/setup.sh --use-uv

# Optional PyPI mirror; system repositories stay unchanged by default.
bash scripts/setup.sh --mirror tsinghua
# Use normal HTTPS_PROXY / HTTP_PROXY environment variables for a proxy.
```

`--mirror auto` requires curl. In uv mode the mirror applies to bootstrap pip; locked dependency downloads retain the registry URLs recorded in `uv.lock`, and `--inexact` preserves installer tools such as pip/uv. `--configure-system-mirrors` explicitly opts into the legacy repository rewrite helpers; backups are kept next to rewritten files. Helpers do not cover every derivative or deb822 source format, so administrator-managed repository configuration is preferable. `--yes` honors each prompt's default. Python virtual environments and verification are checked again on every run; only successful system package installation is cached under a distribution/configuration hash in `.setup-state/`. Use `--force` after removing system packages. Nonempty directories that are not valid venvs are preserved and rejected.

## Docker

Install Docker Engine or Docker Desktop with Linux containers and a working daemon. The project does not install Docker or modify daemon settings.

```bash
bash scripts/docker.sh build
bash scripts/docker.sh run doctor
bash scripts/docker.sh run validate manifests/calibration/cwe416-trigger.yaml
bash scripts/docker.sh run run manifests/calibration/cwe416-trigger.yaml
bash scripts/docker.sh run run manifests/calibration/cwe125-normal.yaml
bash scripts/docker.sh run batch --jobs 1
```

The helper persists evidence in the host project's `.cwe-witness/`, disables container networking, and uses your UID/GID in the ordinary mode. `CWE_DOCKER_IMAGE` overrides the default `cwe-witness:local`; `CWE_DOCKER_OUTPUT` selects a different host evidence directory. The image includes calibration fixtures and manifests, with an allowlist excluding history, datasets, credentials, virtualenvs and generated evidence from the build context.

For your own input bundle, put its manifest, sources and fixtures inside one directory and mount it read-only:

```bash
bash scripts/docker.sh run --input-dir /absolute/path/to/bundle validate /inputs/case.yaml
bash scripts/docker.sh run --input-dir /absolute/path/to/bundle run /inputs/case.yaml
```

Clang/ASan and ordinary FD observation can run in the default mode. Bubblewrap path-policy runs additionally need mount/network namespaces; strace needs tracing permission. Docker's default seccomp policy restricts namespace operations. On a trusted Linux host, opt in only when those observers are needed:

```bash
bash scripts/docker.sh run --full-isolation doctor
# Supply a supported path-policy manifest in your own bundle:
bash scripts/docker.sh run --full-isolation --input-dir /absolute/path/to/bundle run /inputs/case.yaml
```

This mode runs as container root, adds `SYS_ADMIN` and `SYS_PTRACE`, and relaxes seccomp/AppArmor. It is intended for disposable, trusted research environments. It may create root-owned evidence. It does not use `--privileged`, mount the Docker socket or mount the parent workspace. Rootless Docker, user-namespace remapping, Docker Desktop and host LSM/kernel policies can still deny nested namespaces; no setup script can guarantee those capabilities. The installer reports Bubblewrap probing separately from `doctor`'s compiler/ASan/Valgrind checks. An installed binary or successful image build alone does not establish runtime observer support.

The bundled `cwe22-trigger.yaml` uses synthetic files and a supported path-traversal profile. Its runtime still requires usable Bubblewrap namespaces and strace; it must not be counted as confirmed when those capabilities are missing. Result meanings and supported profile definitions are described in the main README.

## Validation and troubleshooting

`--system-only` is for image builds. `--skip-verify` deliberately skips runtime probes; run `doctor` after starting the image. A missing Python 3.11+, compiler runtime, symbolizer or FD observer causes setup to fail; unavailable Bubblewrap namespaces produce a separate warning because they affect specific observers. Build failures name missing packages without claiming installation succeeded. The script preserves existing Python environments and does not clean research data.

Script tests use mocked package plans and Docker invocation capture, without installing OS packages. CI also builds the actual image and runs `doctor` plus positive/negative calibration checks. Local validation status is recorded in [SETUP_VALIDATION.md](SETUP_VALIDATION.md).

References: [RHEL Python versions](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/installing_and_using_dynamic_programming_languages/index), [Arch compiler-rt](https://archlinux.org/packages/extra/x86_64/compiler-rt/), [Docker seccomp restrictions](https://docs.docker.com/engine/security/seccomp/).
