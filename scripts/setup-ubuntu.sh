#!/usr/bin/env bash
# Compatibility entry point; distro detection and installation live in setup.sh.
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec bash "${SCRIPT_DIR}/setup.sh" "$@"
