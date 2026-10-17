#!/usr/bin/env bash
# =============================================================================
# CWE Witness — one-command bootstrap for a fresh Linux machine.
#
# Supports: Ubuntu/Debian (apt), Fedora / Enterprise Linux 9+ (dnf/yum),
#           Arch Linux / Manjaro (pacman).
#
# Features:
#   - Optional PyPI mirror selection and proxy support. System repository
#     rewrites require --configure-system-mirrors.
#   - System package checkpoints are tied to distro and script contents.
#     Python, virtualenv and runtime checks always run again.
#   - Timestamped logging to .setup-state/logs/ and the console.
#   - Interactive confirmations for critical operations (use --yes for CI).
#
# Usage:
#   bash scripts/setup.sh [options]
#
# Options:
#   -y, --yes                 Non-interactive; accept defaults for all prompts
#       --mirror NAME         Mirror to use: auto|official|tsinghua|ustc|aliyun
#                             (default: official; auto probes reachable mirrors)
#       --proxy URL           HTTP(S) proxy for package managers and pip
#       --python-bin PATH     Python interpreter (must be >= 3.11)
#       --venv-dir PATH       Virtualenv location (default: <project>/.venv)
#       --use-uv              Install uv into the venv and use `uv sync`
#       --skip-mirrors        Do not touch system package-manager sources (default)
#       --configure-system-mirrors  Opt in to rewriting system repositories
#       --skip-system         Do not install system packages (Python deps only)
#       --force               Reinstall cached system packages
#       --dry-run             Print distribution and packages; change nothing
#       --system-only         Install only system packages (for image builds)
#       --no-dev              Install runtime Python dependencies only
#       --skip-verify         Skip runtime probes (e.g. during docker build)
#   -h, --help                Show this help and exit
#
# Re-run after an interruption with the same command. Only system-package
# installation is skipped when the configuration is unchanged.
# =============================================================================

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
STATE_DIR="${STATE_DIR:-${PROJECT_ROOT}/.setup-state}"
CHECKPOINT_DIR="${STATE_DIR}/checkpoints"
LOG_DIR="${STATE_DIR}/logs"
LOG_FILE="${LOG_DIR}/setup-$(date +%Y%m%d-%H%M%S).log"

# ---------------------------------------------------------------------------
# Configuration (overridable via CLI flags)
# ---------------------------------------------------------------------------
ASSUME_YES=0
MIRROR="official"
PROXY_URL="${HTTPS_PROXY:-${https_proxy:-${HTTP_PROXY:-${http_proxy:-}}}}"
PYTHON_BIN="${PYTHON_BIN:-}"
VENV_DIR="${VENV_DIR:-}"
USE_UV=0
SKIP_MIRRORS=1
SKIP_SYSTEM=0
FORCE=0
DRY_RUN=0
SYSTEM_ONLY=0
NO_DEV=0
SKIP_VERIFY=0

DISTRO_ID=""
DISTRO_LIKE=""
DISTRO_VERSION=""
PM=""
SUDO=()

# Steps in execution order (used for progress display and resume).
STEPS=(preflight network mirrors system-packages python venv python-deps verify)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_ts() { date '+%Y-%m-%d %H:%M:%S'; }
log()  { printf '%s [INFO ] %s\n' "$(_ts)" "$*"; }
ok()   { printf '%s [ OK  ] %s\n' "$(_ts)" "$*"; }
warn() { printf '%s [ WARN] %s\n' "$(_ts)" "$*" >&2; }
err()  { printf '%s [ERROR] %s\n' "$(_ts)" "$*" >&2; }
die()  { err "$*"; exit 1; }

on_error() {
    local line=$1
    err "Setup failed at line ${line}. Full log: ${LOG_FILE}"
    err "Fix the problem, then re-run the same command to resume from checkpoints."
}
trap 'on_error ${LINENO}' ERR

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "${BASH_SOURCE[0]}"; }

confirm() {
    # Usage: confirm "question" [default: y|n] -> returns 0 for yes
    local question=$1 default=${2:-y} reply=""
    if [[ ${ASSUME_YES} -eq 1 ]]; then
        log "AUTO-CONFIRM: ${question}"
        [[ ${default} == y ]]
        return
    fi
    local hint="[Y/n]"; [[ ${default} == "n" ]] && hint="[y/N]"
    if [[ -t 0 ]]; then
        read -r -p "${question} ${hint} " reply </dev/tty || true
    else
        log "Non-interactive shell; default '${default}' for: ${question}"
        reply=""
    fi
    reply=${reply:-${default}}
    [[ ${reply} =~ ^[Yy] ]]
}

# Only package installation is cached. Runtime state must always be rediscovered.
step_done() {
    [[ $1 == system-packages && ${SKIP_SYSTEM} -eq 0 && ${FORCE} -eq 0 ]] || return 1
    [[ -f "${CHECKPOINT_DIR}/$1-${CONFIG_KEY}" ]]
}
mark_done() { date -Is > "${CHECKPOINT_DIR}/$1-${CONFIG_KEY}"; ok "Step '$1' complete"; }

step_index() {
    local i
    for i in "${!STEPS[@]}"; do [[ ${STEPS[$i]} == "$1" ]] && echo $((i + 1)) && return; done
}

run_step() {
    local name=$1
    if step_done "${name}"; then
        log "[$(( $(step_index "${name}") ))/${#STEPS[@]}] ${name}: already done, skipping"
        return 0
    fi
    log "========== [$(step_index "${name}")/${#STEPS[@]}] STEP: ${name} =========="
    "step_${name//-/_}"
    if [[ ${name} != system-packages || ${SKIP_SYSTEM} -eq 0 ]]; then
        mark_done "${name}"
    fi
}

retry() {
    # Usage: retry <attempts> <command...>
    local attempts=$1; shift
    local n
    for n in $(seq 1 "${attempts}"); do
        if "$@"; then return 0; fi
        warn "Command failed (attempt ${n}/${attempts}): $*"
        sleep $((n * 2))
    done
    return 1
}

reachable() {
    # Usage: reachable <url> [timeout_seconds]
    curl -fsS -m "${2:-8}" -o /dev/null "$1" >/dev/null 2>&1
}

url_latency_ms() {
    # Echoes latency in ms, or 999999 if unreachable.
    local url=$1
    local duration
    if duration=$(curl -fsS -m 8 -o /dev/null -w '%{time_total}' "$url" 2>/dev/null); then
        awk -v duration="${duration}" 'BEGIN {printf "%d", duration * 1000}'
    else
        echo 999999
    fi
}

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mirror|--proxy|--python-bin|--venv-dir)
            [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "Missing value for $1" ;;
    esac
    case "$1" in
        -y|--yes)       ASSUME_YES=1 ;;
        --mirror)       MIRROR=$2; shift ;;
        --proxy)        PROXY_URL=$2; shift ;;
        --python-bin)   PYTHON_BIN=$2; shift ;;
        --venv-dir)     VENV_DIR=$2; shift ;;
        --use-uv)       USE_UV=1 ;;
        --skip-mirrors) SKIP_MIRRORS=1 ;;
        --configure-system-mirrors) SKIP_MIRRORS=0 ;;
        --dry-run)      DRY_RUN=1 ;;
        --system-only)  SYSTEM_ONLY=1 ;;
        --no-dev)       NO_DEV=1 ;;
        --skip-verify)  SKIP_VERIFY=1 ;;
        --skip-system)  SKIP_SYSTEM=1 ;;
        --force)        FORCE=1 ;;
        -h|--help)      usage; exit 0 ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
    shift
done

VENV_DIR="${VENV_DIR:-${PROJECT_ROOT}/.venv}"

case "${MIRROR}" in
    auto|official|tsinghua|ustc|aliyun) ;;
    *) die "--mirror must be one of: auto, official, tsinghua, ustc, aliyun" ;;
esac

# ---------------------------------------------------------------------------
# STEP 1: preflight — detect distro, package manager, privileges
# ---------------------------------------------------------------------------
step_preflight() {
    [[ "$(uname -s)" == "Linux" ]] || die "This script targets Linux. On Windows, run it inside WSL."

    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/setup-packages.sh"
    detect_distribution
    select_system_packages
    log "Distribution: ID=${DISTRO_ID} VERSION_ID=${DISTRO_VERSION} ID_LIKE='${DISTRO_LIKE}' arch=$(uname -m)"
    log "Package manager: ${PM:-not needed}"
    [[ -n ${PM} || ${SKIP_SYSTEM} -eq 1 ]] || die "Unsupported distribution; use --skip-system or the Docker image."
    if [[ ${DRY_RUN} -eq 1 ]]; then
        printf 'System packages:'; printf ' %q' "${SYSTEM_PACKAGES[@]}"; printf '\n'
        return 0
    fi
    if [[ ${SKIP_SYSTEM} -eq 0 ]]; then
        if [[ ${EUID} -eq 0 ]]; then SUDO=()
        elif command -v sudo >/dev/null 2>&1; then SUDO=(sudo)
        else die "Need root or sudo to install system packages (or use --skip-system)."
        fi
    fi

    if [[ -n "${PROXY_URL}" ]]; then
        export HTTPS_PROXY="${PROXY_URL}" HTTP_PROXY="${PROXY_URL}" \
               https_proxy="${PROXY_URL}" http_proxy="${PROXY_URL}"
        log "Using configured proxy (URL omitted from logs)"
        reachable "https://pypi.org" 10 || warn "Proxy set but pypi.org unreachable through it"
    fi
}

# ---------------------------------------------------------------------------
# STEP 2: network — pick the fastest mirror when MIRROR=auto
# ---------------------------------------------------------------------------
step_network() {
    if [[ "${MIRROR}" != "auto" ]]; then
        log "Mirror forced to '${MIRROR}' by user"
        return 0
    fi
    command -v curl >/dev/null 2>&1 || die "--mirror auto requires curl; choose --mirror official or install curl."
    log "Probing mirror latency (PyPI endpoints as reference)..."
    local t_official t_tuna t_ustc t_aliyun
    t_official=$(url_latency_ms "https://pypi.org/simple/")
    t_tuna=$(url_latency_ms "https://pypi.tuna.tsinghua.edu.cn/simple/")
    t_ustc=$(url_latency_ms "https://mirrors.ustc.edu.cn/pypi/simple/")
    t_aliyun=$(url_latency_ms "https://mirrors.aliyun.com/pypi/simple/")
    log "Latency ms: pypi.org=${t_official} tsinghua=${t_tuna} ustc=${t_ustc} aliyun=${t_aliyun}"

    local best=official best_ms=${t_official}
    for cand in "tsinghua:${t_tuna}" "ustc:${t_ustc}" "aliyun:${t_aliyun}"; do
        local name=${cand%%:*} ms=${cand##*:}
        if (( ms < best_ms )); then best=${name}; best_ms=${ms}; fi
    done
    MIRROR=${best}
    if (( best_ms >= 999999 )); then
        warn "No mirror reachable. Continuing with 'official' and retries."
        MIRROR=official
    fi
    ok "Selected mirror: ${MIRROR}"
}

pypi_index_url() {
    case "${MIRROR}" in
        tsinghua) echo "https://pypi.tuna.tsinghua.edu.cn/simple" ;;
        ustc)     echo "https://mirrors.ustc.edu.cn/pypi/simple" ;;
        aliyun)   echo "https://mirrors.aliyun.com/pypi/simple/" ;;
        *)        echo "https://pypi.org/simple" ;;
    esac
}

distro_mirror_host() {
    case "${MIRROR}" in
        tsinghua) echo "mirrors.tuna.tsinghua.edu.cn" ;;
        ustc)     echo "mirrors.ustc.edu.cn" ;;
        aliyun)   echo "mirrors.aliyun.com" ;;
        *)        echo "" ;;
    esac
}

# ---------------------------------------------------------------------------
# Package-manager abstraction
# ---------------------------------------------------------------------------
pm_update_quiet() {
    case "${PM}" in
        apt)    "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 update -qq ;;
        dnf)    "${SUDO[@]}" dnf -y -q makecache ;;
        yum)    "${SUDO[@]}" yum -y -q makecache ;;
        pacman) : ;; # Refresh and upgrade atomically during installation; avoid partial upgrades.
    esac
}

pm_update() {
    log "Refreshing package metadata (${PM})"
    retry 3 pm_update_quiet
}

pm_install() {
    log "Installing: $*"
    case "${PM}" in
        apt)    retry 2 env "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" ;;
        dnf)    retry 2 "${SUDO[@]}" dnf install -y "$@" ;;
        yum)    retry 2 "${SUDO[@]}" yum install -y "$@" ;;
        pacman) retry 2 "${SUDO[@]}" pacman -Syu --needed --noconfirm "$@" ;;
    esac
}

# ---------------------------------------------------------------------------
# STEP 3: mirrors — reconfigure package-manager sources (with backups)
# ---------------------------------------------------------------------------
backup_file() {
    local f=$1
    [[ -f $f ]] && "${SUDO[@]}" cp -a "$f" "${f}.bak-$(date +%Y%m%d-%H%M%S)"
}

configure_apt_mirror() {
    local host; host=$(distro_mirror_host)
    [[ -n ${host} ]] || { log "Mirror 'official': apt sources unchanged"; return 0; }
    local list=/etc/apt/sources.list
    [[ -f ${list} ]] || { warn "${list} not found (deb822 format?); skipping apt mirror rewrite"; return 0; }
    backup_file "${list}"
    if [[ ${DISTRO_ID} == "ubuntu" || ${DISTRO_LIKE} == *ubuntu* ]]; then
        "${SUDO[@]}" sed -i \
            -e "s|//archive.ubuntu.com/ubuntu|//${host}/ubuntu|g" \
            -e "s|//security.ubuntu.com/ubuntu|//${host}/ubuntu|g" \
            -e "s|//cn.archive.ubuntu.com/ubuntu|//${host}/ubuntu|g" "${list}"
    else
        "${SUDO[@]}" sed -i \
            -e "s|//deb.debian.org/debian-security|//${host}/debian-security|g" \
            -e "s|//deb.debian.org/debian|//${host}/debian|g" \
            -e "s|//security.debian.org/debian-security|//${host}/debian-security|g" "${list}"
    fi
    ok "apt sources now use ${host} (backup next to ${list})"
}

configure_dnf_mirror() {
    local host; host=$(distro_mirror_host)
    [[ -n ${host} ]] || { log "Mirror 'official': dnf/yum sources unchanged"; return 0; }
    local dir=/etc/yum.repos.d
    [[ -d ${dir} ]] || return 0
    # Best-effort baseurl replacement per distro family; metalink lines are
    # commented out so the mirror baseurl takes effect.
    local family=""
    case "${DISTRO_ID}" in
        centos)           family="centos" ;;
        rocky)            family="rocky" ;;
        almalinux)        family="almalinux" ;;
        fedora)           family="fedora" ;;
        rhel|redhatenterpriseserver)
            warn "RHEL uses subscription repositories; skipping mirror rewrite"
            return 0 ;;
        *) warn "Unknown dnf distro '${DISTRO_ID}'; skipping mirror rewrite"; return 0 ;;
    esac
    local repo
    for repo in "${dir}"/*.repo; do
        [[ -f ${repo} ]] || continue
        backup_file "${repo}"
        "${SUDO[@]}" sed -i \
            -e 's|^metalink=|#metalink=|g' \
            -e 's|^mirrorlist=|#mirrorlist=|g' \
            -e "s|^#baseurl=https\?://[^/]*/${family}|baseurl=https://${host}/${family}|g" \
            -e "s|^baseurl=https\?://[^/]*/${family}|baseurl=https://${host}/${family}|g" \
            "${repo}" || warn "Mirror rewrite failed for ${repo}"
    done
    ok "dnf/yum repos now use ${host}/${family}"
}

configure_pacman_mirror() {
    local host; host=$(distro_mirror_host)
    [[ -n ${host} ]] || { log "Mirror 'official': pacman mirrorlist unchanged"; return 0; }
    local list=/etc/pacman.d/mirrorlist
    backup_file "${list}"
    local tmp; tmp=$(mktemp)
    cat > "${tmp}" <<EOF
## Generated by CWE Witness setup.sh on $(_ts)
Server = https://${host}/archlinux/\$repo/os/\$arch
Server = https://mirrors.tuna.tsinghua.edu.cn/archlinux/\$repo/os/\$arch
Server = https://mirrors.ustc.edu.cn/archlinux/\$repo/os/\$arch
Server = https://mirrors.aliyun.com/archlinux/\$repo/os/\$arch
EOF
    "${SUDO[@]}" install -m 0644 "${tmp}" "${list}"
    rm -f "${tmp}"
    ok "pacman mirrorlist updated (backup next to ${list})"
}

step_mirrors() {
    if [[ ${SKIP_MIRRORS} -eq 1 ]]; then
        log "--skip-mirrors given; system sources untouched"
        return 0
    fi
    if [[ ${SKIP_SYSTEM} -eq 1 ]]; then
        log "--skip-system given; no need to touch system sources"
        return 0
    fi
    if [[ ${MIRROR} == "official" ]]; then
        log "Using official sources; no mirror rewrite needed"
        return 0
    fi
    if ! confirm "Rewrite ${PM} sources to use the '${MIRROR}' mirror? (backups are created)" "y"; then
        log "User declined mirror rewrite"
        return 0
    fi
    case "${PM}" in
        apt)          configure_apt_mirror ;;
        dnf|yum)      configure_dnf_mirror ;;
        pacman)       configure_pacman_mirror ;;
    esac
    pm_update
}

# ---------------------------------------------------------------------------
# STEP 4: system packages
# ---------------------------------------------------------------------------
step_system_packages() {
    if [[ ${SKIP_SYSTEM} -eq 1 ]]; then
        log "--skip-system given; assuming clang/valgrind/etc. are already installed"
        return 0
    fi
    pm_update
    pm_install "${SYSTEM_PACKAGES[@]}"

    # Verify critical tools actually landed.
    local tool missing=0
    for tool in clang llvm-symbolizer valgrind bwrap strace pkg-config; do
        if command -v "${tool}" >/dev/null 2>&1; then
            ok "found: ${tool} ($(command -v "${tool}"))"
        else
            err "missing after install: ${tool}"
            missing=1
        fi
    done
    [[ ${missing} -eq 0 ]] || die "Some required tools failed to install"
}

# ---------------------------------------------------------------------------
# STEP 5: python — locate or validate a >= 3.11 interpreter
# ---------------------------------------------------------------------------
py_version_ok() {
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
        >/dev/null 2>&1
}

step_python() {
    if [[ -n "${PYTHON_BIN}" ]]; then
        PYTHON_BIN=$(command -v "${PYTHON_BIN}") || die "--python-bin interpreter not found"
    else
        local cand
        for cand in python3 python3.14 python3.13 python3.12 python3.11; do
            if command -v "${cand}" >/dev/null 2>&1 && py_version_ok "${cand}"; then
                PYTHON_BIN=$(command -v "${cand}")
                break
            fi
        done
    fi
    [[ -n ${PYTHON_BIN} ]] || die "No Python >= 3.11 found. Install one (e.g. 'apt install python3.12' on Ubuntu 24.04+, or build from source) and re-run."
    py_version_ok "${PYTHON_BIN}" || die "${PYTHON_BIN} is older than 3.11"
    # Resolve relative interpreter/venv arguments before changing working directory.
    PYTHON_BIN=$("${PYTHON_BIN}" -c 'import sys; print(sys.executable)')
    VENV_DIR=$("${PYTHON_BIN}" -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "${VENV_DIR}")
    ok "Python: ${PYTHON_BIN} ($("${PYTHON_BIN}" --version 2>&1))"
}

# ---------------------------------------------------------------------------
# STEP 6: venv
# ---------------------------------------------------------------------------
step_venv() {
    if [[ -x "${VENV_DIR}/bin/python" ]]; then
        log "Reusing existing virtualenv at ${VENV_DIR}"
    else
        if [[ -d ${VENV_DIR} && -n $(ls -A "${VENV_DIR}") ]]; then
            die "Refusing to overwrite nonempty directory ${VENV_DIR}; choose another --venv-dir."
        fi
        "${PYTHON_BIN}" -m venv "${VENV_DIR}" || {
            if [[ ${PM} == apt && ${SKIP_SYSTEM} -eq 0 ]]; then
                warn "venv creation failed; attempting to install python3-venv"
                local venv_package
                venv_package=$("${PYTHON_BIN}" -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}-venv")')
                pm_install "${venv_package}"
                "${PYTHON_BIN}" -m venv "${VENV_DIR}"
            else
                die "python -m venv failed; install matching venv/ensurepip support and choose a fresh --venv-dir."
            fi
        }
    fi
    py_version_ok "${VENV_DIR}/bin/python" || die "Virtualenv at ${VENV_DIR} is broken or older than Python 3.11"
    ok "Virtualenv ready: ${VENV_DIR}"
}

# ---------------------------------------------------------------------------
# STEP 7: python-deps — pip mirror config + editable install + dev tools
# ---------------------------------------------------------------------------
step_python_deps() {
    local pip="${VENV_DIR}/bin/pip"
    local index; index=$(pypi_index_url)

    # venv-scoped pip configuration: least invasive, idempotent.
    cat > "${VENV_DIR}/pip.conf" <<EOF
[global]
index-url = ${index}
timeout = 30
retries = 5
EOF
    log "pip index: ${index} (written to ${VENV_DIR}/pip.conf)"

    retry 3 "${VENV_DIR}/bin/python" -m pip install --upgrade pip
    if [[ ${USE_UV} -eq 1 ]]; then
        # uv via PyPI avoids the astral.sh installer which downloads from GitHub.
        retry 3 "${pip}" install uv
        log "Installing project with uv sync"
        [[ ${MIRROR} == official ]] || warn "uv uses registry URLs from uv.lock; the selected mirror applies to pip bootstrap only."
        local groups=(--all-groups)
        [[ ${NO_DEV} -eq 0 ]] || groups=(--no-dev)
        (cd "${PROJECT_ROOT}"; retry 3 env UV_PROJECT_ENVIRONMENT="${VENV_DIR}" "${VENV_DIR}/bin/uv" sync --locked --inexact --python "${PYTHON_BIN}" "${groups[@]}")
    else
        local deps=(-e "${PROJECT_ROOT}")
        [[ ${NO_DEV} -eq 1 ]] || deps+=(pytest ruff mypy types-PyYAML)
        retry 3 "${pip}" install --upgrade "${deps[@]}"
    fi

    ok "Python dependencies installed"
}

# ---------------------------------------------------------------------------
# STEP 8: verify — imports, profiles, doctor
# ---------------------------------------------------------------------------
step_verify() {
    [[ ${SKIP_VERIFY} -eq 0 ]] || { warn "Runtime verification SKIPPED (--skip-verify). Run cweverify doctor after starting the container."; return 0; }
    local py="${VENV_DIR}/bin/python"
    cd "${PROJECT_ROOT}"

    if "${py}" -c 'import cwe_witness'; then
        ok "import cwe_witness: PASS"
    else
        die "import cwe_witness failed"
    fi

    local count
    count=$("${py}" -c \
        'from cwe_witness.profiles import available_profiles; print(len(available_profiles()))')
    [[ ${count} -gt 0 ]] || die "No profiles loaded"
    ok "Profiles loaded: ${count}"

    [[ -x "${VENV_DIR}/bin/cweverify" ]] || die "cweverify entry point missing in ${VENV_DIR}/bin"
    if "${VENV_DIR}/bin/cweverify" doctor; then
        ok "cweverify doctor: PASS (compiler/ASan/FD observer)"
        if command -v bwrap >/dev/null 2>&1 && bwrap --die-with-parent --ro-bind / / --unshare-net -- /bin/true >/dev/null 2>&1; then
            ok "Bubblewrap namespace probe: PASS"
        else
            warn "Bubblewrap namespace probe: UNAVAILABLE. Path-policy runs may be UNSUPPORTED; see SETUP.md (Docker/host namespace policy)."
        fi
    else
        die "cweverify doctor failed — check clang/ASan/Valgrind installation above"
    fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    if [[ ${SYSTEM_ONLY} -eq 1 ]]; then
        ok "System packages installed. Python environment and runtime verification were not run."
        return 0
    fi
    cat <<EOF

=====================================================================
CWE Witness installation complete.
  Log:          ${LOG_FILE}
  Checkpoints:  ${CHECKPOINT_DIR}
  Virtualenv:   ${VENV_DIR}
  Mirror:       ${MIRROR}

Activate the environment:
  source "${VENV_DIR}/bin/activate"

Next steps:
  cweverify doctor
  cweverify validate manifests/calibration/cwe416-trigger.yaml
  cweverify run manifests/calibration/cwe416-trigger.yaml
  python -m pytest -q
=====================================================================
EOF
}

main() {
    log "CWE Witness setup starting (project: ${PROJECT_ROOT})"
    [[ ${SYSTEM_ONLY} -eq 0 || ${SKIP_SYSTEM} -eq 0 ]] || die "--system-only and --skip-system cannot be combined."
    step_preflight
    [[ ${DRY_RUN} -eq 0 ]] || return 0
    mkdir -p "${LOG_DIR}" "${CHECKPOINT_DIR}"
    exec > >(tee -a "${LOG_FILE}") 2>&1
    CONFIG_KEY=$( { cat "${BASH_SOURCE[0]}" "${SCRIPT_DIR}/setup-packages.sh"; printf '%s\n' "${DISTRO_ID}" "${DISTRO_VERSION}" "${SKIP_MIRRORS}" "${MIRROR}"; } | sha256sum | cut -c1-16)
    STEPS=(network mirrors system-packages python venv python-deps verify)
    [[ ${SYSTEM_ONLY} -eq 0 ]] || STEPS=(network mirrors system-packages python)
    local s
    for s in "${STEPS[@]}"; do run_step "${s}"; done
    print_summary
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
