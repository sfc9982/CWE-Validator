#!/usr/bin/env bash
# Shared, side-effect-free distribution/package planning for setup.sh and tests.
detect_distribution() {
    local ID='' ID_LIKE='' VERSION_ID=''
    local os_release=${1:-/etc/os-release}
    # shellcheck disable=SC1090,SC1091
    [[ ! -r ${os_release} ]] || source "${os_release}"
    DISTRO_ID=${ID:-unknown}
    DISTRO_LIKE=${ID_LIKE:-}
    # Used by the calling installer when computing checkpoints.
    # shellcheck disable=SC2034
    DISTRO_VERSION=${VERSION_ID:-unknown}
    PM=''
    case " ${DISTRO_ID} ${DISTRO_LIKE} " in
        *' alpine '*)
            [[ ${SKIP_SYSTEM} -eq 1 ]] || die "Alpine/musl is not supported by this toolchain; use the Debian-based Docker image." ;;
        *' ubuntu '*|*' debian '*) PM=apt ;;
        *' fedora '*|*' rhel '*|*' centos '*|*' rocky '*|*' almalinux '*)
            PM=dnf
            command -v dnf >/dev/null 2>&1 || PM=yum ;;
        *' arch '*|*' manjaro '*) PM=pacman ;;
    esac
    if [[ ${SKIP_SYSTEM} -eq 0 && -n ${PM} && ${DRY_RUN} -eq 0 ]]; then
        local command_name=${PM}
        [[ ${PM} != apt ]] || command_name=apt-get
        command -v "${command_name}" >/dev/null 2>&1 || die "Expected package manager ${command_name} not found."
    fi
}

select_system_packages() {
    SYSTEM_PACKAGES=()
    case "${PM}" in
        apt)
            SYSTEM_PACKAGES=(build-essential clang llvm libclang-rt-dev valgrind
                libssl-dev pkg-config bubblewrap strace python3 python3-venv python3-pip
                curl ca-certificates git)
            ;;
        dnf|yum)
            SYSTEM_PACKAGES=(gcc gcc-c++ make clang llvm compiler-rt valgrind
                openssl-devel pkgconf-pkg-config bubblewrap strace curl ca-certificates git)
            # Enterprise Linux 9 defaults to Python 3.9. Its 3.11 suite is separate.
            if [[ " ${DISTRO_ID} ${DISTRO_LIKE} " == *' rhel '* || ${DISTRO_ID} == centos || ${DISTRO_ID} == rocky || ${DISTRO_ID} == almalinux ]]; then
                SYSTEM_PACKAGES+=(python3.11 python3.11-pip)
            else
                SYSTEM_PACKAGES+=(python3 python3-pip)
            fi
            ;;
        pacman)
            SYSTEM_PACKAGES=(base-devel clang llvm compiler-rt valgrind openssl pkgconf
                bubblewrap strace python python-pip curl ca-certificates git)
            ;;
    esac
}
