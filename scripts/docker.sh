#!/usr/bin/env bash
# Build/run the standalone image without mounting the parent research workspace.
set -Eeuo pipefail
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
IMAGE="${CWE_DOCKER_IMAGE:-cwe-witness:local}"
usage() {
    cat <<'HELP'
Usage:
  bash scripts/docker.sh build [docker build options...]
  bash scripts/docker.sh run [--full-isolation] [--input-dir DIR] [cweverify arguments...]

Defaults to `doctor`; evidence is persisted under .cwe-witness/.
Environment: CWE_DOCKER_IMAGE, CWE_DOCKER_OUTPUT (absolute or caller-relative path).
--full-isolation permits nested Bubblewrap mounts/namespaces and strace.
It runs as container root and relaxes seccomp/AppArmor; output may be root-owned.
HELP
}
case "${1:---help}" in
    -h|--help) usage; exit 0 ;;
    build|run) action=$1; shift ;;
    *) usage >&2; exit 2 ;;
esac
command -v docker >/dev/null 2>&1 || { echo 'Docker CLI is not installed.' >&2; exit 1; }
if [[ ${action} == build ]]; then
    exec docker build --tag "${IMAGE}" "$@" "${PROJECT_ROOT}"
fi
full=0
input=''
while [[ $# -gt 0 ]]; do
    case "$1" in
        --full-isolation) full=1; shift ;;
        --input-dir)
            [[ $# -ge 2 && -d $2 ]] || { echo '--input-dir requires an existing directory.' >&2; exit 2; }
            input="$(cd -- "$2" && pwd -P)"; shift 2 ;;
        --) shift; break ;;
        *) break ;;
    esac
done
output="${CWE_DOCKER_OUTPUT:-${PROJECT_ROOT}/.cwe-witness}"
mkdir -p -- "${output}"
output="$(cd -- "${output}" && pwd -P)"
args=(run --rm --network none --pids-limit 256
    --mount "type=bind,source=${output},target=/opt/cwe-witness/.cwe-witness")
if [[ ${full} -eq 1 ]]; then
    args+=(--user 0:0 --cap-add SYS_ADMIN --cap-add SYS_PTRACE
        --security-opt seccomp=unconfined --security-opt apparmor=unconfined)
else
    args+=(--user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges=true)
fi
if [[ -n ${input} ]]; then
    args+=(--mount "type=bind,source=${input},target=/inputs,readonly")
fi
[[ $# -gt 0 ]] || set -- doctor
exec docker "${args[@]}" "${IMAGE}" "$@"
