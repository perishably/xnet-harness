#!/usr/bin/env bash
# Git Bash and PowerShell are transport membranes for the same pinned controller.
set -euo pipefail

fail() { printf '%s\n' "$*" >&2; exit 2; }
usage() {
    printf '%s\n' 'Usage: oroboros-membrane.sh --config FILE --action plan|cycle|verify --python FILE.exe --script-sha256 HEX64 --core-sha256 HEX64 [--packet FILE]'
}

config=''; action=''; packet=''; python_executable=''; script_sha256=''; core_sha256=''
declare -A seen=()
while (( $# )); do
    option="$1"
    case "$option" in
        --help) (( $# == 1 )) || fail '--help must be used alone.'; usage; exit 0 ;;
        --config|--action|--packet|--python|--script-sha256|--core-sha256)
            (( $# >= 2 )) || fail "Missing value for $option."
            [[ -z "${seen[$option]+present}" ]] || fail "Duplicate option: $option."
            seen[$option]=1
            value="$2"
            [[ -n "$value" ]] || fail "Empty value for $option."
            case "$option" in
                --config) config="$value" ;;
                --action) action="$value" ;;
                --packet) packet="$value" ;;
                --python) python_executable="$value" ;;
                --script-sha256) script_sha256="$value" ;;
                --core-sha256) core_sha256="$value" ;;
            esac
            shift 2 ;;
        *) fail "Unknown option: $option." ;;
    esac
done

[[ -n "$config" && -n "$python_executable" ]] || fail '--config and --python are required.'
case "$action" in plan|cycle|verify) ;; *) fail 'Action must be plan, cycle, or verify.' ;; esac
[[ "$script_sha256" =~ ^[0-9a-fA-F]{64}$ && "$core_sha256" =~ ^[0-9a-fA-F]{64}$ ]] || fail 'Both source pins must be full SHA256 hex strings.'
if [[ "$action" == 'cycle' ]]; then
    [[ -n "$packet" ]] || fail 'cycle requires --packet.'
else
    [[ -z "$packet" ]] || fail '--packet is only accepted for cycle.'
fi

command -v cygpath >/dev/null || fail 'This launcher requires Git Bash cygpath.'
command -v sha256sum >/dev/null || fail 'This launcher requires Git Bash sha256sum.'
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
script_path="$script_dir/oroboros-sphere.py"
core_path="$repo_root/xnet/oroboros_sphere.py"

regular_file() {
    local input="$1" resolved native
    [[ "$input" != \\\\* && "$input" != //* ]] || fail 'Network file paths are outside the local membrane contract.'
    resolved="$(cygpath -u -- "$input")"
    [[ -f "$resolved" && ! -L "$resolved" ]] || fail 'Membrane input must be a regular local file.'
    native="$(cygpath -aw -- "$resolved")"
    [[ "$native" != \\\\* ]] || fail 'Network file paths are outside the local membrane contract.'
    printf '%s' "$resolved"
}
script_path="$(regular_file "$script_path")"
core_path="$(regular_file "$core_path")"
config="$(regular_file "$config")"
python_executable="$(regular_file "$python_executable")"
[[ "${python_executable,,}" == *.exe ]] || fail '--python must identify a local Python .exe.'

script_hash_output="$(sha256sum -- "$script_path")"
core_hash_output="$(sha256sum -- "$core_path")"
[[ "${script_hash_output%% *}" == "${script_sha256,,}" ]] || fail 'Pinned sphere CLI source hash mismatch.'
[[ "${core_hash_output%% *}" == "${core_sha256,,}" ]] || fail 'Pinned sphere core source hash mismatch.'

controller_arguments=(-I -B "$(cygpath -aw -- "$script_path")" --config "$(cygpath -aw -- "$config")" --lane git-bash --action "$action")
if [[ "$action" == 'cycle' ]]; then
    packet="$(regular_file "$packet")"
    controller_arguments+=(--packet "$(cygpath -aw -- "$packet")")
fi
# Explicit conversion plus exclusion prevents MSYS from rewriting data arguments.
MSYS2_ARG_CONV_EXCL='*' exec "$python_executable" "${controller_arguments[@]}"
