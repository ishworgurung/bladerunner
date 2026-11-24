# shellcheck shell=bash
# Shared helpers for the bladerunner scripts: logging, dependency checks, an
# exit-cleanup stack and tiny assertion helpers. Source it, do not execute it.
#
#   source "$(dirname "$0")/lib/common.sh"

# Guard against double-sourcing.
[ -n "${_BR_COMMON_SH:-}" ] && return 0
_BR_COMMON_SH=1

# Colour only when writing to a terminal.
if [ -t 2 ]; then _C_R=$'\e[31m'; _C_G=$'\e[32m'; _C_Y=$'\e[33m'; _C_B=$'\e[1m'; _C_0=$'\e[0m'
else _C_R=; _C_G=; _C_Y=; _C_B=; _C_0=; fi

log()  { printf '%s[%s]%s %s\n' "$_C_B" "${LOG_TAG:-bladerunner}" "$_C_0" "$*" >&2; }
warn() { printf '%s[%s] WARN:%s %s\n' "$_C_Y" "${LOG_TAG:-bladerunner}" "$_C_0" "$*" >&2; }
die()  { printf '%s[%s] FATAL:%s %s\n' "$_C_R" "${LOG_TAG:-bladerunner}" "$_C_0" "$*" >&2; exit 1; }

# need CMD...: fail early, naming every missing tool at once.
need() {
  local missing=() c
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
  [ ${#missing[@]} -eq 0 ] || die "missing required tools: ${missing[*]}"
}

# ---- exit-cleanup stack ----------------------------------------------------
# on_exit CMD: run CMD when the script exits, in reverse registration order,
# whatever the exit reason. Lets each library register its own teardown.
_BR_EXIT_CMDS=()
on_exit() { _BR_EXIT_CMDS+=("$1"); }
_br_run_exit() {
  local rc=$? i
  trap - EXIT
  for ((i=${#_BR_EXIT_CMDS[@]}-1; i>=0; i--)); do eval "${_BR_EXIT_CMDS[i]}" || true; done
  exit $rc
}
trap _br_run_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# retry N DELAY CMD...: run CMD until it succeeds, at most N times.
retry() {
  local n=$1 d=$2 i; shift 2
  for ((i=1; i<=n; i++)); do "$@" && return 0; sleep "$d"; done
  return 1
}

# free_port: print a currently unused TCP port on 127.0.0.1.
free_port() {
  python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'
}

# ---- assertions ------------------------------------------------------------
# Failures are counted rather than fatal so one run reports every failing check.
ASSERT_FAILS=0
ASSERT_PASSES=0
_pass() { ASSERT_PASSES=$((ASSERT_PASSES+1)); printf '  %sPASS%s %s\n' "$_C_G" "$_C_0" "$1" >&2; }
_fail() { ASSERT_FAILS=$((ASSERT_FAILS+1));   printf '  %sFAIL%s %s\n' "$_C_R" "$_C_0" "$1" >&2; }

# assert_eq DESC GOT WANT
assert_eq() { if [ "$2" = "$3" ]; then _pass "$1 (= $3)"; else _fail "$1: got $2, want $3"; fi; }
# assert_ge DESC GOT MIN
assert_ge() { if [ "$2" -ge "$3" ] 2>/dev/null; then _pass "$1 ($2 >= $3)"; else _fail "$1: got $2, want >= $3"; fi; }
# assert_true DESC CMD...: pass when the command succeeds
assert_true() { local d=$1; shift; if "$@" >/dev/null 2>&1; then _pass "$d"; else _fail "$d"; fi; }
