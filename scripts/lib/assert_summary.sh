# shellcheck shell=bash
# Prints the assertion tally and returns non-zero if anything failed.
# Requires common.sh to have been sourced.
assert_summary() {
  printf '\n%s: %d passed, %d failed\n' "${1:-result}" "$ASSERT_PASSES" "$ASSERT_FAILS" >&2
  [ "$ASSERT_FAILS" -eq 0 ]
}
