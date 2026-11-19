#!/usr/bin/env bash
# Full regression entry point: unit tests, then the four gate suites.
# Non-zero exit = a real regression. XFAIL lines are tracked open items, not greens.
#
# Two rules this file exists to honour:
#  - a pipe's exit status is NOT the program's: never trust `$?` after `| tail`
#  - the suites share containers and pinned UDP ports (7801/7802/7803, plus 7812/7813), so two
#    concurrent runs interfere and manufacture failures that look like product bugs. Refuse to
#    overlap rather than debug a phantom.
set -u
cd "$(dirname "$0")/.."

LOCK=/tmp/rsnext-gates.lock
if ! mkdir "$LOCK" 2>/dev/null; then
  echo "gates.sh is already running (lock: $LOCK)."
  echo "The suites share containers and ports - do not run them, or parts of them, concurrently."
  exit 4
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

rc=0
echo "### cargo test (Docker)"
docker exec rsnext-dev cargo test --workspace > /tmp/rsnext-cargo-test.log 2>&1
if [ $? -ne 0 ]; then rc=1; echo "cargo test FAILED"; tail -25 /tmp/rsnext-cargo-test.log; fi
grep -E 'test result' /tmp/rsnext-cargo-test.log | sed 's/^/    /'

for s in m2 u123 wot web channel mesh files rss wiki ban presence circles forget; do
  echo; echo "### gates_$s.sh"
  bash "tools/gates_$s.sh"
  code=$?
  [ $code -ne 0 ] && { rc=1; echo "  -> gates_$s.sh exited $code"; }
done

echo; echo "AGGREGATE rc=$rc"
exit $rc
