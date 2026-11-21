#!/usr/bin/env bash
# End to end: Go tests, the CLI on good and bad examples, a Helm pipeline, and
# the generated SLO rules checked and unit-tested by promtool in Docker.
set -euo pipefail
cd "$(dirname "$0")/.."
pass() { echo "PASS  $*" >&2; }
fail() { echo "FAIL  $*" >&2; exit 1; }
mkdir -p build bin

go vet ./... && go test ./... >/dev/null && pass "go: vet and tests"
go build -o bin/boecheck ./cmd/boecheck

out=$(./bin/boecheck scan examples/good) || fail "good examples reported a failure: $out"
pass "scan: examples/good is clean ($(echo "$out" | tail -1))"

rc=0; out=$(./bin/boecheck scan examples/bad) || rc=$?
[ "$rc" = 1 ] || fail "bad examples should exit 1, got $rc"
for id in BG001 BG002 BG003 BG006 BG007 BG008 BG009 TF001 TF002 TF004 TF006 AN001 AN002; do
  case "$out" in *"FAIL $id"*) ;; *) fail "bad examples did not trip $id" ;; esac
done
pass "scan: examples/bad is rejected ($(echo "$out" | tail -1))"

./bin/boecheck scan --boe build/boe.md examples/bad >/dev/null || true
grep -q '### SC-28 Protection of Information at Rest' build/boe.md || fail "BoE is missing SC-28"
pass "boe: Body of Evidence written to build/boe.md ($(wc -l < build/boe.md | tr -d ' ') lines)"

if command -v helm >/dev/null; then
  helm template shop examples/chart | ./bin/boecheck scan --skip BG007,BG008,BG009 - >/dev/null || fail "helm output failed the scan"
  pass "helm: rendered chart scanned through stdin"
else
  echo "SKIP  helm not installed" >&2
fi

./bin/boecheck slo examples/slo.yaml > build/rules.yml
./bin/boecheck runbook examples/slo.yaml > build/RUNBOOK.md
if docker info >/dev/null 2>&1; then
  img=prom/prometheus:v2.55.1
  docker run --rm --entrypoint promtool -v "$PWD":/w "$img" check rules /w/build/rules.yml >/dev/null || fail "promtool rejected the generated rules"
  pass "slo: promtool accepts the generated rules"
  docker run --rm --entrypoint promtool -v "$PWD":/w "$img" test rules /w/tests/slo_test.yml >/dev/null || fail "promtool unit test failed"
  pass "slo: a 2% error rate fires the page alert, a 0.05% rate does not"
else
  echo "SKIP  docker not running, promtool checks skipped" >&2
fi
echo "ALL PASS" >&2
