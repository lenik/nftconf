#!/usr/bin/env bash
# Host-side function coverage for the nftconf docker lab.
#
#   demo/scripts/function-cover.sh
#   NFTCONF_DEMO_DOWN=1 demo/scripts/function-cover.sh   # tear down after
#
# Exit 77 (meson skip) when Docker is missing or the daemon is unreachable.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
DEMO=$(cd "$HERE/.." && pwd)
cd "$DEMO"

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not found"
  exit 77
fi
if ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon not reachable"
  exit 77
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "SKIP: docker compose not found"
  exit 77
fi

PASS=0
FAIL=0
ok() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

compose() { docker compose "$@"; }

run_exec() {
  local svc=$1
  shift
  echo
  echo "---- $svc: $* ----"
  if compose exec -T "$svc" "$@"; then
    ok "$svc $*"
  else
    bad "$svc $*"
  fi
}

cleanup() {
  compose exec -T gw /opt/nftconf/demo/scripts/smoke-test.sh policy-cleanup \
    >/dev/null 2>&1 || true
  if [[ "${NFTCONF_DEMO_DOWN:-0}" == 1 ]]; then
    echo
    echo "== docker compose down =="
    compose down -v || true
  fi
}
trap cleanup EXIT

echo "== docker compose up --build =="
compose up -d --build --force-recreate

echo "== wait for gw health =="
healthy=0
gw_id=""
for _ in $(seq 1 60); do
  gw_id=$(compose ps -q gw 2>/dev/null || true)
  if [[ -n "$gw_id" ]]; then
    st=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$gw_id" 2>/dev/null || true)
    if [[ "$st" == "healthy" ]]; then
      healthy=1
      break
    fi
  fi
  sleep 1
done
if [[ "$healthy" -eq 1 ]]; then
  ok "gw is healthy"
else
  echo "gw never became healthy"
  compose logs gw | tail -n 80 || true
  exit 1
fi

echo "== wait for client/app =="
for svc in app client mgmt-client; do
  ready=0
  for _ in $(seq 1 30); do
    cid=$(compose ps -q "$svc" 2>/dev/null || true)
    if [[ -n "$cid" ]]; then
      st=$(docker inspect --format '{{.State.Status}}' "$cid" 2>/dev/null || true)
      if [[ "$st" == "running" ]]; then
        ready=1
        break
      fi
    fi
    sleep 0.5
  done
  if [[ "$ready" -eq 1 ]]; then
    ok "$svc is running"
  else
    echo "$svc is not running"
    compose logs "$svc" | tail -n 40 || true
    FAIL=$((FAIL + 1))
  fi
done
if [[ "$FAIL" -ne 0 ]]; then
  exit 1
fi

run_exec gw python3 -m unittest discover -s /opt/nftconf/tests -p 'test_*.py'
run_exec client /demo/scripts/smoke-test.sh nat
run_exec client /demo/scripts/smoke-test.sh whitelist
run_exec mgmt-client /demo/scripts/smoke-test.sh mgmt
run_exec gw /opt/nftconf/demo/scripts/smoke-test.sh daemon
run_exec gw /opt/nftconf/demo/scripts/smoke-test.sh pidfile
run_exec gw /opt/nftconf/demo/scripts/smoke-test.sh incoming-apply
run_exec client /demo/scripts/smoke-test.sh incoming-policy
run_exec gw /opt/nftconf/demo/scripts/smoke-test.sh outgoing

echo
echo "Function-cover: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
