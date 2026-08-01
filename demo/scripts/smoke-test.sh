#!/usr/bin/env bash
# Smoke tests for the nftconf demo compose lab.
#
#   docker compose exec client /demo/scripts/smoke-test.sh
#   docker compose exec mgmt-client /demo/scripts/smoke-test.sh mgmt
#   docker compose exec gw /opt/nftconf/demo/scripts/smoke-test.sh daemon
#   docker compose exec gw /opt/nftconf/demo/scripts/smoke-test.sh pidfile
set -euo pipefail

GW_EXT=10.66.10.2
GW_MGMT=10.66.30.2
PASS=0
FAIL=0

ok() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }
section() { echo; echo "== $* =="; }

curl_ok() {
  local url=$1 label=$2
  if curl -fsS --connect-timeout 2 --max-time 3 "$url" >/dev/null 2>&1; then
    ok "$label ($url)"
  else
    bad "$label ($url)"
  fi
}

nc_ok() {
  local host=$1 port=$2 label=$3
  if nc -z -w 2 "$host" "$port" 2>/dev/null; then
    ok "$label ($host:$port)"
  else
    bad "$label ($host:$port)"
  fi
}

nc_fail() {
  local host=$1 port=$2 label=$3
  if nc -z -w 2 "$host" "$port" 2>/dev/null; then
    bad "$label should be blocked ($host:$port)"
  else
    ok "$label blocked ($host:$port)"
  fi
}

on_ext() { ip -4 addr show 2>/dev/null | grep -q '10\.66\.10\.'; }
on_mgmt() { ip -4 addr show 2>/dev/null | grep -q '10\.66\.30\.'; }
on_gw() { [[ -f /run/nftconf.pid ]]; }

mode=${1:-all}

case "$mode" in
  nat|all)
    section "NAT (client → ext VIP → app)"
    if on_ext; then
      curl_ok "http://$GW_EXT:8080/" "DNAT 8080"
      curl_ok "http://$GW_EXT:8443/" "DNAT 8443"
    else
      echo "  SKIP: not on ext net"
    fi
    ;;&
  whitelist|all)
    section "Whitelist / shield INPUT on ext VIP"
    if on_ext; then
      nc_ok "$GW_EXT" 2222 "whitelisted 2222"
      nc_ok "$GW_EXT" 9090 "whitelisted 9090"
      nc_fail "$GW_EXT" 5555 "non-whitelisted 5555"
      curl_ok "http://$GW_EXT:8080/" "DNAT works with shield on"
    else
      echo "  SKIP: not on ext net"
    fi
    ;;&
  mgmt|all)
    section "Management NIC address scope"
    if on_mgmt; then
      nc_ok "$GW_MGMT" 9100 "mgmt whitelist 9100"
      nc_fail "$GW_MGMT" 5555 "mgmt non-whitelist 5555"
      nc_fail "$GW_MGMT" 2222 "2222 not in mgmt whitelist"
    else
      echo "  SKIP: not on mgmt net (use: docker compose exec mgmt-client ...)"
    fi
    ;;&
  daemon|all)
    section "Daemon live reload"
    if ! on_gw; then
      echo "  SKIP: run on gw (docker compose exec gw ... daemon)"
    else
      ROOT=/opt/nftconf
      export PYTHONPATH="$ROOT"
      wl="$ROOT/demo/conf.d/whitelist.conf"
      backup=$(mktemp)
      cp "$wl" "$backup"
      cleanup_wl() { cp "$backup" "$wl"; rm -f "$backup"; }
      trap cleanup_wl EXIT

      # Assert via live nft rules: local probes to $GW_EXT skip INPUT shield.
      echo "whitelist tcp 5555  # smoke reload" >>"$wl"
      opened=0
      for _ in $(seq 1 20); do
        sleep 0.3
        if nft list ruleset 2>/dev/null | grep -E 'tcp dport 5555 accept' >/dev/null; then
          opened=1
          break
        fi
      done
      if [[ "$opened" -eq 1 ]]; then
        ok "reload added tcp dport 5555 accept"
      else
        bad "reload did not add 5555 rule"
      fi

      cp "$backup" "$wl"
      closed=0
      for _ in $(seq 1 20); do
        sleep 0.3
        if ! nft list ruleset 2>/dev/null | grep -E 'tcp dport 5555 accept' >/dev/null; then
          closed=1
          break
        fi
      done
      if [[ "$closed" -eq 1 ]]; then
        ok "reload removed 5555 after revert"
      else
        bad "5555 rule still present after revert"
      fi
      trap - EXIT
      rm -f "$backup"
    fi
    ;;&
  pidfile|all)
    section "Pidfile single-instance"
    if ! on_gw; then
      echo "  SKIP: run on gw (docker compose exec gw ... pidfile)"
    else
      ROOT=/opt/nftconf
      export PYTHONPATH="$ROOT"
      if python3 -m nftconf_app daemon /run/nftconf/nftconf.conf --pid /run/nftconf.pid \
        >/tmp/nftconf-second.log 2>&1; then
        bad "second daemon should have refused"
      else
        if grep -qi 'already running' /tmp/nftconf-second.log; then
          ok "second instance refused (pidfile)"
        else
          bad "unexpected error: $(head -c 240 /tmp/nftconf-second.log)"
        fi
      fi
      pid=$(tr -d ' \n' </run/nftconf.pid)
      if kill -0 "$pid" 2>/dev/null; then
        ok "original daemon still running (pid $pid)"
      else
        bad "original daemon died"
      fi
    fi
    ;;&
esac

echo
echo "Result: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
