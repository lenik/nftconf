#!/usr/bin/env bash
# Smoke tests for the nftconf demo compose lab.
#
#   docker compose exec client /demo/scripts/smoke-test.sh
#   docker compose exec mgmt-client /demo/scripts/smoke-test.sh mgmt
#   docker compose exec gw /opt/nftconf/demo/scripts/smoke-test.sh daemon
#   docker compose exec gw /opt/nftconf/demo/scripts/smoke-test.sh pidfile
#   ./scripts/function-cover.sh
set -euo pipefail

GW_EXT=10.66.10.2
GW_MGMT=10.66.30.2
PASS=0
FAIL=0

ok() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }
section() { echo; echo "== $* =="; }

wait_nft() {
  local pattern=$1
  local i
  for i in $(seq 1 30); do
    if nft list ruleset 2>/dev/null | grep -E "$pattern" >/dev/null; then
      return 0
    fi
    sleep 0.3
  done
  return 1
}

wait_nft_absent() {
  local pattern=$1
  local i
  for i in $(seq 1 30); do
    if ! nft list ruleset 2>/dev/null | grep -E "$pattern" >/dev/null; then
      return 0
    fi
    sleep 0.3
  done
  return 1
}

# Write stdin to DEST via rename so inotify sees a complete file (not a truncate).
atomic_write() {
  local dest=$1 tmp
  tmp=$(mktemp "${dest}.XXXXXX")
  cat >"$tmp"
  mv -f "$tmp" "$dest"
}

of_chain_name() {
  nft list table ip demo 2>/dev/null | awk '/chain nc_of_/ { print $2; exit }'
}

wait_of() {
  local pattern=$1
  local i ch
  for i in $(seq 1 30); do
    ch=$(of_chain_name)
    if [[ -n "$ch" ]] && nft list chain ip demo "$ch" 2>/dev/null | grep -E "$pattern" >/dev/null; then
      return 0
    fi
    sleep 0.3
  done
  return 1
}

wait_of_absent() {
  local pattern=$1
  local i ch
  for i in $(seq 1 30); do
    ch=$(of_chain_name)
    if [[ -n "$ch" ]] && ! nft list chain ip demo "$ch" 2>/dev/null | grep -E "$pattern" >/dev/null; then
      return 0
    fi
    sleep 0.3
  done
  return 1
}

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
      echo "allow incoming tcp 5555  # smoke reload" >>"$wl"
      opened=0
      for _ in $(seq 1 20); do
        sleep 0.3
        if nft list ruleset 2>/dev/null | grep -E '(^|[{, ])5555([, }]|$)' >/dev/null; then
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
        if ! nft list ruleset 2>/dev/null | grep -E '(^|[{, ])5555([, }]|$)' >/dev/null; then
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
  incoming-policy)
    section "Incoming allow/deny specificity (client → ext VIP)"
    if on_ext; then
      nc_ok "$GW_EXT" 8000 "range-allow 8000"
      nc_fail "$GW_EXT" 8033 "singleton-deny 8033 (beats range 8000-8100)"
      nc_ok "$GW_EXT" 8100 "range-allow 8100"
    else
      echo "  SKIP: not on ext net (apply incoming policy on gw first)"
    fi
    ;;&
  incoming-apply)
    section "Apply incoming range-allow + singleton-deny"
    if ! on_gw; then
      echo "  SKIP: run on gw"
    else
      ROOT=/opt/nftconf
      wl="$ROOT/demo/conf.d/whitelist.conf"
      bak=/run/nftconf/whitelist.conf.bak
      mkdir -p /run/nftconf
      if [[ ! -f "$bak" ]]; then
        cp "$wl" "$bak"
      fi
      ensure_listen() {
        local port=$1
        if nc -z -w 1 127.0.0.1 "$port" 2>/dev/null; then
          return 0
        fi
        python3 - "$port" <<'PY' &
import socket, sys
port = int(sys.argv[1])
body = b"ok\n"
hdr = b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)f
s.bind(("0.0.0.0", port))
s.listen(16)
while True:
    c, _ = s.accept()
    try:
        c.settimeout(1.0)
        try:
            c.recv(1024)
        except OSError:
            pass
        try:
            c.sendall(hdr + body)
        except OSError:
            pass
    finally:
        c.close()
PY
      }
      for p in 8000 8033 8100; do
        ensure_listen "$p"
      done
      if ! grep -q 'function-cover incoming' "$wl"; then
        cat >>"$wl" <<'EOF'

# function-cover incoming
allow incoming tcp 8000-8100
deny incoming tcp 8033
EOF
      fi
      if wait_nft 'tcp dport 8033 drop' && wait_nft 'tcp dport 8000-8100 accept'; then
        ok "nft: singleton deny 8033 before range allow 8000-8100"
      else
        bad "nft did not compile incoming deny-33 vs range"
        echo "---- nft ruleset (tail) ----"
        nft list ruleset 2>/dev/null | tail -n 80 || true
      fi
    fi
    ;;&
  outgoing)
    section "Outgoing allow/deny (gw → app)"
    if ! on_gw; then
      echo "  SKIP: run on gw"
    else
      ROOT=/opt/nftconf
      oc="$ROOT/demo/conf.d/outgoing.conf"
      bak=/run/nftconf/outgoing.conf.bak
      mkdir -p /run/nftconf
      if [[ ! -f "$bak" ]]; then
        cp "$oc" "$bak"
      fi
      restore_out() {
        local tmp
        tmp=$(mktemp "${oc}.XXXXXX")
        cp "$bak" "$tmp"
        mv -f "$tmp" "$oc"
      }
      trap restore_out EXIT

      APP=10.66.20.10
      # 9100/9200 are not DNATed; nat SNAT on 8080/8443 would rewrite gw→app.
      if curl -fsS --connect-timeout 2 --max-time 3 "http://$APP:9100/" >/dev/null; then
        ok "baseline gw→app:9100 (no outgoing policy)"
      else
        bad "baseline gw→app:9100 failed before policy"
      fi

      atomic_write "$oc" <<'EOF'
# function-cover outgoing: single port allow beats all-traffic deny
allow outgoing ip 10.66.20.10 tcp 9100
deny outgoing ip 10.66.20.10
EOF
      if wait_of 'tcp dport 9100 accept' && wait_of 'drop'; then
        ok "nft: outgoing tcp 9100 accept then dest drop"
      else
        bad "nft did not compile outgoing allow-9100 / deny-all"
        nft list table ip demo 2>/dev/null | grep -E 'nc_of_|daddr 10.66' || true
      fi
      if curl -fsS --connect-timeout 2 --max-time 3 "http://$APP:9100/" >/dev/null; then
        ok "outgoing allow tcp 9100 (deny-all underneath)"
      else
        bad "gw→app:9100 should pass (port allow > dest deny)"
      fi
      if curl -fsS --connect-timeout 2 --max-time 3 "http://$APP:9200/" >/dev/null; then
        bad "gw→app:9200 should be denied"
      else
        ok "outgoing deny all other tcp to app (9200 blocked)"
      fi

      atomic_write "$oc" <<'EOF'
# function-cover outgoing: deny entire dest
deny outgoing ip 10.66.20.10
EOF
      if wait_of_absent 'dport 9100 accept' && wait_of 'drop'; then
        ok "nft: outgoing dest drop only"
      else
        bad "nft still has stale outgoing 9100 accept"
        ch=$(of_chain_name); [[ -n "$ch" ]] && nft list chain ip demo "$ch" || true
      fi
      if curl -fsS --connect-timeout 2 --max-time 3 "http://$APP:9100/" >/dev/null; then
        bad "gw→app:9100 should be denied after dest drop"
        ch=$(of_chain_name); [[ -n "$ch" ]] && nft list chain ip demo "$ch" || true
      else
        ok "outgoing deny CIDR blocks 9100"
      fi

      atomic_write "$oc" <<'EOF'
# function-cover outgoing: longer prefix first
allow outgoing ip 10.66.20.0/24
deny outgoing ip 10.66.20.10 tcp 9200
EOF
      if wait_of 'tcp dport 9200 drop' && wait_of '10\.66\.20\.0/24'; then
        ok "nft: /32 deny-9200 and /24 allow"
      else
        bad "nft missing longer-prefix outgoing rules"
      fi
      if curl -fsS --connect-timeout 2 --max-time 3 "http://$APP:9100/" >/dev/null; then
        ok "outgoing /24 allow still opens 9100"
      else
        bad "gw→app:9100 should pass via /24 allow"
      fi
      if curl -fsS --connect-timeout 2 --max-time 3 "http://$APP:9200/" >/dev/null; then
        bad "gw→app:9200 should be denied by /32"
      else
        ok "outgoing /32 deny 9200 beats /24 allow"
      fi

      restore_out
      trap - EXIT
      if wait_nft_absent 'ip daddr 10\.66\.20\.10(/32)? drop'; then
        ok "outgoing policy restored"
      else
        bad "outgoing rules still present after restore"
      fi
      if curl -fsS --connect-timeout 2 --max-time 3 "http://$APP:9100/" >/dev/null; then
        ok "gw→app:9100 after outgoing restore"
      else
        bad "gw→app:9100 failed after outgoing restore"
      fi
    fi
    ;;&
  policy-cleanup)
    section "Restore function-cover conf.d files"
    if ! on_gw; then
      echo "  SKIP: run on gw"
    else
      ROOT=/opt/nftconf
      restored=0
      if [[ -f /run/nftconf/whitelist.conf.bak ]]; then
        cp /run/nftconf/whitelist.conf.bak "$ROOT/demo/conf.d/whitelist.conf"
        rm -f /run/nftconf/whitelist.conf.bak
        restored=1
      fi
      if [[ -f /run/nftconf/outgoing.conf.bak ]]; then
        tmp=$(mktemp "$ROOT/demo/conf.d/outgoing.conf.XXXXXX")
        cp /run/nftconf/outgoing.conf.bak "$tmp"
        mv -f "$tmp" "$ROOT/demo/conf.d/outgoing.conf"
        rm -f /run/nftconf/outgoing.conf.bak
        restored=1
      fi
      if [[ "$restored" -eq 1 ]]; then
        wait_nft_absent 'tcp dport 8033 drop' || true
        wait_nft_absent 'ip daddr 10\.66\.20\.10(/32)? drop' || true
        ok "restored whitelist.conf / outgoing.conf"
      else
        ok "no function-cover backups to restore"
      fi
    fi
    ;;&
  unit)
    section "Python unit tests (bind-mounted source)"
    if [[ ! -d /opt/nftconf/tests ]]; then
      echo "  SKIP: source tree not mounted"
    else
      export PYTHONPATH=/opt/nftconf
      if python3 -m unittest discover -s /opt/nftconf/tests -p 'test_*.py' -v; then
        ok "python unittest discover"
      else
        bad "python unittest discover"
      fi
    fi
    ;;&
esac

echo
echo "Result: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
