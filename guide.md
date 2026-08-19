# nftconf guide

Declarative **nftables** configuration with live reconcile, file watching, and
ownership-tagged rules.

## Install and run

```bash
sudo apt install meson ninja-build python3 gettext asciidoctor pandoc texinfo nftables
meson setup /build
ninja -C /build
sudo meson install -C /build
```

From a build tree without installing:

```bash
PYTHONPATH=/path/to/nftconf /build/nftconf --help
# or
PYTHONPATH=. python3 -m nftconf_app check demo/nftconf.conf
```

## Commands

| Command | Purpose |
|---------|---------|
| `load FILE` | Reconcile config → live nft (`-c` packs statements into sets) |
| `unload FILE` | Remove exact matching statements (`-f` splits leftovers; empty chains go) |
| `status FILE` | Show drift |
| `check FILE` | Parse/print resolved nft rules |
| `show FILE` | Per-statement status: `on` / `N/M` / `---` / `xxx` |
| `daemon FILE` | Watch + reload; pidfile single-instance |
| `stop` | Stop daemon via `--pid` |
| `convert FILE…` | Write `nftables.d/*.nft` |

Global flags (anywhere): `-v` / `--verbose`, `-q` / `--quiet`, `-h`, `--version`.

Conflict policy on load/daemon/convert:

- default — abort on conflict
- `-f` / `--force` — overwrite (load)
- `-n` / `--no-clobber` — skip conflicts
- `--dry-run` — print only

`load -c/--compact` packs matching allow/deny lines into nft sets.
`unload -f/--force` splits a leftover compacted rule when the statement
no longer matches as a whole.

## Config language

This is the full syntax reference. A file is one directive per line. Context
directives apply to every rule below them until the next context change.
There are no braces and no explicit end-of-scope.

### Lexical rules

- Tokens are whitespace-separated. Blank lines are ignored.
- `#` starts a comment to end of line, unless it is inside `'...'` or `"..."`.
  On the same line as a NAT/filter statement, that text is copied into the
  nft rule comment after the `nftconf:owner:key` tag.
- The first token is the directive. Directive names and keywords (`tcp`,
  `on`, `with`, families, priority names) are case-insensitive. Table names,
  interface names, and addresses are kept as written.
- Unknown directives are errors.
- `include` copies the current context into the included file; changes
  inside the include do not leak back.

### Defaults

Until set otherwise: table `nftconf`, family `ip`, no `iifname`, no
`ip daddr` (unless the rule writes `ADDR:PORT`), filter priority `0`,
`shield off`.

### Contexts

```nftconf
table demo
priority filter

interface eth0
address 203.0.113.10
dest address 10.0.0.50

include conf.d/*.conf
```

- `table NAME [family]` — target table (default `nftconf`). Family is
  `ip` (default), `ip6`, `inet`, `arp`, `bridge`, or `netdev`.
- `interface IFACE…` — match `iifname`; also resolve IPv4 addresses from
  those NICs until an `address` line overrides them. One rule is emitted
  per interface.
- `address ADDR…` — destination-address match (`ip daddr`). Several
  addresses become `{ a, b }`.
- `dest address ADDR…` / `dest interface IFACE…` — default internal/VIP
  side for `nat … to PORT`. `destination` is an alias of `dest`. If several
  dest addresses are set, the first is used in the `to` clause.
- `priority NAME|NUM` — INPUT hook priority for filter/shield rules:
  `raw` (-300), `mangle` (-150), `dstnat` (-100), `filter` (0),
  `security` (50), `srcnat` (100), or an integer. NAT hooks ignore this.
- `shield on|off` — `on`/`yes` puts later accepts into a drop-default
  chain for this scope (established/related and ICMP are allowed
  automatically). `off`/`no` uses ordinary INPUT. `shield on` does not
  open application ports by itself.
- `include GLOB` — include matching files (relative to the including
  file), sorted; inherits a copy of the current context. Cycles error.
  An empty match is a warning.

### Port specs (tcp / udp / sctp / dccp)

After a portful protocol, write a **port spec**:

| Form | Example | Emitted nft |
|------|---------|-------------|
| Single port (0–65535) | `allow incoming tcp 22` | `tcp dport 22` |
| Inclusive range | `allow incoming tcp 8000-8080` | `tcp dport 8000-8080` |
| List (spaces and/or commas) | `allow incoming tcp 80 443 1080` | `tcp dport { 80, 443, 1080 }` |
| Mixed list + range | `allow incoming tcp 80 8000-8080` | singles first, then the range |
| Address prefix | `allow incoming tcp 192.0.2.10:80 443` | `ip daddr 192.0.2.10 tcp dport { 80, 443 }` |

Rules:

- `HIGH` must be ≥ `LOW`. `22-22` collapses to `22`. `0080` normalizes to `80`.
- A list is sorted and deduplicated. A *single* port or range never gets
  set braces.
- Following bare ports inherit the address from `ADDR:PORT` on the same
  line. Two different addresses on one line are an error.
- Without an inline address, the current `address` / `interface` context
  supplies `ip daddr`. If that is empty, the match is port-only.
- Lists work on **filter** (`allow` / `deny` / `whitelist` / `blacklist`) and
  **NAT** (`nat` / `dnat` / `snat` / `masquerade` / `redirect`) after the
  protocol and before `to`.
- Not used for `icmp`, `icmpv6`, or `ct`.

NAT `to DEST` is **one token**:

- `ADDR` — keep the left-hand port spec (1:1), e.g.
  `nat tcp 80 443 8000-8080 to 10.0.0.50`
- `PORT` or `PORT-PORT` — use `dest address` / `dest interface`
- `ADDR:PORT` — explicit rewrite, e.g. `nat tcp 443 to 10.0.0.50:8443`

### NAT

```nftconf
nat tcp 8080 to 8080
nat tcp 80 443 8000-8080 to 10.0.0.50
nat tcp 443 to 10.0.0.50:8443
dnat udp 53 5353 to 10.0.0.53
snat tcp 80 443 to 203.0.113.10
masquerade
masquerade tcp 80 443
redirect tcp 80 443 to 8080
```

- `nat` — DNAT (prerouting + output) plus SNAT return path when the match
  address is a single IP.
- `dnat` — DNAT only.
- `snat` — postrouting SNAT.
- `masquerade` — postrouting masquerade; optional proto and port spec.
- `redirect` — redirect to a local port or range (`to` is not a list).

NAT uses prerouting/output/postrouting. **It does not open INPUT.** Host
delivery still needs `allow incoming` (or `whitelist`).

A `nat`/`dnat` line with no match address (no `address`/`interface` and no
`ADDR:PORT`) is an error.

### Allow / deny / shield

```nftconf
shield on
allow incoming tcp 22
allow incoming tcp 80 443 1080 8000-8080
deny incoming tcp 33
allow incoming udp 53
allow outgoing ip 10.0.0.0/8 tcp 443
allow outgoing ip 192.0.2.0/24
deny outgoing ip 8.8.8.8 udp 53
accept icmp
reject tcp 25 587 with tcp reset
```

- `allow incoming` / `deny incoming` apply to INPUT (`iifname` + `daddr`
  from context). `in` / `input` are aliases of `incoming`.
- `allow outgoing ip CIDR… [PROTO [PORT…]]…` applies to OUTPUT
  (`oifname` + `ip daddr`). Omit proto/ports to match **all** traffic to
  that CIDR. `out` / `output` alias `outgoing`.
- `whitelist` / `blacklist` are aliases of `allow incoming` /
  `deny incoming`.
- With `shield on`, incoming allows/denies join a per-scope shield chain
  that ends in `drop`. Established/related and ICMP are accepted
  automatically.
- **Priority** (nftables first-match): a **single port** is evaluated
  before a **range**; at the same specificity, **allow** is evaluated
  before **deny**.
  - `allow incoming tcp 10-100` plus `deny incoming tcp 33` → 33 is denied.
  - `allow incoming tcp 10-100` plus `deny incoming tcp 10-100` → 10–100
    are allowed.
- Longer outgoing prefixes are emitted before shorter ones (`/32` before
  `/8`).
- `reject … with TYPE…` is unchanged (`tcp reset`, …).

`nftconf convert` folds incoming allow port lists into `$whitelist_ports`.

## Multi-NIC / address scope

Each time you set `interface` / `address`, following rules use that scope.
Example: public VIP DNAT + separate management NIC shield:

```nftconf
table demo

interface eth0
address 10.66.10.2
dest address 10.66.20.10
include conf.d/nat.conf
include conf.d/whitelist.conf

interface eth2
address 10.66.30.2
include conf.d/mgmt.conf
```

## Daemon, reload, pidfile

```bash
sudo nftconf daemon -v /etc/nftconf/nftconf.conf --pid /run/nftconf.pid
# edit conf.d → automatic reconcile (~0.4s debounce)
sudo nftconf stop --pid /run/nftconf.pid
```

A second `daemon` with the same pidfile exits: `already running`.

## Docker demo lab

```bash
cd demo
docker compose up -d --build
docker compose exec client /demo/scripts/smoke-test.sh
docker compose exec mgmt-client /demo/scripts/smoke-test.sh mgmt
docker compose exec gw /opt/nftconf/demo/scripts/smoke-test.sh daemon
docker compose exec gw /opt/nftconf/demo/scripts/smoke-test.sh pidfile
./scripts/function-cover.sh
```

See [demo/README.md](demo/README.md).

## Documentation set

| Doc | Format |
|-----|--------|
| `nftconf(1)` | AsciiDoctor → man |
| `info nftconf` | AsciiDoctor → DocBook → Texinfo |
| `guide.md` | This Markdown guide |
| `README.md` / `README-zh.md` | Project overview |

## License

AGPL-3.0-or-later. See `LICENSE`.
