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
| `load FILE` | Reconcile config → live nft |
| `unload FILE` | Remove owned live rules |
| `status FILE` | Show drift |
| `check` / `show FILE` | Parse/print rules (no apply) |
| `daemon FILE` | Watch + reload; pidfile single-instance |
| `stop` | Stop daemon via `--pid` |
| `convert FILE…` | Write `nftables.d/*.nft` |

Global flags (anywhere): `-v` / `--verbose`, `-q` / `--quiet`, `-h`, `--version`.

Conflict policy on load/unload/daemon/convert:

- default — abort on conflict
- `-f` / `--force` — overwrite / remove anyway
- `-n` / `--no-clobber` — skip conflicts
- `--dry-run` — print only

## Config language

```nftconf
table demo
priority filter

interface eth0
address 203.0.113.10
dest address 10.0.0.50

include conf.d/*.conf
```

### Contexts

- `table NAME [family]` — default table `nftconf`, family `ip`
- `interface IFACE…` — `iifname` match; auto-resolve IPv4 unless `address` set
- `address ADDR…` — destination address match (multi-address OK)
- `dest address` / `dest interface` — defaults for `nat … to PORT`
- `priority NAME|NUM` — filter hook priority
- `shield on|off` — drop-default INPUT allow-list for this scope
- `include GLOB` — nested files inherit the current context

### NAT

```nftconf
nat tcp 8080 to 8080
nat tcp 443 to 10.0.0.50:8443
masquerade
redirect tcp 80 to 8080
```

NAT uses prerouting/output/postrouting. **It does not open INPUT.**

### Whitelist / shield

```nftconf
shield on
whitelist tcp 22
whitelist tcp 9090
```

With `shield on`, whitelist/accept rules join a per-scope shield chain that ends
in `drop`. Established/related and ICMP are accepted automatically.

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
