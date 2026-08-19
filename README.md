# nftconf

Declarative **nftables** configuration tool: reconcile a small config language
against the live ruleset, watch files for changes, and own every rule with a
stable comment tag.

## Features

- **load / unload / status / check / show** — live reconcile; `show` prints per-statement status (`on` / `N/M` / `---` / `xxx`)
- **daemon** — inotify reload + **pidfile** (single instance)
- **NAT** (`nat`/`dnat`/`snat`/`masquerade`/`redirect`) without opening INPUT
- **allow / deny** — incoming INPUT and outgoing OUTPUT policy
- **TCP/UDP port lists and ranges** — `allow incoming tcp 80 443 1080 8000-8080`
- **Context scopes** — multi-NIC / multi-address via `interface` / `address`
- **convert** — emit consolidated `nftables.d/*.nft`
- **Docker demo** — NAT, shield, reload, pidfile, dual-NIC lab under `demo/`

## Quick start

```bash
sudo apt install meson ninja-build python3 gettext asciidoctor pandoc texinfo nftables
meson setup /build
ninja -C /build
sudo /build/nftconf load -v demo/nftconf.conf   # needs root + nftables
```

```bash
nftconf load FILE
nftconf daemon FILE --pid /run/nftconf.pid
nftconf stop --pid /run/nftconf.pid
nftconf convert FILE -o nftables.d/out.nft
```

## Repository layout

| Path | Role |
|------|------|
| `nftconf.py` | Launcher |
| `nftconf_app/` | Python package (parse, reconcile, CLI) |
| `docs/*.adoc` | AsciiDoctor sources (man + info) |
| `guide.md` | Markdown user guide |
| `demo/` | Docker Compose test lab |
| `po/` | gettext catalogs |
| `debian/` | Packaging |

## Documentation

- Man page: `man nftconf` (from `docs/nftconf.1.adoc` via AsciiDoctor)
- Info manual: `info nftconf` (AsciiDoctor → DocBook → Texinfo)
- Guide: [guide.md](guide.md)
- Chinese overview: [README-zh.md](README-zh.md)
- Demo lab: [demo/README.md](demo/README.md)

Build docs with Meson (`asciidoctor`, `pandoc`, `makeinfo` required).

## Config sketch

```nftconf
table demo
interface eth0
address 203.0.113.10
dest address 10.0.0.50
priority filter

shield on
allow incoming tcp 22
allow incoming tcp 80 443 1080 8000-8080
deny incoming tcp 33
allow outgoing ip 10.0.0.0/8 tcp 443
nat tcp 8080 to 8080
nat tcp 80 443 to 10.0.0.50

include conf.d/*.conf
```

See [guide.md](guide.md) for the full language (ports, ranges, lists, NAT, shield).

## Build and test

Use absolute build directory **`/build`**:

```bash
meson setup /build
ninja -C /build
meson test -C /build
```

### i18n

```bash
ninja -C /build posync    # refresh pot/po from sources
LANGUAGE=zh_CN /build/nftconf -h
```

### Install helpers

```bash
meson install -C /build
ninja -C /build install-symlinks
ninja -C /build uninstall-symlinks
ninja -C /build look          # DESTDIR tree preview
```

## Docker demo

```bash
cd demo && docker compose up -d --build
docker compose exec client /demo/scripts/smoke-test.sh
./demo/scripts/function-cover.sh    # NAT, shield, allow/deny, daemon
```

## Debian package

```bash
dpkg-buildpackage -us -uc
```

## License

Copyright (C) 2026 Lenik <nftconf@bodz.net>

Licensed under **AGPL-3.0-or-later**.  
This project opposes AI exploitation and AI hegemony, and rejects mindless
MIT-style licensing and politically naive BSD-style licensing.  
See `LICENSE`.
