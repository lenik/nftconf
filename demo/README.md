# nftconf docker demo

Lab network to exercise **NAT**, **whitelist/shield**, **daemon file watch**, **pidfile**, and **multi-NIC / address context**.

## Topology

```
 client (10.66.10.10)
        |
   ext 10.66.10.0/24
        |
     gw 10.66.10.2  (nftconf daemon)
      | \_____________
      |               \
 int 10.66.20.0/24   mgmt 10.66.30.0/24
      |               |
 app 10.66.20.10   mgmt-client 10.66.30.10
```

| Role | Address | Purpose |
|------|---------|---------|
| `gw` | 10.66.10.2 / 10.66.20.2 / 10.66.30.2 | Runs `nftconf daemon`, DNAT + shield |
| `app` | 10.66.20.10 | HTTP on 8080/8443/9100 (DNAT target) |
| `client` | 10.66.10.10 | Probes ext VIP |
| `mgmt-client` | 10.66.30.10 | Probes management NIC scope |

## Quick start

```bash
cd demo
docker compose up -d --build

# NAT + ext whitelist
docker compose exec client /demo/scripts/smoke-test.sh nat
docker compose exec client /demo/scripts/smoke-test.sh whitelist

# Management address scope
docker compose exec mgmt-client /demo/scripts/smoke-test.sh mgmt

# Live reload + pidfile (must run on gw)
docker compose exec gw /opt/nftconf/demo/scripts/smoke-test.sh daemon
docker compose exec gw /opt/nftconf/demo/scripts/smoke-test.sh pidfile

# Everything the current container can see
docker compose exec client /demo/scripts/smoke-test.sh
```

## What each check covers

- **NAT** — `client → 10.66.10.2:8080/8443` DNATs to `app:8080/8443`.
- **Whitelist** — INPUT shield on ext VIP allows 2222/9090, drops 5555; DNAT still works (FORWARD/prerouting).
- **Context** — mgmt address `10.66.30.2` has its own shield membership (9100 yes, 2222/5555 no).
- **Daemon** — editing `conf.d/*.conf` reloads within ~1s via inotify.
- **Pidfile** — `/run/nftconf.pid`; a second `daemon` exits with “already running”.

## Config layout

- `nftconf.conf` — human-readable template (interfaces may be ethN placeholders)
- `scripts/entrypoint.sh` — resolves ifaces by IP, writes `/run/nftconf/nftconf.conf`, starts daemon
- `conf.d/nat.conf` — DNAT ports
- `conf.d/whitelist.conf` — ext shield allow-list
- `conf.d/mgmt.conf` — mgmt shield allow-list

## Manual probes

```bash
# DNAT
docker compose exec client curl -s http://10.66.10.2:8080/

# Watch live rules on gw
docker compose exec gw nft list ruleset

# Edit and watch daemon reload
docker compose exec gw bash -c 'echo "whitelist tcp 5555" >> /opt/nftconf/demo/conf.d/whitelist.conf'
docker compose logs -f gw
```

## Tear down

```bash
docker compose down -v
```
