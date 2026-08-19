"""unload — remove live rules for statements in FILE."""

from __future__ import annotations

from pathlib import Path

from nftconf_app.coverage import live_port_atoms, live_scope_key, replace_dport_atoms
from nftconf_app.log import log
from nftconf_app.model import _comment, _rule_key
from nftconf_app.nft import _delete_lives, _nft_script, _parse_desired_stmt, scan_live
from nftconf_app.parse import parse_file


def _loc(family: str, table: str, chain: str, sig: str) -> tuple:
    return (family, table, chain) + live_scope_key(sig)


def cmd_unload(
    config_path: Path,
    *,
    dry_run: bool = False,
    force: bool = False,
) -> int:
    cfg = parse_file(config_path)
    owner = cfg.owner
    live = scan_live(owner=owner)
    desired = cfg.by_key()
    log.debug(
        "unload owner=%s desired=%d live=%d force=%s",
        owner,
        len(desired),
        len(live),
        force,
    )

    exact = [live[k] for k in desired if k in live]
    leftover = [lr for k, lr in live.items() if k not in desired]
    unmatched = [desired[k] for k in desired if k not in live]

    to_delete = list(exact)
    add_script: list[str] = []

    if force and unmatched and leftover:
        punch: dict[tuple, set[str]] = {}
        for dr in unmatched:
            family, table, chain, body = _parse_desired_stmt(dr.stmt)
            _proto, ports, _wild = live_port_atoms(body)
            if not ports:
                continue
            punch.setdefault(_loc(family, table, chain, body), set()).update(ports)

        for lr in leftover:
            drop_ports = punch.get(
                _loc(lr.family, lr.table, lr.chain, lr.signature)
            )
            if not drop_ports:
                continue
            _lproto, lports, _wild = live_port_atoms(lr.signature)
            if not (set(lports) & drop_ports):
                continue
            remaining = [a for a in lports if a not in drop_ports]
            to_delete.append(lr)
            new_sig = replace_dport_atoms(lr.signature, remaining)
            if new_sig:
                key = _rule_key("split", lr.family, lr.table, lr.chain, new_sig)
                add_script.append(
                    f"add rule {lr.family} {lr.table} {lr.chain} "
                    f"{new_sig} {_comment(owner, key)}"
                )

    if not to_delete and not add_script:
        log.info("unload complete (-0 stmts; owner=%s)", owner)
        return 0

    removed = _delete_lives(to_delete, dry_run=dry_run)
    if add_script:
        if dry_run:
            for s in add_script:
                log.info("would: %s", s)
        else:
            _nft_script("\n".join(add_script) + "\n")

    log.info("unload complete (-%d stmts; owner=%s)", removed, owner)
    return 0
