"""unload — remove live rules for statements in FILE."""

from __future__ import annotations

from pathlib import Path

from nftconf_app.coverage import plan_force_split, replace_dport_atoms
from nftconf_app.log import log
from nftconf_app.model import _comment, _rule_key
from nftconf_app.nft import (
    _delete_lives,
    _nft_script,
    _parse_desired_stmt,
    scan_all_rules,
    scan_live,
)
from nftconf_app.parse import parse_file


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
    skip_keys = {lr.key for lr in exact if lr.key}

    if force and unmatched:
        # Compact leftovers may be owned by a parent include file, and may
        # omit daddr (one packed tcp set). Scan every nftconf-owned rule.
        owned = [
            lr
            for lr in scan_all_rules()
            if lr.owner is not None and lr.key is not None
        ]
        pool = leftover + [lr for lr in owned if lr.key not in live]
        want = [_parse_desired_stmt(dr.stmt) for dr in unmatched]
        splits = plan_force_split(want, pool, skip_keys=skip_keys)
        seen: set[tuple[str, str, int]] = set()
        for lr, remaining in splits:
            ident = (lr.family, lr.table, lr.handle)
            if ident in seen:
                continue
            seen.add(ident)
            to_delete.append(lr)
            new_sig = replace_dport_atoms(lr.signature, remaining)
            if new_sig:
                keep_owner = lr.owner or owner
                key = _rule_key("split", lr.family, lr.table, lr.chain, new_sig)
                add_script.append(
                    f"add rule {lr.family} {lr.table} {lr.chain} "
                    f"{new_sig} {_comment(keep_owner, key)}"
                )
                log.debug(
                    "force-split %s/%s/%s handle %s drop leftover set → %s",
                    lr.family,
                    lr.table,
                    lr.chain,
                    lr.handle,
                    new_sig,
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
