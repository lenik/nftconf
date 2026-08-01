"""unload — remove live rules owned by FILE."""

from __future__ import annotations

from pathlib import Path

from nftconf_app.log import log
from nftconf_app.model import ConflictError, _owner_id
from nftconf_app.nft import _delete_lives, scan_live
from nftconf_app.reconcile import find_unload_conflicts


def cmd_unload(
    config_path: Path,
    *,
    dry_run: bool = False,
    force: bool = False,
    no_clobber: bool = False,
) -> int:
    if force and no_clobber:
        raise ConflictError("cannot combine --force and --no-clobber")
    owner = _owner_id(config_path.resolve())
    live = scan_live(owner=owner)
    log.debug("unload owner=%s live=%d", owner, len(live))
    if not live:
        log.info("unload complete (-0 stmts; owner=%s)", owner)
        return 0

    foreign = find_unload_conflicts(owner, live)
    if foreign:
        for lr in foreign[:10]:
            who = (
                f"nftconf:{lr.owner}:{lr.key}"
                if lr.owner
                else f"foreign handle {lr.handle}"
            )
            msg = f"conflict: {lr.family}/{lr.table}/{lr.chain} has {who}"
            if force:
                log.warning("%s — forcing remove of owned rules", msg)
            elif no_clobber:
                log.warning("%s — skipping unload (--no-clobber)", msg)
            else:
                log.error("%s (use -f to remove owned rules or -n to skip)", msg)
        if len(foreign) > 10:
            log.error("... and %d more", len(foreign) - 10)
        if no_clobber:
            log.info(
                "unload skipped (%d foreign rule(s) in managed chains)", len(foreign)
            )
            return 0
        if not force:
            raise ConflictError(
                f"{len(foreign)} foreign rule(s) in chains owned rules share"
            )

    removed = _delete_lives(list(live.values()), dry_run=dry_run)
    log.info("unload complete (-%d stmts; owner=%s)", removed, owner)
    return 0
