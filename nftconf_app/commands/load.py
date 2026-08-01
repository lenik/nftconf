"""load — reconcile FILE against live nft."""

from __future__ import annotations

from pathlib import Path

from nftconf_app.log import log
from nftconf_app.parse import parse_file
from nftconf_app.reconcile import reconcile


def cmd_load(
    config_path: Path,
    *,
    dry_run: bool = False,
    force: bool = False,
    no_clobber: bool = False,
) -> int:
    cfg = parse_file(config_path)
    log.debug("parsed %s: %d rules owner=%s", config_path, len(cfg.rules), cfg.owner)
    added, removed = reconcile(
        cfg, dry_run=dry_run, force=force, no_clobber=no_clobber
    )
    log.info(
        "load complete (+%d/-%d stmts, %d desired; owner=%s)",
        added,
        removed,
        len(cfg.rules),
        cfg.owner,
    )
    return 0
