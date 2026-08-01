"""status — show desired vs live drift."""

from __future__ import annotations

from pathlib import Path

from nftconf_app.log import log
from nftconf_app.nft import scan_live
from nftconf_app.parse import parse_file


def cmd_status(config_path: Path) -> int:
    """Show desired vs live drift (always from in-memory nft)."""
    cfg = parse_file(config_path)
    desired = cfg.by_key()
    live = scan_live(owner=cfg.owner)
    missing = sorted(set(desired) - set(live))
    extra = sorted(set(live) - set(desired))
    ok = sorted(set(desired) & set(live))
    print(
        f"owner={cfg.owner}  desired={len(desired)}  live={len(live)}  "
        f"in-sync={len(ok)}  missing={len(missing)}  extra={len(extra)}"
    )
    for k in missing:
        print(f"  missing  {desired[k].summary} [{k}]")
        log.debug("missing %s", k)
    for k in extra:
        lr = live[k]
        print(f"  extra    {lr.chain}#{lr.handle} [{k}]")
        log.debug("extra %s handle %s", k, lr.handle)
    return 1 if missing or extra else 0
