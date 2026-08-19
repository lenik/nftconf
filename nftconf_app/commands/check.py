"""check — parse and print resolved nft rules."""

from __future__ import annotations

from pathlib import Path

from nftconf_app.log import log
from nftconf_app.parse import parse_file


def cmd_check(config_path: Path) -> int:
    cfg = parse_file(config_path)
    # check output is the deliverable — use stdout directly
    print(f"# {config_path} — {len(cfg.rules)} rules, owner={cfg.owner}")
    for r in cfg.rules:
        print(f"{r.kind:16} {r.summary}")
        print(f"  {r.stmt}")
        log.debug("%s", r.stmt)
    return 0
