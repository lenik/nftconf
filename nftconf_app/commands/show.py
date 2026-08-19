"""show — per-statement live status (not an alias of check)."""

from __future__ import annotations

from pathlib import Path

from nftconf_app.coverage import coverage_for_policies, format_stmt_status
from nftconf_app.nft import scan_all_rules
from nftconf_app.parse import parse_file


def cmd_show(config_path: Path) -> int:
    cfg = parse_file(config_path, keep_going=True)
    try:
        lives = [lr for lr in scan_all_rules() if lr.owner == cfg.owner]
    except Exception:
        lives = []

    printed_header = False
    current: Path | None = None
    errors = 0
    for sl in cfg.source_lines:
        if sl.path != current:
            current = sl.path
            if sl.path != cfg.path.resolve() or printed_header:
                print(f"# {sl.path}")
            printed_header = True
        if sl.error:
            st = format_stmt_status(error=True)
            errors += 1
        elif sl.role == "policy" and sl.policies:
            hit, total = coverage_for_policies(sl.policies, lives)
            st = format_stmt_status(hit=hit, total=total)
        else:
            st = " " * 8
        print(f"{st}  {sl.text}")
    return 1 if errors else 0
