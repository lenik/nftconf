"""convert — write consolidated nftables.d/*.nft."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from nftconf_app.log import log
from nftconf_app.model import DEFAULT_NFTABLES_D, ConfigError, ConflictError
from nftconf_app.parse import parse_file
from nftconf_app.render import _render_nftables


def cmd_convert(
    files: list[Path],
    *,
    output: Optional[Path] = None,
    force: bool = False,
    no_clobber: bool = False,
    dry_run: bool = False,
) -> int:
    if force and no_clobber:
        raise ConflictError("cannot combine --force and --no-clobber")
    if not files:
        raise ConfigError("convert: no input files")
    if output is not None and len(files) > 1:
        raise ConfigError("convert: -o/--output requires a single input file")

    for src in files:
        cfg = parse_file(src)
        text = _render_nftables(cfg)
        if output is not None:
            out = output
        else:
            out = DEFAULT_NFTABLES_D / (src.stem + ".nft")

        if dry_run:
            log.info("would write %s (%d bytes)", out, len(text.encode()))
            print(text)
            continue

        if out.exists():
            if no_clobber:
                log.warning("skip existing %s (--no-clobber)", out)
                continue
            if not force:
                raise ConflictError(
                    f"refusing to overwrite {out} (use -f or -n)"
                )
            log.warning("overwriting %s", out)

        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text)
        log.info("wrote %s", out)
    return 0
