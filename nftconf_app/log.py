"""Logging setup for nftconf."""

from __future__ import annotations

import logging
import sys

log = logging.getLogger("nftconf")


def setup_logging(verbose: int = 0, quiet: bool = False) -> None:
    """Configure nftconf logger from -v/--verbose and -q/--quiet.

    Levels: quiet→ERROR, default→INFO, -v→DEBUG.
    """
    if quiet:
        level = logging.ERROR
    elif verbose >= 1:
        level = logging.DEBUG
    else:
        level = logging.INFO
    root = logging.getLogger("nftconf")
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("nftconf: %(levelname)s: %(message)s"))
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False
