#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <nftconf@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""nftconf launcher — declarative nftables config tool."""

from __future__ import annotations

import sys
from pathlib import Path


def _bootstrap_path() -> None:
    """Ensure nftconf_app is importable (source tree, builddir, or install)."""
    here = Path(__file__).resolve().parent
    candidates = [here]
    # Meson builddir (/build/nftconf) → look at configured source root marker
    marker = here / ".nftconf-source-root"
    if marker.is_file():
        candidates.append(Path(marker.read_text().strip()))
    # Dev: launcher living in the project root
    if (here / "nftconf_app").is_dir():
        candidates.append(here)
    for cand in candidates:
        if (cand / "nftconf_app").is_dir():
            s = str(cand)
            if s not in sys.path:
                sys.path.insert(0, s)
            return


_bootstrap_path()

from nftconf_app.i18n import init_i18n  # noqa: E402
from nftconf_app.cli import main  # noqa: E402

if __name__ == "__main__":
    init_i18n(sys.argv[0])
    raise SystemExit(main())
