#!/usr/bin/python3
# Copyright (C) 2026 Lenik <nftconf@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""nftconf launcher — declarative nftables config tool."""

from __future__ import annotations

import sys
import sysconfig
from pathlib import Path


def _bootstrap_path() -> None:
    """Ensure nftconf_app is importable (install, builddir, or source tree)."""
    # Already on sys.path (normal Debian/system install)?
    try:
        import nftconf_app  # noqa: F401

        return
    except ImportError:
        pass

    here = Path(__file__).resolve().parent
    candidates: list[Path] = []

    # Meson builddir marker written next to the build output binary
    marker = here / ".nftconf-source-root"
    if marker.is_file():
        candidates.append(Path(marker.read_text().strip()))

    # Launcher living in the project root / bindir sibling layouts
    candidates.append(here)

    # Debian and other system prefixes (in case a non-system python ran us)
    for key in ("purelib", "platlib"):
        p = sysconfig.get_path(key)
        if p:
            candidates.append(Path(p))
    for p in (
        Path("/usr/lib/python3/dist-packages"),
        Path("/usr/local/lib/python3/dist-packages"),
    ):
        candidates.append(p)

    # Versioned dist-packages (python3.X)
    ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    candidates.append(Path(f"/usr/lib/python{ver}/dist-packages"))

    seen: set[str] = set()
    for cand in candidates:
        # cand may be the package parent (contains nftconf_app/) or site-packages
        root = cand if (cand / "nftconf_app").is_dir() else cand
        if not (root / "nftconf_app").is_dir():
            continue
        s = str(root)
        if s in seen:
            continue
        seen.add(s)
        if s not in sys.path:
            sys.path.insert(0, s)
        try:
            import nftconf_app  # noqa: F401

            return
        except ImportError:
            continue


_bootstrap_path()

try:
    from nftconf_app.i18n import init_i18n
    from nftconf_app.cli import main
except ImportError as e:
    sys.stderr.write(
        f"nftconf: cannot import nftconf_app ({e}).\n"
        "Install the package (e.g. meson install / dpkg -i) or set PYTHONPATH "
        "to the source tree containing nftconf_app/.\n"
    )
    raise SystemExit(1) from e

if __name__ == "__main__":
    init_i18n(sys.argv[0])
    raise SystemExit(main())
