"""gettext setup for nftconf."""

from __future__ import annotations

import gettext
import locale
import os
from pathlib import Path
from typing import Optional

TEXT_DOMAIN = "nftconf"

_trans: Optional[gettext.NullTranslations] = None


def init_i18n(argv0: str) -> gettext.NullTranslations:
    """Install translations. Prefer ZEPHYR_LOCALEDIR, then build/po, then system."""
    global _trans
    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        pass

    localedir = os.environ.get("ZEPHYR_LOCALEDIR")
    if not localedir:
        argv_path = Path(argv0).resolve()
        for cand in (
            argv_path.parent / "po",
            argv_path.parent.parent / "po",
        ):
            if cand.is_dir():
                localedir = str(cand)
                break

    _trans = gettext.translation(
        TEXT_DOMAIN, localedir=localedir, fallback=True
    )
    _trans.install()
    return _trans


def _(message: str) -> str:
    """Translate via the catalog loaded by init_i18n."""
    if _trans is None:
        return message
    return _trans.gettext(message)
