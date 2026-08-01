"""python -m nftconf_app"""

from __future__ import annotations

import sys

from nftconf_app.i18n import init_i18n
from nftconf_app.cli import main

if __name__ == "__main__":
    init_i18n(sys.argv[0])
    raise SystemExit(main())
