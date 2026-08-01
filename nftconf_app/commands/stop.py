"""stop — stop daemon via pidfile."""

from __future__ import annotations

import os
import signal
import time
from pathlib import Path

from nftconf_app.log import log


def cmd_stop(pidfile: Path) -> int:
    if not pidfile.is_file():
        log.error("no pid file: %s", pidfile)
        return 1
    try:
        pid = int(pidfile.read_text().strip())
    except ValueError:
        log.error("invalid pid file: %s", pidfile)
        return 1
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        log.info("process %s not running", pid)
        pidfile.unlink(missing_ok=True)
        return 0
    except PermissionError:
        log.error(
            "permission denied signaling pid %s (try: sudo nftconf stop --pid %s)",
            pid,
            pidfile,
        )
        return 1
    for _ in range(50):
        try:
            os.kill(pid, 0)
            time.sleep(0.1)
        except ProcessLookupError:
            break
    log.info("stopped pid %s", pid)
    return 0
