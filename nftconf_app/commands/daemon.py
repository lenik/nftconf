"""daemon — watch FILE; reconcile on change."""

from __future__ import annotations

import os
import signal
import struct
import time
from pathlib import Path
from typing import Optional

from nftconf_app.log import log
from nftconf_app.model import Config, ConfigError
from nftconf_app.parse import parse_file
from nftconf_app.reconcile import reconcile


class Inotify:
    IN_CLOSE_WRITE = 0x00000008
    IN_MOVED_TO = 0x00000080
    IN_CREATE = 0x00000100
    IN_DELETE = 0x00000200
    IN_MODIFY = 0x00000002
    IN_ATTRIB = 0x00000004
    MASK = (
        IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB
    )

    def __init__(self) -> None:
        import ctypes
        import ctypes.util

        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self.libc = libc
        fd = libc.inotify_init1(0x80000)
        if fd < 0:
            fd = libc.inotify_init()
        if fd < 0:
            raise OSError("inotify_init failed")
        self.fd = fd
        self._wd: dict[int, Path] = {}
        self._watched: set[Path] = set()

    def add_watch_dir(self, path: Path) -> None:
        path = path.resolve()
        if not path.is_dir():
            path = path.parent
        if path in self._watched:
            return
        wd = self.libc.inotify_add_watch(self.fd, str(path).encode(), self.MASK)
        if wd < 0:
            raise OSError(f"inotify_add_watch failed for {path}")
        self._wd[wd] = path
        self._watched.add(path)

    def close(self) -> None:
        os.close(self.fd)

    def read_events(self, timeout: float = 1.0) -> list[Path]:
        import select

        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return []
        data = os.read(self.fd, 65536)
        events: list[Path] = []
        offset = 0
        while offset + 16 <= len(data):
            wd, _mask, _cookie, name_len = struct.unpack_from("iIII", data, offset)
            offset += 16
            name = ""
            if name_len:
                raw = data[offset : offset + name_len]
                offset += name_len
                name = raw.split(b"\0", 1)[0].decode(errors="replace")
            base = self._wd.get(wd)
            if base is None:
                continue
            events.append(base / name if name else base)
        return events


def _watch_dirs(cfg: Config) -> set[Path]:
    dirs = {cfg.path.resolve().parent}
    for p in cfg.includes:
        dirs.add(p.resolve().parent)
    return dirs


def _reload(
    config_path: Path,
    reason: str,
    *,
    force: bool = False,
    no_clobber: bool = False,
) -> Config:
    cfg = parse_file(config_path)
    added, removed = reconcile(
        cfg, dry_run=False, force=force, no_clobber=no_clobber
    )
    log.info("%s: +%d/-%d, %d rules", reason, added, removed, len(cfg.rules))
    return cfg


def cmd_daemon(
    config_path: Path,
    pidfile: Path,
    *,
    force: bool = False,
    no_clobber: bool = False,
) -> int:
    config_path = config_path.resolve()
    pidfile = Path(pidfile)

    if pidfile.exists():
        try:
            old_pid = int(pidfile.read_text().strip())
            os.kill(old_pid, 0)
            log.error("already running (pid %s)", old_pid)
            return 1
        except (ValueError, ProcessLookupError, PermissionError):
            pass

    pidfile.parent.mkdir(parents=True, exist_ok=True)
    pidfile.write_text(str(os.getpid()) + "\n")

    stop = False

    def _on_stop(signum, frame):  # noqa: ARG001
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _on_stop)
    signal.signal(signal.SIGINT, _on_stop)

    try:
        cfg = _reload(
            config_path, "initial load", force=force, no_clobber=no_clobber
        )
    except Exception as e:
        log.error("initial load failed: %s", e)
        pidfile.unlink(missing_ok=True)
        return 1

    try:
        inotify: Optional[Inotify] = Inotify()
    except OSError as e:
        log.warning("inotify unavailable (%s), using mtime poll", e)
        inotify = None

    def refresh(c: Config) -> None:
        if not inotify:
            return
        for d in _watch_dirs(c):
            try:
                inotify.add_watch_dir(d)
            except OSError as err:
                log.warning("watch %s: %s", d, err)

    if inotify:
        refresh(cfg)
        pending = False
        last = 0.0
        log.info("daemon watching %s (pid %s)", config_path, os.getpid())
        try:
            while not stop:
                if inotify.read_events(1.0):
                    pending = True
                now = time.time()
                if pending and now - last >= 0.4:
                    try:
                        cfg = _reload(
                            config_path,
                            "reload",
                            force=force,
                            no_clobber=no_clobber,
                        )
                        refresh(cfg)
                    except Exception as e:
                        log.error("reload error: %s", e)
                    last = now
                    pending = False
        finally:
            inotify.close()
    else:
        log.info("daemon (poll) watching %s (pid %s)", config_path, os.getpid())
        snap = {
            str(p): p.stat().st_mtime if p.exists() else -1.0
            for p in [cfg.path, *cfg.includes]
        }
        while not stop:
            time.sleep(1.0)
            try:
                cfg2 = parse_file(config_path)
            except ConfigError as e:
                log.error("parse error: %s", e)
                continue
            snap2 = {
                str(p): p.stat().st_mtime if p.exists() else -1.0
                for p in [cfg2.path, *cfg2.includes]
            }
            if snap2 != snap:
                try:
                    cfg = _reload(
                        config_path,
                        "reload",
                        force=force,
                        no_clobber=no_clobber,
                    )
                    snap = {
                        str(p): p.stat().st_mtime if p.exists() else -1.0
                        for p in [cfg.path, *cfg.includes]
                    }
                except Exception as e:
                    log.error("reload error: %s", e)

    if pidfile.is_file():
        try:
            if pidfile.read_text().strip() == str(os.getpid()):
                pidfile.unlink()
        except OSError:
            pass
    log.info("daemon stopped")
    return 0
