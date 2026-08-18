"""argparse CLI and main() dispatch."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Optional

from nftconf_app import VERSION
from nftconf_app.commands.check import cmd_check
from nftconf_app.commands.convert import cmd_convert
from nftconf_app.commands.daemon import cmd_daemon
from nftconf_app.commands.load import cmd_load
from nftconf_app.commands.status import cmd_status
from nftconf_app.commands.stop import cmd_stop
from nftconf_app.commands.unload import cmd_unload
from nftconf_app.i18n import _
from nftconf_app.log import log, setup_logging
from nftconf_app.model import DEFAULT_PID, ConfigError, ConflictError


def _extract_global_flags(argv: list[str]) -> tuple[list[str], int, bool, bool]:
    """Pull -vqh/--verbose/--quiet/--version from anywhere; return (rest, v, q, version)."""
    verbose = 0
    quiet = False
    want_version = False
    rest: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-v", "--verbose"):
            verbose += 1
        elif re.fullmatch(r"-v+", a):
            verbose += len(a) - 1
        elif a in ("-q", "--quiet"):
            quiet = True
        elif a == "--version":
            want_version = True
        elif a in ("-h", "--help") and not rest:
            rest.append(a)
        else:
            rest.append(a)
        i += 1
    return rest, verbose, quiet, want_version


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nftconf",
        description=_("Declarative nftables config (live reconcile)"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_(
            "Conflict policy (load / unload):\n"
            "  default          abort if existing nft settings conflict\n"
            "  -f, --force      overwrite (load) or remove owned rules anyway (unload)\n"
            "  -n, --no-clobber skip conflicting changes; leave existing settings alone\n"
            "\n"
            "Global options (before or after CMD):\n"
            "  -v, --verbose    DEBUG logging\n"
            "  -q, --quiet      ERROR only\n"
            "  -h, --help       show help\n"
            "  --version        show version\n"
            "\n"
            "Notes:\n"
            "  NAT (nat/dnat/redirect) is handled in prerouting/forward — it does not\n"
            "  open INPUT. Use explicit whitelist/accept for ports that need host delivery\n"
            "  (SSH, etc.). With shield on, whitelist rules join the shield allow-list.\n"
            "  dest address / dest interface set defaults for the nat … to … side.\n"
            "  TCP/UDP matches take a port, a range (8000-8080), or a list\n"
            "  (80 443 1080 8000-8080). convert writes nftables.d/*.nft\n"
            "  (defines + port sets).\n"
        ),
    )

    sub = p.add_subparsers(dest="cmd", metavar="CMD")

    def add_conflict_opts(sp: argparse.ArgumentParser) -> None:
        g = sp.add_mutually_exclusive_group()
        g.add_argument(
            "-f",
            "--force",
            action="store_true",
            help=_("force overwrite/remove on conflict"),
        )
        g.add_argument(
            "-n",
            "--no-clobber",
            action="store_true",
            help=_("skip conflicting changes"),
        )
        sp.add_argument(
            "--dry-run",
            action="store_true",
            help=_("show actions without applying"),
        )

    sp_load = sub.add_parser("load", help=_("reconcile FILE against live nft"))
    sp_load.add_argument("file", type=Path)
    add_conflict_opts(sp_load)

    sp_unload = sub.add_parser("unload", help=_("remove live rules owned by FILE"))
    sp_unload.add_argument("file", type=Path)
    add_conflict_opts(sp_unload)

    sp_status = sub.add_parser("status", help=_("show drift vs live nft"))
    sp_status.add_argument("file", type=Path)

    sp_check = sub.add_parser("check", help=_("parse and print resolved rules"))
    sp_check.add_argument("file", type=Path)

    sp_show = sub.add_parser("show", help=_("alias for check"))
    sp_show.add_argument("file", type=Path)

    sp_daemon = sub.add_parser("daemon", help=_("watch FILE; reconcile on change"))
    sp_daemon.add_argument("file", type=Path)
    sp_daemon.add_argument(
        "--pid",
        type=Path,
        default=Path(DEFAULT_PID),
        help=_("pidfile path (default: %(default)s)"),
    )
    add_conflict_opts(sp_daemon)

    sp_stop = sub.add_parser("stop", help=_("stop daemon"))
    sp_stop.add_argument("file", type=Path, nargs="?", default=None)
    sp_stop.add_argument(
        "--pid",
        type=Path,
        default=Path(DEFAULT_PID),
        help=_("pidfile path (default: %(default)s)"),
    )

    sp_conv = sub.add_parser(
        "convert",
        help=_("convert nftconf FILE(s) to nftables.d/*.nft"),
    )
    sp_conv.add_argument("files", nargs="+", type=Path, metavar="FILE")
    sp_conv.add_argument(
        "-o",
        "--output",
        type=Path,
        help=_("output file (single input only); default nftables.d/<stem>.nft"),
    )
    add_conflict_opts(sp_conv)

    sub.add_parser("help", help=_("show this help"))

    return p


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    rest, verbose, quiet, want_version = _extract_global_flags(argv)

    if want_version:
        print(f"nftconf {VERSION}")
        return 0

    if rest == ["help"]:
        rest = ["-h"]

    setup_logging(verbose=verbose, quiet=quiet)

    parser = _build_parser()
    try:
        ns = parser.parse_args(rest)
    except SystemExit as e:
        return int(e.code) if e.code is not None else 0

    if not ns.cmd or ns.cmd == "help":
        parser.print_help()
        return 0

    try:
        if ns.cmd == "load":
            return cmd_load(
                ns.file,
                dry_run=ns.dry_run,
                force=ns.force,
                no_clobber=ns.no_clobber,
            )
        if ns.cmd == "unload":
            return cmd_unload(
                ns.file,
                dry_run=ns.dry_run,
                force=ns.force,
                no_clobber=ns.no_clobber,
            )
        if ns.cmd == "status":
            return cmd_status(ns.file)
        if ns.cmd in ("check", "show"):
            return cmd_check(ns.file)
        if ns.cmd == "daemon":
            return cmd_daemon(
                ns.file,
                ns.pid,
                force=ns.force,
                no_clobber=ns.no_clobber,
            )
        if ns.cmd == "stop":
            return cmd_stop(ns.pid)
        if ns.cmd == "convert":
            return cmd_convert(
                list(ns.files),
                output=ns.output,
                force=ns.force,
                no_clobber=ns.no_clobber,
                dry_run=ns.dry_run,
            )
        parser.print_help()
        return 2
    except ConflictError as e:
        log.error("%s", e)
        return 1
    except ConfigError as e:
        log.error("%s", e)
        return 1
    except RuntimeError as e:
        log.error("%s", e)
        return 1
