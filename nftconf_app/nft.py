"""Live nftables scan, ensure chains, delete helpers."""

from __future__ import annotations

import re
import subprocess
from typing import Iterable, Optional

from nftconf_app.model import LiveRule, _ADD_RULE_RE, _COMMENT_RE, _HANDLE_LINE
from nftconf_app.parse import _filter_chain, _nat_chains, _shield_names


def _nft(*args: str, check: bool = True) -> str:
    try:
        res = subprocess.run(
            ["nft", *args], check=False, capture_output=True, text=True
        )
    except FileNotFoundError as e:
        raise SystemExit("nftconf: nft command not found") from e
    if check and res.returncode != 0:
        err = (res.stderr or res.stdout or "").strip()
        raise RuntimeError(f"nft {' '.join(args)} failed: {err}")
    return res.stdout


def _nft_script(script: str) -> None:
    res = subprocess.run(
        ["nft", "-f", "-"],
        input=script,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        err = (res.stderr or res.stdout or "").strip()
        lines = [ln for ln in script.splitlines() if ln.strip()]
        preview = "\n".join(lines[:3])
        more = f"\n... ({len(lines) - 3} more)" if len(lines) > 3 else ""
        raise RuntimeError(f"nft apply failed: {err}\n---\n{preview}{more}")


def _ensure_table(family: str, table: str) -> None:
    _nft("add", "table", family, table, check=False)


def _add_chain(family: str, table: str, name: str, *body: str) -> None:
    _nft("add", "chain", family, table, name, "{", *body, "}", check=False)


def ensure_needs(needs: Iterable[tuple]) -> None:
    seen: set[tuple] = set()
    for n in needs:
        if n in seen:
            continue
        seen.add(n)
        family, table = n[0], n[1]
        kind = n[2]
        _ensure_table(family, table)
        if kind == "nat":
            ch = _nat_chains(family, table)
            _add_chain(
                family,
                table,
                ch["pre"],
                "type",
                "nat",
                "hook",
                "prerouting",
                "priority",
                "dstnat",
                ";",
            )
            _add_chain(
                family,
                table,
                ch["out"],
                "type",
                "nat",
                "hook",
                "output",
                "priority",
                "-100",
                ";",
            )
            _add_chain(
                family,
                table,
                ch["post"],
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "srcnat",
                ";",
            )
        elif kind == "filter":
            priority = n[3]
            name = _filter_chain(family, table, priority)
            _add_chain(
                family,
                table,
                name,
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                str(priority),
                ";",
                "policy",
                "accept",
                ";",
            )
        elif kind == "shield":
            priority, iface, daddrs_csv = n[3], n[4], n[5]
            daddrs = tuple(a for a in daddrs_csv.split(",") if a)
            names = _shield_names(family, table, priority, iface, daddrs)
            # regular filter chain (for the jump) + regular shield chain (no hook)
            ensure_needs([(family, table, "filter", priority)])
            _add_chain(family, table, names["chain"])


def list_all_tables() -> list[tuple[str, str]]:
    out = _nft("list", "tables", check=False)
    tables: list[tuple[str, str]] = []
    for line in out.splitlines():
        # table ip admin
        m = re.match(r"table\s+(\S+)\s+(\S+)", line.strip())
        if m:
            tables.append((m.group(1), m.group(2)))
    return tables


def _normalize_sig(body: str) -> str:
    """Rule body fingerprint for conflict detection (comment-stripped)."""
    body = _COMMENT_RE.sub("", body)
    body = re.sub(r"#\s*handle\s+\d+\s*$", "", body)
    return " ".join(body.split())


def _parse_desired_stmt(stmt: str) -> tuple[str, str, str, str]:
    m = _ADD_RULE_RE.match(stmt.strip())
    if not m:
        raise RuntimeError(f"internal: cannot parse stmt: {stmt}")
    return m.group("family"), m.group("table"), m.group("chain"), m.group("body")


def scan_all_rules(
    tables: Optional[Iterable[tuple[str, str]]] = None,
) -> list[LiveRule]:
    """Scan in-memory nft rules (owned and foreign)."""
    rules: list[LiveRule] = []
    for family, table in tables if tables is not None else list_all_tables():
        out = _nft("-a", "list", "table", family, table, check=False)
        if not out.strip():
            continue
        current_chain: Optional[str] = None
        for line in out.splitlines():
            m_ch = re.match(r"\s*chain\s+(\S+)", line)
            if m_ch:
                current_chain = m_ch.group(1)
                continue
            if current_chain is None:
                continue
            m_h = _HANDLE_LINE.search(line)
            if not m_h:
                continue
            # skip chain-type declaration lines
            if re.match(r"\s*type\s+", line):
                continue
            body = line.strip()
            m_cmt = _COMMENT_RE.search(body)
            owner = key = None
            if m_cmt:
                owner, key = m_cmt.group(1), m_cmt.group(2)
            rules.append(
                LiveRule(
                    owner=owner,
                    key=key,
                    family=family,
                    table=table,
                    chain=current_chain,
                    handle=int(m_h.group(1)),
                    signature=_normalize_sig(body),
                    raw=body,
                )
            )
    return rules


def scan_live(owner: Optional[str] = None) -> dict[str, LiveRule]:
    """nftconf-owned rules keyed by rule key. Optionally filter by owner."""
    by_key: dict[str, LiveRule] = {}
    for lr in scan_all_rules():
        if lr.owner is None or lr.key is None:
            continue
        if owner is not None and lr.owner != owner:
            continue
        by_key[lr.key] = lr
    return by_key


def _delete_lives(lives: list[LiveRule], *, dry_run: bool) -> int:
    from nftconf_app.log import log

    lives = sorted(lives, key=lambda x: (x.family, x.table, x.chain, -x.handle))
    n = 0
    for lr in lives:
        who = f"nftconf:{lr.owner}:{lr.key}" if lr.owner else "foreign"
        if dry_run:
            log.info(
                "would delete %s %s %s handle %s (%s)",
                lr.family,
                lr.table,
                lr.chain,
                lr.handle,
                who,
            )
        else:
            log.debug(
                "delete %s %s %s handle %s (%s)",
                lr.family,
                lr.table,
                lr.chain,
                lr.handle,
                who,
            )
            _nft(
                "delete",
                "rule",
                lr.family,
                lr.table,
                lr.chain,
                "handle",
                str(lr.handle),
                check=False,
            )
        n += 1
    return n
