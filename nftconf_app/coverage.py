"""Map config statements to live nft coverage (show / unload)."""

from __future__ import annotations

import re
from typing import Iterable, Optional

from nftconf_app.model import LiveRule, SemPolicy, format_dports, port_atoms

_DPORT_RE = re.compile(
    r"\b(tcp|udp|sctp|dccp)\s+dport\s+(\{[^}]+\}|\S+)",
    re.IGNORECASE,
)
_L4_RE = re.compile(r"\bmeta\s+l4proto\s+(tcp|udp|sctp|dccp)\b", re.IGNORECASE)
_VERDICT_RE = re.compile(r"\b(accept|drop|reject)\b", re.IGNORECASE)
_DADDR_RE = re.compile(r"\bip(?:6)?\s+daddr\s+(\S+)")
_IIF_RE = re.compile(r'\biifname\s+"([^"]+)"')
_OIF_RE = re.compile(r'\boifname\s+"([^"]+)"')


def format_stmt_status(*, error: bool = False, hit: int = 0, total: int = 0) -> str:
    """Width-8 right-aligned: on, N/M, ---, xxx."""
    if error:
        s = "xxx"
    elif total <= 0 or hit <= 0:
        s = "---"
    elif hit >= total:
        s = "on"
    else:
        s = f"{hit}/{total}"
    return f"{s:>8}"


def policy_units(p: SemPolicy) -> list[tuple[str, str, str]]:
    """(proto, atom, dest) atoms for one compiled policy row."""
    dest = p.dests[0] if p.dests else "*"
    if p.proto is None:
        return [("*", "*", dest)]
    if not p.dports:
        return [(p.proto, "*", dest)]
    return [(p.proto, a, dest) for a in port_atoms(p.dports)]


def line_units(policies: Iterable[SemPolicy]) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for p in policies:
        out.extend(policy_units(p))
    return out


def sig_verdict(sig: str) -> Optional[str]:
    m = _VERDICT_RE.search(sig)
    return m.group(1).lower() if m else None


def _sig_daddrs(sig: str) -> list[str]:
    found: list[str] = []
    for m in _DADDR_RE.finditer(sig):
        tok = m.group(1).rstrip(",")
        if tok.startswith("{") and tok.endswith("}"):
            found.extend(x.strip() for x in tok[1:-1].split(",") if x.strip())
        else:
            found.append(tok)
    return found


def live_port_atoms(sig: str) -> tuple[Optional[str], list[str], bool]:
    """Return (proto, dport atoms, proto_or_all_without_ports)."""
    m = _DPORT_RE.search(sig)
    if m:
        return m.group(1).lower(), port_atoms(m.group(2)), False
    m4 = _L4_RE.search(sig)
    if m4:
        return m4.group(1).lower(), [], True
    if _VERDICT_RE.search(sig) and "dport" not in sig:
        return None, [], True
    return None, [], False


def _dest_ok(p: SemPolicy, sig: str) -> bool:
    if not p.dests:
        return True
    live_d = _sig_daddrs(sig)
    if not live_d:
        # shield inner rules have no daddr (matched on the jump)
        return True
    want = set(p.dests)
    return bool(want & set(live_d))


def _iface_ok(p: SemPolicy, sig: str) -> bool:
    if not p.interface:
        return True
    if p.direction == "outgoing":
        m = _OIF_RE.search(sig)
        return m is None or m.group(1) == p.interface
    m = _IIF_RE.search(sig)
    return m is None or m.group(1) == p.interface


def unit_is_live(
    unit: tuple[str, str, str], p: SemPolicy, lives: Iterable[LiveRule]
) -> bool:
    proto_u, atom, _dest = unit
    for lr in lives:
        sig = lr.signature
        if sig_verdict(sig) != p.verdict:
            continue
        if not _dest_ok(p, sig):
            continue
        if not _iface_ok(p, sig):
            continue
        lproto, lports, wild = live_port_atoms(sig)
        if proto_u == "*":
            if wild and lproto is None:
                return True
            continue
        if lproto is not None and lproto != proto_u:
            continue
        if wild:
            return True
        if atom == "*" and lports:
            continue
        if atom == "*":
            return True
        if atom in lports:
            return True
    return False


def coverage_for_policies(
    policies: list[SemPolicy], lives: Iterable[LiveRule]
) -> tuple[int, int]:
    units = line_units(policies)
    if not units:
        return 0, 0
    lives = list(lives)
    hit = 0
    for p in policies:
        for u in policy_units(p):
            if unit_is_live(u, p, lives):
                hit += 1
    return hit, len(units)


def live_scope_key(sig: str) -> tuple:
    """Match leftover compacted rules only in the same proto/verdict/addr/iface."""
    proto, _ports, _wild = live_port_atoms(sig)
    daddrs = tuple(sorted(_sig_daddrs(sig)))
    iif = _IIF_RE.search(sig)
    oif = _OIF_RE.search(sig)
    return (
        proto or "",
        sig_verdict(sig) or "",
        daddrs,
        iif.group(1) if iif else "",
        oif.group(1) if oif else "",
    )


def replace_dport_atoms(sig: str, remaining: list[str]) -> Optional[str]:
    """Rewrite dport RHS. None → delete the rule (no ports left)."""
    m = _DPORT_RE.search(sig)
    if not m:
        return None if not remaining else sig
    if not remaining:
        return None
    rhs = format_dports(remaining)
    start, end = m.span(2)
    return sig[:start] + rhs + sig[end:]
