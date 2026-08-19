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


def chain_kind(chain: str) -> str:
    if chain.startswith("nc_of_"):
        return "out"
    if chain.startswith("nc_sh_"):
        return "shield"
    if chain.startswith("nc_in_"):
        return "in"
    return chain


def _kinds_compatible(desired_chain: str, live_chain: str) -> bool:
    dk, lk = chain_kind(desired_chain), chain_kind(live_chain)
    if dk == lk:
        return True
    return {dk, lk} <= {"in", "shield"}


def _iface_overlap(want: str, live: str) -> bool:
    wi = _IIF_RE.search(want)
    li = _IIF_RE.search(live)
    if wi and li and wi.group(1) != li.group(1):
        return False
    wo = _OIF_RE.search(want)
    lo = _OIF_RE.search(live)
    if wo and lo and wo.group(1) != lo.group(1):
        return False
    return True


def punch_overlap(want_body: str, live_sig: str) -> set[str]:
    """Ports in both bodies when proto/verdict/addr/iface are compatible."""
    wp, wports, _ = live_port_atoms(want_body)
    lp, lports, _ = live_port_atoms(live_sig)
    if not wports or not lports or wp != lp:
        return set()
    if sig_verdict(want_body) != sig_verdict(live_sig):
        return set()
    hit = set(wports) & set(lports)
    if not hit:
        return set()
    wd = set(_sig_daddrs(want_body))
    ld = set(_sig_daddrs(live_sig))
    if wd and ld and not (wd & ld):
        return set()
    if not _iface_overlap(want_body, live_sig):
        return set()
    return hit


def plan_force_split(
    desired: list[tuple[str, str, str, str]],
    lives: list[LiveRule],
    *,
    skip_keys: Optional[set[str]] = None,
) -> list[tuple[LiveRule, list[str]]]:
    """For each leftover live rule, remaining dport atoms after punching FILE.

    desired entries are (family, table, chain, body). skip_keys are exact
    matches already queued for whole-rule delete.
    """
    skip = skip_keys or set()
    punch: dict[tuple[str, str, int], set[str]] = {}
    by_id: dict[tuple[str, str, int], LiveRule] = {}
    for lr in lives:
        if lr.owner is None or lr.key is None or lr.key in skip:
            continue
        ident = (lr.family, lr.table, lr.handle)
        by_id[ident] = lr
        punch.setdefault(ident, set())

    for family, table, chain, body in desired:
        for ident, lr in by_id.items():
            if lr.family != family or lr.table != table:
                continue
            if not _kinds_compatible(chain, lr.chain):
                continue
            punch[ident].update(punch_overlap(body, lr.signature))

    out: list[tuple[LiveRule, list[str]]] = []
    for ident, lr in by_id.items():
        drop = punch.get(ident) or set()
        if not drop:
            continue
        _lp, lports, _wild = live_port_atoms(lr.signature)
        if not (set(lports) & drop):
            continue
        remaining = [a for a in lports if a not in drop]
        out.append((lr, remaining))
    return out


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
