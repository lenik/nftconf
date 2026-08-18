"""Parse nftconf config files into DesiredRule / semantic models."""

from __future__ import annotations

import hashlib
import os
import re
import socket
import struct
import subprocess
from glob import glob
from pathlib import Path
from typing import Optional

from nftconf_app.log import log
from nftconf_app.model import (
    FAMILIES,
    PRIORITY_NAMES,
    PROTO_PORT,
    Config,
    ConfigError,
    Context,
    DesiredRule,
    SemNat,
    SemWhitelist,
    _comment,
    _owner_id,
    _rule_key,
    format_dports,
    normalize_port_atom,
)

_SPEC_RE = re.compile(
    r"""
    ^(?:
        (?P<addr>(?:\d{1,3}\.){3}\d{1,3}|\[?[0-9a-fA-F:]+\]?):
        (?P<ports>\d+(?:-\d+)?)
      |
        (?P<ports_only>\d+(?:-\d+)?)
    )$
    """,
    re.VERBOSE,
)


def _strip_comment(line: str) -> str:
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i].rstrip()
    return line.rstrip()


def _parse_priority(tok: str) -> int:
    if tok in PRIORITY_NAMES:
        return PRIORITY_NAMES[tok]
    try:
        return int(tok)
    except ValueError as e:
        raise ConfigError(f"invalid priority: {tok!r}") from e


def _parse_spec(spec: str) -> tuple[Optional[str], str]:
    m = _SPEC_RE.match(spec)
    if not m:
        raise ConfigError(
            f"invalid address/port spec: {spec!r} "
            "(want PORT, PORT-PORT, ADDR:PORT, or [IPv6]:PORT)"
        )
    if m.group("ports_only"):
        return None, normalize_port_atom(m.group("ports_only"))
    addr = m.group("addr")
    if addr.startswith("[") and addr.endswith("]"):
        addr = addr[1:-1]
    return addr, normalize_port_atom(m.group("ports"))


def _split_comma_outside_brackets(s: str) -> list[str]:
    """Split on commas that are not inside [IPv6] brackets."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in s:
        if ch == "[":
            depth += 1
            buf.append(ch)
        elif ch == "]":
            if depth:
                depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            piece = "".join(buf).strip()
            if piece:
                parts.append(piece)
            buf = []
        else:
            buf.append(ch)
    piece = "".join(buf).strip()
    if piece:
        parts.append(piece)
    if not parts:
        raise ConfigError(f"empty port list in {s!r}")
    return parts


def _parse_match_ports(tokens: list[str]) -> tuple[Optional[str], str]:
    """Parse PROTO-following tokens as a port list.

    Each whitespace token may itself contain commas. Pieces are:
      PORT              e.g. 80
      PORT-PORT         e.g. 8000-8080 (inclusive)
      ADDR:PORT[S]      e.g. 192.0.2.10:80 or [2001:db8::1]:443

    Multiple pieces become one nftables anonymous set. An address, if
    present, must be the same on every ADDR:… piece; bare ports inherit it.
    """
    if not tokens:
        raise ConfigError(
            "missing port spec (want PORT, PORT-PORT, a list, or ADDR:PORT)"
        )
    addr: Optional[str] = None
    atoms: list[str] = []
    for tok in tokens:
        for piece in _split_comma_outside_brackets(tok):
            try:
                a, p = _parse_spec(piece)
            except ConfigError:
                raise ConfigError(
                    f"invalid port or spec: {piece!r} "
                    "(want PORT, PORT-PORT, or ADDR:PORT)"
                ) from None
            if a is not None:
                if addr is not None and a != addr:
                    raise ConfigError(
                        f"conflicting match addresses in port list: "
                        f"{addr} vs {a}"
                    )
                addr = a
            atoms.append(p)
    return addr, format_dports(atoms)


def _parse_dest(spec: str, ctx: Context, *, dports: str) -> tuple[str, str]:
    """Resolve nat … to DEST.

    DEST forms:
      ADDR:PORT(S)     explicit
      PORT(S)          uses dest address / dest interface
      ADDR             same port(s) as source (dports)
    """
    # Bare IPv4 / IPv6 address → keep source ports
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", spec):
        return spec, dports
    if re.fullmatch(r"[0-9a-fA-F:]+", spec) and spec.count(":") >= 2:
        return spec, dports

    try:
        addr, ports = _parse_match_ports([spec])
    except ConfigError:
        raise ConfigError(
            f"invalid destination: {spec!r} "
            "(want ADDR:PORT, PORT, PORT-PORT, a port list, "
            "or ADDR with dest address context)"
        ) from None

    if addr is None:
        dests = _context_dest_addrs(ctx)
        if not dests:
            raise ConfigError(
                "destination has no address; set 'dest address' / "
                "'dest interface' or use ADDR:PORT"
            )
        addr = dests[0]
        if len(dests) > 1:
            log.debug(
                "dest address: using %s (of %d) for to-clause",
                addr,
                len(dests),
            )
        return addr, ports
    return addr, ports


def _iface_addrs(iface: str) -> list[str]:
    addrs: list[str] = []
    try:
        import fcntl

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ifreq = struct.pack("256s", iface[:15].encode())
            res = fcntl.ioctl(sock.fileno(), 0x8915, ifreq)
            ip = socket.inet_ntoa(res[20:24])
            if ip and ip != "0.0.0.0":
                addrs.append(ip)
        finally:
            sock.close()
    except OSError:
        pass
    if not addrs:
        try:
            out = subprocess.check_output(
                ["ip", "-4", "-o", "addr", "show", "dev", iface],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out):
                addrs.append(m.group(1))
        except (OSError, subprocess.CalledProcessError):
            pass
    return list(dict.fromkeys(addrs))


def _context_daddrs(ctx: Context) -> tuple[str, ...]:
    if ctx.addresses:
        return tuple(ctx.addresses)
    if ctx.resolve_iface_addrs and ctx.interfaces:
        found: list[str] = []
        for iface in ctx.interfaces:
            found.extend(_iface_addrs(iface))
        return tuple(dict.fromkeys(found))
    return ()


def _context_dest_addrs(ctx: Context) -> tuple[str, ...]:
    if ctx.dest_addresses:
        return tuple(ctx.dest_addresses)
    if ctx.resolve_dest_iface_addrs and ctx.dest_interfaces:
        found: list[str] = []
        for iface in ctx.dest_interfaces:
            found.extend(_iface_addrs(iface))
        return tuple(dict.fromkeys(found))
    return ()


def _copy_ctx(ctx: Context) -> Context:
    return Context(
        table=ctx.table,
        family=ctx.family,
        interfaces=list(ctx.interfaces),
        addresses=list(ctx.addresses),
        filter_priority=ctx.filter_priority,
        resolve_iface_addrs=ctx.resolve_iface_addrs,
        dest_interfaces=list(ctx.dest_interfaces),
        dest_addresses=list(ctx.dest_addresses),
        resolve_dest_iface_addrs=ctx.resolve_dest_iface_addrs,
        shield=ctx.shield,
    )


def _append_rule(cfg: Config, rule: DesiredRule) -> None:
    """Append a rule, skipping duplicates (same key)."""
    if any(r.key == rule.key for r in cfg.rules):
        log.debug("skip duplicate rule %s [%s]", rule.summary, rule.key)
        return
    cfg.rules.append(rule)


def parse_file(
    path: Path,
    *,
    owner: Optional[str] = None,
    _stack: Optional[list[Path]] = None,
    _ctx: Optional[Context] = None,
) -> Config:
    path = path.resolve()
    stack = _stack or []
    if path in stack:
        raise ConfigError(
            "include cycle: " + " -> ".join(str(p) for p in stack + [path])
        )
    if not path.is_file():
        raise ConfigError(f"file not found: {path}")

    if owner is None:
        owner = _owner_id(path)

    cfg = Config(path=path, owner=owner)
    ctx = Context() if _ctx is None else _copy_ctx(_ctx)
    stack = stack + [path]
    # Track whether shield infrastructure was emitted for current shield scope
    shield_infra_keys: set[str] = set()

    with path.open() as fh:
        for lineno, raw in enumerate(fh, 1):
            line = _strip_comment(raw).strip()
            if not line:
                continue
            try:
                _handle_line(line, ctx, cfg, path, stack, shield_infra_keys)
            except ConfigError as e:
                if e.path is None:
                    raise ConfigError(e.msg, path=path, lineno=lineno) from None
                raise
            except Exception as e:
                raise ConfigError(str(e), path=path, lineno=lineno) from e

    return cfg


def _handle_line(
    line: str,
    ctx: Context,
    cfg: Config,
    path: Path,
    stack: list[Path],
    shield_infra_keys: set[str],
) -> None:
    parts = line.split()
    op = parts[0].lower()

    # --- contexts ---
    if op == "table":
        if len(parts) < 2:
            raise ConfigError("usage: table NAME [family]")
        ctx.table = parts[1]
        if len(parts) >= 3:
            fam = parts[2].lower()
            if fam not in FAMILIES:
                raise ConfigError(f"invalid family: {fam}")
            ctx.family = fam
        return

    if op == "interface":
        if len(parts) < 2:
            raise ConfigError("usage: interface IFACE [IFACE...]")
        ctx.interfaces = parts[1:]
        ctx.addresses = []
        ctx.resolve_iface_addrs = True
        return

    if op == "address":
        if len(parts) < 2:
            raise ConfigError("usage: address ADDR [ADDR...]")
        ctx.addresses = parts[1:]
        ctx.resolve_iface_addrs = False
        return

    if op in ("dest", "destination"):
        if len(parts) < 3:
            raise ConfigError(
                "usage: dest interface IFACE... | dest address ADDR..."
            )
        sub = parts[1].lower()
        if sub == "interface":
            ctx.dest_interfaces = parts[2:]
            ctx.dest_addresses = []
            ctx.resolve_dest_iface_addrs = True
            return
        if sub == "address":
            ctx.dest_addresses = parts[2:]
            ctx.resolve_dest_iface_addrs = False
            return
        raise ConfigError(
            "usage: dest interface IFACE... | dest address ADDR..."
        )

    if op == "priority":
        if len(parts) != 2:
            raise ConfigError("usage: priority NAME|NUMBER")
        ctx.filter_priority = _parse_priority(parts[1])
        return

    if op == "shield":
        if len(parts) != 2 or parts[1].lower() not in ("on", "off", "yes", "no"):
            raise ConfigError("usage: shield on|off")
        ctx.shield = parts[1].lower() in ("on", "yes")
        if ctx.shield:
            cfg.shield_wanted = True
        return

    if op == "include":
        if len(parts) != 2:
            raise ConfigError("usage: include GLOB")
        pattern = parts[1]
        base = path.parent
        abs_pat = pattern if os.path.isabs(pattern) else str(base / pattern)
        matches = sorted(Path(p).resolve() for p in glob(abs_pat))
        if not matches:
            log.warning("include matched nothing: %s", pattern)
            return
        for inc in matches:
            if not inc.is_file():
                continue
            cfg.includes.append(inc)
            sub = parse_file(inc, owner=cfg.owner, _stack=stack, _ctx=ctx)
            cfg.rules.extend(sub.rules)
            cfg.includes.extend(sub.includes)
            cfg.tables |= sub.tables
            cfg.shield_wanted = cfg.shield_wanted or sub.shield_wanted
            cfg.sem_nat.extend(sub.sem_nat)
            cfg.sem_wl.extend(sub.sem_wl)
        return

    # --- NAT ---
    if op in ("nat", "dnat", "snat", "masquerade", "redirect"):
        _emit_nat(op, parts, ctx, cfg, path)
        return

    # --- filter verdicts ---
    if op in ("accept", "drop", "reject", "whitelist", "allow"):
        _emit_filter(op, parts, ctx, cfg, path, shield_infra_keys)
        return

    raise ConfigError(
        f"unknown directive: {op} "
        f"(contexts: table|interface|address|dest|priority|shield|include; "
        f"nat: nat|dnat|snat|masquerade|redirect; "
        f"filter: accept|allow|whitelist|drop|reject)"
    )


# ---------------------------------------------------------------------------
# Emit helpers
# ---------------------------------------------------------------------------


def _chain_hash(tag: str) -> str:
    return hashlib.sha256(tag.encode()).hexdigest()[:8]


def _nat_chains(family: str, table: str) -> dict[str, str]:
    h = _chain_hash(f"nat:{family}:{table}")
    return {
        "pre": f"nc_pre_{h}",
        "out": f"nc_out_{h}",
        "post": f"nc_post_{h}",
    }


def _filter_chain(family: str, table: str, priority: int) -> str:
    h = _chain_hash(f"filter:{family}:{table}:{priority}")
    return f"nc_in_{h}"


def _shield_names(
    family: str, table: str, priority: int, iface: str, daddrs: tuple[str, ...]
) -> dict[str, str]:
    h = _chain_hash(
        f"shield:{family}:{table}:{priority}:{iface}:{','.join(daddrs)}"
    )
    return {
        "chain": f"nc_sh_{h}",
        "jump_chain": _filter_chain(family, table, priority),
    }


def _daddr_match(daddrs: tuple[str, ...], family: str) -> str:
    if not daddrs:
        return ""
    key = "ip6" if family == "ip6" else "ip"
    if family == "inet":
        # mixed — prefer ip for v4 literals
        key = "ip" if all(":" not in a or a.count(":") == 0 for a in daddrs) else "ip"
        if any(":" in a for a in daddrs):
            key = "ip6" if all(":" in a for a in daddrs) else "ip"
    if len(daddrs) == 1:
        return f"{key} daddr {daddrs[0]} "
    return f"{key} daddr {{ {', '.join(daddrs)} }} "


def _iface_match(iface: Optional[str]) -> str:
    return f'iifname "{iface}" ' if iface else ""


def _ensure_shield_infra(
    ctx: Context,
    cfg: Config,
    path: Path,
    iface: Optional[str],
    daddrs: tuple[str, ...],
    shield_infra_keys: set[str],
) -> dict[str, str]:
    """Emit jump + ct/icmp/drop once per shield scope. Returns chain names."""
    names = _shield_names(
        ctx.family, ctx.table, ctx.filter_priority, iface or "", daddrs
    )
    cfg.tables.add((ctx.family, ctx.table))

    infra_key = _rule_key(
        "shield-infra",
        ctx.family,
        ctx.table,
        str(ctx.filter_priority),
        iface or "",
        ",".join(daddrs),
    )
    if infra_key in shield_infra_keys:
        return names
    shield_infra_keys.add(infra_key)

    owner = cfg.owner
    cmt = _comment(owner, infra_key)
    daddr = _daddr_match(daddrs, ctx.family)
    im = _iface_match(iface)
    jump_chain = names["jump_chain"]
    sh = names["chain"]

    # Jump from filter input → shield chain (match iface + daddrs)
    jump_stmt = (
        f"add rule {ctx.family} {ctx.table} {jump_chain} "
        f"{im}{daddr}jump {sh} {cmt}"
    )
    # Fixed prefix/suffix inside shield chain — separate keys so live scan
    # can see them; rebuilt as a group when membership changes.
    ct_key = _rule_key("shield-ct", infra_key)
    icmp_key = _rule_key("shield-icmp", infra_key)
    drop_key = _rule_key("shield-drop", infra_key)

    needs_filter = (
        (ctx.family, ctx.table, "filter", ctx.filter_priority),
        (
            ctx.family,
            ctx.table,
            "shield",
            ctx.filter_priority,
            iface or "",
            ",".join(daddrs),
        ),
    )
    needs_shield = (
        (
            ctx.family,
            ctx.table,
            "shield",
            ctx.filter_priority,
            iface or "",
            ",".join(daddrs),
        ),
    )

    _append_rule(
        cfg,
        DesiredRule(
            key=infra_key,
            kind="shield-jump",
            stmt=jump_stmt,
            needs=needs_filter,
            source=str(path),
            summary=f"shield jump → {sh}",
        ),
    )
    _append_rule(
        cfg,
        DesiredRule(
            key=ct_key,
            kind="shield-ct",
            stmt=(
                f"add rule {ctx.family} {ctx.table} {sh} "
                f"ct state established,related accept {_comment(owner, ct_key)}"
            ),
            needs=needs_shield,
            source=str(path),
            summary="shield ct established,related accept",
        ),
    )
    _append_rule(
        cfg,
        DesiredRule(
            key=icmp_key,
            kind="shield-icmp",
            stmt=(
                f"add rule {ctx.family} {ctx.table} {sh} "
                f"ip protocol icmp accept {_comment(owner, icmp_key)}"
            ),
            needs=needs_shield,
            source=str(path),
            summary="shield icmp accept",
        ),
    )
    _append_rule(
        cfg,
        DesiredRule(
            key=drop_key,
            kind="shield-drop",
            stmt=(
                f"add rule {ctx.family} {ctx.table} {sh} "
                f"drop {_comment(owner, drop_key)}"
            ),
            needs=needs_shield,
            source=str(path),
            summary="shield drop",
        ),
    )
    return names


def _ifaces(ctx: Context) -> list[Optional[str]]:
    return list(ctx.interfaces) if ctx.interfaces else [None]


def _require_to_clause(
    parts: list[str], usage: str
) -> tuple[str, list[str], str]:
    """Parse ``OP PROTO PORT... to DEST`` into (proto, port tokens, dest)."""
    if len(parts) < 5:
        raise ConfigError(usage)
    to_idx = None
    for i, p in enumerate(parts):
        if p.lower() == "to":
            to_idx = i
    if to_idx is None or to_idx != len(parts) - 2 or to_idx < 3:
        raise ConfigError(usage)
    proto = parts[1].lower()
    if proto not in PROTO_PORT:
        raise ConfigError(f"unsupported proto: {proto}")
    port_tokens = parts[2:to_idx]
    if not port_tokens:
        raise ConfigError(usage)
    return proto, port_tokens, parts[-1]


def _emit_nat(
    op: str,
    parts: list[str],
    ctx: Context,
    cfg: Config,
    path: Path,
) -> None:
    cfg.tables.add((ctx.family, ctx.table))
    chains = _nat_chains(ctx.family, ctx.table)
    needs = ((ctx.family, ctx.table, "nat"),)

    if op == "masquerade":
        # masquerade [PROTO [PORT...]]
        proto = None
        daddrs: tuple[str, ...] = ()
        dports = None
        if len(parts) >= 2:
            proto = parts[1].lower()
            if proto not in PROTO_PORT:
                raise ConfigError("usage: masquerade [PROTO [PORT...]]")
        if len(parts) >= 3:
            a, dports = _parse_match_ports(parts[2:])
            daddrs = (a,) if a else _context_daddrs(ctx)
        for iface in _ifaces(ctx):
            key = _rule_key(
                "masquerade",
                ctx.family,
                ctx.table,
                proto or "",
                ",".join(daddrs),
                dports or "",
                iface or "",
            )
            match = _iface_match(iface) + _daddr_match(daddrs, ctx.family)
            if proto and dports:
                match += f"{proto} dport {dports} "
            elif proto:
                match += f"meta l4proto {proto} "
            stmt = (
                f"add rule {ctx.family} {ctx.table} {chains['post']} "
                f"{match}masquerade {_comment(cfg.owner, key)}"
            )
            _append_rule(
                cfg,
                DesiredRule(
                    key=key,
                    kind="masquerade",
                    stmt=stmt,
                    needs=needs,
                    source=str(path),
                    summary=f"masquerade {proto or '*'} {dports or '*'}",
                ),
            )
        return

    if op == "redirect":
        # redirect PROTO PORT... to PORT
        proto, port_tokens, to_port_tok = _require_to_clause(
            parts, "usage: redirect PROTO PORT... to PORT"
        )
        src_addr, dports = _parse_match_ports(port_tokens)
        try:
            to_port = normalize_port_atom(to_port_tok)
        except ConfigError as e:
            raise ConfigError(f"invalid redirect port: {to_port_tok}") from e
        daddrs = (src_addr,) if src_addr else _context_daddrs(ctx)
        for iface in _ifaces(ctx):
            daddr = _daddr_match(daddrs, ctx.family)
            im = _iface_match(iface)
            for hook, chain, use_iface in (
                ("pre", chains["pre"], True),
                ("out", chains["out"], False),
            ):
                key = _rule_key(
                    "redirect",
                    hook,
                    ctx.family,
                    ctx.table,
                    proto,
                    ",".join(daddrs),
                    dports,
                    to_port,
                    iface or "",
                )
                prefix = im if use_iface else ""
                stmt = (
                    f"add rule {ctx.family} {ctx.table} {chain} "
                    f"{prefix}{daddr}{proto} dport {dports} "
                    f"redirect to {to_port} {_comment(cfg.owner, key)}"
                )
                _append_rule(
                    cfg,
                    DesiredRule(
                        key=key,
                        kind="redirect",
                        stmt=stmt,
                        needs=needs,
                        source=str(path),
                        summary=f"redirect/{hook} {proto} {dports} → {to_port}",
                    ),
                )
        return

    if op == "snat":
        # snat PROTO PORT... to ADDR[:PORT]
        proto, port_tokens, to = _require_to_clause(
            parts, "usage: snat PROTO PORT... to ADDR[:PORT]"
        )
        src_addr, dports = _parse_match_ports(port_tokens)
        daddrs = (src_addr,) if src_addr else _context_daddrs(ctx)
        for iface in _ifaces(ctx):
            key = _rule_key(
                "snat",
                ctx.family,
                ctx.table,
                proto,
                ",".join(daddrs),
                dports,
                to,
                iface or "",
            )
            stmt = (
                f"add rule {ctx.family} {ctx.table} {chains['post']} "
                f"{_daddr_match(daddrs, ctx.family) if daddrs else ''}"
                f"{proto} dport {dports} snat to {to} "
                f"{_comment(cfg.owner, key)}"
            )
            _append_rule(
                cfg,
                DesiredRule(
                    key=key,
                    kind="snat",
                    stmt=stmt,
                    needs=needs,
                    source=str(path),
                    summary=f"snat {proto} {dports} → {to}",
                ),
            )
        return

    # nat | dnat : PROTO PORT... to DEST
    proto, port_tokens, dest = _require_to_clause(
        parts, f"usage: {op} PROTO PORT... to DEST"
    )
    src_addr, dports = _parse_match_ports(port_tokens)
    to_addr, to_ports = _parse_dest(dest, ctx, dports=dports)
    daddrs = (src_addr,) if src_addr else _context_daddrs(ctx)
    if not daddrs:
        raise ConfigError(
            f"{op} rule has no match address; "
            "set 'address' / 'interface' or use ADDR:PORT"
        )
    do_snat = op == "nat"  # convenience: DNAT + SNAT like admin-dnat.sh
    for iface in _ifaces(ctx):
        cfg.sem_nat.append(
            SemNat(
                op=op,
                proto=proto,
                daddrs=daddrs,
                dports=dports,
                to_addr=to_addr,
                to_ports=to_ports,
                interface=iface,
                table=ctx.table,
                family=ctx.family,
                source=str(path),
            )
        )
        daddr = _daddr_match(daddrs, ctx.family)
        im = _iface_match(iface)
        # 1:1 port map → dnat to ADDR; otherwise ADDR:PORTS
        if to_ports == dports:
            dnat_to = to_addr
        else:
            dnat_to = f"{to_addr}:{to_ports}"
        pieces: list[tuple[str, str, str]] = [
            (
                "pre",
                chains["pre"],
                f"{im}{daddr}{proto} dport {dports} dnat to {dnat_to}",
            ),
            (
                "out",
                chains["out"],
                f"{daddr}{proto} dport {dports} dnat to {dnat_to}",
            ),
        ]
        if do_snat and len(daddrs) == 1:
            pieces.append(
                (
                    "post",
                    chains["post"],
                    f"ip daddr {to_addr} {proto} dport {to_ports} snat to {daddrs[0]}",
                ),
            )
        for hook, chain, body in pieces:
            key = _rule_key(
                op,
                hook,
                ctx.family,
                ctx.table,
                proto,
                ",".join(daddrs),
                dports,
                to_addr,
                to_ports,
                iface or "",
            )
            stmt = (
                f"add rule {ctx.family} {ctx.table} {chain} "
                f"{body} {_comment(cfg.owner, key)}"
            )
            _append_rule(
                cfg,
                DesiredRule(
                    key=key,
                    kind=f"{op}/{hook}",
                    stmt=stmt,
                    needs=needs,
                    source=str(path),
                    summary=(
                        f"{op}/{hook} {proto} {','.join(daddrs)}:{dports} "
                        f"→ {to_addr}:{to_ports}"
                    ),
                ),
            )


def _parse_filter_match(
    parts: list[str], ctx: Context
) -> tuple[str, str, tuple[str, ...], Optional[str]]:
    """Return (match_expr, summary_tail, daddrs_used, ports_or_None).

    Forms:
      accept                         → catch-all
      accept icmp
      accept icmpv6
      accept ct established[,related]...
      accept PROTO PORT...           → tcp/udp + port/range/list[/addr]
      accept PROTO                   → meta l4proto (no port)
    """
    if len(parts) == 1:
        return "", "*", (), None

    tok = parts[1].lower()

    if tok == "ct":
        if len(parts) < 3:
            raise ConfigError("usage: accept|drop|reject ct STATE[,STATE...]")
        states = parts[2].lower()
        return f"ct state {states} ", f"ct {states}", (), None

    if tok in ("icmp", "icmpv6"):
        if len(parts) > 2:
            # accept icmp echo-request  →  icmp type echo-request
            icmp_type = parts[2]
            if tok == "icmp":
                return f"icmp type {icmp_type} ", f"icmp {icmp_type}", (), None
            return f"icmpv6 type {icmp_type} ", f"icmpv6 {icmp_type}", (), None
        if tok == "icmp":
            return "ip protocol icmp ", "icmp", (), None
        return "meta l4proto ipv6-icmp ", "icmpv6", (), None

    if tok in PROTO_PORT:
        if len(parts) == 2:
            return f"meta l4proto {tok} ", tok, (), None
        src_addr, dports = _parse_match_ports(parts[2:])
        daddrs = (src_addr,) if src_addr else _context_daddrs(ctx)
        daddr = _daddr_match(daddrs, ctx.family)
        return f"{daddr}{tok} dport {dports} ", f"{tok} {dports}", daddrs, dports

    if tok in ("ip", "ip6", "any"):
        return "", tok, (), None

    raise ConfigError(f"invalid match: {tok!r}")


def _emit_filter(
    op: str,
    parts: list[str],
    ctx: Context,
    cfg: Config,
    path: Path,
    shield_infra_keys: set[str],
) -> None:
    # whitelist/allow → accept
    verdict = "accept" if op in ("whitelist", "allow") else op
    reject_with = None
    # reject PROTO PORT... [with ICMP_TYPE]
    body = parts
    if verdict == "reject" and "with" in [p.lower() for p in parts]:
        wi = next(i for i, p in enumerate(parts) if p.lower() == "with")
        if wi + 1 >= len(parts):
            raise ConfigError("usage: reject ... with TYPE")
        reject_with = " ".join(parts[wi + 1 :])
        body = parts[:wi]

    match_expr, summary_tail, daddrs, dports = _parse_filter_match(body, ctx)
    if verdict == "reject":
        action = f"reject with {reject_with}" if reject_with else "reject"
    else:
        action = verdict

    cfg.tables.add((ctx.family, ctx.table))

    # Semantic whitelist for convert (port accepts only)
    if (
        verdict == "accept"
        and dports
        and len(body) >= 3
        and body[1].lower() in PROTO_PORT
    ):
        wl_daddrs = daddrs if daddrs else _context_daddrs(ctx)
        for iface in _ifaces(ctx):
            cfg.sem_wl.append(
                SemWhitelist(
                    proto=body[1].lower(),
                    daddrs=wl_daddrs,
                    dports=dports,
                    interface=iface,
                    table=ctx.table,
                    family=ctx.family,
                    filter_priority=ctx.filter_priority,
                    shield=ctx.shield,
                    source=str(path),
                )
            )

    for iface in _ifaces(ctx):
        if ctx.shield:
            # Ensure infra; put accepts in shield chain; drop is infra
            if not daddrs and verdict != "drop":
                daddrs = _context_daddrs(ctx)
            names = _ensure_shield_infra(
                ctx,
                cfg,
                path,
                iface,
                daddrs if daddrs else _context_daddrs(ctx),
                shield_infra_keys,
            )
            # User drop inside shield is unusual — infra already ends with drop.
            # Still allow explicit accepts/whitelists.
            if verdict == "drop" and not match_expr:
                continue  # covered by shield-drop infra
            chain = names["chain"]
            # Insert before drop: we add accepts anytime; reconcile rebuilds
            # shield chain order (see apply).
            key = _rule_key(
                "shield-" + verdict,
                ctx.family,
                ctx.table,
                str(ctx.filter_priority),
                iface or "",
                ",".join(daddrs),
                match_expr,
                action,
            )
            # Port accepts inside shield should not re-match daddr (already jumped)
            # Use proto dport only when we have ports
            if dports:
                proto = body[1].lower()
                inner = f"{proto} dport {dports} "
            else:
                inner = match_expr
                # strip daddr from match inside shield — traffic already matched
                inner = re.sub(r"ip6? daddr \{[^}]+\} ", "", inner)
                inner = re.sub(r"ip6? daddr \S+ ", "", inner)
            stmt = (
                f"add rule {ctx.family} {ctx.table} {chain} "
                f"{inner}{action} {_comment(cfg.owner, key)}"
            )
            needs = (
                (
                    ctx.family,
                    ctx.table,
                    "shield",
                    ctx.filter_priority,
                    iface or "",
                    ",".join(daddrs if daddrs else _context_daddrs(ctx)),
                ),
            )
            _append_rule(
                cfg,
                DesiredRule(
                    key=key,
                    kind=f"shield-{verdict}",
                    stmt=stmt,
                    needs=needs,
                    source=str(path),
                    summary=f"shield {verdict} {summary_tail}",
                ),
            )
        else:
            chain = _filter_chain(ctx.family, ctx.table, ctx.filter_priority)
            key = _rule_key(
                verdict,
                ctx.family,
                ctx.table,
                str(ctx.filter_priority),
                iface or "",
                match_expr,
                action,
            )
            stmt = (
                f"add rule {ctx.family} {ctx.table} {chain} "
                f"{_iface_match(iface)}{match_expr}{action} "
                f"{_comment(cfg.owner, key)}"
            )
            _append_rule(
                cfg,
                DesiredRule(
                    key=key,
                    kind=verdict,
                    stmt=stmt,
                    needs=((ctx.family, ctx.table, "filter", ctx.filter_priority),),
                    source=str(path),
                    summary=f"{verdict} {summary_tail}",
                ),
            )
