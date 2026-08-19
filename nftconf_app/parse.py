"""Parse nftconf config files into DesiredRule / semantic models."""

from __future__ import annotations

import hashlib
import ipaddress
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
    SemPolicy,
    SemWhitelist,
    SourceLine,
    _comment,
    _owner_id,
    _rule_comment,
    _rule_key,
    format_dports,
    normalize_port_atom,
    port_atoms,
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


def _split_inline_comment(line: str) -> tuple[str, str]:
    """Split a trailing # comment outside quotes. Returns (code, note)."""
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i].rstrip(), line[i + 1 :].strip()
    return line.rstrip(), ""


def _strip_comment(line: str) -> str:
    return _split_inline_comment(line)[0]


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
    _defer_policy: bool = False,
    compact: bool = False,
    keep_going: bool = False,
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

    cfg = Config(path=path, owner=owner, compact=compact)
    ctx = Context() if _ctx is None else _copy_ctx(_ctx)
    stack = stack + [path]
    # Track whether shield infrastructure was emitted for current shield scope
    shield_infra_keys: set[str] = set()

    with path.open() as fh:
        for lineno, raw in enumerate(fh, 1):
            code, note = _split_inline_comment(raw)
            line = code.strip()
            if not line:
                continue
            sl = SourceLine(path=path, lineno=lineno, text=line, note=note)
            cfg.source_lines.append(sl)
            cfg.line_note = note
            try:
                _handle_line(
                    line,
                    ctx,
                    cfg,
                    path,
                    stack,
                    shield_infra_keys,
                    lineno=lineno,
                    source_line=sl,
                    compact=compact,
                    keep_going=keep_going,
                )
            except ConfigError as e:
                msg = e.msg
                if keep_going:
                    sl.error = msg
                    continue
                if e.path is None:
                    raise ConfigError(msg, path=path, lineno=lineno) from None
                raise
            except Exception as e:
                if keep_going:
                    sl.error = str(e)
                    continue
                raise ConfigError(str(e), path=path, lineno=lineno) from e
            finally:
                cfg.line_note = ""

    if not _defer_policy:
        _compile_policies(cfg, path)

    return cfg


def _handle_line(
    line: str,
    ctx: Context,
    cfg: Config,
    path: Path,
    stack: list[Path],
    shield_infra_keys: set[str],
    *,
    lineno: int = 0,
    source_line: Optional[SourceLine] = None,
    compact: bool = False,
    keep_going: bool = False,
) -> None:
    parts = line.split()
    op = parts[0].lower()

    def _role(role: str) -> None:
        if source_line is not None:
            source_line.role = role

    # --- contexts ---
    if op == "table":
        _role("context")
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
        _role("context")
        if len(parts) < 2:
            raise ConfigError("usage: interface IFACE [IFACE...]")
        ctx.interfaces = parts[1:]
        ctx.addresses = []
        ctx.resolve_iface_addrs = True
        return

    if op == "address":
        _role("context")
        if len(parts) < 2:
            raise ConfigError("usage: address ADDR [ADDR...]")
        ctx.addresses = parts[1:]
        ctx.resolve_iface_addrs = False
        return

    if op in ("dest", "destination"):
        _role("context")
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
        _role("context")
        if len(parts) != 2:
            raise ConfigError("usage: priority NAME|NUMBER")
        ctx.filter_priority = _parse_priority(parts[1])
        return

    if op == "shield":
        _role("context")
        if len(parts) != 2 or parts[1].lower() not in ("on", "off", "yes", "no"):
            raise ConfigError("usage: shield on|off")
        ctx.shield = parts[1].lower() in ("on", "yes")
        if ctx.shield:
            cfg.shield_wanted = True
        return

    if op == "include":
        _role("include")
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
            sub = parse_file(
                inc,
                owner=cfg.owner,
                _stack=stack,
                _ctx=ctx,
                _defer_policy=True,
                compact=compact,
                keep_going=keep_going,
            )
            cfg.rules.extend(sub.rules)
            cfg.includes.extend(sub.includes)
            cfg.tables |= sub.tables
            cfg.shield_wanted = cfg.shield_wanted or sub.shield_wanted
            cfg.sem_nat.extend(sub.sem_nat)
            cfg.sem_wl.extend(sub.sem_wl)
            cfg.sem_policy.extend(sub.sem_policy)
            cfg.source_lines.extend(sub.source_lines)
        return

    # --- NAT ---
    if op in ("nat", "dnat", "snat", "masquerade", "redirect"):
        _role("nat")
        _emit_nat(op, parts, ctx, cfg, path)
        return

    # --- filter policy (allow/deny incoming|outgoing) ---
    if op in ("allow", "deny", "whitelist", "blacklist"):
        _role("policy")
        _collect_policy(
            op, parts, ctx, cfg, path, lineno=lineno, source_line=source_line
        )
        return

    # --- legacy / non-port filter (icmp, ct, reject, catch-all) ---
    if op == "reject":
        _role("filter")
        _emit_filter(op, parts, ctx, cfg, path, shield_infra_keys)
        return
    if op in ("accept", "drop"):
        rest0 = parts[1].lower() if len(parts) > 1 else ""
        if rest0 in _DIRECTIONS or rest0 in PROTO_PORT:
            _role("policy")
            _collect_policy(
                op, parts, ctx, cfg, path, lineno=lineno, source_line=source_line
            )
            return
        _role("filter")
        _emit_filter(op, parts, ctx, cfg, path, shield_infra_keys)
        return

    raise ConfigError(
        f"unknown directive: {op} "
        f"(contexts: table|interface|address|dest|priority|shield|include; "
        f"nat: nat|dnat|snat|masquerade|redirect; "
        f"filter: allow|deny|whitelist|blacklist|accept|drop|reject)"
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


def _output_filter_chain(family: str, table: str, priority: int) -> str:
    h = _chain_hash(f"filter-out:{family}:{table}:{priority}")
    return f"nc_of_{h}"


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


def _oiface_match(iface: Optional[str]) -> str:
    return f'oifname "{iface}" ' if iface else ""


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


_DIRECTIONS = {
    "incoming": "incoming",
    "in": "incoming",
    "input": "incoming",
    "outgoing": "outgoing",
    "out": "outgoing",
    "output": "outgoing",
}

_PROTO_ORDER = ("tcp", "udp", "sctp", "dccp")


def _parse_cidr(tok: str) -> str:
    try:
        net = ipaddress.ip_network(tok, strict=False)
    except ValueError as e:
        raise ConfigError(
            f"invalid CIDR: {tok!r} (want ADDR or ADDR/PREFIX)"
        ) from e
    return str(net)


def _cidr_prefixlen(cidr: str) -> int:
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen
    except ValueError:
        return 0


def _collect_policy(
    op: str,
    parts: list[str],
    ctx: Context,
    cfg: Config,
    path: Path,
    *,
    lineno: int = 0,
    source_line: Optional[SourceLine] = None,
) -> None:
    if op in ("whitelist", "allow", "accept"):
        verdict = "accept"
    else:
        verdict = "drop"

    rest = parts[1:]
    direction = "incoming"
    if rest and rest[0].lower() in _DIRECTIONS:
        direction = _DIRECTIONS[rest[0].lower()]
        rest = rest[1:]
    if op == "whitelist" and direction != "incoming":
        raise ConfigError("whitelist is incoming only; use 'allow outgoing ...'")
    if op == "blacklist" and direction != "incoming":
        raise ConfigError("blacklist is incoming only; use 'deny outgoing ...'")

    raw = source_line.text if source_line is not None else " ".join(parts)
    if direction == "outgoing":
        _collect_outgoing(
            verdict,
            rest,
            ctx,
            cfg,
            path,
            lineno=lineno,
            raw=raw,
            source_line=source_line,
        )
        return
    _collect_incoming(
        verdict,
        rest,
        ctx,
        cfg,
        path,
        lineno=lineno,
        raw=raw,
        source_line=source_line,
    )


def _collect_incoming(
    verdict: str,
    rest: list[str],
    ctx: Context,
    cfg: Config,
    path: Path,
    *,
    lineno: int = 0,
    raw: str = "",
    source_line: Optional[SourceLine] = None,
) -> None:
    proto: Optional[str] = None
    dports = ""
    dests = _context_daddrs(ctx)
    if rest:
        tok = rest[0].lower()
        if tok not in PROTO_PORT:
            raise ConfigError(
                "usage: allow|deny incoming PROTO [PORT...]"
            )
        proto = tok
        if len(rest) > 1:
            src_addr, dports = _parse_match_ports(rest[1:])
            if src_addr:
                dests = (src_addr,)
    for iface in _ifaces(ctx):
        p = SemPolicy(
            verdict=verdict,
            direction="incoming",
            proto=proto,
            dests=dests,
            dports=dports,
            interface=iface,
            table=ctx.table,
            family=ctx.family,
            filter_priority=ctx.filter_priority,
            shield=ctx.shield,
            source=str(path),
            lineno=lineno,
            raw=raw,
            note=source_line.note if source_line is not None else "",
        )
        cfg.sem_policy.append(p)
        if source_line is not None:
            source_line.policies.append(p)


def _collect_outgoing(
    verdict: str,
    rest: list[str],
    ctx: Context,
    cfg: Config,
    path: Path,
    *,
    lineno: int = 0,
    raw: str = "",
    source_line: Optional[SourceLine] = None,
) -> None:
    usage = (
        "usage: allow|deny outgoing ip CIDR [CIDR...] [PROTO [PORT...]]..."
    )
    if len(rest) < 2 or rest[0].lower() not in ("ip", "ip6"):
        raise ConfigError(usage)
    i = 1
    cidrs: list[str] = []
    while i < len(rest) and rest[i].lower() not in PROTO_PORT:
        cidrs.append(_parse_cidr(rest[i]))
        i += 1
    if not cidrs:
        raise ConfigError(usage)

    groups: list[tuple[Optional[str], str]] = []
    if i >= len(rest):
        groups.append((None, ""))
    else:
        while i < len(rest):
            proto = rest[i].lower()
            if proto not in PROTO_PORT:
                raise ConfigError(usage)
            i += 1
            port_toks: list[str] = []
            while i < len(rest) and rest[i].lower() not in PROTO_PORT:
                port_toks.append(rest[i])
                i += 1
            dports = _parse_match_ports(port_toks)[1] if port_toks else ""
            groups.append((proto, dports))

    for iface in _ifaces(ctx):
        for cidr in cidrs:
            for proto, dports in groups:
                p = SemPolicy(
                    verdict=verdict,
                    direction="outgoing",
                    proto=proto,
                    dests=(cidr,),
                    dports=dports,
                    interface=iface,
                    table=ctx.table,
                    family=ctx.family,
                    filter_priority=ctx.filter_priority,
                    shield=False,
                    source=str(path),
                    lineno=lineno,
                    raw=raw,
                    note=source_line.note if source_line is not None else "",
                )
                cfg.sem_policy.append(p)
                if source_line is not None:
                    source_line.policies.append(p)


def _split_port_atoms(dports: str) -> tuple[list[str], list[str], bool]:
    """Return (singles, ranges, is_all)."""
    if not dports:
        return [], [], True
    singles: list[str] = []
    ranges: list[str] = []
    for a in port_atoms(dports):
        if "-" in a:
            ranges.append(a)
        else:
            singles.append(a)
    return singles, ranges, False


def _compile_policies(cfg: Config, path: Path) -> None:
    """Emit nft rules: singles before ranges; allow before deny at each level."""
    if not cfg.sem_policy:
        return
    shield_infra_keys: set[str] = set()
    incoming: dict[tuple, list[SemPolicy]] = {}
    outgoing: dict[tuple, list[SemPolicy]] = {}
    for p in cfg.sem_policy:
        if p.direction == "outgoing":
            key = (
                p.family,
                p.table,
                p.filter_priority,
                p.interface or "",
                p.dests[0] if p.dests else "",
            )
            outgoing.setdefault(key, []).append(p)
        else:
            key = (
                p.family,
                p.table,
                p.filter_priority,
                p.interface or "",
                ",".join(p.dests),
                p.shield,
            )
            incoming.setdefault(key, []).append(p)

    order = [0]

    def next_order() -> int:
        order[0] += 1
        return order[0]

    for key, rows in incoming.items():
        family, table, prio, iface, dests_csv, shield = key
        dests = tuple(a for a in dests_csv.split(",") if a)
        _emit_policy_group(
            cfg,
            path,
            rows,
            direction="incoming",
            dests=dests,
            iface=iface or None,
            shield=shield,
            family=family,
            table=table,
            prio=prio,
            next_order=next_order,
            shield_infra_keys=shield_infra_keys,
            compact=cfg.compact,
        )

    out_keys = sorted(
        outgoing,
        key=lambda k: (-_cidr_prefixlen(k[4]), k[4], k[0], k[1], k[2], k[3]),
    )
    for key in out_keys:
        rows = outgoing[key]
        family, table, prio, iface, dest = key
        _emit_policy_group(
            cfg,
            path,
            rows,
            direction="outgoing",
            dests=(dest,) if dest else (),
            iface=iface or None,
            shield=False,
            family=family,
            table=table,
            prio=prio,
            next_order=next_order,
            shield_infra_keys=shield_infra_keys,
            compact=cfg.compact,
        )


def _stmt_bucket(p: SemPolicy) -> int:
    """Lower runs first: singles, then ranges, allow before deny at each level."""
    allow = p.verdict == "accept"
    if p.proto is None:
        return 8 if not allow else 7
    singles, ranges, is_all = _split_port_atoms(p.dports)
    if is_all:
        return 6 if not allow else 5
    if singles and not ranges:
        return 1 if not allow else 0
    # ranges and mixed lists are less specific than a singleton statement
    return 3 if not allow else 2


def _emit_policy_group(
    cfg: Config,
    path: Path,
    rows: list[SemPolicy],
    *,
    direction: str,
    dests: tuple[str, ...],
    iface: Optional[str],
    shield: bool,
    family: str,
    table: str,
    prio: int,
    next_order,
    shield_infra_keys: set[str],
    compact: bool,
) -> None:
    ctx = Context(
        table=table,
        family=family,
        filter_priority=prio,
        shield=shield,
    )
    daddr = _daddr_match(dests, family)
    im_in = _iface_match(iface)
    im_out = _oiface_match(iface)

    names: Optional[dict[str, str]] = None
    if direction == "incoming" and shield:
        names = _ensure_shield_infra(
            ctx, cfg, path, iface, dests, shield_infra_keys
        )

    if compact:
        packed_note = "; ".join(dict.fromkeys(p.note for p in rows if p.note))
        steps = _compact_policy_steps(rows)
        for verdict, proto, dports in steps:
            _emit_compiled_policy(
                cfg,
                path,
                verdict=verdict,
                direction=direction,
                proto=proto,
                dports=dports,
                dests=dests,
                daddr=daddr,
                im_in=im_in,
                im_out=im_out,
                iface=iface,
                family=family,
                table=table,
                prio=prio,
                shield=shield,
                names=names,
                order=next_order(),
                note=packed_note,
            )
            _maybe_sem_wl(
                cfg,
                path,
                verdict=verdict,
                direction=direction,
                proto=proto,
                dports=dports,
                dests=dests,
                iface=iface,
                family=family,
                table=table,
                prio=prio,
                shield=shield,
            )
        return

    ordered = sorted(rows, key=lambda p: (_stmt_bucket(p), p.lineno, p.source))
    for p in ordered:
        dports = p.dports
        if dports:
            dports = format_dports(port_atoms(dports))
        use_dests = p.dests if p.dests else dests
        use_daddr = _daddr_match(use_dests, family) if use_dests != dests else daddr
        _emit_compiled_policy(
            cfg,
            path,
            verdict=p.verdict,
            direction=direction,
            proto=p.proto,
            dports=dports,
            dests=use_dests,
            daddr=use_daddr,
            im_in=im_in,
            im_out=im_out,
            iface=iface,
            family=family,
            table=table,
            prio=prio,
            shield=shield,
            names=names,
            order=next_order(),
            lineno=p.lineno,
            stmt_source=p.source,
            note=p.note,
        )
        _maybe_sem_wl(
            cfg,
            path,
            verdict=p.verdict,
            direction=direction,
            proto=p.proto,
            dports=dports,
            dests=use_dests,
            iface=iface,
            family=family,
            table=table,
            prio=prio,
            shield=shield,
        )


def _maybe_sem_wl(
    cfg: Config,
    path: Path,
    *,
    verdict: str,
    direction: str,
    proto: Optional[str],
    dports: str,
    dests: tuple[str, ...],
    iface: Optional[str],
    family: str,
    table: str,
    prio: int,
    shield: bool,
) -> None:
    if (
        direction == "incoming"
        and verdict == "accept"
        and proto
        and proto in PROTO_PORT
        and dports
    ):
        cfg.sem_wl.append(
            SemWhitelist(
                proto=proto,
                daddrs=dests,
                dports=dports,
                interface=iface,
                table=table,
                family=family,
                filter_priority=prio,
                shield=shield,
                source=str(path),
            )
        )


def _compact_policy_steps(
    rows: list[SemPolicy],
) -> list[tuple[str, Optional[str], str]]:
    singles_allow: dict[str, list[str]] = {}
    singles_deny: dict[str, list[str]] = {}
    ranges_allow: dict[str, list[str]] = {}
    ranges_deny: dict[str, list[str]] = {}
    proto_all_allow: set[str] = set()
    proto_all_deny: set[str] = set()
    traffic_allow = False
    traffic_deny = False

    for p in rows:
        if p.proto is None:
            if p.verdict == "accept":
                traffic_allow = True
            else:
                traffic_deny = True
            continue
        proto = p.proto
        singles, ranges, is_all = _split_port_atoms(p.dports)
        if is_all:
            if p.verdict == "accept":
                proto_all_allow.add(proto)
            else:
                proto_all_deny.add(proto)
            continue
        if p.verdict == "accept":
            singles_allow.setdefault(proto, []).extend(singles)
            ranges_allow.setdefault(proto, []).extend(ranges)
        else:
            singles_deny.setdefault(proto, []).extend(singles)
            ranges_deny.setdefault(proto, []).extend(ranges)

    steps: list[tuple[str, Optional[str], str]] = []
    for proto in _PROTO_ORDER:
        if singles_allow.get(proto):
            steps.append(("accept", proto, format_dports(singles_allow[proto])))
        if singles_deny.get(proto):
            steps.append(("drop", proto, format_dports(singles_deny[proto])))
        if ranges_allow.get(proto):
            steps.append(("accept", proto, format_dports(ranges_allow[proto])))
        if ranges_deny.get(proto):
            steps.append(("drop", proto, format_dports(ranges_deny[proto])))
        if proto in proto_all_allow:
            steps.append(("accept", proto, ""))
        if proto in proto_all_deny:
            steps.append(("drop", proto, ""))
    if traffic_allow:
        steps.append(("accept", None, ""))
    if traffic_deny:
        steps.append(("drop", None, ""))
    return steps


def _emit_compiled_policy(
    cfg: Config,
    path: Path,
    *,
    verdict: str,
    direction: str,
    proto: Optional[str],
    dports: str,
    dests: tuple[str, ...],
    daddr: str,
    im_in: str,
    im_out: str,
    iface: Optional[str],
    family: str,
    table: str,
    prio: int,
    shield: bool,
    names: Optional[dict[str, str]],
    order: int,
    lineno: int = 0,
    stmt_source: str = "",
    note: str = "",
) -> None:
    cfg.tables.add((family, table))
    if proto and dports:
        match = f"{proto} dport {dports} "
        summary = f"{proto} {dports}"
    elif proto:
        match = f"meta l4proto {proto} "
        summary = proto
    else:
        match = ""
        summary = "*"

    action = verdict
    if direction == "outgoing":
        chain = _output_filter_chain(family, table, prio)
        prefix = f"{im_out}{daddr}"
        kind = f"out-{verdict}"
        needs = ((family, table, "filter-out", prio),)
        inner = f"{prefix}{match}"
    elif shield and names:
        chain = names["chain"]
        kind = "shield-accept" if verdict == "accept" else "shield-deny"
        needs = (
            (
                family,
                table,
                "shield",
                prio,
                iface or "",
                ",".join(dests),
            ),
        )
        inner = match
    else:
        chain = _filter_chain(family, table, prio)
        prefix = f"{im_in}{daddr}"
        kind = f"in-{verdict}"
        needs = ((family, table, "filter", prio),)
        inner = f"{prefix}{match}"

    key_parts = [
        kind,
        family,
        table,
        str(prio),
        iface or "",
        ",".join(dests),
        proto or "",
        dports,
        verdict,
    ]
    if lineno:
        key_parts.extend([stmt_source or str(path), str(lineno)])
    key = _rule_key(*key_parts, note=note)
    stmt = (
        f"add rule {family} {table} {chain} "
        f"{inner}{action} {_rule_comment(cfg, key, note=note)}"
    )
    _append_rule(
        cfg,
        DesiredRule(
            key=key,
            kind=kind,
            stmt=stmt,
            needs=needs,
            source=str(path),
            summary=f"{direction} {verdict} {summary}",
            order=order,
            lineno=lineno,
        ),
    )


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
                note=cfg.line_note,
            )
            match = _iface_match(iface) + _daddr_match(daddrs, ctx.family)
            if proto and dports:
                match += f"{proto} dport {dports} "
            elif proto:
                match += f"meta l4proto {proto} "
            stmt = (
                f"add rule {ctx.family} {ctx.table} {chains['post']} "
                f"{match}masquerade {_rule_comment(cfg, key)}"
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
                    note=cfg.line_note,
                )
                prefix = im if use_iface else ""
                stmt = (
                    f"add rule {ctx.family} {ctx.table} {chain} "
                    f"{prefix}{daddr}{proto} dport {dports} "
                    f"redirect to {to_port} {_rule_comment(cfg, key)}"
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
                note=cfg.line_note,
            )
            stmt = (
                f"add rule {ctx.family} {ctx.table} {chains['post']} "
                f"{_daddr_match(daddrs, ctx.family) if daddrs else ''}"
                f"{proto} dport {dports} snat to {to} "
                f"{_rule_comment(cfg, key)}"
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
                note=cfg.line_note,
            )
            stmt = (
                f"add rule {ctx.family} {ctx.table} {chain} "
                f"{body} {_rule_comment(cfg, key)}"
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
                note=cfg.line_note,
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
                f"{inner}{action} {_rule_comment(cfg, key)}"
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
                note=cfg.line_note,
            )
            stmt = (
                f"add rule {ctx.family} {ctx.table} {chain} "
                f"{_iface_match(iface)}{match_expr}{action} "
                f"{_rule_comment(cfg, key)}"
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
