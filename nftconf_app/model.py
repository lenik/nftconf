"""Data model, errors, and shared helpers for nftconf."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

PRIORITY_NAMES = {
    "raw": -300,
    "mangle": -150,
    "dstnat": -100,
    "filter": 0,
    "security": 50,
    "srcnat": 100,
}

# L4 protos that take a port SPEC
PROTO_PORT = {"tcp", "udp", "sctp", "dccp"}
# Anything acceptable after accept/drop/reject/nat/…
PROTO_ALL = PROTO_PORT | {"icmp", "icmpv6", "ip", "ip6", "any"}

FAMILIES = ("ip", "ip6", "inet", "arp", "bridge", "netdev")

DEFAULT_PID = "/run/nftconf.pid"
DEFAULT_NFTABLES_D = Path("nftables.d")

# nftconf:<owner>:<key>  — one comment per live nft statement (1:1 with DesiredRule)
_COMMENT_RE = re.compile(r'comment\s+"nftconf:([0-9a-f]+):([0-9a-f]+)"')
_HANDLE_LINE = re.compile(r"#\s*handle\s+(\d+)")
_ADD_RULE_RE = re.compile(
    r"^add rule (?P<family>\S+) (?P<table>\S+) (?P<chain>\S+) (?P<body>.*)$"
)


class ConfigError(Exception):
    def __init__(
        self,
        msg: str,
        path: Optional[Path] = None,
        lineno: Optional[int] = None,
    ):
        self.msg = msg
        self.path = path
        self.lineno = lineno
        loc = ""
        if path is not None:
            loc = str(path)
            if lineno is not None:
                loc += f":{lineno}"
            loc += ": "
        super().__init__(f"{loc}{msg}")


class ConflictError(Exception):
    """Existing nft settings conflict with the requested operation."""


def _owner_id(config_path: Path) -> str:
    """Stable ownership id for a top-level config file."""
    return hashlib.sha256(str(config_path.resolve()).encode()).hexdigest()[:12]


def _rule_key(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _comment(owner: str, key: str) -> str:
    return f'comment "nftconf:{owner}:{key}"'


@dataclass(frozen=True)
class DesiredRule:
    """One owned nft statement (1:1 with a live rule comment)."""

    key: str
    kind: str
    stmt: str
    # chains that must exist before apply: (family, table, kind, ...)
    needs: tuple[tuple, ...]
    source: str
    summary: str


@dataclass
class Context:
    table: str = "nftconf"
    family: str = "ip"
    interfaces: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    filter_priority: int = 0
    resolve_iface_addrs: bool = False
    # Defaults for nat … to … (internal / VIP side)
    dest_interfaces: list[str] = field(default_factory=list)
    dest_addresses: list[str] = field(default_factory=list)
    resolve_dest_iface_addrs: bool = False
    # shield on → filter accepts go into drop-default shield chain
    shield: bool = False


@dataclass(frozen=True)
class SemNat:
    """High-level NAT mapping (for convert)."""

    op: str  # nat | dnat
    proto: str
    daddrs: tuple[str, ...]
    dports: str
    to_addr: str
    to_ports: str
    interface: Optional[str]
    table: str
    family: str
    source: str


@dataclass(frozen=True)
class SemWhitelist:
    """High-level whitelist/accept (for convert)."""

    proto: str
    daddrs: tuple[str, ...]
    dports: str
    interface: Optional[str]
    table: str
    family: str
    filter_priority: int
    shield: bool
    source: str


@dataclass
class Config:
    path: Path
    owner: str
    rules: list[DesiredRule] = field(default_factory=list)
    includes: list[Path] = field(default_factory=list)
    # tables/chains referenced (for ensure + live scan)
    tables: set[tuple[str, str]] = field(default_factory=set)
    # shield on seen anywhere in this config tree
    shield_wanted: bool = False
    # High-level rules for `convert`
    sem_nat: list[SemNat] = field(default_factory=list)
    sem_wl: list[SemWhitelist] = field(default_factory=list)

    def by_key(self) -> dict[str, DesiredRule]:
        out: dict[str, DesiredRule] = {}
        for r in self.rules:
            if r.key in out:
                raise ConfigError(
                    f"duplicate logical rule key {r.key} ({r.summary})",
                    path=self.path,
                )
            out[r.key] = r
        return out


@dataclass
class LiveRule:
    owner: Optional[str]  # None = not nftconf-owned
    key: Optional[str]
    family: str
    table: str
    chain: str
    handle: int
    signature: str  # normalized body without comment
    raw: str
