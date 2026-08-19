"""Reconcile desired config against live nftables."""

from __future__ import annotations

from typing import Optional

from nftconf_app.log import log
from nftconf_app.model import Config, ConflictError, DesiredRule, LiveRule
from nftconf_app.nft import (
    _delete_lives,
    _nft_script,
    _normalize_sig,
    _parse_desired_stmt,
    ensure_needs,
    scan_all_rules,
    scan_live,
)


def _shield_ordered_keys(desired: dict[str, DesiredRule]) -> list[str]:
    """Order shield-chain rules: ct, icmp, policy (by order), drop last."""
    ct, icmp, mid, drop = [], [], [], []
    for k, r in desired.items():
        if r.kind == "shield-ct":
            ct.append(k)
        elif r.kind == "shield-icmp":
            icmp.append(k)
        elif r.kind == "shield-drop":
            drop.append(k)
        elif r.kind.startswith("shield-") and r.kind != "shield-jump":
            mid.append(k)
    mid.sort(key=lambda k: (desired[k].order, k))
    return ct + icmp + mid + drop


def _desired_signature(rule: DesiredRule) -> tuple[str, str, str, str]:
    family, table, chain, body = _parse_desired_stmt(rule.stmt)
    return family, table, chain, _normalize_sig(body)


def find_load_conflicts(
    cfg: Config,
    to_add: set[str],
    desired: dict[str, DesiredRule],
    to_remove: Optional[set[str]] = None,
) -> list[tuple[DesiredRule, LiveRule]]:
    """Foreign/other-owner rules with the same signature in the target chain."""
    if not to_add:
        return []
    removing = to_remove or set()
    tables = {(r.needs[0][0], r.needs[0][1]) for r in desired.values() if r.needs}
    # also from stmt
    for k in to_add:
        f, t, _, _ = _desired_signature(desired[k])
        tables.add((f, t))
    live_all = scan_all_rules(tables)
    by_loc: dict[tuple[str, str, str, str], list[LiveRule]] = {}
    for lr in live_all:
        by_loc.setdefault((lr.family, lr.table, lr.chain, lr.signature), []).append(lr)

    conflicts: list[tuple[DesiredRule, LiveRule]] = []
    for key in sorted(to_add):
        rule = desired[key]
        family, table, chain, sig = _desired_signature(rule)
        for lr in by_loc.get((family, table, chain, sig), []):
            # Same owner+key already present — not a conflict (shouldn't be in to_add)
            if lr.owner == cfg.owner and lr.key == key:
                continue
            # Owned live rule already queued for delete (shield/policy rebuild).
            if lr.owner == cfg.owner and lr.key in removing:
                continue
            # Our other key with identical signature — treat as conflict to force/skip
            conflicts.append((rule, lr))
    return conflicts


def find_unload_conflicts(owner: str, live: dict[str, LiveRule]) -> list[LiveRule]:
    """Foreign rules sharing chains that contain our owned rules."""
    if not live:
        return []
    chains = {(lr.family, lr.table, lr.chain) for lr in live.values()}
    tables = {(f, t) for f, t, _ in chains}
    foreign: list[LiveRule] = []
    for lr in scan_all_rules(tables):
        if (lr.family, lr.table, lr.chain) not in chains:
            continue
        if lr.owner == owner:
            continue
        foreign.append(lr)
    return foreign


def reconcile(
    cfg: Config,
    *,
    dry_run: bool = False,
    force: bool = False,
    no_clobber: bool = False,
) -> tuple[int, int]:
    """Diff desired config against live nft; apply add/remove. Returns (added, removed)."""
    if force and no_clobber:
        raise ConflictError("cannot combine --force and --no-clobber")

    desired = cfg.by_key()
    live = scan_live(owner=cfg.owner)

    desired_keys = set(desired)
    live_keys = set(live)

    to_remove = live_keys - desired_keys
    to_add = desired_keys - live_keys

    # Shield chains need stable order (ct → icmp → policy → drop).
    shield_body = {
        k
        for k, r in desired.items()
        if r.kind.startswith("shield-") and r.kind != "shield-jump"
    }
    live_shield_body = {k for k, lr in live.items() if lr.chain.startswith("nc_sh_")}
    if (to_remove | to_add) & (shield_body | live_shield_body):
        rebuild = shield_body | live_shield_body
        to_remove |= rebuild & live_keys
        to_add |= rebuild & desired_keys

    # Incoming/outgoing policy: first-match order (singles, then ranges, allow>deny).
    for prefix, chain_pfx in (("in-", "nc_in_"), ("out-", "nc_of_")):
        body = {k for k, r in desired.items() if r.kind.startswith(prefix)}
        live_body = {k for k, lr in live.items() if lr.chain.startswith(chain_pfx)}
        if (to_remove | to_add) & (body | live_body):
            rebuild = body | live_body
            to_remove |= rebuild & live_keys
            to_add |= rebuild & desired_keys

    log.debug(
        "reconcile owner=%s desired=%d live=%d to_add=%d to_remove=%d",
        cfg.owner,
        len(desired),
        len(live),
        len(to_add),
        len(to_remove),
    )

    conflicts = find_load_conflicts(cfg, to_add, desired, to_remove)
    skipped_keys: set[str] = set()
    if conflicts:
        for rule, lr in conflicts:
            who = (
                f"nftconf:{lr.owner}:{lr.key}"
                if lr.owner
                else f"foreign handle {lr.handle}"
            )
            msg = (
                f"conflict: {rule.summary} collides with {who} "
                f"in {lr.family}/{lr.table}/{lr.chain}"
            )
            if force:
                log.warning("%s — forcing overwrite", msg)
            elif no_clobber:
                log.warning("%s — skipping (--no-clobber)", msg)
                skipped_keys.add(rule.key)
            else:
                log.error("%s (use -f to overwrite or -n to skip)", msg)
        if not force and not no_clobber:
            raise ConflictError(
                f"{len(conflicts)} conflict(s) with existing nft settings"
            )
        if force:
            # Remove conflicting live rules before we add
            seen_handles: set[tuple[str, str, str, int]] = set()
            dels: list[LiveRule] = []
            for _rule, lr in conflicts:
                h = (lr.family, lr.table, lr.chain, lr.handle)
                if h not in seen_handles:
                    seen_handles.add(h)
                    dels.append(lr)
            _delete_lives(dels, dry_run=dry_run)
        if no_clobber:
            to_add -= skipped_keys

    removed = 0
    if to_remove:
        removed = _delete_lives(
            [live[k] for k in to_remove if k in live],
            dry_run=dry_run,
        )

    added = 0
    if to_add:
        add_rules = [desired[k] for k in sorted(to_add) if k in desired]
        all_needs: list[tuple] = []
        for r in desired.values():
            all_needs.extend(r.needs)
        if not dry_run:
            ensure_needs(all_needs)

        jump = [r for r in add_rules if r.kind == "shield-jump"]
        body_keys = _shield_ordered_keys(
            {
                r.key: r
                for r in add_rules
                if r.kind.startswith("shield-") and r.kind != "shield-jump"
            }
        )
        body = [desired[k] for k in body_keys if k in to_add]
        policy = sorted(
            [
                r
                for r in add_rules
                if r.kind.startswith(("in-", "out-"))
            ],
            key=lambda r: (r.order, r.key),
        )
        other = [
            r
            for r in add_rules
            if not r.kind.startswith("shield-")
            and not r.kind.startswith(("in-", "out-"))
        ]
        ordered = other + policy + jump + body

        stmts = [r.stmt for r in ordered]
        for s in stmts:
            log.debug("%s", s)
        if dry_run:
            for s in stmts:
                log.info("would: %s", s)
            added = len(stmts)
        elif stmts:
            _nft_script("\n".join(stmts) + "\n")
            added = len(stmts)

    if skipped_keys:
        log.info("skipped %d conflicting stmt(s)", len(skipped_keys))
    return added, removed
