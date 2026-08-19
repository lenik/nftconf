from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from nftconf_app.parse import parse_file
from nftconf_app.i18n import init_i18n
from nftconf_app.model import ConfigError, format_dports, normalize_port_atom, port_atoms
from nftconf_app.render import _render_nftables


def _parse_text(text: str):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "t.conf"
        p.write_text(text, encoding="utf-8")
        return parse_file(p)


class ParseTests(unittest.TestCase):
    def test_nat_and_whitelist_context(self) -> None:
        text = """
table demo
address 10.0.0.1
dest address 10.0.0.2
shield on
nat tcp 8080 to 8080
whitelist tcp 22
"""
        cfg = _parse_text(text)
        self.assertTrue(cfg.shield_wanted)
        self.assertGreaterEqual(len(cfg.rules), 1)
        self.assertTrue(
            any(r.kind.startswith("nat") or "dnat" in r.kind for r in cfg.rules)
            or any("dnat" in r.stmt for r in cfg.rules)
        )

    def test_i18n_installs(self) -> None:
        init_i18n("nftconf")
        import builtins

        self.assertTrue(callable(getattr(builtins, "_", None)))


class PortAtomTests(unittest.TestCase):
    def test_normalize_single_and_range(self) -> None:
        self.assertEqual(normalize_port_atom("80"), "80")
        self.assertEqual(normalize_port_atom("0080"), "80")
        self.assertEqual(normalize_port_atom("8000-8080"), "8000-8080")
        self.assertEqual(normalize_port_atom("22-22"), "22")

    def test_normalize_rejects_bad_ranges(self) -> None:
        with self.assertRaises(ConfigError):
            normalize_port_atom("8080-8000")
        with self.assertRaises(ConfigError):
            normalize_port_atom("65536")
        with self.assertRaises(ConfigError):
            normalize_port_atom("http")

    def test_format_dports_scalar_range_set(self) -> None:
        self.assertEqual(format_dports(["443", "80"]), "{ 80, 443 }")
        self.assertEqual(format_dports(["80"]), "80")
        self.assertEqual(
            format_dports(["8000-8080", "80", "443", "1080"]),
            "{ 80, 443, 1080, 8000-8080 }",
        )

    def test_port_atoms_roundtrip(self) -> None:
        expr = "{ 80, 443, 1080, 8000-8080 }"
        self.assertEqual(port_atoms(expr), ["80", "443", "1080", "8000-8080"])
        self.assertEqual(port_atoms("22"), ["22"])


class PortListParseTests(unittest.TestCase):
    def test_whitelist_port_list_and_range(self) -> None:
        cfg = _parse_text(
            """
address 10.0.0.1
whitelist tcp 80 443 1080 8000-8080
"""
        )
        stmts = "\n".join(r.stmt for r in cfg.rules)
        # Singles and ranges are separate matches (single port beats a range).
        self.assertIn("tcp dport { 80, 443, 1080 }", stmts)
        self.assertIn("tcp dport 8000-8080", stmts)
        self.assertTrue(cfg.sem_wl)

    def test_whitelist_comma_separated(self) -> None:
        cfg = _parse_text("address 10.0.0.1\nwhitelist tcp 80,443,1080,8000-8080\n")
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertIn("tcp dport { 80, 443, 1080 }", stmts)
        self.assertIn("tcp dport 8000-8080", stmts)

    def test_single_port_has_no_set_braces(self) -> None:
        cfg = _parse_text("address 10.0.0.1\nwhitelist tcp 22\n")
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertIn("tcp dport 22 ", stmts)
        self.assertNotIn("{", stmts)

    def test_single_range_has_no_set_braces(self) -> None:
        cfg = _parse_text("address 10.0.0.1\naccept udp 60000-61000\n")
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertIn("udp dport 60000-61000 ", stmts)
        self.assertNotIn("{", stmts)

    def test_addr_prefix_applies_to_following_ports(self) -> None:
        cfg = _parse_text("whitelist tcp 192.0.2.10:80 443\n")
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertIn("ip daddr 192.0.2.10 ", stmts)
        self.assertIn("tcp dport { 80, 443 }", stmts)

    def test_conflicting_addresses_rejected(self) -> None:
        with self.assertRaises(ConfigError) as cm:
            _parse_text("whitelist tcp 192.0.2.10:80 192.0.2.11:443\n")
        self.assertIn("conflicting match addresses", str(cm.exception))

    def test_reject_with_port_list(self) -> None:
        cfg = _parse_text("address 10.0.0.1\nreject tcp 25 587 with tcp reset\n")
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertIn("tcp dport { 25, 587 }", stmts)
        self.assertIn("reject with tcp reset", stmts)

    def test_nat_port_list_one_to_one(self) -> None:
        cfg = _parse_text(
            """
address 10.0.0.1
dest address 10.0.0.2
nat tcp 80 443 8000-8080 to 10.0.0.2
"""
        )
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertIn("tcp dport { 80, 443, 8000-8080 } dnat to 10.0.0.2", stmts)
        self.assertTrue(any("snat to 10.0.0.1" in r.stmt for r in cfg.rules))

    def test_dnat_port_list(self) -> None:
        cfg = _parse_text(
            """
address 10.0.0.1
dnat udp 53 5353 to 10.0.0.53
"""
        )
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertIn("udp dport { 53, 5353 } dnat to 10.0.0.53", stmts)

    def test_masquerade_port_list(self) -> None:
        cfg = _parse_text("masquerade tcp 80 443\n")
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertIn("tcp dport { 80, 443 } masquerade", stmts)

    def test_redirect_port_list(self) -> None:
        cfg = _parse_text("redirect tcp 80 443 to 8080\n")
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertIn("tcp dport { 80, 443 } redirect to 8080", stmts)

    def test_invalid_port_errors(self) -> None:
        with self.assertRaises(ConfigError):
            _parse_text("whitelist tcp 80-20\n")
        with self.assertRaises(ConfigError):
            _parse_text("whitelist tcp 99999\n")
        with self.assertRaises(ConfigError):
            _parse_text("whitelist tcp ssh\n")

    def test_convert_expands_whitelist_port_list(self) -> None:
        cfg = _parse_text(
            """
address 203.0.113.10
whitelist tcp 80 443 1080 8000-8080
"""
        )
        out = _render_nftables(cfg)
        self.assertIn(
            "define whitelist_ports = { 80, 443, 1080, 8000-8080 }", out
        )
        self.assertIn("tcp dport $whitelist_ports accept", out)

    def test_shield_whitelist_port_list(self) -> None:
        cfg = _parse_text(
            """
address 10.0.0.1
shield on
whitelist tcp 80 443 1080 8000-8080
"""
        )
        inner = [r.stmt for r in cfg.rules if r.kind == "shield-accept"]
        self.assertTrue(inner)
        joined = "\n".join(inner)
        self.assertIn("tcp dport { 80, 443, 1080 }", joined)
        self.assertIn("tcp dport 8000-8080", joined)
        self.assertNotRegex(inner[0], r"nc_sh_\S+\s+ip daddr")


class AllowDenyPolicyTests(unittest.TestCase):
    def _stmt_kinds(self, cfg) -> list[tuple[int, str, str]]:
        return [
            (r.order, r.kind, r.stmt)
            for r in cfg.rules
            if r.kind.startswith(("in-", "out-", "shield-accept", "shield-deny"))
        ]

    def test_simple_port_beats_range_deny_33(self) -> None:
        cfg = _parse_text(
            """
allow incoming tcp 10-100
deny incoming tcp 33
"""
        )
        kinds = self._stmt_kinds(cfg)
        kinds.sort()
        self.assertEqual(kinds[0][1], "in-drop")
        self.assertIn("tcp dport 33 drop", kinds[0][2])
        self.assertEqual(kinds[1][1], "in-accept")
        self.assertIn("tcp dport 10-100 accept", kinds[1][2])

    def test_same_range_allow_beats_deny(self) -> None:
        cfg = _parse_text(
            """
allow incoming tcp 10-100
deny incoming tcp 10-100
"""
        )
        kinds = self._stmt_kinds(cfg)
        kinds.sort()
        self.assertEqual(kinds[0][1], "in-accept")
        self.assertIn("tcp dport 10-100 accept", kinds[0][2])
        self.assertEqual(kinds[1][1], "in-drop")
        self.assertIn("tcp dport 10-100 drop", kinds[1][2])

    def test_same_simple_port_allow_beats_deny(self) -> None:
        cfg = _parse_text(
            """
deny incoming tcp 80
allow incoming tcp 80
"""
        )
        kinds = self._stmt_kinds(cfg)
        kinds.sort()
        self.assertEqual(kinds[0][1], "in-accept")
        self.assertIn("tcp dport 80 accept", kinds[0][2])
        self.assertEqual(kinds[1][1], "in-drop")

    def test_outgoing_cidr_all_traffic(self) -> None:
        cfg = _parse_text("allow outgoing ip 1.2.3.4/24\n")
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertTrue(any(r.kind == "out-accept" for r in cfg.rules))
        self.assertIn("ip daddr 1.2.3.0/24", stmts)
        self.assertNotIn("dport", stmts)
        self.assertIn("nc_of_", stmts)

    def test_outgoing_tcp_ports_then_all_deny(self) -> None:
        cfg = _parse_text(
            """
allow outgoing ip 10.0.0.0/8 tcp 443
deny outgoing ip 10.0.0.0/8
"""
        )
        kinds = [(r.order, r.kind, r.stmt) for r in cfg.rules if r.kind.startswith("out-")]
        kinds.sort()
        self.assertIn("tcp dport 443 accept", kinds[0][2])
        self.assertEqual(kinds[1][1], "out-drop")
        self.assertNotIn("dport", kinds[1][2])

    def test_outgoing_longer_prefix_first(self) -> None:
        cfg = _parse_text(
            """
allow outgoing ip 10.0.0.0/8 tcp 10-100
deny outgoing ip 10.1.2.3 tcp 33
"""
        )
        kinds = [(r.order, r.kind, r.stmt) for r in cfg.rules if r.kind.startswith("out-")]
        kinds.sort()
        self.assertIn("10.1.2.3/32", kinds[0][2])
        self.assertIn("tcp dport 33 drop", kinds[0][2])
        self.assertIn("10.0.0.0/8", kinds[1][2])

    def test_blacklist_alias(self) -> None:
        cfg = _parse_text("blacklist tcp 25\n")
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertIn("tcp dport 25 drop", stmts)

    def test_policy_keys_stable_across_other_scope(self) -> None:
        """Adding rules in one shield scope must not change keys in another."""
        base = """
address 10.0.0.1
shield on
allow incoming tcp 22
address 10.0.0.2
shield on
allow incoming tcp 80
"""
        extra = base + "address 10.0.0.1\nallow incoming tcp 33\n"
        k80_a = [r.key for r in _parse_text(base).rules if "dport 80" in r.stmt]
        k80_b = [r.key for r in _parse_text(extra).rules if "dport 80" in r.stmt]
        self.assertTrue(k80_a)
        self.assertEqual(k80_a, k80_b)

    def test_allow_incoming_udp_list(self) -> None:
        cfg = _parse_text("allow incoming udp 53 5353 60000-61000\n")
        stmts = "\n".join(r.stmt for r in cfg.rules)
        self.assertIn("udp dport { 53, 5353 }", stmts)
        self.assertIn("udp dport 60000-61000", stmts)


if __name__ == "__main__":
    unittest.main()
