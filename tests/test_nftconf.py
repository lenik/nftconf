from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from nftconf_app.parse import parse_file
from nftconf_app.i18n import init_i18n


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
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.conf"
            p.write_text(text, encoding="utf-8")
            cfg = parse_file(p)
            self.assertTrue(cfg.shield_wanted)
            self.assertGreaterEqual(len(cfg.rules), 1)
            self.assertTrue(any(r.kind.startswith("nat") or "dnat" in r.kind for r in cfg.rules)
                            or any("dnat" in r.stmt for r in cfg.rules))

    def test_i18n_installs(self) -> None:
        init_i18n("nftconf")
        # builtins._ should exist after install
        import builtins

        self.assertTrue(callable(getattr(builtins, "_", None)))


if __name__ == "__main__":
    unittest.main()
