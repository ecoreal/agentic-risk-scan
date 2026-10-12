"""Keep the shipped rule registry in sync with docs/rules.md.

`docs/rules.md` is the public rule reference linked from the README and from
every finding's help URI. An undocumented rule (or a doc row for a removed
rule) means users hit 404s or miss capabilities, so pin both directions.
"""

from pathlib import Path
import re
import unittest

from agentic_risk_scan.registry import RULES


DOCS = Path(__file__).resolve().parent.parent / "docs" / "rules.md"


class RuleRegistryDocsTests(unittest.TestCase):
    def test_every_registered_rule_is_documented(self) -> None:
        text = DOCS.read_text(encoding="utf-8")
        documented = set(re.findall(r"`([A-Z]+\d{3})`", text))
        missing = sorted(rule.rule_id for rule in RULES if rule.rule_id not in documented)
        self.assertEqual([], missing, f"rules missing from docs/rules.md: {missing}")

    def test_every_documented_rule_is_registered(self) -> None:
        text = DOCS.read_text(encoding="utf-8")
        known = {rule.rule_id for rule in RULES}
        documented = set(re.findall(r"`([A-Z]+\d{3})`", text))
        extra = sorted(rule_id for rule_id in documented if rule_id not in known)
        self.assertEqual([], extra, f"docs/rules.md documents unregistered rules: {extra}")

    def test_anchor_ids_match_rule_ids(self) -> None:
        # Every row must carry an <a id="..."> anchor matching the lowercase
        # rule id; the registry's help_uri links to exactly those anchors.
        text = DOCS.read_text(encoding="utf-8")
        anchors = set(re.findall(r'<a id="([a-z]+\d{3})"></a>', text))
        expected = {rule.rule_id.lower() for rule in RULES}
        self.assertEqual(sorted(expected), sorted(anchors))


if __name__ == "__main__":
    unittest.main()
