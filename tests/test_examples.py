"""Guard the shipped examples/ fixtures.

These examples are the README's proof: the README quotes their exact scores and
severity counts. Two regressions must never slip through:

1. A safe example scoring above 0 -> a false positive, the exact failure the
   project's design principles warn against.
2. Drift in the unsafe example's counts -> the README's quoted numbers become
   fabrication.

This test pins both directions against real scans of the committed fixtures.
"""

from pathlib import Path
import unittest

from agentic_risk_scan.scanner import scan_path


EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


class SafeExampleTests(unittest.TestCase):
    def test_safe_agent_workflow_scores_zero(self) -> None:
        result = scan_path(EXAMPLES / "safe-agent-workflow")
        self.assertEqual([], result.findings)
        self.assertEqual(0, result.risk_score())

    def test_safe_agent_configs_score_zero(self) -> None:
        result = scan_path(EXAMPLES / "safe-agent-configs")
        self.assertEqual([], result.findings)
        self.assertEqual(0, result.risk_score())


class UnsafeExampleTests(unittest.TestCase):
    def test_unsafe_ai_pr_bot_matches_readme_numbers(self) -> None:
        # The README Example section quotes these exact values. Keep them in sync.
        result = scan_path(EXAMPLES / "unsafe-ai-pr-bot")
        summary = result.summary()
        self.assertEqual(1, summary["critical"])
        self.assertEqual(11, summary["high"])
        self.assertEqual(3, summary["medium"])
        self.assertEqual(1, summary["low"])
        self.assertEqual(16, summary["total"])
        self.assertEqual(4, result.scanned_files)
        self.assertEqual(100, result.risk_score())

    def test_unsafe_agent_configs_flag_expected_rules(self) -> None:
        result = scan_path(EXAMPLES / "unsafe-agent-configs")
        rule_ids = {finding.rule_id for finding in result.findings}
        # Every Codex/Claude/Gemini config rule the example is built to trip.
        for rule_id in (
            "CFG001",
            "CFG002",
            "CFG003",
            "CFG004",
            "CFG005",
            "CFG006",
            "CFG007",
            "CFG008",
            "CFG009",
            "CFG010",
            "CFG011",
            "CFG012",
            "CFG013",
            "CFG014",
        ):
            self.assertIn(rule_id, rule_ids)
        self.assertGreater(result.risk_score(), 0)


if __name__ == "__main__":
    unittest.main()
