from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agentic_risk_scan.scanner import scan_path


class GitHubActionsRuleTests(unittest.TestCase):
    def test_detects_pull_request_target_head_checkout(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow = root / ".github" / "workflows" / "agent.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                """
name: ai-pr
on:
  pull_request_target:
permissions:
  contents: write
  pull-requests: write
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
""",
                encoding="utf-8",
            )

            result = scan_path(root)
            rule_ids = {finding.rule_id for finding in result.findings}
            self.assertIn("GHA001", rule_ids)
            self.assertIn("GHA002", rule_ids)
            self.assertIn("GHA003", rule_ids)

    def test_common_words_do_not_trigger_ai_workflow_detection(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow = root / ".github" / "workflows" / "main.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                """
name: main
on:
  issue_comment:
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
""",
                encoding="utf-8",
            )

            result = scan_path(root)
            self.assertNotIn("GHA002", {finding.rule_id for finding in result.findings})

    def test_safe_read_only_workflow_has_no_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow = root / ".github" / "workflows" / "safe.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                """
name: lint
on:
  pull_request:
permissions:
  contents: read
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: python -m unittest discover
""",
                encoding="utf-8",
            )

            result = scan_path(root)
            self.assertEqual([], result.findings)


if __name__ == "__main__":
    unittest.main()

