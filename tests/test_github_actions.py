from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agentic_risk_scan.scanner import scan_path


class TriggerDetectionTests(unittest.TestCase):
    def _events(self, body: str) -> set[str]:
        from agentic_risk_scan.rules.github_actions import detect_events

        return detect_events(body)

    def test_schedule_only_workflow_with_issues_permission_has_no_trigger(self) -> None:
        # `issues: write` under permissions is not a trigger; previously the
        # bare-line pattern fabricated an untrusted trigger for schedule-only
        # workflows (found scanning modelcontextprotocol/servers).
        events = self._events(
            """
name: sweep
on:
  schedule:
    - cron: "0 6 * * *"
  workflow_dispatch:
permissions:
  issues: write
jobs:
  sweep:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        )
        self.assertEqual(set(), events)

    def test_jobs_and_permissions_keys_are_not_events(self) -> None:
        events = self._events(
            """
name: build
on:
  push:
jobs:
  permissions:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
permissions:
  contents: read
"""
        )
        self.assertEqual(set(), events)

    def test_real_untrusted_triggers_still_detected(self) -> None:
        events = self._events(
            """
name: claude
on:
  issue_comment:
    types: [created]
  pull_request_review:
    types: [submitted]
jobs: {}
"""
        )
        self.assertEqual({"issue_comment"}, events)

    def test_inline_list_and_scalar_forms(self) -> None:
        self.assertEqual({"pull_request"}, self._events("on: [pull_request, push]\njobs: {}\n"))
        self.assertEqual({"pull_request"}, self._events("on: pull_request\njobs: {}\n"))
        self.assertEqual({"issue_comment"}, self._events('on: "issue_comment"\njobs: {}\n'))

    def test_nested_event_config_does_not_leak_other_events(self) -> None:
        events = self._events(
            """
on:
  pull_request:
    types: [opened]
    branches: [main]
  workflow_dispatch:
jobs: {}
"""
        )
        self.assertEqual({"pull_request"}, events)


class FailOpenStepTests(unittest.TestCase):
    def _scan(self, body: str) -> set[str]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow = root / ".github" / "workflows" / "w.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(body, encoding="utf-8")
            result = scan_path(root)
            return {finding.rule_id for finding in result.findings}

    def test_install_step_continuing_on_error_is_flagged(self) -> None:
        rule_ids = self._scan(
            """
name: pr-scan
on:
  pull_request:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: install scanner
        run: pip install edge-scanner
        continue-on-error: true
      - name: scan repository
        run: edge-scanner check .
"""
        )
        self.assertIn("GHA009", rule_ids)

    def test_optional_coverage_upload_continuing_on_error_is_not_flagged(self) -> None:
        rule_ids = self._scan(
            """
name: build
on:
  pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: upload coverage
        uses: codecov/codecov-action@b9fd7d16f6d7d1b5d2bec1a2887e65c4b1ae5d0a # v4.5.0
        continue-on-error: true
      - run: make build
"""
        )
        self.assertNotIn("GHA009", rule_ids)

    def test_setup_action_continuing_on_error_is_not_flagged(self) -> None:
        # "latest" contains "test" and "checkout" contains "check": matching
        # must use word boundaries, and setup-* steps are not the hazard.
        rule_ids = self._scan(
            """
name: build
on:
  pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        continue-on-error: true
        with:
          node-version: 22
"""
        )
        self.assertNotIn("GHA009", rule_ids)

    def test_trusted_trigger_verify_step_is_not_flagged(self) -> None:
        rule_ids = self._scan(
            """
name: release
on:
  push:
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: verify artifacts
        run: sha256sum -c checksums.txt
        continue-on-error: true
"""
        )
        self.assertNotIn("GHA009", rule_ids)


class GitHubActionsRuleTests(unittest.TestCase):
    def test_workflow_run_meta_interpolation_is_untrusted(self) -> None:
        # A workflow_run chained workflow runs with write permissions, and the
        # upstream run's branch name / commit message come from the fork.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow = root / ".github" / "workflows" / "post.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                """
name: post-process
on:
  workflow_run:
    workflows: ["ci"]
    types: [completed]
permissions:
  contents: write
jobs:
  act:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.workflow_run.head_branch }}" >> out.txt
      - run: echo "${{ github.event.workflow_run.head_commit.message }}" >> out.txt
""",
                encoding="utf-8",
            )

            result = scan_path(root)
            rule_ids = {finding.rule_id for finding in result.findings}
            self.assertIn("GHA003", rule_ids)

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

