from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stderr, redirect_stdout
import json
import unittest
import io

from agentic_risk_scan.cli import main


def run_cli(args: list[str]) -> int:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        return main(args)


def capture_cli(args: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(args)
    return code, stdout.getvalue(), stderr.getvalue()


class CLITests(unittest.TestCase):
    def test_json_output_file_and_fail_on_none(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow = root / ".github" / "workflows" / "agent.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                """
on: [issue_comment]
permissions: write-all
jobs:
  ai:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.comment.body }}"
""",
                encoding="utf-8",
            )
            output = root / "report.json"

            code = run_cli(["scan", str(root), "--format", "json", "--output", str(output), "--fail-on", "none"])
            self.assertEqual(0, code)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertGreaterEqual(payload["summary"]["total"], 1)

    def test_baseline_filters_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            instructions = root / "AGENTS.md"
            instructions.write_text("allowed-tools: *\n", encoding="utf-8")
            baseline = root / "baseline.json"

            first = run_cli(["scan", str(root), "--update-baseline", str(baseline), "--fail-on", "none"])
            second = run_cli(["scan", str(root), "--baseline", str(baseline), "--fail-on", "medium"])

            self.assertEqual(0, first)
            self.assertEqual(0, second)

    def test_config_suppresses_and_sets_fail_on(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            instructions = root / "AGENTS.md"
            instructions.write_text("allowed-tools: *\n", encoding="utf-8")
            config = root / ".agentic-risk-scan.json"
            config.write_text(
                json.dumps(
                    {
                        "fail_on": "medium",
                        "suppressions": [
                            {
                                "rule_id": "AGENT005",
                                "path": "AGENTS.md",
                                "reason": "test suppression",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            code = run_cli(["scan", str(root)])
            self.assertEqual(0, code)

    def test_config_severity_override_changes_fail_threshold(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            instructions = root / "AGENTS.md"
            instructions.write_text("allowed-tools: *\n", encoding="utf-8")
            config = root / ".agentic-risk-scan.json"
            config.write_text(
                json.dumps(
                    {
                        "fail_on": "high",
                        "severity_overrides": {
                            "AGENT005": "high"
                        },
                    }
                ),
                encoding="utf-8",
            )

            code, stdout, _ = capture_cli(["scan", str(root)])
            self.assertEqual(1, code)
            self.assertIn("[HIGH] AGENT005", stdout)

    def test_config_excludes_files_and_disable_rule(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            instructions = root / "AGENTS.md"
            instructions.write_text("allowed-tools: *\n", encoding="utf-8")
            config = root / ".agentic-risk-scan.json"
            config.write_text(
                json.dumps({"exclude": ["AGENTS.md"], "fail_on": "medium"}),
                encoding="utf-8",
            )

            excluded = run_cli(["scan", str(root)])
            disabled = run_cli(["scan", str(root), "--no-config", "--disable-rule", "AGENT005", "--fail-on", "medium"])

            self.assertEqual(0, excluded)
            self.assertEqual(0, disabled)

    def test_init_config_refuses_overwrite(self) -> None:
        with TemporaryDirectory() as tmp:
            config = Path(tmp) / ".agentic-risk-scan.json"

            first = run_cli(["init-config", str(config)])
            second = run_cli(["init-config", str(config)])

            self.assertEqual(0, first)
            self.assertEqual(2, second)

    def test_inline_ignore_suppresses_same_line_finding(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            instructions = root / "AGENTS.md"
            instructions.write_text("allowed-tools: *  # agentic-risk-scan: ignore AGENT005\n", encoding="utf-8")

            ignored = run_cli(["scan", str(root), "--fail-on", "medium"])
            not_ignored = run_cli(["scan", str(root), "--fail-on", "medium", "--no-inline-ignores"])

            self.assertEqual(0, ignored)
            self.assertEqual(1, not_ignored)

    def test_inline_disable_next_line_suppresses_next_line_finding(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            instructions = root / "AGENTS.md"
            instructions.write_text(
                "<!-- agentic-risk-scan: disable-next-line AGENT005 -->\nallowed-tools: *\n",
                encoding="utf-8",
            )

            code = run_cli(["scan", str(root), "--fail-on", "medium"])
            self.assertEqual(0, code)

    def test_github_annotation_format(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            instructions = root / "AGENTS.md"
            instructions.write_text("allowed-tools: *\n", encoding="utf-8")

            code, stdout, _ = capture_cli(["scan", str(root), "--format", "github", "--fail-on", "none"])
            self.assertEqual(0, code)
            self.assertIn("::warning file=AGENTS.md,line=1,title=AGENT005", stdout)

    def test_rules_markdown_format(self) -> None:
        code, stdout, _ = capture_cli(["rules", "--format", "markdown"])

        self.assertEqual(0, code)
        self.assertIn("## GitHub Actions", stdout)
        self.assertIn("| `GHA001` | critical |", stdout)


if __name__ == "__main__":
    unittest.main()
