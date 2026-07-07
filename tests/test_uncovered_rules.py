"""Direct coverage for rules that previously had no dedicated test.

Each fixture was verified to fire exactly the intended rule id before being
committed here. Rules covered: AGENT002, CFG000, GHA004, GHA005, GHA006,
GHA007, MCP000, MCP003, MCP004, MCP005, MCP006, MCP008, PKG002.
"""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agentic_risk_scan.scanner import scan_path


def _scan_file(rel_path: str, content: str) -> set[str]:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        result = scan_path(root)
        return {finding.rule_id for finding in result.findings}


class GitHubActionsUncoveredRuleTests(unittest.TestCase):
    def test_gha004_dangerous_shell_on_untrusted_trigger(self) -> None:
        rule_ids = _scan_file(
            ".github/workflows/build.yml",
            """
name: build
on:
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: eval "$USER_INPUT"
""",
        )
        self.assertIn("GHA004", rule_ids)

    def test_gha005_secrets_on_untrusted_trigger(self) -> None:
        rule_ids = _scan_file(
            ".github/workflows/triage.yml",
            """
name: triage
on:
  issue_comment:
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.API_KEY }}"
""",
        )
        self.assertIn("GHA005", rule_ids)

    def test_gha006_self_hosted_runner_on_untrusted_trigger(self) -> None:
        rule_ids = _scan_file(
            ".github/workflows/runner.yml",
            """
name: runner
on:
  pull_request:
jobs:
  run:
    runs-on: self-hosted
    steps:
      - run: echo hello
""",
        )
        self.assertIn("GHA006", rule_ids)

    def test_gha007_id_token_write_on_untrusted_trigger(self) -> None:
        rule_ids = _scan_file(
            ".github/workflows/deploy.yml",
            """
name: deploy
on:
  issue_comment:
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
""",
        )
        self.assertIn("GHA007", rule_ids)


class MCPUncoveredRuleTests(unittest.TestCase):
    def test_mcp000_invalid_json(self) -> None:
        rule_ids = _scan_file(".mcp.json", "{ this is not valid json ")
        self.assertIn("MCP000", rule_ids)

    def test_mcp003_inline_interpreter_execution(self) -> None:
        rule_ids = _scan_file(
            ".mcp.json",
            """
{
  "mcpServers": {
    "inline": {
      "command": "node",
      "args": ["-e", "console.log('hi')"]
    }
  }
}
""",
        )
        self.assertIn("MCP003", rule_ids)

    def test_mcp004_broad_runtime_flag(self) -> None:
        rule_ids = _scan_file(
            ".mcp.json",
            """
{
  "mcpServers": {
    "broad": {
      "command": "my-mcp-server",
      "args": ["--allow-all"]
    }
  }
}
""",
        )
        self.assertIn("MCP004", rule_ids)

    def test_mcp005_executable_from_temporary_path(self) -> None:
        rule_ids = _scan_file(
            ".mcp.json",
            """
{
  "mcpServers": {
    "temp": {
      "command": "/tmp/mcp-server"
    }
  }
}
""",
        )
        self.assertIn("MCP005", rule_ids)

    def test_mcp006_broad_working_directory(self) -> None:
        rule_ids = _scan_file(
            ".mcp.json",
            """
{
  "mcpServers": {
    "rooted": {
      "command": "mcp-server",
      "cwd": "/"
    }
  }
}
""",
        )
        self.assertIn("MCP006", rule_ids)

    def test_mcp008_unpinned_npx_package(self) -> None:
        rule_ids = _scan_file(
            ".mcp.json",
            """
{
  "mcpServers": {
    "unpinned": {
      "command": "npx",
      "args": ["some-mcp-server"]
    }
  }
}
""",
        )
        self.assertIn("MCP008", rule_ids)


class PackageScriptUncoveredRuleTests(unittest.TestCase):
    def test_pkg002_dangerous_non_lifecycle_script(self) -> None:
        rule_ids = _scan_file(
            "package.json",
            """
{
  "scripts": {
    "debug": "eval \\"$CODE\\""
  }
}
""",
        )
        self.assertIn("PKG002", rule_ids)


class AgentConfigUncoveredRuleTests(unittest.TestCase):
    def test_cfg000_invalid_json_settings(self) -> None:
        rule_ids = _scan_file(".claude/settings.json", "{ not valid json ")
        self.assertIn("CFG000", rule_ids)


class AgentInstructionUncoveredRuleTests(unittest.TestCase):
    def test_agent002_zero_width_character(self) -> None:
        # U+200B zero-width space embedded inside an otherwise benign sentence.
        content = "Follow the norm​al review process for every change.\n"
        rule_ids = _scan_file("AGENTS.md", content)
        self.assertIn("AGENT002", rule_ids)


if __name__ == "__main__":
    unittest.main()
