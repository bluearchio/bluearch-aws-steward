from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from bluearch_aws_steward.cli import main
from bluearch_aws_steward.mcp_install import (
    MCP_SERVER_NAME,
    install_mcp_clients,
    native_add_command,
    native_remove_command,
    resolve_mcp_clients,
    uninstall_mcp_clients,
)


class McpInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = {
            "mcpServers": {
                MCP_SERVER_NAME: {
                    "command": "/opt/bluearch/bin/bluearch-steward-mcp",
                    "args": [],
                    "env": {
                        "PYTHONUNBUFFERED": "1",
                        "AWS_SDK_LOAD_CONFIG": "1",
                    },
                }
            }
        }

    def test_cursor_install_preserves_other_servers_and_creates_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory)
            config_path = home / ".cursor" / "mcp.json"
            config_path.parent.mkdir(parents=True)
            config_path.write_text(
                json.dumps({"mcpServers": {"existing": {"command": "existing"}}}),
                encoding="utf-8",
            )

            result = install_mcp_clients(["cursor"], self.config, home=home)

            payload = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertIn("existing", payload["mcpServers"])
            self.assertEqual(
                payload["mcpServers"][MCP_SERVER_NAME]["command"],
                "/opt/bluearch/bin/bluearch-steward-mcp",
            )
            self.assertTrue(Path(result[0]["backup_path"]).is_file())

    def test_cursor_uninstall_preserves_other_servers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory)
            config_path = home / ".cursor" / "mcp.json"
            config_path.parent.mkdir(parents=True)
            config_path.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            MCP_SERVER_NAME: {"command": "steward"},
                            "existing": {"command": "existing"},
                        }
                    }
                ),
                encoding="utf-8",
            )

            result = uninstall_mcp_clients(["cursor"], home=home)

            payload = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertNotIn(MCP_SERVER_NAME, payload["mcpServers"])
            self.assertIn("existing", payload["mcpServers"])
            self.assertEqual(result[0]["status"], "removed")

    def test_cursor_dry_run_does_not_write_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory)

            result = install_mcp_clients(["cursor"], self.config, home=home, dry_run=True)

            self.assertEqual(result[0]["status"], "planned")
            self.assertFalse((home / ".cursor" / "mcp.json").exists())

    def test_all_selects_only_detected_clients(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory)
            home.joinpath(".cursor").mkdir()

            clients = resolve_mcp_clients(
                ["all"],
                home=home,
                executable_finder=lambda name: f"/usr/bin/{name}" if name == "codex" else None,
            )

            self.assertEqual(clients, ["codex", "cursor"])

    def test_all_cannot_be_combined_with_an_explicit_client(self) -> None:
        with self.assertRaisesRegex(ValueError, "all by itself"):
            resolve_mcp_clients(["all", "codex"])

    def test_native_commands_use_user_scope_and_safe_environment(self) -> None:
        server = self.config["mcpServers"][MCP_SERVER_NAME]

        codex = native_add_command("codex", "/usr/bin/codex", server)
        claude = native_add_command("claude", "/usr/bin/claude", server)

        self.assertEqual(codex[:4], ["/usr/bin/codex", "mcp", "add", MCP_SERVER_NAME])
        self.assertIn("AWS_SDK_LOAD_CONFIG=1", codex)
        self.assertNotIn("AWS_PROFILE", " ".join(codex))
        self.assertEqual(
            claude[:6],
            ["/usr/bin/claude", "mcp", "add", MCP_SERVER_NAME, "--scope", "user"],
        )
        self.assertEqual(
            native_remove_command("claude", "/usr/bin/claude"),
            ["/usr/bin/claude", "mcp", "remove", MCP_SERVER_NAME, "--scope", "user"],
        )

    def test_cli_dry_run_is_non_interactive_and_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory)
            output = StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "mcp",
                        "install",
                        "--client",
                        "cursor",
                        "--runtime",
                        "uvx",
                        "--dry-run",
                    ]
                )

            self.assertEqual(result, 0)
            self.assertIn("cursor", output.getvalue())
            self.assertFalse((home / ".cursor" / "mcp.json").exists())


if __name__ == "__main__":
    unittest.main()
