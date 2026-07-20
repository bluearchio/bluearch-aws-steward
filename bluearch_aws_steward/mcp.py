from __future__ import annotations

import sys

from bluearch_aws_steward.mcp_server import run_mcp_stdio_server


def main() -> int:
    try:
        return run_mcp_stdio_server()
    except KeyboardInterrupt:
        print("BlueArch AWS Steward MCP server stopped.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
