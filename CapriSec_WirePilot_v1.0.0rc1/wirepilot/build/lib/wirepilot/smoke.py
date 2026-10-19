"""A real stdio MCP client for local installation checks; no Claude account needed."""

from __future__ import annotations
import argparse
import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def check(capture=None):
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "wirepilot.server"], env=dict(os.environ)
    )
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as client:
            await client.initialize()
            tools = await client.list_tools()

            async def call(name, args):
                result = await client.call_tool(name, args)
                if result.isError:
                    raise ValueError(str(result.content))
                return result.structuredContent

            health = await call("health_check", {})
            summary = {
                "mcp_initialized": True,
                "tool_count": len(tools.tools),
                "health": health,
            }
            if capture:
                cap = await call("register_capture", {"path": capture})
                report = await call(
                    "investigate_pcap", {"capture_id": cap["capture_id"]}
                )
                summary["investigation"] = {
                    "capture_id": cap["capture_id"],
                    "sha256": cap["sha256"],
                    "packets": report["summary"]["packets"],
                    "findings": report["total_findings"],
                    "coverage": report["coverage"],
                }
            return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", help="Capture path inside WIREPILOT_CAPTURE_ROOT")
    args = parser.parse_args()
    try:
        result = asyncio.run(check(args.capture))
        print(json.dumps(result, indent=2))
        return 0 if result["health"]["status"] == "ready" else 1
    except Exception as exc:
        print(json.dumps({"status": "error", "detail": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
