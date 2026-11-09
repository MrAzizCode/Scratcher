"""Export the current package's advertised MCP schemas for offline reference."""
import argparse
import json
import pathlib
from mcp_client import Client

root = pathlib.Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument("--version", choices=["0.4", "0.5"], default="0.5")
args = parser.parse_args()
with Client(root / f"dist-v{args.version}/ScratcherMCP.exe") as client:
    advertised = client.rpc("tools/list")
    assert len(advertised["tools"]) == {"0.4": 135, "0.5": 146}[args.version]
    (root / f"reports/v{args.version}/mcp-tools.json").write_text(
        json.dumps(advertised, indent=2, ensure_ascii=False), encoding="utf-8")
print(root / f"reports/v{args.version}/mcp-tools.json")
