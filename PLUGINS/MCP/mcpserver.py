import argparse
import os
import sys
import uuid

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(project_root))

from mcp.server import FastMCP
from Lib.configs import BASE_DIR

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    import django

    django.setup()

    uuid_file_path = os.path.join(BASE_DIR, "Docker", "mcp_uuid")
    try:
        with open(uuid_file_path, 'r') as f:
            default_uuid = f.read().strip()
    except FileNotFoundError:
        default_uuid = str(uuid.uuid1()).replace('-', "")[0:16]
        os.makedirs(os.path.dirname(uuid_file_path), exist_ok=True)
        with open(uuid_file_path, 'w') as f:
            f.write(default_uuid)

    parser = argparse.ArgumentParser(description="ASP MCP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=7001, help="Bind port (default: 7001)")
    parser.add_argument("--uuid", default=default_uuid, help=f"UUID path prefix (default: {default_uuid})")
    args = parser.parse_args()

    host = args.host
    port = args.port
    uuid_str = args.uuid

    mcp = FastMCP("ASP-MCP")
    mcp.settings.sse_path = f"/{uuid_str}/sse"
    mcp.settings.message_path = f"/{uuid_str}/messages"
    mcp.settings.host = host
    mcp.settings.port = port
    mcp.settings.transport_security = None

    from PLUGINS.MCP.llmfunc import REGISTERED_MCP_TOOLS

    for tool in REGISTERED_MCP_TOOLS:
        mcp.add_tool(tool)

    print(f"mcp server url: http://{host}:{port}/{uuid_str}/sse")
    mcp.run(transport="sse")
