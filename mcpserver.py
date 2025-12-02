import os
import sys
import uuid

# Add the project root directory to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from mcp.server import FastMCP

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASF.settings")
    import django

    django.setup()
    from Lib.llmfunc import function_call_debug, get_case_by_case_id

    # Define UUID file path
    uuid_file_path = os.path.join("..", "Docker", "mcp_uuid")
    # Try to read UUID from file
    try:
        with open(uuid_file_path, 'r') as f:
            uuid_str = f.read().strip()
    except FileNotFoundError:
        # If file doesn't exist, generate new UUID and save it
        uuid_str = str(uuid.uuid1()).replace('-', "")[0:16]
        os.makedirs(os.path.dirname(uuid_file_path), exist_ok=True)
        with open(uuid_file_path, 'w') as f:
            f.write(uuid_str)

    mcp = FastMCP("ASF-MCP")
    host = "0.0.0.0"
    port = 7001
    mcp.settings.sse_path = f"/{uuid_str}/sse"
    mcp.settings.message_path = f"/{uuid_str}/messages"

    mcp.settings.host = host
    mcp.settings.port = port

    # add tools
    mcp.add_tool(function_call_debug)
    mcp.add_tool(get_case_by_case_id)
    print(f"mcp server url: http://your_server_ip:{port}/{uuid_str}/sse")
    mcp.run(transport="sse")
