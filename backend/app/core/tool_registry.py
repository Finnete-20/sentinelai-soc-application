from app.tools.url_tool import url_reputation_check

TOOLS = {
    "url_reputation_check": {
        "description": "Checks if a URL is malicious using external reputation signals",
        "function": url_reputation_check,
        "input_schema": {
            "url": "string"
        }
    }
}


def execute_tool(tool_name: str, args: dict):
    if tool_name not in TOOLS:
        raise ValueError(f"Unknown tool: {tool_name}")

    tool = TOOLS[tool_name]
    return tool["function"](**args)