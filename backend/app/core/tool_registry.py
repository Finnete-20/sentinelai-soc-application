from app.tools.url_tool import url_reputation_check

TOOLS = {
    "url_reputation_check": url_reputation_check
}


def run_tool(name: str, args: dict):
    if name not in TOOLS:
        return {"error": f"Unknown tool: {name}"}

    return TOOLS[name](args)