import requests


def url_reputation_check(url: str):
    # REAL MCP TOOL (external behavior simulation)
    if "malicious" in url:
        return {
            "url": url,
            "risk": "high",
            "verdict": "malicious"
        }

    return {
        "url": url,
        "risk": "low",
        "verdict": "safe"
    }


TOOL_REGISTRY = {
    "url_reputation_check": {
        "description": "Checks if a URL is malicious using external reputation logic",
        "function": url_reputation_check,
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"}
            }
        }
    }
}