from app.tools.url_tool import url_reputation_check
from app.tools.cve_tool import cve_lookup
from app.tools.mitre_tool import mitre_mapper
from app.tools.memory_tool import memory_lookup, memory_store
from app.tools.report_tool import generate_executive_report


TOOLS = {
    "url_reputation_check": {
        "description": "Analyze a URL using phishing heuristics and VirusTotal intelligence",
        "function": url_reputation_check,
        "input_schema": {
            "url": "string"
        }
    },

    "cve_lookup": {
        "description": "Lookup vulnerability information for a CVE identifier",
        "function": cve_lookup,
        "input_schema": {
            "cve": "string"
        }
    },

    "mitre_mapper": {
        "description": "Map attacker behavior to MITRE ATT&CK techniques",
        "function": mitre_mapper,
        "input_schema": {
            "evidence": "string"
        }
    },

    "memory_lookup": {
        "description": "Retrieve prior investigation context",
        "function": memory_lookup,
        "input_schema": {
            "query": "string"
        }
    },

    "memory_store": {
        "description": "Store investigation findings for future correlation",
        "function": memory_store,
        "input_schema": {
            "finding": "string"
        }
    },

    "generate_executive_report": {
        "description": "Generate a SOC executive investigation report",
        "function": generate_executive_report,
        "input_schema": {
            "investigation": "string"
        }
    }
}


TOOL_REGISTRY = {
    name: details["function"]
    for name, details in TOOLS.items()
}


def execute_tool(tool_name: str, args: dict):

    if tool_name not in TOOLS:
        raise ValueError(f"Unknown tool: {tool_name}")

    tool = TOOLS[tool_name]

    return tool["function"](**args)