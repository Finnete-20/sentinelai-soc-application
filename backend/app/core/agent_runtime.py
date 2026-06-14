import json
import re

from app.core.llm_client import run_llm
from app.core.tool_registry import TOOLS


MAX_TOOL_CALLS = 10


def build_openai_tools():

    tools = []

    for name, details in TOOLS.items():

        properties = {}

        required = []

        for field in details["input_schema"]:

            properties[field] = {
                "type": "string"
            }

            required.append(field)

        tools.append({
            "type": "function",
            "function": {
                "name": name,
                "description": details["description"],
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required
                }
            }
        })

    return tools


def execute_tool(tool_name, arguments):

    if tool_name not in TOOLS:

        return {
            "error": f"Unknown tool: {tool_name}"
        }

    return TOOLS[tool_name]["function"](
        **arguments
    )


def auto_correlate(
    tool_name,
    tool_result,
    investigation_log
):

    if tool_name == "analyze_email":

        findings = " ".join(
            tool_result.get(
                "findings",
                []
            )
        )

        mitre = execute_tool(
            "mitre_mapper",
            {
                "evidence":
                findings + " phishing impersonation"
            }
        )

        investigation_log.append({
            "tool": "mitre_mapper",
            "arguments": {
                "evidence": findings
            },
            "result": mitre
        })


def run_agent_graph(user_input):

    investigation_log = []

    cves = re.findall(
        r"CVE-\d{4}-\d+",
        user_input,
        re.IGNORECASE
    )

    for cve in cves:

        result = execute_tool(
            "cve_lookup",
            {
                "cve": cve
            }
        )

        investigation_log.append({
            "tool": "cve_lookup",
            "arguments": {
                "cve": cve
            },
            "result": result
        })

    memory = execute_tool(
        "memory_lookup",
        {
            "query":
            user_input[:100]
        }
    )

    investigation_log.append({
        "tool": "memory_lookup",
        "arguments": {
            "query": user_input[:100]
        },
        "result": memory
    })

    tools = build_openai_tools()

    messages = [
        {
            "role": "user",
            "content": user_input
        }
    ]

    tool_calls_count = 0

    while tool_calls_count < MAX_TOOL_CALLS:

        response = run_llm(
            messages=messages,
            tools=tools
        )

        message = response.choices[0].message

        if not message.tool_calls:

            result = json.loads(
                message.content
            )

            report = execute_tool(
                "generate_executive_report",
                {
                    "investigation":
                    result.get(
                        "reason",
                        ""
                    )
                }
            )

            investigation_log.append({
                "tool":
                "generate_executive_report",
                "arguments": {
                    "investigation":
                    result.get(
                        "reason",
                        ""
                    )
                },
                "result": report
            })

            result[
                "executive_summary"
            ] = report[
                "executive_summary"
            ]

            result[
                "investigation_log"
            ] = investigation_log

            return result

        messages.append(message)

        for tool_call in message.tool_calls:

            name = tool_call.function.name

            arguments = json.loads(
                tool_call.function.arguments
            )

            tool_result = execute_tool(
                name,
                arguments
            )

            investigation_log.append({
                "tool": name,
                "arguments": arguments,
                "result": tool_result
            })

            auto_correlate(
                name,
                tool_result,
                investigation_log
            )

            messages.append({
                "role": "tool",
                "tool_call_id":
                tool_call.id,
                "content":
                json.dumps(
                    tool_result
                )
            })

        tool_calls_count += 1

    return {
        "verdict": "suspicious",
        "confidence": 0.5,
        "risk_score": 5,
        "reason":
        "Maximum tool calls exceeded.",
        "investigation_log":
        investigation_log
    }