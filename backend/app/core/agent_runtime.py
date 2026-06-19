import json

from app.core.llm_client import run_llm
from app.core.tool_registry import TOOLS

MAX_TOOL_CALLS = 15


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

        tools.append(
            {
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
            }
        )

    return tools


def execute_tool(tool_name, arguments):

    if tool_name not in TOOLS:
        return {
            "error": f"Unknown tool: {tool_name}"
        }

    try:
        return TOOLS[tool_name]["function"](
            **arguments
        )

    except Exception as e:
        return {
            "error": str(e)
        }


def enforce_cve_risk_logic(result, investigation_log):

    highest_cvss = None
    cve_findings = []

    for entry in investigation_log:

        if entry.get("tool") != "cve_lookup":
            continue

        tool_result = entry.get("result", {})

        cvss = tool_result.get("cvss_score")

        if cvss is None:
            continue

        cve_findings.append(
            {
                "cve": tool_result.get("cve"),
                "severity": tool_result.get("severity"),
                "cvss_score": cvss
            }
        )

        if highest_cvss is None or cvss > highest_cvss:
            highest_cvss = cvss

    if highest_cvss is None:
        return result

    result["cve_findings"] = cve_findings

    if highest_cvss >= 9.0:

        result["verdict"] = "critical"
        result["risk_score"] = max(
            int(result.get("risk_score", 0)),
            95
        )
        result["incident_type"] = "critical_vulnerability"

    elif highest_cvss >= 7.0:

        result["verdict"] = "high"
        result["risk_score"] = max(
            int(result.get("risk_score", 0)),
            80
        )
        result["incident_type"] = "high_risk_vulnerability"

    elif highest_cvss >= 4.0:

        result["verdict"] = "medium"
        result["risk_score"] = max(
            int(result.get("risk_score", 0)),
            55
        )
        result["incident_type"] = "medium_risk_vulnerability"

    return result


def run_agent_graph(user_input):

    investigation_log = []

    messages = [
        {
            "role": "user",
            "content": user_input
        }
    ]

    tools = build_openai_tools()

    tool_calls_count = 0

    while tool_calls_count < MAX_TOOL_CALLS:

        try:

            response = run_llm(
                messages=messages,
                tools=tools
            )

        except Exception as e:

            return {
                "verdict": "error",
                "confidence": 0,
                "incident_type": "system_error",
                "reason": str(e),
                "investigation_log": investigation_log
            }

        message = response.choices[0].message

        if not message.tool_calls:

            try:

                content = (
                    message.content or ""
                ).strip()

                if content.startswith("```"):

                    content = (
                        content
                        .replace("```json", "")
                        .replace("```", "")
                        .strip()
                    )

                result = json.loads(content)

            except Exception:

                return {
                    "verdict": "error",
                    "confidence": 0,
                    "incident_type": "parse_error",
                    "reason": str(message.content),
                    "investigation_log": investigation_log
                }

            result = enforce_cve_risk_logic(
                result,
                investigation_log
            )

            result["investigation_log"] = investigation_log

            return result

        messages.append(
            {
                "role": "assistant",
                "content": message.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments
                        }
                    }
                    for tc in message.tool_calls
                ]
            }
        )

        for tool_call in message.tool_calls:

            tool_name = tool_call.function.name

            try:
                arguments = json.loads(
                    tool_call.function.arguments
                )
            except Exception:
                arguments = {}

            tool_result = execute_tool(
                tool_name,
                arguments
            )

            investigation_log.append(
                {
                    "tool": tool_name,
                    "arguments": arguments,
                    "result": tool_result
                }
            )

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(tool_result)
                }
            )

        tool_calls_count += 1

    return {
        "verdict": "error",
        "confidence": 0,
        "incident_type": "system_error",
        "reason": "Maximum tool calls exceeded.",
        "investigation_log": investigation_log
    }