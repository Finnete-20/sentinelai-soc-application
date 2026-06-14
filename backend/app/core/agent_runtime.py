import json

from app.core.llm_client import run_llm
from app.core.tool_registry import TOOLS


MAX_TOOL_CALLS = 10


def build_openai_tools():

    openai_tools = []

    for name, details in TOOLS.items():

        properties = {}

        required = []

        for field_name in details["input_schema"]:

            properties[field_name] = {
                "type": "string"
            }

            required.append(field_name)

        openai_tools.append(
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

    return openai_tools


def execute_tool(tool_name, arguments):

    if tool_name not in TOOLS:

        return {
            "error": f"Unknown tool: {tool_name}"
        }

    tool = TOOLS[tool_name]

    fn = tool["function"]

    try:

        return fn(**arguments)

    except Exception as e:

        return {
            "error": str(e)
        }


def auto_correlate(
    tool_name,
    tool_result,
    investigation_log
):

    try:

        # ==================================
        # Email investigations
        # ==================================

        if tool_name == "analyze_email":

            verdict = tool_result.get(
                "verdict",
                ""
            )

            findings = " ".join(
                tool_result.get(
                    "findings",
                    []
                )
            )

            if verdict in [
                "suspicious",
                "malicious"
            ]:

                mitre_result = execute_tool(
                    "mitre_mapper",
                    {
                        "evidence": (
                            findings +
                            " phishing"
                        )
                    }
                )

                investigation_log.append(
                    {
                        "tool": "mitre_mapper",
                        "arguments": {
                            "evidence": findings
                        },
                        "result": mitre_result
                    }
                )

        # ==================================
        # URL investigations
        # ==================================

        if tool_name == "url_reputation_check":

            verdict = tool_result.get(
                "verdict",
                ""
            )

            if verdict in [
                "suspicious",
                "malicious"
            ]:

                mitre_result = execute_tool(
                    "mitre_mapper",
                    {
                        "evidence": "phishing"
                    }
                )

                investigation_log.append(
                    {
                        "tool": "mitre_mapper",
                        "arguments": {
                            "evidence": "phishing"
                        },
                        "result": mitre_result
                    }
                )

    except Exception:
        pass


def run_agent_graph(user_input):

    tools = build_openai_tools()

    messages = [
        {
            "role": "user",
            "content": user_input
        }
    ]

    investigation_log = []

    tool_calls_count = 0

    while tool_calls_count < MAX_TOOL_CALLS:

        response = run_llm(
            messages=messages,
            tools=tools
        )

        message = response.choices[0].message

        if not message.tool_calls:

            content = message.content

            try:

                result = json.loads(
                    content
                )

                # ==========================
                # Memory correlation
                # ==========================

                memory_result = execute_tool(
                    "memory_lookup",
                    {
                        "query": user_input
                    }
                )

                investigation_log.append(
                    {
                        "tool": "memory_lookup",
                        "arguments": {
                            "query": user_input
                        },
                        "result": memory_result
                    }
                )

                # ==========================
                # Store findings
                # ==========================

                if result.get(
                    "verdict"
                ) in [
                    "suspicious",
                    "malicious"
                ]:

                    finding = (
                        f"{result.get('verdict')} "
                        f"{result.get('incident_type', 'incident')} "
                        f"detected: "
                        f"{user_input[:300]}"
                    )

                    memory_store_result = (
                        execute_tool(
                            "memory_store",
                            {
                                "finding": finding
                            }
                        )
                    )

                    investigation_log.append(
                        {
                            "tool": "memory_store",
                            "arguments": {
                                "finding": finding
                            },
                            "result": (
                                memory_store_result
                            )
                        }
                    )

                # ==========================
                # Executive report
                # ==========================

                report_result = execute_tool(
                    "generate_executive_report",
                    {
                        "investigation":
                        result.get(
                            "reason",
                            ""
                        )
                    }
                )

                investigation_log.append(
                    {
                        "tool":
                        "generate_executive_report",
                        "arguments": {
                            "investigation":
                            result.get(
                                "reason",
                                ""
                            )
                        },
                        "result": report_result
                    }
                )

                result[
                    "executive_summary"
                ] = report_result.get(
                    "executive_summary",
                    ""
                )

                result[
                    "investigation_log"
                ] = investigation_log

                return result

            except Exception:

                return {
                    "verdict": "suspicious",
                    "confidence": 0.5,
                    "risk_score": 5,
                    "reason": content,
                    "investigation_log":
                    investigation_log
                }

        messages.append(message)

        for tool_call in message.tool_calls:

            tool_name = (
                tool_call.function.name
            )

            arguments = json.loads(
                tool_call.function.arguments
            )

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

            auto_correlate(
                tool_name,
                tool_result,
                investigation_log
            )

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id":
                    tool_call.id,
                    "content": json.dumps(
                        tool_result
                    )
                }
            )

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