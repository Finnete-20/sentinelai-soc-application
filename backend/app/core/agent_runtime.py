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


def auto_correlate(
    tool_name,
    tool_result,
    investigation_log
):

    try:

        if tool_name == "analyze_email":

            findings = " ".join(
                tool_result.get(
                    "findings",
                    []
                )
            )

            mitre_result = execute_tool(
                "mitre_mapper",
                {
                    "evidence":
                    findings +
                    " phishing impersonation"
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

        elif tool_name == "url_reputation_check":

            if tool_result.get(
                "verdict"
            ) in [
                "suspicious",
                "malicious"
            ]:

                mitre_result = execute_tool(
                    "mitre_mapper",
                    {
                        "evidence":
                        "phishing malicious url"
                    }
                )

                investigation_log.append(
                    {
                        "tool": "mitre_mapper",
                        "arguments": {
                            "evidence":
                            "phishing malicious url"
                        },
                        "result": mitre_result
                    }
                )

    except Exception:
        pass


def extract_indicator_for_memory(
    text
):

    emails = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        text
    )

    if emails:
        return emails[0]

    urls = re.findall(
        r"https?://[^\s]+",
        text
    )

    if urls:
        return urls[0]

    cves = re.findall(
        r"CVE-\d{4}-\d+",
        text,
        re.IGNORECASE
    )

    if cves:
        return cves[0]

    ips = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    )

    if ips:
        return ips[0]

    return text[:50]


def run_agent_graph(
    user_input
):

    investigation_log = []

    # =====================================
    # CVE AUTO LOOKUP
    # =====================================

    cve_findings = []

    cves = re.findall(
        r"CVE-\d{4}-\d+",
        user_input,
        re.IGNORECASE
    )

    for cve in cves:

        cve_result = execute_tool(
            "cve_lookup",
            {
                "cve": cve
            }
        )

        investigation_log.append(
            {
                "tool": "cve_lookup",
                "arguments": {
                    "cve": cve
                },
                "result": cve_result
            }
        )

        cve_findings.append(
            cve_result
        )

    # =====================================
    # MEMORY CORRELATION
    # =====================================

    indicator = (
        extract_indicator_for_memory(
            user_input
        )
    )

    memory_result = execute_tool(
        "memory_lookup",
        {
            "query": indicator
        }
    )

    investigation_log.append(
        {
            "tool": "memory_lookup",
            "arguments": {
                "query": indicator
            },
            "result": memory_result
        }
    )

    # =====================================
    # LLM EXECUTION
    # =====================================

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

        message = (
            response.choices[0].message
        )

        # =====================================
        # FINAL RESPONSE
        # =====================================

        if not message.tool_calls:

            try:

                content = (
                    message.content
                    .replace("```json", "")
                    .replace("```", "")
                    .strip()
                )

                result = json.loads(
                    content
                )

            except Exception:

                return {
                    "verdict":
                    "suspicious",
                    "confidence":
                    0.5,
                    "risk_score":
                    5,
                    "reason":
                    f"Failed to parse model JSON: {message.content}",
                    "investigation_log":
                    investigation_log
                }

            # =====================================
            # MITRE FINDINGS
            # =====================================

            mitre_findings = []

            for item in investigation_log:

                if (
                    item["tool"]
                    == "mitre_mapper"
                ):

                    mitre_findings.extend(
                        item["result"].get(
                            "matches",
                            []
                        )
                    )

            result[
                "mitre_findings"
            ] = mitre_findings

            result[
                "cve_findings"
            ] = cve_findings

            # =====================================
            # MEMORY STORE
            # =====================================

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
                    f"{indicator}"
                )

                memory_store_result = (
                    execute_tool(
                        "memory_store",
                        {
                            "finding":
                            finding
                        }
                    )
                )

                investigation_log.append(
                    {
                        "tool":
                        "memory_store",
                        "arguments": {
                            "finding":
                            finding
                        },
                        "result":
                        memory_store_result
                    }
                )

            # =====================================
            # REPORT GENERATION
            # =====================================

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
                    "result":
                    report
                }
            )

            result[
                "executive_summary"
            ] = report.get(
                "executive_summary",
                ""
            )

            result[
                "investigation_log"
            ] = investigation_log

            return result

        messages.append(
            message
        )

        # =====================================
        # TOOL CALLS
        # =====================================

        for tool_call in message.tool_calls:

            tool_name = (
                tool_call.function.name
            )

            arguments = json.loads(
                tool_call.function.arguments
            )

            # Prevent duplicate report generation

            if (
                tool_name
                == "generate_executive_report"
            ):
                continue

            tool_result = execute_tool(
                tool_name,
                arguments
            )

            investigation_log.append(
                {
                    "tool":
                    tool_name,
                    "arguments":
                    arguments,
                    "result":
                    tool_result
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
                    "content":
                    json.dumps(
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