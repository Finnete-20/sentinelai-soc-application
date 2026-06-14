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

            mitre = execute_tool(
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
                    "result": mitre
                }
            )

    except Exception:
        pass


def extract_indicators(text):

    emails = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        text
    )

    urls = re.findall(
        r"https?://[^\s]+",
        text
    )

    cves = re.findall(
        r"CVE-\d{4}-\d+",
        text,
        re.IGNORECASE
    )

    return {
        "emails": emails,
        "urls": urls,
        "cves": cves
    }


def run_agent_graph(user_input):

    investigation_log = []

    indicators = extract_indicators(
        user_input
    )

    # ==================================
    # Memory Correlation
    # ==================================

    for email in indicators["emails"]:

        memory = execute_tool(
            "memory_lookup",
            {
                "query": email
            }
        )

        investigation_log.append(
            {
                "tool": "memory_lookup",
                "arguments": {
                    "query": email
                },
                "result": memory
            }
        )

    for url in indicators["urls"]:

        memory = execute_tool(
            "memory_lookup",
            {
                "query": url
            }
        )

        investigation_log.append(
            {
                "tool": "memory_lookup",
                "arguments": {
                    "query": url
                },
                "result": memory
            }
        )

    # ==================================
    # CVE Correlation
    # ==================================

    for cve in indicators["cves"]:

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

    tools = build_openai_tools()

    messages = [
        {
            "role": "user",
            "content": user_input
        }
    ]

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
                "risk_score": 0,
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

                result = json.loads(
                    content
                )

            except Exception:

                result = {
                    "verdict": "suspicious",
                    "confidence": 0.5,
                    "risk_score": 5,
                    "incident_type": "unknown",
                    "reason": str(
                        message.content
                    ),
                    "mitre_findings": [],
                    "cve_findings": []
                }

            # ==========================
            # MITRE COLLECTION
            # ==========================

            mitre_findings = []

            for item in investigation_log:

                if item["tool"] == "mitre_mapper":

                    matches = item[
                        "result"
                    ].get(
                        "matches",
                        []
                    )

                    mitre_findings.extend(
                        matches
                    )

            result[
                "mitre_findings"
            ] = mitre_findings

            # ==========================
            # MEMORY RISK BOOST
            # ==========================

            memory_hits = 0

            for item in investigation_log:

                if item["tool"] == "memory_lookup":

                    memory_hits += (
                        item["result"].get(
                            "matches_found",
                            0
                        )
                    )

            result["risk_score"] = (
                result.get(
                    "risk_score",
                    0
                )
                + min(
                    memory_hits,
                    3
                )
            )

            if result["risk_score"] >= 8:

                result["verdict"] = (
                    "malicious"
                )

            elif result["risk_score"] >= 4:

                result["verdict"] = (
                    "suspicious"
                )

            # ==========================
            # SINGLE REPORT GENERATION
            # ==========================

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
                    "result": report
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
            {
                "role": "assistant",
                "content":
                message.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name":
                            tc.function.name,
                            "arguments":
                            tc.function.arguments
                        }
                    }
                    for tc in message.tool_calls
                ]
            }
        )

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
        "incident_type":
        "system_error",
        "reason":
        "Maximum tool calls exceeded.",
        "investigation_log":
        investigation_log
    }