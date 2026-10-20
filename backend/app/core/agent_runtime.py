
import ipaddress
import json
import logging
import math

from app.core.llm_client import run_llm
from app.core.tool_registry import TOOLS


logger = logging.getLogger(__name__)

MAX_TOOL_CALLS = 15

VALID_VERDICTS = {
    "safe",
    "benign",
    "suspicious",
    "malicious",
    "high",
    "critical",
    "error",
}


def build_openai_tools():
    """Convert registered tools into OpenAI function definitions."""
    openai_tools = []

    for name, details in TOOLS.items():
        properties = {
            field: {"type": "string"}
            for field in details["input_schema"]
        }

        openai_tools.append({
            "type": "function",
            "function": {
                "name": name,
                "description": details["description"],
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": list(details["input_schema"].keys()),
                    "additionalProperties": False,
                },
            },
        })

    return openai_tools


def validate_tool_arguments(tool_name, arguments):
    """Validate tool arguments before executing a registered tool."""
    if not isinstance(arguments, dict):
        return False, "Tool arguments must be a JSON object."

    if tool_name == "abuseipdb_lookup":
        ip = arguments.get("ip")

        if not isinstance(ip, str) or not ip.strip():
            return False, "AbuseIPDB requires a valid IP address."

        try:
            parsed_ip = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False, (
                "AbuseIPDB lookup skipped: the supplied indicator "
                "is not a valid IP address. A hostname cannot be "
                "used in place of an IP address."
            )

        if not parsed_ip.is_global:
            return False, (
                "AbuseIPDB lookup skipped: the IP address is not "
                "globally routable."
            )

    return True, None


def execute_tool(tool_name, arguments):
    """Execute a registered tool after validating its arguments."""
    if tool_name not in TOOLS:
        return {
            "error": f"Unknown tool: {tool_name}",
            "status": "error",
            "tool": tool_name,
        }

    valid, error_message = validate_tool_arguments(
        tool_name,
        arguments,
    )

    if not valid:
        return {
            "source": tool_name,
            "error": error_message,
            "status": "error",
            "available": False,
        }

    try:
        result = TOOLS[tool_name]["function"](**arguments)

        if isinstance(result, dict):
            return result

        return {"raw_result": result}

    except Exception as exc:
        logger.exception("Tool execution failed: %s", tool_name)
        return {
            "error": str(exc),
            "status": "error",
            "tool": tool_name,
        }


def identify_indicator(arguments):
    """Identify the primary indicator passed to a tool."""
    for field, indicator_type in (
        ("cve", "cve"),
        ("url", "url"),
        ("ip", "ip"),
        ("domain", "domain"),
        ("email", "email"),
        ("indicator", "unknown"),
    ):
        value = arguments.get(field)
        if value:
            return str(value), indicator_type

    return None, "unknown"


def normalize_tool_evidence(tool_name, arguments, result):
    """Normalize a tool result while retaining its original output."""
    if not isinstance(result, dict):
        result = {"raw_result": result}

    indicator, indicator_type = identify_indicator(arguments)

    failed = (
        bool(result.get("error"))
        or result.get("status") == "error"
    )

    if failed:
        status = "error"
        finding = str(
            result.get("error") or "Tool execution failed."
        )
    else:
        status = "success"
        finding = (
            result.get("finding")
            or result.get("description")
            or result.get("message")
            or result.get("analysis")
            or "Tool returned data; interpretation required."
        )

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "source": tool_name,
        "finding": finding,
        "severity": result.get("severity"),
        "cvss_score": result.get("cvss_score"),
        "confidence": result.get("confidence"),
        "status": status,
        "raw_result": result,
    }


def parse_llm_result(content):
    """Parse the final LLM response and require a JSON object."""
    if not content:
        raise ValueError("The model returned an empty response.")

    content = content.strip()

    if content.startswith("```"):
        lines = content.splitlines()

        if lines and lines[0].startswith("```"):
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        content = "\n".join(lines).strip()

        if content.startswith("json"):
            content = content[4:].strip()

    result = json.loads(content)

    if not isinstance(result, dict):
        raise ValueError(
            "The final model response must be a JSON object."
        )

    return result


def is_valid_score(value, minimum, maximum):
    """Return whether a score is finite, numeric, and within range."""
    if isinstance(value, bool):
        return False

    if not isinstance(value, (int, float)):
        return False

    return math.isfinite(value) and minimum <= value <= maximum


def validate_final_result(result, evidence):
    """
    Validate response structure and add consistency warnings.

    Risk score uses a 0-100 scale.
    Confidence uses a 0-1 scale.

    This function does not infer compromise from CVSS alone and does not
    silently replace a valid model verdict based on keywords.
    """
    warnings = []
    missing = result.get("missing_evidence", [])

    if not isinstance(missing, list):
        missing = [
            "The model returned missing_evidence in an invalid format."
        ]

    verdict = result.get("verdict")

    if (
        not isinstance(verdict, str)
        or verdict.lower() not in VALID_VERDICTS
    ):
        warnings.append("Verdict is missing or unsupported.")
        result["verdict"] = "suspicious"
        missing.append(
            "The model did not return a supported verdict. "
            "The provisional verdict requires analyst review."
        )
    else:
        result["verdict"] = verdict.lower()

    if not is_valid_score(result.get("risk_score"), 0, 100):
        warnings.append(
            "Risk score must be numeric and between 0 and 100."
        )
        result["risk_score"] = 50
        missing.append(
            "Risk score was invalid; 50 is a provisional placeholder, "
            "not a measured risk assessment."
        )

    if not is_valid_score(result.get("confidence"), 0, 1):
        warnings.append(
            "Confidence must be numeric and between 0 and 1."
        )
        result["confidence"] = 0
        missing.append(
            "Confidence was invalid and has been set to zero."
        )

    text_fields = (
        "incident_type",
        "reason",
        "executive_summary",
    )

    for field in text_fields:
        value = result.get(field)

        if not isinstance(value, str) or not value.strip():
            warnings.append(
                f"Required field '{field}' is missing or invalid."
            )

            if field == "reason":
                result[field] = (
                    "The model did not provide a valid rationale. "
                    "Analyst review is required."
                )
            elif field == "executive_summary":
                result[field] = result.get(
                    "reason",
                    "Assessment unavailable.",
                )
            else:
                result[field] = "unknown"

    list_fields = (
        "supporting_evidence",
        "contradictory_evidence",
        "mitre_findings",
        "cve_findings",
        "recommended_actions",
    )

    for field in list_fields:
        if field not in result:
            result[field] = []
        elif not isinstance(result[field], list):
            warnings.append(f"Field '{field}' must be a list.")
            result[field] = []

    failed_tools = [
        item for item in evidence
        if item.get("status") == "error"
    ]

    if failed_tools:
        warnings.append(
            "One or more tools failed. Failed lookups are not clean results."
        )
        missing.append(
            "Some evidence sources could not complete their lookups."
        )

    # CVSS indicates vulnerability severity, not successful exploitation.
    critical_cves = [
        item for item in evidence
        if item.get("indicator_type") == "cve"
        and item.get("status") == "success"
        and is_valid_score(item.get("cvss_score"), 9, 10)
    ]

    if critical_cves and result["verdict"] in {"safe", "benign"}:
        warnings.append(
            "A critical CVSS finding exists. Verify that the rationale "
            "distinguishes vulnerability severity from compromise."
        )

    if (
        result["verdict"] in {"malicious", "high", "critical"}
        and not result["supporting_evidence"]
        and not evidence
    ):
        warnings.append(
            "A high-severity verdict has no recorded supporting evidence."
        )
        missing.append(
            "Independent evidence supporting the high-severity verdict "
            "has not been recorded."
        )

    # Cross-check verdict, risk, confidence, rationale, and evidence.
    # These checks flag inconsistencies; they do not choose a verdict.
    risk = result["risk_score"]
    confidence = result["confidence"]
    verdict = result["verdict"]
    reason = result.get("reason", "")
    reason_text = reason.strip() if isinstance(reason, str) else ""

    high_risk_verdicts = {"malicious", "high", "critical"}
    low_risk_verdicts = {"safe", "benign"}

    if risk >= 80 and verdict in low_risk_verdicts:
        warnings.append(
            "The low-risk verdict conflicts with a very high risk score. "
            "Reconcile the verdict, score, rationale, and evidence."
        )
        missing.append(
            "The verdict and risk score conflict and require analyst review."
        )

    if risk <= 20 and verdict in high_risk_verdicts:
        warnings.append(
            "The high-severity verdict conflicts with a very low risk score. "
            "Reconcile the verdict, score, rationale, and evidence."
        )
        missing.append(
            "The verdict and risk score conflict and require analyst review."
        )

    if risk >= 80 and confidence < 0.25:
        warnings.append(
            "Risk is very high but confidence is very low. "
            "Explain the uncertainty and review whether the score is justified."
        )

    if (
        risk <= 20
        and confidence >= 0.9
        and verdict in high_risk_verdicts
    ):
        warnings.append(
            "The high-severity verdict conflicts with a low risk score "
            "despite high confidence. Review the assessment."
        )

    if confidence >= 0.9 and not evidence:
        warnings.append(
            "Confidence is very high, but no tool evidence was recorded. "
            "Verify the evidence basis or revise confidence."
        )
        missing.append(
            "No tool evidence was recorded to support the confidence level."
        )

    generic_reasons = {
        "assessment based on the recorded investigation results.",
        "investigation completed.",
        "assessment unavailable.",
    }

    if not reason_text or reason_text.casefold() in generic_reasons:
        warnings.append(
            "The rationale is missing or generic. Explain how the evidence "
            "supports the verdict, risk score, and confidence."
        )
        missing.append(
            "A specific rationale connecting the evidence to the assessment is needed."
        )

    if (
        verdict in high_risk_verdicts
        and not result["supporting_evidence"]
        and not evidence
    ):
        warnings.append(
            "A high-severity verdict has no recorded supporting evidence."
        )
        missing.append(
            "Independent evidence supporting the high-severity verdict "
            "has not been recorded."
        )

    # Contradictory evidence should be acknowledged, not silently discarded.
    if result["contradictory_evidence"] and not reason_text:
        warnings.append(
            "Contradictory evidence is present, but the rationale does not "
            "explain how the conflict affects the assessment."
        )

    result["missing_evidence"] = list(dict.fromkeys(missing))
    result["validation_warnings"] = list(dict.fromkeys(warnings))

    if warnings:
        logger.warning(
            "Final response validation warnings: %s",
            result["validation_warnings"],
        )

    return result


def make_error_result(
    incident_type,
    reason,
    investigation_log,
    evidence,
):
    """Return a consistent response when an investigation fails."""
    return {
        "verdict": "error",
        "risk_score": 0,
        "confidence": 0,
        "incident_type": incident_type,
        "reason": reason,
        "executive_summary": reason,
        "supporting_evidence": [],
        "contradictory_evidence": [],
        "missing_evidence": [
            "A complete security assessment was not produced."
        ],
        "recommended_actions": [
            "Review application logs and retry the investigation."
        ],
        "mitre_findings": [],
        "cve_findings": [],
        "investigation_log": investigation_log,
        "evidence": evidence,
        "validation_warnings": [],
    }


def run_agent_graph(user_input):
    """Run the LLM-led investigation and validate the final response."""
    investigation_log = []
    normalized_evidence = []

    messages = [{
        "role": "user",
        "content": user_input,
    }]

    tools = build_openai_tools()
    tool_calls_count = 0

    while True:
        try:
            response = run_llm(
                messages=messages,
                tools=tools,
            )
            message = response.choices[0].message

        except Exception:
            logger.exception("LLM request failed.")

            return make_error_result(
                "system_error",
                "The LLM request failed. Check the application logs.",
                investigation_log,
                normalized_evidence,
            )

        if not message.tool_calls:
            try:
                result = parse_llm_result(message.content)

            except (ValueError, json.JSONDecodeError):
                logger.warning("The LLM returned invalid final JSON.")

                return make_error_result(
                    "parse_error",
                    "The model returned an invalid JSON response.",
                    investigation_log,
                    normalized_evidence,
                )

            result = validate_final_result(
                result,
                normalized_evidence,
            )

            # Keep fields used by the current frontend.
            result["investigation_log"] = investigation_log
            result["evidence"] = normalized_evidence

            return result

        # Preserve the assistant tool-call message for the API conversation.
        messages.append({
            "role": "assistant",
            "content": message.content or "",
            "tool_calls": [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.function.name,
                        "arguments": call.function.arguments,
                    },
                }
                for call in message.tool_calls
            ],
        })

        for tool_call in message.tool_calls:
            if tool_calls_count >= MAX_TOOL_CALLS:
                return make_error_result(
                    "system_error",
                    "Maximum tool calls exceeded.",
                    investigation_log,
                    normalized_evidence,
                )

            tool_calls_count += 1
            tool_name = tool_call.function.name

            try:
                arguments = json.loads(
                    tool_call.function.arguments or "{}"
                )

                if not isinstance(arguments, dict):
                    raise ValueError(
                        "Tool arguments must be a JSON object."
                    )

                # FIX: Preserve the original user input for email analysis.
                # The model may corrupt multiline text when constructing
                # function arguments, so do not trust its reconstructed copy.
                if tool_name == "analyze_email":
                    arguments["email_text"] = user_input

                tool_result = execute_tool(tool_name, arguments)

            except (ValueError, json.JSONDecodeError):
                arguments = {}
                tool_result = {
                    "error": "Invalid JSON tool arguments.",
                    "status": "error",
                    "tool": tool_name,
                }

            evidence = normalize_tool_evidence(
                tool_name,
                arguments,
                tool_result,
            )

            normalized_evidence.append(evidence)

            investigation_log.append({
                "tool": tool_name,
                "arguments": arguments,
                "result": tool_result,
                "status": evidence["status"],
            })

            # The model uses the actual tool output for further reasoning.
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(
                    tool_result,
                    default=str,
                ),
            })
