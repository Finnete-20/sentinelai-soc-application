
"""SentinelAI investigation runtime.

Workflow:
Incident
 -> Indicator extraction
 -> LLM-selected evidence collection
 -> Evidence normalization
 -> Evidence correlation
 -> LLM reasoning
 -> Validated final assessment
"""

import ipaddress
import json
import logging
import math

from app.core.llm_client import run_llm
from app.core.tool_registry import TOOLS


logger = logging.getLogger(__name__)

MAX_TOOL_CALLS = 15
MAX_TOOL_ROUNDS = 8

VERDICT_ALIASES = {
    "safe": "benign",
    "high": "critical",
}

VALID_VERDICTS = {
    "malicious",
    "suspicious",
    "benign",
    "critical",
    "error",
}


def build_openai_tools():
    """Convert the internal tool registry into OpenAI tool definitions."""
    definitions = []

    for name, details in TOOLS.items():
        properties = {
            field: {"type": "string"}
            for field in details["input_schema"]
        }

        definitions.append(
            {
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
            }
        )

    return definitions


def identify_indicator(arguments):
    """Identify the primary indicator and its type from tool arguments."""
    for field, indicator_type in (
        ("cve", "cve"),
        ("url", "url"),
        ("ip", "ip"),
        ("domain", "domain"),
        ("email", "email"),
        ("email_text", "email"),
        ("indicator", "unknown"),
    ):
        value = arguments.get(field)

        if value:
            return str(value), indicator_type

    return None, "unknown"


def validate_tool_arguments(tool_name, arguments):
    """Validate tool names, required arguments, and IP lookup inputs."""
    if not isinstance(arguments, dict):
        return False, "Tool arguments must be a JSON object."

    if tool_name not in TOOLS:
        return False, f"Unknown tool: {tool_name}"

    required_fields = TOOLS[tool_name]["input_schema"]

    for field in required_fields:
        value = arguments.get(field)

        if not isinstance(value, str) or not value.strip():
            return False, f"Missing or invalid required argument: {field}"

    if tool_name == "abuseipdb_lookup":
        try:
            parsed_ip = ipaddress.ip_address(arguments["ip"].strip())
        except ValueError:
            return False, "AbuseIPDB requires a valid IP address."

        if not parsed_ip.is_global:
            return False, "AbuseIPDB lookup skipped: IP is not globally routable."

    return True, None


def execute_tool(tool_name, arguments):
    """Execute a registered tool and return structured errors if it fails."""
    if tool_name not in TOOLS:
        return {
            "source": tool_name,
            "status": "error",
            "available": False,
            "error": f"Unknown tool: {tool_name}",
        }

    valid, validation_error = validate_tool_arguments(
        tool_name,
        arguments,
    )

    if not valid:
        return {
            "source": tool_name,
            "status": "error",
            "available": False,
            "error": validation_error,
        }

    try:
        function = TOOLS[tool_name]["function"]
        result = function(**arguments)

        if isinstance(result, dict):
            result.setdefault("source", tool_name)
            return result

        return {
            "source": tool_name,
            "status": "success",
            "available": True,
            "raw_result": result,
        }

    except Exception as exc:
        logger.exception("Tool execution failed: %s", tool_name)

        return {
            "source": tool_name,
            "status": "error",
            "available": False,
            "error": f"{tool_name} execution failed: {type(exc).__name__}",
        }


def _as_list(value):
    """Convert a value to a list without splitting strings into characters."""
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return [value]


def _safe_text(value, default=""):
    """Convert values to safe text for evidence records."""
    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)

    return str(value)


def _first_present(mapping, *keys):
    """Return the first non-empty value found in a dictionary."""
    if not isinstance(mapping, dict):
        return None

    for key in keys:
        value = mapping.get(key)

        if value is not None and value != "":
            return value

    return None


def _infer_severity(result):
    """Normalize severity from explicit provider fields or CVSS score."""
    severity = _first_present(
        result,
        "severity",
        "baseSeverity",
    )

    if isinstance(severity, str):
        severity = severity.lower().strip()

        if severity in {
            "critical",
            "high",
            "medium",
            "low",
            "informational",
        }:
            return severity

    score = _first_present(
        result,
        "cvss_score",
        "cvssScore",
        "baseScore",
    )

    try:
        score = float(score)
    except (TypeError, ValueError):
        score = None

    if score is not None:
        if score >= 9.0:
            return "critical"

        if score >= 7.0:
            return "high"

        if score >= 4.0:
            return "medium"

        if score > 0:
            return "low"

    return "unknown"


def _infer_confidence(result):
    """Normalize confidence to high, medium, low, or unknown."""
    confidence = result.get("confidence")

    if isinstance(confidence, str):
        value = confidence.lower().strip()

        if value in {"high", "medium", "low"}:
            return value

    if isinstance(confidence, (int, float)):
        if confidence >= 0.8:
            return "high"

        if confidence >= 0.5:
            return "medium"

        return "low"


    return "unknown"


def normalize_tool_evidence(tool_name, arguments, result):
    """Convert raw tool output into the common evidence structure."""
    if not isinstance(result, dict):
        result = {"raw_result": result}

    indicator, indicator_type = identify_indicator(arguments)

    source = _safe_text(
        result.get("source"),
        tool_name,
    )

    failed = (
        bool(result.get("error"))
        or result.get("status") in {
            "error",
            "unavailable",
            "timeout",
        }
        or result.get("available") is False
    )

    finding = _safe_text(
        _first_present(
            result,
            "finding",
            "description",
            "message",
            "analysis",
            "summary",
            "error",
        ),
        "Tool returned data; interpretation required.",
    )

    # A successful provider response can still be neutral when it found
    # no matching record. No-match is not proof of benignness or maliciousness.
    finding_lower = finding.lower()

    no_match_phrases = (
        "no matching listing",
        "no matching historical scan",
        "no matching scan",
        "no results",
        "no result found",
        "not found",
        "no records found",
        "no matching records",
        "no data found",
    )

    explicit_negative = any(
        result.get(field) is False
        for field in ("listed", "found", "is_malicious", "malicious")
    )

    zero_results = (
        result.get("total_results") == 0
        or result.get("count") == 0
        or result.get("query_status") in {"no_results", "not_found"}
    )

    no_match_finding = any(
        phrase in finding_lower for phrase in no_match_phrases
    )

    neutral_no_match = not failed and (
        explicit_negative or zero_results or no_match_finding
    )

    normalized = {
        "indicator": _safe_text(
            _first_present(result, "indicator") or indicator,
            "unknown",
        ),
        "indicator_type": _safe_text(
            _first_present(result, "indicator_type") or indicator_type,
            "unknown",
        ),
        "source": source,
        "finding": finding,
        "severity": _infer_severity(result),
        "confidence": _infer_confidence(result),
        "direction": "missing" if failed else "contextual",
        "status": "error" if failed else "success",
        "available": not failed,
        "supporting_evidence": [],
        "contradictory_evidence": [],
        "missing_evidence": [],
        "raw_result": result,
    }

    if failed:
        normalized["missing_evidence"].append(
            f"{source} did not provide usable evidence: {finding}"
        )
        return normalized

    # Preserve explicitly supplied evidence and its direction, but do not
    # promote provider no-match/negative lookup results into support.
    for field in (
        "supporting_evidence",
        "evidence",
        "indicators",
        "threat_names",
    ):
        for item in _as_list(result.get(field)):
            if not item:
                continue

            if isinstance(item, dict):
                direction = str(
                    item.get("direction", "supporting")
                ).lower()

                detail = _safe_text(
                    item.get("finding")
                    or item.get("detail")
                    or item
                )
            else:
                direction = "supporting"
                detail = _safe_text(item)

            if neutral_no_match:
                # Retain raw provider data and the neutral finding below.
                # Do not classify a no-match result as support or conflict.
                continue

            if direction == "contradictory":
                normalized["contradictory_evidence"].append(detail)

            elif direction in {"supporting", "malicious"}:
                normalized["supporting_evidence"].append(detail)

    # Explicit positive provider signals are supporting evidence.
    positive_fields = (
        (
            "listed",
            "Provider reports that the indicator is listed.",
        ),
        (
            "is_malicious",
            "Provider explicitly identifies the indicator as malicious.",
        ),
        (
            "malicious",
            "Provider explicitly identifies the indicator as malicious.",
        ),
    )

    for field, detail in positive_fields:
        if result.get(field) is True:
            normalized["supporting_evidence"].append(detail)

    # Keep negative/no-match responses contextual. Add detail to the finding
    # without treating it as evidence that the indicator is benign.
    if neutral_no_match:
        negative_fields = [
            field
            for field in ("is_malicious", "malicious", "listed", "found")
            if result.get(field) is False
        ]

        if negative_fields:
            normalized["finding"] = (
                f"{finding} Provider explicitly returned "
                f"{', '.join(f'{field}=false' for field in negative_fields)}."
            )

        normalized["direction"] = "contextual"

    # Preserve critical CVE severity even if exploitation is not observed.
    cvss_score = _first_present(
        result,
        "cvss_score",
        "cvssScore",
        "baseScore",
    )

    if cvss_score is not None:
        try:
            score = float(cvss_score)

            if score >= 9.0:
                normalized["supporting_evidence"].append(
                    f"Critical vulnerability severity reported "
                    f"(CVSS {score:.1f})."
                )

        except (TypeError, ValueError):
            pass

    # Generic provider findings are supporting only when they are not
    # no-match/context-only responses.
    if (
        finding
        and finding != "Tool returned data; interpretation required."
        and not neutral_no_match
    ):
        normalized["supporting_evidence"].append(finding)

    # Deduplicate while preserving order.
    for field in (
        "supporting_evidence",
        "contradictory_evidence",
        "missing_evidence",
    ):
        normalized[field] = list(
            dict.fromkeys(normalized[field])
        )

    if normalized["supporting_evidence"]:
        normalized["direction"] = "supporting"

    elif normalized["contradictory_evidence"]:
        normalized["direction"] = "contradictory"

    else:
        normalized["direction"] = "contextual"

    return normalized


def correlate_evidence(evidence_items):
    """Group evidence by indicator without deciding the final verdict."""
    grouped = {}

    for item in evidence_items:
        indicator_type = item.get(
            "indicator_type",
            "unknown",
        )

        indicator = item.get(
            "indicator",
            "unknown",
        )

        key = (
            indicator_type,
            indicator,
        )

        if key not in grouped:
            grouped[key] = {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "sources": [],
                "supporting_evidence": [],
                "contradictory_evidence": [],
                "missing_evidence": [],
            }

        group = grouped[key]

        group["sources"].append(
            item.get("source", "unknown")
        )

        # Contextual evidence contributes provider coverage/source context,
        # but only explicitly classified evidence enters these lists.
        group["supporting_evidence"].extend(
            item.get("supporting_evidence", [])
        )

        group["contradictory_evidence"].extend(
            item.get("contradictory_evidence", [])
        )

        group["missing_evidence"].extend(
            item.get("missing_evidence", [])
        )

    for group in grouped.values():
        for field in (
            "sources",
            "supporting_evidence",
            "contradictory_evidence",
            "missing_evidence",
        ):
            group[field] = list(
                dict.fromkeys(group[field])
            )

    return list(grouped.values())


def build_llm_evidence_payload(evidence_items):
    """Prepare normalized evidence and correlation for LLM reasoning."""
    return {
        "evidence_records": evidence_items,
        "correlation": correlate_evidence(evidence_items),
        "reasoning_rules": [
            "A failed or unavailable provider is missing evidence, not benign evidence.",
            "A provider no-results response is contextual coverage information, not supporting or contradictory evidence, and does not prove an indicator is benign.",
            "Only explicit positive or negative provider findings should enter supporting or contradictory evidence lists.",
            "Compare independent sources and identify conflicts.",
            "Do not invent provider results, confidence, or observations.",
            "Critical CVSS severity must not be downgraded because exploitation was not observed.",
        ],
    }


def parse_json_content(content):
    """Parse a JSON object from the model response."""
    if not isinstance(content, str):
        raise ValueError("LLM response content was empty.")

    content = content.strip()

    try:
        parsed = json.loads(content)

        if isinstance(parsed, dict):
            return parsed

    except json.JSONDecodeError:
        pass

    start = content.find("{")
    end = content.rfind("}")

    if start >= 0 and end > start:
        parsed = json.loads(
            content[start : end + 1]
        )

        if isinstance(parsed, dict):
            return parsed

    raise ValueError(
        "LLM response did not contain a valid JSON object."
    )


def _risk_level_from_score(score):
    """Map a 0-100 risk score to a risk level."""
    if score >= 90:
        return "critical"

    if score >= 70:
        return "high"

    if score >= 40:
        return "medium"

    if score >= 15:
        return "low"

    return "informational"


def _valid_score(value):
    """Check whether a risk score is a finite number between 0 and 100."""
    if isinstance(value, bool):
        return False

    if not isinstance(value, (int, float)):
        return False

    return math.isfinite(value) and 0 <= value <= 100


def _is_neutral_no_match_claim(value):
    """Identify provider no-match statements that must not be labeled as evidence."""
    text = _safe_text(value).lower()

    neutral_phrases = (
        "no matching listing",
        "no matching historical scan",
        "no matching scan",
        "no results",
        "no result found",
        "not found",
        "no records found",
        "no matching records",
        "no data found",
        "returned no evidence",
        "no evidence of malicious activity",
        "no matching historical scan results",
    )

    provider_names = ("urlhaus", "urlscan")

    return (
        any(provider in text for provider in provider_names)
        and any(phrase in text for phrase in neutral_phrases)
    )


def validate_final_result(result, evidence_items):
    """Validate the model's final assessment and retain missing evidence."""
    if not isinstance(result, dict):
        result = {}

    warnings = []

    verdict = str(
        result.get("verdict", "suspicious")
    ).strip().lower()

    verdict = VERDICT_ALIASES.get(
        verdict,
        verdict,
    )

    if verdict not in VALID_VERDICTS:
        warnings.append(
            f"Unsupported verdict '{verdict}' was normalized to suspicious."
        )

        verdict = "suspicious"

    confidence = result.get("confidence")

    if isinstance(confidence, str):
        try:
            confidence = float(
                confidence.replace("%", "").strip()
            )

            if confidence > 1:
                confidence /= 100

        except ValueError:
            confidence = None

    if (
        not isinstance(confidence, (int, float))
        or not math.isfinite(confidence)
    ):
        confidence = 0.0

        warnings.append(
            "Invalid confidence was replaced with 0.0."
        )

    confidence = max(
        0.0,
        min(1.0, float(confidence)),
    )

    risk_score = result.get(
        "risk_score",
        result.get("risk_score_0_100"),
    )

    if not _valid_score(risk_score):
        risk_score = 50

        warnings.append(
            "Invalid risk score was replaced with 50."
        )

    risk_score = int(round(risk_score))

    risk_level = str(
        result.get("risk_level")
        or _risk_level_from_score(risk_score)
    ).lower()

    supporting = result.get("supporting_evidence")
    contradictory = result.get("contradictory_evidence")
    missing = result.get("missing_evidence")

    if not isinstance(supporting, list):
        supporting = []

    if not isinstance(contradictory, list):
        contradictory = []

    if not isinstance(missing, list):
        missing = []

    # Always retain provider failures in the final missing-evidence list.
    for item in evidence_items:
        missing.extend(
            item.get("missing_evidence", [])
        )

    # Filter LLM-generated evidence claims that misclassify provider no-match
    # responses as support or contradiction. The normalized evidence records
    # remain available in the returned "evidence" field for full transparency.
    supporting = list(
        dict.fromkeys(
            _safe_text(item)
            for item in supporting
            if item and not _is_neutral_no_match_claim(item)
        )
    )

    contradictory = list(
        dict.fromkeys(
            _safe_text(item)
            for item in contradictory
            if item and not _is_neutral_no_match_claim(item)
        )
    )

    missing = list(
        dict.fromkeys(
            _safe_text(item)
            for item in missing
            if item
        )
    )

    # The system prompt requests "reason". Accept legacy aliases as well.
    reason = _safe_text(
        result.get("reason")
        or result.get("rationale")
        or result.get("summary")
        or result.get("executive_summary")
    )

    if not reason:
        reason = (
            "The model returned an assessment without an explanation. "
            "Review the evidence and investigation log."
        )

        warnings.append(
            "The model did not provide a reason in its final assessment."
        )

    # Flag critical CVE evidence for review without assuming compromise.
    critical_cve_found = any(
        item.get("indicator_type") == "cve"
        and (
            item.get("severity") == "critical"
            or any(
                "critical vulnerability severity"
                in str(evidence).lower()
                for evidence in item.get(
                    "supporting_evidence",
                    [],
                )
            )
        )
        for item in evidence_items
    )

    if critical_cve_found and verdict == "benign":
        warnings.append(
            "Critical CVE evidence is present. Verify that the verdict "
            "distinguishes vulnerability severity from confirmed exploitation."
        )

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "supporting_evidence": supporting,
        "contradictory_evidence": contradictory,
        "missing_evidence": missing,
        "reason": reason,
        "rationale": reason,  # Backward compatibility with existing frontend.
        "warnings": warnings,
    }


def make_error_result(message, evidence_items=None):
    """Return a consistent error result."""
    return {
        "verdict": "error",
        "confidence": 0.0,
        "risk_level": "unknown",
        "risk_score": 0,
        "supporting_evidence": [],
        "contradictory_evidence": [],
        "missing_evidence": [],
        "reason": message,
        "rationale": message,
        "warnings": [],
        "evidence": evidence_items or [],
        "correlation": [],
        "investigation_log": [],
        "tool_calls_made": 0,
    }


def run_agent_graph(user_input: str):
    """Run an LLM-directed investigation with evidence aggregation."""
    if (
        not isinstance(user_input, str)
        or not user_input.strip()
    ):
        return make_error_result(
            "Investigation input must be a non-empty string."
        )

    messages = [
        {
            "role": "user",
            "content": user_input.strip(),
        }
    ]

    tool_definitions = build_openai_tools()

    evidence_items = []
    investigation_log = []

    tool_call_count = 0

    try:
        for _round in range(MAX_TOOL_ROUNDS):
            response = run_llm(
                messages=messages,
                tools=tool_definitions,
            )

            choice = response.choices[0]
            assistant_message = choice.message

            assistant_record = {
                "role": "assistant",
                "content": assistant_message.content or "",
            }

            if assistant_message.tool_calls:
                assistant_record["tool_calls"] = [
                    {
                        "id": tool_call.id,
                        "type": "function",
                        "function": {
                            "name": tool_call.function.name,
                            "arguments": tool_call.function.arguments,
                        },
                    }
                    for tool_call in assistant_message.tool_calls
                ]

            messages.append(assistant_record)

            # No tool calls means the model has returned its final assessment.
            if not assistant_message.tool_calls:
                parsed = parse_json_content(
                    assistant_message.content or "{}"
                )

                final = validate_final_result(
                    parsed,
                    evidence_items,
                )

                final["evidence"] = evidence_items

                final["correlation"] = correlate_evidence(
                    evidence_items
                )

                final["investigation_log"] = investigation_log
                final["tool_calls_made"] = tool_call_count

                return final

            for tool_call in assistant_message.tool_calls:
                if tool_call_count >= MAX_TOOL_CALLS:
                    investigation_log.append(
                        {
                            "event": "tool_limit_reached",
                            "message": (
                                f"Maximum of {MAX_TOOL_CALLS} "
                                "tool calls reached."
                            ),
                        }
                    )

                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": json.dumps(
                                {
                                    "status": "error",
                                    "error": "Tool-call limit reached.",
                                }
                            ),
                        }
                    )

                    continue

                tool_name = tool_call.function.name

                try:
                    arguments = json.loads(
                        tool_call.function.arguments or "{}"
                    )

                except json.JSONDecodeError:
                    arguments = {}

                result = execute_tool(
                    tool_name,
                    arguments,
                )

                normalized = normalize_tool_evidence(
                    tool_name,
                    arguments,
                    result,
                )

                evidence_items.append(normalized)
                tool_call_count += 1

                investigation_log.append(
                    {
                        "tool": tool_name,
                        "arguments": arguments,
                        "status": normalized["status"],
                        "finding": normalized["finding"],
                    }
                )

                tool_payload = {
                    "tool_result": result,
                    "normalized_evidence": normalized,
                    "correlation": correlate_evidence(
                        evidence_items
                    ),
                    "instructions": (
                        "Use normalized_evidence and correlation for reasoning. "
                        "Do not treat errors or no-results as benign. Continue "
                        "investigating if useful, then return the final JSON assessment."
                    ),
                }

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(
                            tool_payload,
                            ensure_ascii=False,
                            default=str,
                        ),
                    }
                )

        return make_error_result(
            "Investigation stopped because the maximum tool-call rounds were reached.",
            evidence_items,
        )

    except Exception as exc:
        logger.exception(
            "SentinelAI investigation failed."
        )

        return make_error_result(
            f"Investigation failed: {type(exc).__name__}",
            evidence_items,
        )
