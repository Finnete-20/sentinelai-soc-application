
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.core.agent_runtime import (
    normalize_tool_evidence,
    run_agent_graph,
    validate_final_result,
)


def make_result(
    verdict="safe",
    risk_score=10,
    confidence=0.85,
    reason=(
        "The available investigation results do not show direct evidence "
        "of compromise. This assessment is limited to the evidence collected."
    ),
):
    """Create a consistent test response for final-result validation."""
    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "incident_type": "url_analysis",
        "reason": reason,
        "executive_summary": reason,
        "supporting_evidence": [],
        "contradictory_evidence": [],
        "missing_evidence": [],
        "recommended_actions": [],
        "mitre_findings": [],
        "cve_findings": [],
    }


def make_tool_call(name, arguments, call_id="call-1"):
    """Build a mock OpenAI function tool call."""
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(
            name=name,
            arguments=json.dumps(arguments),
        ),
    )


def make_llm_response(tool_calls=None, content=None):
    """Build a mock OpenAI chat completion response."""
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    tool_calls=tool_calls,
                    content=content,
                )
            )
        ]
    )


class TestAgentRuntimeValidation(unittest.TestCase):

    def test_valid_response_keeps_verdict_and_scores(self):
        validated = validate_final_result(make_result(), [])

        self.assertEqual(validated["verdict"], "safe")
        self.assertEqual(validated["risk_score"], 10)
        self.assertEqual(validated["confidence"], 0.85)

    def test_invalid_risk_score_is_flagged(self):
        validated = validate_final_result(
            make_result(risk_score=150), []
        )

        self.assertEqual(validated["risk_score"], 50)
        self.assertTrue(validated["validation_warnings"])
        self.assertTrue(validated["missing_evidence"])

    def test_invalid_confidence_is_flagged(self):
        validated = validate_final_result(
            make_result(confidence=2), []
        )

        self.assertEqual(validated["confidence"], 0)
        self.assertTrue(validated["validation_warnings"])

    def test_failed_tool_is_not_treated_as_clean(self):
        evidence = normalize_tool_evidence(
            "url_reputation_check",
            {"url": "https://example.invalid"},
            {
                "error": "Service unavailable",
                "status": "error",
            },
        )

        validated = validate_final_result(
            make_result(),
            [evidence],
        )

        self.assertEqual(evidence["status"], "error")
        self.assertTrue(validated["missing_evidence"])
        self.assertTrue(validated["validation_warnings"])

    def test_critical_cve_does_not_automatically_change_verdict(self):
        evidence = normalize_tool_evidence(
            "cve_lookup",
            {"cve": "CVE-2021-44228"},
            {
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "description": "Critical vulnerability record.",
            },
        )

        validated = validate_final_result(
            make_result(verdict="safe"),
            [evidence],
        )

        self.assertEqual(validated["verdict"], "safe")
        self.assertTrue(validated["validation_warnings"])

    def test_unsupported_verdict_is_flagged(self):
        validated = validate_final_result(
            make_result(verdict="definitely_hacked"),
            [],
        )

        self.assertEqual(validated["verdict"], "suspicious")
        self.assertTrue(validated["validation_warnings"])

    def test_boolean_is_not_a_valid_numeric_score(self):
        validated = validate_final_result(
            make_result(risk_score=True),
            [],
        )

        self.assertEqual(validated["risk_score"], 50)
        self.assertTrue(validated["validation_warnings"])

    def test_safe_verdict_with_very_high_risk_is_flagged(self):
        validated = validate_final_result(
            make_result(verdict="safe", risk_score=95),
            [],
        )

        self.assertEqual(validated["verdict"], "safe")
        self.assertTrue(
            any(
                "low-risk verdict conflicts" in warning.lower()
                for warning in validated["validation_warnings"]
            )
        )

    def test_high_severity_verdict_with_low_risk_is_flagged(self):
        validated = validate_final_result(
            make_result(
                verdict="malicious",
                risk_score=10,
                confidence=0.95,
            ),
            [],
        )

        self.assertEqual(validated["verdict"], "malicious")
        self.assertTrue(
            any(
                "low risk score" in warning.lower()
                for warning in validated["validation_warnings"]
            )
        )

    def test_high_confidence_without_tool_evidence_is_flagged(self):
        validated = validate_final_result(
            make_result(confidence=0.99),
            [],
        )

        self.assertTrue(
            any(
                "no tool evidence" in warning.lower()
                or "evidence basis" in warning.lower()
                for warning in validated["validation_warnings"]
            )
        )

    def test_generic_rationale_is_flagged(self):
        validated = validate_final_result(
            make_result(
                reason=(
                    "Assessment based on the recorded investigation results."
                )
            ),
            [],
        )

        self.assertTrue(
            any(
                "rationale is missing or generic" in warning.lower()
                for warning in validated["validation_warnings"]
            )
        )


class TestOriginalEmailPreservation(unittest.TestCase):

    @patch("app.core.agent_runtime.execute_tool")
    @patch("app.core.agent_runtime.run_llm")
    def test_analyze_email_receives_original_input_unchanged(
        self,
        mock_run_llm,
        mock_execute_tool,
    ):
        original_email = (
            "Subject: Urgent Account Verification\n\n"
            "Please review these links:\n"
            "https://forms.gle/example\n"
            "https://gvsu-login-security.example.com/verify-account\n\n"
            "Thank you,\nIT Support"
        )

        # Simulate the model corrupting the multiline email argument.
        malformed_email = (
            "[https://forms.gle/example\n"
            "https://gvsu-login-security.example.com/verify-account\n\n"
            "Thank](https://forms.gle/example)"
        )

        mock_run_llm.side_effect = [
            make_llm_response(
                tool_calls=[
                    make_tool_call(
                        "analyze_email",
                        {"email_text": malformed_email},
                    )
                ]
            ),
            make_llm_response(
                content=json.dumps(make_result().__dict__)
                if hasattr(make_result(), "__dict__")
                else json.dumps(make_result())
            ),
        ]

        mock_execute_tool.return_value = {
            "email_addresses": [],
            "urls_found": [
                "https://forms.gle/example",
                "https://gvsu-login-security.example.com/verify-account",
            ],
            "domains_found": [
                "forms.gle",
                "gvsu-login-security.example.com",
            ],
            "ips_found": [],
            "cves_found": [],
            "status": "success",
        }

        result = run_agent_graph(original_email)

        mock_execute_tool.assert_called_once()
        args = mock_execute_tool.call_args.args

        self.assertEqual(args[0], "analyze_email")
        self.assertEqual(args[1]["email_text"], original_email)
        self.assertEqual(
            result["investigation_log"][0]["arguments"]["email_text"],
            original_email,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
