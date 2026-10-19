
import unittest

from app.core.agent_runtime import (
    normalize_tool_evidence,
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

        # Vulnerability severity alone must not automatically
        # determine whether a system has been compromised.
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
            make_result(
                verdict="safe",
                risk_score=95,
            ),
            [],
        )

        # Validation warns about the contradiction without silently
        # replacing the LLM's verdict.
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
