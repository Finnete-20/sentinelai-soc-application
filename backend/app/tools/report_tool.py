from datetime import datetime


def get_risk_rating(investigation: str):

    text = investigation.lower()

    if "risk score: 9" in text or "risk score: 10" in text:
        return "Critical"

    if any(
        word in text
        for word in [
            "malicious",
            "ransomware",
            "credential theft",
            "confirmed phishing"
        ]
    ):
        return "High"

    if any(
        word in text
        for word in [
            "suspicious",
            "phishing",
            "impersonation"
        ]
    ):
        return "Medium"

    return "Low"


def generate_executive_report(investigation: str):

    risk_rating = get_risk_rating(
        investigation
    )

    return {
        "report_type": "SOC Executive Report",

        "generated_at": (
            datetime.utcnow().isoformat()
        ),

        "executive_summary": (
            f"SentinelAI completed an investigation. "
            f"Findings indicate: {investigation}"
        ),

        "incident_classification": (
            "Security Incident"
            if risk_rating != "Low"
            else "Informational"
        ),

        "risk_rating": risk_rating,

        "mitre_findings": [],

        "cve_findings": [],

        "recommended_actions": (
            [
                "Contain affected assets",
                "Block malicious indicators",
                "Review authentication logs",
                "Perform threat hunting activities",
                "Notify incident response team"
            ]
            if risk_rating in ["High", "Critical"]
            else [
                "Continue monitoring",
                "Review investigation results"
            ]
        ),

        "analyst_notes": (
            "Generated automatically by SentinelAI."
        )
    }