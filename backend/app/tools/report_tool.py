from datetime import datetime


def get_risk_rating(investigation: str):

    text = investigation.lower()

    if "critical" in text:
        return "Critical"

    if "malicious" in text:
        return "High"

    if "suspicious" in text:
        return "Medium"

    return "Low"


def generate_executive_report(investigation: str):

    risk_rating = get_risk_rating(
        investigation
    )

    return {

        "report_type": "SOC Executive Report",

        "generated_at":
        datetime.utcnow().isoformat(),

        "executive_summary":
        f"SentinelAI completed an investigation. Findings indicate: {investigation}",

        "incident_classification":
        "Security Incident"
        if risk_rating != "Low"
        else "Informational",

        "risk_rating":
        risk_rating,

        "recommended_actions":

        [
            "Contain affected assets",
            "Block malicious indicators",
            "Review authentication logs",
            "Perform threat hunting activities",
            "Notify incident response team"
        ]

        if risk_rating in [
            "High",
            "Critical"
        ]

        else

        [
            "Continue monitoring",
            "Review investigation results"
        ],

        "analyst_notes":
        "Generated automatically by SentinelAI."
    }