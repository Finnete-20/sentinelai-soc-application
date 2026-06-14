from datetime import datetime


def generate_executive_report(investigation: str):

    return {
        "report_type": "SOC Executive Report",

        "generated_at": datetime.utcnow().isoformat(),

        "executive_summary": (
            f"SentinelAI completed an investigation. "
            f"Findings indicate: {investigation}"
        ),

        "incident_classification": "Security Incident",

        "risk_rating": "High",

        "mitre_findings": [],

        "cve_findings": [],

        "recommended_actions": [
            "Contain affected assets",
            "Block malicious indicators",
            "Review authentication logs",
            "Perform threat hunting activities",
            "Notify incident response team"
        ],

        "analyst_notes": (
            "Generated automatically by SentinelAI."
        )
    }