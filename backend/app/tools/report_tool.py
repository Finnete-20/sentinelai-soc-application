from datetime import datetime


def generate_executive_report(investigation: str):

    return {
        "report_type": "SOC Executive Report",
        "generated_at": datetime.utcnow().isoformat(),
        "executive_summary": investigation,
        "analyst_notes": "Generated automatically by SentinelAI."
    }