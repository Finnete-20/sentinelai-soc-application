import requests

def url_reputation_check(url: str):
    """
    MCP TOOL: Checks URL reputation using external request-based heuristics.
    """

    try:
        response = requests.get(url, timeout=5)
        status_code = response.status_code

        suspicious_indicators = [
            "login",
            "verify",
            "secure",
            "update",
            "bank",
            "account"
        ]

        risk_score = 0

        # Heuristic analysis
        if status_code != 200:
            risk_score += 2

        for word in suspicious_indicators:
            if word in url.lower():
                risk_score += 1

        if url.startswith("http://"):
            risk_score += 1

        # Classification
        if risk_score >= 4:
            verdict = "malicious"
            risk = "high"
        elif risk_score >= 2:
            verdict = "suspicious"
            risk = "medium"
        else:
            verdict = "safe"
            risk = "low"

        return {
            "url": url,
            "status_code": status_code,
            "risk_score": risk_score,
            "risk_level": risk,
            "verdict": verdict
        }

    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "risk_level": "medium",
            "verdict": "suspicious"
        }