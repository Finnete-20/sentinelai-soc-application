import os
import base64
import requests
from dotenv import load_dotenv

try:
    load_dotenv()
except Exception:
    pass

VT_API_KEY = os.getenv("VT_API_KEY")


def url_reputation_check(url: str):
    """
    SentinelAI URL Reputation Tool

    Provides:
    - heuristic phishing detection
    - VirusTotal enrichment
    - risk scoring
    """

    result = {
        "url": url,
        "risk_score": 0,
        "verdict": "safe",
        "sources": []
    }

    url_lower = url.lower()

    phishing_keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "account",
        "signin",
        "password",
        "confirm",
        "wallet",
        "invoice",
        "otp",
        "recovery",
        "reset",
        "security",
        "alert",
        "urgent",
        "suspended"
    ]

    if url_lower.startswith("http://"):
        result["risk_score"] += 2

    keyword_hits = 0

    for keyword in phishing_keywords:
        if keyword in url_lower:
            keyword_hits += 1

    result["risk_score"] += keyword_hits

    if keyword_hits >= 3:
        result["risk_score"] += 2

    if VT_API_KEY:
        try:

            url_id = (
                base64.urlsafe_b64encode(url.encode())
                .decode()
                .strip("=")
            )

            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VT_API_KEY},
                timeout=10
            )

            if response.status_code == 200:

                data = response.json()

                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                if malicious > 0:
                    result["risk_score"] += 5

                elif suspicious > 0:
                    result["risk_score"] += 3

                result["sources"].append("virustotal")

        except Exception as e:
            result["sources"].append(
                f"vt_error:{str(e)}"
            )

    if result["risk_score"] >= 4:
        result["verdict"] = "malicious"

    elif result["risk_score"] >= 2:
        result["verdict"] = "suspicious"

    else:
        result["verdict"] = "safe"

    return result