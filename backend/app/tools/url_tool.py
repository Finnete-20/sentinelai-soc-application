
import base64
import os

import requests
from dotenv import load_dotenv

from app.tools.threat_intel_tool import normalize_url

try:
    load_dotenv()
except Exception:
    pass


def url_reputation_check(url: str):
    """Retrieve VirusTotal intelligence for a normalized URL."""
    normalized_url = normalize_url(url)

    result = {
        "source": "virustotal",
        "url": normalized_url or url,
        "indicator_type": "url",
        "virustotal_available": False,
        "last_analysis_stats": {},
        "reputation": None,
        "categories": [],
        "sources": [],
    }

    if not normalized_url:
        result.update({
            "status": "error",
            "available": False,
            "error": "A valid HTTP or HTTPS URL is required.",
        })
        return result

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        result.update({
            "status": "error",
            "available": False,
            "error": "VT_API_KEY is not configured.",
        })
        return result

    url_id = (
        base64.urlsafe_b64encode(normalized_url.encode("utf-8"))
        .decode("ascii")
        .strip("=")
    )

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=10,
        )

        if response.status_code == 404:
            result.update({
                "status": "success",
                "available": True,
                "virustotal_available": True,
                "finding": (
                    "VirusTotal has no existing URL record for this indicator. "
                    "This is not evidence that the URL is benign."
                ),
                "record_found": False,
                "sources": ["virustotal"],
            })
            return result

        response.raise_for_status()
        payload = response.json()

        attributes = (
            payload.get("data", {}).get("attributes", {})
        )

        stats = attributes.get("last_analysis_stats")

        if not isinstance(stats, dict):
            stats = {}

        categories = attributes.get("categories") or {}

        if not isinstance(categories, dict):
            categories = {}

        result.update({
            "status": "success",
            "available": True,
            "virustotal_available": True,
            "record_found": True,
            "last_analysis_stats": stats,
            "reputation": attributes.get("reputation"),
            "categories": list(categories.values()),
            "sources": ["virustotal"],
            "finding": (
                "VirusTotal returned URL intelligence. "
                "Interpret detections alongside other evidence."
            ),
        })

        return result

    except requests.RequestException:
        result.update({
            "status": "error",
            "available": False,
            "error": "The VirusTotal request failed.",
        })
        return result

    except (ValueError, TypeError):
        result.update({
            "status": "error",
            "available": False,
            "error": "VirusTotal returned an invalid API response.",
        })
        return result
