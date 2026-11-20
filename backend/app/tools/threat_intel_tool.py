
"""Threat-intelligence integrations used by SentinelAI.

Providers:
- URLhaus: malware-distribution URL intelligence
- AbuseIPDB: public IP abuse reputation
- urlscan.io: historical webpage and behavioral scan context

Provider failures are returned as structured evidence. They are not benign
findings and must not be interpreted as proof that an indicator is safe.
"""

import ipaddress
import os
import re
from urllib.parse import urlsplit, urlunsplit

import requests
from dotenv import load_dotenv


try:
    load_dotenv(
        dotenv_path=os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../../.env")
        )
    )
except Exception:
    pass


URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
REQUEST_TIMEOUT = 15


def _provider_error(source: str, message: str, indicator=None, indicator_type=None):
    return {
        "source": source,
        "status": "error",
        "available": False,
        "indicator": indicator,
        "indicator_type": indicator_type,
        "finding": message,
        "error": message,
        "evidence": [],
        "missing_evidence": [f"{source} lookup did not complete successfully."],
    }


def normalize_url(value: str) -> str:
    """Normalize an HTTP(S) URL without following redirects or changing its scheme."""
    if not isinstance(value, str):
        return ""

    value = value.strip()

    if (
        len(value) >= 2
        and value[0] == value[-1]
        and value[0] in {"'", '"', "`"}
    ):
        value = value[1:-1].strip()

    markdown_match = re.fullmatch(
        r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
        value,
        flags=re.IGNORECASE,
    )
    if markdown_match:
        value = markdown_match.group(2).strip()

    value = value.rstrip(".,;!?")

    try:
        parts = urlsplit(value)

        if parts.scheme.lower() not in {"http", "https"}:
            return ""

        if not parts.hostname:
            return ""

        # Validate malformed ports.
        _ = parts.port

        if any(char.isspace() or ord(char) < 32 for char in value):
            return ""

        return urlunsplit(
            (
                parts.scheme.lower(),
                parts.netloc,
                parts.path or "/",
                parts.query,
                parts.fragment,
            )
        )

    except (ValueError, TypeError):
        return ""


def _request_json(response):
    response.raise_for_status()
    payload = response.json()

    if not isinstance(payload, dict):
        raise ValueError("Provider response was not a JSON object.")

    return payload


def urlhaus_lookup(url: str):
    """Look up a URL in URLhaus malware-distribution intelligence."""
    normalized_url = normalize_url(url)

    if not normalized_url:
        return _provider_error(
            "urlhaus",
            "A valid HTTP or HTTPS URL is required.",
            indicator=url,
            indicator_type="url",
        )

    api_key = os.getenv("URLHAUS_AUTH_KEY")
    if not api_key:
        return _provider_error(
            "urlhaus",
            "URLHAUS_AUTH_KEY is not configured.",
            indicator=normalized_url,
            indicator_type="url",
        )

    try:
        response = requests.post(
            URLHAUS_API_URL,
            headers={"Auth-Key": api_key},
            data={"url": normalized_url},
            timeout=REQUEST_TIMEOUT,
        )
        payload = _request_json(response)

        query_status = payload.get("query_status", "unknown")
        listed = query_status == "ok"

        evidence = []
        if listed:
            evidence.append(
                {
                    "finding": "URLhaus has a matching URL record.",
                    "severity": "high",
                    "confidence": "high",
                    "direction": "supporting",
                }
            )

        return {
            "source": "urlhaus",
            "status": "success",
            "available": True,
            "indicator": normalized_url,
            "indicator_type": "url",
            "query_status": query_status,
            "listed": listed,
            "finding": (
                "URLhaus reports this URL in its database."
                if listed
                else (
                    "URLhaus returned no matching listing."
                    if query_status == "no_results"
                    else "URLhaus returned an unrecognized query status."
                )
            ),
            "threat": payload.get("threat"),
            "url_status": payload.get("url_status"),
            "tags": payload.get("tags", []),
            "date_added": payload.get("date_added"),
            "evidence": evidence,
            "note": (
                "A no-results response is not proof of benign activity."
            ),
        }

    except requests.Timeout:
        return _provider_error(
            "urlhaus",
            "URLhaus request timed out.",
            normalized_url,
            "url",
        )
    except requests.RequestException:
        return _provider_error(
            "urlhaus",
            "URLhaus request failed.",
            normalized_url,
            "url",
        )
    except (ValueError, TypeError):
        return _provider_error(
            "urlhaus",
            "URLhaus returned an invalid API response.",
            normalized_url,
            "url",
        )


def abuseipdb_lookup(ip: str):
    """Check a globally routable IP address against AbuseIPDB."""
    ip = (ip or "").strip()

    if not ip:
        return _provider_error(
            "abuseipdb",
            "An IP address is required.",
            indicator=ip,
            indicator_type="ip",
        )

    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        return _provider_error(
            "abuseipdb",
            "The supplied IP address is invalid.",
            indicator=ip,
            indicator_type="ip",
        )

    if not parsed_ip.is_global:
        return _provider_error(
            "abuseipdb",
            "Only globally routable IP addresses can be queried.",
            indicator=str(parsed_ip),
            indicator_type="ip",
        )

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return _provider_error(
            "abuseipdb",
            "ABUSEIPDB_API_KEY is not configured.",
            indicator=str(parsed_ip),
            indicator_type="ip",
        )

    try:
        response = requests.get(
            ABUSEIPDB_API_URL,
            headers={
                "Key": api_key,
                "Accept": "application/json",
            },
            params={
                "ipAddress": str(parsed_ip),
                "maxAgeInDays": 90,
            },
            timeout=REQUEST_TIMEOUT,
        )
        payload = _request_json(response)
        data = payload.get("data") or {}

        score = data.get("abuseConfidenceScore")
        reports = data.get("totalReports")

        evidence = []
        if isinstance(score, (int, float)) and score >= 50:
            evidence.append(
                {
                    "finding": (
                        f"AbuseIPDB abuse confidence score is {score}/100."
                    ),
                    "severity": "high" if score >= 75 else "medium",
                    "confidence": "medium",
                    "direction": "supporting",
                }
            )
        elif score == 0:
            evidence.append(
                {
                    "finding": "AbuseIPDB returned an abuse confidence score of 0.",
                    "severity": "informational",
                    "confidence": "low",
                    "direction": "contextual",
                }
            )

        return {
            "source": "abuseipdb",
            "status": "success",
            "available": True,
            "indicator": str(parsed_ip),
            "indicator_type": "ip",
            "abuse_confidence_score": score,
            "total_reports": reports,
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_whitelisted": data.get("isWhitelisted"),
            "finding": "AbuseIPDB returned IP reputation and abuse-report data.",
            "evidence": evidence,
            "note": (
                "A low report count or score does not independently prove "
                "that an IP address is benign."
            ),
        }

    except requests.Timeout:
        return _provider_error(
            "abuseipdb",
            "AbuseIPDB request timed out.",
            str(parsed_ip),
            "ip",
        )
    except requests.RequestException:
        return _provider_error(
            "abuseipdb",
            "AbuseIPDB request failed.",
            str(parsed_ip),
            "ip",
        )
    except (ValueError, TypeError):
        return _provider_error(
            "abuseipdb",
            "AbuseIPDB returned an invalid API response.",
            str(parsed_ip),
            "ip",
        )


def urlscan_lookup(url: str):
    """Search historical urlscan.io records for a URL."""
    normalized_url = normalize_url(url)

    if not normalized_url:
        return _provider_error(
            "urlscan",
            "A valid HTTP or HTTPS URL is required.",
            indicator=url,
            indicator_type="url",
        )

    escaped_url = normalized_url.replace("\\", "\\\\").replace('"', '\\"')
    query = f'page.url:"{escaped_url}"'

    headers = {"Accept": "application/json"}
    api_key = os.getenv("URLSCAN_API_KEY")

    if api_key:
        headers["api-key"] = api_key

    try:
        response = requests.get(
            URLSCAN_SEARCH_URL,
            headers=headers,
            params={"q": query, "size": 10},
            timeout=REQUEST_TIMEOUT,
        )
        payload = _request_json(response)

        results = payload.get("results") or []
        summaries = []

        for item in results:
            page = item.get("page") or {}
            task = item.get("task") or {}
            stats = item.get("stats") or {}

            summaries.append(
                {
                    "scan_id": task.get("uuid"),
                    "scan_time": task.get("time"),
                    "submitted_url": task.get("url"),
                    "page_url": page.get("url"),
                    "domain": page.get("domain") or task.get("domain"),
                    "page_title": page.get("title"),
                    "result_url": item.get("result"),
                    "tags": task.get("tags") or [],
                    "page_status": page.get("status"),
                    "redirected": page.get("redirected"),
                    "ip": page.get("ip"),
                    "server": page.get("server"),
                    "requests": stats.get("requests"),
                    "unique_ips": stats.get("uniqIPs"),
                }
            )

        return {
            "source": "urlscan",
            "status": "success",
            "available": True,
            "indicator": normalized_url,
            "indicator_type": "url",
            "total_results": payload.get("total", len(results)),
            "results": summaries,
            "finding": (
                "Historical scan results were returned."
                if summaries
                else "No matching historical scan results were returned."
            ),
            "evidence": [],
            "note": (
                "Historical scans can refer to redirects or related URLs. "
                "Tags and scan metadata are contextual signals, not an "
                "automatic malicious verdict. No matching scan does not "
                "establish that a URL is benign."
            ),
        }

    except requests.Timeout:
        return _provider_error(
            "urlscan",
            "urlscan.io request timed out.",
            normalized_url,
            "url",
        )
    except requests.RequestException:
        return _provider_error(
            "urlscan",
            "urlscan.io request failed.",
            normalized_url,
            "url",
        )
    except (ValueError, TypeError):
        return _provider_error(
            "urlscan",
            "urlscan.io returned an invalid API response.",
            normalized_url,
            "url",
        )
