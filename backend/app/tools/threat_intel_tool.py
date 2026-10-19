
import ipaddress
import os

import requests
from dotenv import load_dotenv

try:
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env"))
except Exception:
    pass


URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"


def _error(source, message):
    """Return a structured provider failure without exposing credentials."""
    return {
        "source": source,
        "status": "error",
        "available": False,
        "error": message,
    }


def urlhaus_lookup(url: str):
    """Look up a URL in URLhaus malware-distribution intelligence."""
    url = (url or "").strip()
    api_key = os.getenv("URLHAUS_AUTH_KEY")

    if not url:
        return _error("urlhaus", "A URL is required.")

    if not api_key:
        return _error(
            "urlhaus",
            "URLHAUS_AUTH_KEY is not configured.",
        )

    try:
        response = requests.post(
            URLHAUS_API_URL,
            headers={"Auth-Key": api_key},
            data={"url": url},
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json()

        query_status = payload.get("query_status", "unknown")
        found = query_status == "ok"

        return {
            "source": "urlhaus",
            "status": "success",
            "available": True,
            "indicator": url,
            "indicator_type": "url",
            "query_status": query_status,
            "listed": found,
            "finding": (
                "URLhaus reports this URL in its database."
                if found
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
        }

    except requests.RequestException as exc:
        return _error("urlhaus", f"Request failed: {exc}")
    except (ValueError, TypeError) as exc:
        return _error("urlhaus", f"Invalid API response: {exc}")


def abuseipdb_lookup(ip: str):
    """Check an IP address against AbuseIPDB abuse-report data."""
    ip = (ip or "").strip()

    if not ip:
        return _error("abuseipdb", "An IP address is required.")

    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        return _error("abuseipdb", "The supplied IP address is invalid.")

    if not parsed_ip.is_global:
        return _error(
            "abuseipdb",
            "AbuseIPDB lookup is intended for globally routable IP addresses.",
        )

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return _error(
            "abuseipdb",
            "ABUSEIPDB_API_KEY is not configured.",
        )

    try:
        response = requests.get(
            ABUSEIPDB_API_URL,
            headers={
                "Key": api_key,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
            },
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data", {})

        return {
            "source": "abuseipdb",
            "status": "success",
            "available": True,
            "indicator": ip,
            "indicator_type": "ip",
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_whitelisted": data.get("isWhitelisted"),
            "finding": (
                "AbuseIPDB returned IP reputation and abuse-report data."
            ),
        }

    except requests.RequestException as exc:
        return _error("abuseipdb", f"Request failed: {exc}")
    except (ValueError, TypeError) as exc:
        return _error("abuseipdb", f"Invalid API response: {exc}")


def urlscan_lookup(url: str):
    """Search historical urlscan.io results for a URL."""
    url = (url or "").strip()

    if not url:
        return _error("urlscan", "A URL is required.")

    # Escape backslashes and quotes in the Lucene query.
    escaped_url = (
        url.replace("\\", "\\\\")
        .replace('"', '\\"')
    )
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
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json()

        results = payload.get("results", [])
        summaries = []

        for item in results:
            # urlscan.io search results store these objects at top level.
            page = item.get("page") or {}
            task = item.get("task") or {}
            stats = item.get("stats") or {}

            # Search result URL points to the full scan result.
            result_url = item.get("result")

            # Keep tags as contextual evidence, not as a verdict.
            tags = task.get("tags") or []

            summaries.append({
                "scan_id": task.get("uuid"),
                "scan_time": task.get("time"),
                "submitted_url": task.get("url"),
                "page_url": page.get("url"),
                "domain": page.get("domain") or task.get("domain"),
                "page_title": page.get("title"),
                "country": None,
                "overall_malicious": None,
                "overall_score": None,
                "result_url": result_url,
                "tags": tags,
                "page_status": page.get("status"),
                "redirected": page.get("redirected"),
                "ip": page.get("ip"),
                "server": page.get("server"),
                "requests": stats.get("requests"),
                "uniq_ips": stats.get("uniqIPs"),
            })

        return {
            "source": "urlscan",
            "status": "success",
            "available": True,
            "indicator": url,
            "indicator_type": "url",
            "total_results": payload.get("total", len(results)),
            "results": summaries,
            "finding": (
                "Historical scan results were returned."
                if summaries
                else "No matching historical scan results were returned."
            ),
            "note": (
                "Historical results may refer to redirects or related URLs. "
                "Tags are contextual signals and do not by themselves confirm "
                "a malicious verdict. No matching scan does not establish "
                "that a URL is benign."
            ),
        }

    except requests.RequestException as exc:
        return _error("urlscan", f"Request failed: {exc}")
    except (ValueError, TypeError) as exc:
        return _error("urlscan", f"Invalid API response: {exc}")
