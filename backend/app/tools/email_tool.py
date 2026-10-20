
import ipaddress
import re
from urllib.parse import urlsplit

from app.tools.threat_intel_tool import normalize_url


EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

MARKDOWN_LINK_PATTERN = re.compile(
    r"\[([^\]]*)\]\((https?://[^)\s]+)\)",
    re.IGNORECASE,
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"'\])]+",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d+\b",
    re.IGNORECASE,
)


def _extract_urls(email_text):
    """Extract URLs from Markdown links and ordinary email text."""
    text_without_markdown_links = email_text
    urls = []
    seen = set()

    # Extract destinations first so URLs inside link text don't get mixed
    # with the Markdown destination.
    for match in MARKDOWN_LINK_PATTERN.finditer(email_text):
        destination = normalize_url(match.group(2))

        if destination and destination not in seen:
            seen.add(destination)
            urls.append(destination)

    # Remove complete Markdown links before scanning ordinary text.
    text_without_markdown_links = MARKDOWN_LINK_PATTERN.sub(
        " ",
        text_without_markdown_links,
    )

    for match in URL_PATTERN.finditer(text_without_markdown_links):
        candidate = match.group(0).rstrip(".,;!?")
        normalized = normalize_url(candidate)

        if normalized and normalized not in seen:
            seen.add(normalized)
            urls.append(normalized)

    return urls


def _extract_ip_candidates(email_text):
    """Extract unique, syntactically valid IP addresses."""
    ips = []
    seen = set()

    for match in IP_PATTERN.finditer(email_text):
        candidate = match.group(0)

        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue

        normalized = str(parsed)

        if normalized not in seen:
            seen.add(normalized)
            ips.append(normalized)

    return ips


def _domain_from_url(url):
    """Extract the hostname from a normalized URL."""
    try:
        hostname = urlsplit(url).hostname
        return hostname.lower().rstrip(".") if hostname else None
    except ValueError:
        return None


def analyze_email(email_text: str):
    """Extract email addresses, URLs, domains, IPs, and CVEs."""
    if not isinstance(email_text, str):
        return {
            "email_addresses": [],
            "urls_found": [],
            "domains_found": [],
            "ips_found": [],
            "cves_found": [],
            "raw_email": "",
            "error": "Email content must be a string.",
        }

    emails = list(dict.fromkeys(
        address.lower()
        for address in EMAIL_PATTERN.findall(email_text)
    ))

    urls = _extract_urls(email_text)
    ips = _extract_ip_candidates(email_text)

    cves = list(dict.fromkeys(
        cve.upper()
        for cve in CVE_PATTERN.findall(email_text)
    ))

    domains = set()

    for address in emails:
        domains.add(address.rsplit("@", 1)[1].lower())

    for url in urls:
        domain = _domain_from_url(url)
        if domain:
            domains.add(domain)

    return {
        "email_addresses": emails,
        "urls_found": urls,
        "domains_found": sorted(domains),
        "ips_found": ips,
        "cves_found": cves,
        "raw_email": email_text,
    }
