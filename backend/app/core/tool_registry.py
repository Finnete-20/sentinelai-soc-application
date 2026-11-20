
"""Central registry for all tools exposed to the SentinelAI LLM."""

from app.tools.url_tool import url_reputation_check
from app.tools.threat_intel_tool import (
    urlhaus_lookup,
    abuseipdb_lookup,
    urlscan_lookup,
)
from app.tools.cve_tool import cve_lookup
from app.tools.email_tool import analyze_email
from app.tools.mitre_tool import mitre_mapper
from app.tools.memory_tool import memory_lookup, memory_store
from app.tools.report_tool import generate_executive_report


TOOLS = {
    "analyze_email": {
        "description": (
            "Extract URLs, domains, IP addresses, email addresses, and CVE IDs "
            "from email text. Use this before investigating indicators in an email."
        ),
        "function": analyze_email,
        "input_schema": {"email_text": "string"},
    },

    "url_reputation_check": {
        "description": (
            "Query VirusTotal for multi-engine reputation and threat intelligence "
            "about a URL. A low or zero detection count is not proof that a URL is benign."
        ),
        "function": url_reputation_check,
        "input_schema": {"url": "string"},
    },

    "urlhaus_lookup": {
        "description": (
            "Check URLhaus for URLs associated with malware distribution. "
            "A positive listing is meaningful supporting evidence; no listing "
            "does not prove the URL is benign."
        ),
        "function": urlhaus_lookup,
        "input_schema": {"url": "string"},
    },

    "urlscan_lookup": {
        "description": (
            "Search urlscan.io for historical webpage scans, redirects, page "
            "behavior, and related indicators. Historical matches and tags are "
            "contextual evidence, not an automatic verdict."
        ),
        "function": urlscan_lookup,
        "input_schema": {"url": "string"},
    },

    "abuseipdb_lookup": {
        "description": (
            "Check AbuseIPDB for abuse reports and reputation for a public, "
            "globally routable IP address. Do not pass a hostname or private IP."
        ),
        "function": abuseipdb_lookup,
        "input_schema": {"ip": "string"},
    },

    "cve_lookup": {
        "description": (
            "Retrieve CVE details and severity from the NVD. CVSS severity is "
            "important even when active exploitation has not been observed."
        ),
        "function": cve_lookup,
        "input_schema": {"cve": "string"},
    },

    "mitre_mapper": {
        "description": (
            "Map observed behavior or investigation evidence to relevant "
            "MITRE ATT&CK techniques."
        ),
        "function": mitre_mapper,
        "input_schema": {"evidence": "string"},
    },

    "memory_lookup": {
        "description": (
            "Search prior SentinelAI investigation records for relevant "
            "historical findings. Treat memory as contextual evidence and "
            "check whether it refers to the same indicator."
        ),
        "function": memory_lookup,
        "input_schema": {"query": "string"},
    },

    "memory_store": {
        "description": (
            "Store a concise investigation finding for future investigations. "
            "Store only relevant findings, not secrets or credentials."
        ),
        "function": memory_store,
        "input_schema": {"finding": "string"},
    },

    "generate_executive_report": {
        "description": (
            "Format the completed investigation into an executive report. "
            "Call after the investigation verdict and evidence are established."
        ),
        "function": generate_executive_report,
        "input_schema": {"investigation": "string"},
    },
}
