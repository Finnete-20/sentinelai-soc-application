from app.tools.url_tool import url_reputation_check
from app.tools.cve_tool import cve_lookup
from app.tools.mitre_tool import mitre_mapper
from app.tools.email_tool import analyze_email
from app.tools.memory_tool import memory_lookup, memory_store
from app.tools.report_tool import generate_executive_report
from app.tools.threat_intel_tool import (
    urlhaus_lookup,
    abuseipdb_lookup,
    urlscan_lookup,
)


TOOLS = {
    "analyze_email": {
        "description": "Extract indicators and metadata from email content.",
        "function": analyze_email,
        "input_schema": {"email_text": "string"},
    },
    "url_reputation_check": {
        "description": "Retrieve VirusTotal intelligence for a URL.",
        "function": url_reputation_check,
        "input_schema": {"url": "string"},
    },
    "urlhaus_lookup": {
        "description": (
            "Check URLhaus for URL-related malware and malicious URL intelligence."
        ),
        "function": urlhaus_lookup,
        "input_schema": {"url": "string"},
    },
    "abuseipdb_lookup": {
        "description": (
            "Check AbuseIPDB for abuse reports and reputation information "
            "associated with an IP address."
        ),
        "function": abuseipdb_lookup,
        "input_schema": {"ip": "string"},
    },
    "urlscan_lookup": {
        "description": (
            "Search historical urlscan.io scan records for a URL or domain. "
            "Historical matches and tags are contextual signals, not a "
            "confirmed malicious verdict."
        ),
        "function": urlscan_lookup,
        "input_schema": {"url": "string"},
    },
    "cve_lookup": {
        "description": "Retrieve vulnerability intelligence for a CVE.",
        "function": cve_lookup,
        "input_schema": {"cve": "string"},
    },
    "mitre_mapper": {
        "description": "Retrieve MITRE ATT&CK knowledge for analyst reasoning.",
        "function": mitre_mapper,
        "input_schema": {"evidence": "string"},
    },
    "memory_lookup": {
        "description": "Retrieve prior investigation records.",
        "function": memory_lookup,
        "input_schema": {"url": "string"},
    },
    "memory_store": {
        "description": "Store investigation findings.",
        "function": memory_store,
        "input_schema": {"finding": "string"},
    },
    "generate_executive_report": {
        "description": "Format an executive report.",
        "function": generate_executive_report,
        "input_schema": {"investigation": "string"},
    },
}

