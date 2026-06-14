import re


CVE_DATABASE = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "severity": "critical",
        "cvss": 10.0,
        "known_exploited": True,
        "description": "Remote code execution vulnerability in Apache Log4j.",
        "affected_products": [
            "Apache Log4j 2"
        ],
        "recommended_actions": [
            "Upgrade Log4j immediately",
            "Search logs for exploitation attempts",
            "Block known IOC indicators"
        ]
    },

    "CVE-2017-0144": {
        "name": "EternalBlue",
        "severity": "critical",
        "cvss": 9.8,
        "known_exploited": True,
        "description": "SMB remote code execution vulnerability.",
        "affected_products": [
            "Windows SMBv1"
        ],
        "recommended_actions": [
            "Disable SMBv1",
            "Apply Microsoft patches",
            "Scan environment for vulnerable hosts"
        ]
    },

    "CVE-2023-34362": {
        "name": "MOVEit Transfer",
        "severity": "critical",
        "cvss": 9.8,
        "known_exploited": True,
        "description": "SQL injection vulnerability affecting MOVEit Transfer.",
        "affected_products": [
            "MOVEit Transfer"
        ],
        "recommended_actions": [
            "Patch immediately",
            "Review web logs",
            "Investigate possible data exposure"
        ]
    }
}


def _normalize_cve(cve: str):

    if not cve:
        return ""

    match = re.search(
        r"CVE-\d{4}-\d+",
        cve.upper()
    )

    if match:
        return match.group(0)

    return cve.upper()


def cve_lookup(cve: str):

    cve = _normalize_cve(cve)

    if cve in CVE_DATABASE:

        result = CVE_DATABASE[cve].copy()

        result["cve"] = cve

        return result

    return {
        "cve": cve,
        "name": "Unknown CVE",
        "severity": "unknown",
        "cvss": 0.0,
        "known_exploited": False,
        "description": "CVE not present in local intelligence database.",
        "affected_products": [],
        "recommended_actions": [
            "Validate CVE identifier",
            "Perform external vulnerability lookup"
        ]
    }