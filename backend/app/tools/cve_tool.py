CVE_DATABASE = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "severity": "critical",
        "cvss": 10.0,
        "description": "Remote code execution vulnerability in Apache Log4j."
    },
    "CVE-2017-0144": {
        "name": "EternalBlue",
        "severity": "critical",
        "cvss": 9.8,
        "description": "SMB remote code execution vulnerability."
    }
}


def cve_lookup(cve: str):

    cve = cve.upper()

    if cve in CVE_DATABASE:
        return CVE_DATABASE[cve]

    return {
        "name": "Unknown",
        "severity": "unknown",
        "cvss": 0,
        "description": "CVE not found."
    }