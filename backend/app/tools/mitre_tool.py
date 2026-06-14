MITRE_MAPPINGS = {
    "phishing": {
        "technique": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "detection": "Monitor email gateways, URL clicks, and attachment execution."
    },

    "credential": {
        "technique": "T1110",
        "name": "Brute Force / Credential Access",
        "tactic": "Credential Access",
        "detection": "Monitor authentication failures and password spraying."
    },

    "powershell": {
        "technique": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "detection": "Monitor PowerShell command logging and AMSI events."
    },

    "ransomware": {
        "technique": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "detection": "Monitor abnormal file encryption activity."
    },

    "lateral movement": {
        "technique": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "detection": "Monitor remote administration and SMB activity."
    },

    "persistence": {
        "technique": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "detection": "Monitor registry run keys and startup folders."
    },

    "exfiltration": {
        "technique": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "detection": "Monitor large outbound transfers and unusual destinations."
    }
}


def mitre_mapper(evidence: str):

    evidence = evidence.lower()

    matches = []

    for keyword, mapping in MITRE_MAPPINGS.items():

        if keyword in evidence:

            matches.append({
                "keyword": keyword,
                "technique": mapping["technique"],
                "name": mapping["name"],
                "tactic": mapping["tactic"],
                "detection": mapping["detection"]
            })

    return {
        "match_count": len(matches),
        "matches": matches
    }