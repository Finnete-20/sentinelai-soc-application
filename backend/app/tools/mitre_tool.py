MITRE_MAPPINGS = {

    "phishing": {
        "technique": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "detection": "Monitor email gateways and URL clicks."
    },

    "credential": {
        "technique": "T1110",
        "name": "Credential Access",
        "tactic": "Credential Access",
        "detection": "Monitor authentication failures."
    },

    "powershell": {
        "technique": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "detection": "Monitor PowerShell logs."
    },

    "ransomware": {
        "technique": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "detection": "Monitor encryption activity."
    },

    "lateral movement": {
        "technique": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "detection": "Monitor SMB and remote administration."
    },

    "persistence": {
        "technique": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "detection": "Monitor startup entries."
    },

    "exfiltration": {
        "technique": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "detection": "Monitor outbound traffic."
    },

    "impersonation": {
        "technique": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "detection": "Monitor sender spoofing."
    }
}


def mitre_mapper(evidence: str):

    evidence = evidence.lower()

    matches = []

    for keyword, mapping in MITRE_MAPPINGS.items():

        if keyword in evidence:

            matches.append({
                "keyword": keyword,
                **mapping
            })

    return {
        "match_count": len(matches),
        "matches": matches
    }