MITRE_KNOWLEDGE = {

    "phishing": {
        "technique": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "detection": "Monitor email gateways and URL clicks."
    },

    "credential_access": {
        "technique": "T1110",
        "name": "Credential Access",
        "tactic": "Credential Access",
        "detection": "Monitor authentication failures."
    },

    "powershell": {
        "technique": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "detection": "Monitor PowerShell logging."
    },

    "ransomware": {
        "technique": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "detection": "Monitor abnormal encryption activity."
    },

    "lateral_movement": {
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
    }
}


def mitre_mapper(evidence: str):

    return {
        "knowledge_base": MITRE_KNOWLEDGE,
        "query": evidence
    }