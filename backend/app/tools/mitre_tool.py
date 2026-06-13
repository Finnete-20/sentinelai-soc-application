MITRE_MAPPINGS = {
    "phishing": {
        "technique": "T1566",
        "name": "Phishing"
    },
    "credential": {
        "technique": "T1110",
        "name": "Credential Access"
    },
    "powershell": {
        "technique": "T1059.001",
        "name": "PowerShell"
    }
}


def mitre_mapper(evidence: str):

    evidence = evidence.lower()

    matches = []

    for keyword, mapping in MITRE_MAPPINGS.items():

        if keyword in evidence:
            matches.append(mapping)

    return {
        "matches": matches
    }