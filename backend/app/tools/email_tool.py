import re


FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "icloud.com",
    "aol.com"
}


OFFICIAL_ORGANIZATIONS = {
    "grand valley state university": "gvsu.edu",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "openai": "openai.com"
}


SUSPICIOUS_KEYWORDS = [
    "urgent",
    "immediately",
    "verify your account",
    "click here",
    "confirm your identity",
    "password reset",
    "wire transfer",
    "gift card",
    "payment required",
    "limited time",
    "act now",
    "credential",
    "login",
    "security alert",
    "account suspended"
]


def analyze_email(email_text: str):

    text = email_text.lower()

    findings = []

    risk_score = 0

    emails = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        email_text
    )

    urls = re.findall(
        r"https?://[^\s]+",
        email_text
    )

    ips = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        email_text
    )

    cves = re.findall(
        r"CVE-\d{4}-\d+",
        email_text,
        re.IGNORECASE
    )

    domains = []

    for email in emails:

        domain = email.split("@")[1].lower()

        domains.append(domain)

        if domain in FREE_EMAIL_DOMAINS:

            findings.append(
                f"Uses free email provider: {email}"
            )

            risk_score += 3

    for url in urls:

        try:

            domain = (
                url.replace("https://", "")
                .replace("http://", "")
                .split("/")[0]
            )

            domains.append(domain)

        except Exception:
            pass

    for org, expected_domain in OFFICIAL_ORGANIZATIONS.items():

        if org in text:

            for domain in domains:

                if expected_domain not in domain:

                    findings.append(
                        f"Potential impersonation: {org} referenced but contact uses {domain}"
                    )

                    risk_score += 5

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in text:

            findings.append(
                f"Suspicious language detected: {keyword}"
            )

            risk_score += 1

    if "forms.gle" in text:

        findings.append(
            "Google Forms link detected"
        )

        risk_score += 2

    if len(urls) >= 2:

        findings.append(
            "Multiple URLs detected"
        )

        risk_score += 2

    if len(emails) > 1:

        risk_score += 1

    if risk_score >= 8:

        verdict = "malicious"

    elif risk_score >= 4:

        verdict = "suspicious"

    else:

        verdict = "safe"

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "email_addresses": emails,
        "urls_found": urls,
        "domains_found": list(set(domains)),
        "ips_found": ips,
        "cves_found": cves,
        "findings": findings
    }