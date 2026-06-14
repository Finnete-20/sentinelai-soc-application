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
    "act now"
]


def analyze_email(email_text: str):

    text = email_text.lower()

    findings = []
    risk_score = 0

    # =====================================================
    # Extract email addresses
    # =====================================================

    emails = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        email_text
    )

    # =====================================================
    # Free email provider check
    # =====================================================

    for email in emails:

        domain = email.split("@")[1].lower()

        if domain in FREE_EMAIL_DOMAINS:

            findings.append(
                f"Uses free email provider: {email}"
            )

            risk_score += 2

    # =====================================================
    # Organization impersonation checks
    # =====================================================

    for org, expected_domain in OFFICIAL_ORGANIZATIONS.items():

        if org in text:

            for email in emails:

                domain = email.split("@")[1].lower()

                if domain != expected_domain:

                    findings.append(
                        f"Potential impersonation: {org} referenced but contact uses {domain}"
                    )

                    risk_score += 4

    # =====================================================
    # Suspicious language checks
    # =====================================================

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in text:

            findings.append(
                f"Suspicious language detected: '{keyword}'"
            )

            risk_score += 1

    # =====================================================
    # URL extraction
    # =====================================================

    urls = re.findall(
        r"https?://[^\s]+",
        email_text
    )

    if len(urls) > 3:

        findings.append(
            "Email contains multiple URLs"
        )

        risk_score += 2

    # =====================================================
    # Verdict
    # =====================================================

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
        "findings": findings
    }