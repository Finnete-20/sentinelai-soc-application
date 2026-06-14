import re


def analyze_email(email_text: str):

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

    domains = set()

    for email in emails:

        try:
            domains.add(
                email.split("@")[1].lower()
            )
        except Exception:
            pass

    for url in urls:

        try:

            domain = (
                url.replace("https://", "")
                .replace("http://", "")
                .split("/")[0]
                .lower()
            )

            domains.add(domain)

        except Exception:
            pass

    return {
        "email_addresses": emails,
        "urls_found": urls,
        "domains_found": list(domains),
        "ips_found": ips,
        "cves_found": cves,
        "recipient_count": email_text.lower().count("to "),
        "contains_google_forms": (
            "forms.gle" in email_text.lower()
        ),
        "contains_bitly": (
            "bit.ly" in email_text.lower()
        ),
        "contains_tinyurl": (
            "tinyurl" in email_text.lower()
        ),
        "raw_text_length": len(email_text)
    }