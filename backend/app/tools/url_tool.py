import os
import requests

def url_reputation_check(args: dict):
    url = args.get("url")

    if not url:
        return {"error": "missing url"}

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {"error": "missing VT_API_KEY"}

    headers = {"x-apikey": api_key}

    # Step 1: submit URL
    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    return {
        "submitted": submit.status_code,
        "raw": submit.json() if submit.ok else submit.text
    }