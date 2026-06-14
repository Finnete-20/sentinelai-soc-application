import os
import base64
import requests
from dotenv import load_dotenv

try:
    load_dotenv()
except Exception:
    pass

VT_API_KEY = os.getenv("VT_API_KEY")


def url_reputation_check(url: str):

    result = {
        "url": url,
        "virustotal_available": False,
        "last_analysis_stats": {},
        "reputation": None,
        "categories": [],
        "sources": []
    }

    if not VT_API_KEY:

        return result

    try:

        url_id = (
            base64.urlsafe_b64encode(
                url.encode()
            )
            .decode()
            .strip("=")
        )

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={
                "x-apikey": VT_API_KEY
            },
            timeout=10
        )

        if response.status_code == 200:

            data = response.json()

            attributes = (
                data.get("data", {})
                .get("attributes", {})
            )

            result["virustotal_available"] = True

            result["last_analysis_stats"] = (
                attributes.get(
                    "last_analysis_stats",
                    {}
                )
            )

            result["reputation"] = (
                attributes.get(
                    "reputation"
                )
            )

            result["categories"] = list(
                (
                    attributes.get(
                        "categories",
                        {}
                    )
                ).values()
            )

            result["sources"].append(
                "virustotal"
            )

    except Exception as e:

        result["sources"].append(
            f"vt_error:{str(e)}"
        )

    return result