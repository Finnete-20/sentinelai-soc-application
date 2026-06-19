import os

from dotenv import load_dotenv
from openai import OpenAI


try:
    load_dotenv(encoding="utf-8")
except Exception:
    pass


CURRENT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_ROOT = os.path.abspath(
    os.path.join(CURRENT_DIR, "../../")
)

PROMPT_PATH = os.path.join(
    PROJECT_ROOT,
    "app",
    "prompts",
    "system_prompt.txt"
)


def load_system_prompt():

    if os.path.exists(PROMPT_PATH):

        with open(
            PROMPT_PATH,
            "r",
            encoding="utf-8"
        ) as f:

            return f.read()

    return (
        "You are SentinelAI, "
        "an AI-powered SOC analyst."
    )


def get_client():

    api_key = os.getenv(
        "OPENAI_API_KEY"
    )

    if (
        not api_key
        or "your_openai_api_key_here" in api_key
    ):
        raise ValueError(
            "OPENAI_API_KEY not configured"
        )

    return OpenAI(
        api_key=api_key
    )


def run_llm(
    messages,
    tools=None,
    model="gpt-4o-mini"
):

    client = get_client()

    system_prompt = load_system_prompt()

    full_messages = [
        {
            "role": "system",
            "content": system_prompt
        },
        *messages
    ]

    request = {
        "model": model,
        "messages": full_messages,
        "temperature": 0.2,
        "response_format": {
            "type": "json_object"
        }
    }

    if tools:
        request["tools"] = tools

    return client.chat.completions.create(
        **request
    )