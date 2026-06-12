import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise ValueError("Missing OPENAI_API_KEY in .env")

client = OpenAI(api_key=api_key)


def call_llm(messages, tools=None):
    request = {
        "model": os.getenv("MODEL_NAME", "gpt-4.1-mini"),
        "messages": messages,
    }

    if tools:
        request["tools"] = tools
        request["tool_choice"] = "auto"

    return client.chat.completions.create(**request)