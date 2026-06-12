from pathlib import Path

def load_system_prompt():
    return Path("app/prompts/system_prompt.txt").read_text()

def run_agent(user_input: str):
    system_prompt = load_system_prompt()

    messages = [
        {
            "role": "system",
            "content": system_prompt
        },
        {
            "role": "user",
            "content": user_input
        }
    ]

    # your existing LLM + tool logic stays BELOW this
    # (do NOT change tool runtime unless needed)

    return "OK"  # temporary safe fallback if needed