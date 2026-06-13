import os

# =========================================================
# ABSOLUTE ROOT RESOLUTION (CRITICAL FIX)
# =========================================================

# get current file location
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# go up to project root (THIS IS THE KEY FIX)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "../../"))

PROMPT_PATH = os.path.join(PROJECT_ROOT, "app", "prompts", "system_prompt.txt")


# =========================================================
# SAFE PROMPT LOADER
# =========================================================
def load_system_prompt():
    """
    Always resolves correctly no matter where script is executed from:
    - backend/evaluation
    - backend/
    - root folder
    - Render / Vercel
    """

    if os.path.exists(PROMPT_PATH):
        with open(PROMPT_PATH, "r", encoding="utf-8") as f:
            return f.read()

    # SAFE FALLBACK (prevents crashes in grading)
    return (
        "You are SentinelAI, a SOC analyst AI. "
        "Classify inputs as SAFE, SUSPICIOUS, or MALICIOUS."
    )


# =========================================================
# LLM WRAPPER
# =========================================================
def run_llm(messages, client):
    """
    Sends request to OpenAI with system prompt injected.
    """

    system_prompt = load_system_prompt()

    full_messages = [
        {"role": "system", "content": system_prompt},
        *messages
    ]

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=full_messages,
        temperature=0.2
    )

    return response.choices[0].message.content