from app.core.llm import call_llm
from app.core.tool_registry import run_tool
import json


SYSTEM_PROMPT = """
You are SentinelAI, an autonomous SOC analyst.

You analyze URLs, emails, and security inputs.

You MUST behave as an agent:
- Decide when tools are needed
- Call tools if needed
- Use tool outputs before final decision

TOOLS AVAILABLE:
- url_reputation_check: checks URL reputation

OUTPUT FORMAT RULES:

If tool is needed:
{
  "tool": "tool_name",
  "args": {}
}

If final answer:
{
  "final": true,
  "threat_level": "low|medium|high",
  "explanation": "...",
  "verdict": "safe|malicious",
  "evidence": "..."
}
"""


def run_agent(user_input: str):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_input}
    ]

    trace = []

    for _ in range(5):  # safety loop

        response = call_llm(messages)

        # parse safely
        try:
            data = json.loads(response)
        except:
            return {
                "error": "LLM did not return valid JSON",
                "raw": response
            }

        # -------------------------
        # TOOL CALL
        # -------------------------
        if "tool" in data:

            tool_name = data["tool"]
            tool_args = data.get("args", {})

            trace.append({
                "step": "tool_call",
                "tool": tool_name,
                "args": tool_args
            })

            result = run_tool(tool_name, tool_args)

            trace.append({
                "step": "tool_result",
                "result": result
            })

            messages.append({
                "role": "tool",
                "content": json.dumps(result)
            })

            continue

        # -------------------------
        # FINAL ANSWER
        # -------------------------
        if data.get("final"):

            trace.append({
                "step": "final",
                "result": data
            })

            return {
                "result": data,
                "trace": trace
            }

    return {
        "error": "max iterations reached",
        "trace": trace
    }