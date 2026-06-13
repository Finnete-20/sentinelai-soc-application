import json

from app.core.llm_client import run_llm
from app.core.tool_registry import TOOLS


MAX_STEPS = 8


def parse_tool_call(response: str):

    try:

        if not response.lower().startswith("tool:"):
            return None, None

        parts = response.split("|")

        tool_name = (
            parts[0]
            .replace("tool:", "")
            .strip()
        )

        tool_input = (
            parts[1].strip()
            if len(parts) > 1
            else ""
        )

        return tool_name, tool_input

    except Exception:
        return None, None


def execute_tool(tool_name, tool_input):

    if tool_name not in TOOLS:

        return {
            "error": f"Unknown tool: {tool_name}"
        }

    tool = TOOLS[tool_name]

    fn = tool["function"]

    schema = tool["input_schema"]

    field_name = list(schema.keys())[0]

    kwargs = {
        field_name: tool_input
    }

    return fn(**kwargs)


def run_agent_graph(user_input, client=None):

    messages = [
        {
            "role": "user",
            "content": user_input
        }
    ]

    investigation_log = []

    step = 0

    response = run_llm(messages, client)

    while step < MAX_STEPS:

        if (
            isinstance(response, str)
            and response.lower().startswith("tool:")
        ):

            tool_name, tool_input = (
                parse_tool_call(response)
            )

            result = execute_tool(
                tool_name,
                tool_input
            )

            investigation_log.append({
                "tool": tool_name,
                "input": tool_input,
                "result": result
            })

            messages.append({
                "role": "assistant",
                "content": response
            })

            messages.append({
                "role": "tool",
                "content": json.dumps(result)
            })

            response = run_llm(
                messages,
                client
            )

            step += 1

            continue

        break

    try:

        final_response = json.loads(response)

        final_response[
            "investigation_log"
        ] = investigation_log

        return final_response

    except Exception:

        return {
            "verdict": "suspicious",
            "confidence": 0.5,
            "reason": response,
            "investigation_log": investigation_log
        }