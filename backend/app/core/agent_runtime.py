import json
from app.core.llm_client import call_llm
from app.core.tool_registry import execute_tool
from app.prompts.system_prompt import load_system_prompt


def run_agent(user_input: str):
    """
    Agentic loop:
    LLM decides tool usage → tool executes → LLM re-evaluates → final answer
    """

    system_prompt = load_system_prompt()

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_input}
    ]

    max_iterations = 3

    for _ in range(max_iterations):

        response = call_llm(messages)

        # Try parse tool call
        try:
            tool_call = json.loads(response)

            if "tool" in tool_call:
                tool_name = tool_call["tool"]
                args = tool_call.get("args", {})

                tool_result = execute_tool(tool_name, args)

                # feed tool result back into model
                messages.append({"role": "assistant", "content": response})
                messages.append({"role": "tool", "content": json.dumps(tool_result)})

                continue

        except Exception:
            # Not a tool call → final answer
            return response

    return response