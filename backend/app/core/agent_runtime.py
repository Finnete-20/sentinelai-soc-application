import json

from app.core.llm_client import run_llm
from app.core.tool_registry import TOOLS


MAX_TOOL_CALLS = 10


def build_openai_tools():

    openai_tools = []

    for name, details in TOOLS.items():

        properties = {}

        required = []

        for field_name in details["input_schema"]:

            properties[field_name] = {
                "type": "string"
            }

            required.append(field_name)

        openai_tools.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": details["description"],
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": required
                    }
                }
            }
        )

    return openai_tools


def execute_tool(tool_name, arguments):

    if tool_name not in TOOLS:

        return {
            "error": f"Unknown tool: {tool_name}"
        }

    tool = TOOLS[tool_name]

    fn = tool["function"]

    try:

        result = fn(**arguments)

        return result

    except Exception as e:

        return {
            "error": str(e)
        }


def run_agent_graph(user_input):

    tools = build_openai_tools()

    messages = [
        {
            "role": "user",
            "content": user_input
        }
    ]

    investigation_log = []

    tool_calls_count = 0

    while tool_calls_count < MAX_TOOL_CALLS:

        response = run_llm(
            messages=messages,
            tools=tools
        )

        message = response.choices[0].message

        if not message.tool_calls:

            content = message.content

            try:

                result = json.loads(content)

                result["investigation_log"] = (
                    investigation_log
                )

                return result

            except Exception:

                return {
                    "verdict": "suspicious",
                    "confidence": 0.5,
                    "risk_score": 5,
                    "reason": content,
                    "investigation_log": investigation_log
                }

        messages.append(message)

        for tool_call in message.tool_calls:

            tool_name = (
                tool_call.function.name
            )

            arguments = json.loads(
                tool_call.function.arguments
            )

            tool_result = execute_tool(
                tool_name,
                arguments
            )

            investigation_log.append(
                {
                    "tool": tool_name,
                    "arguments": arguments,
                    "result": tool_result
                }
            )

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(
                        tool_result
                    )
                }
            )

        tool_calls_count += 1

    return {
        "verdict": "suspicious",
        "confidence": 0.5,
        "risk_score": 5,
        "reason": "Maximum tool calls exceeded.",
        "investigation_log": investigation_log
    }