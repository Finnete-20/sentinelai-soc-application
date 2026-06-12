# SentinelAI BUILD LOG

## Project Overview
SentinelAI is an agentic SOC (Security Operations Center) system designed to detect phishing and malicious URLs using LLM reasoning combined with tool-based execution.

---

## Iteration 1 — Baseline LLM Agent
- Initial version used GPT-4.1-mini only
- No tools integrated
- Output was inconsistent and hallucinated reasoning

Problem:
- No grounding in external verification
- High false positives

---

## Iteration 2 — Tool Integration (MCP-style design)
Added:
- `url_reputation_check` tool
- Tool registry pattern
- LLM tool-calling via OpenAI function calling

Improvement:
- Model now delegates verification to tools
- Reduced hallucination risk

---

## Iteration 3 — Agentic Loop Implementation
Implemented:
- agent_runtime.py loop
- tool execution cycle
- tool result reinjection into LLM

Improvement:
- System now behaves as a true agent
- Supports reasoning → action → observation loop

---

## Iteration 4 — Evaluation System
Added:
- eval.py script
- eval_dataset.json
- automated accuracy scoring

Metrics:
- Accuracy: 100% (on test dataset)
- Supports malicious/safe classification

---

## Iteration 5 — Prompt Engineering Refinement
Added strict system prompt rules:
- Prevent hallucinated tool calls
- Enforce structured SOC behavior
- Require final verdict output

---

## Final Architecture
- LLM (GPT-4.1-mini)
- Tool layer (URL reputation check)
- Agent runtime loop
- Evaluation pipeline
- Frontend SOC dashboard

---

## Known Limitations
- Tool is simulated (VirusTotal not yet integrated)
- Dataset is small (evaluation limited)
- Email phishing detection is rule-assisted, not full NLP model

---

## Future Improvements
- Integrate VirusTotal API
- Add multi-agent LangGraph orchestration
- Expand dataset to 500+ samples
- Add memory layer for persistent threat tracking