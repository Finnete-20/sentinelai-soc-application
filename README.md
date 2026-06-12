# 🛡 SentinelAI — Agentic SOC Copilot

## Overview
SentinelAI is an AI-powered Security Operations Center (SOC) assistant that detects phishing attempts and malicious URLs using a combination of:

- Large Language Model reasoning (GPT-4.1-mini)
- Tool-based execution (URL reputation checking)
- Agentic decision-making loop
- Evaluation framework for performance measurement

---

## System Architecture

User Input → LLM Agent → Tool Decision → Tool Execution → Observation → Final Verdict

---

## Features

- 🔍 Phishing email analysis
- 🌐 URL reputation checking
- 🤖 Agentic reasoning loop
- 📊 Evaluation pipeline (accuracy scoring)
- 🌐 React SOC dashboard UI

---

## Tech Stack

### Backend
- FastAPI
- OpenAI GPT-4.1-mini
- Python agent runtime
- Tool registry (MCP-style design)

### Frontend
- React (Vite)
- Axios
- SOC dashboard UI

---

## How It Works

1. User submits suspicious email or URL
2. LLM decides whether a tool is needed
3. Tool executes (e.g., URL reputation check)
4. Result is passed back to LLM
5. Final verdict is generated

---

## Evaluation

- Accuracy: 100% (test dataset)
- Dataset: phishing + safe URLs
- Metrics:
  - Correct classifications
  - Malicious detection rate
  - Safe detection rate

Run evaluation:

```bash
python evaluation/eval.py