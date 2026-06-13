# SentinelAI BUILD LOG

## Project Overview

SentinelAI is an agentic Security Operations Center (SOC) analyst designed to investigate URLs and potential phishing activity using LLM reasoning combined with external threat intelligence.

The goal of the project was to move beyond a traditional chatbot and build a system where an LLM can reason about a security request, decide when a tool is needed, execute that tool, interpret the result, and generate a structured security verdict.

---

## Iteration 1 – Baseline LLM Prototype

### Architecture

* Single GPT-4o-mini based workflow
* No external tools
* Prompt-response interaction only

### Results

The model could explain security concepts and provide general phishing guidance, but it frequently relied on assumptions instead of evidence.

### Problems Identified

* No grounding in external threat intelligence
* Hallucinated security reasoning
* Inconsistent classifications
* Not truly agentic

### Lessons Learned

A SOC analyst system requires access to real-world intelligence rather than relying solely on model knowledge.

---

## Iteration 2 – MCP Tool Integration

### Changes Implemented

Created a custom MCP-style tool:

* `url_reputation_check`

Tool definition included:

* Tool name
* Tool description
* Input schema
* Executable function

### Improvement

The system gained access to external threat intelligence and URL reputation analysis.

### Impact

Reduced unsupported reasoning and provided evidence-based verdicts.

---

## Iteration 3 – Agent Runtime Loop

### Changes Implemented

Created an agent runtime loop that supports:

1. LLM reasoning
2. Tool selection
3. Tool execution
4. Observation of tool output
5. Final decision generation

### Improvement

The system transitioned from a simple prompt-response application into an agentic workflow.

### Agentic Behavior

The model can:

* Determine whether a tool is required
* Request tool execution
* Review tool output
* Produce a final SOC verdict

This implements a reasoning → action → observation pattern.

---

## Iteration 4 – VirusTotal Grounding

### Changes Implemented

Integrated VirusTotal URL intelligence.

The URL reputation tool now combines:

* Heuristic phishing indicators
* HTTP/HTTPS checks
* Suspicious keyword detection
* VirusTotal analysis results

### Improvement

Threat assessments became grounded in real-world security intelligence rather than relying entirely on model reasoning.

### Impact

Improved confidence and realism of security classifications.

---

## Iteration 5 – Evaluation Framework

### Changes Implemented

Created:

* `eval.py`
* `eval_dataset.json`
* `report.json`

Evaluation metrics:

* Accuracy
* Precision
* Recall
* F1 Score
* True Positives
* False Positives
* True Negatives
* False Negatives

### Initial Results

Initial URL scoring thresholds produced low recall and excessive "suspicious" classifications.

### Problem Identified

Many phishing URLs were not being classified as malicious despite containing multiple phishing indicators.

---

## Iteration 6 – Threshold Tuning and Validation

### Changes Implemented

Refined URL reputation scoring logic.

Added:

* Additional phishing indicators
* Improved risk thresholds
* Better malicious classification rules

### Final Evaluation Results

Accuracy: 90.9%

Precision: 95.5%

Recall: 84.0%

F1 Score: 89.4%

Confusion Matrix:

* TP = 21
* FP = 1
* TN = 29
* FN = 4

### Impact

Substantially improved phishing detection performance while maintaining a low false-positive rate.

---

## Prompt Engineering History

### Prompt Version 1

Simple SOC analyst role prompt.

Problems:

* Inconsistent output formatting
* Weak tool usage behavior

---

### Prompt Version 2

Added:

* Structured JSON output
* Tool usage instructions
* Security classification guidance

Improvement:

* More consistent responses
* Better tool integration

---

### Final Prompt

Added:

* Strict SOC analyst role
* Mandatory structured output
* Confidence reporting
* Evidence-based verdicts

Result:

* Stable outputs
* Better evaluation consistency
* Reduced hallucinated responses

---

## Final Architecture

Frontend (React/Vite)

↓

FastAPI Backend

↓

Agent Runtime

↓

GPT-4o-mini

↓

URL Reputation Tool

↓

VirusTotal API

---

## Known Limitations

* Currently focused on URL investigations
* Single-tool architecture
* Limited evaluation dataset size
* No persistent memory between investigations

---

## Future Improvements

* Add AbuseIPDB integration
* Add WHOIS enrichment
* Expand evaluation dataset to 500+ samples
* Introduce multi-agent orchestration
* Add persistent incident tracking and memory

---

## Summary

SentinelAI evolved from a simple LLM prototype into an agentic SOC analyst capable of tool usage, grounded threat intelligence analysis, structured decision making, and quantitative evaluation.

The project demonstrates prompt engineering, grounding, MCP-style tool integration, agentic execution, deployment, and evaluation within a real cybersecurity use case.
