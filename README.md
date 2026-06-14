# SentinelAI

## AI-Powered SOC Analyst

SentinelAI is an AI-powered Security Operations Center (SOC) analyst that autonomously investigates cybersecurity incidents using LLM-driven reasoning, MCP tools, VirusTotal threat intelligence, live NVD CVE lookups, MITRE ATT&CK knowledge, memory correlation, and executive reporting.

The system is designed to emulate Tier 2 / Tier 3 SOC analyst workflows by allowing the model to make investigation decisions, call tools autonomously, gather evidence, correlate findings, and produce executive-level reports.

---

# Live Application

## Frontend

https://sentinelai-soc-application.vercel.app

## Backend

https://sentinelai-backend-w5bu.onrender.com

---

# Problem Statement

Security analysts spend significant time investigating alerts, phishing emails, suspicious URLs, vulnerabilities, and threat intelligence indicators.

Many organizations lack the resources to perform consistent investigations across every alert.

SentinelAI helps automate this process by:

- Investigating security incidents
- Correlating evidence
- Querying threat intelligence
- Looking up vulnerabilities
- Mapping MITRE ATT&CK techniques
- Generating executive reports

The goal is to reduce analyst workload while improving investigation consistency.

---

# Target Users

- Security Operations Centers (SOC)
- Security Analysts
- Cybersecurity Students
- Incident Response Teams
- Threat Intelligence Analysts

---

# System Architecture

```text
User Input
      │
      ▼
 GPT-4.1-mini
      │
      ▼
 MCP Tool Selection
      │
      ▼
 ┌───────────────────────┐
 │ analyze_email         │
 │ url_reputation_check  │
 │ cve_lookup            │
 │ memory_lookup         │
 │ memory_store          │
 │ mitre_mapper          │
 │ generate_report       │
 └───────────────────────┘
      │
      ▼
 Grounded Evidence
      │
      ▼
 GPT-4.1-mini Reasoning
      │
      ▼
 Executive Report
      │
      ▼
 Final Investigation
```

---

# Technologies Used

## Frontend

- React
- Vite
- JavaScript
- Vercel

## Backend

- FastAPI
- Python
- OpenAI API

## Threat Intelligence

- VirusTotal API
- NVD API

## Security Knowledge

- MITRE ATT&CK

---

# MCP Tools

## analyze_email

Purpose:

Extract indicators from email content.

Returns:

- Email addresses
- URLs
- Domains
- CVEs
- IP addresses

---

## url_reputation_check

Purpose:

Query VirusTotal for URL reputation.

Returns:

- Reputation information
- Analysis statistics
- Categories
- Threat intelligence

---

## cve_lookup

Purpose:

Retrieve live vulnerability intelligence from the National Vulnerability Database (NVD).

Returns:

- CVSS score
- Severity
- Description
- Vulnerability details

---

## memory_lookup

Purpose:

Search previous investigations.

Returns:

- Historical findings
- Prior investigations

---

## memory_store

Purpose:

Persist investigation findings for future correlation.

Returns:

- Stored record confirmation

---

## mitre_mapper

Purpose:

Provide MITRE ATT&CK reference knowledge.

Returns:

- Techniques
- Tactics
- Detection recommendations

---

## generate_executive_report

Purpose:

Generate executive-level summaries.

Returns:

- Executive summary
- Analyst notes

---

# What Makes SentinelAI Agentic?

The model is responsible for investigation decisions.

The Python application does not decide:

- Which tools to call
- Whether a tool should be called
- What verdict to assign
- What risk score to assign
- What investigation path to follow

Instead:

1. The model receives the incident.
2. The model decides which MCP tools are needed.
3. The model calls tools.
4. The model receives tool results.
5. The model decides whether more tools are required.
6. The model produces the final investigation result.

This satisfies the project's definition of agentic behavior because the model, not Python, drives decision-making.

---

# Grounding

SentinelAI is grounded through multiple external sources.

## VirusTotal

Provides live threat intelligence for URLs.

## NVD

Provides live CVE intelligence and vulnerability data.

## MITRE ATT&CK

Provides attacker technique knowledge.

## Memory

Provides historical investigation context.

These sources give the model access to information not available through pretraining alone.

---

# Example Investigation

Input:

```text
GVSU Enrollment Form!

Michael Brown <williamsmithn800@gmail.com>

https://forms.gle/r1yZEXiJ1ms6Rsw58
```

Investigation Process:

1. Model receives email.
2. Model calls analyze_email.
3. Model discovers URL and sender.
4. Model calls url_reputation_check.
5. Model calls memory_lookup.
6. Model calls mitre_mapper.
7. Model generates final assessment.

Output:

```json
{
  "verdict": "malicious",
  "confidence": 0.85,
  "incident_type": "Phishing Attempt"
}
```

---

# Evaluation

Evaluation

Evaluation was performed using a dataset of 55 cybersecurity investigation samples located in:

evaluation/eval_dataset.json

The evaluation can be reproduced by running:

python evaluation/eval.py

Metrics:

{
  "accuracy": 0.764,
  "precision": 0.929,
  "recall": 0.520,
  "f1": 0.667
}

Results:

- Accuracy: 76.4%
- Precision: 92.9%
- Recall: 52.0%
- F1 Score: 66.7%

Interpretation:

- High precision indicates that incidents classified as malicious are usually correct.
- Low false-positive rates help reduce analyst fatigue.
- Recall remains an area for future improvement.

How to Test SentinelAI

1. Open the deployed application.
2. Submit a phishing email, suspicious URL, or CVE identifier.
3. Observe the investigation timeline and tool calls.
4. Verify that the model autonomously selects MCP tools and produces a final investigation report.

Example test input:

GVSU Enrollment Form!

Michael Brown <williamsmithn800@gmail.com>

https://forms.gle/r1yZEXiJ1ms6Rsw58

Expected behavior:

- Model calls analyze_email
- Model calls url_reputation_check
- Model may call memory_lookup
- Model may call mitre_mapper
- Model generates an executive report
- Model produces a final verdict based on collected evidence

The complete evaluation framework, dataset, and generated results are included in the repository under the evaluation folder.

---

# Known Limitations

- Recall can be improved on certain phishing scenarios
- Memory storage is local
- Limited enterprise integrations
- MITRE knowledge is reference-based

---

# Future Work

- Splunk integration
- CrowdStrike integration
- Microsoft Defender integration
- Enterprise memory storage
- Expanded evaluation datasets
- Additional threat intelligence feeds
- Analyst feedback learning loops

---

# Repository Structure

```text
backend/
├── app/
│   ├── api/
│   ├── core/
│   ├── tools/
│   ├── prompts/
│   └── reports/
│
├── evaluation/
│   ├── eval.py
│   ├── eval_dataset.json
│   └── report.json
│
└── requirements.txt

frontend/
├── src/
├── public/
└── package.json
```

---

# Build Log

A detailed development history, iterations, evaluation process, architectural changes, and responses to instructor feedback can be found in:

```text
BUILD_LOG.md
```

---

# Author

**Finnete George**

Master's Student in Cybersecurity

Grand Valley State University

---

# License

Educational Capstone Project

AI-Powered Security Operations Center Analyst