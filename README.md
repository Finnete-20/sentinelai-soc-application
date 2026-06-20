# SentinelAI

## AI-Powered SOC Analyst

SentinelAI is an AI-powered Security Operations Center (SOC) analyst that autonomously investigates cybersecurity incidents using LLM-driven reasoning, MCP tools, VirusTotal threat intelligence, live NVD CVE lookups, MITRE ATT&CK knowledge, memory correlation, and executive reporting.

The system is designed to emulate Tier 2 / Tier 3 SOC analyst workflows by allowing the model to make investigation decisions, call tools autonomously, gather evidence, correlate findings, and produce executive-level reports.

This project was developed as a capstone project for Generative AI Systems and combines concepts from prompt engineering, grounding, agentic workflows, MCP tools, deployment, and evaluation into a single production-ready application.

---

# Live Application

## Frontend

https://sentinelai-soc-application.vercel.app

## Backend

https://sentinelai-backend-w5bu.onrender.com

---

# Problem Statement

Security analysts spend significant time investigating alerts, phishing emails, suspicious URLs, vulnerabilities, and threat intelligence indicators.

Many organizations lack the resources to perform consistent investigations across every alert. Analysts often need to manually collect information from multiple systems before making a decision.

SentinelAI helps automate this process by:

* Investigating security incidents
* Correlating evidence
* Querying threat intelligence
* Looking up vulnerabilities
* Mapping MITRE ATT&CK techniques
* Generating executive reports

The goal is to reduce analyst workload while improving investigation consistency and providing transparent reasoning.

---

# Why I Built SentinelAI

Security investigations often require analysts to gather information from multiple sources before making decisions. SentinelAI was designed to mimic that process by allowing the model to collect evidence, call tools, analyze findings, and generate conclusions autonomously.

The project also allowed me to combine cybersecurity concepts with modern AI engineering techniques including prompt engineering, MCP tools, grounding, evaluation, and deployment.

---

# Target Users

* Security Operations Centers (SOC)
* Security Analysts
* Cybersecurity Students
* Incident Response Teams
* Threat Intelligence Analysts

---

# System Architecture

```text
User Input
      │
      ▼
 GPT-4o-mini
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
 GPT-4o-mini Reasoning
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

* React
* Vite
* JavaScript
* Vercel

## Backend

* FastAPI
* Python
* OpenAI API

## Threat Intelligence

* VirusTotal API
* National Vulnerability Database (NVD)

## Security Knowledge

* MITRE ATT&CK

---

# MCP Tools

A major project requirement was implementing MCP tools that are exposed to the model through the tools parameter and selected autonomously during investigations.

## analyze_email

Purpose:

Extract indicators from email content.

Returns:

* Email addresses
* URLs
* Domains
* CVEs
* IP addresses

---

## url_reputation_check

Purpose:

Query VirusTotal for URL reputation.

Returns:

* Reputation information
* Analysis statistics
* Categories
* Threat intelligence

---

## cve_lookup

Purpose:

Retrieve live vulnerability intelligence from the National Vulnerability Database (NVD).

Returns:

* CVSS score
* Severity
* Description
* Vulnerability details

---

## memory_lookup

Purpose:

Search previous investigations.

Returns:

* Historical findings
* Prior investigations

---

## memory_store

Purpose:

Persist investigation findings for future correlation.

Returns:

* Stored record confirmation

---

## mitre_mapper

Purpose:

Provide MITRE ATT&CK reference knowledge.

Returns:

* Techniques
* Tactics
* Detection recommendations

---

## generate_executive_report

Purpose:

Generate executive-level summaries.

Returns:

* Executive summary
* Analyst notes

---

# What Makes SentinelAI Agentic?

The model is responsible for investigation decisions.

The Python application does not decide:

* Which tools to call
* Whether a tool should be called
* What verdict to assign
* What risk score to assign
* What investigation path to follow

Instead:

1. The model receives the incident.
2. The model decides which MCP tools are needed.
3. The model calls tools.
4. The application executes the tool.
5. The model receives tool results.
6. The model decides whether additional investigation is required.
7. The model produces the final investigation result.

This satisfies the project's definition of agentic behavior because the model, not Python, drives decision-making.

If the model were removed and replaced with static logic, the system would not behave the same way.

---

# Grounding

SentinelAI is grounded through multiple external sources.

## VirusTotal

Provides live threat intelligence for URLs.

## National Vulnerability Database (NVD)

Provides live CVE intelligence and vulnerability data.

## MITRE ATT&CK

Provides attacker technique knowledge.

## Memory

Provides historical investigation context.

These sources give the model access to information not available through pretraining alone and allow decisions to be based on current evidence.

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
  "incident_type": "phishing_attempt"
}
```

---

# Example CVE Investigation

Input:

```text
Analyze CVE-2021-44228
```

Investigation Process:

1. Model detects a CVE reference.
2. Model calls cve_lookup.
3. Live NVD intelligence is retrieved.
4. Model evaluates severity and vulnerability details.
5. Model generates final assessment.

Output:

```json
{
  "verdict": "critical",
  "risk_score": 95,
  "incident_type": "critical_vulnerability"
}
```

This example was particularly important because instructor feedback identified an earlier issue where critical vulnerabilities could be underestimated. The final version correctly identifies Log4Shell as a critical vulnerability and includes supporting evidence in the investigation output.

---

# Evaluation

Evaluation was performed using a dataset of 55 cybersecurity investigation scenarios covering phishing emails, suspicious URLs, benign URLs, CVE investigations, and threat intelligence workflows.

The evaluation dataset is located in:

```text
evaluation/eval_dataset.json
```

The evaluation can be reproduced by running:

```bash
python evaluation/eval.py
```

Final Results:

```json
{
  "accuracy": 0.982,
  "precision": 0.962,
  "recall": 1.0,
  "f1": 0.98,
  "tp": 25,
  "fp": 1,
  "tn": 29,
  "fn": 0
}
```

Results Summary:

* Accuracy: 98.2%
* Precision: 96.2%
* Recall: 100%
* F1 Score: 98.0%
* True Positives: 25
* True Negatives: 29
* False Positives: 1
* False Negatives: 0

These results were especially important because SentinelAI is designed to support cybersecurity investigations. Eliminating false negatives became a major goal because missing a real threat is generally more costly than investigating an additional alert.

One of the most valuable outcomes of the evaluation process was discovering situations where the system retrieved correct information but produced incorrect conclusions. Structured testing helped uncover weaknesses that would have been easy to miss through casual testing and directly influenced improvements made throughout development.

The final evaluation demonstrates that SentinelAI can accurately investigate cybersecurity incidents while maintaining strong precision and recall across multiple investigation types.

---

# Changes Made After Draft Feedback

The most important feedback I received involved CVE-2021-44228 (Log4Shell).

During instructor testing, SentinelAI successfully retrieved vulnerability information from the National Vulnerability Database, but the final assessment incorrectly classified the vulnerability as safe because the reasoning process focused too heavily on active exploitation evidence rather than vulnerability severity.

This was one of the most valuable discoveries during the project because it demonstrated that retrieving correct information does not automatically guarantee a correct conclusion.

To address this issue I:

* Improved vulnerability reasoning logic
* Incorporated CVSS severity into final assessments
* Added additional testing using critical vulnerabilities
* Improved investigation outputs to better reflect vulnerability risk
* Added fallback behavior when external vulnerability services are temporarily unavailable

The final version correctly identifies Log4Shell as a critical vulnerability with a risk score of 95 and supporting MITRE ATT&CK evidence.

Example output:

```json
{
  "verdict": "critical",
  "confidence": 0.9,
  "risk_score": 95,
  "incident_type": "critical_vulnerability"
}
```

This change significantly improved overall evaluation performance and eliminated false negatives within the evaluation dataset.

I also expanded the documentation to better explain architectural decisions, evaluation methodology, deployment challenges, and lessons learned throughout development.



---

# How to Test SentinelAI

## Test 1 – Critical Vulnerability

Input:

```text
Analyze CVE-2021-44228
```

Expected:

* cve_lookup tool called
* NVD data retrieved
* Critical vulnerability identified
* Risk score approximately 95

---

## Test 2 – Suspicious URL

Input:

```text
Investigate this URL: https://malicious-example.com
```

Expected:

* url_reputation_check tool called
* VirusTotal data retrieved
* Threat intelligence analyzed
* Final verdict generated

---

## Test 3 – Benign Email

Input:

```text
Hello team,

Please review the attached agenda for tomorrow's meeting.

Regards,
Finnete
```

Expected:

* analyze_email tool called
* No malicious indicators found
* Safe verdict returned

---

# Repository Structure

```text
backend/
├── app/
│   ├── api/
│   ├── core/
│   ├── prompts/
│   ├── tools/
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

A detailed development history, prompt iterations, architectural decisions, evaluation process, deployment challenges, and lessons learned can be found in:

```text
BUILD_LOG.md
```

---
# Lessons Learned

The biggest lesson from this project was that building an AI application is not just about prompting a model.

The most difficult part of the project was learning the difference between a system that uses an LLM and a system that is truly agentic. Early versions of SentinelAI worked, but many important decisions were still controlled by Python code. Refactoring the architecture so that the model made investigation decisions fundamentally changed how the system behaved and brought the project in line with the goals of the assignment.

Another lesson came from evaluation. One of the most surprising findings was that SentinelAI could retrieve completely correct vulnerability information and still reach the wrong conclusion. The Log4Shell issue demonstrated that accurate retrieval and accurate reasoning are not the same thing. Without structured testing, I might never have discovered that problem.

Deployment was also more challenging than expected. I spent significant time resolving environment variable issues, API connectivity problems, frontend-backend communication issues, and Render deployment failures. Those challenges helped me better understand what it takes to move an AI project from a local prototype into a system that real users can access.

Next time, I will expand the threat intelligence integrations, improve confidence calibration, add additional analyst workflows, and build a larger benchmark dataset containing several hundred investigation scenarios.

This project taught me how prompt engineering, grounding, MCP tools, agentic architectures, evaluation, and deployment all work together in a real AI system.


---

# Author

**Finnete George**

Master of Science in Cybersecurity

Grand Valley State University

---

# License

Educational Capstone Project

AI-Powered Security Operations Center Analyst
