# SentinelAI Build Log

## Project Goal

SentinelAI is an AI-powered Security Operations Center (SOC) analyst that autonomously investigates cybersecurity incidents using LLM reasoning, MCP tools, VirusTotal threat intelligence, CVE intelligence, MITRE ATT&CK knowledge, memory correlation, and executive reporting.

The objective was to build a production-ready security investigation platform that behaves like a Tier 2/Tier 3 SOC analyst rather than a simple chatbot.

---

# Initial Architecture

The first version of SentinelAI relied heavily on Python decision logic.

Examples included:

* Hardcoded phishing detection
* Hardcoded risk scoring
* Hardcoded verdict assignment
* Hardcoded MITRE mappings
* Python-controlled investigation flow

Although functional, this architecture did not satisfy the agentic requirements because Python was making most investigation decisions.

Examples included:

* Python deciding when something was phishing
* Python assigning malicious/suspicious verdicts
* Python calculating investigation outcomes
* Rule-based reasoning replacing model reasoning

---

# Iteration 1: LLM-Centered Investigation Flow

The investigation runtime was redesigned so that:

* The LLM receives the user incident
* The LLM decides which MCP tools to call
* The LLM receives tool results
* The LLM decides what to investigate next
* The LLM produces the final verdict

The Python layer became an execution engine rather than a decision engine.

This significantly increased agentic behavior.

---

# Iteration 2: MCP Tool Architecture

Security capabilities were exposed as MCP tools:

### analyze_email

Extracts indicators from email content.

### url_reputation_check

Queries VirusTotal for URL intelligence.

### cve_lookup

Retrieves vulnerability intelligence.

### memory_lookup

Searches previous investigations.

### memory_store

Stores investigation findings.

### mitre_mapper

Provides MITRE ATT&CK reference knowledge.

### generate_executive_report

Produces executive-level summaries.

The LLM decides when and how to use each tool.

---

# Iteration 3: Live Threat Intelligence

The original CVE implementation used a local vulnerability database.

This was replaced with a live NVD lookup.

Benefits:

* Real-world vulnerability intelligence
* Up-to-date CVSS scores
* Real vulnerability descriptions
* Better grounding

VirusTotal integration was also retained to provide live URL reputation intelligence.

---

# Iteration 4: Deployment Improvements

Frontend:

* React
* Vite
* Vercel

Backend:

* FastAPI
* Render

Several deployment issues were resolved:

* CORS failures
* Environment variable configuration
* API connectivity
* Production routing

The final system is publicly accessible.

---

# Iteration 5: Evaluation Framework

A structured evaluation framework was added.

Dataset size:

* 55 security investigation samples

Metrics collected:

* Accuracy
* Precision
* Recall
* F1 Score

Final results:

* Accuracy: 76.4%
* Precision: 92.9%
* Recall: 52.0%
* F1 Score: 66.7%

The system favors low false positives, which is desirable in SOC workflows.

---

# Final Architecture

User Input

↓

GPT-4.1-mini

↓

LLM decides tool usage

↓

MCP Tool Execution

↓

VirusTotal / NVD / Memory / MITRE

↓

LLM reasoning

↓

Executive Report

↓

Final Investigation Result

---

# Known Limitations

Current limitations include:

* Memory storage is local rather than enterprise-scale
* Recall can be improved on difficult phishing cases
* VirusTotal coverage depends on available intelligence
* MITRE ATT&CK knowledge is currently reference-based rather than dynamically retrieved

---

# Future Improvements

Given additional development time:

* Add SIEM integrations
* Add Splunk connectors
* Add Microsoft Defender integration
* Add CrowdStrike integration


---

# Final Outcome

SentinelAI evolved from a partially rule-based security application into a fully agentic AI SOC analyst where the model drives investigation decisions, tool usage, evidence correlation, and reporting.

The final system demonstrates prompt engineering, grounding, MCP tool execution, autonomous reasoning, evaluation, deployment, and iterative improvement.
