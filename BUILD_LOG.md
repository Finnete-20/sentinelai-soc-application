# SentinelAI Build Log

# Project Goal

SentinelAI is an AI-powered Security Operations Center (SOC) analyst that autonomously investigates cybersecurity incidents using LLM reasoning, MCP tools, VirusTotal threat intelligence, CVE intelligence, MITRE ATT&CK knowledge, memory correlation, and executive reporting.

The objective was to build a production-ready security investigation platform that behaves like a Tier 2 / Tier 3 SOC analyst.

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
* Python assigning malicious or suspicious verdicts
* Python calculating investigation outcomes
* Rule-based reasoning replacing model reasoning

The project worked technically, but it did not satisfy the course definition of an agentic AI system.

This became the primary focus of the final iteration.

---

# Prompt Engineering Iterations

## Prompt Version 1

The original system prompt focused on identifying phishing emails and producing investigation results.

Issues discovered:

* Tool usage was inconsistent
* The model sometimes stopped investigating too early
* Executive reports lacked consistency
* Investigations relied too heavily on Python logic

---

## Prompt Version 2

The system prompt was redesigned to emphasize:

* Autonomous investigation
* Evidence-based reasoning
* MCP tool usage
* Threat intelligence gathering
* Memory correlation
* MITRE ATT&CK analysis
* Executive reporting

The prompt explicitly instructed the model to:

* Decide which tools to use
* Decide when tools should be used
* Correlate evidence
* Produce structured investigation results

---

## Result

The revised prompt improved:

* Tool utilization
* Investigation quality
* Evidence correlation
* Executive reporting consistency
* Agentic behavior

The final architecture places the model in control of investigation decisions.

---

# Iteration 1: LLM-Centered Investigation Flow

The investigation runtime was redesigned so that:

* The LLM receives the user incident
* The LLM decides which MCP tools to call
* The LLM receives tool results
* The LLM decides what to investigate next
* The LLM decides when to stop
* The LLM produces the final verdict

The Python layer became an execution engine rather than a decision engine.

This significantly increased agentic behavior.

---

# Iteration 2: MCP Tool Architecture

Security capabilities were exposed as MCP tools.

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

The model decides when and how to use each tool.

---

# Iteration 3: Live Threat Intelligence

The original CVE implementation used a local vulnerability database.

This was replaced with a live NVD lookup.

Benefits:

* Real-world vulnerability intelligence
* Up-to-date CVSS scores
* Real vulnerability descriptions
* Better grounding
* Current vulnerability information

VirusTotal integration was also retained to provide live URL reputation intelligence.

The combination of NVD and VirusTotal gives the model access to information unavailable through pretraining alone.

---

# Iteration 4: Agentic Refactoring

A major redesign removed rule-based investigation logic.

Removed components included:

* Hardcoded phishing scoring
* Hardcoded malicious verdicts
* Hardcoded suspicious verdicts
* Hardcoded risk calculations
* Hardcoded investigation routing

Instead:

* The model decides which tools to call
* The model interprets tool results
* The model determines risk
* The model assigns verdicts
* The model produces reports

This transformed the system from a rule-based pipeline into an agentic investigation platform.

---

# Iteration 5: Deployment Improvements

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
* Frontend-backend communication

The final system is publicly accessible.

---

# Iteration 6: Evaluation Framework

A structured evaluation framework was added.

Dataset size:

* 55 cybersecurity investigation samples

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

Interpretation:

* High precision indicates low false-positive rates
* Low false positives reduce analyst fatigue
* Recall remains an area for future improvement

The evaluation framework provides measurable evidence of system performance.

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

# Agentic Behavior

The final system satisfies the course definition of agentic AI.

The model autonomously:

* Decides whether a tool is needed
* Selects which tool to call
* Interprets tool outputs
* Decides whether additional investigation is required
* Produces the final verdict

The Python layer executes tool requests but does not make investigation decisions.

If the model were removed, the system would not behave the same way.

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
* Add live MITRE ATT&CK retrieval

---

# Final Outcome

SentinelAI evolved from a partially rule-based security application into a fully agentic AI SOC analyst where the model drives investigation decisions, tool usage, evidence correlation, and reporting.

The final system demonstrates:

* Prompt engineering
* System prompting
* Grounding
* MCP tool definition
* MCP tool execution
* Agentic reasoning
* Threat intelligence integration
* Evaluation
* Deployment
* Iterative improvement

The resulting platform provides autonomous cybersecurity investigations using real-world threat intelligence and LLM-driven decision making.
