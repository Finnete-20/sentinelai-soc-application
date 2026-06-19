# SentinelAI Build Log

# Project Goal

SentinelAI is an AI-powered Security Operations Center (SOC) analyst designed to investigate cybersecurity incidents using GPT-4o-mini, MCP tools, threat intelligence feeds, vulnerability intelligence, memory correlation, and executive reporting.

The goal was to build a system that behaves like a Tier 2 / Tier 3 security analyst rather than a simple chatbot. I wanted the application to investigate incidents, gather evidence, reason about findings, and explain conclusions in a way that would be useful to a real analyst.

---

# Why I Chose This Project

My background is in software quality assurance and cybersecurity. Throughout my studies and professional experience, I have seen how much analyst time is spent manually reviewing phishing emails, suspicious URLs, vulnerability reports, and threat intelligence data.

I wanted to build something that could automate parts of that investigation process while still maintaining transparency about how conclusions were reached.

Rather than creating another chatbot, I wanted to build a system that reflected real cybersecurity workflows and solved a problem that I genuinely care about.

Because my master's degree is in cybersecurity, building a SOC analyst was a natural fit. It allowed me to combine security knowledge, software engineering, prompt engineering, deployment, and AI system design into a single project.

---

# Initial Architecture

The first version of SentinelAI worked, but it was not truly agentic.

Most of the important decisions were being made by Python code rather than the language model.

Examples included:

* Hardcoded phishing detection
* Hardcoded risk scoring
* Hardcoded verdict assignment
* Hardcoded MITRE mappings
* Python-controlled investigation flow

The system could produce investigation results, but many conclusions were determined by predefined rules rather than model reasoning.

After reviewing the project requirements and receiving feedback throughout development, I realized the architecture behaved more like an automated workflow than an AI agent.

This became the biggest focus of the project.

---

# Prompt Engineering Iterations

## Prompt Version 1

The original prompt focused primarily on phishing analysis.

The model was instructed to investigate emails and produce structured reports.

Problems I observed:

* Tool usage was inconsistent
* The model sometimes stopped investigating too early
* Reports varied significantly between runs
* The system relied heavily on Python rules

Although the application worked, it was not making full use of the available tools.

---

## Prompt Version 2

The system prompt was redesigned to position the model as a SOC analyst responsible for investigation decisions.

The prompt emphasized:

* Evidence collection
* Threat intelligence gathering
* Tool usage
* Risk assessment
* MITRE ATT&CK mapping
* Executive reporting

The prompt explicitly instructed the model to decide:

* Which tools should be called
* When additional investigation was needed
* How evidence should be correlated
* When an investigation should stop

This significantly improved tool utilization and investigation quality.

---

# Transition to Agentic Architecture

One of the most important changes in the project was shifting responsibility away from Python code and into the language model.

Instead of Python deciding:

* Which investigation path to follow
* Which verdict to assign
* Which risk score to use
* Which evidence was important

the model became responsible for those decisions.

The runtime was redesigned so that:

1. The model receives the user request.
2. The model decides whether tools are needed.
3. The model selects tools.
4. Tool results are returned.
5. The model determines whether additional investigation is required.
6. The model generates the final assessment.

The Python layer became an execution engine rather than a decision engine.

This redesign transformed SentinelAI from a rule-based workflow into an agentic system.

---

# MCP Tool Development

A major requirement of the project was implementing MCP tools.

I created and exposed seven tools to GPT-4o-mini.

### analyze_email

Extracts:

* Email addresses
* URLs
* Domains
* IP addresses
* CVEs

### url_reputation_check

Retrieves:

* VirusTotal reputation data
* Threat intelligence
* Detection statistics

### cve_lookup

Retrieves:

* Live vulnerability information
* CVSS scores
* Severity information
* Vulnerability descriptions

### memory_lookup

Searches previous investigations.

### memory_store

Stores investigation findings.

### mitre_mapper

Provides MITRE ATT&CK knowledge.

### generate_executive_report

Creates executive-level investigation summaries.

The model determines when these tools should be used.

This satisfies the MCP requirement because the model decides when to call a tool, the application executes the tool, and the tool result is returned to the model for further reasoning.

---

# Grounding and Real-Time Data

One of my goals was ensuring that SentinelAI was grounded in real-world information rather than relying only on model training data.

To achieve this, I integrated:

### VirusTotal

Used for live URL reputation analysis.

### National Vulnerability Database (NVD)

Used for live CVE intelligence.

### MITRE ATT&CK

Used for attacker behavior mapping.

### Investigation Memory

Used for historical correlation.

These sources provide information that the model would not otherwise know and allow investigations to be based on current intelligence rather than assumptions.

---

# Challenges I Encountered

Several challenges appeared during development.

## Challenge 1: Understanding Agentic Systems

The biggest challenge was understanding the difference between a system that uses an LLM and a system that is genuinely agentic.

My early versions worked, but most decisions were still controlled by Python.

Refactoring the application so that the model made investigation decisions required significant architectural changes.

This was the most important redesign in the entire project.

---

## Challenge 2: Deployment

The application worked locally long before it worked in production.

I encountered:

* CORS issues
* Environment variable problems
* API connectivity failures
* Frontend-backend communication issues
* Render deployment issues

Resolving these problems helped me better understand what is required to deploy AI systems for real users rather than just running them locally.

---

## Challenge 3: External API Reliability

Because SentinelAI depends on live services, occasional API failures occurred.

The NVD API occasionally timed out or returned temporary failures.

VirusTotal also depended on external availability and API responses.

Handling these situations required improving error handling and implementing fallback behavior so investigations could continue even when services were temporarily unavailable.

This made the application significantly more reliable.

---

## Challenge 4: Vulnerability Classification

One of the most valuable discoveries occurred during testing.

SentinelAI successfully retrieved information for CVE-2021-44228 (Log4Shell) but initially classified it as safe because the reasoning process focused too heavily on active exploitation evidence instead of vulnerability severity.

This showed me that retrieving correct information does not automatically guarantee a correct conclusion.

To address this, I updated the investigation workflow so that critical vulnerability severity is properly reflected in final assessments.

The final system now correctly identifies Log4Shell as a critical vulnerability with an appropriate risk score.

---

# Evaluation

To evaluate SentinelAI, I created a dataset containing 55 cybersecurity investigation samples.

Location:

evaluation/eval_dataset.json

Metrics collected:

* Accuracy
* Precision
* Recall
* F1 Score

Final Results:

* Accuracy: 74.5%
* Precision: 92.3%
* Recall: 48.0%
* F1 Score: 63.2%

One of the most valuable parts of the evaluation process was identifying failure cases.

The evaluation framework revealed situations where the system behaved differently than expected and helped guide improvements throughout development.

Rather than focusing only on successful demonstrations, I intentionally documented failures and used them to improve the investigation workflow.

The evaluation can be reproduced by running:

python evaluation/eval.py

---

# Changes Made After Draft Feedback

Instructor feedback identified an important issue involving CVE-2021-44228 (Log4Shell).

Although SentinelAI correctly retrieved vulnerability information from the NVD API, the final assessment could incorrectly classify critical vulnerabilities as safe.

To address this:

* Vulnerability reasoning was improved
* CVSS severity information was incorporated into assessments
* Investigation outputs were updated to better reflect vulnerability risk
* Additional testing was performed using known high-severity vulnerabilities

The final system correctly identifies Log4Shell as a critical vulnerability and includes supporting evidence within the investigation report.

I also expanded the documentation to better explain architectural decisions, evaluation methodology, development challenges, and lessons learned.

---

# What Surprised Me

One thing that surprised me during development was that building the tools was often easier than getting the model to use them consistently.

Early versions of the project had all of the required components, but investigations sometimes felt scripted because Python was still making too many decisions.

Another surprise was how important evaluation became. Several issues only became visible after running structured test cases. The Log4Shell classification issue is a good example. The vulnerability information was retrieved correctly, but evaluation exposed a flaw in the downstream reasoning process that would have been easy to miss through casual testing.

This reinforced the importance of testing AI systems with realistic scenarios rather than relying on a handful of successful examples.

---

# What I Learned

This project taught me that building trustworthy AI systems requires much more than writing prompts.

The most important lesson was learning how prompting, grounding, tool usage, architecture, evaluation, and deployment all interact.

I also learned that AI systems can still make incorrect decisions even when they have access to correct information. Reliable systems require both model reasoning and engineering safeguards.

Most importantly, I learned how to move from a prototype that demonstrates an idea to a deployed system that another person can actually use.

---

# Final Outcome

SentinelAI evolved from a partially rule-based security investigation application into a fully agentic AI SOC analyst.

The final system demonstrates:

* Prompt engineering
* System prompting
* Grounding
* MCP tool definition
* MCP tool execution
* Agentic reasoning
* Live threat intelligence integration
* Evaluation
* Deployment
* Iterative improvement

The result is a deployed AI application capable of performing autonomous cybersecurity investigations using real-world intelligence and model-driven decision making.
