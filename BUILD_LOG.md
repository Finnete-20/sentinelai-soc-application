# SentinelAI – Project Build Log

## 1. Project Goal

SentinelAI is an AI-powered Security Operations Center (SOC) analyst designed to investigate cybersecurity incidents using GPT-4o-mini, MCP tools, threat intelligence feeds, vulnerability intelligence, investigation memory, and executive reporting.

The goal was to build a system that behaves like a Tier 2 / Tier 3 security analyst rather than a simple chatbot. SentinelAI investigates incidents, gathers supporting evidence, reasons about findings, and presents conclusions in a format useful to security analysts.

## 2. Why I Chose This Project

My background is in software quality assurance and cybersecurity. Throughout my studies and professional experience, I observed how much analyst time is spent manually reviewing phishing emails, suspicious URLs, vulnerability reports, and threat intelligence data.

I wanted to develop a system that could automate parts of this investigation process while maintaining transparency about how conclusions were reached.

Rather than creating another chatbot, I wanted to build an application that reflects real cybersecurity workflows and addresses a practical security problem.

My master's degree in cybersecurity provided an opportunity to combine security knowledge, software engineering, prompt engineering, AI system design, and application deployment into one project.

## 3. Initial Architecture

The first version of SentinelAI was functional, but it was not fully agentic.

Many important investigation decisions were being made by Python code rather than the language model.

Examples included:

- Hardcoded phishing detection.
- Hardcoded risk scoring.
- Hardcoded verdict assignment.
- Hardcoded MITRE ATT&CK mappings.
- Python-controlled investigation flow.

Although the application could generate investigation results, many conclusions were determined by predefined rules rather than model reasoning.

After reviewing the project requirements and receiving feedback throughout development, I realized that the architecture behaved more like an automated workflow than an autonomous AI agent.

This became the primary focus of the redesign.

## 4. Prompt Engineering Iterations

### Prompt Version 1

The original system prompt focused primarily on phishing analysis.

The model was instructed to investigate emails and generate structured reports.

However, testing revealed several limitations:

- Tool usage was inconsistent.
- The model sometimes stopped investigating too early.
- Investigation reports varied between runs.
- The system relied heavily on Python rules.

Although the application worked, it was not making full use of the available tools.

### Prompt Version 2

The system prompt was redesigned to position the model as a SOC analyst responsible for investigation decisions.

The updated prompt emphasized:

- Evidence collection.
- Threat intelligence gathering.
- Tool selection and execution.
- Risk assessment.
- MITRE ATT&CK mapping.
- Executive reporting.

The model was explicitly instructed to determine:

- Which tools should be called.
- When additional investigation was necessary.
- How evidence should be correlated.
- When an investigation should stop.
- How the final assessment should be generated.

This improved tool utilization and investigation quality.

## 5. Transition to an Agentic Architecture

One of the most important changes was shifting investigation decision-making away from Python code and into the language model.

Instead of Python determining the investigation path, verdict, risk score, and relevant evidence, the model became responsible for those decisions.

The runtime was redesigned around the following process:

1. The model receives the investigation request.
2. The model determines whether tools are needed.
3. The model selects the appropriate tools.
4. The application executes the selected tools.
5. Tool results are returned to the model.
6. The model determines whether further investigation is required.
7. The model generates the final assessment.

The Python layer became an execution engine rather than the primary decision-making component.

This redesign transformed SentinelAI from a largely rule-based workflow into an agentic investigation system.

## 6. MCP Tool Development

A major project requirement was implementing Model Context Protocol (MCP) tools.

I created and exposed seven tools to GPT-4o-mini.

### 6.1 analyze_email

Extracts relevant indicators from submitted email content, including:

- Email addresses.
- URLs.
- Domains.
- IP addresses.
- CVE identifiers.

### 6.2 url_reputation_check

Retrieves URL reputation information through VirusTotal, including:

- Threat intelligence.
- Reputation data.
- Detection statistics.

### 6.3 cve_lookup

Retrieves vulnerability information from the National Vulnerability Database (NVD), including:

- CVE descriptions.
- CVSS scores.
- Severity information.
- Vulnerability details.

### 6.4 memory_lookup

Searches previous investigations for relevant historical findings.

### 6.5 memory_store

Stores investigation findings for future reference and correlation.

### 6.6 mitre_mapper

Provides MITRE ATT&CK knowledge to support mapping observed activity to known adversary tactics and techniques.

### 6.7 generate_executive_report

Generates structured, executive-level investigation summaries.

The model determines when these tools should be used. The application executes the requested tool, returns its results, and allows the model to continue reasoning.

This supports the project's agentic design: the model decides when to call tools, while the application handles their execution.

## 7. Grounding and Real-Time Threat Intelligence

An important objective was ensuring that SentinelAI relied on real-world information rather than only the model's training data.

The initial integrations included:

### VirusTotal

Used to retrieve URL reputation and threat detection information.

### National Vulnerability Database (NVD)

Used to retrieve vulnerability descriptions, CVSS scores, and severity information.

### MITRE ATT&CK

Used to support mapping investigation findings to known attacker tactics and techniques.

### Investigation Memory

Used to retrieve and store historical investigation findings for correlation.

These integrations allow the model to incorporate external information into its assessments.

## 8. Challenges Encountered During Development

### Challenge 1: Understanding Agentic Systems

The biggest architectural challenge was understanding the difference between an application that uses an LLM and one that is genuinely agentic.

My early versions worked, but most investigation decisions were still controlled by Python.

Refactoring the application so that the model made investigation decisions required significant architectural changes.

This became the most important redesign in the project.

### Challenge 2: Deployment

The application worked locally before it was successfully deployed.

Some of the challenges encountered included:

- Cross-Origin Resource Sharing (CORS) issues.
- Environment variable configuration.
- API connectivity failures.
- Frontend and backend communication problems.
- Render deployment issues.

Resolving these issues helped me understand the additional engineering required to make AI applications accessible outside a local development environment.

### Challenge 3: External API Reliability

SentinelAI depends on external services for threat intelligence and vulnerability information.

During development, some services occasionally returned temporary failures or timed out.

For example:

- The NVD API occasionally timed out or returned temporary failures.
- VirusTotal depended on external service availability and API responses.

I improved error handling and fallback behavior so that investigations could continue when external services were temporarily unavailable.

### Challenge 4: Vulnerability Classification

One of the most important discoveries occurred during testing.

SentinelAI successfully retrieved information for CVE-2021-44228 (Log4Shell), but initially classified it as safe.

The problem was that the reasoning process focused too heavily on active exploitation evidence instead of properly accounting for the vulnerability's severity.

This demonstrated that retrieving accurate information does not automatically guarantee an accurate final assessment.

To address this issue, I improved the investigation workflow so that CVSS severity information was appropriately reflected in the final assessment.

## 9. Evaluation Framework

To evaluate SentinelAI, I created a dataset containing 55 cybersecurity investigation scenarios.

The dataset covers:

- Phishing emails.
- Suspicious URLs.
- Benign URLs.
- Vulnerability investigations.
- Threat intelligence workflows.

**Dataset location:**

`evaluation/eval_dataset.json`

The evaluation framework measures:

- Accuracy.
- Precision.
- Recall.
- F1 Score.

### Final Evaluation Results

| Metric | Result |
|---|---:|
| Accuracy | 98.2% |
| Precision | 96.2% |
| Recall | 100% |
| F1 Score | 98.0% |
| True Positives | 25 |
| True Negatives | 29 |
| False Positives | 1 |
| False Negatives | 0 |

The evaluation process was important because it revealed situations where the system behaved differently from what was expected.

Rather than relying only on successful demonstrations, I used structured test cases to identify weaknesses and guide improvements.

The Log4Shell classification issue was one example. SentinelAI retrieved the vulnerability information correctly but initially produced an incorrect assessment because of a weakness in its reasoning process.

This issue reinforced the importance of evaluating AI systems using realistic scenarios.

### Reproducing the Evaluation

The evaluation can be executed using:

```bash
python evaluation/eval.py
```

The evaluation script processes the dataset, compares predicted verdicts against expected labels, calculates the performance metrics, and generates a JSON report.

The report is saved as:

`evaluation/report.json`

## 10. Improvements Following Instructor Feedback

Instructor feedback identified an important issue involving CVE-2021-44228 (Log4Shell).

Although SentinelAI correctly retrieved vulnerability information from the NVD API, the final assessment could incorrectly classify critical vulnerabilities as safe.

The reasoning process focused too heavily on active exploitation evidence instead of adequately considering vulnerability severity.

To address this issue, I made the following improvements:

- Improved vulnerability reasoning.
- Incorporated CVSS severity information into assessments.
- Updated investigation outputs to better reflect vulnerability risk.
- Performed additional testing using known high-severity vulnerabilities.
- Improved fallback behavior when external vulnerability services are temporarily unavailable.

The final system correctly identifies Log4Shell as a critical vulnerability, with a risk score of 95 and supporting MITRE ATT&CK evidence.

**Example output:**

```json
{
  "verdict": "critical",
  "confidence": 0.9,
  "risk_score": 95,
  "incident_type": "critical_vulnerability"
}
```

This improvement addressed the identified classification issue and eliminated false negatives within the evaluation dataset.

I also expanded the project documentation to explain the architecture, evaluation methodology, deployment challenges, and lessons learned.

## 11. What Surprised Me

One thing that surprised me was that developing the tools was often easier than getting the model to use them consistently.

The early versions already contained the required components, but investigations sometimes felt scripted because Python was still making too many decisions.

Another important discovery was how much evaluation contributed to improving the application.

Several issues only became visible after running structured test cases. The Log4Shell classification issue is a good example: the vulnerability information was retrieved correctly, but the final reasoning was incorrect.

This reinforced the importance of testing AI systems with realistic scenarios rather than relying on a few successful demonstrations.

## 12. What I Learned

This project taught me that building trustworthy AI systems requires much more than writing prompts.

The most important lessons were:

- **Agentic architecture:** Understanding how to move decision-making from predefined Python logic to model-driven reasoning.
- **Prompt engineering:** Designing system prompts that guide investigation behavior and tool usage.
- **Grounding:** Using external intelligence sources to support model assessments.
- **MCP integration:** Defining tools and allowing the model to decide when they should be executed.
- **Evaluation:** Using structured datasets and performance metrics to identify weaknesses.
- **Reliability:** Handling external API failures and temporary service interruptions.
- **Deployment:** Moving an AI application from local development into a production environment.

Most importantly, I learned that AI systems can still produce incorrect conclusions even when they have access to accurate information. Reliable AI applications require careful architecture, evaluation, and engineering safeguards.

## 13. Final Outcome

SentinelAI evolved from a partially rule-based cybersecurity investigation application into an agentic AI SOC analyst.

The completed project demonstrates:

- System prompt engineering.
- Agentic reasoning.
- Grounding with external information.
- MCP tool definition and execution.
- Threat intelligence integration.
- Vulnerability intelligence retrieval.
- Investigation memory.
- MITRE ATT&CK mapping.
- Structured evaluation.
- Application deployment.
- Iterative testing and improvement.

The final result is a deployed AI application designed to investigate cybersecurity incidents using model-driven decisions, external intelligence, and supporting evidence.

The project represents the practical application of cybersecurity knowledge, software engineering, and AI system development in building a more autonomous security investigation assistant.