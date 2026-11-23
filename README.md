# SentinelAI - AI-Powered SOC Analyst

SentinelAI is an AI-powered Security Operations Center (SOC) analyst designed to investigate cybersecurity incidents through LLM-driven reasoning, MCP tools, threat-intelligence integrations, vulnerability lookups, MITRE ATT&CK mapping, investigation memory, and executive reporting.

The application models parts of a Tier 2/Tier 3 SOC analyst workflow: receiving an incident, determining what evidence is needed, invoking relevant tools, reviewing findings, correlating evidence, and generating an executive investigation report.

**Project:** Generative AI Systems Capstone Project  
**Author:** Finnete George  
**Institution:** Grand Valley State University

---

## Live Application

- **Frontend:** https://sentinelai-soc-application.vercel.app
- **Backend:** https://sentinelai-backend-w5bu.onrender.com

---

## 1. Problem Statement

Security analysts spend significant time investigating alerts, phishing emails, suspicious URLs, IP addresses, vulnerabilities, and threat-intelligence indicators.

Many investigations require analysts to collect information from multiple independent sources before making a decision.

SentinelAI aims to automate and support these investigation activities by:

- Investigating cybersecurity incidents.
- Analyzing suspicious emails.
- Extracting indicators of compromise (IOCs).
- Querying threat-intelligence sources.
- Looking up vulnerabilities.
- Mapping MITRE ATT&CK techniques.
- Correlating historical investigation context.
- Generating executive investigation reports.

The goal is to reduce repetitive analyst workload while improving investigation consistency, evidence collection, and reporting.

## 2. Why I Built SentinelAI

SentinelAI was developed to explore how an AI-powered SOC analyst can autonomously investigate security incidents using an LLM and external cybersecurity tools.

The project combines cybersecurity concepts with modern AI engineering techniques, including:

- Prompt engineering.
- Large Language Model (LLM) integration.
- Model Context Protocol (MCP) tools.
- Agentic workflows.
- Grounding and external data retrieval.
- Investigation memory.
- Structured evaluation.
- Cloud deployment.

## 3. Target Users

- Security Operations Centers (SOC).
- Security analysts.
- Incident response teams.
- Threat intelligence analysts.
- Cybersecurity students and researchers.

---

## 4. System Architecture

SentinelAI uses a frontend-backend architecture with an LLM-driven investigation runtime.

### Architecture Overview

```text
             USER
               |
               v
       React Frontend
        Vercel Hosting
               |
               v
        FastAPI Backend
        Render Hosting
               |
               v
      LLM Investigation Agent
               |
               v
       Model-Driven Reasoning
               |
               v
          MCP Tools
               |
       +-------+-------+
       |       |       |
       v       v       v
    Email    Threat   Vulnerability
   Analysis  Intel    Intelligence
       |       |       |
       +-------+-------+
               |
               v
        Evidence Collection
               |
               v
       LLM Evidence Analysis
               |
               v
       Executive Report
               |
               v
        Final Investigation
```

### Investigation Workflow

1. The user submits an incident through the React frontend.
2. The frontend sends the investigation request to the FastAPI backend.
3. The backend passes the incident to the LLM investigation runtime.
4. The model evaluates the incident and decides which tools are relevant.
5. The backend executes the requested MCP tools.
6. Tool results are returned to the model.
7. The model evaluates the evidence and determines whether additional investigation is necessary.
8. The model generates the final investigation assessment.
9. The frontend displays the investigation results.

The investigation path is model-driven. Not every tool must be called during every investigation.

### Agentic Design

A major architectural requirement was ensuring that the LLM drives investigation decisions rather than relying on predefined Python decision logic.

The model is responsible for deciding:

- Which tools to call.
- Whether additional investigation is necessary.
- How to interpret returned evidence.
- What conclusions are supported by the evidence.
- What verdict and risk assessment to produce.
- What investigation steps should follow.

Python provides the execution environment, manages tool calls, and returns results to the model.

This architecture is intended to support autonomous investigation rather than a fixed sequence of hard-coded investigation steps.

---

## 5. Technologies Used

| Component | Technology |
|---|---|
| Frontend | React |
| Frontend tooling | Vite |
| Frontend language | JavaScript |
| Frontend hosting | Vercel |
| Backend | FastAPI |
| Backend language | Python |
| Backend hosting | Render |
| LLM integration | OpenAI API |
| Threat intelligence | VirusTotal |
| URL intelligence | URLhaus, urlscan.io |
| IP intelligence | AbuseIPDB |
| Vulnerability intelligence | National Vulnerability Database (NVD) |
| Security knowledge | MITRE ATT&CK |
| Agent integration | MCP tools |

The configured model name should be verified against the current backend settings before documenting a specific model version.

---

## 6. MCP Tools and Integrations

SentinelAI uses MCP tools to expose cybersecurity investigation capabilities to the LLM.

The model selects relevant tools during an investigation based on the incident and available evidence.

### 6.1 analyze_email

**Purpose:** Analyze email content and extract potentially relevant indicators.

**Capabilities:**
- Extract email addresses.
- Identify URLs.
- Identify domains.
- Extract IP addresses.
- Identify CVE references.
- Identify potentially suspicious email characteristics.

### 6.2 url_reputation_check

**Purpose:** Retrieve URL reputation information from VirusTotal.

**Capabilities:**
- URL reputation analysis.
- Threat intelligence results.
- Security vendor analysis statistics.
- URL categorization.
- Detection information.

### 6.3 urlhaus_lookup

**Purpose:** Check URL information against URLhaus.

**Capabilities:**
- URL threat intelligence.
- Known malicious URL information.
- Available malware-related URL records.

An absence of URLhaus records does not establish that a URL is safe.

### 6.4 urlscan_lookup

**Purpose:** Retrieve URL scanning information from urlscan.io.

**Capabilities:**
- Historical URL scan information.
- Domain and URL observations.
- Available scan results.
- Relevant website analysis information.

A missing historical scan does not prove that a URL is benign.

### 6.5 abuseipdb_lookup

**Purpose:** Check IP addresses against AbuseIPDB.

**Capabilities:**
- Abuse confidence information.
- IP reporting history.
- ISP information.
- Domain information.
- Available IP reputation details.

IP reputation findings must be interpreted in context. An IP address appearing in an investigation does not automatically establish that it is connected to a suspicious URL or email.

### 6.6 cve_lookup

**Purpose:** Retrieve vulnerability intelligence from the National Vulnerability Database.

**Capabilities:**
- CVE descriptions.
- CVSS scores.
- Vulnerability severity.
- Vulnerability details.
- Available vulnerability references.

### 6.7 mitre_mapper

**Purpose:** Provide MITRE ATT&CK knowledge to support investigation analysis.

**Capabilities:**
- ATT&CK tactics.
- ATT&CK techniques.
- Technique references.
- Detection recommendations.

### 6.8 memory_lookup

**Purpose:** Retrieve relevant historical investigation context.

**Capabilities:**
- Previous investigation findings.
- Historical indicators.
- Prior investigation context.
- Potentially related observations.

### 6.9 memory_store

**Purpose:** Store investigation findings for future reference.

**Capabilities:**
- Persist investigation information.
- Store relevant findings.
- Support future investigation correlation.

### 6.10 generate_executive_report

**Purpose:** Generate an executive-level investigation report.

**Expected report information:**
- Executive summary.
- Investigation verdict.
- Risk score.
- Supporting evidence.
- Identified indicators.
- MITRE ATT&CK mapping.
- Investigation timeline.
- Recommended actions.

The available tool definitions in the backend remain the source of truth for the exact registered tool names and capabilities.

---

## 7. Grounding and Threat Intelligence

SentinelAI uses external cybersecurity intelligence to ground investigation findings.

### VirusTotal

Provides URL reputation and security vendor analysis information.

### URLhaus

Provides information about URLs associated with malicious activity.

### urlscan.io

Provides website scanning and historical URL observations where available.

### AbuseIPDB

Provides IP reputation information and abuse reporting history.

### National Vulnerability Database

Provides vulnerability information, including CVE descriptions and CVSS severity information.

### MITRE ATT&CK

Provides a knowledge base of adversary tactics and techniques.

### Investigation Memory

Provides historical context from previous investigations where relevant.

**Important:** Missing intelligence records must not automatically be interpreted as evidence of safety. Additionally, separate indicators must not be treated as related unless the investigation establishes a supported relationship between them.

---

## 8. Example Investigations

### Test 1 — Analyze an Incident

**AI ANALYST**

Investigate this simulated phishing incident:

**Incident Details:**

Email:

> Your account will be suspended. Verify your credentials immediately.

URL:

`http://secure-login-example.com/account/verify`

IP Address:

`8.8.8.8`

CVE:

`CVE-2021-44228` (Log4Shell)

**Investigation Instructions:**

Use all relevant available tools:

1. Email analysis.
2. VirusTotal.
3. URLhaus.
4. urlscan.io.
5. AbuseIPDB.
6. NVD vulnerability lookup.
7. MITRE ATT&CK mapping.
8. Memory tools, if relevant.

Generate a complete executive investigation report containing:

- Overall verdict.
- Risk score and severity.
- Evidence collected from each intelligence source.
- Investigation timeline.
- Identified indicators of compromise (IOCs).
- MITRE ATT&CK techniques.
- Relevant historical incident context.
- Recommended containment and remediation actions.

**Expected Behavior:**

- The AI analyst autonomously determines which tools to invoke.
- Relevant tool results are incorporated into the investigation.
- Unavailable intelligence sources are clearly identified.
- Findings are correlated carefully without assuming unrelated indicators are connected.
- The final executive report explains the verdict using supporting evidence.
- The report distinguishes confirmed findings from assumptions and unavailable information.

**Important Investigation Considerations:**

This is a simulated incident.

The presence of an IP address or CVE in the input does not automatically establish that either is associated with the phishing URL.

For example, `8.8.8.8` is a Google Public DNS address. Its presence in the incident does not establish malicious activity.

Similarly, CVE-2021-44228 is a separate vulnerability reference. The investigation must not assume that Log4Shell is related to the phishing email without supporting evidence.

---

### Test 2 — Critical Vulnerability Investigation

**Input:**

```text
Analyze CVE-2021-44228
```

**Expected Investigation:**

1. The model identifies the CVE reference.
2. The model invokes `cve_lookup`.
3. NVD vulnerability information is retrieved.
4. The model evaluates CVSS severity and vulnerability details.
5. The model generates a vulnerability assessment.

**Expected Behavior:**

- Log4Shell should be identified as a critical vulnerability.
- CVSS severity should be reflected in the assessment.
- The report should include supporting vulnerability evidence.

During development, instructor feedback identified an earlier reasoning issue where critical vulnerabilities could be incorrectly classified as safe despite successful retrieval of NVD information.

This issue led to improvements in vulnerability reasoning and evaluation.

---

### Test 3 — Suspicious URL Investigation

**Input:**

```text
Investigate this URL: https://malicious-example.com
```

**Expected Investigation:**

- URL reputation lookup where available.
- Threat intelligence analysis.
- Review of returned evidence.
- Final investigation assessment.

The model should not assume that a placeholder URL has a malicious reputation record.

---

### Test 4 — Benign Email Investigation

**Input:**

```text
Hello team,

Please review the attached agenda for tomorrow's meeting.

Regards
```

**Expected Investigation:**

- Email content analysis.
- Indicator extraction.
- Review of suspicious characteristics.
- Final assessment based on available evidence.

---

## 9. Evaluation

SentinelAI was evaluated using a dataset of 55 cybersecurity investigation scenarios.

The dataset covers:

- Phishing emails.
- Suspicious URLs.
- Benign URLs.
- CVE investigations.
- Threat intelligence workflows.

### Evaluation Files

```text
backend/
└── evaluation/
    ├── eval.py
    ├── eval_dataset.json
    └── report.json
```

### Running the Evaluation

From the backend directory:

```bash
python evaluation/eval.py
```

The evaluation script processes the dataset, runs investigations, compares predicted results against expected labels, calculates performance metrics, and generates `report.json`.

### Previously Reported Evaluation Results

The existing README reported the following results:

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

These are historical README figures and should be confirmed against the latest generated `report.json` before being presented as final results.

### Evaluation Metrics

| Metric | Description |
|---|---|
| Accuracy | Percentage of all predictions classified correctly. |
| Precision | Percentage of predicted positive cases that were actually positive. |
| Recall | Percentage of actual positive cases correctly identified. |
| F1 Score | Harmonic mean of precision and recall. |
| True Positives | Malicious cases correctly identified. |
| False Positives | Safe cases incorrectly classified as malicious. |
| True Negatives | Safe cases correctly identified. |
| False Negatives | Malicious cases incorrectly classified as safe. |

The evaluation implementation should be reviewed to confirm how suspicious cases are treated and whether the evaluation is binary or multiclass.

### Evaluation Improvements

Structured evaluation helped identify cases where SentinelAI retrieved correct information but generated an incorrect conclusion.

The Log4Shell investigation was particularly important because it demonstrated that accurate information retrieval does not automatically guarantee accurate reasoning.

Evaluation-driven improvements helped strengthen vulnerability assessment and investigation consistency.

---

## 10. Changes Made After Instructor Feedback

One of the most important issues identified during instructor testing involved CVE-2021-44228 (Log4Shell).

The earlier version retrieved vulnerability information from NVD but incorrectly classified the vulnerability as safe because the reasoning process focused too heavily on active exploitation evidence rather than vulnerability severity.

To address this issue, improvements included:

- Improving vulnerability reasoning.
- Incorporating CVSS severity into final assessments.
- Adding additional tests involving critical vulnerabilities.
- Improving investigation outputs and supporting evidence.
- Adding fallback behavior when external vulnerability services are unavailable.

The project also underwent evaluation-driven improvements to reduce incorrect classifications.

---

## 11. Repository Structure

```text
sentinelai-soc-application/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── prompts/
│   │   ├── tools/
│   │   └── reports/
│   │
│   ├── evaluation/
│   │   ├── eval.py
│   │   ├── eval_dataset.json
│   │   └── report.json
│   │
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── BUILD_LOG.md
└── README.md
```

---

## 12. Local Development

### Backend Setup

Navigate to the backend directory:

```bash
cd backend
```

Create a Python virtual environment:

```bash
python -m venv .venv
```

Activate the environment.

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure the required environment variables for the backend before starting the application.

Start the FastAPI application using the actual application entry point configured in the repository.

### Frontend Setup

Navigate to the frontend directory:

```bash
cd frontend
```

Install dependencies using the package manager and lockfile in the repository.

Configure the backend API base URL to point to the local or deployed backend.

Start the Vite development server using the development script in `package.json`.

---

## 13. API Documentation

### GET `/`

Returns the backend service status.

Example response:

```json
{
  "status": "online",
  "service": "SentinelAI SOC",
  "version": "2.0"
}
```

### POST `/investigate`

Submits an incident for investigation.

**Example Request:**

```json
{
  "input": "Analyze CVE-2021-44228"
}
```

The endpoint passes the submitted input to the investigation runtime and returns the investigation result.

The exact response fields depend on the current backend response structure.

### Interactive API Documentation

FastAPI provides interactive API documentation at:

```text
/docs
```

When the backend is running, visit:

`https://sentinelai-backend-w5bu.onrender.com/docs`

---

## 14. Deployment

SentinelAI is deployed using:

| Component | Hosting Platform |
|---|---|
| Frontend | Vercel |
| Backend | Render |

### Frontend Deployment

The React application is hosted on Vercel.

The frontend communicates with the backend through its configured API base URL.

### Backend Deployment

The FastAPI application is hosted on Render.

The backend provides the investigation API and executes the investigation runtime and available tools.

### Deployment Considerations

- Configure the required API credentials in the hosting environment.
- Ensure the frontend API URL points to the correct backend.
- Configure backend CORS to allow the deployed frontend origin.
- Verify the backend application entry point.
- Check external API connectivity.
- Never commit API keys, tokens, or secrets to GitHub.

---

## 15. Lessons Learned

The biggest lesson from SentinelAI was that building an AI application involves more than prompt engineering.

One of the most important architectural challenges was understanding the difference between a system that uses an LLM and a genuinely model-driven agentic workflow.

Refactoring the application so that the model makes investigation decisions fundamentally changed how SentinelAI operates.

Another important lesson came from evaluation. The Log4Shell issue demonstrated that retrieving correct vulnerability information does not automatically guarantee a correct conclusion.

Structured testing helped identify weaknesses that would have been difficult to discover through casual testing.

Deployment also introduced practical challenges involving environment variables, API connectivity, frontend-backend communication, and hosting configuration.

### Future Improvements

Potential future improvements include:

- Expanding threat intelligence integrations.
- Improving confidence calibration.
- Enhancing explainability.
- Expanding the evaluation dataset.
- Supporting additional SOC investigation workflows.
- Improving evidence correlation.
- Testing conflicting intelligence results and external service failures.

---

## 16. Build Log

A detailed development history, including architectural decisions, prompt iterations, tool implementation, evaluation improvements, deployment challenges, and lessons learned, is documented in:

```text
BUILD_LOG.md
```

---

## 17. Author

**Finnete George**

Master of Science in Cybersecurity  
Grand Valley State University

---

## 18. License

Educational Capstone Project.

AI-Powered Security Operations Center Analyst.
