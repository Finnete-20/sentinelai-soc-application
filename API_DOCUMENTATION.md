# SentinelAI – API Documentation

## 1. Overview

SentinelAI provides a REST API built with FastAPI. The API connects the React frontend to the backend investigation engine and exposes endpoints for cybersecurity investigations, service health checks, and evaluation reports.

The backend communicates with the agent runtime, which coordinates the language model and available security tools.

**Backend framework:** FastAPI  
**API version:** 2.0  
**Content type:** JSON

## 2. Base URL

The frontend is currently configured to communicate with:

```text
https://sentinelai-soc-backend.onrender.com
```

For local development, the backend URL depends on the local server configuration.

## 3. Available Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Checks backend service status |
| POST | `/investigate` | Submits a cybersecurity investigation |
| GET | `/report` | Retrieves the evaluation report |

## 4. Health Check Endpoint

### GET /

Checks whether the SentinelAI backend is online.

**Request:**

```http
GET /
```

**Example response:**

```json
{
  "status": "online",
  "service": "SentinelAI SOC",
  "version": "2.0"
}
```

**Response fields:**

| Field | Description |
|---|---|
| `status` | Backend service status |
| `service` | Application name |
| `version` | Backend API version |

## 5. Investigation Endpoint

### POST /investigate

The primary SentinelAI endpoint.

It accepts cybersecurity incident information and passes the submitted input to the agent runtime for investigation.

**Request:**

```http
POST /investigate
Content-Type: application/json
```

### Request Body

```json
{
  "input": "Investigate this suspicious URL: http://example.com/login"
}
```

The request uses the following Pydantic model:

```python
class InvestigationRequest(BaseModel):
    input: str
```

### Processing Workflow

When a request is received:

1. FastAPI validates the request body.
2. The investigation endpoint passes the input to `run_agent_graph()`.
3. The agent runtime processes the investigation.
4. The language model can request security tool executions.
5. Tool results are returned to the model for further reasoning.
6. The runtime generates the final assessment and executive summary.
7. FastAPI returns the investigation result as JSON.

### Example Response Structure

The following illustrates the expected structure defined by the agent's system prompt and runtime. Actual values depend on the investigation.

```json
{
  "verdict": "malicious",
  "confidence": 0.95,
  "risk_score": 90,
  "incident_type": "phishing",
  "reason": "The submitted URL contains suspicious characteristics.",
  "mitre_findings": [],
  "cve_findings": [],
  "executive_summary": "Investigation summary.",
  "investigation_log": [
    {
      "tool": "url_reputation_check",
      "arguments": {
        "url": "http://example.com/login"
      },
      "result": {}
    }
  ]
}
```

This is an illustrative response, not a guaranteed response for every investigation.

### Response Fields

| Field | Description |
|---|---|
| `verdict` | Final investigation classification |
| `confidence` | Model-reported confidence |
| `risk_score` | Model-reported risk score |
| `incident_type` | Identified incident category |
| `reason` | Explanation supporting the assessment |
| `mitre_findings` | MITRE ATT&CK findings |
| `cve_findings` | Vulnerability findings |
| `executive_summary` | Generated executive summary |
| `investigation_log` | Tool execution history |

## 6. Evaluation Report Endpoint

### GET /report

Retrieves the evaluation results stored in the backend.

The endpoint reads:

```text
evaluation/report.json
```

**Request:**

```http
GET /report
```

### Successful Response

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

### If No Evaluation Report Exists

```json
{
  "error": "No evaluation report found"
}
```

The current implementation returns this error object without explicitly setting a non-200 HTTP status code.

## 7. Frontend API Integration

File:

`frontend/src/api/client.js`

The React frontend communicates with the backend using the JavaScript Fetch API.

### Backend Configuration

```javascript
const BASE_URL = "https://sentinelai-soc-backend.onrender.com";
```

### Investigation Function

The frontend exposes an asynchronous function:

```javascript
export async function investigate(input)
```

This function:

1. Normalizes the submitted investigation input.
2. Sends a POST request to `/investigate`.
3. Sets the request content type to JSON.
4. Converts the input into a JSON request body.
5. Processes the backend response.
6. Returns either the investigation data or an error.

### Example Request

```javascript
const response = await fetch(`${BASE_URL}/investigate`, {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({
        input: "Investigate this suspicious URL."
    })
});
```

### Frontend Success Response

```javascript
{
    success: true,
    data: data
}
```

### Frontend Error Response

```javascript
{
    success: false,
    error: error.message
}
```

The frontend catches network errors and non-successful HTTP responses and returns them using the error structure.

## 8. Input Normalization

Before submitting an investigation, the frontend runs the input through:

```javascript
normalizeInvestigationInput(input)
```

This function:

- Checks that the input is a string.
- Removes Markdown link wrapping around URLs using a regular expression.
- Trims leading and trailing whitespace.

This helps ensure that URLs submitted through formatted text are passed to the backend in a cleaner format.

## 9. CORS Configuration

The backend uses FastAPI's `CORSMiddleware` to control cross-origin requests.

The configured allowed origins are:

```python
allow_origins=[
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://sentinelai-soc-application.vercel.app",
    "https://sentinelai-soc-application-grwvs4yf1-finnete-george-s-projects.vercel.app",
]
```

Additional settings:

```python
allow_credentials=True
allow_methods=["*"]
allow_headers=["*"]
```

This configuration allows the frontend to communicate with the backend from the listed local development and Vercel origins.

## 10. Error Handling

The current API implementation handles errors at different stages.

| Scenario | Current behavior |
|---|---|
| Invalid request body | FastAPI request validation |
| Missing required `input` field | FastAPI validation error |
| LLM request failure | Agent runtime returns an error result |
| Invalid model JSON | Agent runtime returns a parsing error result |
| Maximum tool-call limit exceeded | Agent runtime returns an error result |
| Failed frontend network request | Frontend returns an error object |
| Non-successful HTTP response | Frontend returns an error containing the HTTP status |
| Missing evaluation report | `/report` returns an error JSON object |

FastAPI validation errors normally use HTTP 422.

The frontend currently checks `response.ok` and throws an error containing the returned HTTP status when the response is unsuccessful.

## 11. Interactive API Documentation

FastAPI automatically generates interactive API documentation.

When the backend is running, the documentation is available at:

```text
/docs
```

For example, with a local server:

```text
http://127.0.0.1:8000/docs
```

The OpenAPI specification is also available at:

```text
/openapi.json
```

The interactive documentation allows developers to inspect endpoints, review request schemas, and submit API requests.

## 12. Local API Testing

Start the backend from the backend directory:

```bash
uvicorn app.main:app --reload
```

Check the service:

```bash
curl http://127.0.0.1:8000/
```

Submit an investigation:

```bash
curl -X POST http://127.0.0.1:8000/investigate \
-H "Content-Type: application/json" \
-d '{"input":"Investigate this suspicious URL: http://example.com/login"}'
```

Retrieve the evaluation report:

```bash
curl http://127.0.0.1:8000/report
```

## 13. Security Considerations

The API uses environment variables to configure sensitive credentials.

The backend requires:

- `OPENAI_API_KEY`
- `VT_API_KEY`

These credentials should never be exposed in frontend code or committed to the public repository.

Additional production improvements may include:

- Authentication and authorization.
- Request rate limiting.
- Input size restrictions.
- More detailed API error responses.
- Structured logging.
- Stronger validation of investigation results.

## 14. Summary

The SentinelAI API provides the communication layer between the React frontend and the Python investigation engine.

The three main endpoints support service health monitoring, cybersecurity investigations, and evaluation report retrieval.

Together with the agent runtime and security tool registry, the API enables the frontend to submit incidents and receive structured investigation results.