# SentinelAI SOC Application – Deployment Guide

## 1. Overview

SentinelAI SOC Application uses a separate frontend and backend deployment architecture.

| Component | Platform | Purpose |
|---|---|---|
| Frontend | Vercel | Hosts the web application |
| Backend | Render | Hosts the FastAPI application |
| AI Integration | OpenAI API | Powers AI-driven security investigations |
| Threat Intelligence | VirusTotal API | Provides URL and file reputation analysis |

## 2. Frontend Deployment – Vercel

The frontend is deployed using Vercel.

**Production URL:**

https://sentinelai-soc-application.vercel.app

### Deployment Steps

1. Push the latest frontend changes to GitHub.
2. Open the Vercel dashboard.
3. Select the SentinelAI project.
4. Confirm the correct GitHub repository is connected.
5. Review the build settings.
6. Deploy the latest changes.
7. Open the production URL and verify that the application loads.

### Frontend Configuration

The frontend communicates with the backend through the API base URL configured in:

`frontend/src/api/client.js`

Verify that the configured backend URL points to the active Render deployment.

## 3. Backend Deployment – Render

The backend is deployed on Render and runs the FastAPI application.

### Deployment Steps

1. Open the Render dashboard.
2. Select the SentinelAI backend service.
3. Confirm the connected GitHub repository and deployment branch.
4. Verify the build and start commands.
5. Configure the required environment variables.
6. Deploy the latest changes.
7. Check the service logs for startup errors.

### Backend Configuration

The backend uses FastAPI.

The following endpoints can be used to verify the deployment:

- `/` – Service health information.
- `/docs` – Interactive API documentation.
- `/openapi.json` – OpenAPI specification.
- `/investigate` – Security investigation endpoint.

## 4. Environment Variables

Configure API credentials through the environment-variable settings in the respective deployment platforms.

| Variable | Purpose |
|---|---|
| `OPENAI_API_KEY` | Authenticates requests to the OpenAI API |
| `VIRUSTOTAL_API_KEY` | Authenticates requests to the VirusTotal API |

**Important:** Confirm these variable names against the backend source code and environment configuration before deployment.

Never commit API keys, passwords, or other secrets to GitHub.

## 5. CORS Configuration

The FastAPI backend uses Cross-Origin Resource Sharing (CORS) to allow requests from approved frontend origins.

The production frontend domain must be included in the backend CORS configuration.

When changing the frontend domain, update the allowed origins in the backend application.

## 6. Post-Deployment Verification

After deploying the frontend and backend, perform the following checks:

- [ ] Frontend production URL loads successfully.
- [ ] Backend service starts successfully.
- [ ] FastAPI documentation is accessible.
- [ ] Frontend can communicate with the backend.
- [ ] Investigation requests return responses.
- [ ] VirusTotal integration works when configured.
- [ ] No API credentials are exposed in frontend code.
- [ ] Deployment logs do not contain critical errors.

## 7. Troubleshooting

| Issue | Possible Cause | Recommended Check |
|---|---|---|
| Frontend cannot reach backend | Incorrect API base URL | Verify `client.js` |
| CORS error | Frontend domain not allowed | Review FastAPI CORS configuration |
| Backend fails to start | Missing dependencies or configuration | Review Render logs |
| OpenAI request fails | Missing or invalid API key | Verify backend environment variables |
| VirusTotal request fails | Missing or invalid API key | Verify VirusTotal configuration |
| Changes are not visible | Deployment did not complete | Review Vercel or Render deployment logs |

## 8. Security Considerations

- Store API credentials as environment variables.
- Never expose backend API keys in frontend code.
- Restrict CORS to trusted frontend domains.
- Avoid committing `.env` files to GitHub.
- Review deployment logs for unexpected errors.
- Keep dependencies updated.

## 9. Deployment Architecture

The application follows a frontend-backend deployment model:

**User → Vercel Frontend → Render FastAPI Backend → AI Agent and Investigation Tools → Investigation Results → Frontend**

This architecture separates the user interface from the investigation engine and its external integrations.