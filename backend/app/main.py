from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.core.agent_runtime import run_agent_graph
from app.api.report import router as report_router


app = FastAPI(
    title="SentinelAI",
    description="AI-powered SOC Analyst",
    version="2.0"
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://sentinelai-soc-application.vercel.app",
        "https://sentinelai-soc-application-grwvs4yf1-finnete-george-s-projects.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# ROUTERS
# =========================================================

app.include_router(report_router)


# =========================================================
# REQUEST MODELS
# =========================================================

class InvestigationRequest(BaseModel):
    input: str


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/")
def health():

    return {
        "status": "online",
        "service": "SentinelAI SOC",
        "version": "2.0"
    }


# =========================================================
# INVESTIGATION ENDPOINT
# =========================================================

@app.post("/investigate")
def investigate(request: InvestigationRequest):

    result = run_agent_graph(
        request.input
    )

    return result