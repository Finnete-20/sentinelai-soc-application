from fastapi import FastAPI
from pydantic import BaseModel

from app.core.agent_runtime import run_agent_graph
from app.api.report import router as report_router


app = FastAPI(
    title="SentinelAI",
    description="AI-powered SOC Analyst",
    version="2.0"
)


app.include_router(report_router)


class InvestigationRequest(BaseModel):
    input: str


@app.get("/")
def health():

    return {
        "status": "online",
        "service": "SentinelAI SOC"
    }


@app.post("/investigate")
def investigate(request: InvestigationRequest):

    result = run_agent_graph(
        request.input
    )

    return result