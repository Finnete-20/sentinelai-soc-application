from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.agent_runtime import run_agent
from app.api.report import router as report_router

app = FastAPI(
    title="SentinelAI SOC Copilot",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# routes
app.include_router(report_router)


@app.get("/")
def root():
    return {
        "status": "ok",
        "message": "SentinelAI running"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/investigate")
def investigate(payload: dict):
    result = run_agent(payload.get("input", ""))
    return {
        "input": payload.get("input"),
        "result": result
    }