from fastapi import FastAPI
from pydantic import BaseModel
from app.core.agent_runtime import run_agent

app = FastAPI(title="SentinelAI SOC Agent")

class RequestBody(BaseModel):
    input: str


@app.get("/")
def health():
    return {"status": "ok", "message": "SentinelAI running"}


@app.post("/investigate")
def investigate(body: RequestBody):
    return run_agent(body.input)