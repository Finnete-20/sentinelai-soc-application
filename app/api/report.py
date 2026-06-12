from fastapi import APIRouter
import json
from pathlib import Path

router = APIRouter()

@router.get("/report")
def get_report():
    report_path = Path("evaluation/report.json")

    if not report_path.exists():
        return {"error": "No evaluation report found"}

    with open(report_path, "r") as f:
        return json.load(f)