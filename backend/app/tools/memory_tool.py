import json
import os
from datetime import datetime


BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../")
)

MEMORY_FILE = os.path.join(
    BASE_DIR,
    "investigation_memory.json"
)


def _load():

    if not os.path.exists(MEMORY_FILE):
        return []

    try:
        with open(MEMORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

            if isinstance(data, list):
                return data

            return []

    except Exception:
        return []


def _save(data):

    with open(MEMORY_FILE, "w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            indent=2
        )


def memory_lookup(query: str):

    memory = _load()

    query = query.lower()

    matches = []

    for item in memory:

        text = json.dumps(item).lower()

        if query in text:
            matches.append(item)

    return {
        "query": query,
        "matches_found": len(matches),
        "results": matches[-10:]
    }


def memory_store(finding: str):

    memory = _load()

    record = {
        "timestamp": datetime.utcnow().isoformat(),
        "finding": finding
    }

    memory.append(record)

    _save(memory)

    return {
        "stored": True,
        "record": record,
        "total_records": len(memory)
    }


def memory_stats():

    memory = _load()

    return {
        "records": len(memory)
    }