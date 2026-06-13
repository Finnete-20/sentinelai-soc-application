import json
import os

MEMORY_FILE = "investigation_memory.json"


def _load():

    if not os.path.exists(MEMORY_FILE):
        return []

    try:
        with open(MEMORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save(data):

    with open(MEMORY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def memory_lookup(query: str):

    memory = _load()

    matches = []

    for item in memory:

        if query.lower() in str(item).lower():
            matches.append(item)

    return matches[-10:]


def memory_store(finding: str):

    memory = _load()

    memory.append(finding)

    _save(memory)

    return {
        "stored": True,
        "finding": finding
    }