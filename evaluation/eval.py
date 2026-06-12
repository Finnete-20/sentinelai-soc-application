import json
from app.core.agent_runtime import run_agent


def extract_verdict(text: str):
    text = text.lower()
    if "malicious" in text:
        return "malicious"
    if "safe" in text:
        return "safe"
    return "unknown"


def run_evaluation():
    with open("evaluation/eval_dataset.json") as f:
        dataset = json.load(f)

    results = []
    correct = 0

    for item in dataset:
        output = run_agent(item["input"])
        prediction = extract_verdict(output)

        correct_flag = prediction == item["expected"]

        results.append({
            "input": item["input"],
            "expected": item["expected"],
            "predicted": prediction,
            "output": output,
            "correct": correct_flag
        })

        if correct_flag:
            correct += 1

    report = {
        "accuracy": correct / len(dataset),
        "total": len(dataset),
        "correct": correct,
        "results": results
    }

    with open("evaluation/report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("Accuracy:", report["accuracy"])


if __name__ == "__main__":
    run_evaluation()