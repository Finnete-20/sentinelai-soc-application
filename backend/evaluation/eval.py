import json
import os
import re
import sys

# --------------------------------------------------
# Add backend folder to Python path
# --------------------------------------------------

BACKEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.tools.url_tool import url_reputation_check

# --------------------------------------------------

DATASET_PATH = os.path.join(
    os.path.dirname(__file__),
    "eval_dataset.json"
)


def load_dataset():
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_url(text: str):
    match = re.search(r"https?://[^\s]+", text)
    if match:
        return match.group(0)
    return None


def predict(sample):

    url = extract_url(sample["input"])

    if url is None:
        return "safe"

    result = url_reputation_check(url)

    return result.get("verdict", "unknown").lower()


def run_evaluation():

    dataset = load_dataset()

    tp = fp = tn = fn = 0

    print("\n🚀 Starting SentinelAI Evaluation (60 samples)\n")

    for sample in dataset:

        expected = sample["expected"].lower()

        predicted = predict(sample)

        if expected == "malicious":

            if predicted == "malicious":

                tp += 1
                print("✅ malicious → malicious")

            else:

                fn += 1
                print(f"❌ malicious → {predicted}")

        elif expected == "safe":

            if predicted == "safe":

                tn += 1
                print("✅ safe → safe")

            else:

                fp += 1
                print(f"❌ safe → {predicted}")

    total = len(dataset)

    accuracy = (tp + tn) / total if total else 0

    precision = tp / (tp + fp) if (tp + fp) else 0

    recall = tp / (tp + fn) if (tp + fn) else 0

    f1 = (
        (2 * precision * recall) / (precision + recall)
        if precision + recall
        else 0
    )

    report = {
        "accuracy": round(accuracy, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }

    print("\n📊 FINAL REPORT\n")

    print(json.dumps(report, indent=2))

    with open(
        os.path.join(os.path.dirname(__file__), "report.json"),
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    run_evaluation()