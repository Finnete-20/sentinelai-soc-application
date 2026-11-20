import json
import os
import sys

# Fix Windows UTF-8 output when redirecting to files
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


BACKEND_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        ".."
    )
)

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)


from app.core.agent_runtime import run_agent_graph


DATASET_PATH = os.path.join(
    os.path.dirname(__file__),
    "eval_dataset.json"
)


def load_dataset():
    with open(
        DATASET_PATH,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def normalize_verdict(verdict):
    """
    Normalize agent verdicts into the labels used by the evaluator.

    benign -> safe
    """
    verdict = str(verdict).strip().lower()

    # Treat equivalent labels as the same verdict
    if verdict == "benign":
        verdict = "safe"

    # Only allow recognized verdicts
    if verdict not in [
        "safe",
        "suspicious",
        "malicious"
    ]:
        verdict = "unknown"

    return verdict


def predict(sample):
    result = run_agent_graph(
        sample["input"]
    )

    raw_verdict = result.get(
        "verdict",
        "unknown"
    )

    verdict = normalize_verdict(raw_verdict)

    print("\n" + "=" * 80)

    print("INPUT:")
    print(sample["input"])

    print("\nEXPECTED:")
    print(sample["expected"])

    print("\nRAW RESULT:")
    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False
        )
    )

    print("\nNORMALIZED PREDICTION:")
    print(verdict)

    print("=" * 80)

    return verdict


def run_evaluation():
    dataset = load_dataset()

    tp = fp = tn = fn = 0

    print(
        f"\nStarting SentinelAI Evaluation ({len(dataset)} samples)\n"
    )

    for sample in dataset:
        expected = str(
            sample["expected"]
        ).strip().lower()

        predicted = predict(sample)

        # Malicious and suspicious count as positive detections
        if expected == "malicious":
            if predicted in [
                "malicious",
                "suspicious"
            ]:
                tp += 1

                print(
                    f"[PASS] malicious -> {predicted}"
                )
            else:
                fn += 1

                print(
                    f"[FAIL] malicious -> {predicted}"
                )

        # Safe and benign expected labels count as negative cases
        else:
            if predicted == "safe":
                tn += 1

                print(
                    "[PASS] safe -> safe"
                )
            else:
                fp += 1

                print(
                    f"[FAIL] safe -> {predicted}"
                )

    total = len(dataset)

    accuracy = (
        (tp + tn) / total
        if total
        else 0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0
    )

    f1 = (
        (2 * precision * recall)
        / (precision + recall)
        if precision + recall
        else 0
    )

    report = {
        "accuracy": round(
            accuracy,
            3
        ),
        "precision": round(
            precision,
            3
        ),
        "recall": round(
            recall,
            3
        ),
        "f1": round(
            f1,
            3
        ),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn
    }

    print("\nFINAL REPORT\n")

    print(
        json.dumps(
            report,
            indent=2
        )
    )

    report_path = os.path.join(
        os.path.dirname(__file__),
        "report.json"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            report,
            f,
            indent=2
        )

    print(
        f"\nReport saved to: {report_path}"
    )


if __name__ == "__main__":
    run_evaluation()