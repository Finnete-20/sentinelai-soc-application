# SentinelAI – Evaluation Methodology and Results

## 1. Overview

SentinelAI was evaluated using a dataset of 55 cybersecurity investigation scenarios designed to assess its ability to distinguish between safe and malicious URLs.

The evaluation focuses on the system's ability to investigate submitted URLs, produce a security verdict, and classify potentially malicious activity.

The evaluation framework executes each scenario through the SentinelAI agent runtime and compares the predicted verdict against the expected label.

## 2. Evaluation Dataset

**Dataset:** `evaluation/eval_dataset.json`

The dataset contains 55 test scenarios:

| Category | Number of Scenarios |
|---|---:|
| Safe URLs | 30 |
| Malicious URLs | 25 |
| **Total** | **55** |

### Safe URL Scenarios

The safe category includes established websites across several categories, including:

- Technology companies.
- Social media platforms.
- News websites.
- Developer platforms.
- Cloud services.
- Online productivity tools.

Examples include:

- `google.com`
- `github.com`
- `microsoft.com`
- `apple.com`
- `linkedin.com`
- `wikipedia.org`
- `cloudflare.com`
- `vercel.com`

### Malicious URL Scenarios

The malicious category contains suspicious URL patterns designed to resemble phishing and impersonation attempts.

Examples include:

- `secure-login-verification.com`
- `paypal-login-security.com`
- `bank-update-account.com`
- `microsoft-support-login.com`
- `account-suspended-verify.com`
- `crypto-wallet-recovery-login.com`

These scenarios test whether SentinelAI can identify suspicious URL naming patterns and distinguish them from established legitimate domains.

## 3. Evaluation Methodology

The evaluation is implemented in:

`evaluation/eval.py`

The script imports the SentinelAI agent runtime and executes each dataset entry using:

```python
run_agent_graph(sample["input"])
```

The predicted verdict is extracted from the agent response and normalized before comparison.

### Verdict Normalization

The evaluator recognizes three verdicts:

- `safe`
- `suspicious`
- `malicious`

The label `benign` is normalized to `safe`.

Any unrecognized verdict is classified as `unknown`.

### Classification Rules

The evaluator uses binary classification rules.

**Positive class: Malicious**

If the expected label is `malicious`:

- Predicted `malicious` = True Positive.
- Predicted `suspicious` = True Positive.
- Predicted `safe` or `unknown` = False Negative.

**Negative class: Safe**

For expected non-malicious cases:

- Predicted `safe` = True Negative.
- Predicted `suspicious`, `malicious`, or `unknown` = False Positive.

This means suspicious predictions are counted as successful detections for malicious cases but as false positives for safe cases.

## 4. Evaluation Metrics

The evaluation framework calculates four primary performance metrics.

### Accuracy

Measures the proportion of all scenarios classified correctly.

\[
Accuracy = \frac{TP + TN}{TP + TN + FP + FN}
\]

### Precision

Measures how many positive detections were correct.

\[
Precision = \frac{TP}{TP + FP}
\]

### Recall

Measures how many actual malicious scenarios were successfully detected.

\[
Recall = \frac{TP}{TP + FN}
\]

### F1 Score

Measures the balance between precision and recall.

\[
F1 = 2 \times \frac{Precision \times Recall}{Precision + Recall}
\]

## 5. Final Evaluation Results

<text>Results recorded in `evaluation/report.json`.</text>

| Metric | Result |
|---|---:|
| Accuracy | **98.2%** |
| Precision | **96.2%** |
| Recall | **100%** |
| F1 Score | **98.0%** |

### Confusion Matrix

| Actual / Predicted | Malicious | Safe |
|---|---:|---:|
| Malicious | 25 | 0 |
| Safe | 1 | 29 |

### Classification Counts

| Classification | Count |
|---|---:|
| True Positives (TP) | 25 |
| True Negatives (TN) | 29 |
| False Positives (FP) | 1 |
| False Negatives (FN) | 0 |
| **Total** | **55** |

### Results Interpretation

**Accuracy – 98.2%**

SentinelAI correctly classified 54 out of 55 investigation scenarios.

**Precision – 96.2%**

Of the 26 scenarios flagged as positive detections, 25 were actual malicious cases.

**Recall – 100%**

All 25 malicious scenarios were detected by the evaluator. No malicious scenario was classified as safe or unknown.

**F1 Score – 98.0%**

The system achieved a strong balance between precision and recall across the evaluated dataset.

## 6. False Positive Analysis

The evaluation recorded one false positive.

A false positive occurs when a safe scenario is incorrectly classified as suspicious or malicious.

This means one of the 30 safe scenarios was incorrectly flagged.

The remaining 29 safe scenarios were correctly classified.

Reducing false positives is important because excessive incorrect alerts can increase analyst workload and reduce confidence in automated security systems.

## 7. False Negative Analysis

The evaluation recorded zero false negatives.

All 25 malicious scenarios were detected as either `malicious` or `suspicious`.

This produced a recall score of 100% within the evaluation dataset.

Avoiding false negatives is important because undetected malicious activity can expose an organization to phishing, credential theft, and other security threats.

## 8. Evaluation Report Generation

The evaluation script automatically generates a JSON report.

Output file:

`evaluation/report.json`

Example:

```json
{
  "accuracy": 0.982,
  "precision": 0.962,
  "recall": 1.0,
  "f1": 0.98,
  "tp": 25,
  "fp": 1,
  "tn": 29,
  "fn": 0
}
```

The report contains the calculated performance metrics and classification counts.

## 9. How to Run the Evaluation

From the backend directory, execute:

```bash
python evaluation/eval.py
```

The script:

1. Loads the evaluation dataset.
2. Submits each scenario to the SentinelAI agent runtime.
3. Retrieves the predicted verdict.
4. Normalizes the verdict.
5. Compares the prediction against the expected label.
6. Updates the confusion matrix counts.
7. Calculates accuracy, precision, recall, and F1 score.
8. Saves the results to `evaluation/report.json`.

The script also prints each investigation input, expected verdict, raw result, and normalized prediction to the terminal.

## 10. Evaluation Limitations

The evaluation results should be interpreted within the scope of the dataset and methodology used.

The current dataset contains 55 predefined URL scenarios. Its safe examples primarily use established domains, while its malicious examples use suspicious URL naming patterns.

The dataset does not establish that every malicious-labeled URL is a live, confirmed phishing website or that every safe-labeled URL is guaranteed to remain safe.

Additional limitations include:

- The dataset is relatively small.
- Malicious scenarios emphasize phishing-style domain patterns.
- The dataset does not cover every type of cyberattack.
- External threat intelligence availability can affect investigation results.
- Model-generated verdicts may vary across runs.
- The evaluation does not independently verify every URL against confirmed incident records.

The results therefore demonstrate performance on the defined evaluation dataset, not a guarantee of equivalent accuracy across all real-world cybersecurity incidents.

Future evaluation improvements could include larger datasets, independently verified threat intelligence labels, additional attack categories, and repeated testing to measure consistency.

## 11. Conclusion

SentinelAI achieved 98.2% accuracy, 96.2% precision, 100% recall, and a 98.0% F1 score across 55 cybersecurity investigation scenarios.

The evaluation recorded 25 true positives, 29 true negatives, one false positive, and zero false negatives.

The results demonstrate strong classification performance within the tested dataset.

The evaluation process also provides a repeatable method for identifying classification errors and measuring improvements as SentinelAI continues to develop.