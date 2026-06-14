import { useState } from "react";
import { investigate } from "../api/client";

export default function Investigator() {

    const [input, setInput] = useState("");

    const [loading, setLoading] =
        useState(false);

    const [result, setResult] =
        useState(null);

    async function handleSubmit() {

        if (!input.trim()) return;

        setLoading(true);

        const response =
            await investigate(input);

        setResult(response);

        setLoading(false);
    }

    return (
        <div
            style={{
                maxWidth: "1100px",
                margin: "0 auto",
                padding: "30px",
                fontFamily: "Arial"
            }}
        >
            <h1>
                SentinelAI SOC Analyst
            </h1>

            <p>
                Autonomous Security Investigation Platform
            </p>

            <textarea
                rows={6}
                value={input}
                onChange={(e) =>
                    setInput(e.target.value)
                }
                placeholder="
Investigate phishing URL http://secure-login-verification.com

or

Analyze CVE-2021-44228

or

Review this suspicious email...
"
                style={{
                    width: "100%",
                    padding: "12px"
                }}
            />

            <button
                onClick={handleSubmit}
                disabled={loading}
                style={{
                    marginTop: "10px",
                    padding: "10px 20px"
                }}
            >
                {loading
                    ? "Investigating..."
                    : "Investigate"}
            </button>

            {result?.success && (

                <div
                    style={{
                        marginTop: "30px"
                    }}
                >

                    <h2>
                        Investigation Result
                    </h2>

                    <div>

                        <h3>
                            Verdict:
                            {" "}
                            {result.data.verdict}
                        </h3>

                        <p>
                            Risk Score:
                            {" "}
                            {result.data.risk_score}
                        </p>

                        <p>
                            Confidence:
                            {" "}
                            {result.data.confidence}
                        </p>

                        <p>
                            Incident Type:
                            {" "}
                            {result.data.incident_type}
                        </p>

                        <p>
                            Reason:
                            {" "}
                            {result.data.reason}
                        </p>

                    </div>

                    <hr />

                    <h3>
                        Executive Summary
                    </h3>

                    <p>
                        {
                            result.data
                                .executive_summary
                        }
                    </p>

                    <hr />

                    <h3>
                        MITRE ATT&CK Findings
                    </h3>

                    <pre>
                        {
                            JSON.stringify(
                                result.data
                                    .mitre_findings,
                                null,
                                2
                            )
                        }
                    </pre>

                    <hr />

                    <h3>
                        Investigation Timeline
                    </h3>

                    <pre
                        style={{
                            background: "#111",
                            color: "#0f0",
                            padding: "15px",
                            overflowX: "auto"
                        }}
                    >
                        {
                            JSON.stringify(
                                result.data
                                    .investigation_log,
                                null,
                                2
                            )
                        }
                    </pre>

                </div>
            )}

            {
                result?.success === false &&
                (
                    <p
                        style={{
                            color: "red"
                        }}
                    >
                        {result.error}
                    </p>
                )
            }

        </div>
    );
}