import { useState } from "react";
import { investigate } from "../api/client";

export default function Investigator() {
    const [input, setInput] = useState("");
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);

    const handleSubmit = async () => {
        if (!input.trim()) return;

        setLoading(true);
        setResult(null);

        const res = await investigate(input);

        setResult(res);
        setLoading(false);
    };

    const renderVerdict = (result) => {
        if (!result?.data?.result) return null;

        const text = result.data.result.toLowerCase();

        let color = "gray";
        if (text.includes("malicious")) color = "red";
        else if (text.includes("safe")) color = "green";
        else color = "orange";

        return (
            <div style={{
                padding: "10px",
                marginTop: "10px",
                border: `2px solid ${color}`,
                borderRadius: "8px"
            }}>
                <strong>Verdict:</strong> {result.data.result}
            </div>
        );
    };

    return (
        <div style={{
            padding: "30px",
            fontFamily: "Arial",
            maxWidth: "900px",
            margin: "0 auto"
        }}>
            <h1>🛡 SentinelAI SOC Copilot</h1>
            <p>AI-powered phishing & threat intelligence analysis system</p>

            <textarea
                rows={5}
                style={{
                    width: "100%",
                    padding: "10px",
                    fontSize: "14px"
                }}
                placeholder="Paste suspicious URL, email, or log..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
            />

            <button
                onClick={handleSubmit}
                style={{
                    marginTop: "10px",
                    padding: "10px 20px",
                    cursor: "pointer"
                }}
            >
                Analyze Threat
            </button>

            {loading && (
                <p style={{ marginTop: "10px" }}>Analyzing with AI agent...</p>
            )}

            {result?.success === false && (
                <p style={{ color: "red" }}>
                    Error: {result.error}
                </p>
            )}

            {result?.success && (
                <div style={{ marginTop: "20px" }}>
                    <h3>Analysis Output</h3>

                    <pre style={{
                        background: "#111",
                        color: "#0f0",
                        padding: "15px",
                        borderRadius: "8px"
                    }}>
                        {JSON.stringify(result.data, null, 2)}
                    </pre>

                    {renderVerdict(result)}
                </div>
            )}
        </div>
    );
}