import { useState } from "react";
import { investigate } from "../api/client";
import "./Investigator.css";

export default function Investigator() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function handleSubmit() {
    if (!input.trim()) return;

    setLoading(true);

    const response = await investigate(input);

    setResult(response);

    setLoading(false);
  }

  const verdictClass =
    result?.data?.verdict?.toLowerCase() || "";

  return (
    <div className="page">

      <div className="header">
        <h1>🛡 SentinelAI SOC Analyst</h1>

        <p className="subtitle">
          Autonomous Security Investigation Platform
        </p>
      </div>

      <textarea
        className="input-box"
        rows={6}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder={`Investigate phishing URL http://secure-login-verification.com

Analyze CVE-2021-44228

Review this suspicious email...`}
      />

      <button
        className="button"
        onClick={handleSubmit}
        disabled={loading}
      >
        {loading ? "🔍 Investigating..." : "Investigate"}
      </button>

      {result?.success && (
        <div className="results">

          <h2>Investigation Result</h2>

          <div className="metrics">

            <div className="card">
              <div className="card-title">VERDICT</div>
              <div className={`card-value ${verdictClass}`}>
                {result.data.verdict.toUpperCase()}
              </div>
            </div>

            <div className="card">
              <div className="card-title">RISK SCORE</div>
              <div className="card-value">
                {result.data.risk_score}
              </div>
            </div>

            <div className="card">
              <div className="card-title">CONFIDENCE</div>
              <div className="card-value">
                {result.data.confidence}
              </div>
            </div>

            <div className="card">
              <div className="card-title">INCIDENT TYPE</div>
              <div className="card-value">
                {result.data.incident_type}
              </div>
            </div>

          </div>

          <div className="section">
            <h3>Reason</h3>
            <p>{result.data.reason}</p>
          </div>

          <div className="section">
            <h3>Executive Summary</h3>
            <p>{result.data.executive_summary}</p>
          </div>

          <div className="section">
            <h3>MITRE ATT&CK Findings</h3>

            <pre>
              {JSON.stringify(
                result.data.mitre_findings,
                null,
                2
              )}
            </pre>
          </div>

          <div className="section">
            <h3>Investigation Timeline</h3>

            <pre className="timeline">
              {JSON.stringify(
                result.data.investigation_log,
                null,
                2
              )}
            </pre>
          </div>

        </div>
      )}

      {result?.success === false && (
        <p className="error">
          {result.error}
        </p>
      )}

    </div>
  );
}