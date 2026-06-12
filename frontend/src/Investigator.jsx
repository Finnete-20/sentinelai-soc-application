import { useState } from "react";
import { investigate, getReport } from "../api/client";

export default function Investigator() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    setLoading(true);
    const data = await investigate(input);
    setResult(data);
    setLoading(false);
  };

  const loadReport = async () => {
    const data = await getReport();
    setReport(data);
  };

  const getVerdictColor = (text) => {
    if (!text) return "#888";
    if (text.toLowerCase().includes("malicious")) return "#ff4d4d";
    if (text.toLowerCase().includes("safe")) return "#4dff88";
    return "#ffd24d";
  };

  return (
    <div style={styles.container}>
      <h1 style={styles.title}>🛡 SentinelAI SOC Console</h1>

      <div style={styles.grid}>
        {/* LEFT PANEL */}
        <div style={styles.panel}>
          <h3>Threat Input</h3>

          <textarea
            placeholder="Paste email, URL, or suspicious log..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            style={styles.textarea}
          />

          <button onClick={handleAnalyze} style={styles.button}>
            Analyze Threat
          </button>

          <button onClick={loadReport} style={styles.buttonSecondary}>
            Load Evaluation Report
          </button>
        </div>

        {/* RIGHT PANEL */}
        <div style={styles.panel}>
          <h3>Analysis Output</h3>

          {loading && <p>Analyzing incident...</p>}

          {result && (
            <div style={styles.resultBox}>
              <p><b>Input:</b> {result.input}</p>

              <div
                style={{
                  ...styles.verdict,
                  backgroundColor: getVerdictColor(result.result),
                }}
              >
                {result.result}
              </div>
            </div>
          )}

          {!result && !loading && <p>No analysis yet.</p>}
        </div>
      </div>

      {/* REPORT SECTION */}
      {report && (
        <div style={styles.reportBox}>
          <h3>📊 Evaluation Report</h3>
          <pre>{JSON.stringify(report, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

const styles = {
  container: {
    fontFamily: "Arial",
    padding: 20,
    backgroundColor: "#0b0f19",
    color: "#fff",
    minHeight: "100vh",
  },
  title: {
    textAlign: "center",
    marginBottom: 20,
  },
  grid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: 20,
  },
  panel: {
    backgroundColor: "#111827",
    padding: 15,
    borderRadius: 10,
  },
  textarea: {
    width: "100%",
    height: 150,
    marginTop: 10,
    marginBottom: 10,
    padding: 10,
    borderRadius: 6,
  },
  button: {
    width: "100%",
    padding: 10,
    marginTop: 10,
    backgroundColor: "#3b82f6",
    color: "#fff",
    border: "none",
    borderRadius: 6,
    cursor: "pointer",
  },
  buttonSecondary: {
    width: "100%",
    padding: 10,
    marginTop: 10,
    backgroundColor: "#6b7280",
    color: "#fff",
    border: "none",
    borderRadius: 6,
    cursor: "pointer",
  },
  resultBox: {
    marginTop: 10,
    padding: 10,
    backgroundColor: "#1f2937",
    borderRadius: 6,
  },
  verdict: {
    marginTop: 10,
    padding: 10,
    fontWeight: "bold",
    borderRadius: 6,
    textAlign: "center",
  },
  reportBox: {
    marginTop: 20,
    backgroundColor: "#111827",
    padding: 15,
    borderRadius: 10,
  },
};