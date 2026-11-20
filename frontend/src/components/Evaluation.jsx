import { useEffect, useState } from "react";
import { getEvaluationReport } from "../api/client";

export default function Evaluation() {
    const [report, setReport] = useState(null);

    useEffect(() => {
        const load = async () => {
            try {
                const data = await getEvaluationReport();
                setReport(data);
            } catch (error) {
                setReport({
                    error: true,
                    message: error.message || "Failed to load evaluation report.",
                });
            }
        };

        load();
    }, []);

    if (!report) {
        return <p>Loading evaluation...</p>;
    }

    if (report.error) {
        return <p style={{ color: "red" }}>{report.message}</p>;
    }

    return (
        <div style={{ padding: 20 }}>
            <h2>📊 Evaluation Report</h2>

            <h3>
                Accuracy:{" "}
                {typeof report.accuracy === "number"
                    ? (report.accuracy * 100).toFixed(2)
                    : "N/A"}
                %
            </h3>

            <p>
                Total: {report.total} | Correct: {report.correct}
            </p>

            <table
                border="1"
                cellPadding="8"
                style={{ marginTop: 20, borderCollapse: "collapse" }}
            >
                <thead>
                    <tr>
                        <th>Input</th>
                        <th>Expected</th>
                        <th>Predicted</th>
                        <th>Correct</th>
                    </tr>
                </thead>

                <tbody>
                    {(report.results || []).map((r, i) => (
                        <tr key={i}>
                            <td>{r.input}</td>
                            <td>{r.expected}</td>
                            <td>{r.predicted}</td>
                            <td>{r.correct ? "✅" : "❌"}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}