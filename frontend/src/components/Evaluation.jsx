import { useEffect, useState } from "react";
import { getEvaluationReport } from "../api/client";

export default function Evaluation() {
    const [report, setReport] = useState(null);

    useEffect(() => {
        load();
    }, []);

    const load = async () => {
        const data = await getEvaluationReport();
        setReport(data);
    };

    if (!report) return <p>Loading evaluation...</p>;

    if (report.error) {
        return <p style={{ color: "red" }}>{report.message}</p>;
    }

    return (
        <div style={{ padding: 20 }}>
            <h2>📊 Evaluation Report</h2>

            <h3>Accuracy: {(report.accuracy * 100).toFixed(2)}%</h3>
            <p>Total: {report.total} | Correct: {report.correct}</p>

            <table border="1" cellPadding="8" style={{ marginTop: 20 }}>
                <thead>
                    <tr>
                        <th>Input</th>
                        <th>Expected</th>
                        <th>Predicted</th>
                        <th>Correct</th>
                    </tr>
                </thead>
                <tbody>
                    {report.results.map((r, i) => (
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