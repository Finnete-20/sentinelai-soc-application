import { useState } from "react";
import { analyzeURL } from "../api/client";

export default function InvestigatorPage() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);

  const handleCheck = async () => {
    const res = await analyzeURL(url);
    setResult(res);
  };

  return (
    <div style={{ padding: 20 }}>
      <h2>URL Investigator</h2>

      <input
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="Enter URL"
      />

      <button onClick={handleCheck}>Analyze</button>

      {result && (
        <pre>{JSON.stringify(result, null, 2)}</pre>
      )}
    </div>
  );
}