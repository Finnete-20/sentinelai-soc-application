const BASE_URL = "http://localhost:8000";

export async function analyzeURL(url) {
  const res = await fetch(`${BASE_URL}/investigate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });

  return await res.json();
}

export async function runEvaluation(dataset) {
  const res = await fetch(`${BASE_URL}/evaluate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ dataset })
  });

  return await res.json();
}