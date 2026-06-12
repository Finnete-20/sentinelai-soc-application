const BASE_URL = "https://sentinelai-soc-backend.onrender.com";

export async function investigate(input) {
  const res = await fetch(`${BASE_URL}/investigate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ input }),
  });

  return res.json();
}

export async function getReport() {
  const res = await fetch(`${BASE_URL}/report`);
  return res.json();
}