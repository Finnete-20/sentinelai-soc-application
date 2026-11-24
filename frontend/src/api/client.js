
const BASE_URL = import.meta.env.DEV
    ? "http://127.0.0.1:8000"
    : "https://sentinelai-soc-backend.onrender.com";

/**
 * Convert Markdown-wrapped URLs into plain URLs before sending
 * investigation input to the backend.
 */
function normalizeInvestigationInput(input) {
    if (typeof input !== "string") {
        return input;
    }

    return input
        .replace(
            /\[((?:https?:\/\/)[^\]]+)\]\(((?:https?:\/\/)[^)]+)\)/gi,
            "$2"
        )
        .trim();
}

export async function investigate(input) {
    try {
        const normalizedInput = normalizeInvestigationInput(input);

        const response = await fetch(`${BASE_URL}/investigate`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                input: normalizedInput
            })
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }

        const data = await response.json();

        return {
            success: true,
            data
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}
