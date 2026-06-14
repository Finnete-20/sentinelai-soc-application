const BASE_URL = "http://localhost:8000";

export async function investigate(input) {
    try {
        const response = await fetch(
            `${BASE_URL}/investigate`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    input
                })
            }
        );

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